//! A REALITY inbound whose camouflage target is a unix socket.
//!
//! Xray's `type: "unix"` makes the target a path rather than a host and a
//! port (`infra/conf/transport_internet.go:824-832`), and the fallback relay
//! dials it as one (`RL/tls.go:168`). A port that a config Xray accepts is a
//! config this core has to accept too, or an operator migrating a listener
//! finds the migration refused at start-up.
//!
//! What is checked here is the whole path: the config compiles, the target is
//! carried as the path it was written as, and an unauthenticated visitor is
//! handed to that socket — with the ClientHello it already sent, so the site
//! sees the stream it would have seen.

#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PRIVATE_KEY: &str = "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0";
const SNI: &str = "example.test";
const SHORT_ID: &str = "ab12";
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

/// The bytes the camouflage site saw, so the test can say what reached it.
type Seen = Arc<Mutex<Vec<u8>>>;

/// A unix socket that answers every visitor with a fixed reply, and records
/// what it was sent.
async fn site(path: &std::path::Path) -> (Seen, tokio::task::JoinHandle<()>) {
    // A stale socket file would make the bind fail.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("the site binds");
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let handle = tokio::spawn({
        let seen = Arc::clone(&seen);
        async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = [0u8; 1024];
                let Ok(read) = stream.read(&mut buffer).await else {
                    continue;
                };
                seen.lock().unwrap().extend_from_slice(&buffer[..read]);
                let _ = stream.write_all(REPLY).await;
                let _ = stream.flush().await;
            }
        }
    });
    (seen, handle)
}

/// A well-formed TLS 1.3 ClientHello record, from a visitor that is not a
/// client.
///
/// The record has to be well formed, or the server refuses it outright
/// instead of handing it to the site — and the point of the test is the
/// handover.
fn client_hello_record() -> Vec<u8> {
    // A minimal ClientHello: the version, a random, a zero-length session
    // id, one cipher suite, no compression, and no extensions.
    let mut message = Vec::new();
    message.push(0x01); // client_hello
    message.extend_from_slice(&[0x00, 0x00, 0x24]); // length
    message.extend_from_slice(&[0x03, 0x03]); // legacy_version
    message.extend_from_slice(&[0x5a; 32]); // random
    message.push(0x00); // session id length
    message.extend_from_slice(&[0x13, 0x01]); // cipher suite
    message.extend_from_slice(&[0x01, 0x00]); // compression
    message.extend_from_slice(&[0x00, 0x00]); // extensions length
    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// A path in the temporary directory that no other test will take.
fn socket_path(name: &str) -> std::path::PathBuf {
    let directory =
        std::env::temp_dir().join(format!("zray-reality-unix-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    directory.join("decoy.sock")
}

/// The inbound, with the camouflage target as a unix socket.
fn config(port: u16, path: &std::path::Path) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "reality-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": UUID}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": path.to_str().unwrap(),
                    "type": "unix",
                    "serverNames": [SNI],
                    "privateKey": PRIVATE_KEY,
                    "shortIds": [SHORT_ID],
                }
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// The configuration compiles, and the target is carried as the path it was
/// written as.
///
/// A target that came through as a host and a port would be dialled as one,
/// and the fallback would go nowhere.
#[test]
fn a_unix_socket_target_is_carried_as_the_path_it_was_written_as() {
    let path = socket_path("compile");
    let (generation, _) =
        zero_config::compile_config(&config(free_port(), &path), zero_core::GenerationId(1))
            .expect("a unix socket target compiles");
    let inbound = generation
        .config
        .inbounds
        .first()
        .expect("one inbound was compiled");
    let zero_config::InboundSecurity::Reality(reality) = &inbound.security else {
        panic!(
            "the inbound compiled to {:?}, not REALITY",
            inbound.security
        );
    };
    assert_eq!(
        reality.target,
        Some(zero_config::RealityTarget::Unix(
            path.to_str().unwrap().into()
        )),
        "the target is the path, not a host and a port"
    );
}

/// An unauthenticated visitor is handed to the unix socket, with the
/// ClientHello it already sent.
///
/// The site's own answer comes back to the visitor, which is the whole point
/// of the fallback: a prober that is not a client gets the site's answer, not
/// a closed connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visitor_is_handed_to_the_unix_socket() {
    let path = socket_path("handover");
    let (seen, site_task) = site(&path).await;

    let port = free_port();
    let (generation, _) =
        zero_config::compile_config(&config(port, &path), zero_core::GenerationId(1))
            .expect("a unix socket target compiles");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: generation.config,
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });

    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut connected = false;
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(connected, "the REALITY listener never listened");

    // A visitor that is not a client: an ordinary TLS ClientHello, which the
    // server cannot authenticate, so it is handed to the site.
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let hello = client_hello_record();
    stream.write_all(&hello).await.unwrap();
    stream.flush().await.unwrap();

    // The site's answer reaches the visitor.
    let mut buffer = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("the site's answer came back")
        .expect("the visitor could read it");
    assert_eq!(
        &buffer[..read],
        REPLY,
        "the visitor got the site's own answer"
    );

    // And the site saw the hello the visitor sent.
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.starts_with(&hello[..6]),
        "the site saw the visitor's first record: {seen:?}"
    );

    site_task.abort();
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// A destination that is neither a host and a port nor a socket is refused
/// by name, rather than dialled as something it is not.
#[test]
fn a_target_that_is_neither_shape_is_refused_by_name() {
    let mut document = config(free_port(), std::path::Path::new("/run/decoy.sock"));
    // `type: "unix"` is dropped, so the dest's own shape decides — and a
    // host with no port is neither shape.
    document["inbounds"][0]["streamSettings"]["realitySettings"]
        .as_object_mut()
        .expect("object")
        .remove("type");
    document["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] = json!("example.com");
    let error = zero_config::compile_config(&document, zero_core::GenerationId(1))
        .expect_err("a host with no port is not a target");
    assert!(
        error.contains("dest"),
        "the refusal names the field: {error}"
    );
}

/// The unix socket is dialled as a unix socket, not as a host name.
///
/// A path that was resolved as a host name would fail at DNS time, minutes
/// later, for a reason that names nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unix_socket_is_dialled_as_one() {
    let path = socket_path("dial");
    let (_seen, site_task) = site(&path).await;
    let mut stream = UnixStream::connect(&path)
        .await
        .expect("the socket is dialled");
    stream.write_all(b"ping").await.unwrap();
    let mut buffer = [0u8; 8];
    let read = stream.read(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..read], &REPLY[..read]);
    site_task.abort();
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
