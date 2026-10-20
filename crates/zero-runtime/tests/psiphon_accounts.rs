//! The Psiphon outbound on a running server, with accounts and limits.
//!
//! The rig is one process: a Trojan inbound whose client is an *account*, a
//! native Psiphon outbound, and an in-process Psiphon server (from
//! `zero-psiphon`'s `test-util` feature) that forwards to a loopback origin.
//! The path a request takes is therefore the whole one:
//!
//! ```text
//! client -> Trojan inbound -> Psiphon outbound -> SSH tunnel -> mock Psiphon
//!        server -> origin
//! ```
//!
//! What is checked is what a panel relies on: the account's bytes are visible
//! while its session is open, the account is listed as online, the outbound's
//! own traffic counter moves, and a speed limit on the account holds the
//! session to the limit rather than letting it run free. The transport under
//! the account is a Psiphon tunnel, which is the point: the metering must not
//! care what carries it.
//!
//! The mock server is the same one the crate's own tests use
//! (`zero_psiphon::mock`), so this test needs no Go toolchain and no
//! network.
//!
//! These tests run on a thread with a deliberately large stack
//! (`WORKER_STACK`). The chain of futures a single session goes through —
//! the inbound handler, the relay, the balancer, the outbound, the Psiphon
//! client's dial loop, the candidate race, the carrier, and russh's key
//! exchange — is deep, and an unoptimised build gives each of those frames
//! several times the stack an optimised one does. That is a property of the
//! build, not of the code: the same test passes in `--release` on the
//! default stack, and the runtime's own threads carry the same chain in
//! production.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The stack the tests run on: enough for the session's whole future chain
/// in an unoptimised build.
const WORKER_STACK: usize = 16 * 1024 * 1024;

const PASSWORD: &str = "a-trojan-password";
/// The marker the origin answers with.
const MARKER: &str = "psiphon-mock-origin";
/// The size of the origin's body. It is big enough that a speed limit in
/// force is visible in the time the transfer takes.
const BODY: usize = 64 * 1024;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An HTTP origin that answers every request with the marker.
async fn origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }
                let mut body = vec![b'.'; BODY];
                body[..MARKER.len()].copy_from_slice(MARKER.as_bytes());
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).await.ok();
                stream.write_all(&body).await.ok();
                stream.flush().await.ok();
            });
        }
    });
    (address, handle)
}

/// The server entry of the mock Psiphon server, as the outbound's settings.
fn psiphon_settings(entry: &zero_psiphon::ServerEntry) -> Value {
    json!({
        "serverEntries": entry.to_value(),
        "protocols": ["SSH"],
    })
}

struct Rig {
    server: Arc<zero_runtime::Server>,
    server_port: u16,
    origin_port: u16,
}

async fn rig() -> Rig {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("ZRAY_TEST_LOG").unwrap_or_else(|_| "warn".into()),
        ))
        .with_test_writer()
        .try_init();

    let (origin_address, _origin_task) = origin().await;

    // The in-process Psiphon server, forwarding to the origin.
    let mock =
        zero_psiphon::mock::serve(origin_address, zero_psiphon::mock::MockOptions::new()).await;

    let server_port = free_port();
    let config = json!({
        "inbounds": [{
            "tag": "server", "listen": "127.0.0.1", "port": server_port, "protocol": "trojan",
            "settings": {"clients": [{"password": PASSWORD, "email": "alice@panel"}]},
        }],
        "outbounds": [{
            "tag": "psiphon", "protocol": "psiphon",
            "settings": psiphon_settings(&mock.entry),
        }],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["server"], "outboundTag": "psiphon"},
        ]},
    });

    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;

    Rig {
        server,
        server_port,
        origin_port: origin_address.port(),
    }
}

/// A Trojan session to the rig's inbound, asking for `host:port`.
///
/// The Trojan header is the protocol's own: 56 hex characters of the
/// password's SHA-224, CRLF, the command byte, the address, the port, CRLF,
/// and then the payload.
async fn open(rig: &Rig, host: &str, port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", rig.server_port))
        .await
        .unwrap();

    use sha2::Digest as _;
    let digest = sha2::Sha224::digest(PASSWORD.as_bytes());
    let mut header = hex::encode(digest).into_bytes();
    header.extend_from_slice(b"\r\n");
    header.push(0x01); // connect
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        header.push(0x01);
        header.extend_from_slice(&ip.octets());
    } else {
        header.push(0x03);
        header.push(host.len() as u8);
        header.extend_from_slice(host.as_bytes());
    }
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(b"\r\n");
    header.extend_from_slice(b"GET /marker.txt HTTP/1.1\r\nHost: origin\r\n\r\n");

    stream.write_all(&header).await.unwrap();
    stream
}

/// Read the whole response, up to the end of the body.
async fn read_response(stream: &mut TcpStream) -> String {
    let mut text = String::new();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buffer))
            .await
            .expect("the response arrives in time")
            .expect("the response");
        if read == 0 {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&buffer[..read]));
    }
    text
}

/// Run an async test body on a thread with [`WORKER_STACK`].
macro_rules! deep_stack_test {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            let handle = std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("a runtime")
                        .block_on(async $body)
                })
                .expect("a thread");
            handle.join().expect("the test thread");
        }
    };
}

deep_stack_test!(an_accounts_traffic_is_metered_through_a_psiphon_tunnel, {
    let rig = rig().await;

    let mut session = open(&rig, "127.0.0.1", rig.origin_port).await;
    let response = read_response(&mut session).await;
    eprintln!("RESPONSE: {response:?}");
    eprintln!(
        "STATS: accepted={} succeeded={} failed={}",
        rig.server
            .stats
            .accepted
            .load(std::sync::atomic::Ordering::Relaxed),
        rig.server
            .stats
            .succeeded
            .load(std::sync::atomic::Ordering::Relaxed),
        rig.server
            .stats
            .failed
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    eprintln!("COUNTERS: {:?}", rig.server.stats.traffic_counters(false));
    assert!(
        response.contains(MARKER),
        "the request went through the psiphon tunnel: {response}"
    );

    // The account's figures are visible while its session is open.
    let traffic = rig.server.stats.accounts.traffic(false);
    assert_eq!(traffic.len(), 1, "{traffic:?}");
    assert_eq!(traffic[0].email, "alice@panel");
    assert!(traffic[0].uplink > 0, "{traffic:?}");
    assert!(traffic[0].downlink > 0, "{traffic:?}");

    // The account is online.
    let online = rig.server.stats.accounts.online();
    assert_eq!(online.len(), 1, "{online:?}");
    assert_eq!(online[0].sessions, 1);

    // And the outbound's own counter moved: the traffic left through the
    // psiphon outbound, not somewhere else. The outbound's figure is written
    // when the session ends, so the session has to end first.
    drop(session);
    let mut counters = Vec::new();
    for _ in 0..250 {
        counters = rig.server.stats.traffic_counters(false);
        if counters
            .iter()
            .any(|(name, value)| name == "outbound>>>psiphon>>>traffic>>>downlink" && *value > 0)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        counters
            .iter()
            .any(|(name, value)| name == "outbound>>>psiphon>>>traffic>>>downlink" && *value > 0),
        "{counters:?}"
    );
    assert!(
        counters
            .iter()
            .any(|(name, value)| name == "user>>>alice@panel>>>traffic>>>downlink" && *value > 0),
        "{counters:?}"
    );
});

deep_stack_test!(an_accounts_limit_holds_its_psiphon_session_to_the_limit, {
    let rig = rig().await;

    // A limit of 32 KiB per second: the session may move that much and then
    // waits, which is what the limit means.
    rig.server
        .stats
        .accounts
        .set_limit("alice@panel", 32 * 1024, 32 * 1024);

    let mut session = open(&rig, "127.0.0.1", rig.origin_port).await;

    // The origin sends a body larger than the limit allows in a second, so
    // the transfer is held back: the limit slows the session down rather
    // than failing it.
    let started = std::time::Instant::now();
    let response = read_response(&mut session).await;
    let elapsed = started.elapsed();
    assert!(
        response.contains(MARKER),
        "{}",
        &response[..response.len().min(200)]
    );
    assert!(
        response.len() >= BODY,
        "the whole body arrived: {} bytes",
        response.len()
    );
    // 64 KiB at 32 KiB per second cannot arrive instantly.
    assert!(
        elapsed >= Duration::from_millis(500),
        "the limit held the transfer back: {elapsed:?}"
    );
});

deep_stack_test!(removing_the_account_ends_its_psiphon_session, {
    let rig = rig().await;

    let mut session = open(&rig, "127.0.0.1", rig.origin_port).await;
    let response = read_response(&mut session).await;
    assert!(response.contains(MARKER), "{response}");

    // The account goes away at run time; its session must end, and it must
    // end even though the session's bytes are inside a Psiphon tunnel.
    rig.server
        .remove_accounts("server", &["alice@panel"])
        .expect("the account is removed");

    let mut buffer = vec![0u8; 16];
    let ended = matches!(
        tokio::time::timeout(Duration::from_secs(10), session.read(&mut buffer)).await,
        Ok(Ok(0) | Err(_))
    );
    assert!(ended, "the session ended with its account");
});
