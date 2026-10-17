//! Per-account metering on the inbounds that need a certificate: Hysteria2
//! and TUIC (over QUIC) and AnyTLS ([`zero_runtime::accounts`]).
//!
//! The rig is two servers in one process, as in `loopback_tls_interop.rs`: a
//! relay with the inbound under test, holding two accounts, and a client that
//! reaches it through a SOCKS5 inbound with alice's credentials. QUIC is the
//! interesting case: an account logs in once per *connection*, and the client
//! keeps that connection for later streams, so removing an account must also
//! stop the streams it opens afterwards on a connection that is already up.

use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const DECOY_UUID: &str = "0f3c2a10-8b5e-4d7a-9c21-6e4b8f0a1d33";
const PASSWORD: &str = "alice-shared-password";
const SERVER_NAME: &str = "zray.test";

const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA_CERTIFICATE: &str = include_str!("fixtures/loopback-ca.pem");

fn free_port(udp: bool) -> u16 {
    if udp {
        StdUdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        StdTcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

/// The relay's settings with alice and a decoy, and the client's settings
/// that log in as alice.
fn settings(protocol: &str, port: u16) -> (Value, Value) {
    match protocol {
        "hysteria2" | "anytls" => (
            json!({"users": [
                {"password": "decoy-password", "email": "decoy@panel"},
                {"password": PASSWORD, "email": "alice@panel"},
            ]}),
            json!({"servers": [{"address": SERVER_NAME, "port": port, "password": PASSWORD}]}),
        ),
        "tuic" => (
            json!({"users": [
                {"uuid": DECOY_UUID, "password": "decoy-password", "email": "decoy@panel"},
                {"uuid": UUID, "password": PASSWORD, "email": "alice@panel"},
            ]}),
            json!({"servers": [{
                "address": SERVER_NAME, "port": port, "uuid": UUID, "password": PASSWORD,
            }]}),
        ),
        other => panic!("no rig for {other}"),
    }
}

async fn spawn(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .expect("listeners bound");
    server
}

struct Rig {
    relay: Arc<zero_runtime::Server>,
    socks: SocketAddr,
    echo: SocketAddr,
    protocol: &'static str,
}

async fn rig(protocol: &'static str) -> Rig {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let relay_port = free_port(protocol != "anytls");
    let socks_port = free_port(false);
    let (server_settings, client_settings) = settings(protocol, relay_port);
    let relay = spawn(json!({
        "inbounds": [{
            "tag": "relay-in", "listen": "127.0.0.1", "port": relay_port,
            "protocol": protocol, "settings": server_settings,
            "streamSettings": {"security": "tls", "tlsSettings": {
                "certificates": [{"certificate": [CERTIFICATE], "key": [PRIVATE_KEY]}],
            }},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;
    // The client runs as long as the test: its own task holds it.
    let _client = spawn(json!({
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
        }],
        "outbounds": [{
            "tag": "proxy", "protocol": protocol, "settings": client_settings,
            "streamSettings": {"security": "tls", "tlsSettings": {
                "serverName": SERVER_NAME,
                "certificates": [{"usage": "verify", "certificate": [CA_CERTIFICATE]}],
            }},
        }],
        "dns": {"hosts": {SERVER_NAME: ["127.0.0.1"]}},
    }))
    .await;
    Rig {
        relay,
        socks: SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
        protocol,
    }
}

impl Rig {
    /// A session to the echo service through the client's SOCKS5 inbound,
    /// or `None` when it does not carry an echo.
    async fn session(&self) -> Option<TcpStream> {
        let attempt = async {
            let mut stream = TcpStream::connect(self.socks).await.ok()?;
            stream.write_all(&[5, 1, 0]).await.ok()?;
            let mut method = [0u8; 2];
            stream.read_exact(&mut method).await.ok()?;
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&self.echo.port().to_be_bytes());
            stream.write_all(&request).await.ok()?;
            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await.ok()?;
            (reply[1] == 0).then_some(())?;
            stream.write_all(b"ping").await.ok()?;
            let mut back = [0u8; 4];
            stream.read_exact(&mut back).await.ok()?;
            (&back == b"ping").then_some(stream)
        };
        tokio::time::timeout(Duration::from_secs(5), attempt)
            .await
            .ok()
            .flatten()
    }

    fn alice(&self) -> zero_config::InboundClient {
        let client = match self.protocol {
            "tuic" => json!({"uuid": UUID, "password": PASSWORD, "email": "alice@panel"}),
            _ => json!({"password": PASSWORD, "email": "alice@panel"}),
        };
        self.relay.parse_account("relay-in", &client).unwrap()
    }
}

async fn ended(session: &mut TcpStream) -> bool {
    let _ = session.write_all(b"anyone?").await;
    let mut buf = [0u8; 16];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), session.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn the_account_is_metered_and_can_be_removed_and_restored(protocol: &'static str) {
    let rig = rig(protocol).await;
    let mut session = rig.session().await.expect("alice connects");
    let payload = vec![0x42u8; 128 * 1024];
    session.write_all(&payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    session.read_exact(&mut back).await.unwrap();

    // Counted under alice while the session is open; the decoy has nothing.
    let traffic = rig.relay.stats.accounts.traffic(false);
    assert_eq!(traffic.len(), 1, "{protocol}: {traffic:?}");
    assert_eq!(traffic[0].email, "alice@panel");
    assert!(
        traffic[0].uplink >= payload.len() as u64,
        "{protocol}: {traffic:?}"
    );
    assert!(
        traffic[0].downlink >= payload.len() as u64,
        "{protocol}: {traffic:?}"
    );
    assert_eq!(rig.relay.stats.accounts.online()[0].email, "alice@panel");

    // Removed: the open session ends, and a new one is refused even though
    // the client may still hold the QUIC connection alice logged in on.
    let removed = rig
        .relay
        .remove_accounts("relay-in", &["alice@panel"])
        .unwrap();
    assert_eq!(removed, 1);
    assert!(
        ended(&mut session).await,
        "{protocol}: the session survived"
    );
    assert!(
        rig.session().await.is_none(),
        "{protocol}: a removed account opened a new stream"
    );

    // Restored at run time: the next session works.
    rig.relay.add_accounts("relay-in", &[rig.alice()]).unwrap();
    let mut restored = None;
    for _ in 0..3 {
        // A QUIC client may need one failed attempt to notice its pooled
        // connection was refused and open a fresh one.
        restored = rig.session().await;
        if restored.is_some() {
            break;
        }
    }
    assert!(
        restored.is_some(),
        "{protocol}: the restored account is refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_accounts_are_metered_removed_and_restored() {
    the_account_is_metered_and_can_be_removed_and_restored("hysteria2").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tuic_accounts_are_metered_removed_and_restored() {
    the_account_is_metered_and_can_be_removed_and_restored("tuic").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anytls_accounts_are_metered_removed_and_restored() {
    the_account_is_metered_and_can_be_removed_and_restored("anytls").await;
}
