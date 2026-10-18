//! The WireGuard inbound, from the outside: a real WireGuard peer (this
//! project's own client) connects to it, and TCP and UDP carried through the
//! tunnel come out of the server's routing and reach their destinations.
//!
//! The handshake, the keys, and which peer may use which addresses are all
//! exercised: a peer that is not in the list, or that uses an address it was
//! not given, gets nothing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use zero_protocol::wg_stack::{WgStack, WgStackParams};

fn key_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = x25519_dalek::StaticSecret::from([seed; 32]);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let mut reply = b"tcp:".to_vec();
                reply.extend_from_slice(&buffer[..read]);
                let _ = stream.write_all(&reply).await;
            });
        }
    });
    address
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            let mut reply = b"udp:".to_vec();
            reply.extend_from_slice(&buffer[..read]);
            let _ = socket.send_to(&reply, from).await;
        }
    });
    address
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_server(
    port: u16,
    secret: [u8; 32],
    peers: serde_json::Value,
) -> Arc<zero_runtime::Server> {
    let config = json!({
        "inbounds": [{"tag": "wg", "protocol": "wireguard", "listen": "127.0.0.1", "port": port,
            "settings": {"secretKey": b64(&secret), "peers": peers}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;
    server
}

fn client(port: u16, secret: [u8; 32], server_public: [u8; 32], address: &str) -> WgStack {
    WgStack::start(
        format!("127.0.0.1:{port}").parse().unwrap(),
        WgStackParams {
            private_key: secret,
            peer_public_key: server_public,
            preshared_key: None,
            addresses: vec![address.parse().unwrap()],
            persistent_keepalive: Some(5),
            obfuscation: Default::default(),
            reserved: [0; 3],
            dns: "127.0.0.1:53".parse().unwrap(),
        },
    )
    .expect("client")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_reaches_tcp_and_udp_through_the_inbound() {
    let (server_secret, server_public) = key_pair(1);
    let (client_secret, client_public) = key_pair(2);
    let port = free_udp_port();
    let server = start_server(
        port,
        server_secret,
        json!([{"publicKey": b64(&client_public), "allowedIPs": ["10.7.0.2/32"], "email": "wg@panel"}]),
    )
    .await;
    let (tcp, udp) = (tcp_echo().await, udp_echo().await);
    let peer = client(port, client_secret, server_public, "10.7.0.2");

    let mut stream = tokio::time::timeout(Duration::from_secs(15), peer.connect(tcp))
        .await
        .expect("connect timed out")
        .expect("connect");
    stream.write_all(b"hello").await.unwrap();
    let mut answer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut answer))
        .await
        .expect("no tcp answer")
        .unwrap();
    assert_eq!(&answer[..read], b"tcp:hello");

    let (from, reply) = peer.exchange_udp(udp, b"ping").await.expect("udp");
    assert_eq!(from, udp);
    assert_eq!(reply, b"udp:ping");

    // The peer's packets, both ways, counted under its email.
    let traffic = server.stats.accounts.traffic(false);
    assert_eq!(traffic.len(), 1, "{traffic:?}");
    assert_eq!(traffic[0].email, "wg@panel");
    assert!(
        traffic[0].uplink > 9 && traffic[0].downlink > 13,
        "{traffic:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_the_server_does_not_know_gets_nothing() {
    let (server_secret, server_public) = key_pair(1);
    let (_, known_public) = key_pair(2);
    let (stranger_secret, _) = key_pair(9);
    let port = free_udp_port();
    start_server(
        port,
        server_secret,
        json!([{"publicKey": b64(&known_public)}]),
    )
    .await;
    let tcp = tcp_echo().await;
    let stranger = client(port, stranger_secret, server_public, "10.7.0.9");
    let attempt = tokio::time::timeout(Duration::from_secs(6), stranger.connect(tcp)).await;
    assert!(
        !matches!(attempt, Ok(Ok(_))),
        "an unknown key must not get a tunnel"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_cannot_use_an_address_it_was_not_given() {
    let (server_secret, server_public) = key_pair(1);
    let (client_secret, client_public) = key_pair(2);
    let port = free_udp_port();
    start_server(
        port,
        server_secret,
        json!([{"publicKey": b64(&client_public), "allowedIPs": ["10.7.0.2/32"]}]),
    )
    .await;
    let tcp = tcp_echo().await;
    // The peer is configured to send from an address outside its allowed list.
    let peer = client(port, client_secret, server_public, "10.7.0.77");
    let attempt = tokio::time::timeout(Duration::from_secs(6), peer.connect(tcp)).await;
    assert!(
        !matches!(attempt, Ok(Ok(_))),
        "packets from outside allowedIPs must be dropped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_come_and_go_while_the_inbound_runs() {
    let (server_secret, server_public) = key_pair(1);
    let (client_secret, client_public) = key_pair(2);
    let (_, other_public) = key_pair(3);
    let port = free_udp_port();
    // A panel's inbound starts with no peers and gets them as users come.
    let server = start_server(port, server_secret, json!([])).await;
    server.stats.accounts.set_track_addresses(true);
    let tcp = tcp_echo().await;
    let add = |public: [u8; 32], address: &str, email: &str| {
        let peer = json!({"publicKey": b64(&public), "allowedIPs": [address], "email": email});
        let account = server.parse_account("wg", &peer).expect("a peer account");
        server.add_accounts("wg", &[account]).expect("added");
    };
    add(other_public, "10.7.0.3/32", "other@panel");
    add(client_public, "10.7.0.2/32", "wg@panel");

    let peer = client(port, client_secret, server_public, "10.7.0.2");
    let mut stream = tokio::time::timeout(Duration::from_secs(15), peer.connect(tcp))
        .await
        .expect("connect timed out")
        .expect("an added peer connects");
    stream.write_all(b"hello").await.unwrap();
    let mut answer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut answer))
        .await
        .expect("no tcp answer")
        .unwrap();
    assert_eq!(&answer[..read], b"tcp:hello");
    let online = server.stats.accounts.online();
    assert_eq!(online.len(), 1, "{online:?}");
    assert_eq!(online[0].email, "wg@panel");
    assert_eq!(
        online[0].addresses,
        vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );

    // Removing another peer leaves this one's tunnel alone.
    assert_eq!(server.remove_accounts("wg", &["other@panel"]).unwrap(), 1);
    let again = tokio::time::timeout(Duration::from_secs(10), peer.connect(tcp)).await;
    assert!(
        matches!(again, Ok(Ok(_))),
        "the tunnel survived another peer's removal"
    );

    // Removed, it is cut off and offline.
    assert_eq!(server.remove_accounts("wg", &["wg@panel"]).unwrap(), 1);
    assert!(server.stats.accounts.online().is_empty());
    let after = tokio::time::timeout(Duration::from_secs(6), peer.connect(tcp)).await;
    assert!(
        !matches!(after, Ok(Ok(_))),
        "a removed peer must not get through"
    );
}
