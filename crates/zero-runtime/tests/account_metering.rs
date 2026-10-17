//! Per-account metering on a real server inbound ([`zero_runtime::accounts`]).
//!
//! The rig is one process with two halves: a SOCKS5 inbound whose only route
//! is a proxy outbound, and the matching server inbound, whose account has an
//! `email`, in front of an echo sink. What is checked is what a panel relies
//! on: the account's bytes are visible while its session is still open, the
//! session is listed as online, and a reload that drops the account ends the
//! session it already had.

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";
const OTHER_UUID: &str = "0f3c2a10-8b5e-4d7a-9c21-6e4b8f0a1d33";
const PASSWORD: &str = "a-trojan-password";
/// Shadowsocks 2022 keys (16 bytes, base64): the server's, alice's, another's.
const SS_SERVER_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
const SS_ALICE_KEY: &str = "YWxpY2UtYWxpY2UtYWxpYw==";
const SS_OTHER_KEY: &str = "Ym9iLWJvYi1ib2ItYm9iLQ==";

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The server inbound and the outbound that reaches it, for `protocol`, with
/// the account named `email` (or, with `None`, an unrelated account only).
fn server_pair(protocol: &str, port: u16, email: Option<&str>) -> (Value, Value) {
    let email = email.unwrap_or("someone-else");
    let (id, password) = if email == "someone-else" {
        (OTHER_UUID, "another-password")
    } else {
        (UUID, PASSWORD)
    };
    match protocol {
        "vless" => (
            json!({
                "tag": "server", "listen": "127.0.0.1", "port": port, "protocol": "vless",
                "settings": {"clients": [{"id": id, "email": email}], "decryption": "none"},
            }),
            json!({
                "tag": "to-server", "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": port,
                    "users": [{"id": UUID, "encryption": "none"}],
                }]},
            }),
        ),
        "vmess" => (
            json!({
                "tag": "server", "listen": "127.0.0.1", "port": port, "protocol": "vmess",
                "settings": {"clients": [{"id": id, "email": email}]},
            }),
            json!({
                "tag": "to-server", "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": port,
                    "users": [{"id": UUID, "security": "aes-128-gcm"}],
                }]},
            }),
        ),
        "trojan" => (
            json!({
                "tag": "server", "listen": "127.0.0.1", "port": port, "protocol": "trojan",
                "settings": {"clients": [{"password": password, "email": email}]},
            }),
            json!({
                "tag": "to-server", "protocol": "trojan",
                "settings": {"servers": [{
                    "address": "127.0.0.1", "port": port, "password": PASSWORD,
                }]},
            }),
        ),
        "shadowsocks" => (
            json!({
                "tag": "server", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
                "settings": {"method": "chacha20-ietf-poly1305", "clients": [
                    {"password": "a-decoy-password", "email": "decoy@panel"},
                    {"password": password, "email": email},
                ]},
            }),
            json!({
                "tag": "to-server", "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "127.0.0.1", "port": port,
                    "method": "chacha20-ietf-poly1305", "password": PASSWORD,
                }]},
            }),
        ),
        "ss2022" => (
            json!({
                "tag": "server", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
                "settings": {"method": "2022-blake3-aes-128-gcm", "password": SS_SERVER_KEY, "clients": [
                    {"password": if email == "someone-else" { SS_OTHER_KEY } else { SS_ALICE_KEY }, "email": email},
                ]},
            }),
            json!({
                "tag": "to-server", "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "127.0.0.1", "port": port,
                    "method": "2022-blake3-aes-128-gcm",
                    "password": format!("{SS_SERVER_KEY}:{SS_ALICE_KEY}"),
                }]},
            }),
        ),
        other => panic!("no rig for {other}"),
    }
}

fn config(protocol: &str, socks_port: u16, server_port: u16, email: Option<&str>) -> Value {
    let (inbound, outbound) = server_pair(protocol, server_port, email);
    json!({
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"},
            inbound,
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, outbound],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["socks"], "outboundTag": "to-server"},
        ]},
    })
}

struct Rig {
    server: Arc<zero_runtime::Server>,
    protocol: &'static str,
    socks_port: u16,
    server_port: u16,
    sink_port: u16,
}

async fn rig(protocol: &'static str) -> Rig {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = sink.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let (socks_port, server_port) = (free_port(), free_port());
    let config = config(protocol, socks_port, server_port, Some("alice@panel"));
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
        protocol,
        socks_port,
        server_port,
        sink_port,
    }
}

impl Rig {
    /// A session to the echo sink through the SOCKS5 inbound.
    async fn open(&self) -> TcpStream {
        let mut stream = TcpStream::connect(("127.0.0.1", self.socks_port))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&self.sink_port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
            .await
            .expect("SOCKS reply in time")
            .expect("SOCKS reply");
        assert_eq!(reply[1], 0, "SOCKS request refused");
        stream
    }

    fn reload_without_alice(&self) {
        let config = config(self.protocol, self.socks_port, self.server_port, None);
        let (generation, _) =
            zero_config::compile_config(&config, zero_core::GenerationId(2)).unwrap();
        self.server
            .reload(Arc::clone(&generation.config), generation.id)
            .expect("a reload that keeps the listeners");
    }
}

/// Whether a fresh session through the rig carries an echo.
async fn reaches_the_sink(rig: &Rig) -> bool {
    let attempt = async {
        let mut stream = TcpStream::connect(("127.0.0.1", rig.socks_port))
            .await
            .ok()?;
        stream.write_all(&[5, 1, 0]).await.ok()?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.ok()?;
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&rig.sink_port.to_be_bytes());
        stream.write_all(&request).await.ok()?;
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.ok()?;
        stream.write_all(b"ping").await.ok()?;
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.ok()?;
        Some(&back == b"ping")
    };
    tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// The account the rig's outbound authenticates as.
fn alice(rig: &Rig) -> zero_config::InboundClient {
    let client = match rig.protocol {
        "trojan" | "shadowsocks" => json!({"password": PASSWORD, "email": "alice@panel"}),
        "ss2022" => json!({"password": SS_ALICE_KEY, "email": "alice@panel"}),
        _ => json!({"id": UUID, "email": "alice@panel"}),
    };
    rig.server.parse_account("server", &client).unwrap()
}

async fn ended(session: &mut TcpStream) -> bool {
    let _ = session.write_all(b"anyone?").await;
    let mut buf = [0u8; 16];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), session.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn echo(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("echo in time")
        .expect("echo");
    assert_eq!(back, payload);
}

async fn bytes_are_visible_before_the_session_closes(protocol: &'static str) {
    let rig = rig(protocol).await;
    rig.server.stats.accounts.set_track_addresses(true);
    let mut session = rig.open().await;
    let payload = vec![0x5a; 256 * 1024];
    echo(&mut session, &payload).await;

    let traffic = rig.server.stats.accounts.traffic(false);
    assert_eq!(traffic.len(), 1, "{protocol}: {traffic:?}");
    assert_eq!(traffic[0].email, "alice@panel");
    // The request header and the protocol's framing ride on top of the
    // payload, so the figures are at least the payload, not exactly it.
    assert!(
        traffic[0].uplink >= payload.len() as u64,
        "{protocol}: {traffic:?}"
    );
    assert!(
        traffic[0].downlink >= payload.len() as u64,
        "{protocol}: {traffic:?}"
    );

    let online = rig.server.stats.accounts.online();
    assert_eq!(online.len(), 1, "{protocol}: {online:?}");
    assert_eq!(online[0].sessions, 1);
    assert_eq!(
        online[0].addresses,
        vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );

    let counters = rig.server.stats.traffic_counters(false);
    assert!(
        counters
            .iter()
            .any(|(name, value)| name == "user>>>alice@panel>>>traffic>>>downlink" && *value > 0),
        "{protocol}: {counters:?}"
    );
    drop(session);
}

async fn a_reload_that_drops_the_account_ends_its_session(protocol: &'static str) {
    let rig = rig(protocol).await;
    let mut session = rig.open().await;
    echo(&mut session, b"still here").await;

    rig.reload_without_alice();

    // The ended session closes; a write may still be buffered, but the read
    // must see the end rather than hang.
    let _ = session.write_all(b"anyone?").await;
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), session.read(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{protocol}: the dropped account's session stayed open"));
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "{protocol}: the session still carried data: {read:?}"
    );
    assert!(rig.server.stats.accounts.online().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_bytes_are_visible_before_the_session_closes() {
    bytes_are_visible_before_the_session_closes("vless").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_bytes_are_visible_before_the_session_closes() {
    bytes_are_visible_before_the_session_closes("vmess").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_bytes_are_visible_before_the_session_closes() {
    bytes_are_visible_before_the_session_closes("trojan").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_reload_that_drops_the_account_ends_its_session() {
    a_reload_that_drops_the_account_ends_its_session("vless").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_reload_that_drops_the_account_ends_its_session() {
    a_reload_that_drops_the_account_ends_its_session("vmess").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_reload_that_drops_the_account_ends_its_session() {
    a_reload_that_drops_the_account_ends_its_session("trojan").await;
}

async fn accounts_come_and_go_without_a_reload(protocol: &'static str) {
    let rig = rig(protocol).await;
    let generation = rig.server.current_generation();
    let mut session = rig.open().await;
    echo(&mut session, b"before").await;

    // Removing the account ends what it had open and refuses what comes next.
    let removed = rig
        .server
        .remove_accounts("server", &["alice@panel"])
        .unwrap();
    assert_eq!(removed, 1);
    assert!(
        ended(&mut session).await,
        "{protocol}: removed account kept its session"
    );
    assert!(
        !reaches_the_sink(&rig).await,
        "{protocol}: removed account still connects"
    );

    // Adding it back works for the next session, still without a reload.
    rig.server.add_accounts("server", &[alice(&rig)]).unwrap();
    assert!(
        reaches_the_sink(&rig).await,
        "{protocol}: re-added account refused"
    );
    assert_eq!(rig.server.current_generation(), generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_accounts_come_and_go_without_a_reload() {
    accounts_come_and_go_without_a_reload("vless").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_accounts_come_and_go_without_a_reload() {
    accounts_come_and_go_without_a_reload("vmess").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_accounts_come_and_go_without_a_reload() {
    accounts_come_and_go_without_a_reload("trojan").await;
}

/// Re-adding an account unchanged (a panel re-syncing) leaves its session
/// alone; changing its credential ends the session opened with the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_changed_credential_ends_the_session() {
    let rig = rig("vless").await;
    let mut session = rig.open().await;
    echo(&mut session, b"one").await;

    rig.server.add_accounts("server", &[alice(&rig)]).unwrap();
    echo(&mut session, b"still open").await;

    let new_id = zero_config::parse_inbound_client(
        "vless",
        &json!({"id": OTHER_UUID, "email": "alice@panel"}),
    )
    .unwrap();
    rig.server.add_accounts("server", &[new_id]).unwrap();
    assert!(
        ended(&mut session).await,
        "the old credential's session survived"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_credential_cannot_belong_to_two_accounts() {
    let rig = rig("vless").await;
    let twin =
        zero_config::parse_inbound_client("vless", &json!({"id": UUID, "email": "mallory@panel"}))
            .unwrap();
    let refused = rig.server.add_accounts("server", &[twin]).unwrap_err();
    assert!(refused.contains("already used"), "{refused}");
    let wrong = zero_config::parse_inbound_client(
        "trojan",
        &json!({"password": "x", "email": "bob@panel"}),
    )
    .unwrap();
    assert!(rig.server.add_accounts("server", &[wrong]).is_err());
    assert!(rig.server.add_accounts("nowhere", &[alice(&rig)]).is_err());
    assert!(rig
        .server
        .remove_accounts("socks", &["alice@panel"])
        .is_err());
    assert!(
        reaches_the_sink(&rig).await,
        "a refused change still changed something"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_bytes_are_visible_before_the_session_closes() {
    bytes_are_visible_before_the_session_closes("shadowsocks").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_bytes_are_visible_before_the_session_closes() {
    bytes_are_visible_before_the_session_closes("ss2022").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_reload_that_drops_the_account_ends_its_session() {
    a_reload_that_drops_the_account_ends_its_session("shadowsocks").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_reload_that_drops_the_account_ends_its_session() {
    a_reload_that_drops_the_account_ends_its_session("ss2022").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_accounts_come_and_go_without_a_reload() {
    accounts_come_and_go_without_a_reload("shadowsocks").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_accounts_come_and_go_without_a_reload() {
    accounts_come_and_go_without_a_reload("ss2022").await;
}

/// A multi-user inbound whose last account is removed admits nobody: in
/// Shadowsocks 2022 every user holds the server key, and that key alone must
/// not then get in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_emptied_multi_user_inbound_admits_nobody() {
    for protocol in ["ss2022", "shadowsocks"] {
        let rig = rig(protocol).await;
        rig.server
            .remove_accounts("server", &["alice@panel", "decoy@panel"])
            .unwrap();
        assert!(
            !reaches_the_sink(&rig).await,
            "{protocol}: alice still connects"
        );
    }
    // The server key, which every 2022 user's `serverKey:userKey` holds, is
    // refused on its own once there is no account, also after a reload that
    // lists none.
    let rig = rig("ss2022").await;
    let mut config = config(
        "ss2022",
        rig.socks_port,
        rig.server_port,
        Some("alice@panel"),
    );
    config["outbounds"][1]["settings"]["servers"][0]["password"] = json!(SS_SERVER_KEY);
    config["inbounds"][1]["settings"]["clients"] = json!([]);
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(2)).unwrap();
    rig.server
        .reload(Arc::clone(&generation.config), generation.id)
        .unwrap();
    assert!(
        !reaches_the_sink(&rig).await,
        "an emptied 2022 inbound let in the server key alone"
    );
}

/// Live events name the account's sessions and a refused handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_and_refusals_are_reported_as_events() {
    use zero_runtime::events::Event;
    let rig = rig("vless").await;
    let mut events = rig.server.stats.events().subscribe();
    let mut session = rig.open().await;
    echo(&mut session, b"evented").await;
    drop(session);
    rig.server
        .remove_accounts("server", &["alice@panel"])
        .unwrap();
    assert!(!reaches_the_sink(&rig).await);

    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let complete = |seen: &[Event]| {
        seen.iter()
            .any(|e| matches!(e, Event::SessionClosed { .. }))
            && seen
                .iter()
                .any(|e| matches!(e, Event::SessionFailed { .. }))
    };
    while !complete(&seen) {
        let next = tokio::time::timeout_at(deadline, events.recv())
            .await
            .unwrap_or_else(|_| panic!("events so far: {seen:?}"))
            .unwrap();
        seen.push(next.event);
    }
    assert!(seen.iter().any(|e| matches!(e, Event::SessionOpened { email, inbound, .. } if email == "alice@panel" && inbound == "server")), "{seen:?}");
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::SessionClosed { uplink, .. } if *uplink >= 7)),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::AccountsRemoved { .. })),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::SessionFailed { inbound, .. } if inbound == "server")),
        "{seen:?}"
    );
}

/// A speed limit holds a real session to its rate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_speed_limit_slows_a_real_session() {
    let rig = rig("vless").await;
    rig.server
        .stats
        .accounts
        .set_limit("alice@panel", 0, 100_000);
    let mut session = rig.open().await;
    let started = std::time::Instant::now();
    echo(&mut session, &vec![3u8; 250_000]).await;
    let elapsed = started.elapsed();
    // 250 KB at 100 KB/s with a second of burst: at least about 1.5 s.
    assert!(elapsed >= Duration::from_millis(1200), "{elapsed:?}");
}
