//! Configuration changes a reload cannot make, made without restarting the
//! process ([`zero_runtime::host`]): inbounds added, removed and re-bound,
//! with the figures carried on and a bad change rolled back.
//!
//! The rig: a [`Host`] with VLESS inbounds in front of an echo sink, and a
//! separate client server whose SOCKS5 inbound reaches one of them.

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zero_runtime::host::{Applied, Host};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn vless(tag: &str, port: u16, email: &str) -> Value {
    json!({
        "tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": {"clients": [{"id": UUID, "email": email}], "decryption": "none"},
    })
}

fn compile(config: &Value, generation: u64) -> Arc<zero_config::RuntimeConfig> {
    let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(generation))
        .unwrap_or_else(|error| panic!("rejected: {error}\n{config:#}"));
    generation.config
}

fn host_config(inbounds: Vec<Value>) -> Arc<zero_config::RuntimeConfig> {
    compile(
        &json!({"inbounds": inbounds, "outbounds": [{"tag": "direct", "protocol": "freedom"}]}),
        1,
    )
}

async fn echo_sink() -> u16 {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = sink.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

/// A client server whose SOCKS5 inbound goes to the VLESS inbound on
/// `server_port`; returns the SOCKS port.
async fn client_to(server_port: u16) -> u16 {
    let socks_port = free_port();
    let config = compile(
        &json!({
            "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}],
            "outbounds": [{"tag": "out", "protocol": "vless", "settings": {"vnext": [{
                "address": "127.0.0.1", "port": server_port,
                "users": [{"id": UUID, "encryption": "none"}],
            }]}}],
        }),
        1,
    );
    let client = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config,
        generation: zero_core::GenerationId(1),
    }));
    let running = Arc::clone(&client);
    tokio::spawn(async move { running.run().await });
    client.wait_until_listening().await;
    socks_port
}

/// A session to the sink through the SOCKS port, if it carries an echo.
async fn session(socks_port: u16, sink_port: u16) -> Option<TcpStream> {
    let attempt = async {
        let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.ok()?;
        stream.write_all(&[5, 1, 0]).await.ok()?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.ok()?;
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&sink_port.to_be_bytes());
        stream.write_all(&request).await.ok()?;
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.ok()?;
        stream.write_all(b"ping").await.ok()?;
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.ok()?;
        (&back == b"ping").then_some(stream)
    };
    tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .ok()
        .flatten()
}

async fn still_echoes(stream: &mut TcpStream) -> bool {
    if stream.write_all(b"pong").await.is_err() {
        return false;
    }
    let mut back = [0u8; 4];
    matches!(
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut back)).await,
        Ok(Ok(_))
    ) && &back == b"pong"
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_is_added_and_removed_without_a_restart() {
    let sink = echo_sink().await;
    let (port_a, port_b) = (free_port(), free_port());
    let host = Host::start(host_config(vec![vless("a", port_a, "alice@panel")]))
        .await
        .unwrap();
    let mut events = host.stats().events().subscribe();
    let via_a = client_to(port_a).await;
    let via_b = client_to(port_b).await;
    let mut open_on_a = session(via_a, sink).await.expect("inbound a serves");
    assert!(session(via_b, sink).await.is_none(), "b is not there yet");

    // Adding b needs a listener: a handover, not a reload.
    let applied = host
        .apply(host_config(vec![
            vless("a", port_a, "alice@panel"),
            vless("b", port_b, "bob@panel"),
        ]))
        .await
        .unwrap();
    assert_eq!(applied, Applied::Restarted);
    assert!(session(via_b, sink).await.is_some(), "b does not serve");
    assert!(session(via_a, sink).await.is_some(), "a no longer serves");
    assert!(
        still_echoes(&mut open_on_a).await,
        "the session open before the handover was cut"
    );
    // The figures went on across the handover.
    let traffic = host.stats().accounts.traffic(false);
    assert!(
        traffic
            .iter()
            .any(|t| t.email == "alice@panel" && t.uplink > 0),
        "{traffic:?}"
    );
    let changed = loop {
        let record = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("an inbounds_changed event")
            .unwrap();
        if let zero_runtime::events::Event::InboundsChanged { added, removed } = record.event {
            break (added, removed);
        }
    };
    assert_eq!(changed, (vec!["b".to_string()], vec![]));

    // Removing a: its listener closes and the account it held there is
    // ended; b goes on.
    let applied = host
        .apply(host_config(vec![vless("b", port_b, "bob@panel")]))
        .await
        .unwrap();
    assert_eq!(applied, Applied::Restarted);
    assert!(session(via_a, sink).await.is_none(), "a still serves");
    assert!(
        !still_echoes(&mut open_on_a).await,
        "a's account kept its session"
    );
    assert!(session(via_b, sink).await.is_some(), "b stopped serving");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_a_reload_can_make_is_a_reload() {
    let sink = echo_sink().await;
    let port = free_port();
    let host = Host::start(host_config(vec![vless("a", port, "alice@panel")]))
        .await
        .unwrap();
    let via = client_to(port).await;
    let mut open = session(via, sink).await.unwrap();
    let before = host.server();
    let applied = host
        .apply(host_config(vec![vless("a", port, "renamed@panel")]))
        .await
        .unwrap();
    assert_eq!(applied, Applied::Reloaded);
    assert!(
        Arc::ptr_eq(&before, &host.server()),
        "a reload replaced the server"
    );
    // The account the session was opened under is gone; the new one connects.
    assert!(!still_echoes(&mut open).await);
    assert!(session(via, sink).await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_that_cannot_start_is_rolled_back() {
    let sink = echo_sink().await;
    let port = free_port();
    let host = Host::start(host_config(vec![vless("a", port, "alice@panel")]))
        .await
        .unwrap();
    let via = client_to(port).await;
    // A port something else holds.
    let squatter = StdListener::bind("127.0.0.1:0").unwrap();
    let taken = squatter.local_addr().unwrap().port();
    let started = std::time::Instant::now();
    let refused = host
        .apply(host_config(vec![
            vless("a", port, "alice@panel"),
            vless("b", taken, "bob@panel"),
        ]))
        .await
        .unwrap_err();
    assert!(refused.contains("cannot listen"), "{refused}");
    // Found before anything closed: no wait, and no gap in service.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(
        session(via, sink).await.is_some(),
        "the previous configuration stopped serving"
    );
    drop(squatter);
}

/// A successor that fails after the old listeners closed (here a VLESS
/// Encryption key the parser lets through and the server cannot use) puts the
/// previous configuration back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_successor_that_fails_to_start_is_rolled_back() {
    let sink = echo_sink().await;
    let port = free_port();
    let host = Host::start(host_config(vec![vless("a", port, "alice@panel")]))
        .await
        .unwrap();
    let via = client_to(port).await;
    let broken = json!({
        "tag": "enc", "listen": "127.0.0.1", "port": free_port(), "protocol": "vless",
        "settings": {"clients": [{"id": UUID}], "decryption": "mlkem768x25519plus.native.600s.AAAA"},
    });
    let refused = host
        .apply(host_config(vec![vless("a", port, "alice@panel"), broken]))
        .await
        .unwrap_err();
    assert!(refused.contains("could not start"), "{refused}");
    assert!(
        session(via, sink).await.is_some(),
        "the previous configuration was not put back"
    );
}

/// `POST /reload` on a host adds an inbound and says it restarted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_management_api_reload_can_add_an_inbound() {
    let sink = echo_sink().await;
    let (port_a, port_b, api_port) = (free_port(), free_port(), free_port());
    let host = Arc::new(
        Host::start(host_config(vec![vless("a", port_a, "alice@panel")]))
            .await
            .unwrap(),
    );
    let api = zero_runtime::api::ManagementServer::new(zero_runtime::api::ManagementConfig {
        listen: format!("127.0.0.1:{api_port}").parse().unwrap(),
        bearer_token: None,
    })
    .unwrap();
    tokio::spawn(api.run_host(Arc::clone(&host)));
    let via_b = client_to(port_b).await;

    let body = json!({
        "inbounds": [vless("a", port_a, "alice@panel"), vless("b", port_b, "bob@panel")],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    })
    .to_string();
    let reply = loop {
        // The API listener may not be bound yet.
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", api_port)).await {
            let request = format!(
                "POST /reload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            break reply;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(reply.contains("\"applied\":\"restarted\""), "{reply}");
    assert!(
        session(via_b, sink).await.is_some(),
        "the added inbound does not serve"
    );
}
