//! Interop against a real Psiphon server.
//!
//! `psiphon-tunnel-core`'s server binary, run locally, is the compatibility
//! oracle: it implements the Psiphon side of the credential payload, the host
//! key pinning and the channel forwarding, so a Rust client that completes
//! this test speaks the real protocol and not merely its own reflection.
//!
//! Ignored by default, like the repository's other external-oracle tests: it
//! needs the harness in `.research/psiphon-server-harness`.
//!
//! Run with:
//!
//! ```text
//! ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry.json \
//! ZERO_PSIPHON_TARGET=127.0.0.1:20085 \
//!   cargo test -p zero-psiphon --features test-util --test real_server -- --ignored --nocapture
//! ```

use std::time::Duration;

use zero_psiphon::client::Client;
use zero_psiphon::config::ClientConfig;
use zero_psiphon::obfuscator::OsshClient;
use zero_psiphon::protocol::TunnelProtocol;
use zero_psiphon::server_entry::ServerEntry;
use zero_psiphon::tls_ossh::TlsOsshOptions;
use zero_psiphon::tunnel::{HandshakeParams, SshTunnel, TunnelOptions};

fn server_entry() -> Option<ServerEntry> {
    let path = std::env::var("ZERO_PSIPHON_SERVER_ENTRY").ok()?;
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("reading {path}: {error}"));
    Some(ServerEntry::from_json(&text).expect("the server entry parses"))
}

fn target() -> (String, u16) {
    let value = std::env::var("ZERO_PSIPHON_TARGET").unwrap_or_else(|_| "127.0.0.1:20085".into());
    let (host, port) = value.rsplit_once(':').expect("host:port");
    (host.to_string(), port.parse().expect("a port"))
}

/// Establish a tunnel over `protocol`, fetch the marker through it, and
/// return the response body.
async fn tunnel_fetch(entry: &ServerEntry, protocol: TunnelProtocol) -> String {
    let port = entry
        .port_for(protocol)
        .unwrap_or_else(|_| panic!("the server entry has no {protocol} port"));

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the harness server is listening");
    let options = TunnelOptions::default();

    // Each transport is a carrier under the same SSH session.
    let tunnel = match protocol {
        TunnelProtocol::Ssh => {
            SshTunnel::establish(stream, entry, &options, Duration::from_secs(10)).await
        }
        TunnelProtocol::Ossh => {
            let carrier = OsshClient::new(stream, entry.ssh_obfuscated_key().as_bytes());
            SshTunnel::establish(carrier, entry, &options, Duration::from_secs(10)).await
        }
        TunnelProtocol::TlsOssh => {
            // TLS first, then the same OSSH layer: the server's TLS port
            // carries exactly what its plain OSSH port does.
            let carrier = zero_psiphon::tls_ossh::wrap(
                stream,
                entry.ssh_obfuscated_key(),
                &TlsOsshOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{protocol}: the TLS session came up: {error}"));
            SshTunnel::establish(carrier, entry, &options, Duration::from_secs(10)).await
        }
        other => panic!("unsupported protocol in this test: {other}"),
    }
    .unwrap_or_else(|error| panic!("{protocol}: the real server rejected the tunnel: {error}"));

    // The server refuses port forwards until the Psiphon handshake has
    // completed; this is the same SSH global request the Go client sends.
    let response = tunnel
        .handshake(&HandshakeParams::new(protocol))
        .await
        .unwrap_or_else(|error| panic!("{protocol}: tunnel handshake: {error}"));
    assert!(
        response.is_empty() || response.starts_with(b"{"),
        "the handshake response is JSON or empty, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    let (host, port) = target();
    let mut stream = tunnel
        .open(&host, port)
        .await
        .unwrap_or_else(|error| panic!("{protocol}: opening a channel: {error}"));

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(
            format!("GET /marker.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("writing through the tunnel");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("reading through the tunnel");
    tunnel.close().await;

    let text = String::from_utf8_lossy(&response).into_owned();
    assert!(
        text.starts_with("HTTP/1."),
        "{protocol}: expected an HTTP response through the tunnel, got: {text}"
    );
    assert!(
        text.contains("psiphon-harness-marker"),
        "{protocol}: expected the test origin's body, got: {text}"
    );
    text
}

/// Plain SSH: the simplest Psiphon transport, and the one every other
/// transport ends in.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness"]
async fn plain_ssh_against_the_real_server_carries_a_request() {
    let Some(entry) = server_entry() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };
    tunnel_fetch(&entry, TunnelProtocol::Ssh).await;
}

/// OSSH: the same SSH session under Psiphon's obfuscation layer.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness"]
async fn obfuscated_ssh_against_the_real_server_carries_a_request() {
    let Some(entry) = server_entry() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };
    tunnel_fetch(&entry, TunnelProtocol::Ossh).await;
}

/// TLS-OSSH: the obfuscated SSH session inside a TLS session, which is what
/// makes the connection look like an HTTPS connection to a server whose
/// certificate nobody can verify.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness"]
async fn tls_obfuscated_ssh_against_the_real_server_carries_a_request() {
    let Some(entry) = server_entry() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };
    tunnel_fetch(&entry, TunnelProtocol::TlsOssh).await;
}

/// The whole client, not one carrier: server selection, the dial loop, the
/// credential payload, the handshake, and a stream to a destination.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness"]
async fn the_dial_loop_carries_a_request_end_to_end() {
    let Some(entry) = server_entry() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };

    // Every transport the entry offers, one after another, so a regression in
    // any of them shows up here rather than only in its own test.
    for protocol in [
        TunnelProtocol::Ssh,
        TunnelProtocol::Ossh,
        TunnelProtocol::TlsOssh,
    ] {
        let config = ClientConfig {
            server_entries: vec![entry.clone()],
            protocols: vec![protocol],
            establish_timeout: Duration::from_secs(15),
            ..Default::default()
        };
        let client = Client::connect(config)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: connecting: {error}"));
        assert_eq!(client.protocol().await, Some(protocol));

        let (host, port) = target();
        let mut stream = client
            .dial(&host, port)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: dialing {host}:{port}: {error}"));

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(
                format!("GET /marker.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap_or_else(|error| panic!("{protocol}: writing: {error}"));
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: reading: {error}"));

        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains("psiphon-harness-marker"),
            "{protocol}: expected the origin's body, got: {text}"
        );
        client.close().await;
    }
}
