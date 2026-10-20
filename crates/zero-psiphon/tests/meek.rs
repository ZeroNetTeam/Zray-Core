//! Interop against a real Psiphon server over the meek transport.
//!
//! Meek carries a byte stream inside HTTP request and response bodies, and
//! Psiphon's unfronted HTTPS variant puts that HTTP exchange inside a TLS
//! session. The stack this test drives is the one the Go client drives, from
//! the bottom up:
//!
//! ```text
//! HTTP request/response bodies  <-  zero_psiphon::meek
//! TLS session                   <-  the HTTPS carrier
//! OSSH cipher                   <-  zero_psiphon::obfuscator
//! SSH session                   <-  zero_psiphon::tunnel
//! ```
//!
//! The OSSH layer matters: Psiphon's server expects the SSH session to
//! arrive obfuscated (`psiphon/server/tunnelServer.go` builds the server-side
//! obfuscator from `SshObfuscatedKey`), and the Go client applies the same
//! layer over the meek connection (`psiphon/tunnel.go`,
//! `NewClientObfuscatedSSHConn`).
//!
//! Ignored by default, like the repository's other external-oracle tests: it
//! needs the harness in `.research/psiphon-server-harness`.
//!
//! Run with:
//!
//! ```text
//! ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry.json \
//! ZERO_PSIPHON_TARGET=127.0.0.1:20085 \
//!   cargo test -p zero-psiphon --test meek -- --ignored --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use zero_psiphon::meek::{MeekOptions, MeekStream};
use zero_psiphon::obfuscator::OsshClient;
use zero_psiphon::protocol::TunnelProtocol;
use zero_psiphon::server_entry::ServerEntry;
use zero_psiphon::tls_ossh::{tls_config, TlsOsshOptions};
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

/// Unfronted meek over TLS: the whole stack, against the real psiphond.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness"]
async fn unfronted_meek_against_the_real_server_carries_a_request() {
    let Some(entry) = server_entry() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };

    assert!(
        entry
            .capabilities()
            .iter()
            .any(|capability| capability.contains("MEEK")),
        "the server entry advertises no MEEK capability: {:?}",
        entry.capabilities()
    );
    assert!(
        entry.supports_protocol(TunnelProtocol::UnfrontedMeekHttps),
        "the server entry does not advertise UNFRONTED-MEEK-HTTPS: {:?}",
        entry.capabilities()
    );

    // The meek listener is its own port (`meekServerPort` in the entry,
    // `meekPort` in `psiphond.config`), not the obfuscated SSH port.
    let port = entry
        .meek_server_port()
        .expect("the server entry has a meek port");
    let address = entry.ip_address().to_string();

    // 1. The TCP connection to the meek listener.
    let tcp = tokio::net::TcpStream::connect((address.as_str(), port))
        .await
        .unwrap_or_else(|error| {
            panic!("connecting to the meek listener on {address}:{port}: {error}")
        });

    // 2. TLS. The harness server's certificate is self-signed and its name is
    //    an IP literal, so the verifier accepts any certificate, exactly as
    //    the TLS-OSSH carrier does.
    let mut config = (*tls_config(
        entry.meek_obfuscated_key(),
        &TlsOsshOptions {
            passthrough: false,
            ..Default::default()
        },
    ))
    .clone();
    // The Go client sends no SNI for an address literal
    // (`dialParameters.go`: `MeekSNIServerName = ""`).
    config.enable_sni = false;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name =
        rustls::pki_types::ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let tls = connector
        .connect(server_name, tcp)
        .await
        .unwrap_or_else(|error| panic!("the TLS session came up: {error}"));

    // 3. The meek layer. The Host header is the address and the port, the
    //    form the Go client uses for a non-443 meek port
    //    (`dialParameters.go`: `net.JoinHostPort(hostname, meekPort)`).
    let host_header = format!("{address}:{port}");
    let options = MeekOptions::unfronted(
        TunnelProtocol::UnfrontedMeekHttps,
        entry.meek_obfuscated_key(),
        entry.meek_cookie_encryption_public_key(),
        host_header,
    );
    let mut rng = rand::thread_rng();
    let meek = MeekStream::new(tls, options, &mut rng)
        .expect("the meek session starts with a fresh cookie");

    // 4. The OSSH layer over the meek stream, then the SSH session over that.
    let carrier = OsshClient::new(meek, entry.ssh_obfuscated_key().as_bytes());
    let tunnel = SshTunnel::establish(
        carrier,
        &entry,
        &TunnelOptions::default(),
        Duration::from_secs(20),
    )
    .await
    .unwrap_or_else(|error| panic!("the real server rejected the tunnel: {error}"));

    // The server refuses port forwards until the Psiphon handshake has
    // completed; this is the same SSH global request the Go client sends.
    let response = tunnel
        .handshake(&HandshakeParams::new(TunnelProtocol::UnfrontedMeekHttps))
        .await
        .unwrap_or_else(|error| panic!("tunnel handshake: {error}"));
    assert!(
        response.is_empty() || response.starts_with(b"{"),
        "the handshake response is JSON or empty, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    // 5. A request through the tunnel, to the harness's loopback origin.
    let (host, port) = target();
    let mut stream = tunnel
        .open(&host, port)
        .await
        .unwrap_or_else(|error| panic!("opening a channel: {error}"));

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(
            format!("GET /marker.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("writing through the tunnel");
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .expect("reading through the tunnel");
    tunnel.close().await;

    let text = String::from_utf8_lossy(&body).into_owned();
    assert!(
        text.starts_with("HTTP/1."),
        "expected an HTTP response through the tunnel, got: {text}"
    );
    assert!(
        text.contains("psiphon-harness-marker"),
        "expected the test origin's body, got: {text}"
    );
}
