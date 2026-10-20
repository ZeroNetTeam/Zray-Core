//! Interop for the **fronted** meek transports against a real `psiphond`.
//!
//! An unfronted meek connection dials the Psiphon server itself
//! (`tests/meek.rs`). A fronted one does not: the client dials a *fronting
//! provider* — a CDN edge — that the censor has no reason to block, asks for a
//! fronting host name in the `Host` header, and lets the CDN forward the HTTP
//! request to the Psiphon server it fronts. `psiphond` then sees an ordinary
//! meek request and cannot tell the difference.
//!
//! ```text
//!   client ──TLS :443 (or plain HTTP :80)──▶ fronting provider ──HTTP──▶ psiphond :20087
//!          Host: <fronting host>              (CDN edge)                 (unfronted meek)
//! ```
//!
//! The harness has no CDN, so this test uses the local stand-in in
//! `.research/psiphon-server-harness/tools/fronting-provider.py`: a TLS (or
//! plain TCP) listener that forwards request bytes to the harness `psiphond`'s
//! unfronted meek port and streams the response back.
//!
//! The server entry is built here rather than read from the harness config:
//! the harness entry advertises the unfronted transports only, because a
//! fronted entry belongs to whichever fronting provider the server is deployed
//! behind. This test writes the fields a fielded fronted entry carries —
//! `meekFrontingAddresses`, `meekFrontingHosts` and the `FRONTED-MEEK`
//! capability — and points the client at the local edge's port through
//! `ClientConfig::dial_options`, since a local edge cannot bind 443/80.
//!
//! Ignored by default, like the repository's other external-oracle tests: it
//! needs the harness in `.research/psiphon-server-harness`, its origin, and
//! the fronting provider. `./verify-fronted.sh` runs the whole thing in one
//! shell:
//!
//! ```text
//! ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry.json \
//! ZERO_PSIPHON_TARGET=127.0.0.1:20085 \
//!   cargo test -p zero-psiphon --test fronted_meek -- --ignored --nocapture
//! ```
//!
//! Extra environment overrides (all with harness defaults):
//! `ZERO_PSIPHON_FRONTING_ADDRESS` (127.0.0.1), `ZERO_PSIPHON_FRONTING_HOST`
//! (localhost), `ZERO_PSIPHON_FRONTING_PORT` (20443, the TLS edge) and
//! `ZERO_PSIPHON_FRONTING_HTTP_PORT` (20480, the plain edge).

use std::time::Duration;

use zero_psiphon::client::Client;
use zero_psiphon::config::{ClientConfig, TunnelDialOptions};
use zero_psiphon::protocol::TunnelProtocol;
use zero_psiphon::server_entry::ServerEntry;

/// The address the local fronting provider listens on.
fn fronting_address() -> String {
    std::env::var("ZERO_PSIPHON_FRONTING_ADDRESS").unwrap_or_else(|_| "127.0.0.1".into())
}

/// The name the client asks for: what a CDN edge is configured to serve, and
/// therefore what the `Host` header carries.
fn fronting_host() -> String {
    std::env::var("ZERO_PSIPHON_FRONTING_HOST").unwrap_or_else(|_| "localhost".into())
}

/// The edge's port for `FRONTED-MEEK-OSSH`, i.e. the stand-in for 443.
fn fronting_port() -> u16 {
    std::env::var("ZERO_PSIPHON_FRONTING_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20443)
}

/// The edge's port for `FRONTED-MEEK-HTTP-OSSH`, i.e. the stand-in for 80.
fn fronting_http_port() -> u16 {
    std::env::var("ZERO_PSIPHON_FRONTING_HTTP_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20480)
}

/// The destination the tunnel is asked for.
fn target() -> (String, u16) {
    let value = std::env::var("ZERO_PSIPHON_TARGET").unwrap_or_else(|_| "127.0.0.1:20085".into());
    let (host, port) = value.rsplit_once(':').expect("host:port");
    (host.to_string(), port.parse().expect("a port"))
}

/// The harness entry, rewritten into the fronted entry a deployed server
/// behind a CDN would have.
///
/// What changes:
///  * `meekFrontingAddresses` — the edge to dial, in place of the server's own
///    address.
///  * `meekFrontingHosts` — the name to ask for in the `Host` header.
///  * `capabilities` — only this transport, so the client cannot quietly fall
///    back to plain SSH and make the test pass without a CDN in the path.
///    (The capability string drops the `-OSSH` suffix, as Psiphon's
///    `GetCapability` does: the capability for `FRONTED-MEEK-OSSH` is
///    `FRONTED-MEEK`.)
///
/// Everything else — the SSH host key, the obfuscated SSH key, the meek cookie
/// key — is the server's and stays.
fn fronted_server_entry(protocol: TunnelProtocol) -> Option<ServerEntry> {
    let path = std::env::var("ZERO_PSIPHON_SERVER_ENTRY").ok()?;
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("reading {path}: {error}"));
    let mut value: serde_json::Value =
        serde_json::from_str(&text).expect("the harness entry is JSON");
    let fields = value
        .as_object_mut()
        .unwrap_or_else(|| panic!("{path} is a JSON object"));

    fields.insert(
        "meekFrontingAddresses".into(),
        serde_json::json!([fronting_address()]),
    );
    fields.insert(
        "meekFrontingHosts".into(),
        serde_json::json!([fronting_host()]),
    );
    fields.insert(
        "capabilities".into(),
        serde_json::json!([protocol.capability()]),
    );

    Some(ServerEntry::from_value(value).expect("the fronted entry parses"))
}

/// Establish a tunnel over `protocol` through the local edge, and fetch the
/// origin's marker through it.
async fn tunnel_through_the_edge(protocol: TunnelProtocol, dial_port: u16) {
    let Some(entry) = fronted_server_entry(protocol) else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };

    // The entry is what a fielded fronted entry looks like.
    assert!(
        entry.supports_protocol(protocol),
        "the built entry does not advertise {protocol}: {:?}",
        entry.capabilities()
    );
    assert_eq!(
        entry.meek_fronting_addresses(),
        &[fronting_address()][..],
        "meekFrontingAddresses is what the client dials"
    );
    assert_eq!(
        entry.meek_fronting_hosts(),
        &[fronting_host()][..],
        "meekFrontingHosts is what the client asks for in the Host header"
    );
    assert!(
        !entry.meek_fronting_disable_sni(),
        "SNI is on, so the edge sees the fronting address in the ClientHello"
    );

    // Every other transport is out of the entry, so a tunnel here can only be
    // a fronted-meek tunnel; `fronted_dial_port` redirects the dial from 443
    // (or 80) to the local edge, which cannot bind those ports in a test.
    let config = ClientConfig {
        server_entries: vec![entry],
        protocols: vec![protocol],
        establish_timeout: Duration::from_secs(20),
        establish_concurrency: 1,
        tunnel_pool_size: 1,
        dial_options: TunnelDialOptions {
            fronted_dial_port: Some(dial_port),
        },
        ..Default::default()
    };

    let client = Client::connect(config).await.unwrap_or_else(|error| {
        panic!(
            "{protocol} did not establish a tunnel through the local fronting provider on \
             127.0.0.1:{dial_port} (is tools/fronting-provider.py running, and is {protocol} \
             one of TunnelProtocol::supported()?): {error}"
        )
    });
    assert_eq!(
        client.protocol().await,
        Some(protocol),
        "the tunnel must have been carried by the fronted transport under test"
    );

    // A request through the tunnel, to the harness's loopback origin: the same
    // assertion as the unfronted test, through a path the client believes ends
    // at the CDN.
    let (host, port) = target();
    let mut stream = client
        .dial(&host, port)
        .await
        .unwrap_or_else(|error| panic!("opening a channel through the fronted tunnel: {error}"));

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
    client.close().await;

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

/// `FRONTED-MEEK-OSSH`: the client dials the fronting address over **TLS**,
/// asks for the fronting host, and the edge forwards to `psiphond`.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness and its fronting provider"]
async fn fronted_meek_over_tls_through_a_local_edge_carries_a_request() {
    tunnel_through_the_edge(TunnelProtocol::FrontedMeek, fronting_port()).await;
}

/// `FRONTED-MEEK-HTTP-OSSH`: the same, with **no TLS** below the HTTP — the
/// fronting provider is a plain TCP listener, as an HTTP-only edge is.
#[tokio::test]
#[ignore = "needs the local psiphon-server harness and its fronting provider"]
async fn fronted_meek_over_plain_http_through_a_local_edge_carries_a_request() {
    tunnel_through_the_edge(TunnelProtocol::FrontedMeekHttp, fronting_http_port()).await;
}

/// The fronted carrier built by hand, the way `tests/meek.rs` builds the
/// unfronted one.
///
/// The two tests above go through the client's server selection, which is what
/// makes them end-to-end — and also what makes them fail for a reason that has
/// nothing to do with the carrier, when a transport is not (yet) one the
/// selection loop will offer. This one drives the same stack directly, so a
/// broken carrier and a transport that selection does not offer are told
/// apart:
///
/// ```text
/// TLS to the edge ── meek (Host: <fronting host>) ── OSSH ── SSH ── marker
/// ```
#[tokio::test]
#[ignore = "needs the local psiphon-server harness and its fronting provider"]
async fn the_fronted_carrier_carries_the_stack_through_the_tls_edge() {
    use std::sync::Arc;

    use zero_psiphon::meek::{MeekOptions, MeekStream};
    use zero_psiphon::obfuscator::OsshClient;
    use zero_psiphon::tls_ossh::{tls_config, TlsOsshOptions};
    use zero_psiphon::tunnel::{HandshakeParams, SshTunnel, TunnelOptions};

    let Some(entry) = fronted_server_entry(TunnelProtocol::FrontedMeek) else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };
    let address = fronting_address();
    let port = fronting_port();

    // 1. The TCP connection to the edge, on the port a real client would reach
    //    at :443.
    let tcp = tokio::net::TcpStream::connect((address.as_str(), port))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "connecting to the fronting provider on {address}:{port} (is \
                 tools/fronting-provider.py running?): {error}"
            )
        });

    // 2. TLS to the edge. The edge's certificate is not verified (as with
    //    TLS-OSSH: the SSH host key inside is what identifies the server), and
    //    the server name is the fronting address, which is what the Go client
    //    sends unless `meekFrontingDisableSNI` is set.
    let tls_options = TlsOsshOptions {
        server_name: Some(address.clone()),
        passthrough: false,
        ..Default::default()
    };
    let mut config = (*tls_config(entry.meek_obfuscated_key(), &tls_options)).clone();
    config.enable_sni = true;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(address.clone())
        .expect("an IP literal is a valid server name");
    let tls = connector
        .connect(name, tcp)
        .await
        .unwrap_or_else(|error| panic!("the TLS session with the edge came up: {error}"));

    // 3. The meek layer, asking for the fronting host — the difference from
    //    the unfronted transport.
    let options = MeekOptions::fronted(
        TunnelProtocol::FrontedMeek,
        entry.meek_obfuscated_key(),
        entry.meek_cookie_encryption_public_key(),
        fronting_host(),
    );
    let mut rng = rand::thread_rng();
    let meek = MeekStream::new(tls, options, &mut rng)
        .expect("the meek session starts with a fresh cookie");

    // 4. The same OSSH and SSH stack the unfronted transport runs.
    let carrier = OsshClient::new(meek, entry.ssh_obfuscated_key().as_bytes());
    let tunnel = SshTunnel::establish(
        carrier,
        &entry,
        &TunnelOptions::default(),
        Duration::from_secs(20),
    )
    .await
    .unwrap_or_else(|error| panic!("the real server rejected the tunnel: {error}"));
    let response = tunnel
        .handshake(&HandshakeParams::new(TunnelProtocol::FrontedMeek))
        .await
        .unwrap_or_else(|error| panic!("tunnel handshake: {error}"));
    assert!(
        response.is_empty() || response.starts_with(b"{"),
        "the handshake response is JSON or empty, got: {:?}",
        String::from_utf8_lossy(&response)
    );

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
        text.contains("psiphon-harness-marker"),
        "expected the test origin's body through the fronted carrier, got: {text}"
    );
}
