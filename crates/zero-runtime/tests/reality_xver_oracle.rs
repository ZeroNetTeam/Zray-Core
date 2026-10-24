//! The REALITY `xver` PROXY header, compared against the official server's
//! through a target that actually reads it.
//!
//! REALITY's camouflage is only believable if the site behind the port sees
//! what it would see if it were exposed directly. `realitySettings.xver` asks
//! the server to put a PROXY protocol header in front of the visitor's traffic
//! so the site learns the visitor's real address (`RL/tls.go:174-180`,
//! `proxyproto.HeaderProxyFromAddrs`): version 1 is the text line
//! `PROXY TCP4 <src> <dst> <sport> <dport>\r\n`, version 2 the binary form with
//! the 12-byte signature. The byte layout is pinned locally by
//! `crates/reality/tests/fallback.rs:175-251` and the Zray runtime test
//! `crates/zero-runtime/tests/fallback.rs:229`, but none of those runs an
//! official Xray server: they prove Zray agrees with itself. A wrong header is
//! invisible to a plain TLS decoy, which simply discards what it cannot parse,
//! so nothing in the differential suite would notice one.
//!
//! This test is the missing measurement, and it is the gap named in
//! `docs/specs/REALITY-server.md` §9 item 8. It puts a *recording* target
//! between each REALITY server and a real Xray TLS decoy: the target reads the
//! first bytes of every connection, parses a PROXY header if one is there,
//! records it, strips it, and relays the rest to the decoy. Pointing both
//! servers' `dest` at that target and driving an unauthenticated visitor (a
//! real TLS ClientHello captured from this workspace's own client) through
//! each inbound makes the two implementations produce their header to the same
//! kind of target, in the same run.
//!
//! The recorder has to strip the header before relaying for a reason that is
//! itself part of the behaviour under test: Go asks the camouflage site about
//! its handshake shapes at start-up and writes the PROXY header on *those*
//! dials too (`RL/record_detect.go:37,71`), before the probe's ClientHello.
//! A target that handed that prefix to the TLS decoy would never get an
//! answer, and the shape-probe connections would fail for both servers. The
//! recorder is lenient about the prefix — present or absent — because the
//! visitors being compared are the ones the test drives.
//!
//! What is asserted, per version (1 then 2) and per server (official Xray,
//! Zray): the target received a well-formed header of that version, the bytes
//! on the wire are exactly what `proxyproto.HeaderProxyFromAddrs` writes for
//! this visitor and this inbound (`PROXY TCP4 127.0.0.1 127.0.0.1 <sport>
//! <dport>\r\n`, or the 28-byte v2 header), the source address and port are the
//! visitor's, the destination address and port are the inbound's, and the
//! visitor's ClientHello follows the header with no bytes lost in between. Then
//! the two headers are compared for the same shape and fields.
//!
//! ```bash
//! ZRAY_XRAY_BINARY=/usr/bin/xray \
//!   cargo test -p zero-runtime --test reality_xver_oracle \
//!   -- --ignored --test-threads=1
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zero_security::tls13::record::{record_header, CONTENT_HANDSHAKE};
use zero_security::tls13::{HelloParams, PendingHello};

#[path = "reality_support/mod.rs"]
mod reality_support;

use reality_support::{
    free_port, oracle_binary, oracle_version, oracle_x25519_keypair, reality_server_settings,
    spawn_decoy, vless_reality_server_config_with, wait_for, ServerProcess, REALITY_SNI,
};

/// The 12 bytes that begin a version 2 header (`zero-protocol`'s constant is
/// deliberately not reused: the point is to read the bytes the oracle writes,
/// not to agree with this workspace's own reader).
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// What a version 1 header starts with.
const V1_PREFIX: &[u8] = b"PROXY ";
/// The specification's longest version 1 header, CRLF included.
const V1_MAX_WIRE: usize = 107 + 2;
/// How much of the TLS record behind the header the recorder keeps, so the
/// record shows the visitor's own ClientHello and not an empty slot.
const CAPTURED_PAYLOAD: usize = 1024;
/// How long a read may be silent before the recorder stops waiting for more of
/// the opening. A header and the record behind it are written back to back.
const OPENING_QUIET: Duration = Duration::from_millis(100);
/// The first read of a connection can legitimately wait for a server to finish
/// dialling its target, so it is allowed to be slower than the rest.
const FIRST_READ: Duration = Duration::from_secs(5);

/// One PROXY header as the target read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProxyHeader {
    version: u8,
    family: ProxyFamily,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    /// How many bytes the header occupied on the wire.
    len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyFamily {
    Tcp4,
    Tcp6,
    /// `PROXY UNKNOWN` / version 2's `LOCAL` command.
    Unspecified,
}

impl ProxyFamily {
    fn label(self) -> &'static str {
        match self {
            ProxyFamily::Tcp4 => "TCP4",
            ProxyFamily::Tcp6 => "TCP6",
            ProxyFamily::Unspecified => "UNSPECIFIED",
        }
    }
}

/// One connection the camouflage target accepted, as far as it read it.
#[derive(Debug, Clone)]
struct TargetRecord {
    /// The server's own address, as the target saw it.
    peer: SocketAddr,
    header: Option<ProxyHeader>,
    /// Every byte read from the opening, header included.
    raw: Vec<u8>,
}

impl TargetRecord {
    /// The bytes behind the header: what the target is about to relay.
    fn payload(&self) -> &[u8] {
        &self.raw[self.header.map_or(0, |header| header.len)..]
    }

    fn opening(&self) -> String {
        match self.header {
            Some(header) => format!(
                "v{} {} source {:?} destination {:?} ({} bytes)",
                header.version,
                header.family.label(),
                header.source,
                header.destination,
                header.len
            ),
            None => "no PROXY header".to_string(),
        }
    }
}

/// A TCP target that records the first bytes of every connection, strips a
/// PROXY header if one is there, and relays the rest to the real decoy.
struct RecordingTarget {
    address: SocketAddr,
    records: Arc<Mutex<Vec<TargetRecord>>>,
}

impl RecordingTarget {
    async fn start(decoy: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a recording target on loopback");
        let address = listener.local_addr().expect("its address");
        let records = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&records);
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    if let Err(error) = record_and_relay(stream, peer, decoy, log).await {
                        eprintln!("recording target: a connection from {peer} failed: {error}");
                    }
                });
            }
        });
        Self { address, records }
    }

    fn snapshot(&self) -> Vec<TargetRecord> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Wait for the first connection the predicate accepts, or `None` if the
    /// target never saw one before `limit`.
    async fn wait_for_record<F>(&self, matches: F, limit: Duration) -> Option<TargetRecord>
    where
        F: Fn(&TargetRecord) -> bool,
    {
        let started = Instant::now();
        loop {
            if let Some(record) = self.snapshot().into_iter().find(|record| matches(record)) {
                return Some(record);
            }
            if started.elapsed() >= limit {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Every connection the target accepted, for the failure message of a
    /// server that put the wrong thing on it.
    fn summarise(&self) -> String {
        let records = self.snapshot();
        if records.is_empty() {
            return "the target accepted no recorded connection at all".to_string();
        }
        records
            .iter()
            .map(|record| {
                format!(
                    "from {}: {}; first bytes {}",
                    record.peer,
                    record.opening(),
                    hex(&record.raw[..record.raw.len().min(48)])
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Record one opening, then hand the connection — with any PROXY header taken
/// off — to the decoy and relay both directions.
async fn record_and_relay(
    mut client: TcpStream,
    peer: SocketAddr,
    decoy: SocketAddr,
    records: Arc<Mutex<Vec<TargetRecord>>>,
) -> std::io::Result<()> {
    let (header, raw) = capture_opening(&mut client).await?;
    let header_len = header.map_or(0, |header| header.len);
    records
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(TargetRecord {
            peer,
            header,
            raw: raw.clone(),
        });

    let mut target = TcpStream::connect(decoy).await?;
    target.write_all(&raw[header_len..]).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await?;
    Ok(())
}

/// Read the first bytes of a connection: enough to decide whether a PROXY
/// header opens it, then a prefix of whatever follows so the record shows the
/// visitor's own TLS record.
async fn capture_opening(
    stream: &mut TcpStream,
) -> std::io::Result<(Option<ProxyHeader>, Vec<u8>)> {
    let mut raw = Vec::new();
    // Twelve bytes is the version 2 signature's length and more than the six a
    // version 1 line needs to be recognisable.
    read_at_least(stream, &mut raw, 12, FIRST_READ).await?;
    if raw.starts_with(&V2_SIGNATURE) {
        read_at_least(stream, &mut raw, 16, FIRST_READ).await?;
        if raw.len() >= 16 {
            let address_len = u16::from_be_bytes([raw[14], raw[15]]) as usize;
            read_at_least(stream, &mut raw, 16 + address_len, FIRST_READ).await?;
        }
    } else if raw.starts_with(V1_PREFIX) {
        while find(&raw, b"\r\n").is_none() && raw.len() < V1_MAX_WIRE {
            if !read_more(stream, &mut raw, FIRST_READ).await? {
                break;
            }
        }
    }
    let header = parse_proxy_header(&raw);
    let header_len = header.map_or(0, |header| header.len);
    let want = header_len + CAPTURED_PAYLOAD;
    while raw.len() < want {
        if !read_more(stream, &mut raw, OPENING_QUIET).await? {
            break;
        }
    }
    Ok((header, raw))
}

/// Read until the buffer holds `want` bytes, the stream ends, or a read is
/// silent for `quiet`.
async fn read_at_least(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    want: usize,
    quiet: Duration,
) -> std::io::Result<()> {
    while buffer.len() < want {
        if !read_more(stream, buffer, quiet).await? {
            break;
        }
    }
    Ok(())
}

/// One read. `false` means end of stream or silence for `quiet`.
async fn read_more(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    quiet: Duration,
) -> std::io::Result<bool> {
    let mut scratch = [0u8; 4096];
    match tokio::time::timeout(quiet, stream.read(&mut scratch)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(read)) => {
            buffer.extend_from_slice(&scratch[..read]);
            Ok(true)
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Ok(false),
    }
}

/// Parse the PROXY header at the front of `bytes`, independently of this
/// workspace's own `zero_protocol::proxy_protocol` reader: the comparison is
/// with the bytes the official server wrote, not with Zray's reading of them.
fn parse_proxy_header(bytes: &[u8]) -> Option<ProxyHeader> {
    if bytes.starts_with(V1_PREFIX) {
        let end = find(bytes, b"\r\n")?;
        let line = std::str::from_utf8(&bytes[..end]).ok()?;
        let fields: Vec<&str> = line.split(' ').collect();
        let len = end + 2;
        if fields.len() == 2 && fields[1] == "UNKNOWN" {
            return Some(ProxyHeader {
                version: 1,
                family: ProxyFamily::Unspecified,
                source: None,
                destination: None,
                len,
            });
        }
        if fields.len() != 6 {
            return None;
        }
        let family = match fields[1] {
            "TCP4" => ProxyFamily::Tcp4,
            "TCP6" => ProxyFamily::Tcp6,
            _ => return None,
        };
        Some(ProxyHeader {
            version: 1,
            family,
            source: Some(SocketAddr::new(
                fields[2].parse().ok()?,
                fields[4].parse().ok()?,
            )),
            destination: Some(SocketAddr::new(
                fields[3].parse().ok()?,
                fields[5].parse().ok()?,
            )),
            len,
        })
    } else if bytes.starts_with(&V2_SIGNATURE) {
        if bytes.len() < 16 {
            return None;
        }
        if bytes[12] >> 4 != 2 {
            return None;
        }
        let command = bytes[12] & 0x0f;
        let family = match bytes[13] {
            0x11 => ProxyFamily::Tcp4,
            0x21 => ProxyFamily::Tcp6,
            _ => ProxyFamily::Unspecified,
        };
        let address_len = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
        let len = 16 + address_len;
        if bytes.len() < len {
            return None;
        }
        let (source, destination) = if command == 0x00 {
            // The LOCAL command: the sender explicitly said it does not know.
            (None, None)
        } else {
            match family {
                ProxyFamily::Tcp4 if address_len >= 12 => (
                    Some(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                        u16::from_be_bytes([bytes[24], bytes[25]]),
                    )),
                    Some(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23])),
                        u16::from_be_bytes([bytes[26], bytes[27]]),
                    )),
                ),
                ProxyFamily::Tcp6 if address_len >= 36 => (
                    Some(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(&bytes[16..32]).expect("16 address bytes"),
                        )),
                        u16::from_be_bytes([bytes[48], bytes[49]]),
                    )),
                    Some(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(&bytes[32..48]).expect("16 address bytes"),
                        )),
                        u16::from_be_bytes([bytes[50], bytes[51]]),
                    )),
                ),
                _ => (None, None),
            }
        };
        Some(ProxyHeader {
            version: 2,
            family,
            source,
            destination,
            len,
        })
    } else {
        None
    }
}

/// The exact version 1 header `proxyproto.HeaderProxyFromAddrs(1, visitor,
/// inbound)` writes, byte for byte.
fn expected_v1(visitor: SocketAddr, inbound: SocketAddr) -> Vec<u8> {
    match (visitor.ip(), inbound.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => format!(
            "PROXY TCP4 {source} {destination} {} {}\r\n",
            visitor.port(),
            inbound.port()
        )
        .into_bytes(),
        (IpAddr::V6(source), IpAddr::V6(destination)) => format!(
            "PROXY TCP6 {source} {destination} {} {}\r\n",
            visitor.port(),
            inbound.port()
        )
        .into_bytes(),
        _ => {
            panic!("the visitor and the inbound are not one address family: {visitor} -> {inbound}")
        }
    }
}

/// The exact version 2 header go-proxyproto writes for a TCP4 pair: the
/// signature, `0x21` (version 2, PROXY command), `0x11` (TCP4), the length,
/// both addresses and both ports.
fn expected_v2(visitor: SocketAddr, inbound: SocketAddr) -> Vec<u8> {
    let mut expected = V2_SIGNATURE.to_vec();
    match (visitor.ip(), inbound.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            expected.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
            expected.extend_from_slice(&source.octets());
            expected.extend_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            expected.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            expected.extend_from_slice(&source.octets());
            expected.extend_from_slice(&destination.octets());
        }
        _ => {
            panic!("the visitor and the inbound are not one address family: {visitor} -> {inbound}")
        }
    }
    expected.extend_from_slice(&visitor.port().to_be_bytes());
    expected.extend_from_slice(&inbound.port().to_be_bytes());
    expected
}

/// A real TLS ClientHello, as this workspace's own Chrome-shaped client builds
/// it: a TLS 1.3 offer with a key share, the decoy's server name, and a
/// session id that is not one REALITY sealed. The server cannot authenticate
/// it, which is exactly the visitor this test needs — one that must be handed
/// to the camouflage site.
fn visitor_client_hello() -> Vec<u8> {
    let hello = PendingHello::new(&HelloParams::new(REALITY_SNI));
    let mut record = record_header(CONTENT_HANDSHAKE, hello.msg.len()).to_vec();
    // TLS 1.3 keeps the legacy ClientHello record version at 0x0301.
    record[2] = 0x01;
    record.extend_from_slice(&hello.msg);
    record
}

/// Assert the header on `record` is the one the official proxy protocol code
/// writes for this visitor and this inbound, and that the visitor's hello
/// follows it.
fn assert_proxy_header(
    record: &TargetRecord,
    xver: u8,
    visitor: SocketAddr,
    inbound: SocketAddr,
    hello: &[u8],
    whose: &str,
) -> ProxyHeader {
    let header = record.header.unwrap_or_else(|| {
        panic!(
            "{whose}: the visitor's connection reached the target without a PROXY header, so a \
             site inspecting the prefix would see the ClientHello as the header.\n\
             The target saw:\n{}",
            record.opening()
        )
    });
    assert_eq!(
        header.version,
        xver,
        "{whose}: the target read a version {} header where xver {xver} asked for one; the target \
         saw {} ({} bytes)",
        header.version,
        record.opening(),
        record.raw.len()
    );
    let expected = match xver {
        1 => expected_v1(visitor, inbound),
        2 => expected_v2(visitor, inbound),
        other => panic!("xver outside 1..=2: {other}"),
    };
    assert_eq!(
        &record.raw[..header.len],
        expected.as_slice(),
        "{whose}: the header bytes the target read are not the ones \
         proxyproto.HeaderProxyFromAddrs({xver}, visitor, inbound) writes\n  target read: {}\n  \
         expected:    {}",
        hex(&record.raw[..header.len]),
        hex(&expected)
    );
    assert_eq!(
        header.family,
        ProxyFamily::Tcp4,
        "{whose}: a loopback visitor must be announced as TCP4; the target saw {}",
        record.opening()
    );
    assert_eq!(
        header.source,
        Some(visitor),
        "{whose}: the target was told the visitor is {:?}, not {visitor}",
        header.source
    );
    assert_eq!(
        header.destination,
        Some(inbound),
        "{whose}: the target was told the visitor was connecting to {:?}, not {inbound}",
        header.destination
    );
    // What follows the header must be the visitor's own TLS record, so the
    // decoy answers the handshake the visitor started and a prober gets the
    // site's reply rather than an alert about a truncated hello.
    let payload = record.payload();
    assert!(
        payload.len() >= 5,
        "{whose}: only {} payload bytes were captured behind the header: {}",
        payload.len(),
        hex(payload)
    );
    assert_eq!(
        &payload[..5],
        &hello[..5],
        "{whose}: the bytes behind the PROXY header are not the visitor's ClientHello record \
         (expected {:?}, got {})",
        &hello[..5],
        hex(&payload[..payload.len().min(16)])
    );
    let common = payload.len().min(hello.len());
    assert_eq!(
        &payload[..common],
        &hello[..common],
        "{whose}: the replayed hello diverges from the visitor's own bytes"
    );
    header
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn spawn_zray(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    server
}

/// For `xver` 1 and then 2: start an official Xray REALITY inbound and a Zray
/// one, both with `dest` = a recording target in front of a real Xray TLS
/// decoy, drive the same unauthenticated visitor through each, and compare the
/// PROXY header each server's target read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn both_servers_write_the_same_proxy_header_for_the_same_visitor() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!(
        "oracle: {} (REALITY xver PROXY header)",
        oracle_version(&binary)
    );

    // The camouflage site both servers fall back to: an official Xray TLS
    // server, so "relayed" means a real TLS session and not a mock.
    let decoy_port = free_port();
    let mut decoy = spawn_decoy(&binary, decoy_port);
    let decoy_address = SocketAddr::from(([127, 0, 0, 1], decoy_port));
    assert!(
        wait_for(decoy_address).await,
        "the camouflage site never listened:\n{}",
        decoy.tail(20)
    );

    // The target both servers believe is the site. It records the PROXY
    // header, strips it, and relays the TLS record to the real decoy.
    let target = RecordingTarget::start(decoy_address).await;
    eprintln!(
        "recording target at {}, relaying to the decoy at {decoy_address}",
        target.address
    );

    let hello = visitor_client_hello();

    for xver in [1u64, 2u64] {
        // One keypair and one realitySettings block for both servers, so a
        // difference in the headers cannot be a difference in the settings.
        let (private_key, _public_key) = oracle_x25519_keypair(&binary);
        let mut reality = reality_server_settings(&private_key, target.address);
        reality["xver"] = json!(xver);

        let oracle_port = free_port();
        let mut oracle = ServerProcess::spawn_named(
            &binary,
            vless_reality_server_config_with(oracle_port, reality.clone()),
            "xver-oracle",
        );
        let oracle_address = SocketAddr::from(([127, 0, 0, 1], oracle_port));
        assert!(
            wait_for(oracle_address).await,
            "the official REALITY server never listened with xver {xver}:\n{}",
            oracle.tail(20)
        );

        let zray_port = free_port();
        let _zray = spawn_zray(vless_reality_server_config_with(zray_port, reality));
        let zray_address = SocketAddr::from(([127, 0, 0, 1], zray_port));
        assert!(
            wait_for(zray_address).await,
            "this port's REALITY server never listened with xver {xver}"
        );

        // The other dial Go prefixed, and the reason the recorder has to strip
        // a header rather than assume the first bytes are TLS: the official
        // server's start-up shape probes write it too (`RL/record_detect.go:37,71`).
        // If this never arrives the recorder is not the harness this test
        // claims to be, so it is an assertion and not a print.
        assert!(
            target
                .wait_for_record(
                    |record| record.header.is_some_and(|header| {
                        header.version == xver as u8
                            && header.destination.is_some_and(|destination| {
                                destination.port() == target.address.port()
                            })
                    }),
                    Duration::from_secs(10),
                )
                .await
                .is_some(),
            "the official server with xver {xver} never put its start-up shape probes through the \
             target, so the harness did not exercise stripping a header from a probe's \
             ClientHello.\nThe target saw:\n{}",
            target.summarise()
        );

        let mut headers = Vec::new();
        for (name, inbound) in [
            ("the official server", oracle_address),
            ("this port's server", zray_address),
        ] {
            // A raw TCP visitor, holding the socket so its ephemeral port is
            // the one the header must name.
            let mut visitor = TcpStream::connect(inbound)
                .await
                .unwrap_or_else(|error| panic!("{name} never listened on {inbound}: {error}"));
            visitor.set_nodelay(true).expect("TCP_NODELAY");
            let visitor_address = visitor.local_addr().expect("a local address");
            visitor.write_all(&hello).await.expect("the ClientHello");
            visitor
                .flush()
                .await
                .expect("the ClientHello reaches the wire");

            let record = target
                .wait_for_record(
                    |record| {
                        record.header.is_some_and(|header| {
                            header.version == xver as u8
                                && header.source == Some(visitor_address)
                                && header.destination == Some(inbound)
                        }) && record
                            .payload()
                            .first()
                            .is_some_and(|first| *first == CONTENT_HANDSHAKE)
                    },
                    Duration::from_secs(20),
                )
                .await
                .unwrap_or_else(|| {
                    panic!(
                        "{name}: with xver {xver}, the visitor from {visitor_address} to \
                         {inbound} produced no PROXY header at the target.\n\
                         The target saw:\n{}",
                        target.summarise()
                    )
                });

            let header = assert_proxy_header(
                &record,
                xver as u8,
                visitor_address,
                inbound,
                &hello,
                &format!("{name} with xver {xver}"),
            );
            eprintln!(
                "{name} with xver {xver}: {} from {visitor_address} to {inbound}; {} bytes behind \
                 it",
                header.family.label(),
                record.payload().len()
            );
            headers.push((name, header));
            drop(visitor);
        }

        // The comparison the test exists for: the two implementations put the
        // same header shape on the wire for the same kind of visitor. Their
        // ports differ by construction (two listeners, two visitor sockets),
        // so the fields that must agree are the ones that are not the ports.
        let (oracle_name, oracle_header) = headers[0];
        let (zray_name, zray_header) = headers[1];
        assert_eq!(
            oracle_header.version, zray_header.version,
            "{oracle_name} and {zray_name} announced different PROXY protocol versions"
        );
        assert_eq!(
            oracle_header.family,
            zray_header.family,
            "{oracle_name} announced {} and {zray_name} {}",
            oracle_header.family.label(),
            zray_header.family.label()
        );
        assert_eq!(
            oracle_header.len, zray_header.len,
            "{oracle_name} wrote a {}-byte header and {zray_name} a {}-byte one",
            oracle_header.len, zray_header.len
        );
        assert_eq!(
            oracle_header.source.map(|address| address.ip()),
            zray_header.source.map(|address| address.ip()),
            "{oracle_name} and {zray_name} told the target different source addresses"
        );
        assert_eq!(
            oracle_header.destination.map(|address| address.ip()),
            zray_header.destination.map(|address| address.ip()),
            "{oracle_name} and {zray_name} told the target different destination addresses"
        );
        eprintln!(
            "xver {xver}: both servers wrote a {} {} byte header with the visitor's source ip and \
             the inbound's destination ip",
            oracle_header.version, oracle_header.len
        );
    }

    // Every dial either server made to `dest` must carry the header: Go writes
    // one on *every* dial (`RL/tls.go:174`, `RL/record_detect.go:37,71`), and
    // this port now does too, the start-up shape and budget probes included
    // (`ZR/server.rs::learn_post_handshake`). A bare TLS opening here is a dial
    // an inspecting target would reject if it required the header — which is
    // exactly the camouflage a listener behind a PROXY-aware front needs.
    let records = target.snapshot();
    let prefixed = records
        .iter()
        .filter(|record| record.header.is_some())
        .count();
    let bare_dials: Vec<&TargetRecord> = records
        .iter()
        .filter(|record| {
            record.header.is_none() && record.payload().first() == Some(&CONTENT_HANDSHAKE)
        })
        .collect();
    let samples = bare_dials
        .iter()
        .take(3)
        .map(|record| hex(&record.raw[..record.raw.len().min(12)]))
        .collect::<Vec<_>>();
    assert!(
        bare_dials.is_empty(),
        "{} of {} dials reached the target without the PROXY header xver asks for (they began \
         {samples:?}); an inspecting target would refuse exactly those, so the listener would \
         learn nothing about the site it claims to be",
        bare_dials.len(),
        records.len()
    );
    eprintln!(
        "the target accepted {} connections, all with a PROXY header",
        records.len()
    );
    let _ = prefixed;
}
