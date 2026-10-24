//! How long a silent fallback session lives, measured on the official Xray
//! REALITY server and on this port's — not assumed for either.
//!
//! `docs/specs/REALITY-server.md` §9 item 9 records the last unproven REALITY
//! server divergence as: this port closes a silent fallback flow at its idle
//! limit (`reality::fallback::DEFAULT_IDLE_TIMEOUT`, 300 s), while Go's REALITY
//! relay `io.Copy`s until one side closes (`RL/tls.go:451-452`), which the spec
//! reads as unbounded. The port's mechanism is pinned locally, with a shortened
//! timeout, by
//! `crates/reality/tests/fallback.rs::a_visitor_that_says_nothing_is_closed_at_the_idle_limit`
//! — but nothing has ever timed the *official server* in that situation, so the
//! claim rests on the shape of the Go code, not on a measurement. Xray's own
//! inbound policy (`connIdle`, default 300 s) is the obvious way for that claim
//! to be wrong in steady state: if it also closes the fallback, the divergence
//! is not observable at all.
//!
//! This test is the measurement. Both servers are given the same REALITY
//! settings — one X25519 keypair, one shortId, `xver` 0, `serverNames` — and
//! `dest` = a recording target, a plain tokio TCP listener that accepts a
//! connection, keeps it open, and notes when the peer closes or errors. An
//! unauthenticated visitor connects to each inbound, sends a valid-looking TLS
//! ClientHello whose REALITY seal it cannot produce, and then goes completely
//! silent. The hello is the whole of what the visitor says: REALITY consumes it,
//! decides the visitor is not one of its clients, and hands those exact bytes to
//! the target; nothing is left for the relay's own copy, so the idle timer's
//! first period sees no activity. That is the silent fallback flow §9 names. (A
//! plaintext HTTP request takes the same fallback path but is *not* the same
//! flow — its bytes past the first five are copied through the relay after the
//! fallback starts, which the idle timer counts as activity and re-arms on, so
//! the port closes between one and two periods after that last byte; measured,
//! its session was still open at this test's 330 s cap. The ClientHello is the
//! flow whose 300 s limit the spec claims, so it is the one measured here.)
//!
//! The test waits (bounded, [`MEASUREMENT_CAP`]) for the connection to close, on
//! the visitor's socket and on the target's socket, and prints both timestamps.
//! The target is deliberately not a TLS site. REALITY asks its site for
//! handshake shapes at start-up, so the recorder will also see those probe
//! dials, and they fail as TLS against a plain listener: that is fine, they are
//! recorded as ordinary connections, identified by their bytes and ignored. The
//! visitors are identified by the exact ClientHello bytes they sent, so a probe
//! cannot be mistaken for the flow under measurement.
//!
//! What is asserted, per server: the visitor's ClientHello reached the target
//! (the fallback happened), the target sent nothing back, and this port's
//! session closes at ~300 s on both sides. For the official server the measured
//! lifetime is allowed to be either of the two documented behaviours — closed
//! at ~300 s (its inbound policy or its own relay limit applies to the fallback
//! too) or still open at the cap (Go copies until a side closes) — and whichever
//! was observed is printed as the verdict for §9 item 9. A third behaviour,
//! such as closing much earlier on one side only, is a failure with the
//! numbers in the message.
//!
//! ```bash
//! ZRAY_XRAY_BINARY=/usr/bin/xray CARGO_INCREMENTAL=0 \
//!   cargo test -p zero-runtime --test reality_fallback_lifetime \
//!   -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! It takes about five and a half minutes: the official server gets the whole
//! cap when it is unbounded.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zero_security::tls13::record::{record_header, CONTENT_HANDSHAKE};
use zero_security::tls13::{HelloParams, PendingHello};

#[path = "reality_support/mod.rs"]
mod reality_support;

use reality_support::{
    free_port, oracle_binary, oracle_version, oracle_x25519_keypair, reality_server_settings,
    vless_reality_server_config_with, wait_for, ServerProcess, REALITY_SNI,
};

/// The idle limit §9 attributes to this port (`reality::fallback::DEFAULT_IDLE_TIMEOUT`).
///
/// Written out here rather than imported, so that changing the constant shows
/// up as this test failing against a measurement instead of silently
/// redefining the claim.
const CLAIMED_IDLE_LIMIT: Duration = Duration::from_secs(300);
/// How long a measurement waits before calling a session unbounded: the
/// claimed limit plus 30 s. A session that lives past 300 s but closes at, say,
/// 310 s would also be classed unbounded by the 300 s limit; the cap leaves a
/// margin so only a session that is really still open after the limit gets
/// that verdict.
const MEASUREMENT_CAP: Duration = Duration::from_secs(330);
/// A close is "at the limit" from this much before it: the relay starts after
/// the hello was read and the target dialled, so the measured lifetime is
/// never the timer minus a large amount, and a loaded machine only makes a
/// close later. It cannot be much earlier than the timer without being a
/// different behaviour.
const LIFETIME_FLOOR: Duration = Duration::from_secs(280);
/// ... and to this much after it, so a late timer still counts as the limit.
const LIFETIME_CEILING: Duration = Duration::from_secs(330);

/// How much of a connection's opening the target keeps: enough for a full
/// ClientHello, so the visitor can be identified by the bytes it sent.
const RETAINED_BYTES: usize = 8 * 1024;

/// One TCP connection the camouflage target accepted.
#[derive(Debug, Clone)]
struct Connection {
    peer: SocketAddr,
    accepted: Instant,
    /// The first [`RETAINED_BYTES`] bytes the peer sent.
    received: Vec<u8>,
    /// Everything the peer sent, so a truncated hello is visible as such.
    total_received: usize,
    /// When the peer closed, and what ended the read.
    closed: Option<Close>,
}

#[derive(Debug, Clone)]
struct Close {
    at: Instant,
    reason: String,
}

/// A plain TCP target that records every connection and its lifetime.
///
/// It sends nothing: the point is to hold the socket the server hands it and
/// notice when the server takes it away. No relaying, no TLS, no echo.
struct RecordingTarget {
    address: SocketAddr,
    connections: Arc<Mutex<Vec<Connection>>>,
}

impl RecordingTarget {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a recording target on loopback");
        let address = listener
            .local_addr()
            .expect("the recording target's address");
        let connections = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, peer)) = listener.accept().await else {
                    return;
                };
                let index = {
                    let mut connections =
                        log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    connections.push(Connection {
                        peer,
                        accepted: Instant::now(),
                        received: Vec::new(),
                        total_received: 0,
                        closed: None,
                    });
                    connections.len() - 1
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) => {
                                close(&log, index, "the peer closed (FIN)".to_string());
                                return;
                            }
                            Ok(read) => {
                                let mut connections =
                                    log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                                let Some(connection) = connections.get_mut(index) else {
                                    return;
                                };
                                connection.total_received += read;
                                let room = RETAINED_BYTES.saturating_sub(connection.received.len());
                                connection
                                    .received
                                    .extend_from_slice(&buffer[..read.min(room)]);
                            }
                            Err(error) => {
                                close(&log, index, format!("read failed: {error}"));
                                return;
                            }
                        }
                    }
                });
            }
        });
        Self {
            address,
            connections,
        }
    }

    fn snapshot(&self) -> Vec<Connection> {
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The one connection whose opening is exactly the ClientHello this test's
    /// visitor sent. The servers' start-up shape probes write the hellos of
    /// `utls` clients, whose random and key share differ, so they cannot match.
    fn connection_for(&self, hello: &[u8]) -> Option<Connection> {
        self.snapshot()
            .into_iter()
            .find(|connection| connection.received.starts_with(hello))
    }

    /// Every connection, for the failure message of a fallback that never
    /// arrived.
    fn describe(&self, started: Instant) -> String {
        let connections = self.snapshot();
        if connections.is_empty() {
            return "the target accepted no connection at all".to_string();
        }
        connections
            .iter()
            .map(|connection| {
                let opening = connection
                    .received
                    .iter()
                    .take(16)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let outcome = match &connection.closed {
                    Some(close) => format!(
                        "closed +{:.3}s ({})",
                        close.at.saturating_duration_since(started).as_secs_f64(),
                        close.reason
                    ),
                    None => "still open".to_string(),
                };
                format!(
                    "from {} accepted +{:.3}s, {} byte(s), opening {opening}, {outcome}",
                    connection.peer,
                    connection
                        .accepted
                        .saturating_duration_since(started)
                        .as_secs_f64(),
                    connection.total_received,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn close(connections: &Arc<Mutex<Vec<Connection>>>, index: usize, reason: String) {
    let mut connections = connections
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(connection) = connections.get_mut(index) {
        if connection.closed.is_none() {
            connection.closed = Some(Close {
                at: Instant::now(),
                reason,
            });
        }
    }
}

/// One server's fallback session, timed from both ends.
#[derive(Debug)]
struct Measured {
    label: &'static str,
    /// When the visitor's socket ended, relative to the moment it went silent.
    visitor_closed_after: Option<Duration>,
    /// When the target's socket ended, relative to the same moment.
    target_closed_after: Option<Duration>,
    /// When the target accepted the fallback connection.
    target_accepted_after: Option<Duration>,
    /// How many bytes of the visitor's ClientHello reached the target.
    target_received: usize,
    /// How many bytes the visitor sent, so a truncated replay is visible. The
    /// two synthetic hellos are allowed to differ in length — their GREASE
    /// extensions are drawn at random — which is why this is per measurement.
    expected_hello_bytes: usize,
    target_close_reason: Option<String>,
    /// What the target sent to the visitor. Nothing, by construction; anything
    /// else means the recorder is not the silent target this test claims.
    bytes_back_to_visitor: usize,
    /// How long the measurement watched before giving up on an open session.
    observed_for: Duration,
}

impl Measured {
    fn summary(&self) -> String {
        format!(
            "{}: target accepted the fallback {}, took {} byte(s) of the visitor's \
             ClientHello, and closed {}; the visitor's socket closed {}; bytes sent back to \
             the visitor: {}; observed for {:.3} s",
            self.label,
            at(self.target_accepted_after),
            self.target_received,
            at(self.target_closed_after),
            at(self.visitor_closed_after),
            self.bytes_back_to_visitor,
            self.observed_for.as_secs_f64(),
        )
    }
}

/// An absolute offset rendered as a timestamp, or "still open at the cap".
fn at(duration: Option<Duration>) -> String {
    match duration {
        Some(duration) => format!("at +{:.3} s", duration.as_secs_f64()),
        None => "never (still open at the cap)".to_string(),
    }
}

/// A visitor's only words: a well-formed TLS 1.3 ClientHello for the inbound's
/// own server name, with a random key share the server cannot authenticate.
///
/// The session id is all zeros, so the REALITY seal cannot open; both servers
/// read the whole record, fail to authenticate it, and fall back. The name is
/// the configured one deliberately: the visitor must be turned away for being
/// unauthenticated, not for asking for a site the server does not serve.
fn visitor_client_hello() -> Vec<u8> {
    let hello = PendingHello::new(&HelloParams::new(REALITY_SNI));
    let mut record = record_header(CONTENT_HANDSHAKE, hello.msg.len()).to_vec();
    // TLS 1.3 keeps the legacy ClientHello record version at 0x0301.
    record[2] = 0x01;
    record.extend_from_slice(&hello.msg);
    record
}

/// Wait for the session to end on both ends, or for the cap.
///
/// The visitor's socket is read, never written: a read that stays silent is the
/// state under measurement. The target's socket is polled every 50 ms because
/// its reader records the close in the target's own task.
async fn measure(
    label: &'static str,
    mut visitor: TcpStream,
    recorder: &RecordingTarget,
    hello: &[u8],
    started: Instant,
) -> Measured {
    let mut buffer = [0u8; 1024];
    let mut visitor_closed_after = None;
    let mut bytes_back_to_visitor = 0usize;
    let poll = Duration::from_millis(50);
    loop {
        if visitor_closed_after.is_none() {
            // A read that times out is the expected, silent case; only zero
            // bytes or a failed read are the server closing the session.
            match tokio::time::timeout(poll, visitor.read(&mut buffer)).await {
                Ok(Ok(0)) => visitor_closed_after = Some(started.elapsed()),
                Ok(Err(_)) => visitor_closed_after = Some(started.elapsed()),
                Ok(Ok(read)) => bytes_back_to_visitor += read,
                Err(_) => {}
            }
        } else {
            tokio::time::sleep(poll).await;
        }
        let target_closed = recorder
            .connection_for(hello)
            .and_then(|connection| connection.closed)
            .is_some();
        if visitor_closed_after.is_some() && target_closed {
            break;
        }
        if started.elapsed() >= MEASUREMENT_CAP {
            break;
        }
    }

    let connection = recorder.connection_for(hello);
    let target_accepted_after = connection
        .as_ref()
        .map(|connection| connection.accepted.saturating_duration_since(started));
    let target_received = connection.as_ref().map_or(0, |c| c.total_received);
    let target_close = connection.and_then(|connection| connection.closed);
    Measured {
        label,
        visitor_closed_after,
        target_closed_after: target_close
            .as_ref()
            .map(|close| close.at.saturating_duration_since(started)),
        target_accepted_after,
        target_received,
        expected_hello_bytes: hello.len(),
        target_close_reason: target_close.map(|close| close.reason),
        bytes_back_to_visitor,
        observed_for: started.elapsed(),
    }
}

fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("ZRAY_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_env("ZRAY_TEST_LOG")
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
                )
                .with_test_writer()
                .try_init();
        }
    });
}

fn spawn_zray(config: Value) -> Arc<zero_runtime::Server> {
    init_logging();
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

/// Measure both servers' fallback session lifetime in one run, in parallel,
/// and print what was actually observed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; measures a real 300 s idle limit (about six minutes)"]
async fn the_fallback_session_lifetime_is_measured_on_both_servers() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    let version = oracle_version(&binary);

    // The camouflage target both servers fall back to. It only has to hold the
    // socket and notice when the server takes it away; the servers' start-up
    // shape probes fail as TLS here, which is tolerated by design.
    let recorder = RecordingTarget::start().await;

    // One keypair and one realitySettings block for both servers, so a
    // difference in lifetimes cannot be a difference in the settings.
    let (private_key, _public_key) = oracle_x25519_keypair(&binary);
    let reality = reality_server_settings(&private_key, recorder.address);

    let oracle_port = free_port();
    let mut oracle = ServerProcess::spawn_named(
        &binary,
        vless_reality_server_config_with(oracle_port, reality.clone()),
        "fallback-lifetime-oracle",
    );
    let oracle_address = SocketAddr::from(([127, 0, 0, 1], oracle_port));
    assert!(
        wait_for(oracle_address).await,
        "the official REALITY server never listened:\n{}",
        oracle.tail(20)
    );

    let zray_port = free_port();
    let _zray = spawn_zray(vless_reality_server_config_with(zray_port, reality));
    let zray_address = SocketAddr::from(([127, 0, 0, 1], zray_port));
    assert!(
        wait_for(zray_address).await,
        "this port's REALITY server never listened"
    );

    // Two hellos, so each visitor's flow is identifiable at the target even
    // though both servers share one recorder.
    let oracle_hello = visitor_client_hello();
    let zray_hello = visitor_client_hello();
    assert_ne!(
        oracle_hello, zray_hello,
        "the two synthetic ClientHellos are identical, so the target could not tell \
         the two fallback flows apart"
    );

    let mut oracle_visitor = TcpStream::connect(oracle_address)
        .await
        .expect("the official server accepts the visitor");
    let mut zray_visitor = TcpStream::connect(zray_address)
        .await
        .expect("this port accepts the visitor");
    oracle_visitor
        .set_nodelay(true)
        .expect("TCP_NODELAY on the visitor");
    zray_visitor
        .set_nodelay(true)
        .expect("TCP_NODELAY on the visitor");

    // Both visitors say their piece and then nothing, forever. The clock that
    // both lifetimes are measured against starts the moment they are silent.
    oracle_visitor
        .write_all(&oracle_hello)
        .await
        .expect("the visitor's ClientHello reaches the official server");
    zray_visitor
        .write_all(&zray_hello)
        .await
        .expect("the visitor's ClientHello reaches this port");
    oracle_visitor
        .flush()
        .await
        .expect("the visitor's ClientHello is on the wire");
    zray_visitor
        .flush()
        .await
        .expect("the visitor's ClientHello is on the wire");
    let silence_started = Instant::now();

    eprintln!("oracle: {version}");
    eprintln!(
        "recording target at {} (dest for both servers); visitors sent their full \
         ClientHello and went silent at +0.000 s",
        recorder.address
    );

    // The fallback must actually have happened before the lifetime means
    // anything: both visitors' exact hello bytes must show up at the target.
    let seen_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let oracle_seen = recorder.connection_for(&oracle_hello).is_some();
        let zray_seen = recorder.connection_for(&zray_hello).is_some();
        if oracle_seen && zray_seen {
            break;
        }
        if Instant::now() >= seen_deadline {
            panic!(
                "the fallback never reached the recording target within 30 s \
                 (official seen: {oracle_seen}, this port seen: {zray_seen}); the \
                 unauthenticated visitor was not relayed.\nThe target saw:\n{}",
                recorder.describe(silence_started)
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    eprintln!(
        "the recording target received both visitors' ClientHellos (official {} bytes, this \
         port {} bytes); measuring lifetimes (cap {:.0} s)",
        oracle_hello.len(),
        zray_hello.len(),
        MEASUREMENT_CAP.as_secs_f64()
    );

    let (oracle_measured, zray_measured) = tokio::join!(
        measure(
            "the official server",
            oracle_visitor,
            &recorder,
            &oracle_hello,
            silence_started,
        ),
        measure(
            "this port",
            zray_visitor,
            &recorder,
            &zray_hello,
            silence_started,
        ),
    );

    for measured in [&oracle_measured, &zray_measured] {
        eprintln!("{}", measured.summary());
        if let Some(reason) = &measured.target_close_reason {
            eprintln!("  target's view of the close: {reason}");
        }
    }

    // The harness's own preconditions, before the lifetimes: both flows really
    // were fallbacks that reached the silent target, and the target (which
    // never writes) sent nothing back.
    for measured in [&oracle_measured, &zray_measured] {
        assert!(
            measured.target_accepted_after.is_some(),
            "{}: the visitor's ClientHello reached no connection at the target, so there \
             is no fallback session to time",
            measured.label
        );
        assert_eq!(
            measured.target_received, measured.expected_hello_bytes,
            "{}: the target did not receive the whole ClientHello the visitor sent ({} of {} \
             bytes), so the relayed flow under measurement is not the visitor's",
            measured.label, measured.target_received, measured.expected_hello_bytes
        );
        assert_eq!(
            measured.bytes_back_to_visitor, 0,
            "{}: the target sent bytes back to the visitor, but this recorder never writes; \
             the harness is not the silent target it claims",
            measured.label
        );
    }

    // This port: the §9 claim's own half. It must close at its idle limit, and
    // on both ends.
    for (side, closed_after) in [
        ("visitor side", zray_measured.visitor_closed_after),
        ("target side", zray_measured.target_closed_after),
    ] {
        let closed_after = closed_after.unwrap_or_else(|| {
            panic!(
                "this port's fallback session was never closed on the {side} within the \
                 {} s cap; its idle limit is {} s.\n{}",
                MEASUREMENT_CAP.as_secs(),
                CLAIMED_IDLE_LIMIT.as_secs(),
                zray_measured.summary()
            )
        });
        assert!(
            (LIFETIME_FLOOR..=LIFETIME_CEILING).contains(&closed_after),
            "this port closed its fallback session on the {side} at +{:.3} s, outside \
             the {}–{} s band around its {} s idle limit.\n{}",
            closed_after.as_secs_f64(),
            LIFETIME_FLOOR.as_secs(),
            LIFETIME_CEILING.as_secs(),
            CLAIMED_IDLE_LIMIT.as_secs(),
            zray_measured.summary()
        );
    }

    // The official server: whichever of the two documented behaviours was
    // observed, with the numbers in the verdict. Both are a pass for the
    // measurement; only a third behaviour (an early or one-sided close) is not.
    let verdict = match (
        oracle_measured.visitor_closed_after,
        oracle_measured.target_closed_after,
    ) {
        (Some(visitor), Some(target)) => {
            assert!(
                (LIFETIME_FLOOR..=LIFETIME_CEILING).contains(&visitor),
                "the official server closed the fallback on the visitor side at +{:.3} s, \
                 neither ~{} s (its inbound policy) nor open at the {} s cap (unbounded).\n{}",
                visitor.as_secs_f64(),
                CLAIMED_IDLE_LIMIT.as_secs(),
                MEASUREMENT_CAP.as_secs(),
                oracle_measured.summary()
            );
            assert!(
                (LIFETIME_FLOOR..=LIFETIME_CEILING).contains(&target),
                "the official server closed the fallback on the target side at +{:.3} s, \
                 neither ~{} s (its inbound policy) nor open at the {} s cap (unbounded).\n{}",
                target.as_secs_f64(),
                CLAIMED_IDLE_LIMIT.as_secs(),
                MEASUREMENT_CAP.as_secs(),
                oracle_measured.summary()
            );
            format!(
                "the official server closes the fallback too, at ~{} s (visitor +{:.3} s, \
                 target +{:.3} s) — its inbound policy or its own relay limit reaches the \
                 fallback path, so §9 item 9's claimed divergence does not survive \
                 measurement in steady state",
                CLAIMED_IDLE_LIMIT.as_secs(),
                visitor.as_secs_f64(),
                target.as_secs_f64(),
            )
        }
        (None, None) => format!(
            "the official server's fallback was still open at the {:.0} s cap on both \
             ends (this port closed at ~{:.0} s) — it copies until one side closes, as \
             §9 item 9 claims, so the divergence survives measurement",
            MEASUREMENT_CAP.as_secs_f64(),
            CLAIMED_IDLE_LIMIT.as_secs_f64(),
        ),
        (visitor, target) => panic!(
            "the official server's fallback closed on one side only within the {} s cap: \
             visitor {}, target {}.\n{}",
            MEASUREMENT_CAP.as_secs(),
            at(visitor),
            at(target),
            oracle_measured.summary()
        ),
    };
    eprintln!("VERDICT for docs/specs/REALITY-server.md §9 item 9: {verdict}");
}
