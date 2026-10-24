//! The REALITY server's tolerance for records that advance nothing — the
//! port's against the camouflage site's, and against the official server's.
//!
//! A TLS 1.3 peer may send records that carry no information — an empty
//! application-data record, a compatibility ChangeCipherSpec, a warning
//! alert — and Go's `crypto/tls` counts them *consecutively*, closing the
//! connection once the run passes `MaxUselessRecords`. REALITY makes that
//! count part of its camouflage: the listener asks the site it borrows its
//! name from how many of them the site tolerates, so an observer cannot tell
//! the REALITY listener from the site by spamming no-ops at both
//! (`RL/record_detect.go:137-185`, `RL/tls.go:425-427`).
//!
//! The port's read path used to answer with a bound of its own — 256
//! records — where the site answered with its own, which is a measurable
//! difference a prober could use. This test is the measurement that was
//! missing. It:
//!
//! 1. asks the camouflage site, with the port's own probe, how many useless
//!    records it tolerates (Go's runs: two, then seventeen, then
//!    thirty-three);
//! 2. drives a REALITY client at the port that completes the handshake,
//!    sends exactly that many empty application-data records, and then asks
//!    the server to carry a VLESS request to an echo service — and asserts
//!    the request gets through;
//! 3. repeats with one more record and asserts the connection is closed;
//! 4. measures the *official* server the same way and records what it
//!    answers, because the two answers differ and the difference is named in
//!    `docs/specs/REALITY-server.md` §5.
//!
//! ```bash
//! ZRAY_XRAY_BINARY=/usr/bin/xray \
//!   cargo test -p zero-runtime --test reality_useless_records \
//!   -- --ignored --test-threads=1
//! ```
//!
//! The port learns the site's answer at start-up over three ALPN buckets
//! (`ZR/server.rs::learn_post_handshake`), and a connection that arrives
//! before the bucket has been measured goes on the default. The test waits
//! for the learning to settle before it measures, and the wait is a poll of
//! the behaviour itself rather than a sleep: the edge is the observable.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[path = "reality_support/mod.rs"]
mod reality_support;

use reality_support::{
    echo_service, free_port, oracle_binary, oracle_version, oracle_x25519_keypair,
    reality_short_id, spawn_decoy, vless_reality_server_config, wait_for, ServerProcess,
    REALITY_SNI, UUID_BYTES,
};

/// The wire length of one empty application-data record: five header bytes,
/// one inner content-type byte, a padding run and the AEAD tag. Any length at
/// or above 22 is well formed; 69 is the one the unit tests use.
const EMPTY_RECORD_WIRE_LEN: u16 = 69;

/// Go's `maxUselessRecords` in the REALITY fork (`RL/common.go:70`): the
/// bound the official server answers with when it has not been told the
/// site's, and so the number a run past it must close at.
const GO_DEFAULT_BUDGET: usize = 32;

/// What came back after the run of useless records.
#[derive(Debug)]
enum Outcome {
    /// The echo payload arrives: the run of useless records was tolerated and
    /// the connection still carried a tunnel request.
    Carried,
    /// The connection was closed or went silent after the handshake: the
    /// server gave up on the run of useless records. The string says what the
    /// client saw, so a failure report can tell a close from a timeout.
    Refused(String),
}

impl Outcome {
    fn is_carried(&self) -> bool {
        matches!(self, Outcome::Carried)
    }

    fn describe(&self) -> &str {
        match self {
            Outcome::Carried => "carried",
            Outcome::Refused(reason) => reason,
        }
    }
}

/// One REALITY handshake, a run of empty records, and a VLESS request to
/// `target` under it — in that order, so that the records that advance
/// nothing are the only ones the server has to count.
async fn budget_run(
    server: SocketAddr,
    public_key: &str,
    target: SocketAddr,
    empties: usize,
) -> Outcome {
    let key = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key)
            .expect("the oracle's public key is base64url")
            .try_into()
            .expect("the oracle's public key is 32 bytes")
    };
    let params =
        zero_security::RealityParams::from_config(Arc::from(REALITY_SNI), key, &reality_short_id());
    let tcp = TcpStream::connect(server)
        .await
        .unwrap_or_else(|error| panic!("the REALITY server never listened on {server}: {error}"));
    let mut stream = zero_security::reality_connect(tcp, &params)
        .await
        .unwrap_or_else(|error| panic!("the REALITY handshake was refused: {error}"));
    if empties > 0 {
        let run = vec![EMPTY_RECORD_WIRE_LEN; empties];
        stream
            .queue_empty_records(&run)
            .expect("the empty records fit the record layer");
        if let Err(error) = stream.flush().await {
            return Outcome::Refused(format!("the run of empty records failed to flush: {error}"));
        }
    }
    let payload = b"the budget is the site's".to_vec();
    if let Err(error) = stream.write_all(&vless_request(target, &payload)).await {
        return Outcome::Refused(format!("the VLESS request failed to write: {error}"));
    }
    if let Err(error) = stream.flush().await {
        return Outcome::Refused(format!("the VLESS request failed to flush: {error}"));
    }
    let read = async {
        // A VLESS server answers with its two-byte response header before any
        // payload: version 0, no addons.
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header != [0, 0] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected VLESS response header {header:?}"),
            ));
        }
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await?;
        Ok::<_, std::io::Error>(echoed)
    };
    match tokio::time::timeout(Duration::from_secs(5), read).await {
        Ok(Ok(echoed)) if echoed == payload => Outcome::Carried,
        Ok(Ok(echoed)) => Outcome::Refused(format!("the echo came back altered: {echoed:?}")),
        Ok(Err(error)) => Outcome::Refused(format!(
            "the run of empty records ended the tunnel: {error}"
        )),
        Err(_) => Outcome::Refused("the server went silent instead of answering".into()),
    }
}

fn vless_request(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 16 + payload.len());
    out.push(zero_protocol::vless::VERSION);
    out.extend_from_slice(&UUID_BYTES);
    out.push(0); // no addons
    out.push(zero_protocol::vless::CMD_TCP);
    out.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        IpAddr::V4(ip) => {
            out.push(zero_protocol::vless::ADDR_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(zero_protocol::vless::ADDR_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(payload);
    out
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

/// The camouflage site's own tolerance, asked the way the port asks it: Go's
/// runs of compatibility ChangeCipherSpec records, the run that draws the
/// site's objection naming its bound (`RL/record_detect.go:137-185`).
async fn site_budget(decoy: SocketAddr) -> u64 {
    zero_security::tls13::ccs_probe::probe_budget(
        || async move {
            TcpStream::connect(decoy).await.map_err(|error| {
                zero_core::Failure::new(
                    zero_core::FailureKind::TcpRefused,
                    zero_core::Stage::SocketConnected,
                )
                .with_detail(error.to_string())
            })
        },
        REALITY_SNI,
    )
    .await
    .unwrap_or_else(|| {
        panic!("the site at {decoy} never answered how many useless records it tolerates")
    })
}

/// Wait until the port has learned the site's answer for the bucket this
/// client uses, then return. The learning is asynchronous by design: a
/// connection that beats it goes on the default, and this test measures the
/// boundary on purpose, so it waits for the boundary to be the learned one.
async fn wait_until_learned(server: SocketAddr, public_key: &str, echo: SocketAddr, site: u64) {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let at_edge = budget_run(server, public_key, echo, site as usize).await;
        let past_edge = budget_run(server, public_key, echo, site as usize + 1).await;
        if at_edge.is_carried() && !past_edge.is_carried() {
            return;
        }
        if Instant::now() > deadline {
            panic!(
                "the port never put the site's {site}-record answer on the bucket this client \
                 uses: at the edge it {}, one past it it {}",
                at_edge.describe(),
                past_edge.describe()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn the_useless_record_budget_is_the_sites() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!(
        "oracle: {} (REALITY useless-record budget)",
        oracle_version(&binary)
    );

    let echo = echo_service().await;
    let (private_key, public_key) = oracle_x25519_keypair(&binary);
    let decoy_port = free_port();
    let mut decoy = spawn_decoy(&binary, decoy_port);
    let decoy_address = SocketAddr::from(([127, 0, 0, 1], decoy_port));
    assert!(
        wait_for(decoy_address).await,
        "the camouflage site never listened:\n{}",
        decoy.tail(20)
    );

    // The site's answer, measured before any REALITY server starts asking it:
    // this is the number the port has to answer with.
    let site = site_budget(decoy_address).await;
    eprintln!("the camouflage site tolerates {site} useless records");
    assert!(
        site >= 1 && site < GO_DEFAULT_BUDGET as u64,
        "this decoy's answer ({site}) is not the interesting one: the test needs a site that \
         tolerates fewer records than Go's default, or the port's answer cannot be told from \
         the default"
    );

    // The official server, on the same camouflage site.
    let oracle_port = free_port();
    let mut oracle = ServerProcess::spawn_named(
        &binary,
        vless_reality_server_config(oracle_port, &private_key, decoy_address),
        "useless-oracle",
    );
    let oracle_address = SocketAddr::from(([127, 0, 0, 1], oracle_port));
    assert!(
        wait_for(oracle_address).await,
        "the oracle REALITY server never listened:\n{}",
        oracle.tail(20)
    );

    // The port, told exactly what the oracle was told.
    let zray_port = free_port();
    let _zray = spawn_zray(vless_reality_server_config(
        zray_port,
        &private_key,
        decoy_address,
    ));
    let zray_address = SocketAddr::from(([127, 0, 0, 1], zray_port));
    assert!(
        wait_for(zray_address).await,
        "the Zray REALITY server never listened"
    );

    // A control with no useless records at all: a tunnel that does not work
    // would make the edge measurements meaningless.
    for (name, server) in [("official", oracle_address), ("port", zray_address)] {
        let control = budget_run(server, &public_key, echo, 0).await;
        assert!(
            control.is_carried(),
            "the {name} server did not carry the control request: {}",
            control.describe()
        );
    }

    // The port's answer is the site's: a run of exactly `site` empty records
    // still carries the request, and one more ends the connection. This is
    // the assertion the old 256-record ceiling failed — and the old probe,
    // which only read the handshake's return value, failed too: it learned
    // "unlimited" and carried anything.
    wait_until_learned(zray_address, &public_key, echo, site).await;
    let at_edge = budget_run(zray_address, &public_key, echo, site as usize).await;
    let past_edge = budget_run(zray_address, &public_key, echo, site as usize + 1).await;
    assert!(
        at_edge.is_carried(),
        "the port refused a run of {site} useless records, the number its site tolerates: {}",
        at_edge.describe()
    );
    assert!(
        !past_edge.is_carried(),
        "the port carried a run of {} useless records although the site it claims to be \
         tolerates {site}; a prober can tell the two apart by that alone: {}",
        site + 1,
        past_edge.describe()
    );

    // The official server, measured the same way on the same site. It answers
    // with Go's default rather than the site's number: the REALITY fork only
    // applies the learned bound inside its wait-for-the-site's-shapes loop
    // (`RL/tls.go:396-421`), and that loop breaks without it as soon as the
    // shapes are already known — which they are here, because the official
    // server learns them at listener start. The port applies the site's answer
    // as soon as it has it. That is a difference, and it is recorded here so
    // it cannot rot: the port is the closer of the two to the site it borrows
    // its name from.
    let oracle_at_default = budget_run(oracle_address, &public_key, echo, GO_DEFAULT_BUDGET).await;
    let oracle_past_default =
        budget_run(oracle_address, &public_key, echo, GO_DEFAULT_BUDGET + 1).await;
    assert!(
        oracle_at_default.is_carried(),
        "the official server refused a run of {GO_DEFAULT_BUDGET} useless records, so it is not \
         on Go's default and the divergence this test records has changed: {}",
        oracle_at_default.describe()
    );
    assert!(
        !oracle_past_default.is_carried(),
        "the official server carried {} useless records; it is no longer on Go's default {} and \
         the divergence this test records has changed: {}",
        GO_DEFAULT_BUDGET + 1,
        GO_DEFAULT_BUDGET,
        oracle_past_default.describe()
    );
    eprintln!(
        "site tolerates {site}; the port answers with the site's {site}; the official server \
         answers with Go's default {GO_DEFAULT_BUDGET}"
    );
}
