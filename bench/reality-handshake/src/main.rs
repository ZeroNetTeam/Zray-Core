//! What a REALITY handshake costs the *server*: the official Xray binary
//! against this workspace's REALITY server, measured the same way for both.
//!
//! The claim this exists to test is that Zray's REALITY server is "identical
//! to the original but faster and more efficient". `crates/reality` is proved
//! identical elsewhere — `zero-runtime/tests/xray_oracle.rs` drives Xray's
//! client against it and compares bytes and traffic. Nothing measured it.
//! This does, on loopback, with one client for every server and hundreds of
//! handshakes per server.
//!
//! What is measured, exactly: open a TCP connection to the server, complete
//! the REALITY handshake (a TLS 1.3 handshake whose certificate check is an
//! HMAC under the server's X25519 key), and stop. That boundary is the same
//! for every row, and it is the client's side of it, because that is the only
//! thing both a separate process and an in-process server can be asked.
//!
//! What is not measured: VLESS or Trojan framing, Vision, multiplexing, any
//! payload at all, and any kind of throughput. A REALITY handshake is crypto
//! and syscalls — X25519, HKDF, Ed25519, AES-GCM, and a handful of reads and
//! writes — so the numbers are a *cost per connection* for a server facing
//! many clients, not something a user on a real link would notice.
//!
//! Three servers are measured, because only two of them can be compared
//! fairly:
//!
//! * `xray` — the official binary, VLESS + REALITY inbound, camouflage site
//!   behind it.
//! * `zray` — this workspace's binary, started on the *same config file*.
//! * `zray-inproc` — `reality::handshake_or_fallback` on a loopback listener
//!   inside this process, which isolates the handshake from everything a
//!   runtime does around it. Its CPU is not separable from the client's, and
//!   the report says so rather than guessing.
//!
//! It refuses to print a comparison it cannot stand behind: if a handshake
//! failed, if a server died, if the two runs did not happen under comparable
//! CPU conditions, or if a server was never proved to carry traffic, the
//! output says that instead of the number.
//!
//! Run with `cargo run --release -p reality-handshake-bench`. Environment:
//!
//! * `ZRAY_XRAY_BINARY` — the Xray binary (default: `xray` on `PATH`).
//! * `ZRAY_BINARY` — the Zray binary (default: `target/release/zray`).
//! * `REALITY_BENCH_ROUNDS` (default 3), `REALITY_BENCH_N` (default 200, the
//!   number of handshakes in each round), `REALITY_BENCH_WARMUP` (default 30).
//! * `REALITY_BENCH_MLDSA=1` — put Xray's ML-DSA-65 binding on both sides,
//!   which is a different, much heavier handshake.

#[path = "../../../crates/zero-runtime/tests/reality_support/mod.rs"]
mod support;

mod client;
mod proc;
mod server;
mod stats;

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use client::{Bytes, Client};
use server::{Cpu, Extras, Outcomes, Row};
use stats::Summary;
use support::{REALITY_SHORT_ID, REALITY_SNI};

/// Handshakes per round per server. The floor the harness is written to is
/// 200: enough that a nearest-rank p99 is not simply the maximum, and long
/// enough that the clock's resolution is irrelevant.
const DEFAULT_PER_ROUND: usize = 200;
/// Rounds per server, interleaved, so drift hits every row equally.
const DEFAULT_ROUNDS: usize = 3;
/// Handshakes thrown away before measuring: a server's first connections pay
/// for cold page faults, cold caches and a first-time session setup, and none
/// of that is what the table is about.
const DEFAULT_WARMUP: usize = 30;
/// A machine busier than this fraction of its CPUs is busy enough that the
/// latencies may be the neighbours' scheduling rather than the server's work.
const BUSY_FRACTION: f64 = 0.5;
/// How far apart two rows' machine-busyness may be before the comparison is
/// called unfair even if both are below the limit above.
const BUSY_SPREAD_LIMIT: f64 = 0.15;
/// How far apart the two external servers' *client*-side CPU per handshake may
/// be before the run is called incomparable. The client is the same code in
/// both rows, so a spread here means the conditions differed, not the servers.
const CLIENT_CPU_TOLERANCE: f64 = 0.25;

/// One round against one server.
struct Round {
    latencies_ms: Vec<f64>,
    bytes: Vec<Bytes>,
    wall: Duration,
    server_cpu: Option<Duration>,
    client_cpu: Option<Duration>,
    load_before: Option<f64>,
    load_after: Option<f64>,
    /// `(busy, total)` machine jiffies before and after the round.
    machine_before: Option<(u64, u64)>,
    machine_after: Option<(u64, u64)>,
    failures: Vec<String>,
}

impl Round {
    fn new() -> Self {
        Self {
            latencies_ms: Vec::new(),
            bytes: Vec::new(),
            wall: Duration::ZERO,
            server_cpu: None,
            client_cpu: None,
            load_before: None,
            load_after: None,
            machine_before: None,
            machine_after: None,
            failures: Vec::new(),
        }
    }

}

/// Everything measured against one server.
struct Measured {
    name: &'static str,
    note: String,
    version: String,
    resident_bytes: Option<u64>,
    /// What the camouflage site said it sends after a handshake (in-process
    /// row only; the two binaries ask the site themselves).
    shapes: Option<String>,
    /// What the in-process server did with the *measured* handshakes, counted
    /// between two snapshots so warm-up and pre-flight connections are not
    /// confused with them.
    outcomes: Option<Outcomes>,
    rounds: Vec<Round>,
    cpu_measured: bool,
    /// Whether the server process was still running when the rounds ended.
    alive: bool,
    preflight: Option<Result<(), String>>,
    /// p50 of a bare TCP connect to this server, measured once before the
    /// rounds: the floor under every latency in the table.
    connect_floor_ms: Option<f64>,
}

impl Measured {
    fn handshakes(&self) -> usize {
        self.rounds.iter().map(|round| round.latencies_ms.len()).sum()
    }

    fn wall(&self) -> Duration {
        self.rounds.iter().map(|round| round.wall).sum()
    }

    fn handshakes_per_second(&self) -> f64 {
        let wall = self.wall().as_secs_f64();
        if wall <= 0.0 {
            return 0.0;
        }
        self.handshakes() as f64 / wall
    }

    /// Every latency from every round as one sample: the headline numbers.
    fn pooled(&self) -> Summary {
        Summary::of(
            self.rounds
                .iter()
                .flat_map(|round| round.latencies_ms.iter().copied())
                .collect(),
        )
    }

    /// Per-round medians, whose spread is how the harness notices that the
    /// rounds disagreed with each other.
    fn p50_by_round(&self) -> Vec<f64> {
        self.rounds
            .iter()
            .filter(|round| !round.latencies_ms.is_empty())
            .map(|round| Summary::of(round.latencies_ms.clone()).p50)
            .collect()
    }

    fn mean_bytes_per_handshake(&self) -> (u64, u64) {
        let sent: u64 = self
            .rounds
            .iter()
            .flat_map(|round| round.bytes.iter())
            .map(|bytes| bytes.sent)
            .sum();
        let read: u64 = self
            .rounds
            .iter()
            .flat_map(|round| round.bytes.iter())
            .map(|bytes| bytes.read)
            .sum();
        let count = self.handshakes().max(1) as u64;
        (sent / count, read / count)
    }

    fn cpu_per_handshake(&self, which: Which) -> Option<f64> {
        if which == Which::Server && !self.cpu_measured {
            return None;
        }
        if self.handshakes() == 0 {
            return None;
        }
        let mut total = 0.0;
        let mut seen = 0usize;
        for round in &self.rounds {
            let value = match which {
                Which::Server => round.server_cpu,
                Which::Client => round.client_cpu,
            };
            if let Some(value) = value {
                total += value.as_secs_f64();
                seen += 1;
            }
        }
        if seen != self.rounds.len() || seen == 0 {
            return None;
        }
        Some(total / self.handshakes() as f64)
    }

    /// How busy the machine was while this row was measured.
    fn machine_busy(&self) -> Option<f64> {
        let mut busy = 0u64;
        let mut total = 0u64;
        for round in &self.rounds {
            let (Some((busy_before, total_before)), Some((busy_after, total_after))) =
                (round.machine_before, round.machine_after)
            else {
                continue;
            };
            busy += busy_after.saturating_sub(busy_before);
            total += total_after.saturating_sub(total_before);
        }
        if total == 0 {
            return None;
        }
        Some(busy as f64 / total as f64)
    }

    fn failures(&self) -> Vec<String> {
        self.rounds
            .iter()
            .flat_map(|round| round.failures.iter().cloned())
            .collect()
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Which {
    Server,
    Client,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let rounds = env_usize("REALITY_BENCH_ROUNDS", DEFAULT_ROUNDS);
    let per_round = env_usize("REALITY_BENCH_N", DEFAULT_PER_ROUND);
    let warmup = env_usize("REALITY_BENCH_WARMUP", DEFAULT_WARMUP);
    let mldsa = std::env::var_os("REALITY_BENCH_MLDSA").is_some();
    if per_round < 200 {
        eprintln!(
            "reality-handshake: {per_round} handshakes per round is below the 200 this harness is \
             written for; a p99 over {per_round} samples is the second-slowest sample. Refusing."
        );
        std::process::exit(2);
    }

    let xray_binary = match support::oracle_binary() {
        Ok(binary) => binary,
        Err(reason) => {
            eprintln!("reality-handshake: {reason}");
            std::process::exit(2);
        }
    };
    let zray_binary = match zray_binary() {
        Ok(binary) => binary,
        Err(reason) => {
            eprintln!("reality-handshake: {reason}");
            std::process::exit(2);
        }
    };
    let xray_version = support::oracle_version(&xray_binary);
    let zray_version = zray_version(&zray_binary);

    // The camouflage site: a real TLS 1.3 server for the decoy name, so both
    // implementations are asked about a site that behaves like one.
    let decoy_port = support::free_port();
    // The ML-DSA-65 certificate is ~3.5 KB, and Xray's REALITY server shapes
    // its own flight to the sizes it reads from the camouflage site, so that
    // binding needs a decoy big enough to shape against — the same reason the
    // oracle test's ML-DSA case uses the large fixture.
    let mut decoy = if mldsa {
        support::spawn_decoy_with(
            &xray_binary,
            decoy_port,
            support::BIG_DECOY_CERTIFICATE,
            support::BIG_DECOY_PRIVATE_KEY,
        )
    } else {
        support::spawn_decoy(&xray_binary, decoy_port)
    };
    let decoy_address = SocketAddr::from(([127, 0, 0, 1], decoy_port));
    if !support::wait_for(decoy_address).await {
        eprintln!(
            "reality-handshake: the camouflage site never listened on {decoy_address}\n{}",
            decoy.tail(20)
        );
        std::process::exit(2);
    }

    // One keypair, from the oracle's own generator, for every server: the
    // comparison is worthless if Xray and Zray are not given the same key.
    let (private_key, public_key) = support::oracle_x25519_keypair(&xray_binary);
    let public_key = match decode_base64(&public_key, "the X25519 public key") {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        }
        Ok(bytes) => {
            eprintln!(
                "reality-handshake: the X25519 public key is {} bytes, not 32",
                bytes.len()
            );
            std::process::exit(2);
        }
        Err(reason) => {
            eprintln!("reality-handshake: {reason}");
            std::process::exit(2);
        }
    };

    let mut extras = Extras::default();
    let mut mldsa_verify: Option<Box<[u8]>> = None;
    if mldsa {
        let (seed, verify) = oracle_mldsa65_keypair(&xray_binary);
        mldsa_verify = match decode_base64(&verify, "the ML-DSA-65 verify key") {
            Ok(bytes) => Some(bytes.into_boxed_slice()),
            Err(reason) => {
                eprintln!("reality-handshake: {reason}");
                std::process::exit(2);
            }
        };
        extras.mldsa65_seed = Some(seed);
    }

    // The client every row is measured with: Zray's REALITY client, default
    // parameters, one object reused for every server.
    let params = zero_security::RealityParams::from_config_with_fingerprint_and_mldsa(
        Arc::from(REALITY_SNI),
        public_key,
        &support::reality_short_id(),
        zero_security::fingerprint::FingerprintProfile::Chrome,
        mldsa_verify,
    );
    let client = Client::new(SocketAddr::from(([127, 0, 0, 1], 0)), params.clone());

    // ---- the servers -----------------------------------------------------

    let xray_port = support::free_port();
    let zray_port = support::free_port();
    let mut rows = vec![
        Row::xray(
            &xray_binary,
            xray_port,
            &private_key,
            decoy_address,
            extras.clone(),
        ),
        Row::zray_binary(
            &zray_binary,
            zray_port,
            &private_key,
            decoy_address,
            extras.clone(),
        ),
    ];

    let mut settings = support::reality_server_settings(&private_key, decoy_address);
    if let Some(seed) = &extras.mldsa65_seed {
        settings["mldsa65Seed"] = serde_json::json!(seed);
    }
    let server_config = match reality::RealityServerConfig::from_xray_settings(&settings) {
        Ok(config) => config,
        Err(reason) => {
            eprintln!("reality-handshake: the realitySettings block was refused: {reason}");
            std::process::exit(2);
        }
    };
    let (in_process, shapes) = match server::InProcessServer::start(
        server_config.server_params(),
        Some(decoy_address),
        REALITY_SNI,
    )
    .await
    {
        Ok(server) => server,
        Err(reason) => {
            eprintln!("reality-handshake: {reason}");
            std::process::exit(2);
        }
    };
    rows.push(Row::zray_in_process(in_process, shapes));

    // Every external server has to be listening before anything is measured.
    let mut fatal: Vec<String> = Vec::new();
    for row in rows.iter_mut().filter(|row| row.is_external()) {
        let (name, address) = (row.name, row.address);
        if !support::wait_for(address).await {
            let tail = row.log_tail(20);
            fatal.push(format!(
                "the {name} server never listened on {address}\n{tail}"
            ));
        }
    }
    if !fatal.is_empty() {
        for reason in &fatal {
            eprintln!("reality-handshake: {reason}");
        }
        std::process::exit(2);
    }

    // ---- what this run is -------------------------------------------------

    println!("reality-handshake: the REALITY server side, Xray against Zray");
    println!();
    println!(
        "machine      {} CPUs, load average {} at start",
        proc::cpu_count(),
        match proc::load_average() {
            Some(load) => format!("{load:.2}"),
            None => "unknown".into(),
        }
    );
    println!("xray         {xray_version}  ({xray_binary})");
    println!("zray         {zray_version}  ({zray_binary})");
    println!(
        "in-process   reality crate: handshake_or_fallback on a loopback listener, inside this process"
    );
    println!("decoy        Xray serving TLS 1.3 for {REALITY_SNI} on {decoy_address}");
    println!("config       VLESS over TCP under REALITY; one config file, given to both binaries");
    println!(
        "             serverNames [{REALITY_SNI:?}], shortIds [{REALITY_SHORT_ID:?}], key from `xray x25519`"
    );
    println!(
        "             ML-DSA-65 binding: {}",
        if mldsa {
            "on (mldsa65Seed / mldsa65Verify)"
        } else {
            "off"
        }
    );
    println!(
        "client       Zray's REALITY client (zero_security::reality_connect), Chrome fingerprint, hybrid KEM offered: {}",
        params.hybrid_kem
    );
    println!("             the same client and the same parameters for every row");
    println!("boundary     TCP connect + REALITY/TLS 1.3 handshake, completed on the client side");
    println!("not measured VLESS/Trojan framing, Vision, mux, payload, throughput");
    println!("warm-up      {warmup} handshakes per server, discarded");
    println!("measured     {rounds} rounds x {per_round} handshakes per server, sequential, rounds interleaved");

    // ---- is each server really a proxy? -----------------------------------

    println!();
    println!("pre-flight (once per server, not part of any number below):");
    let echo = support::echo_service().await;
    let mut preflight: Vec<Result<(), String>> = Vec::new();
    for row in rows.iter() {
        let client_here = client.clone_for(row.address);
        let outcome = if row.server_accepts_vless() {
            client_here.vless_round_trip(echo, &support::UUID_BYTES).await
        } else {
            // No VLESS layer in the in-process row: the handshake is the whole
            // of it, so a completed handshake is what can be checked.
            client_here
                .handshake()
                .await
                .map(|_| ())
                .map_err(|error| format!("{error} (handshake only: this row has no VLESS layer)"))
        };
        match &outcome {
            Ok(()) => println!(
                "  {:<12} ok      {}",
                row.name,
                if row.server_accepts_vless() {
                    "one VLESS request sent, the payload echoed back"
                } else {
                    "handshake completed"
                }
            ),
            Err(reason) => println!("  {:<12} FAILED  {reason}", row.name),
        }
        preflight.push(outcome);
    }

    // ---- the floor under the table ---------------------------------------

    println!();
    let mut floors: Vec<Option<f64>> = Vec::new();
    for row in rows.iter() {
        let floor = connect_floor(row.address, 50).await;
        match floor {
            Some(p50) => print!("  floor: bare TCP connect to {:<12} p50 {p50:.3} ms    ", row.name),
            None => print!("  floor: bare TCP connect to {:<12} failed            ", row.name),
        }
        let _ = std::io::stdout().flush();
        floors.push(floor);
    }
    println!();

    // ---- warm up ----------------------------------------------------------

    for row in rows.iter() {
        let mut failures = 0;
        for _ in 0..warmup {
            if let Err(reason) = client.clone_for(row.address).handshake().await {
                failures += 1;
                if failures == 1 {
                    println!(
                        "  warm-up: a handshake to {} failed: {reason}",
                        row.name
                    );
                }
            }
        }
        if failures == 0 {
            print!("  warm-up: {} {warmup} handshakes, 0 failures     ", row.name);
            let _ = std::io::stdout().flush();
        }
    }
    println!();

    // ---- measure ----------------------------------------------------------

    // The server counts an accepted handshake when its own side finishes, which
    // can be a moment after the client's future resolves. Let the last of the
    // warm-up land before the tally that the rounds are measured against.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let in_process_before = rows.iter().find_map(Row::outcomes);
    let mut measured: Vec<Measured> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| Measured {
            name: row.name,
            note: row.note.clone(),
            version: row.version.clone(),
            resident_bytes: row.resident_bytes,
            shapes: row.shapes.as_ref().map(server::Shapes::note),
            outcomes: None,
            rounds: Vec::with_capacity(rounds),
            cpu_measured: matches!(row.cpu, Cpu::Process(_)),
            alive: true,
            preflight: None,
            connect_floor_ms: floors[index],
        })
        .collect();

    println!();
    for round_index in 0..rounds {
        for (index, row) in rows.iter().enumerate() {
            let round = measure_round(&client, row, per_round).await;
            measured[index].rounds.push(round);
            print!(
                "\r  measuring round {}/{rounds} for {:<12}",
                round_index + 1,
                row.name
            );
            let _ = std::io::stdout().flush();
        }
    }
    println!("\r{:80}", "");

    tokio::time::sleep(Duration::from_millis(300)).await;
    for (index, row) in rows.iter_mut().enumerate() {
        measured[index].preflight = Some(preflight[index].clone());
        measured[index].alive = row.alive().unwrap_or(true);
        if let Some(outcomes) = row.outcomes() {
            measured[index].outcomes = Some(match &in_process_before {
                // Only the measured handshakes, not the warm-up and pre-flight
                // ones that share the same counter.
                Some(before) => Outcomes {
                    accepted: outcomes.accepted.saturating_sub(before.accepted),
                    fell_back: outcomes.fell_back.saturating_sub(before.fell_back),
                    rejected: outcomes.rejected.saturating_sub(before.rejected),
                    first_complaint: outcomes.first_complaint.clone(),
                },
                None => outcomes,
            });
        }
    }

    // ---- report -----------------------------------------------------------

    println!();
    println!("{}", servers_section(&measured));
    println!();
    println!("{}", table(&measured, rounds, per_round));
    println!();
    println!("{}", comparison(&measured));
    println!();
    println!("{}", machine_readable(&measured, rounds, per_round));
    println!();
    println!("caveats");
    println!(
        "  everything above is loopback: work per connection for a server facing many clients,"
    );
    println!(
        "  not what one client on a real link sees, where the round trips dominate."
    );
    println!(
        "  A handshake costs crypto and syscalls (X25519, HKDF, Ed25519, AES-GCM, a few reads and"
    );
    println!(
        "  writes), not throughput; nothing here carries a payload through the tunnel."
    );
    println!(
        "  zray-inproc's server runs in this process, so its CPU is mixed with the client's and is"
    );
    println!("  reported as such rather than separated.");

    let mut decoy_ok = decoy.is_running();
    let checks = check(&mut measured, rounds, per_round, &mut decoy_ok);
    println!();
    if checks.is_empty() {
        println!("checks       passed");
    } else {
        println!("checks       {} failed:", checks.len());
        for check in &checks {
            println!("  - {check}");
        }
        println!();
        println!(
            "reality-handshake: this run is NOT a result. The comparison above must not be quoted; \
             fix what failed and run it again."
        );
    }
    drop(rows);
    let _ = decoy.tail(1);

    if !checks.is_empty() {
        std::process::exit(1);
    }
}

/// Do `count` handshakes against `row`, one connection each, and hand back
/// everything that can be said about them.
async fn measure_round(client: &Client, row: &Row, count: usize) -> Round {
    let mut round = Round::new();
    let client_here = client.clone_for(row.address);

    let server_cpu_before = row.cpu_now();
    let client_cpu_before = proc::self_cpu();
    round.load_before = proc::load_average();
    round.machine_before = proc::machine_jiffies();

    let started = Instant::now();
    for _ in 0..count {
        let at = Instant::now();
        match client_here.handshake().await {
            Ok(bytes) => {
                round
                    .latencies_ms
                    .push(at.elapsed().as_secs_f64() * 1000.0);
                round.bytes.push(bytes);
            }
            Err(reason) => {
                if round.failures.len() < 5 {
                    round.failures.push(reason);
                }
                // Stop rather than measure a server that is refusing
                // connections: the checks report what happened.
                break;
            }
        }
    }
    round.wall = started.elapsed();

    let server_cpu_after = row.cpu_now();
    let client_cpu_after = proc::self_cpu();
    round.server_cpu = match (server_cpu_before, server_cpu_after) {
        (Some(before), Some(after)) => Some(after.saturating_sub(before)),
        _ => None,
    };
    round.client_cpu = match (client_cpu_before, client_cpu_after) {
        (Some(before), Some(after)) => Some(after.saturating_sub(before)),
        _ => None,
    };
    round.load_after = proc::load_average();
    round.machine_after = proc::machine_jiffies();
    round
}

/// p50 of a bare loopback TCP connect to `address`, repeated `count` times:
/// what an empty connection costs, so a reader can tell how much of a
/// handshake latency is the machine rather than the handshake.
async fn connect_floor(address: SocketAddr, count: usize) -> Option<f64> {
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let at = Instant::now();
        match tokio::net::TcpStream::connect(address).await {
            Ok(_) => samples.push(at.elapsed().as_secs_f64() * 1000.0),
            Err(_) => return None,
        }
    }
    Some(Summary::of(samples).p50)
}

/// Versions, what each row is, and what it costs to keep running.
fn servers_section(measured: &[Measured]) -> String {
    let mut out = String::from("servers\n");
    for row in measured {
        out.push_str(&format!("  {:<12} {}\n", row.name, row.version));
        out.push_str(&format!("  {:<12} {}\n", "", row.note));
        match row.resident_bytes {
            Some(bytes) => out.push_str(&format!(
                "  {:<12} resident {:.1} MB (context only, not a handshake claim)\n",
                "",
                bytes as f64 / (1024.0 * 1024.0)
            )),
            None => out.push_str(&format!(
                "  {:<12} resident: shares this process\n",
                ""
            )),
        }
        if let Some(shapes) = &row.shapes {
            out.push_str(&format!(
                "  {:<12} camouflage site's post-handshake records: {shapes}\n",
                ""
            ));
        }
        if row.handshakes() > 0 {
            let summary = row.pooled();
            out.push_str(&format!(
                "  {:<12} {} handshakes, fastest {:.3} ms, slowest {:.3} ms\n",
                "", summary.count, summary.min, summary.max
            ));
        }
        if let Some(busy) = row.machine_busy() {
            out.push_str(&format!(
                "  {:<12} machine CPU busy while this row ran: {:.1}% (all work, not just ours)\n",
                "",
                busy * 100.0
            ));
        }
        if let Some(floor) = row.connect_floor_ms {
            out.push_str(&format!(
                "  {:<12} bare TCP connect, p50: {floor:.3} ms (the floor under the latencies above)\n",
                ""
            ));
        }
        if !row.p50_by_round().is_empty() {
            out.push_str(&format!(
                "  {:<12} per-round p50: {:?}\n",
                "",
                row.p50_by_round()
                    .iter()
                    .map(|value| format!("{value:.3} ms"))
                    .collect::<Vec<_>>()
            ));
        }
    }
    out
}

/// The markdown table, exactly as `docs/benchmarks/reality-handshake.md`
/// carries it.
fn table(measured: &[Measured], rounds: usize, per_round: usize) -> String {
    let mut out = String::from(
        "| server | handshakes/s | mean | p50 | p99 | server CPU per handshake | client CPU per handshake | bytes per handshake (sent/read) |\n\
         |---|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    let cell = |value: f64| {
        if value.is_finite() {
            format!("{value:.3} ms")
        } else {
            "n/a".into()
        }
    };
    for row in measured {
        let server_cpu = match row.cpu_per_handshake(Which::Server) {
            Some(seconds) => format!("{:.3} ms", seconds * 1e3),
            None => "_not separable_".into(),
        };
        let client_cpu = match row.cpu_per_handshake(Which::Client) {
            Some(seconds) if row.cpu_measured => format!("{:.3} ms", seconds * 1e3),
            // The in-process server runs on this process's threads, so this
            // number is the client *and* the server together.
            Some(seconds) => format!("{:.3} ms (includes the server)", seconds * 1e3),
            None => "n/a".into(),
        };
        let (sent, read) = row.mean_bytes_per_handshake();
        if row.handshakes() == 0 {
            out.push_str(&format!(
                "| {} | _not measured_ | n/a | n/a | n/a | {server_cpu} | {client_cpu} | n/a |\n",
                row.name
            ));
            continue;
        }
        let summary = row.pooled();
        out.push_str(&format!(
            "| {} | {:.0} | {} | {} | {} | {server_cpu} | {client_cpu} | {sent} / {read} |\n",
            row.name,
            row.handshakes_per_second(),
            cell(summary.mean),
            cell(summary.p50),
            cell(summary.p99),
        ));
    }
    let n = measured.iter().map(Measured::handshakes).max().unwrap_or(0);
    let rank = ((0.99 * n as f64).ceil() as usize).max(1);
    out.push_str(&format!(
        "\nLatency is nearest-rank over all {n} handshakes per server ({rounds} rounds x {per_round});\n\
         the p99 is sample {rank}, not an interpolation. handshakes/s is {n} handshakes over the\n\
         measured wall clock of those {rounds} rounds, which includes the client's own connect and\n\
         bookkeeping — the same for every row.",
    ));
    out
}

/// The side-by-side lines, and how far apart the two are.
fn comparison(measured: &[Measured]) -> String {
    let find = |name: &str| measured.iter().find(|row| row.name == name);
    let (Some(xray), Some(zray)) = (find("xray"), find("zray")) else {
        return "comparison   n/a".into();
    };
    if xray.handshakes() == 0 || zray.handshakes() == 0 {
        return "comparison   not printed: one of the servers produced no handshakes".into();
    }

    let line = |label: &str,
                xray_value: f64,
                zray_value: f64,
                unit: &str,
                lower_is_better: bool|
     -> String {
        let ratio = if xray_value > 0.0 {
            zray_value / xray_value
        } else {
            f64::NAN
        };
        let verdict = if !ratio.is_finite() {
            "n/a".to_string()
        } else if (ratio < 1.0) == lower_is_better {
            format!("zray {:.0}% lower", (1.0 - ratio).abs() * 100.0)
        } else {
            format!("xray {:.0}% lower", (ratio - 1.0).abs() * 100.0)
        };
        let verdict = if lower_is_better {
            verdict
        } else {
            verdict.replace("lower", "higher")
        };
        format!("  {label:<22} xray {xray_value:>10.3} {unit}    zray {zray_value:>10.3} {unit}    {verdict}\n")
    };

    let mut out = String::from("comparison\n");
    out.push_str(&line(
        "handshakes/s",
        xray.handshakes_per_second(),
        zray.handshakes_per_second(),
        "1/s",
        false,
    ));
    out.push_str(&line(
        "mean latency",
        xray.pooled().mean,
        zray.pooled().mean,
        "ms",
        true,
    ));
    out.push_str(&line(
        "p50 latency",
        xray.pooled().p50,
        zray.pooled().p50,
        "ms",
        true,
    ));
    out.push_str(&line(
        "p99 latency",
        xray.pooled().p99,
        zray.pooled().p99,
        "ms",
        true,
    ));
    match (
        xray.cpu_per_handshake(Which::Server),
        zray.cpu_per_handshake(Which::Server),
    ) {
        (Some(xray_cpu), Some(zray_cpu)) => out.push_str(&line(
            "server CPU/handshake",
            xray_cpu * 1e3,
            zray_cpu * 1e3,
            "ms",
            true,
        )),
        _ => out.push_str("  server CPU/handshake   not comparable\n"),
    }
    // Both of these are separate processes, so their "client CPU" is the
    // client alone and comparable; the in-process row is not in this table.
    match (
        xray.cpu_per_handshake(Which::Client),
        zray.cpu_per_handshake(Which::Client),
    ) {
        (Some(xray_cpu), Some(zray_cpu)) => out.push_str(&line(
            "client CPU/handshake",
            xray_cpu * 1e3,
            zray_cpu * 1e3,
            "ms",
            true,
        )),
        _ => out.push_str("  client CPU/handshake   not comparable\n"),
    }
    out
}

/// The lines a script can read: one JSON object per server, then the run's.
fn machine_readable(measured: &[Measured], rounds: usize, per_round: usize) -> String {
    let mut out = String::new();
    for row in measured {
        let (mean, p50, p99) = match row.handshakes() {
            0 => (0.0, 0.0, 0.0),
            _ => {
                let summary = row.pooled();
                (summary.mean, summary.p50, summary.p99)
            }
        };
        let number = |value: Option<f64>| match value {
            Some(value) => format!("{:.6}", value * 1e3),
            None => "null".into(),
        };
        let (sent, read) = row.mean_bytes_per_handshake();
        out.push_str(&format!(
            "reality-handshake: {{\"server\":\"{}\",\"rounds\":{rounds},\"n_per_round\":{per_round},\"handshakes\":{},\"handshakes_per_sec\":{:.1},\"mean_ms\":{mean:.4},\"p50_ms\":{p50:.4},\"p99_ms\":{p99:.4},\"server_cpu_ms_per_handshake\":{},\"client_cpu_ms_per_handshake\":{},\"cpu_shared_with_server\":{},\"bytes_sent_per_handshake\":{sent},\"bytes_read_per_handshake\":{read},\"failures\":{}}}\n",
            row.name,
            row.handshakes(),
            row.handshakes_per_second(),
            number(row.cpu_per_handshake(Which::Server)),
            number(row.cpu_per_handshake(Which::Client)),
            !row.cpu_measured,
            row.failures().len(),
        ));
    }
    out.push_str(&format!(
        "reality-handshake: {{\"verdict\":\"{}\",\"loopback\":true,\"measures\":\"reality+tls13-handshake\",\"client\":\"zray-reality-client\",\"server_config\":\"vless-tcp-reality\",\"mldsa65\":{}}}",
        if measured.iter().all(|row| row.failures().is_empty()) {
            "ok"
        } else {
            "failed"
        },
        std::env::var_os("REALITY_BENCH_MLDSA").is_some(),
    ));
    out
}

/// Everything that must hold before the comparison can be trusted.
fn check(
    measured: &mut [Measured],
    rounds: usize,
    per_round: usize,
    decoy_alive: &mut bool,
) -> Vec<String> {
    let mut failures = Vec::new();
    let expected = rounds * per_round;

    for row in measured.iter() {
        for reason in row.failures().iter().take(3) {
            failures.push(format!("{}: a handshake failed: {reason}", row.name));
        }
        if row.handshakes() < expected && row.failures().is_empty() {
            failures.push(format!(
                "{}: only {} of {expected} handshakes were measured",
                row.name,
                row.handshakes()
            ));
        }
        if !row.alive {
            failures.push(format!("{}: the server was not running at the end", row.name));
        }
        if let Some(Err(reason)) = &row.preflight {
            failures.push(format!(
                "{}: the pre-flight failed, so this server was never proved to carry traffic: {reason}",
                row.name
            ));
        }
        if let Some(outcomes) = &row.outcomes {
            if outcomes.fell_back > 0 || outcomes.rejected > 0 {
                failures.push(format!(
                    "{}: the in-process server did not accept every measured handshake ({} accepted, {} fell back, {} rejected): {}",
                    row.name,
                    outcomes.accepted,
                    outcomes.fell_back,
                    outcomes.rejected,
                    outcomes.first_complaint.clone().unwrap_or_default()
                ));
            }
            if outcomes.accepted as usize != expected {
                failures.push(format!(
                    "{}: the in-process server accepted {} handshakes during the measured rounds, expected {expected}",
                    row.name, outcomes.accepted
                ));
            }
        }
    }

    // The client is the same object in every row, so the bytes it sends must
    // be the same in every row. If they are not, the rows were not the same
    // experiment.
    let sent: Vec<u64> = measured
        .iter()
        .filter(|row| row.handshakes() > 0)
        .map(|row| row.mean_bytes_per_handshake().0)
        .collect();
    if sent.len() > 1 {
        let smallest = *sent.iter().min().unwrap_or(&0) as f64;
        let largest = *sent.iter().max().unwrap_or(&0) as f64;
        // The ClientHello is sealed per connection and its padding varies by a
        // handful of bytes run to run; a systematic difference is what would
        // mean the rows were different experiments.
        if smallest > 0.0 && (largest - smallest) / smallest > 0.01 {
            failures.push(format!(
                "the client sent a different number of bytes per handshake to different servers ({sent:?}), by more than the hello's own run-to-run padding, so the rows were not the same experiment"
            ));
        }
    }

    // The rounds must agree with each other, or the machine moved under the
    // measurement.
    for row in measured.iter() {
        if row.rounds.len() < 2 || row.handshakes() == 0 {
            continue;
        }
        let p50s = row.p50_by_round();
        if stats::spread(&p50s) > 0.5 {
            failures.push(format!(
                "{}: the rounds disagreed with each other (per-round p50 {p50s:?}), so the machine was not steady while it was measured",
                row.name
            ));
        }
    }

    // Comparable CPU conditions. The question is not whether the machine was
    // idle — it is shared, and the rounds are interleaved so that any background
    // work falls on every row — but whether the two servers were measured under
    // the *same* conditions, and whether the machine was too busy for either.
    let busy_by_row: Vec<(&str, f64)> = measured
        .iter()
        .filter(|row| row.handshakes() > 0)
        .filter_map(|row| row.machine_busy().map(|busy| (row.name, busy)))
        .collect();
    for (name, busy) in &busy_by_row {
        if *busy > BUSY_FRACTION {
            failures.push(format!(
                "the machine was {:.0}% busy with other work while the {name} row ran, over the {:.0}% this harness accepts, so those latencies may be the neighbours' scheduling rather than the server's work",
                busy * 100.0,
                BUSY_FRACTION * 100.0
            ));
        }
    }
    if let (Some(quietest), Some(busiest)) = (
        busy_by_row.iter().map(|(_, busy)| *busy).reduce(f64::min),
        busy_by_row.iter().map(|(_, busy)| *busy).reduce(f64::max),
    ) {
        if busiest - quietest > BUSY_SPREAD_LIMIT {
            failures.push(format!(
                "the machine's background load differed between rows ({:?}), so the two servers did not run under comparable CPU conditions",
                busy_by_row
                    .iter()
                    .map(|(name, busy)| format!("{name} {:.0}%", busy * 100.0))
                    .collect::<Vec<_>>()
            ));
        }
    }
    let external: Vec<&Measured> = measured
        .iter()
        .filter(|row| row.cpu_measured && row.handshakes() > 0)
        .collect();
    if external.len() == 2 {
        if let (
            Some(left),
            Some(right),
        ) = (
            external[0].cpu_per_handshake(Which::Client),
            external[1].cpu_per_handshake(Which::Client),
        ) {
            let spread = if left > right {
                (left - right) / left
            } else {
                (right - left) / right
            };
            if spread > CLIENT_CPU_TOLERANCE {
                failures.push(format!(
                    "the client's own CPU per handshake differed by {:.0}% between the {} and {} rows ({:.3} ms vs {:.3} ms) — the same client code on both sides of the table, so the runs did not happen under comparable conditions",
                    spread * 100.0,
                    external[0].name,
                    external[1].name,
                    left * 1e3,
                    right * 1e3
                ));
            }
        }
    }

    if !*decoy_alive {
        failures.push("the camouflage site did not survive the run".into());
    }
    failures
}

/// The Zray binary: the one this workspace builds, unless told otherwise.
fn zray_binary() -> Result<String, String> {
    if let Some(path) = std::env::var_os("ZRAY_BINARY") {
        let path = path.to_string_lossy().into_owned();
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
        return Err(format!("ZRAY_BINARY points at {path}, which does not exist"));
    }
    let built = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/zray");
    if built.exists() {
        return Ok(built.to_string_lossy().into_owned());
    }
    match std::process::Command::new("zray").arg("version").output() {
        Ok(output) if output.status.success() => Ok("zray".into()),
        _ => Err(format!(
            "no Zray binary: build one with `cargo build --release -p zray-cli` (looked for {})",
            built.display()
        )),
    }
}

fn zray_version(binary: &str) -> String {
    std::process::Command::new(binary)
        .arg("version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| {
            text.lines()
                .find(|line| !line.trim().is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into())
}

/// A key in the encodings `xray x25519` and `xray mldsa65` print: unpadded
/// URL-safe base64, or the standard alphabet.
fn decode_base64(text: &str, what: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(text.trim()))
        .map_err(|error| format!("{what} is not base64: {error}"))
}

/// The ML-DSA-65 pair, from the oracle's own `mldsa65` command.
fn oracle_mldsa65_keypair(binary: &str) -> (String, String) {
    let output = std::process::Command::new(binary)
        .arg("mldsa65")
        .output()
        .expect("the oracle binary should be able to generate an ML-DSA-65 keypair");
    assert!(output.status.success(), "`{binary} mldsa65` failed");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|rest| rest.trim().to_string())
            .unwrap_or_else(|| panic!("no {name} line in:\n{text}"))
    };
    (field("Seed:"), field("Verify:"))
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{name}={value:?} is not a number")),
        Err(_) => default,
    }
}

impl Client {
    fn clone_for(&self, address: SocketAddr) -> Client {
        Client {
            address,
            params: self.params.clone(),
        }
    }
}
