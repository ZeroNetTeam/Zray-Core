//! Throughput and latency measurements against a real Psiphon server.
//!
//! Performance is a requirement for this crate, so it is measured rather than
//! assumed. These tests dial the real `psiphond` in the local harness, open a
//! channel to a payload server that runs *inside the test* (so the
//! measurement is the tunnel, not the origin), and report throughput,
//! time-to-first-byte and how throughput scales with concurrent streams.
//!
//! Run with:
//!
//! ```text
//! ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry.json \
//!   cargo test -p zero-psiphon --release --test throughput -- --ignored --nocapture
//! ```
//!
//! Numbers from an optimised build (`--release`) are the ones worth comparing;
//! a debug build spends its time in unoptimised crypto and tells you nothing.
//! `ZERO_PSIPHON_BENCH_BYTES` sets the payload size per stream (default 8 MiB)
//! and `ZERO_PSIPHON_BENCH_STREAMS` the concurrency (default 4).

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zero_psiphon::client::Client;
use zero_psiphon::config::ClientConfig;
use zero_psiphon::protocol::TunnelProtocol;
use zero_psiphon::server_entry::ServerEntry;

fn server_entry() -> Option<ServerEntry> {
    let path = std::env::var("ZERO_PSIPHON_SERVER_ENTRY").ok()?;
    let text = std::fs::read_to_string(&path).ok()?;
    ServerEntry::from_json(&text).ok()
}

fn payload_bytes() -> usize {
    std::env::var("ZERO_PSIPHON_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8 * 1024 * 1024)
}

fn streams() -> usize {
    std::env::var("ZERO_PSIPHON_BENCH_STREAMS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4)
}

/// A payload server that answers any request with `bytes` bytes as fast as it
/// can. It runs on the test's own loopback port, so what is measured between
/// the tunnel's far end and the client is the tunnel.
async fn payload_server(bytes: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Read the request head, then answer with a body of exactly
                // `bytes` bytes and close.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }

                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                // A fixed 64 KiB chunk, reused: the server should not be the
                // bottleneck in any way.
                let chunk = vec![0x5au8; 64 * 1024];
                let mut remaining = bytes;
                while remaining > 0 {
                    let take = remaining.min(chunk.len());
                    if stream.write_all(&chunk[..take]).await.is_err() {
                        return;
                    }
                    remaining -= take;
                }
                let _ = stream.flush().await;
            });
        }
    });

    address
}

/// Download `bytes` through one tunnel stream and return (duration,
/// time-to-first-byte).
async fn download(
    client: &Client,
    target: std::net::SocketAddr,
    bytes: usize,
) -> (Duration, Duration) {
    let started = Instant::now();
    let mut stream = client
        .dial(&target.ip().to_string(), target.port())
        .await
        .expect("the tunnel opens a channel");

    stream
        .write_all(b"GET /payload HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
        .await
        .expect("writing the request");

    // Read the response head first, so time-to-first-byte is not confused with
    // body transfer time.
    let mut received = Vec::with_capacity(bytes + 4096);
    let mut buffer = vec![0u8; 256 * 1024];
    let mut first_byte = None;
    loop {
        let read = stream.read(&mut buffer).await.expect("reading the body");
        if read == 0 {
            break;
        }
        if first_byte.is_none() {
            first_byte = Some(started.elapsed());
        }
        received.extend_from_slice(&buffer[..read]);
    }
    let elapsed = started.elapsed();

    let body = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .expect("the response has a header terminator");
    assert_eq!(
        received.len() - body,
        bytes,
        "the whole payload arrived, with no truncation"
    );

    (elapsed, first_byte.unwrap_or(elapsed))
}

/// One protocol, sequentially and concurrently.
async fn measure(entry: &ServerEntry, protocol: TunnelProtocol) {
    let bytes = payload_bytes();
    let streams = streams();
    let target = payload_server(bytes).await;

    let config = ClientConfig {
        server_entries: vec![entry.clone()],
        protocols: vec![protocol],
        establish_timeout: Duration::from_secs(20),
        ..Default::default()
    };

    let started = Instant::now();
    let client = Client::connect(config)
        .await
        .unwrap_or_else(|error| panic!("{protocol}: connecting: {error}"));
    let establishment = started.elapsed();
    assert_eq!(client.protocol().await, Some(protocol));

    let (elapsed, first_byte) = download(&client, target, bytes).await;
    let megabits = (bytes as f64 * 8.0) / 1_000_000.0;
    println!(
        "{protocol:<9} sequential  {:.1} MiB in {:.2?} -> {:.1} Mbit/s, first byte {:.1?}, established in {:.0?}",
        bytes as f64 / (1024.0 * 1024.0),
        elapsed,
        megabits / elapsed.as_secs_f64(),
        first_byte,
        establishment,
    );

    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let client = &client;
        tasks.push(async move { download(client, target, bytes).await });
    }
    // The client's dial path serialises on one mutex, so these interleave the
    // way concurrent Zray connections do rather than opening in parallel.
    let results = futures::future::join_all(tasks).await;
    let elapsed = started.elapsed();
    let total = bytes * streams;
    println!(
        "{protocol:<9} concurrent  {streams} x {:.1} MiB in {:.2?} -> {:.1} Mbit/s (aggregate)",
        bytes as f64 / (1024.0 * 1024.0),
        elapsed,
        (total as f64 * 8.0) / 1_000_000.0 / elapsed.as_secs_f64(),
    );
    for (elapsed, first_byte) in &results {
        println!(
            "{protocol:<9}   stream      {:.2?} transfer, {:.1?} first byte",
            elapsed, first_byte
        );
    }

    client.close().await;
}

#[tokio::test]
#[ignore = "needs the local psiphon-server harness; run with --release"]
async fn throughput_against_the_real_server() {
    let Some(entry) = server_entry() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to measure");
        return;
    };

    println!(
        "\npayload: {} MiB per stream, {} concurrent streams\n",
        payload_bytes() / (1024 * 1024),
        streams()
    );

    for protocol in [
        TunnelProtocol::Ssh,
        TunnelProtocol::Ossh,
        TunnelProtocol::TlsOssh,
    ] {
        measure(&entry, protocol).await;
    }
}
