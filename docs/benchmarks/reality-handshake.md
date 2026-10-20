# REALITY handshake: the server side, Zray vs Xray

The project says its REALITY server is "identical to the original but faster
and more efficient". The [main README](../../README.md) and
[`docs/benchmarks/`](README.md) already measure the *client*: throughput and
CPU per gigabyte through a tunnel. Nothing measured the *server*. This does,
for the one operation a REALITY server does that no proxy server did before:
authenticate a connection whose proof of identity is hidden inside a
ClientHello.

Measured on 2026-10-20 on the machine described below, with the harness in
[`bench/reality-handshake`](../../bench/reality-handshake).

## Setup

- **Xray** 26.3.27 (official `Xray-linux-64` release build, `d2758a0`,
  go1.26.1 linux/amd64) as the reference server.
- **Zray** 0.1.0, built with `cargo build --release -p zray-cli` — the shipped
  profile (`opt-level = "s"`, fat LTO), run as `zray run <config>`.
- **One config file, byte for byte the same, given to both binaries**: a VLESS
  inbound over TCP under REALITY (`serverNames www.googletagmanager.com`, one
  `shortIds` selector, an X25519 keypair from `xray x25519`), a freedom
  outbound, and an Xray-process camouflage site behind the REALITY inbound
  serving TLS 1.3 for the same name.
- **One client for both**: Zray's own REALITY client
  (`zero_security::reality_connect`), Chrome ClientHello, hybrid key share
  offered, the same parameters in every row. The client is in-process; the
  servers are separate processes (except the third row).
- 32-CPU Linux host, shared with other work, loopback only. The machine was
  7–8% busy with that other work while these rows ran, which the harness
  measures and checks rather than assumes.

Three rows, because only two of them can be compared fairly:

| row | server | CPU accounting |
|---|---|---|
| `xray` | the official Xray binary, VLESS + REALITY inbound | `/proc/<pid>/stat`, `utime + stime`, taken around each round |
| `zray` | Zray's own binary, same config file | same |
| `zray-inproc` | `reality::handshake_or_fallback` on a loopback listener inside the benchmark process | **not separable** — the server shares the process with the client, so no server CPU is reported for this row |

## What is measured

| Metric | How |
|---|---|
| handshakes/s | 200 handshakes per round, 3 rounds per server, rounds interleaved; handshakes ÷ measured wall clock |
| mean, p50, p99 latency | per handshake, nearest-rank over all 600 samples |
| server CPU per handshake | the server process's `utime + stime` before and after each round ÷ handshakes in it |
| client CPU per handshake | the harness's own CPU over the same window — a control, because it is the same client code in every row |
| bytes per handshake | counted on the client's socket, sent and read, until the handshake completes |

**The measured operation** is: open a TCP connection to the server, complete
the REALITY handshake — a TLS 1.3 handshake whose certificate check is an HMAC
under the server's X25519 key — and stop. It is measured from the client's
side, because that is the only boundary a separate process and an in-process
server can both be asked for. **30 warm-up handshakes per server are
discarded** before the rounds, and every success is an *authenticated*
handshake: a server that does not recognise the client relays it to the
camouflage site, which the client reports as a fallback error rather than as a
completed handshake.

**Before any number was taken**, each server was proved to be a working proxy:
one VLESS request was sent through the tunnel (`zray-inproc` has no VLESS
layer, so its pre-flight is the handshake itself) and the payload had to come
back. If a handshake fails, a server dies, the client sends a different
ClientHello to one server than another, the rounds disagree with each other, or
the two rows did not run under comparable CPU conditions, the harness lists the
failed check under the table, prints "this run is NOT a result" and the machine
readable line carries `"verdict":"failed"` — and it exits non-zero, so a script
that runs it cannot mistake one for a result.

## Results

Medians of 3 interleaved rounds of 200 handshakes per server (600 per server),
measured at commit `696e8e4` with the working tree as it stood (see
[repeatability](#repeatability) below):

| server | handshakes/s | mean | p50 | p99 | server CPU per handshake | client CPU per handshake | bytes per handshake (sent/read) |
|---|---:|---:|---:|---:|---:|---:|---:|
| xray | 458 | 2.185 ms | 2.024 ms | 3.168 ms | 0.800 ms | 0.467 ms | 1843 / 2511 |
| zray | **1284** | **0.779 ms** | **0.717 ms** | **1.262 ms** | **0.350 ms** | 0.450 ms | 1847 / 1681 |
| zray-inproc | 1125 | 0.889 ms | 0.825 ms | 1.589 ms | _not separable_ | 0.817 ms (includes the server) | 1844 / 1681 |

Raw machine-readable lines from that run:

```
reality-handshake: {"server":"xray","rounds":3,"n_per_round":200,"handshakes":600,"handshakes_per_sec":457.7,"mean_ms":2.1847,"p50_ms":2.0236,"p99_ms":3.1677,"server_cpu_ms_per_handshake":0.800000,"client_cpu_ms_per_handshake":0.466667,"cpu_shared_with_server":false,"bytes_sent_per_handshake":1843,"bytes_read_per_handshake":2511,"failures":0}
reality-handshake: {"server":"zray","rounds":3,"n_per_round":200,"handshakes":600,"handshakes_per_sec":1283.9,"mean_ms":0.7788,"p50_ms":0.7173,"p99_ms":1.2623,"server_cpu_ms_per_handshake":0.350000,"client_cpu_ms_per_handshake":0.450000,"cpu_shared_with_server":false,"bytes_sent_per_handshake":1847,"bytes_read_per_handshake":1681,"failures":0}
reality-handshake: {"server":"zray-inproc","rounds":3,"n_per_round":200,"handshakes":600,"handshakes_per_sec":1125.3,"mean_ms":0.8886,"p50_ms":0.8253,"p99_ms":1.5887,"server_cpu_ms_per_handshake":null,"client_cpu_ms_per_handshake":0.816667,"cpu_shared_with_server":true,"bytes_sent_per_handshake":1844,"bytes_read_per_handshake":1681,"failures":0}
reality-handshake: {"verdict":"ok","loopback":true,"measures":"reality+tls13-handshake","client":"zray-reality-client","server_config":"vless-tcp-reality","mldsa65":false}
```

The Zray server completed **2.8× the handshakes per second** of the Xray
server on the same config, with **2.3× less server CPU per handshake**, and its
latency was **64–65% lower** at the median and **60% lower** at the 99th
percentile. The two Zray rows landing in the same place (1284/s with the full
runtime, 1125/s for the bare handshake in-process) is the useful part of the
third row: the runtime around the handshake — listener, VLESS inbound, stats —
costs little, and the difference against Xray is in the handshake path itself,
not in the plumbing.

`bytes_sent_per_handshake` differs by a few bytes between rows (1843 / 1847 /
1844): the sealed ClientHello's padding varies run to run, and the harness
accepts that but fails the run if the rows differ by more than 1%.

## Why the gap is not only "the same work, done faster"

Both Zray rows read **1681** bytes per handshake; Xray's client read **2511** —
830 bytes more, before the client's handshake even completed. Those bytes are
the reason to read the CPU column carefully, and the project's own
[`docs/specs/REALITY-server.md`](../specs/REALITY-server.md) explains them:

- **Xray dials the camouflage site on every connection**
  (`xtls-reality` `tls.go` `Server()` dials `dest` before reading the
  ClientHello, and mirrors the client's bytes to it), so each of its handshakes
  includes a TCP connect to a second process and a read of that process's
  ServerHello. Zray's accepting path never touches the target; it learns the
  site's *post-handshake* record sizes once at start-up
  (`learn_post_handshake`, `zero_security::tls13::post_handshake::observe`).
- **Xray pads its first flight to the record sizes it just read from that
  site** (`conn.go` `handshakeLen` / the padding path). Zray seals its four
  messages back to back with no padding, which the spec calls "the largest
  remaining fingerprinting gap" of the port (§3, "Status: DIVERGENT on the
  wire shape, PORTED on the crypto").

So part of the measured advantage is that Zray does *less work per
connection*, and a reader comparing the two servers should know which part is
which. This benchmark cannot say whether that work buys anything a censor can
measure — that argument lives in the spec's §3 and §6, not here. The client's
own CPU also fell by 10% (0.533 → 0.483 ms) for the same reason: it reads 830
fewer bytes. A smaller flight is cheaper for both ends.

What is *not* a design difference, and is the bulk of the crypto: both servers
parse the same ClientHello, do X25519 (plus ML-KEM-768 when the hybrid share is
used), the same HKDF schedule, a per-connection Ed25519 sign, and one AES-GCM
seal of the same four messages. The Zray client authenticating against the Xray
server and the Xray client authenticating against the Zray server are both
covered by `zero-runtime/tests/xray_oracle.rs`, so the handshakes compared here
are the same handshake.

## With the ML-DSA-65 binding on, it is a tie

Xray 26.3.27 and Zray can both sign every handshake with ML-DSA-65 as well
(the server's `mldsa65Seed`, the client's `mldsa65Verify`). The harness measures
that configuration too (`REALITY_BENCH_MLDSA=1`, which also points both servers
at the larger camouflage fixture — the ML-DSA certificate is ~3.5 KB and Xray
shapes its flight to the sizes it reads from the site). Two runs, both passing
the harness's checks:

| run | server | handshakes/s | p50 | p99 | server CPU per handshake | bytes read per handshake |
|---|---|---:|---:|---:|---:|---:|
| A | xray | 543 | 1.788 ms | 2.762 ms | 1.267 ms | 6400 |
| A | zray | 525 | 1.800 ms | 3.770 ms | 1.283 ms | 5011 |
| B | xray | 555 | 1.752 ms | 2.743 ms | 1.283 ms | 6399 |
| B | zray | 560 | 1.627 ms | 3.885 ms | 1.217 ms | 5011 |

The 2.7× advantage of the base configuration **does not survive the binding**.
Throughput is level (the sign of the gap flips between runs), server CPU per
handshake is level (1.22–1.28 ms for both, against 0.35 ms for Zray and 0.78 ms
for Xray without the binding), and the median latency is level. What the binding
adds — around 0.9 ms of ML-DSA-65 signing and a ~3.5 KB certificate flight on
*both* sides — is the same work in both implementations, and it is enough to
bury the design differences that decided the first table.

One difference is consistent in both runs: Zray's **p99 is 37–42% worse**
(3.8 ms against 2.7 ms). With 600 samples a p99 is the sixth-slowest sample, so
this is a signal to investigate rather than a settled number; the harness prints
it, and `REALITY_BENCH_ROUNDS=10` would narrow it.

## What these numbers do not cover

- **Loopback.** Both servers were reached over `127.0.0.1`. A REALITY handshake
  costs crypto and syscalls — X25519, HKDF, Ed25519, AES-GCM, a few reads and
  writes — not throughput. On a real link a client notices the round trips, not
  this; the numbers are a *cost per connection* for a server facing many
  clients, and they say nothing about how many users a box can carry on a real
  network.
- **Sequential, one connection at a time.** No concurrency, no queueing, no
  session resumption, no TLS 1.2, no Vision, no VLESS framing, no payload, no
  mux. One connection per handshake, opened and dropped.
- **The in-process row has no CPU column**, because its server runs on the same
  process as the client; its "client CPU" is the two together and the table
  says so. Its latency is still comparable, and matched the standalone binary.
- **The machine was shared.** 6.6–8.2% of its CPUs were busy with other work
  during each row of the reported run (a later run at 30–34% is in the
  repeatability table), roughly equally for all three (the
  harness measures this from `/proc/stat` around every round and refuses to
  report if the rows differ by more than 15 points). The floor under the table is
  a bare TCP connect to the same server: 0.087 ms (xray), 0.050 ms (zray),
  0.052 ms (zray-inproc) at the median, and the client's own CPU per handshake
  differed between the two external rows by 4%, inside the harness's 25% limit —
  the same client code on both sides of the table.
- **The tree moved under the benchmark.** Other workstreams were editing
  `crates/reality` (the server) and `crates/zero-security/tls13` (the client's
  record layer) while these runs were taken; both binaries and the harness were
  rebuilt from the tree as it stood before each run, and the table is run 5. A
  published number from a repository with uncommitted work in it is a number for
  that revision, not for every revision — and a client-side change to the record
  layer can move the *client* column here without any server changing.
- **The p99 is sample 594 of 600**, nearest-rank, not an interpolation.
- **The shipped profile is `opt-level = "s"` with fat LTO**, not `-O3`; both
  binaries and the benchmark itself were built that way. A `-O3` Zray build
  would measure differently; this is the build that ships.
- **The main table has the ML-DSA-65 binding off**; the section above measures
  it, with the larger camouflage fixture that configuration needs. Two other
  configurations are not measured at all: a client that offers no hybrid
  X25519MLKEM768 share, and one that reuses a connection for many requests
  (there is no such thing here — every handshake is a new connection).

## Reproducing it

```sh
cargo build --release -p zray-cli            # the server under test
cargo build --release -p reality-handshake-bench
./target/release/reality-handshake-bench     # ~4 s; prints the table above
```

It needs `xray` on `PATH` (or `ZRAY_XRAY_BINARY`), and the Zray binary at
`target/release/zray` (or `ZRAY_BINARY`). `REALITY_BENCH_ROUNDS` (3),
`REALITY_BENCH_N` (200 — refused below 200, since a p99 over fewer samples is
just the second-slowest sample) and `REALITY_BENCH_WARMUP` (30) change the
workload.

The harness exits non-zero and says so when it cannot make the run fair: a
failed handshake, a server that died, rounds that disagreed with each other, a
client that sent different bytes to different servers, or two rows measured
under different machine load. Those runs are marked "NOT a result" and their
machine-readable line carries `"verdict":"failed"`.

