# The native Psiphon client: performance and memory

Status: measurements and the design decisions behind them, as of 2026-10-19.
Every number in §2 is either taken from a log in this repository or is
explicitly marked as not reproducible from the repository.

A note on line numbers: `crates/zero-psiphon` is being rewritten in
parallel with this document, so **symbol names, not line numbers, are the
stable anchors** there. The line numbers below are a snapshot taken on
2026-10-19.

Companion documents: [`ARCHITECTURE.md`](ARCHITECTURE.md) for what the crate
is and how it dials, [`WIRE-SPEC.md`](WIRE-SPEC.md) for the byte-level
protocol, [`INTEGRATION.md`](INTEGRATION.md) §8 for the *planned* performance
budget (which differs from the code in a few places — §3.7, §3.9 and §4.3
say where), and [`SERVER-HARNESS.md`](SERVER-HARNESS.md) for the harness.

---

## 0. The short version

The client is not the bottleneck. On loopback, against the real `psiphond`,
a single stream moves 8 MiB through the tunnel in 11–23 ms — 3.0–5.8 Gbit/s —
and the tunnel establishes in 7–10 ms. Those are **loopback** numbers: they
say that the client's framing, its window and its carrier are cheap enough
not to matter next to the kernel's loopback and the Go server's SSH
implementation. They say **nothing** about a real network, where the
round-trip time and the last mile dominate everything this crate does.

The two claims this document makes and the two it does not:

- **It does claim** that the client adds no per-connection cost that scales
  with the number of connections, because one SSH session carries many
  channels and one client is shared per configuration (§3).
- **It does not claim** any absolute throughput figure for a real network.
  No WAN measurement has been taken; §5 lists it as the first thing to do.

---

## 1. Reproducing the measurement

### 1.1 The script

```bash
.research/psiphon-server-harness/bench-rust.sh [payload-MiB] [streams]
```

`bench-rust.sh` (39 lines) does the whole thing in one shell: it stops any
running `psiphond`, starts a fresh one from
`.research/psiphon-server-harness/config/psiphond.config` with the SSH,
OSSH and TLS-OSSH listeners on 20081/20082/20083
(`bench-rust.sh:22-23`), waits for the listeners
(`bench-rust.sh:25-29`), runs the benchmark (`bench-rust.sh:31-35`) and tears
the server down again (`bench-rust.sh:38`).

The one-shell rule is not an accident: the script's own header explains that
"the sandbox kills background children when the shell exits, so server,
benchmark and teardown must share one invocation" (`bench-rust.sh:3-4`).

The defaults are 2 MiB per stream and 2 streams (`bench-rust.sh:10-11`); the
8 MiB / 4-stream run in §2 was made with
`./bench-rust.sh 8 4`.

The log lands in `.research/psiphon-server-harness/logs/bench-rust.log`, and
the server's own log in `logs/psiphond-bench.log`.

### 1.2 The environment variables

The script passes two variables through to the test
(`bench-rust.sh:31-33`):

| Variable | Meaning | Default |
|---|---|---|
| `ZERO_PSIPHON_BENCH_BYTES` | payload bytes per stream | 8 MiB (`tests/throughput.rs:37-42`) |
| `ZERO_PSIPHON_BENCH_STREAMS` | concurrent streams | 4 (`tests/throughput.rs:44-49`) |
| `ZERO_PSIPHON_SERVER_ENTRY` | the harness's signed server entry | required; the test does nothing without it (`tests/throughput.rs:31-35`) |

The script computes the byte count as `MIB * 1024 * 1024` and passes it
through verbatim (`bench-rust.sh:32-33`).

### 1.3 The test

`crates/zero-psiphon/tests/throughput.rs` drives it. It is `#[ignore]`d
(`tests/throughput.rs:210-212`) because it needs the harness, and the
test's own header is emphatic about the build profile: "Numbers from an
optimised build (`--release`) are the ones worth comparing; a debug build
spends its time in unoptimised crypto and tells you nothing"
(`tests/throughput.rs:16-17`). The script uses `--release`
(`bench-rust.sh:34`).

What the test measures, and what it deliberately does not:

- The **payload server runs inside the test**, on its own loopback port
  (`tests/throughput.rs:54-101`), and answers any request with a fixed
  number of bytes. The comment is explicit: "so what is measured between
  the tunnel's far end and the client is the tunnel"
  (`tests/throughput.rs:51-53`). The server writes in a reused 64 KiB chunk
  so that it cannot be the bottleneck (`tests/throughput.rs:84-86`).
- The **time to first byte** is measured separately from the transfer, by
  reading the response head first (`tests/throughput.rs:120-133`).
- The test **asserts that the whole payload arrived** with no truncation
  (`tests/throughput.rs:138-147`).
- The **establishment time** is measured around `Client::connect`
  (`tests/throughput.rs:165-169`).
- Each protocol is measured **sequentially first, then concurrently**
  (`tests/throughput.rs:172-207`).
- The concurrent streams **share one client**, and the test says why: "The
  client's dial path serialises on one mutex, so these interleave the way
  concurrent Zray connections do rather than opening in parallel"
  (`tests/throughput.rs:189-190`).

### 1.4 Running it by hand

```bash
cd .research/psiphon-server-harness
./setup.sh                      # once: build, generate keys, sign the entry
./bench-rust.sh 8 4
```

Or, with the server already running:

```bash
ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry.json \
  cargo test -p zero-psiphon --release --test throughput -- --ignored --nocapture
```

---

## 2. The measurements

### 2.1 The 8 MiB / 4-stream run

Release build, loopback, against the harness's `psiphond`, after the whole
feature set landed (meek, tactics, the shared client, the account
integration). This is the tail of
`.research/psiphon-server-harness/logs/bench-rust.log`, verbatim:

```
SSH sequential  8.0 MiB in 11.53ms -> 5818.7 Mbit/s, first byte 1.5ms, established in 10ms
SSH concurrent  4 x 8.0 MiB in 67.18ms -> 3995.8 Mbit/s (aggregate)
OSSH sequential  8.0 MiB in 17.77ms -> 3777.2 Mbit/s, first byte 897.8µs, established in 7ms
OSSH concurrent  4 x 8.0 MiB in 85.88ms -> 3125.6 Mbit/s (aggregate)
TLS-OSSH sequential  8.0 MiB in 22.50ms -> 2982.1 Mbit/s, first byte 727.1µs, established in 7ms
TLS-OSSH concurrent  4 x 8.0 MiB in 88.36ms -> 3037.8 Mbit/s (aggregate)
```

| Transport | sequential | aggregate (4 × 8 MiB) | establishment | first byte (sequential) |
|---|---|---|---|---|
| SSH | 5818.7 Mbit/s | 3995.8 Mbit/s | 10 ms | 1.5 ms |
| OSSH | 3777.2 Mbit/s | 3125.6 Mbit/s | 7 ms | 0.9 ms |
| TLS-OSSH | 2982.1 Mbit/s | 3037.8 Mbit/s | 7 ms | 0.7 ms |

Loopback runs vary with what else the machine is doing — the first run of
this benchmark, on an earlier revision of the same code, reported 2525 /
2465 / 3066 Mbit/s sequential — so read the three transports against each
other rather than against the absolute figures. What is stable across runs
is the shape: every transport moves gigabytes a second, and establishment
costs about ten milliseconds.

The earlier run in full, for comparison:

```
payload: 8 MiB per stream, 4 concurrent streams

SSH sequential  8.0 MiB in 26.58ms -> 2525.1 Mbit/s, first byte 1.0ms, established in 12ms
SSH concurrent  4 x 8.0 MiB in 130.96ms -> 2049.7 Mbit/s (aggregate)
SSH   stream      124.60ms transfer, 2.5ms first byte
SSH   stream      127.59ms transfer, 3.9ms first byte
SSH   stream      116.58ms transfer, 2.5ms first byte
SSH   stream      130.38ms transfer, 2.6ms first byte
OSSH sequential  8.0 MiB in 27.22ms -> 2465.1 Mbit/s, first byte 1.3ms, established in 9ms
OSSH concurrent  4 x 8.0 MiB in 144.30ms -> 1860.3 Mbit/s (aggregate)
OSSH   stream      141.90ms transfer, 3.1ms first byte
OSSH   stream      143.58ms transfer, 3.1ms first byte
OSSH   stream      144.01ms transfer, 3.2ms first byte
OSSH   stream      138.71ms transfer, 3.1ms first byte
TLS-OSSH sequential  8.0 MiB in 21.89ms -> 3065.6 Mbit/s, first byte 1.4ms, established in 10ms
TLS-OSSH concurrent  4 x 8.0 MiB in 118.40ms -> 2267.2 Mbit/s (aggregate)
TLS-OSSH   stream      105.20ms transfer, 6.1ms first byte
TLS-OSSH   stream      116.63ms transfer, 4.3ms first byte
TLS-OSSH   stream      118.11ms transfer, 6.2ms first byte
TLS-OSSH   stream       95.14ms transfer, 3.1ms first byte
```

Its table:

| Transport | sequential | aggregate (4 × 8 MiB) | establishment | first byte (sequential) |
|---|---|---|---|---|
| SSH | 2525.1 Mbit/s | 2049.7 Mbit/s | 12 ms | 1.0 ms |
| OSSH | 2465.1 Mbit/s | 1860.3 Mbit/s | 9 ms | 1.3 ms |
| TLS-OSSH | 3065.6 Mbit/s | 2267.2 Mbit/s | 10 ms | 1.4 ms |

The benchmark measures three transports, and only three: the test's
protocol list is fixed at SSH, OSSH and TLS-OSSH
(`tests/throughput.rs:224-230`). Meek is not in it, and should not be
compared on the same footing: it is HTTP request/response, so its
throughput is a function of how often the client polls and how large each
request body may be, not of a stream's window. Its correctness is covered
elsewhere — against the real `psiphond` in
`tests/meek.rs` (§10.3 of `SERVER-HARNESS.md` has the evidence).

Three observations, all of them about loopback rather than about the client:

**Concurrency does not help here.** Four streams together move 32 MiB in
131 ms (SSH), which is a *lower* aggregate than the 2525 Mbit/s a single
stream reaches. The four streams share one TCP connection and one SSH
session, and the loopback path between the client, the `psiphond` and the
in-test payload server is the constraint. The server agrees that the four
channels really were open at once: its `server_tunnel` event for that run
records `peak_concurrent_port_forward_count_tcp: 4` and
`total_port_forward_count_tcp: 5`
(`.research/psiphon-server-harness/logs/psiphond-bench.log`). So this is a
property of the path, not of the client.

**OSSH costs a little, and only a little.** Sequentially it is 2.4 % below
plain SSH (2465.1 against 2525.1 Mbit/s); in aggregate it is 9 % below
(1860.3 against 2049.7). The extra work is the RC4 pass over the key
exchange and the padding rewrite; after `NEWKEYS` the OSSH layer is a
pass-through (§3.4).

**TLS-OSSH is the fastest, which is expected.** TLS 1.3's AEAD is
hardware-accelerated, and the OSSH layer over it is the same pass-through.
It also costs the most to establish in the real world, because of the
additional round trips — invisible on loopback, obvious over a WAN.

### 2.2 The server's view of the same run

The harness's server log for the benchmark
(`.research/psiphon-server-harness/logs/psiphond-bench.log`) records what
the Go `psiphond` saw, and it is a useful cross-check on the framing
overhead:

| Transport | bytes down | SSH protocol bytes | framing overhead | server's OSSH padding |
|---|---|---|---|---|
| SSH | 41 943 840 | 42 141 582 | 197 742 (0.47 %) | — |
| OSSH | 41 943 840 | 42 149 672 | 205 832 (0.49 %) | 7 621 |
| TLS-OSSH | 41 943 840 | 42 146 156 | 202 316 (0.48 %) | 2 647 |

The overhead is the SSH packet framing — the length field, the padding and
the MAC — over 40 MiB of payload, and it is half a percent. The `downstream_ossh_padding`
column is the padding the *server* added to its own downstream packets.

### 2.3 The earlier 4 MiB / 2-stream run

An earlier run of the same benchmark, with 4 MiB per stream and 2
concurrent streams, gave:

| Transport | sequential |
|---|---|
| SSH | 3084 Mbit/s |
| OSSH | 3672 Mbit/s |
| TLS-OSSH | 3591 Mbit/s |

**These numbers are not reproducible from the repository.** The log of that
run was not kept — `logs/bench-rust.log` holds only the 8 MiB / 4-stream
run — and no other file in the repository contains them. They are recorded
here because they are the only other measurement that was taken, and because
they are worth comparing with the newer run: OSSH and TLS-OSSH came out
*faster* than plain SSH in that run, and slower in the newer one, which is
what one expects from a measurement whose payload is half the size and whose
absolute throughput is high enough for the run-to-run variance of a shared
machine to matter.

The honest reading is that the two runs agree on the order of magnitude
(2–4 Gbit/s) and disagree on the ordering of the transports, and that the
8 MiB / 4-stream run is the one with a log behind it.

### 2.4 What these numbers are not

They are **loopback** numbers. The client, the `psiphond` and the payload
server all run on the same machine, on the loopback interface, with no
packet loss, no reordering, no congestion control and a round-trip time of
microseconds. They therefore measure:

- the CPU cost of the client's framing and of the Go server's SSH
  implementation;
- the buffer sizes, insofar as a buffer is large enough to keep the
  pipeline full;
- nothing about the network.

They do **not** measure throughput on a real link, and they are not a
prediction of it. A 4 MiB channel window at 100 ms RTT is worth roughly
40 Mbit/s per channel by the bandwidth-delay-product rule, however fast the
client is; on a 10 Gbit/s WAN the limit is the link, and on a 100 Mbit/s
link it is the link. `INTEGRATION.md:1769-1771` makes the same point about
the Go client's 128 KiB window.

---

## 3. The design decisions behind the numbers

### 3.1 One tunnel, many channels

A Psiphon tunnel is an SSH session, and an SSH session carries many
`direct-tcpip` channels. `SshTunnel::open` (`tunnel.rs:378-393`) opens a
channel on an existing session; `Client::dial` (`client.rs:100-116`) opens
one on an existing tunnel. Nothing in the crate opens a second TCP
connection per destination.

This is the single most important decision for cost. Establishing a tunnel
is expensive — a TCP connection, an SSH key exchange, an authentication and
a tunnel handshake, several round trips (`shared.rs:1-7`) — and
multiplexing is nearly free. A process with fifty destinations pays for one
tunnel and fifty channels.

### 3.2 One client per configuration, not per connection

`shared.rs` keeps a process-wide registry of `Client`s keyed by
`ClientConfig::key` (`shared.rs:43-46`, `shared.rs:77-122`). Two Zray
outbounds that dial the same servers with the same settings share one SSH
session; the cache key covers the region, the limits, the identity, the
proxy, the protocol list and each entry's secrets (`config.rs:311-348`).

The registry holds `Weak` references (`shared.rs:43-46`): "the map is a
cache, not an owner. Every dial and every live stream holds a strong
reference" (`shared.rs:39-42`). The strong reference is the `Arc<Instance>`
carried by the `LeasedStream` (`shared.rs:189-199`), so the client and its
tunnel live exactly as long as the last stream through them.

### 3.3 Idle reaping, without a timer

A client that has seen no new dial for five minutes is dropped
(`IDLE_AFTER = 300 s`, `shared.rs:36`). The reaping happens **on the way
in**, at the start of the next `shared::dial` (`shared.rs:80-83`): "No
timer, no task: a process that stops using Psiphon gives the memory back
the next time it dials, and one that never dials again gives it back when
it exits."

The consequence is a deliberate trade: a quiet proxy holds its tunnel for
up to five minutes after the last stream ends, and a process that stops
using Psiphon entirely holds it until it exits. In exchange, the crate runs
**no background task at all** — the only `tokio::spawn` calls in the crate
are in test modules. A client that is not being used costs a socket and
some memory, and nothing else.

### 3.4 The OSSH layer gives its key-exchange state back

`release_kex_state` (`obfuscator.rs:314-337`) runs once **both** directions
have passed `NEWKEYS` (`obfuscator.rs:315-317`) and does four things:

- replaces both RC4 states with `Rc4::forgotten()`, a zeroed 256-byte state
  whose `apply` is a no-op (`obfuscator.rs:322-323`,
  `obfuscator.rs:82-88`);
- drops the seed message, which is dead weight once the key exchange is
  over (`obfuscator.rs:324`);
- re-seeds the padding generator with zeros, so the PRNG's state is gone
  (`obfuscator.rs:325`);
- frees the `kex` and `incoming` buffers when they are empty
  (`obfuscator.rs:327-336`).

After that the layer is a **pass-through in both directions**. On the write
side, once the write state is `Finished` and the output buffer is empty,
`poll_write` forwards straight to the inner stream (`obfuscator.rs:450-452`).
On the read side, once the read state is `Finished`, `poll_read` forwards
straight to the inner stream (`obfuscator.rs:258-260`). The steady-state
cost of the OSSH layer is therefore one branch per read and per write.

**A correction to a common description of this design.** The scratch buffer
is *not* released: `transform_kex` takes the scratch out of the struct and
puts it back (`obfuscator.rs:527-528`, `obfuscator.rs:588`), and the
comment at `obfuscator.rs:327-330` says why — "`out` may be waiting on the
socket, and the scratch buffer is handed back by the code that borrowed it.
The empty ones give their capacity back now (`BytesMut` has no
`shrink_to_fit`)". So the OSSH layer keeps two `BytesMut` capacities (the
`out` buffer and the `scratch`) for the life of the connection. The ciphers
and the preamble are released; the buffers are recycled.

### 3.5 Buffer reuse, and the copies that remain

The OSSH layer allocates its five `BytesMut` buffers once, at construction,
with a reservation (`obfuscator.rs:218-222`): 1 KiB for `out`, 4 KiB each
for `kex`, `incoming` and `scratch`, 1 KiB for `ready`. The framing code
reuses them rather than reallocating per packet: `frame_incoming` splits
frames out of `incoming` with `split_to` (`obfuscator.rs:417`), which does
not copy, and `transform_kex` recycles the scratch through
`std::mem::take` (`obfuscator.rs:527`).

What remains is not zero-copy, and the code does not claim it is:

- On the read path, a framed packet is copied from `incoming` into `ready`
  (`obfuscator.rs:420`) and then from `ready` into the caller's buffer
  (`obfuscator.rs:254`). Two copies per packet, during the key exchange
  only; after `NEWKEYS` the layer passes the bytes through untouched.
- On the write path during the key exchange, a packet is copied into the
  scratch (`obfuscator.rs:563`), obfuscated in place
  (`obfuscator.rs:572`), and copied into `out` (`obfuscator.rs:573`). After
  `NEWKEYS` there is no copy at all (`obfuscator.rs:450-452`).
- `russh` itself copies the caller's write slice into a `Bytes` to queue it
  as a channel message, and copies out of that `Bytes` on the read side.
  That is the library's behaviour, not this crate's, and `INTEGRATION.md`
  §8.3 records the decision not to work around it.

The crate's own boxing discipline is the part that is genuinely at the
setup boundary: the carrier is boxed once, when it is built
(`client.rs:513-515`: "a carrier is boxed only at this setup boundary, never
per packet"), and the stream handed to the caller is boxed once per dial
(`client.rs:110`).

### 3.6 `TCP_NODELAY` on the carriers

`client.rs:541-543` sets `TCP_NODELAY` on the socket that answers the
connect. The reason is in the comment: "Proxy traffic is request/response:
the latency of a small request matters more than the cost of a small packet."

Without it, a small SSH packet can sit in the kernel's delayed-ACK buffer
waiting for more data to coalesce with, which is exactly the wrong trade
for a tunnel that is mostly carrying small messages. This is the kind of
decision that does not show up in a throughput benchmark and shows up in a
first-byte latency measurement.

### 3.7 The window and the packet size

`TunnelOptions::window_size` is 4 MiB and `maximum_packet_size` is 32 KiB
(`tunnel.rs:76-79`); `ClientConfig::channel_window_bytes` is the same 4 MiB
(`config.rs:231`) and is passed into the options at
`client.rs:386`.

The window is what stops a long-fat path from being window-limited: a
channel can have 4 MiB in flight, so the bandwidth-delay product has to fall
below 4 MiB before the window becomes the constraint. At 100 ms RTT that is
a 40 Mbit/s ceiling per channel. The 32 KiB maximum packet is the SSH
protocol's floor for a 32-bit length field's comfortable margin and matches
Psiphon's own `channelMaxPacket` (`psiphon/common/crypto/ssh/channel.go:22`).

**Two things a reader should know about these defaults.**

First, 4 MiB is the Go client's *configurable maximum*
(`psiphon/common/crypto/ssh/channel.go:76-81` allows up to 128 × 32 KiB),
not its default: the Go client's default is 4 × 32 KiB = **128 KiB**
(`psiphon/common/crypto/ssh/channel.go:59-81`, tabulated in
`INTEGRATION.md:1628`). This crate picked the ceiling. `ARCHITECTURE.md`
§7.4 says what to do about it.

Second, the window is a **credit, not a preallocated buffer**. `russh`
tracks it as an `Arc<Mutex<u32>>` and the memory a channel holds depends on
how much unread data is actually buffered, bounded by the window. So the
4 MiB figure is a ceiling a peer could push towards, not an allocation the
client makes up front. The Go client's comment on the same subject is worth
repeating here, because it is the reason the Go client keeps its window
small: "In Psiphon, a single SSH connection is used for all client port
forwards. Bulk data transfers with large channel windows can immediately
backlog the connection with many large SSH packets, introducing large latency
for opening new channels" (`psiphon/common/crypto/ssh/channel.go:40-47`).

### 3.8 What the crate does *not* do on the hot path

- **No per-connection client.** §3.2.
- **No buffered response bodies.** The crate hands out a stream and never
  assembles a body. The only place a body is assembled is the benchmark
  test itself, which has to check the length (`tests/throughput.rs:123-135`).
- **No background task.** §3.3.
- **No timer.** The only `Sleep` in the crate is the meek poll back-off
  (`meek.rs:463-470`), which belongs to the meek carrier's own idle
  behaviour rather than to the client. Every other timeout is a one-shot
  `tokio::time::timeout` around a single operation (`client.rs:526`,
  `client.rs:538`, `tunnel.rs:291`, `tunnel.rs:312`, `tunnel.rs:364`).
- **No per-packet JSON, base64 or signature.** Those are setup-only: the
  credential payload is built once per authentication (`tunnel.rs:301-310`),
  the handshake payload once per tunnel (`tunnel.rs:348`), and the Go-JSON
  encoder only runs when an entry's signature is verified
  (`server_entry.rs:469-470`).

### 3.9 Keepalives

`keepalive_interval` defaults to 25 s (`config.rs:233`) and is passed to
`russh` as the `keepalive@openssh.com` interval, with at most three
unanswered keepalives before the session is considered dead
(`tunnel.rs:283-284`). The server answers each keepalive with 0–256 random
bytes, which it records as a speed-test sample
(`psiphon/server/tunnelServer.go:3275-3300`), so a keepalive is a small
round trip every 25 s per tunnel, plus a line in the server's statistics.

The Go client keeps its tunnels alive on a 60–120 s period
(`INTEGRATION.md:1635`), and `INTEGRATION.md:1722-1726` recommends 60 s for
this crate too, on the grounds that 25 s is more aggressive than the
reference and costs more on a phone.

**What to do.** Raise the default to 60 s unless a harness test says the
server expects faster. It changes nothing about throughput — a keepalive
every 25 s on a 2.5 Gbit/s link is noise — and it changes the server's view
of how fast the link is, which is worth being deliberate about.

---

## 4. Memory

### 4.1 What an idle client holds

One `Client` in the shared registry holds:

- the `ClientConfig`, including the parsed server entries — the entries hold
  their typed fields **and** the raw JSON map they arrived as
  (`server_entry.rs:123-126`), so an entry costs its JSON document as well
  as its fields;
- one to four `SshTunnel`s, each a `russh::client::Handle` plus the
  session's own read and write buffers (`tunnel.rs:227-234`);
- the OSSH layer's post-`NEWKEYS` state: two zeroed 256-byte RC4 states, an
  empty preamble, a zeroed PRNG, and the retained `out` and `scratch`
  `BytesMut` capacities (§3.4);
- for TLS-OSSH, the `rustls` session state and the `ClientHello` plan;
- for the meek carrier, the `MeekStream`'s own buffers: a `pending_out` that
  grows to the request payload limit (64 KiB by default,
  `meek.rs:47`, `meek.rs:715-720`) and a `pending_in` that holds whatever
  the server has sent that the caller has not read;
- one `Arc<AtomicUsize>` for the channel accounting (`client.rs:44`).

Per **open channel**, the crate holds:

- a `TunnelStream` wrapping a `russh::ChannelStream` (`tunnel.rs:405-407`);
- a `CountedStream` that releases the channel slot on drop
  (`client.rs:221-234`);
- a `BoxStream` allocation and, through `shared::dial`, a `LeasedStream`
  holding the `Arc<Instance>` (`shared.rs:189-199`);
- the `russh` channel's own state: the window credit, and a bounded queue of
  pending messages whose depth is `channel_buffer_size` = 64
  (`tunnel.rs:80`, `tunnel.rs:282`).

The number of open channels is bounded by `max_channels`, 128 by default
(`config.rs:232`, `client.rs:101-107`); the 129th is refused with a message
that says so.

### 4.2 What the design avoids

- **No client per connection.** §3.2. A hundred Zray connections through
  one outbound share one SSH session, one key exchange and one handshake.
- **No buffered response bodies.** §3.8.
- **No timer and no task when nothing is happening.** §3.3. A process that
  never dials Psiphon allocates nothing for it at all: the registry is
  populated on the first dial and reaped on the next one
  (`shared.rs:80-83`).
- **No per-packet allocation in the OSSH layer.** §3.5.
- **No duplicate copies of the entries' secrets in logs.** The `Debug`
  implementations of `ServerEntry` and `UpstreamProxy` print the
  diagnostic id and `<redacted>` and nothing else
  (`server_entry.rs:128-138`, `config.rs:41-56`), so a debug dump of a
  configuration does not leak a password.

### 4.3 The number to watch

The worst case is `max_channels` busy channels at the full window:
128 × 4 MiB = 512 MiB of *credit*. The Go client's equivalent is 128 ×
128 KiB = 16 MiB. The credit is not an allocation, so this is a ceiling
rather than a footprint, but it is the number that would move first if a
peer misbehaved or if the window default were raised.

`INTEGRATION.md:1656-1669` gives the per-item budget the plan assumed
(≤ 0.5 MiB for an idle session, ≤ 8 KiB for an idle channel, ≤ 192 KiB for
a busy downloading channel at a 128 KiB window) and the worst case it
derived, 24 MiB with 128 busy channels at that window. **Those figures
assume the Go client's 128 KiB window; this crate uses 4 MiB, so the busy-
channel figure is up to 32× larger.** The plan's numbers have not been
re-measured against the code, and no RSS measurement of the Rust client
exists in this repository. §5 lists it.

---

## 5. What to measure next

In the order it would change decisions.

**Throughput and latency over a real link.** A WAN measurement — a VPS on
another continent, or at least a 100 ms-RTT path — with the same payload
sizes. The prediction to test is the bandwidth-delay-product one: with a
4 MiB window, one channel at 100 ms RTT should reach roughly 40 Mbit/s
regardless of how fast the client is, and the client should be invisible in
the result. This is the measurement that would make the loopback numbers
mean something, and it is also the measurement that would tell us whether
the 4 MiB window is the right default or whether the Go client's 128 KiB
would do.

**Memory under many channels.** The RSS delta of the process with 1, 64 and
128 open channels, idle and busy, measured the way `INTEGRATION.md:1760-1762`
describes (`/proc/self/status` `VmRSS` delta). This is the measurement that
would settle §4.3: how much of the 4 MiB window credit is real, and what a
busy channel actually costs.

**The TLS-OSSH handshake cost.** Establishment was 9–12 ms on loopback
(§2.1), which is a fair measure of the client's CPU and nothing else. Over
a real link the TLS 1.3 handshake's round trips, plus the OSSH seed
message, plus the SSH key exchange, plus the authentication, plus the
`psiphon-handshake` request, add up. A per-stage timing breakdown — and
fixing the unbounded handshake request (`ARCHITECTURE.md` §7.8) — is the
prerequisite for measuring it properly.

**The meek poll cost.** The meek carrier is the only transport where the
client *polls* rather than waits: with nothing to send it still posts an
empty body, backing off from 100 ms to 5 s
(`meek.rs:53-55`, `meek.rs:426-446`). The cost has two halves: the number
of requests an idle meek tunnel makes per minute, and the latency each poll
adds to a downstream byte arriving. Neither has been measured. The carrier
is implemented (`client.rs:441-499`) and interop-verified against the real
`psiphond` (`.research/psiphon-server-harness/logs/verify-meek-evidence.log:25-28`),
but the benchmark does not include it (`tests/throughput.rs:224-230`), so
there is no number for it at all. Note also that the poll interval is
multiplied by 1.5 with a coin flip in Psiphon (`meek.rs:437-439` says the
port uses a fixed factor instead), so the client's back-off is already an
approximation of the reference.

**The racing dial under real conditions.** `establish_concurrency` defaults
to 3 (`config.rs:229`) and the race exists because "a filtered address
accepts the TCP connection and then says nothing"
(`client.rs:270-275`). On loopback every candidate answers instantly, so the
race has never been observed doing its job. How many candidates are dialled
in parallel, and what the time-to-first-tunnel is when the first candidate
is a black hole, is worth measuring against a server that accepts and
silences connections.

**CPU per byte.** The loopback numbers say the client is not the bottleneck
at 2–3 Gbit/s, but they do not say how much CPU the client uses per
gigabit. A `perf` profile of the benchmark would say whether the client's
share of the CPU is worth optimising, and would also show whether the
`russh` copies (§3.5) are worth attacking.
