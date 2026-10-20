# Native Psiphon client: integration plan for Zray-Core

Status: **plan, for implementation**. This document is the file-by-file plan for
adding `{"protocol": "psiphon"}` as an outbound: the `zero-psiphon` crate, the
`zero-config` model/parser changes, the `zero-runtime` dispatch and lifecycle,
feature flags, the user-facing JSON schema, the test harness, and the
performance/RAM budget. It does not change source itself.

Companion documents, written alongside this one:

| Document | What it owns |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Go client flow, config fields, dial selection, concurrency/RAM baseline |
| [`WIRE-SPEC.md`](WIRE-SPEC.md) | byte-exact OSSH / meek / TLS-tunnel spec and Go-derived vectors |
| [`SERVER-HARNESS.md`](SERVER-HARNESS.md) | the real `psiphond` loopback harness and its proven interop recipe |

Citations are `path:line` in this repository or in `.research/psiphon-tunnel-core`
(the Go reference, commit `5709017`). Line numbers are as of 2026-10-19 18:45
CEST; `crates/zero-psiphon` is being written in parallel with this plan, so
**symbol names, not line numbers, are the stable anchors** in that crate. Where
the in-progress skeleton differs from the target shape below, the difference is
called out explicitly.

---

## 0. Summary of the decisions

1. **A new crate, `crates/zero-psiphon`**, owns the whole Psiphon client. It
   depends on `zero-core` (streams, addresses, `Failure`), `zero-protocol`
   (SOCKS5/HTTP-CONNECT upstream), `zero-net` (shaped HTTPS fetch for remote
   server lists/tactics) and crypto crates already in the workspace. It does
   **not** depend on `zero-config` or `zero-runtime`; `zero-runtime` converts
   `zero_config::PsiphonConfig` into `zero_psiphon::ClientConfig`.
2. **`{"protocol": "psiphon"}` is a whole-tunnel outbound with no endpoint**,
   exactly like `{"protocol": "tor"}` (`crates/zero-config/src/model.rs:1224-1228`,
   `crates/zero-runtime/src/outbound.rs:792-900`). `Outbound::endpoint()` returns
   `None`; the dial path is intercepted before endpoint resolution.
3. **TCP only.** UDP routed to a Psiphon outbound is refused before anything is
   dialled, with the same one-sentence style as Tor/MasterDNS
   (`crates/zero-runtime/src/outbound.rs:874-877`,
   `crates/zero-runtime/src/masterdns.rs:107-110`).
4. **No share link.** A `psiphon://` link cannot carry the signed server entries
   that make the outbound usable; the parser returns a sentence pointing at JSON
   (see §3.3). The one-click catalog gets no entry until an app supplies
   entries; the JSON outbound is the supported front end.
5. **The SSH `psiphon-handshake` global request is mandatory**, not an extra: the
   server refuses `direct-tcpip` until `handshakeState.completed`
   (`psiphon/server/tunnelServer.go:5059-5068`), and the state is set only by that
   request (`psiphon/server/api.go:90-98`). The in-progress
   `SshTunnel::handshake` already implements it
   (`crates/zero-psiphon/src/tunnel.rs`).
6. **Feature-gated like Tor.** `zero-runtime` gets `psiphon =
   ["dep:zero-psiphon"]`, off by default for embedders; `zray-cli` turns it on by
   default (russh is a modest dependency next to Arti). Without the feature the
   outbound still parses and validates, and every connection fails with "this
   build was made without Psiphon support" — identical to the Tor contract
   (`crates/zero-runtime/src/outbound.rs:886-895`,
   `crates/zero-runtime/tests/tor_outbound.rs:17-25`).
7. **One SSH connection multiplexes all destinations** (`direct-tcpip` channels).
   One tunnel is kept per identical config and shared through the crate's
   instance cache (the `zero-tor` pattern: `crates/zero-tor/src/lib.rs:40-100`).
   Reload with an unchanged config reuses it; a changed config gets a new
   instance and the old one dies when its last stream ends plus an idle sweep.
8. **Phase 1 is OSSH (and plain SSH for tests) only.** TLS-OSSH, meek, tactics
   fetch/application, remote server lists and the datastore land in later,
   independently shippable phases (§9). This keeps the first merge reviewable
   and every phase testable on its own.
9. **Tests run against an in-process mock `psiphond`** (a `russh` server behind
   the crate's own OSSH server mode) for CI, and against the real Go
   `psiphond` harness as ignored interop tests, exactly like the repository's
   other external oracles (`crates/zero-runtime/tests/tor_outbound.rs:78-81`,
   `crates/zero-runtime/tests/loopback_throughput.rs:1-13`).
10. **The performance budget is bounded by the SSH channel window, not by the
    tunnel.** Defaults are the Go client's: 128 KiB per-channel window, 32 KiB
    SSH packets, one tunnel, ~32 KiB relay buffers
    (`psiphon/common/crypto/ssh/channel.go:59-81`, `psiphon/net.go:361-377`,
    `crates/zero-runtime/src/relay.rs:20-29`).

---

## 1. Repository state this plan builds on

### 1.1 What already exists

`crates/zero-psiphon` is a work-in-progress skeleton created alongside this
plan. Its current contents (line counts as of writing):

| File | State |
|---|---|
| `src/lib.rs` (44) | module map + re-exports; documents the layout |
| `src/protocol.rs` (201) | `TunnelProtocol` with wire names and capability rules, tests |
| `src/server_entry.rs` (623) | typed server entry + raw object, capability rules, Ed25519 signature verify/sign, tests |
| `src/json.rs` (226) | Go `encoding/json` compatible encoder (sorted keys, Go escaping, float64 rules), tests |
| `src/tunnel.rs` (594) | `SshTunnel` (host-key pinning, credential payload, mandatory handshake, `direct-tcpip`), in-module mock server tests |
| `src/error.rs` (137) | `Error` variants, `Stage`, `is_retryable`, `kind` |
| `src/client.rs` (38) | `Client` stub: connect/dial unimplemented |
| `src/config.rs` (28) | `ClientConfig` fields (being extended) |
| `src/obfuscator.rs` (10) | stub |
| `src/meek.rs` (3) | stub |
| `src/tactics.rs` (3) | stub |
| `src/mock.rs` (3) | stub; whole module is behind `feature = "test-util"` |
| `tests/real_server.rs` (102) | ignored interop test against the local Go `psiphond` |

Workspace changes already made: the member and the dependency line
(`Cargo.toml:22`, `Cargo.toml:58`), and workspace deps `russh` and
`ed25519-dalek` (`Cargo.toml:120-131`). `Cargo.lock` already contains the
`zero-psiphon` package (`Cargo.lock:7629-7653`), `russh 0.64.1`
(`Cargo.lock:4268`), `ed25519-dalek 2.2.0`, `hmac 0.12.1`, `sha2 0.10.9`,
`hkdf 0.12.4`, `sha1 0.10.7`, `ring 0.17.14`, `flate2 1.1.10`, `rsa 0.9.10`.
Nothing about Psiphon is wired into `zero-config`, `zero-runtime`, `zray-cli`,
or the docs yet; that is what this plan specifies.

### 1.2 What the rest of this plan touches

- `crates/zero-config/src/model.rs` — enum variant, config struct, accessors,
  validation block (§3.1).
- `crates/zero-config/src/xray_json.rs` — protocol dispatch and
  `parse_psiphon` (§3.2).
- `crates/zero-config/src/share_link.rs` — explicit "JSON only" error (§3.3).
- `crates/zero-runtime/Cargo.toml`, `src/outbound.rs`, `src/server.rs`,
  new `src/psiphon.rs` (§4).
- `crates/zray-cli/Cargo.toml` (§5).
- `docs/config-compatibility.md` — a new "The `psiphon` outbound has no Xray
  counterpart" section (§5.3), following the file's
  "What differs / Why / Pinned by" convention
  (`docs/config-compatibility.md:1-8`, `:91-118` for the Tor precedent).
- Documentation/feature plumbing in the Desktop and Mobile repositories
  (`ZeroNet-Desktop/crates/zeronet-tui/Cargo.toml:16-18`,
  `ZeroNet-Mobile/native/zray-mobile/Cargo.toml:14-18`) is a follow-up outside
  Zray-Core; both already use the same feature pattern for `tor`.

---

## 2. The `zero-psiphon` crate

### 2.1 Module layout (target)

The skeleton's module map is kept; the missing modules are added. Module
boundaries follow `WIRE-SPEC.md` §8.2, with one deliberate deviation: **the
OSSH/meek/TLS byte pipes stay in `zero-psiphon`, not in `zero-transport`.**
`zero-transport`'s contract is "carriers do not know which protocol rides on
them" (`crates/zero-transport/src/lib.rs:1-7`); OSSH is Psiphon-specific, no
other caller needs RC4/prefix framing, and feature-gating keeps the RC4 and
meek code out of builds that do not enable `psiphon`. The internal split
(`cipher`, `seedmsg`, `framing`, `conn`) is preserved as submodules of
`obfuscator`.

| Path | Responsibility | Public items | Spec |
|---|---|---|---|
| `src/lib.rs` | re-exports, crate docs | `Client`, `ClientConfig`, `Error`, `ServerEntry`, `TunnelProtocol`, `dial`, `forget`, `shutdown_all` | — |
| `src/protocol.rs` | wire protocol table, capability rules, port/host selection | `TunnelProtocol`, `capability()`, `supported()`, `parse()`, `port_for`, `host_for` | WIRE-SPEC §0 |
| `src/server_entry.rs` | signed entry parsing, capability rules, Ed25519 verify | `ServerEntry::from_json`, `from_json_array`, `verify_signature`, `sign` (test/harness), accessors | WIRE-SPEC §0; ARCHITECTURE §server entries |
| `src/json.rs` | Go-compatible JSON encoding for signatures | `json::encode`, `encode_string`, `go_float` | ARCHITECTURE §signatures |
| `src/config.rs` | compiled runtime config + validation + cache key | `ClientConfig`, `ClientConfig::key`, `validate`, `Default`, `UpstreamProxy`, `UpstreamProxyKind` | this doc §6 |
| `src/carrier.rs` | choose and build the byte pipe under SSH | `CarrierPlan`, `OsshPlan`, `TlsOsshPlan`, `MeekPlan`, `CarrierDialer`, `DirectDialer`, `connect()` | WIRE-SPEC §0.1, §2.1, §5 |
| `src/obfuscator/mod.rs`, `cipher.rs`, `seedmsg.rs`, `framing.rs`, `conn.rs` | OSSH stream cipher, preamble, SSH packet rewrite, NEWKEYS transition, `AsyncRead`/`AsyncWrite` wrapper; server mode for `mock` | `OsshPlan`, `ObfuscatedStream`, `client()`, `server()` (test-util) | WIRE-SPEC §1.1-1.2, §2 |
| `src/meek.rs` | HTTP request/response carrier | `MeekPlan`, `MeekStream` | WIRE-SPEC §3 |
| `src/tls_tunnel.rs` | TLS-OSSH carrier (passthrough ClientHello, TLS 1.3, any-cert) | `TlsOsshPlan`, `connect()` | WIRE-SPEC §1.3, §5 |
| `src/tunnel.rs` | SSH session, host-key pinning, credential payload, mandatory handshake, channels | `SshTunnel`, `TunnelOptions`, `HandshakeParams`, `TunnelStream` | WIRE-SPEC §2.4-2.7; ARCHITECTURE §handshake |
| `src/client.rs` | tunnel pool, server selection, dial loop, `dial()` | `Client`, `Client::connect`, `dial`, `close`, `is_alive` | ARCHITECTURE §dial |
| `src/shared.rs` | one live `Client` per identical config (the `zero-tor` pattern) | `dial(config, address, port)`, `forget`, `shutdown_all`, test hook `instance_id` | this doc §4.6 |
| `src/tactics.rs` | tactics fetch, signature verify, parameter application | `Record`, `fetch`, `apply` | WIRE-SPEC §7; ARCHITECTURE §tactics |
| `src/remote_server_list.rs` | signed remote list fetch/import | `fetch`, `import` | this doc §7.3 |
| `src/datastore.rs` | atomic JSON persistence of entries/tactics | `Store` | this doc §6.4 |
| `src/upstream.rs` | upstream SOCKS5/HTTP CONNECT dialer | `UpstreamDialer` | this doc §6.3 |
| `src/mock.rs` (`test-util`) | in-process `psiphond` stand-in: SSH + OSSH server, entry builder | `MockServer`, `MockServerConfig`, `SeenChannel` | this doc §7.2 |
| `tests/` | cross-module tests | see §7 | — |

### 2.2 Public API (target signatures)

The runtime needs exactly two entry points and one keep-alive type; everything
else is internal or test surface.

```rust
// src/lib.rs
pub use client::Client;
pub use config::{ClientConfig, UpstreamProxy, UpstreamProxyKind};
pub use error::{Error, Result};
pub use protocol::TunnelProtocol;
pub use server_entry::ServerEntry;
pub use tunnel::{SshTunnel, TunnelOptions, TunnelStream};
pub use shared::{dial, forget, shutdown_all};

/// Open one stream to `address:port` through a shared Psiphon tunnel,
/// establishing or replacing the tunnel as needed.
///
/// This is the only function `zero-runtime` calls per outbound connection.
pub async fn dial(
    config: &ClientConfig,
    address: &zero_core::Address,
    port: u16,
) -> Result<zero_core::BoxStream>;
```

```rust
// src/client.rs
/// A connected Psiphon client: one or more established SSH tunnels and the
/// policy for choosing between them.
pub struct Client {
    config: std::sync::Arc<ClientConfig>,
    tunnels: Vec<std::sync::Arc<Tunnel>>, // len == config.tunnel_pool_size
    session_id: std::sync::Arc<str>,
    next_tunnel: std::sync::atomic::AtomicUsize,
    open_channels: std::sync::atomic::AtomicUsize,
    closed: std::sync::atomic::AtomicBool,
    last_active: std::sync::Mutex<std::time::Instant>,
}

impl Client {
    /// Establish a tunnel, trying `config.server_entries` in the configured
    /// protocol order, up to `config.establish_concurrency` at a time.
    pub async fn connect(config: ClientConfig) -> Result<Client>;

    /// Open one `direct-tcpip` channel on the next tunnel in the pool.
    ///
    /// Domain names are handed to the server unresolved; nothing is looked up
    /// locally.
    pub async fn dial(&self, address: &zero_core::Address, port: u16)
        -> Result<TunnelStream>;

    pub fn is_alive(&self) -> bool;
    pub fn config(&self) -> &ClientConfig;

    /// Disconnect every tunnel and mark the client closed.
    pub async fn close(&self);
}
```

```rust
// src/tunnel.rs (exists; additions in the target shape)
pub struct SshTunnel { /* handle: russh::client::Handle<Pinned>, session_id */ }

impl SshTunnel {
    pub async fn establish<S>(
        stream: S,                        // plain TCP, OSSH-wrapped, TLS-wrapped, meek
        entry: &ServerEntry,
        options: &TunnelOptions,
        timeout: std::time::Duration,
    ) -> Result<Self>
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;

    /// Psiphon's `psiphon-handshake` SSH global request. Mandatory before the
    /// server will forward any port (`psiphon/server/tunnelServer.go:5059-5068`).
    pub async fn handshake(&self, params: &HandshakeParams) -> Result<Vec<u8>>;

    pub async fn open(&self, host: &str, port: u16) -> Result<TunnelStream>;

    pub async fn close(self);
}

/// A `direct-tcpip` byte stream. Holds an `Arc<TunnelKeepAlive>` so the SSH
/// session cannot be dropped while a stream is open.
pub struct TunnelStream {
    inner: russh::ChannelStream<russh::client::Msg>,
    _keepalive: std::sync::Arc<client::KeepAlive>,
}
impl tokio::io::AsyncRead for TunnelStream { /* delegate */ }
impl tokio::io::AsyncWrite for TunnelStream { /* delegate */ }

#[derive(Debug, Clone)]
pub struct TunnelOptions {
    pub client_version: String,        // "SSH-2.0-OpenSSH_9.6"
    pub keepalive_interval: Option<std::time::Duration>,
    pub window_size: u32,              // 131_072 = 4 * 32 KiB, the Go default
    pub maximum_packet_size: u32,      // 32_768
    pub channel_buffer_size: usize,    // 64
    pub session_id: Option<String>,    // tests: pin the 32-hex session id
    pub sponsor_id: String,            // empty or exactly 16 hex chars
    pub capabilities: Vec<String>,     // empty by default (see §6.6)
    pub preferred: russh::Preferred,   // OSSH-compatible algorithm order (§8.4)
}
```

```rust
// src/config.rs
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_entries: Vec<ServerEntry>,
    pub server_entry_signature_public_key: Option<String>, // base64
    pub remote_server_list_urls: Vec<String>,
    pub tactics: bool,
    pub tactics_url: Option<String>,
    pub data_dir: Option<std::path::PathBuf>,
    pub upstream_proxy: Option<UpstreamProxy>,
    pub egress_region: String,               // "" or "US"
    pub protocols: Vec<TunnelProtocol>,      // empty = the default order
    pub establish_timeout: std::time::Duration,
    pub establish_concurrency: usize,        // 1..=8, default 3
    pub tunnel_pool_size: usize,             // 1..=4, default 1
    pub channel_window_bytes: u32,
    pub max_channels: u32,                   // default 128; refuse above it
    pub keepalive_interval: Option<std::time::Duration>,
    pub handshake: HandshakeIdentity,        // propagation channel, sponsor, version, platform
    pub session_id: Option<String>,          // None = random 32 hex per client
}

impl ClientConfig {
    pub fn validate(&self) -> Result<()>;
    /// SHA-256 over every field that changes the tunnel, secrets included.
    /// Used as the shared-instance cache key; never printed.
    pub fn key(&self) -> [u8; 32];
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamProxy {
    pub kind: UpstreamProxyKind,
    pub host: zero_core::Address,
    pub port: u16,
    pub credential: Option<UpstreamCredential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamProxyKind { Socks5, Http }
```

```rust
// src/carrier.rs
pub type CarrierFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<zero_core::BoxStream>> + Send + 'a>>;

/// How a carrier reaches the server. Dyn-compatible so tests can inject the
/// mock and the runtime can inject an upstream proxy without generics.
pub trait CarrierDialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> CarrierFuture<'a>;
}

pub struct DirectDialer;                     // zero_core::connect_protected(addr)
pub struct UpstreamDialer(pub UpstreamProxy);

pub enum CarrierPlan {
    Plain,                                   // SSH, tests/harness only
    Ossh(OsshPlan),
    TlsOssh(TlsOsshPlan),
    Meek(MeekPlan),
}

/// Build the byte pipe for `protocol`. `BoxStream` is acceptable here: it is a
/// setup boundary, never per packet (`crates/zero-core/src/stream.rs:23-27`).
pub async fn connect(
    entry: &ServerEntry,
    protocol: TunnelProtocol,
    dialer: &dyn CarrierDialer,
    options: &CarrierOptions,
) -> Result<zero_core::BoxStream>;
```

Do **not** turn the egress path into a boxed dynamic call per read: `TunnelStream`
keeps the concrete `russh::ChannelStream` and only the runtime boxes the final
stream into `zero_core::BoxStream` (the runtime's established convention,
`crates/zero-runtime/src/outbound.rs:2915-2920`).

### 2.3 State machine of one dial

```text
shared::dial(config, addr, port)
  └─ get-or-create Client for config.key()            [async Mutex per key]
       ├─ if server entries empty → refresh remote list (phase 3)
       ├─ tactics (phase 3, optional)
       ├─ candidates = entries ∩ egress region ∩ implemented protocols
       ├─ for at most `establish_concurrency` candidates concurrently:
       │     carrier::connect
       │       └─ Plain / OSSH / TLS-OSSH / Meek  (protocol order per entry)
       │     SshTunnel::establish(carrier, entry, options, timeout)
       │       ├─ russh KEX (host key pinned by exact bytes)
       │       ├─ password auth with the JSON credential payload
       │       └─ SshTunnel::handshake (psiphon-handshake, mandatory)
       │     first success wins; the rest are dropped (sockets closed by drop)
       └─ cache Arc<Client>, spawn the idle-close task
  └─ Client::dial(&addr, port)
       └─ SshTunnel::open(addr.host_string(), port)  → TunnelStream
```

`Client::dial` maps `russh` failures as follows:

| `russh` / carrier failure | `zero_psiphon::Error` | retry? |
|---|---|---|
| carrier TCP refused/timeout | `Error::Connect` / `Error::Timeout{Tcp}` | next candidate |
| OSSH desync/seed rejected | `Error::Obfuscation` | next candidate (new seed) |
| SSH `NoCommonAlgo` | `Error::Ssh` | next candidate |
| auth rejected | `Error::Ssh` | next candidate |
| handshake rejected | `Error::Ssh` | next candidate |
| channel `ChannelOpenFailure` | `Error::Channel` | same tunnel, report; not retried blindly |
| tunnel closed mid-dial | `Error::Closed` | discard tunnel, re-establish once (§4.6) |

### 2.4 Decoupling rules and dependencies

Allowed, and why:

- `zero-core` — `BoxStream`/`Stream`, `Address`, `Failure`, `connect_protected`
  (`crates/zero-core/src/lib.rs:14-29`, `crates/zero-core/src/platform.rs:290-300`).
- `zero-protocol` — `socks::connect_socks5` / `connect_http` for the upstream
  proxy (`crates/zero-protocol/src/socks.rs:622-690`). No config/runtime types
  leak: they speak `Destination` and `Credential`.
- `zero-net` — `dial_tcp`/`fetch_with` for direct dialling with socket
  protection and a browser-shaped TLS fetch of remote lists/tactics
  (`crates/zero-net/src/dial.rs:129-150`, `crates/zero-net/src/fetch.rs:128-160`).
  `zero-net` depends on `zero-security`, which every app already links.
- `russh 0.64` — the SSH client. **Do not** reuse `zero-provision`'s
  `ssh.rs`: it is a command runner with a different error vocabulary
  (`crates/zero-provision/src/ssh.rs:1-25`), and `zero-provision` is a Desktop
  concern, not part of the engine.
- `ed25519-dalek`, `sha2`, `hmac`, `hkdf`, `rand`, `base64`, `hex`, `bytes`,
  `futures`, `url`, `thiserror`, `tokio`, `tracing` — all workspace or
  lock-file deps already.

Forbidden: `zero-config` (config conversion is the runtime's job), `zero-runtime`
(the runtime is a caller), `arti-*`, any `psiphon`-named dependency (there is
no Rust Psiphon crate; do not introduce one).

Additions to `crates/zero-psiphon/Cargo.toml` beyond the skeleton:

```toml
zero-protocol = { workspace = true }
zero-net = { workspace = true }
flate2 = { workspace = true }   # zlib for the authenticated remote-list package
ring = { workspace = true }     # RSA-PKCS1v15-SHA256 verification of that package
```

`rustls`/`tokio-rustls` stay for the TLS-OSSH carrier (phase 4). No new
registry crates are required: every one of these is in `Cargo.lock` already
(§1.1), and `ring`/`flate2` are workspace dependencies (`Cargo.toml:80-100`).

---

## 3. `zero-config` changes (exact edits)

### 3.1 `crates/zero-config/src/model.rs`

**a) Enum variant.** Insert directly after `Tor(TorConfig)`
(`crates/zero-config/src/model.rs:1224-1228`), because it is the same kind of
outbound (whole tunnel, no endpoint):

```rust
    /// The Psiphon network, through the native Rust client (needs a build with
    /// the `psiphon` feature; without it connections fail with a message saying
    /// so). TCP only. Like Tor it has no endpoint of its own: server entries are
    /// the way in, the destination is where the server connects.
    Psiphon(PsiphonConfig),
```

**b) `name()` / `is_proxy()`.** Add `OutboundProtocol::Psiphon(_) => "psiphon"`
to `name()` (after the Tor arm, `model.rs:1268`), and `| OutboundProtocol::Psiphon(_)`
to the `is_proxy` list (`model.rs:1280-1298`). Both matches are exhaustive, so
the compiler enforces this.

**c) `chainable()` — leave it out.** A Psiphon outbound needs many connections
(one SSH session, many channels), so it is not a single carried byte stream,
exactly like Tor (`model.rs:2116-2134`; see the Tor rationale at
`model.rs:2108-2115`).

**d) `set_port()` — no arm.** It has no port of its own; the `_ => return false`
default is correct (`model.rs:2674-2685`).

**e) `endpoint()` — no arm.** It falls into the existing `_ => None`
(`model.rs:2688-2704`), which is the contract the runtime dispatch depends on.

**f) New types.** Place next to `TorConfig` (`model.rs:1542-1580`):

```rust
/// How the native Psiphon client reaches the Psiphon network.
///
/// Everything here is read from the `"settings"` object of a
/// `{"protocol":"psiphon"}` outbound. `serverEntries` is the only way to make
/// the outbound usable without a network fetch; the remote list URLs and their
/// signing key are the Go client's `RemoteServerListURLs` /
/// `RemoteServerListSignaturePublicKey`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PsiphonConfig {
    /// Signed or locally embedded server-entry JSON objects, in preference
    /// order. Each element is one compact JSON object as the network publishes
    /// it (unknown fields preserved for signature verification).
    pub server_entries: Box<[Box<str>]>,
    /// Signed remote server-list URLs (`RemoteServerListURLs`).
    pub remote_server_list_urls: Box<[Box<str>]>,
    /// The Ed25519 key (base64) that signs remote server entries
    /// (`ServerEntrySignaturePublicKey`).
    pub server_entry_signature_public_key: Option<Box<str>>,
    /// Where to persist imported entries and tactics; `None` keeps them in
    /// memory only (honest default: a proxy config should not need a data dir).
    pub data_dir: Option<Box<str>>,
    /// An upstream SOCKS5/HTTP proxy to reach Psiphon through
    /// (`UpstreamProxyURL`), e.g. a local Tor or another VPN.
    pub upstream_proxy: Option<PsiphonUpstreamProxy>,
    /// ISO 3166-1 alpha-2 egress region; empty means any (`EgressRegion`).
    pub egress_region: Box<str>,
    /// Tunnel protocols to try, best first; empty selects the client's default
    /// order. Names are the Go wire names (`"OSSH"`, `"TLS-OSSH"`, ...).
    pub protocols: Box<[PsiphonTunnelProtocol]>,
    /// Fetch and apply tactics when the client can (§6.4, phase 3).
    pub tactics: bool,
    /// Per-server tunnel establishment budget in seconds
    /// (`TunnelConnectTimeout`, Go default 20; `psiphon/common/parameters/parameters.go:655`).
    pub establish_timeout_secs: u16,
    /// How many server candidates to dial at once.
    pub establish_concurrency: u8,
    /// How many SSH tunnels to keep up; 1 is the Go default
    /// (`psiphon/config.go:56`, `:1724-1726`).
    pub tunnel_pool_size: u8,
    /// SSH channel receive window in bytes
    /// (Go default 4 * 32 KiB; `psiphon/common/crypto/ssh/channel.go:59-81`).
    pub channel_window_bytes: u32,
    /// Refuse a new channel above this many open ones, instead of relying on
    /// the server's LRU (`DEFAULT_MAX_TCP_PORT_FORWARD_COUNT = 512`,
    /// `psiphon/server/trafficRules.go:37-38`).
    pub max_channels: u16,
    /// `keepalive@openssh.com` interval in seconds; 0 disables. The server
    /// drops a tunnel idle for 5 minutes (`psiphon/common/parameters/parameters.go:741-748`).
    pub keepalive_secs: u16,
    /// The identity sent in the mandatory handshake (`propagation_channel_id`,
    /// `sponsor_id`, `client_version`, `client_platform`).
    pub handshake: PsiphonHandshakeIdentity,
}

impl Default for PsiphonConfig { /* see the defaults table in §6.2 */ }

/// The implemented tunnel protocols, as typed values rather than strings: the
/// runtime maps this exhaustively to `zero_psiphon::protocol::TunnelProtocol`,
/// so a name cannot drift between the config crate and the client crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PsiphonTunnelProtocol {
    Ssh,
    Ossh,
    TlsOssh,
    UnfrontedMeek,
    UnfrontedMeekHttps,
    FrontedMeek,
    FrontedMeekHttp,
}

impl PsiphonTunnelProtocol {
    /// The wire name, as in a server entry's `capabilities` and in
    /// `LimitTunnelProtocols` (`psiphon/common/protocol/protocol.go`).
    pub fn name(self) -> &'static str { /* "SSH" | "OSSH" | "TLS-OSSH" | ... */ }
    pub fn parse(name: &str) -> Option<Self> { /* exact, case-sensitive */ }
    pub fn all() -> &'static [Self] { /* the seven above, client preference order */ }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PsiphonUpstreamProxy {
    pub kind: PsiphonProxyKind,
    pub host: Address,
    pub port: u16,
    pub username: Option<Box<str>>,
    pub password: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PsiphonProxyKind { Socks5, Http }

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PsiphonHandshakeIdentity {
    /// Hex; all zeros when the app has no channel identity.
    pub propagation_channel_id: Box<str>,
    /// Exactly 16 hex characters; all zeros when unaffiliated (the harness
    /// value, `SERVER-HARNESS.md` §6.2; the server requires the length,
    /// `psiphon/server/api.go:2161-2163`).
    pub sponsor_id: Box<str>,
    /// An integer string (`psiphon/server/api.go:1480`).
    pub client_version: Box<str>,
    /// Non-empty, no whitespace (`psiphon/server/api.go:2198-2203`).
    pub client_platform: Box<str>,
}
```

**g) Validation.** Add a block inside `Outbound::validate` immediately after
the Tor block (`model.rs:2309-2360`), so the two whole-tunnel outbounds are
validated together:

```rust
if let OutboundProtocol::Psiphon(psiphon) = &self.protocol {
    if psiphon.server_entries.is_empty() && psiphon.remote_server_list_urls.is_empty() {
        return Err(format!(
            "outbound {}: a Psiphon outbound needs serverEntries, or \
             remoteServerListUrls and serverEntrySignaturePublicKey",
            self.tag
        ));
    }
    if !psiphon.remote_server_list_urls.is_empty()
        && psiphon.server_entry_signature_public_key.is_none()
    {
        return Err(format!(
            "outbound {}: a remote server list needs serverEntrySignaturePublicKey",
            self.tag
        ));
    }
    if psiphon.server_entries.len() > 512
        || psiphon.server_entries.iter().any(|entry| entry.len() > 64 * 1024)
    {
        return Err(format!(
            "outbound {}: at most 512 server entries of at most 64 KiB each",
            self.tag
        ));
    }
    if let Some(key) = &psiphon.server_entry_signature_public_key {
        // 32 bytes of standard base64, exactly as the Go client carries it.
        use base64::Engine as _;
        let ok = base64::engine::general_purpose::STANDARD
            .decode(key.trim())
            .is_ok_and(|bytes| bytes.len() == 32);
        if !ok {
            return Err(format!(
                "outbound {}: serverEntrySignaturePublicKey must be 32 bytes of base64",
                self.tag
            ));
        }
    }
    if psiphon.data_dir.as_deref().is_some_and(|dir| dir.trim().is_empty()) {
        return Err(format!("outbound {}: dataDir must not be empty", self.tag));
    }
    if let Some(proxy) = &psiphon.upstream_proxy {
        if proxy.port == 0 {
            return Err(format!(
                "outbound {}: the upstream proxy port must not be 0",
                self.tag
            ));
        }
        let (user, pass) = (&proxy.username, &proxy.password);
        if user.is_some() != pass.is_some() {
            return Err(format!(
                "outbound {}: an upstream proxy needs both a user and a password, or neither",
                self.tag
            ));
        }
    }
    if !psiphon.egress_region.is_empty()
        && (psiphon.egress_region.len() != 2
            || !psiphon.egress_region.bytes().all(|b| b.is_ascii_uppercase()))
    {
        return Err(format!(
            "outbound {}: egressRegion must be two uppercase letters (an ISO 3166-1 code)",
            self.tag
        ));
    }
    if !(5..=300).contains(&psiphon.establish_timeout_secs) {
        return Err(format!(
            "outbound {}: establishTimeoutSeconds must be 5..=300",
            self.tag
        ));
    }
    if !(1..=8).contains(&psiphon.establish_concurrency) {
        return Err(format!(
            "outbound {}: establishConcurrency must be 1..=8",
            self.tag
        ));
    }
    if !(1..=4).contains(&psiphon.tunnel_pool_size) {
        return Err(format!(
            "outbound {}: tunnelPoolSize must be 1..=4",
            self.tag
        ));
    }
    if !(32 * 1024..=4 * 1024 * 1024).contains(&psiphon.channel_window_bytes) {
        return Err(format!(
            "outbound {}: channelWindowBytes must be 32 KiB..=4 MiB",
            self.tag
        ));
    }
    if !(1..=1024).contains(&psiphon.max_channels) {
        return Err(format!(
            "outbound {}: maxChannels must be 1..=1024",
            self.tag
        ));
    }
    if psiphon.keepalive_secs != 0 && !(15..=300).contains(&psiphon.keepalive_secs) {
        return Err(format!(
            "outbound {}: keepaliveSeconds must be 0 (off) or 15..=300",
            self.tag
        ));
    }
    // These follow the Tor/SOCKS rule: an outbound that dials its own network
    // cannot also carry a Xray transport/security stack. Silently ignoring a
    // `tlsSettings` would make a config lie about what leaves the machine.
    if !matches!(self.stream.transport, Transport::Raw)
        || !matches!(self.stream.security, Security::None)
        || self.mux.enabled
        || self.stream.raw_http_header.is_some()
        || !self.stream.evasion.is_empty()
        || self.stream.sockopt.dialer_proxy.is_some()
    {
        return Err(format!(
            "outbound {}: a Psiphon outbound dials its own network and takes no \
             streamSettings, mux, evasion, or dialerProxy",
            self.tag
        ));
    }
    for protocol in psiphon.protocols.iter() {
        if !Self::psiphon_protocol_is_implemented(*protocol) {
            return Err(format!(
                "outbound {}: Psiphon protocol {} is not implemented in this build",
                self.tag,
                protocol.name()
            ));
        }
    }
}
```

`psiphon_protocol_is_implemented` lives in `zero-config` (it cannot call
`zero_psiphon::TunnelProtocol::supported` without depending on the client
crate). Start it as `matches!(p, Ssh | Ossh)` and widen it as carriers land;
`crates/zero-runtime/tests/psiphon_outbound.rs` asserts every name
`PsiphonTunnelProtocol::all()` yields is accepted by
`zero_psiphon::protocol::TunnelProtocol::parse` (pins the two tables together).

### 3.2 `crates/zero-config/src/xray_json.rs`

**a) Dispatch.** Add one arm to the `match proto` in `parse_outbound`
(`xray_json.rs:1706-1735`, the Tor arm is line 1719):

```rust
"psiphon" => parse_psiphon(settings, &path)?,
```

`unflatten_outbound` (`xray_json.rs:1502-1547`) returns `None` for `settings`
without an `address`, so the simplified-form rewrite does not touch a Psiphon
outbound. `parse_stream` still runs for any supplied `streamSettings`
(`xray_json.rs:1737-1740`), and `Outbound::validate` rejects it — that is why
the failure is reported at config-compile time with a path, not at connect
time.

**b) Parser.** Add next to `parse_tor` (`xray_json.rs:2313-2369`):

```rust
/// `{"protocol": "psiphon", "settings": {...}}`.
///
/// Every settings key maps to one `PsiphonConfig` field; unknown keys are
/// refused rather than ignored, because a typo in `upstreamProxy` or
/// `egressRegion` would silently change where traffic goes (the same reason
/// the parser rejects unknown security-relevant Xray fields).
fn parse_psiphon(settings: Option<&Value>, path: &str) -> R<OutboundProtocol> {
    let Some(settings) = settings else {
        return Ok(OutboundProtocol::Psiphon(PsiphonConfig::default()));
    };
    let object = settings
        .as_object()
        .ok_or_else(|| format!("{path}.settings must be an object"))?;

    // 1. Unknown keys are configuration errors.
    const KNOWN: &[&str] = &[
        "serverEntries", "remoteServerListUrls", "serverEntrySignaturePublicKey",
        "dataDir", "upstreamProxy", "egressRegion", "protocols", "tactics",
        "establishTimeoutSeconds", "establishConcurrency", "tunnelPoolSize",
        "channelWindowBytes", "maxChannels", "keepaliveSeconds", "handshake",
    ];
    for key in object.keys() {
        if !KNOWN.contains(&key.as_str()) {
            return Err(format!(
                "{path}.settings: unknown key {key:?}; a misspelt Psiphon setting \
                 would change where traffic goes, so it is refused"
            ));
        }
    }

    // 2. Server entries: objects only, preserved as compact JSON.
    let server_entries = match object.get("serverEntries") {
        None | Some(Value::Null) => Box::new([]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                if !item.is_object() {
                    return Err(format!(
                        "{path}.settings.serverEntries must contain JSON objects, \
                         exactly as the network publishes them"
                    ));
                }
                serde_json::to_string(item)
                    .map(Box::<str>::from)
                    .map_err(|error| format!("{path}.settings.serverEntries: {error}"))
            })
            .collect::<R<Box<[Box<str>]>>>()?,
        Some(_) => {
            return Err(format!(
                "{path}.settings.serverEntries must be an array of server entries"
            ))
        }
    };

    // 3. Remote list URLs: strings over http(s).
    let remote_server_list_urls = string_array(object, "remoteServerListUrls", path)?;
    for url in remote_server_list_urls.iter() {
        let parsed = url::Url::parse(url).map_err(|error| {
            format!("{path}.settings.remoteServerListUrls: {url:?}: {error}")
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!(
                "{path}.settings.remoteServerListUrls: {url:?} must be http or https"
            ));
        }
    }

    // 4. egressRegion is normalized to the Go wire form (uppercase).
    let egress_region = match object.get("egressRegion").and_then(Value::as_str) {
        None => "".into(),
        Some(region) => region.trim().to_ascii_uppercase().into_boxed_str(),
    };

    // 5. protocols: the wire names, in the person's order.
    let protocols = match object.get("protocols") {
        None | Some(Value::Null) => Box::new([]),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let name = item.as_str().ok_or_else(|| {
                    format!("{path}.settings.protocols[{index}] must be a string")
                })?;
                PsiphonTunnelProtocol::parse(name).ok_or_else(|| {
                    format!(
                        "{path}.settings.protocols[{index}]: {name:?} is not a Psiphon \
                         tunnel protocol (SSH, OSSH, TLS-OSSH, UNFRONTED-MEEK, \
                         UNFRONTED-MEEK-HTTPS, FRONTED-MEEK, FRONTED-MEEK-HTTP)"
                    )
                })
            })
            .collect::<R<Box<[PsiphonTunnelProtocol]>>>()?,
        Some(_) => return Err(format!("{path}.settings.protocols must be an array")),
    };

    // 6. upstreamProxy: socks5://[user:pass@]host:port or http://...
    let upstream_proxy = match object.get("upstreamProxy") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(parse_psiphon_proxy(text, path)?),
        Some(_) => return Err(format!("{path}.settings.upstreamProxy must be a string")),
    };

    // 7. handshake identity, with the harness/Go-client defaults.
    let handshake = match object.get("handshake") {
        None | Some(Value::Null) => PsiphonHandshakeIdentity::default(),
        Some(Value::Object(map)) => { /* four optional string keys, same strictness */ }
        Some(_) => return Err(format!("{path}.settings.handshake must be an object")),
    };

    Ok(OutboundProtocol::Psiphon(PsiphonConfig {
        server_entries,
        remote_server_list_urls,
        server_entry_signature_public_key: optional_string(object, "serverEntrySignaturePublicKey"),
        data_dir: optional_string(object, "dataDir"),
        upstream_proxy,
        egress_region,
        protocols,
        tactics: optional_bool(object, "tactics", true),
        establish_timeout_secs: optional_u16(object, "establishTimeoutSeconds", 20, path)?,
        establish_concurrency: optional_u8(object, "establishConcurrency", 3, path)?,
        tunnel_pool_size: optional_u8(object, "tunnelPoolSize", 1, path)?,
        channel_window_bytes: optional_u32(object, "channelWindowBytes", 128 * 1024, path)?,
        max_channels: optional_u16(object, "maxChannels", 128, path)?,
        keepalive_secs: optional_u16(object, "keepaliveSeconds", 60, path)?,
        handshake,
    }))
}
```

`parse_psiphon_proxy` uses `url::Url` (already a `zero-config` dependency,
`crates/zero-config/Cargo.toml:21`): accepted schemes `socks5`, `socks5h`,
`http`; missing/zero port is an error (no hidden default port: guessing 1080
versus 8080 silently is worse than asking); `user:pass` becomes
`username`/`password`. `https://` proxies are refused with "an https upstream
proxy is not implemented yet" rather than downgraded to `http`.

**c) Diagnostics policy.** All the above are hard errors. There is deliberately
no diagnostic note for a partially understood Psiphon outbound: a Psiphon
outbound either describes a network path the client can honour, or it is
rejected. This matches the module's stated rule
(`xray_json.rs:1-6`) and the Tor precedent.

### 3.3 `crates/zero-config/src/share_link.rs`

No new scheme. `psiphon://` falls into the generic "unsupported share link
scheme" error (`share_link.rs:126-163`). Replace that generic outcome with one
sentence that tells the person what to do — add an explicit arm next to `tor`:

```rust
// A Psiphon outbound is server entries plus a signing key plus protocol
// policy; a link cannot carry any of that. Say so instead of "unsupported".
"psiphon" => Err(
    "a psiphon:// link cannot describe a Psiphon outbound: it needs server entries \
     and a signing key, which do not fit in a link. Write the outbound as JSON \
     (see docs/config-compatibility.md)."
        .into(),
),
```

Pinned by a unit test in `share_link.rs`: `a_psiphon_link_says_it_is_json_only`
asserts the error contains "server entries" and "JSON".

### 3.4 Why no one-click catalog entry (yet)

`zero-config::oneclick` entries are static and generate a complete config from
nothing or from a link (`crates/zero-config/src/oneclick.rs:45-120`,
`:191-290`). A Psiphon profile cannot be generated that way: it needs at least
one server entry. When an app ships an embedded list, the right shape is an app
dialog (like the WARP account entry, `Input::WarpAccount`) that writes a normal
JSON profile; that is a UI task in the Desktop/Mobile repositories, not a
catalog generator. `zray-cli` therefore gets no `zray connect psiphon` in v1;
`zray run <config>` is the supported path.

---

## 4. `zero-runtime` changes (exact edits)

### 4.1 `crates/zero-runtime/Cargo.toml`

```toml
[features]
# The native Psiphon client. Off by default for embedders, like `tor`; on by
# default in `zray-cli`. Without it a `psiphon` outbound parses and validates
# but every connection fails with a message saying the build has no Psiphon.
psiphon = ["dep:zero-psiphon"]

[dependencies]
zero-psiphon = { workspace = true, optional = true }
```

The feature name and the "parses, then refuses with a message" contract mirror
`tor` (`crates/zero-runtime/Cargo.toml:13-16`).

### 4.2 New `crates/zero-runtime/src/psiphon.rs` (module, `#[cfg(feature = "psiphon")]`)

This is the only place that knows both config types. It converts, validates the
cross-crate invariants, and maps errors to `zero_core::Failure`.

```rust
//! The bridge between `zero_config::PsiphonConfig` and the native client.

use zero_core::{Failure, FailureKind, Stage};

/// Compile the config-crate settings into the client crate's runtime config.
pub(crate) fn client_config(
    config: &zero_config::PsiphonConfig,
) -> Result<zero_psiphon::ClientConfig, String> {
    let entries = config
        .server_entries
        .iter()
        .map(|text| zero_psiphon::ServerEntry::from_json(text))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("serverEntries: {error}"))?;
    // Signature verification happens in the client at import time; entries that
    // came from the person's config are trusted, remote ones are not.
    let protocols = config
        .protocols
        .iter()
        .copied()
        .map(tunnel_protocol)
        .collect();
    Ok(zero_psiphon::ClientConfig {
        server_entries: entries,
        server_entry_signature_public_key: config
            .server_entry_signature_public_key
            .as_deref()
            .map(str::to_owned),
        remote_server_list_urls: config
            .remote_server_list_urls
            .iter()
            .map(|url| url.to_string())
            .collect(),
        tactics: config.tactics,
        data_dir: config.data_dir.as_deref().map(std::path::PathBuf::from),
        upstream_proxy: config.upstream_proxy.as_ref().map(upstream_proxy),
        egress_region: config.egress_region.to_string(),
        protocols,
        establish_timeout: std::time::Duration::from_secs(config.establish_timeout_secs.into()),
        establish_concurrency: usize::from(config.establish_concurrency),
        tunnel_pool_size: usize::from(config.tunnel_pool_size),
        channel_window_bytes: config.channel_window_bytes,
        max_channels: u32::from(config.max_channels),
        keepalive_interval: (config.keepalive_secs != 0)
            .then(|| std::time::Duration::from_secs(config.keepalive_secs.into())),
        handshake: zero_psiphon::HandshakeIdentity {
            propagation_channel_id: config.handshake.propagation_channel_id.to_string(),
            sponsor_id: config.handshake.sponsor_id.to_string(),
            client_version: config.handshake.client_version.to_string(),
            client_platform: config.handshake.client_platform.to_string(),
        },
        session_id: None,
    })
}

pub(crate) fn tunnel_protocol(
    protocol: zero_config::PsiphonTunnelProtocol,
) -> zero_psiphon::TunnelProtocol {
    use zero_config::PsiphonTunnelProtocol as P;
    use zero_psiphon::TunnelProtocol as T;
    match protocol {              // exhaustive: no default arm
        P::Ssh => T::Ssh,
        P::Ossh => T::Ossh,
        P::TlsOssh => T::TlsOssh,
        P::UnfrontedMeek => T::UnfrontedMeek,
        P::UnfrontedMeekHttps => T::UnfrontedMeekHttps,
        P::FrontedMeek => T::FrontedMeek,
        P::FrontedMeekHttp => T::FrontedMeekHttp,
    }
}

/// Drop-in error mapping so the rest of the runtime sees one taxonomy.
pub(crate) fn failure(error: zero_psiphon::Error) -> Failure { ... }
```

The `failure` mapping (or, preferably, `impl From<zero_psiphon::Error> for
zero_core::Failure` inside `zero-psiphon/src/error.rs`, since that crate
already depends on `zero-core`):

| `zero_psiphon::Error` | `FailureKind` | `Stage` |
|---|---|---|
| `Config`, `Signature` | `LocalPolicy` | `Resolving` |
| `Connect` | `TcpUnreachable` | `SocketConnected` |
| `Timeout { Tcp }` | `TcpTimeout` | `SocketConnected` |
| `Timeout { Tls }` | `TlsTimeout` | `TlsStarted` |
| `Obfuscation` | `ProtocolRejected` | `SocketConnected` |
| `Meek` | `HttpMalformed` | `RequestSent` |
| `Ssh` | `ProtocolRejected` | `TlsCompleted` |
| `Channel` | `ServerRejected` | `RequestSent` |
| `Protocol` | `ProtocolRejected` | `RequestSent` |
| `Closed` | `Cancelled` | `SocketConnected` |
| `Io(e)` | `Failure::from_io(&e, SocketConnected)` | from I/O |

This keeps the observatory/planner's failure taxonomy meaningful
(`crates/zero-core/src/error.rs:50-126`) instead of classifying every Psiphon
failure as `Unknown`.

### 4.3 `crates/zero-runtime/src/outbound.rs`

**a) Early dispatch in both entry points.** Add next to the Tor/MasterDNS
intercepts in `connect` (`outbound.rs:792-800`) and `connect_with_resolver`
(`outbound.rs:821-829`), before `outbound.endpoint()`:

```rust
if let OutboundProtocol::Psiphon(psiphon) = &outbound.protocol {
    return connect_psiphon(psiphon, destination).await;
}
```

Both must be added: the server-side sessions use `connect_with_resolver`
(`crates/zero-runtime/src/server.rs:6243-6245`), and a Psiphon outbound has no
endpoint for the managed resolver to resolve. This mirrors Tor. Note that a
Psiphon outbound deliberately does **not** run inside `within_setup_deadline`
(`outbound.rs:774-790`): the client applies per-candidate and per-attempt
deadlines itself (like Arti, `outbound.rs:867-870`), and a multi-candidate
establishment legitimately outlives the fixed 30 s outbound deadline.

**b) `connect_psiphon`, feature-on and feature-off** — copy the Tor pair
(`outbound.rs:870-895`):

```rust
/// Open a stream through the native Psiphon client.
///
/// The config is converted per call; the client crate caches one live tunnel
/// per identical conversion, so this is cheap on the hot path and survives
/// config reloads for unchanged settings.
#[cfg(feature = "psiphon")]
async fn connect_psiphon(
    config: &zero_config::PsiphonConfig,
    destination: &Destination,
) -> Result<BoxStream, Failure> {
    if destination.network != zero_core::Network::Tcp {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("Psiphon carries TCP only"));
    }
    let client_config = crate::psiphon::client_config(config)
        .map_err(|error| Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
            .with_detail(error))?;
    zero_psiphon::dial(&client_config, &destination.address, destination.port)
        .await
        .map(|stream| boxed(stream))
        .map_err(crate::psiphon::failure)
}

#[cfg(not(feature = "psiphon"))]
async fn connect_psiphon(
    _config: &zero_config::PsiphonConfig,
    _destination: &Destination,
) -> Result<BoxStream, Failure> {
    Err(Failure::new(FailureKind::LocalPolicy, Stage::Resolving).with_detail(
        "this build was made without Psiphon support; use a build with the `psiphon` feature",
    ))
}
```

`crate::psiphon` is declared in `lib.rs` behind the feature
(`crates/zero-runtime/src/lib.rs:6-36` for the module list; add `#[cfg(feature =
"psiphon")] mod psiphon;` next to `mod masterdns;`).

**c) `protocol_header`.** Add an arm returning `Ok(Vec::new())` for
`OutboundProtocol::Psiphon(_)` in `protocol_header`
(`outbound.rs:2858-2906`). The match ends in `other => Err(...)`, so the
compiler will not force this, but without it a Psiphon outbound that reached
the common path would be rejected with "does not open proxied streams".

**d) `strip_response`.** No arm needed: it is already `_ => stream`
(`outbound.rs:2910-2929`).

**e) `warmable` / `chainable`.** No change: both already return `false` for an
unknown protocol (`outbound.rs:2337-2360`, `:2455-2457`), and Psiphon is not
warmable (the SSH session is the warm state, held by the client cache) and not
chainable (a tunnel needs several connections, like Tor).

**f) `filter_family`/clean-IP path.** See §4.4; unchanged here.

### 4.4 `crates/zero-runtime/src/server.rs`

Three exhaustive matches will fail to compile until `Psiphon` is added, which
is the desired forcing function:

1. `connect_vless_mux_target`'s `match &outbound.protocol`
   (`server.rs:5317-5369`, protocol list at `:5344-5352`) — add
   `| OutboundProtocol::Psiphon(_)`.
2. `open_stream`'s equivalent match (`server.rs:6570-6637`, list at
   `:6605-6622`) — add `| OutboundProtocol::Psiphon(_)`.
3. The clean-IP endpoint rewrite (`server.rs:8400-8430`) — add
   `OutboundProtocol::Psiphon(_) => {}` to the "leave alone" arm
   (`:8420-8430`), beside Tor/MasterDns/Socks: server entries are the user's
   chosen path, and rewriting them to a "clean" CDN edge would dial an address
   that is not a Psiphon server.

**a) UDP refusal before dialling.** `proxy_udp_inner` (`server.rs:5779-6018`)
calls `connect_with_resolver` and then matches the protocol for framing; its
`other => Err("… cannot carry UDP")` (`server.rs:6016`) would open a tunnel
channel first. Add the early refusal at the top, beside the `dialerProxy`
refusal:

```rust
if matches!(outbound.protocol, OutboundProtocol::Psiphon(_)) {
    return Err(format!(
        "{} is a Psiphon tunnel, which carries TCP only",
        outbound.tag
    ));
}
```

Tor gets the same behaviour indirectly (its `connect_tor` refuses UDP), but the
message appears before any socket is opened for both. Pinned by a runtime test
(§7.4).

**b) Reload.** No code change. `Server::reload` swaps the config `Arc`
(`server.rs:1467-1540`) and forgets balancer health for changed outbounds by
comparing their `Debug` form (`server.rs:1500-1514`). Two consequences to
design for:

- `PsiphonConfig`'s `Debug` (already derived) must be deterministic and must
  not print secrets. The server entries are `Box<str>` JSON strings, which may
  contain `sshPassword`. **Fix required:** implement `Debug for PsiphonConfig`
  by hand (or store a redacted form in a `Debug` wrapper) so
  `format!("{outbound:?}")` used by reload and diagnostics never prints server
  entry secrets. This is a review blocker.
- An unchanged `PsiphonConfig` produces an unchanged `Outbound::Debug` and
  therefore does not reset health (`server.rs:1500-1514`); the client cache key
  (`ClientConfig::key()`) is likewise unchanged, so the live tunnel is reused
  across the reload. Existing sessions keep their `Arc<Client>` and continue;
  new sessions use the new config. A changed config creates a new client and
  the old tunnel closes when its last stream ends (idle sweep, §4.6).

**c) Stats/accounts.** No Psiphon-specific hooks. The runtime already meters
every proxied stream through `relay()` and into `Stats`
(`crates/zero-runtime/src/server.rs:6210-6265`, `:7010-7060`), per-tag traffic
counters (`Stats::record_tag_traffic`, `server.rs:104-150`) and the accounts
meter (`accounts::meter`, `server.rs:3040-3060`). The Psiphon client only adds
`tracing` events, which the log-privacy tests cover
(`crates/zero-runtime/tests/log_privacy.rs`).

**d) Platform/network change.** `migrate_quic_connections`
(`crates/zero-runtime/src/lib.rs:64-71`) does nothing for Psiphon; a TCP SSH
tunnel is not migrated, it dies and is replaced on the next `dial` (§4.6). The
mobile host should call `zero_psiphon::forget` (or just let the next dial
reconnect) on a network change; add this to the embedding notes in phase 6.

### 4.5 `crates/zray-cli`

```toml
[features]
# The native Psiphon client. On by default in the CLI (the desktop app ships
# it); embedders that link zero-runtime directly opt in.
default = ["psiphon"]
psiphon = ["zero-runtime/psiphon"]
```

No new subcommands or flags in v1. The CLI already runs arbitrary configs
(`crates/zray-cli/src/main.rs:23-48`), and `zray check` reports parse/validate
errors, which includes all the Psiphon settings validation above. A future
`zray psiphon doctor <config>` (config check + tactic fetch + one channel to a
probe destination) can be added once phases 2-3 land, modelled on `zray catalog
doctor` (`crates/zray-cli/src/oneclick.rs:1-12`).

### 4.6 Shared instance lifecycle (`zero-psiphon/src/shared.rs`)

The `zero-tor` pattern, adapted because a Psiphon tunnel must be kept alive by
the streams it carries:

```rust
static CLIENTS: Mutex<Option<HashMap<[u8; 32], Weak<Client>>>> = Mutex::new(None);

/// Dial through the client for `config`, creating it if needed.
pub async fn dial(
    config: &ClientConfig,
    address: &zero_core::Address,
    port: u16,
) -> Result<zero_core::BoxStream> {
    let key = config.key();
    // Fast path: an existing client is alive.
    let existing = with_clients(|map| map.get(&key).and_then(Weak::upgrade));
    let client = match existing {
        Some(client) if client.is_alive() => client,
        _ => establish(config, key).await?,   // per-key async mutex, one dial at a time
    };
    let stream = client.dial(address, port).await?;
    Ok(zero_core::boxed(stream))
}

/// Drop the cache entry (a changed config keeps its own key, so this is for
/// tests and for `shutdown_all`).
pub fn forget(config: &ClientConfig);
pub fn shutdown_all();

#[cfg(feature = "test-util")]
pub fn instance_id(config: &ClientConfig) -> Option<u64>;
```

Rules:

- `Client::dial` returning `Error::Closed`/`Error::Ssh`/`Error::Io` means the
  tunnel died: the shared layer removes the cache entry, establishes a fresh
  client (one attempt, no spinning), and retries the channel once. A second
  failure is returned to the caller. This is the transparent-reconnect story:
  browsers retry their own requests, and the proxy must be able to carry the
  retry on a new tunnel.
- The `Weak` ensures no tunnel outlives its purpose: when no stream and no
  dial holds the `Arc`, the `Client` drops.
- Each `Client` spawns one idle task (the same shape as `sleep_when_idle`,
  `crates/zero-tor/src/lib.rs:400-420`): after `IDLE_AFTER = 120 s` with
  `open_channels == 0`, it calls `handle.disconnect` and marks the client
  closed, so a forgotten proxy config does not hold a socket and ~0.5 MiB for
  the life of the process.
- The cache is swept on every `establish`: entries whose `Weak` no longer
  upgrades are removed, and the map is capped at 8 entries (a host that reloads
  many configs cannot grow it without bound).

### 4.7 Failure messages (the contract users see)

Every message is one actionable sentence, matching `zero-tor`'s rule
(`crates/zero-tor/src/lib.rs:225-250`) and the Tor feature-off message
(`zero-runtime/tests/tor_outbound.rs:17-25`):

| Situation | Message (prefix from `failure`) |
|---|---|
| feature off | "this build was made without Psiphon support; use a build with the `psiphon` feature" |
| no entries and no fetch result | "no Psiphon server entries: add signed entries to serverEntries, or set remoteServerListUrls and serverEntrySignaturePublicKey" |
| all candidates refused | "every Psiphon server entry failed; the last error was: …" |
| UDP destination | "Psiphon carries TCP only" |
| signature bad | "server entry signature: …" / "the remote server list signature does not verify" |
| channel refused by rules | "tunnel channel: the server refused this destination (…)" |

---

## 5. Documentation and packaging

### 5.1 `docs/psiphon/INTEGRATION.md` (this file)

Committed as the design of record.

### 5.2 `docs/psiphon/` companions

`ARCHITECTURE.md`, `WIRE-SPEC.md`, `SERVER-HARNESS.md` are referenced from §0
and from code comments (`crates/zero-psiphon/src/*.rs` already cites the Go
files).

### 5.3 `docs/config-compatibility.md` — new section

The file's contract is "each divergence names the test that holds it in place"
(`docs/config-compatibility.md:1-8`). Add after the Tor section
(`docs/config-compatibility.md:91-118`):

```markdown
## The `psiphon` outbound has no Xray counterpart

**What differs.** `{"protocol": "psiphon"}` runs Psiphon's client protocol
inside the process: it reads the same server entries, tunnels SSH through
obfuscated SSH (OSSH), pins the server host key from the entry, and forwards
destinations as SSH `direct-tcpip` channels. It needs a build with the
`psiphon` feature; without it the outbound parses, then every connection fails
with a message saying the build has no Psiphon.

**Why.** The existing way to use Psiphon was a SOCKS5 outbound pointing at a
separate Psiphon client (see the SOCKS5 section). That works, but it needs a
second process and exposes a local SOCKS port; the native client removes both.

**Divergences from the Go client** (deliberate, each pinned by a test):

- TCP only: no packet tunnel, no UDP. A UDP destination is refused at once.
- No `psiphon://` share link: entries cannot fit a link.
- The bootstrap fetches (remote server list, tactics) use Zray's shaped TLS
  stack, not uTLS; they are not tunnelled and their DNS lookups are local.
- Tactics are stored and a bounded subset is applied; unknown parameters are
  logged and ignored (the Go client applies its full parameter table).
- No server-info exchange between clients, no push payloads, no feedback
  upload, no upgrade download, no in-proxy/Conjure/TapDance/QUIC-OSSH.
- The client sends no `ClientFeatures` and no `sponsor_id` unless configured;
  the server accepts an empty sponsor in the credential payload but requires
  the handshake `sponsor_id` to be 16 hex characters, so the client sends all
  zeros when unaffiliated.

**Pinned by.** `zero-psiphon` (server-entry signature, OSSH vectors, tunnel
tests against an in-process mock), `zero-config` (settings schema),
`zero-runtime/tests/psiphon_outbound.rs` (UDP refusal, feature-off message,
loopback tunnel), and the ignored `zero-runtime/tests/psiphon_interop.rs`
(real `psiphond`, `.research/psiphon-server-harness`).
```

### 5.4 `docs/platforms.md` / `docs/embedding.md`

One paragraph each, in phase 6: the feature name and default per host
(`zero-runtime` off, `zray-cli` on), that server entries are supplied by the
app/config, and that `zero_psiphon::shutdown_all()` belongs in the host's
shutdown path.

---

## 6. The config the user writes

### 6.1 Minimal working outbound

```json
{
  "outbounds": [
    {
      "tag": "psiphon",
      "protocol": "psiphon",
      "settings": {
        "serverEntries": [
          {
            "ipAddress": "192.0.2.10",
            "region": "US",
            "sshPort": 22,
            "sshObfuscatedPort": 2222,
            "sshUsername": "psiphon_abcd",
            "sshPassword": "…",
            "sshHostKey": "AAAAB3NzaC1yc2EAAAADAQAB…",
            "sshObfuscatedKey": "…",
            "capabilities": ["SSH", "OSSH", "TLS"],
            "configurationVersion": 1
          }
        ]
      }
    }
  ]
}
```

An entry is exactly the JSON object the Psiphon network publishes
(`psiphon/common/protocol/serverEntry.go:49-107`), so an app can paste its
embedded list in unchanged. Entries supplied here are trusted (they came from
the person/app, not from the network).

### 6.2 Full field table

| Key | Type | Default | Meaning / validation |
|---|---|---|---|
| `serverEntries` | array of objects | `[]` | Server-entry objects; ≤ 512, ≤ 64 KiB each; trusted |
| `remoteServerListUrls` | array of strings | `[]` | http(s) URLs; requires the key below |
| `serverEntrySignaturePublicKey` | base64 string | none | 32 bytes; Ed25519 key for remote entries |
| `dataDir` | string | none | persistence dir; `None` = memory only |
| `upstreamProxy` | string URL | none | `socks5://[user:pass@]host:port` or `http://…`; https refused |
| `egressRegion` | string | `""` (any) | 2 letters, normalized upper-case |
| `protocols` | array of strings | `[]` (client order: OSSH, TLS-OSSH, UNFRONTED-MEEK-HTTPS, UNFRONTED-MEEK, FRONTED-MEEK-HTTPS, FRONTED-MEEK-HTTP, SSH) | wire names only; phase-1 builds implement OSSH (+SSH) |
| `tactics` | bool | `true` | fetch/apply tactics when implemented; parse-time accepted always |
| `establishTimeoutSeconds` | number | `20` | 5..=300; Go `TunnelConnectTimeout` = 20 s (`psiphon/common/parameters/parameters.go:655`) |
| `establishConcurrency` | number | `3` | 1..=8; Go default 10 (`parameters.go:653`), lowered for phone memory |
| `tunnelPoolSize` | number | `1` | 1..=4; Go default 1 (`psiphon/config.go:56`) |
| `channelWindowBytes` | number | `131072` | 32 KiB..=4 MiB; Go default 4 × 32 KiB (`channel.go:59-81`) |
| `maxChannels` | number | `128` | 1..=1024; the server LRU limit is 512 (`psiphon/server/trafficRules.go:37-38`) |
| `keepaliveSeconds` | number | `60` | 0 = off, else 15..=300; Go randomizes 60-120 s (`parameters.go:747-748`), server idle timeout 5 min |
| `handshake.propagationChannelId` | string | `"0000000000000000"` | hex (`psiphon/server/api.go:1478`) |
| `handshake.sponsorId` | string | `"0000000000000000"` | exactly 16 hex (`api.go:2161-2163`) |
| `handshake.clientVersion` | string | `"1"` | integer string (`api.go:1480`) |
| `handshake.clientPlatform` | string | `"Other"` | non-empty, no whitespace (`api.go:2198-2203`) |

### 6.3 Mapping from Go `config.json`

| Go field (`psiphon/config.go`) | Ours | Note |
|---|---|---|
| `ServerEntrySignaturePublicKey:618` | `serverEntrySignaturePublicKey` | same value/key form |
| `RemoteServerListURLs:423` | `remoteServerListUrls` | list kept; `TransferURL` fronting specs not supported in v1 |
| `UpstreamProxyURL:342` | `upstreamProxy` | socks5/http only; Go also supports socks4a/obfuscated variants |
| `EgressRegion:169` | `egressRegion` | same |
| `LimitTunnelProtocols:247` | `protocols` | subset; `InitialLimitTunnelProtocols` not supported |
| `TunnelPoolSize:315` | `tunnelPoolSize` | capped at 4 (Go allows up to 32) |
| `ConnectionWorkerPoolSize:296` | `establishConcurrency` | default 3 vs Go 10 |
| `TunnelConnectTimeout` (param) | `establishTimeoutSeconds` | 20 s both |
| `SSHChannelWindowSize` (`config.go:888`) | `channelWindowBytes` | Go takes a count of 32 KiB units; ours takes bytes |
| `DataRootDirectory:83` | `dataDir` | data root; not "full control of the directory" as in Go — we create one subdirectory `psiphon/` and never delete outside it |
| `PropagationChannelId:131`, `SponsorId:138`, `ClientVersion:149`, `ClientPlatform:153` | `handshake.*` | same wire values; only the handshake sends them |
| `DisableTactics:400` | `tactics` (inverted) | — |
| `TargetServerEntry:410` | (none) | express it as a one-element `serverEntries` |
| `EmbeddedServerEntryList` (separate client arg, `ConsoleClient/main.go:51-52`) | `serverEntries` | first-class in config instead of a file argument |
| Local proxies (`LocalSocksProxyPort` etc.) | (none) | Zray's inbounds already are the local proxy; no extra listener |
| Notices, feedback, upgrade, exchange, packet tunnel, in-proxy, device region, authorizations | (none) | out of scope, see `WIRE-SPEC.md` risks |

Data-dir layout (phase 3): `<dataDir>/psiphon/server-entries.json` (array of
`{entry, source, timestamp}`), `tactics.json` (record + tag + expiry), both
written with `write → fsync → rename` in the same directory so a crash leaves
the previous file intact. No process-level lock in v1; two Zray processes
sharing one `dataDir` is documented as unsupported (a later phase can add the
Go client's lock file semantics, `psiphon/config.go:85-98`).

### 6.4 Tactics (phase 3)

`tactics: true` makes the client, before its first dial, try a tactics fetch
from a server entry that advertises a tactics protocol
(`ServerEntry::tactics_request_public_key`). The record is a signed JSON body
with a tag, TTL and a `Parameters` map (`psiphon/common/tactics/tactics.go:354-393`);
verification is Ed25519 over the Go-encoded body (the `json.rs` encoder exists
for exactly this class of signature). The client applies a **bounded subset**:
`TunnelConnectTimeout`, `SSHKeepAlivePeriodMin/Max`, `SSHChannelWindowSize`,
`LimitTunnelProtocols` (as an intersection with the config, never an
expansion), and remote server list URLs/key. Unknown parameter names are stored
and logged at debug, never acted on. Failure to fetch is never fatal: the
client dials with its configured values. This is the main behavioural
divergence and is documented in §5.3.

---

## 7. Test plan

Test layers, cheapest first. Existing repository conventions are followed:
unit tests in-module (`#[cfg(test)]`), cross-module tests in `tests/`,
loopback runtime tests with a hand-written server, and ignored tests for
anything that needs the internet or a real implementation
(`crates/zero-runtime/tests/loopback_interop.rs:1-12`,
`crates/zero-runtime/tests/tor_outbound.rs:78-81`).

### 7.1 Unit tests

| File | Test | Asserts |
|---|---|---|
| `zero-psiphon/src/protocol.rs` | existing | capability table, round-trip names |
| `zero-psiphon/src/server_entry.rs` | existing | fields, capability rules, signature round-trip/tamper, Debug redaction |
| `zero-psiphon/src/json.rs` | existing | Go encoding (sorted keys, escaping, float64) |
| `zero-psiphon/src/obfuscator/*` (new) | `derived_keys_match_go_vectors` | RC4 key/IV derivation equals `fixtures/ossh-vectors.json::keyDerivation` |
| | `plain_preamble_matches_go_bytes` | first-write bytes equal `preamblePlain` |
| | `prefixed_preamble_matches_go_bytes` | prefix header + terminator equal `preamblePrefixed{Short,Long}` |
| | `framing_rewrites_until_newkeys` | packet rewrite + padding policy equals `osshFraming` |
| | `newkeys_turns_both_directions_transparent` | byte-for-byte after client+server NEWKEYS |
| | `server_mode_until_newkeys` | mock server derives symmetric state from the seed |
| `zero-psiphon/src/tunnel.rs` | existing (6) | auth payload, host-key pinning, session id, stream carry |
| | `a_channel_before_the_handshake_is_refused` (new) | mock refuses like the Go server (`tunnelServer.go:5059-5068`); client surfaces `Error::Channel` with "administratively prohibited" |
| `zero-psiphon/src/config.rs` | `validation_rejects_each_bad_field` | one-case-per-rule table test |
| | `the_cache_key_covers_secrets` | two configs differing only in a password hash differently |
| `zero-psiphon/src/shared.rs` | `identical_configs_share_one_client` (test-util) | `instance_id` equal; handshake count 1 |
| | `a_dead_tunnel_is_replaced_once` (test-util) | stop mock; dial re-establishes; second dial uses new instance |
| `zero-config` (`model.rs` tests) | `psiphon_configs_are_not_printed_with_secrets` | `Debug` of an outbound with a password does not contain it |
| `zero-config` (`xray_json.rs` tests) | `psiphon_settings_parse_with_defaults` | defaults from §6.2 |
| | `psiphon_rejects_unknown_settings_keys` | typo message names the key |
| | `psiphon_requires_entries_or_remote_list` | both-empty error |
| | `psiphon_remote_list_needs_key` | error |
| | `psiphon_upstream_proxy_forms` | socks5/http ok, https/typo/port 0 refused |
| | `psiphon_protocol_names_are_the_wire_names` | `parse` matches `PsiphonTunnelProtocol::all` |
| | `psiphon_has_no_endpoint` | `Outbound::endpoint() == None` |
| | `psiphon_rejects_stream_settings` | `tlsSettings`/`mux`/`dialerProxy` errors name the tag |
| `zero-config/src/share_link.rs` | `a_psiphon_link_says_it_is_json_only` | message contains "server entries" and "JSON" |

### 7.2 In-process mock `psiphond` (`zero-psiphon/src/mock.rs`, `test-util`)

This is the CI workhorse: a `russh` server behind the crate's own OSSH **server**
mode, so the client can be tested end-to-end with no Go, no network, and no
ports that can collide with a real host.

```rust
//! A mock Psiphon server: the SSH semantics of `psiphond` plus, optionally, the
//! OSSH layer, in one process, on a loopback port.

pub struct MockServerConfig {
    pub protocols: MockProtocols,          // PlainSsh | Ossh | Both
    pub ssh_password: String,
    pub ossh_key: String,                  // hex, as a server entry carries it
    pub echo: bool,                        // relay channels to a local echo sink
    pub require_handshake: bool,           // default true, like psiphond
}

pub struct MockServer {
    entry: ServerEntry,                    // pointing at 127.0.0.1:<port>
    ssh_port: Option<u16>,
    ossh_port: Option<u16>,
    seen: Arc<StdMutex<Vec<SeenChannel>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenChannel { pub host: String, pub port: u16, pub handshaked: bool }

impl MockServer {
    pub async fn start(config: MockServerConfig) -> std::io::Result<Self>;
    pub fn client_config(&self) -> ClientConfig;       // one trusted entry
    pub fn entry_json(&self) -> serde_json::Value;     // for zero-config JSON tests
    pub fn seen(&self) -> Vec<SeenChannel>;
    pub fn stop(self);
}
```

Implementation notes, each pinned by the mock's tests:

- **Host key:** generate with `russh::keys::PrivateKey::random` (or
  `ssh-keygen -t rsa -b 2048` when the interop shape matters); the entry's
  `sshHostKey` is `base64(public_key.to_bytes())`, the same equality the client
  pins (`tunnel.rs::Pinned`; proven against the harness, `SERVER-HARNESS.md`
  §9.1).
- **Password auth:** `russh::server::Handler::auth_password` parses the JSON
  credential payload, checks `SshPassword`, checks `SessionId` is 32 hex, and
  checks the username — i.e. it enforces the server's contract
  (`psiphon/server/tunnelServer.go:3026-3060`), not just "any password".
- **Handshake:** `server::Handler` handles the global request
  `psiphon-handshake` (`russh` exposes `Handler::global_request`; see the
  skeleton's client `send_global_request` counterpart) and records
  `handshaked = true`. Until then `channel_open_direct_tcpip` must
  `reply.reject(ChannelOpenFailure::AdministrativelyProhibited)`, matching the
  real server (`tunnelServer.go:5059-5068`).
- **Channels:** `channel_open_direct_tcpip(channel, host, port, origin, port,
  reply, _session)` → record `SeenChannel`, `reply.accept().await`, spawn a task
  that relays `channel.into_stream()` to the echo sink; the handler returns
  immediately so the session loop is never blocked (the `russh` echoserver
  example shape). This is the same construction the skeleton's in-module tests
  already use (`crates/zero-psiphon/src/tunnel.rs` test module).
- **OSSH server mode:** wrap the accepted `TcpStream` with
  `obfuscator::server(...)` (reads the 16-byte seed, derives keys, replays the
  prefix), then `russh::server::run_stream`.
- **Failure injection:** a builder switch for "refuse the handshake", "refuse
  channel with this reason", "drop after N bytes", "stop after first channel",
  so the client's retry/one-retry semantics can be asserted.
- **Why not reuse `psiphond` for CI:** it needs Go 1.26.9, a signed entry and a
  process tree the agent sandbox may kill (`SERVER-HARNESS.md` §10); the mock
  is milliseconds and hermetic. The real server is the interop oracle, not the
  CI server.

### 7.3 Transport/wire parity

`zero-psiphon/tests/obfuscator_wire.rs` (fixtures copied from
`.research/wire-vectors/fixtures/ossh-vectors.json`, provenance in
`WIRE-SPEC.md` Appendix C):

- `every_ossh_vector_replays` — for each vector group (`preamblePlain`,
  `preamblePrefixedShort`, `preamblePrefixedLong`, `osshFraming`,
  `keyDerivation`, `serverPrefixReply`, `serverIdentificationLinePadding`), the
  Rust implementation produces/accepts the exact bytes. Vectors are generated
  from the Go code, so a green test means the Rust layer matches the reference,
  not itself.
- `a_prefix_terminator_mismatch_fails_closed` — wrong terminator/prefix is an
  error, never a silently different cipher state.
- `a_replayed_seed_is_rejected_by_the_mock_server` — the Go server rejects a
  duplicate seed within 24 h (`WIRE-SPEC.md` §8.1.7); the mock enforces the
  same with a HashSet, and the client always draws a fresh seed on retry
  (assert two attempts use different seeds).

`zero-psiphon/tests/meek_wire.rs` exists from phase 5 with
`fixtures/meek-vectors.json` (`httpRequests`, `cookie`,
`obfuscatedRoundTripCookie`, `payloadPadding`, `tlsTunnel`).

### 7.4 Runtime loopback end-to-end (`zero-runtime/tests/psiphon_outbound.rs`)

Dev-dependency: `zero-psiphon = { workspace = true, features = ["test-util"] }`.
The test builds a real `zero_runtime::Server` with a SOCKS inbound and a
`psiphon` outbound, exactly like `crates/zero-runtime/tests/socks_upstream.rs`
does for SOCKS, and drives traffic through the SOCKS port.

| Test | Asserts |
|---|---|
| `a_build_without_psiphon_says_so` (`cfg(not(feature = "psiphon"))`) | `connect` error contains "without Psiphon support" |
| `psiphon_refuses_udp` | UDP datagram through the outbound returns "carries TCP only" and the mock saw zero channels |
| `a_socks_client_reaches_an_echo_service_through_psiphon` | payload round-trips; mock's `seen()` has one channel to the echo address; `stats.snapshot().accepted == 1` |
| `two_connections_share_one_tunnel` | second SOCKS connection works; `zero_psiphon::shared::instance_id` unchanged; mock counted one SSH auth (test-util counter) |
| `reload_keeps_an_unchanged_psiphon_tunnel` | `server.reload` with the same JSON: instance id unchanged, first stream still open, new stream works |
| `reload_with_changed_entries_builds_a_new_tunnel` | instance id changes, old stream keeps working, new stream uses the new entry |
| `a_config_with_stream_settings_is_rejected` | `zero_config::parse_config` errors with the tag and "dialls its own network" |
| `a_tunnel_that_dies_is_replaced_for_the_next_connection` | stop mock, first connection fails cleanly, restart mock on the same port, next connection succeeds on a new instance |

### 7.5 Ignored interop against the real server

`zero-psiphon/tests/real_server.rs` (exists) gains OSSH/TLS-OSSH cases and a
signature-negative case. The harness contract is in `SERVER-HARNESS.md` §9.2;
the current env interface is:

```text
ZERO_PSIPHON_SERVER_ENTRY       path to config/server-entry-signed.json (array)
ZERO_PSIPHON_ENTRY_PUBKEY       base64 key from config/server-entry-signature.pub
ZERO_PSIPHON_TARGET             origin host:port, default 127.0.0.1:20085
```

Tests:

| Test | Asserts |
|---|---|
| `plain_ssh_against_the_real_server_carries_a_request` (exists) | SSH through `psiphond:20081`, `psiphon-handshake` accepted, `direct-tcpip` returns the marker |
| `ossh_against_the_real_server_carries_a_request` | OSSH through `20082`; this is the phase-2 acceptance gate |
| `tls_ossh_against_the_real_server_carries_a_request` | TLS-OSSH through `20083` (phase 4) |
| `a_tampered_entry_signature_is_refused_before_dialling` | signature negative, no socket is opened (harness has `verify-client-bad-signature.config`) |

`zero-runtime/tests/psiphon_interop.rs` (ignored, feature `psiphon`): the same
end-to-end SOCKS→tunnel→marker path as §7.4 but against the harness, gated on
`ZERO_PSIPHON_SERVER_ENTRY` being set. Runbook:

```text
.research/psiphon-server-harness/run.sh --origin
ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry-signed.json \
ZERO_PSIPHON_ENTRY_PUBKEY=$(cat .research/psiphon-server-harness/config/server-entry-signature.pub) \
cargo test -p zero-runtime --features psiphon --test psiphon_interop -- --ignored --nocapture
.research/psiphon-server-harness/stop.sh
```

### 7.6 Feature matrix and commands (CI)

```text
cargo test -p zero-psiphon --features test-util
cargo test -p zero-config                      # parse/validate
cargo test -p zero-runtime --test psiphon_outbound           # feature off: message test
cargo test -p zero-runtime --features psiphon --test psiphon_outbound
cargo test -p zero-runtime --features psiphon --test psiphon_interop -- --ignored   # harness only
cargo check -p zray-cli                        # default features include psiphon
cargo check -p zray-cli --no-default-features  # and without it
```

No workspace-wide build is needed for review; every command above is
package-scoped. `zero-psiphon`'s own tests must also pass under
`--no-default-features` (they do not need `test-util` except `mock`-dependent
tests, which are `#[cfg(feature = "test-util")]`).

---

## 8. Performance and RAM design

### 8.1 Go baseline (the numbers our design is measured against)

| Quantity | Go client | Source |
|---|---|---|
| SSH channel window | 4 × 32 KiB = **128 KiB** per channel (Psiphon's own reduction from OpenSSH's 2 MiB) | `psiphon/common/crypto/ssh/channel.go:59-81` |
| SSH max packet | 32 KiB | `channel.go:22` |
| Relay buffers | `io.Copy` default **32 KiB** per direction; 4 KiB when `LimitRelayBufferSizes` is set | `psiphon/net.go:361-377` |
| Tunnels per client | 1 (max 32) | `psiphon/config.go:56-57` |
| Concurrent establishment workers | 10 | `psiphon/common/parameters/parameters.go:653` |
| Tunnel connect timeout | 20 s | `parameters.go:655` |
| Overall establish timeout | 300 s | `parameters.go:656` |
| Keepalive | 1-2 min random period, 30 s timeout | `parameters.go:747-750` |
| Server tunnel idle expiry | 5 min (comment) | `parameters.go:741-742` |
| Server port-forward dial timeout | 10 s | `psiphon/server/trafficRules.go:34-38` |
| Server concurrent dialing / established forwards | 64 / 512 per client | `psiphon/server/trafficRules.go:37-38` |
| Server keepalive reply padding | 0-256 random bytes | `psiphon/server/tunnelServer.go:71-73` |
| Credential/handshake payload | ~200 bytes each | harness log, `SERVER-HARNESS.md` §9.1 |
| Go memory test approach | `runtime.MemStats` over reconnect/restart cycles | `psiphon/memory_test/memory_test.go:1-90` |

`ARCHITECTURE.md` is the authoritative baseline for the Go client; if its final
numbers differ from the table above, its numbers win (the table cites the same
Go constants directly, so the discrepancy would itself be a bug).

### 8.2 Per-connection memory budget (Rust)

Key property to exploit: the SSH "window" is a credit counter, not a
preallocated buffer. `russh::ChannelTx` keeps an `Arc<Mutex<u32>>` credit
(`russh 0.64.1 src/channels/io/tx.rs`, pinned by `Cargo.lock:4268-4271`), so an
idle channel costs a channel struct, its bounded mpsc slots
(`channel_buffer_size = 64`, each `ChannelMsg` ~40 bytes ⇒ ~2.5 KiB) and the
window credit, not 128 KiB of buffer.

| Item | Budget | Notes |
|---|---|---|
| SSH session (idle tunnel) | **≤ 0.5 MiB** | russh read buffer (max packet 32 KiB) + write buffer + ciphers + obfuscator state after NEWKEYS (none), + entry/config |
| One idle channel | **≤ 8 KiB** | channel state + bounded message queue; window credit only |
| One busy channel, download | **≤ 192 KiB** | 128 KiB window worth of received `Bytes` + relay's 32 KiB buffer + in-flight packets |
| One busy channel, upload | **≤ 128 KiB** | write window + relay buffer; `ChannelTx` caps each write at max packet |
| Relay buffers (runtime) | 2 × 16 KiB typical, 2 × 64 KiB bulk | pool-recycled `crates/zero-runtime/src/relay.rs:20-45` |
| OSSH scratch during KEX | **≤ ~288 KiB** | one 256 KiB max SSH packet + 32 KiB transform scratch, then released |
| OSSH steady state | **0** additional | after NEWKEYS both directions are pass-through |

Worst case with `max_channels = 128` and all channels busy downloading:
128 × 192 KiB ≈ 24 MiB. The client refuses channel 129 with a clear error
instead of discovering the server's LRU (`DEFAULT_MAX_TCP_PORT_FORWARD_COUNT =
512`) the hard way. `max_channels` is configurable down for low-memory phones.

### 8.3 Copy accounting and zero-copy decisions

The stack for one direction of one channel:

```text
plaintext
  → runtime relay buffer (Vec, 16/64 KiB, pooled, no allocation on reuse)
  → TunnelStream::poll_write
  → russh ChannelTx::poll_mk_msg      [copy #1: Bytes::copy_from_slice]
  → SSH packet assembly + MAC/encrypt [copy #2: into the packet/cipher buffer]
  → OSSH pre-NEWKEYS only              [in-place XOR on a reusable scratch buffer]
  → TCP socket
```

and on read:

```text
TCP → russh deframer → decrypt (in place) → ChannelMsg::Data(Bytes)
  → ChannelRx::poll_read               [copy #1: Bytes → caller's ReadBuf]
  → runtime relay buffer               [copy #2: into the pooled Vec]
  → destination socket
```

Decisions:

- **Keep `BoxStream` only at setup boundaries** (`crates/zero-core/src/stream.rs:23-27`):
  the tunnel stream is a concrete `TunnelStream`; the runtime boxes it once.
- **Do not add a third copy.** A tempting `Vec<u8>` accumulator around OSSH
  would copy every byte twice more; the OSSH layer must transform in place on
  `russh`'s own buffers or on one reusable scratch buffer.
- **Write path:** `russh` copies the write slice into `Bytes` because channel
  messages are queued. The alternative (a hand-rolled channel writer using
  `Channel::data_bytes(Bytes)`) saves copy #1 but duplicates window/flow-control
  and error handling; not worth it in v1. Measure first: the throughput gate in
  §8.5 will show if SSH framing, not copying, is the limit.
- **Read path:** `ChannelRx::poll_read` copies out of `Bytes`; unavoidable
  without forking `russh` to hand out `Bytes`. Not a v1 goal.
- **OSSH framing** parses only the bytes it must (5-byte packet prefix, then the
  packet) and switches to a pass-through state when both NEWKEYS have crossed.
  It never buffers a whole handshake or a whole stream.
- **Buffers are sized from configuration**, not from traffic: no `Vec::grow` on
  the hot path. OSSH's scratch is `Vec::with_capacity(max_packet + 5)`.
- **Base64/json** are setup-only; nothing encodes per packet.

### 8.4 Keepalive and liveness

The server returns 0-256 random bytes on each `keepalive@openssh.com` and treats
them as speed-test samples (`psiphon/server/tunnelServer.go:3275-3300`). `russh`
sends exactly that request name when `keepalive_interval` is set
(`russh 0.64.1 src/client/mod.rs:1359-1380, 1510-1535`), so the client keeps
`keepalive_interval = Some(60s)`, `keepalive_max = 3` and `inactivity_timeout =
None` (an idle tunnel is not a dead one; the Go client's periodic keepalive is
its liveness probe). Note the skeleton's current default of 25 s is more
aggressive than the Go client (60-120 s); set it to 60 s unless a harness test
shows the server expects faster. This matters for mobile battery and for the
number of server-side speed-test samples.

### 8.5 Task model

| Task | Count | Lifetime |
|---|---|---|
| `russh` session driver | 1 per tunnel (`tunnel_pool_size`, default 1) | tunnel lifetime; exits on close/death |
| Egress stream (`direct-tcpip` channel) | **0 extra** — `ChannelStream` is a future, driven by the runtime's relay task | stream lifetime |
| Runtime relay | 1 per proxied session (existing) | session |
| Client idle-close sweeper | 1 per tunnel | tunnel lifetime; 120 s tick |
| Establishment attempts | ≤ `establish_concurrency` (default 3), transient | until first success/abort |
| Bootstrap fetch (list/tactics) | 1 per client, deduplicated by async mutex | startup or retry |

No actor mailbox per connection, no per-connection spawn inside `zero-psiphon`.
The runtime's existing 1-task-per-session relay is the only task added by a
proxied connection, which is the same as every other outbound.

Cancellation: candidates are raced by dropping futures (`zero-net`-style), not
by abandoning tasks; a dropped establishment future closes its socket because
`TcpStream`/`russh` drop does. The establishment deadline is per candidate;
the shared layer imposes one overall retry (not an unbounded loop).

### 8.6 Measurable targets

Targets are gates for phase 2/6, measured on loopback against the mock (so
network variance is out) and reported in the test output:

| Metric | Target | How measured |
|---|---|---|
| OSSH+SSH+handshake, loopback | p50 ≤ 25 ms, p95 ≤ 75 ms | `zero-psiphon` handshake harness test, 100 iterations |
| First byte through the proxy (SOCKS CONNECT→echo), loopback | p50 ≤ 40 ms, p95 ≤ 120 ms | runtime e2e test, 50 connections |
| Throughput, 1 stream, loopback | ≥ 150 MB/s | `zero-runtime/tests/psiphon_throughput.rs`, 256 MiB transfer |
| Throughput, 8 streams, loopback | ≥ 400 MB/s | same harness, 8 concurrent |
| Upload, 1 stream, loopback | ≥ 100 MB/s | same |
| RSS, idle tunnel (no channels) | ≤ 0.5 MiB over process baseline | `/proc/self/status` `VmRSS` delta on Linux |
| RSS, 64 open idle channels | ≤ 1.0 MiB over the idle tunnel | same |
| RSS, 8 busy downloading channels | ≤ 2.0 MiB over idle tunnel | same, with 8 streaming sinks |
| Reconnect after tunnel death | ≤ 1 s extra vs a cold dial on loopback | test-util timing |

Why these numbers: Zray's baseline on the same loopback benchmark machine is
532 MB/s for one TLS stream and 911 MB/s for eight
(`docs/benchmarks/README.md:44-49`); SSH adds a per-packet MAC/encrypt and a
128 KiB window, so 150/400 MB/s is a conservative gate, not a ceiling. On a
real network the link RTT dominates: one channel at 100 ms RTT with a 128 KiB
window is ≈ 10 Mbit/s regardless of CPU, which is exactly why the Go client
keeps the window small and multiplexes many channels (bulk transfers on
separate channels share the tunnel). If a target is missed, the tuning order is
`channelWindowBytes` → `max_channels` → relay buffer promotion threshold, and
the numbers are recorded in `docs/benchmarks/README.md` as a psiphon row.

---

## 9. Risks, sequencing, and acceptance

### 9.1 Risk register

| # | Risk | Impact | Mitigation / gate |
|---|---|---|---|
| 1 | OSSH byte-level port is wrong (RC4 KDF, seed message, packet rewrite, NEWKEYS) | total failure; looks like a blocked network | Go-derived vectors (`fixtures/ossh-vectors.json`) replay in CI; real-server OSSH interop test; mock server built from the server side of the same spec |
| 2 | `russh` algorithm negotiation vs Psiphon's randomized server KEX | `NoCommonAlgo`, intermittent failure | explicitly set `Preferred`: include ML-KEM, curve25519 (both names), ECDH P-256/384/521, DH14/16, GEX; MACs HMAC-SHA2-256/512 (no ETM before NEWKEYS); ciphers chacha20-poly1305 then AES-CTR (no GCM first) — the Psiphon-compatible set from `psiphon/common/crypto/ssh/handshake.go:600-720, 921-1100`; `NoCommonAlgo` error carries both lists, so a failure is diagnosable |
| 3 | OSSH needs MACs/ciphers with encrypted packet lengths | server-side handshake reject or fingerprintable traffic | cipher order above: chacha20-poly1305 first, CTR next; never ETM MAC first; pinned by a unit test on the `russh::Preferred` value |
| 4 | TLS-OSSH blocked by the vendored `rustls` | phase 4 delay only | Psiphon's TLS tunnel needs the passthrough message in the ClientHello random (`WIRE-SPEC.md` §1.3, §5); the vendored rustls fork exposes shaping but not a client-random override (`vendor/rustls/PATCHES.md` documents the two existing patches). Options: (a) test whether `psiphond` accepts a plain TLS 1.3 hello with any-cert verification (harness says any cert is accepted, `SERVER-HARNESS.md` §9.2.3); (b) if passthrough is required, add a third vendored patch `ClientHelloPlan::with_client_random([u8; 32])`, ~20 lines in `vendor/rustls/src/client/hs.rs` + PATCHES.md; decide after a probe against the harness |
| 5 | Meek needs NaCl `crypto_box` (cookie encryption) and HTTP framing | phase 5 delay; OSSH path unaffected | `sodiumoxide`/`crypto_box` not in the lock: implement X25519 + XSalsa20-Poly1305 from `x25519-dalek` + `chacha20poly1305`? (XSalsa20 ≠ ChaCha20 — needs `salsa20` crate, not in lock). Better: start with `UNFRONTED-MEEK` (plain HTTP) where the client echoes the cookie without decrypting it, and add `FRONTED-MEEK` after; verify with the harness's meek listener if enabled. Do not block phase 1-2 on it |
| 6 | Tactics parameter surface is huge | wrong timeouts/window, or ignoring a mandated restriction | apply a documented subset (§6.4); never widen `protocols` from tactics; log unknown parameters; `tactics: true` is not a prerequisite for dialling |
| 7 | Server requires the handshake before channels | every dial fails "administratively prohibited" | handshake is part of `SshTunnel::establish` path (skeleton already); mock refuses pre-handshake so CI catches a regression; real-server interop test pins it |
| 8 | Secrets in logs/reload comparisons | password leak | hand-written `Debug for PsiphonConfig` redacting entries (§4.4b); `ServerEntry`'s Debug already redacts (`server_entry.rs`); add `log_privacy` style test: format the outbound and assert no `sshPassword`/`sshObfuscatedKey` substring |
| 9 | Instance cache grows across reloads | memory leak | `Weak` cache + sweep on establish + cap 8 + idle close (§4.6) |
| 10 | Bootstrap fetches leak DNS/direct traffic | local observer sees Psiphon URLs | documented divergence (§5.3); embedded entries are the recommended deployment; `upstreamProxy` support for fetches is a later phase |
| 11 | No production server entries/keys in the repo | one-click unusable out of the box | entries come from the app/config (`serverEntries`), like the Go client's embedded list argument (`ConsoleClient/main.go:51-52`); do not paste Psiphon's production keys into the repo |
| 12 | `direct-tcpip-no-split-tunnel@psiphon.ca` not implemented | no split-tunnel traffic rules | split tunnel is off by default and not exposed in our config, so the plain channel type is correct (`SERVER-HARNESS.md` §9.2.6) |
| 13 | Server traffic rules reject a destination | user-visible error | mapped to `ServerRejected` with the server message; no retry (it is deterministic) |
| 14 | Android/iOS feature wiring | mobile ships without Psiphon | phase 6: `zero-runtime/psiphon` in `ZeroNet-Mobile/native/zray-mobile` and `Desktop`; both only enable per-app, and mobile binary size should be measured before enabling by default |

### 9.2 Sequencing

Phase ordering is dependency-driven; items in the same phase can proceed in
parallel across developers.

```text
Phase 0 (done or in flight, parallel)
  [x] zero-psiphon skeleton: protocol, server_entry, json, tunnel, error
  [x] workspace deps (russh, ed25519-dalek) and member
  [x] WIRE-SPEC.md + fixtures, SERVER-HARNESS.md + working psiphond
  [ ] ARCHITECTURE.md (task-1, in flight)

Phase 1 — config + runtime wire-up (no wire dependency; can land first)
  - zero-config: enum, struct, parse, validate, link error, docs test
  - zero-runtime: feature, psiphon.rs conversion, dispatch, protocol_header,
    server.rs arms, UDP refusal, feature-off message
  - tests: config unit tests, feature-off/refusal tests
  Exit: {"protocol":"psiphon"} parses, validates, fails cleanly without the
        feature; `cargo check -p zray-cli --no-default-features` clean.

Phase 2 — OSSH + tunnel + egress (critical path)
  - obfuscator/{cipher,seedmsg,framing,conn} + vectors
  - carrier.rs (Plain/OSSH) + DirectDialer
  - Client selection/dial loop + shared cache + idle close
  - mock.rs (SSH + OSSH server) and the e2e suites
  - interop: OSSH against psiphond (20082)
  Exit: SOCKS→psiphon→echo through the mock and the real server; vectors green.

Phase 3 — tactics + remote server list + datastore (parallel with 2)
  - tactics.rs, remote_server_list.rs, datastore.rs
  - config discovery path: empty serverEntries + remoteServerListUrls
  Exit: a signed remote list imported in a test, tampered list refused;
        a tunnel established from a fetched list.

Phase 4 — TLS-OSSH (depends on 2; possible vendored-rustls patch)
  - tls_tunnel.rs; interop against psiphond:20083
  Exit: TLS-OSSH interop test green.

Phase 5 — meek (UNFRONTED first, then FRONTED) (depends on 2; cookie crypto)
  - meek.rs; interop against the harness's meek surface if enabled
  Exit: meek interop green; or documented blocker with evidence.

Phase 6 — performance and packaging
  - throughput/RSS/handshake gates, benchmarks doc row
  - docs/config-compatibility.md section, platforms/embedding notes
  - Desktop/Mobile feature enablement (separate repos)
```

**Must land first:** phase 1 (it creates the compile-time feature matrix and the
error contract) and the `shared`/`Client` skeleton (phase 2's spine). It can be
reviewed and merged before any OSSH code exists because the feature-off path is
fully testable.

**Can be parallelized:** phase 1 vs phase 2 (different files: config/runtime vs
crate internals); phase 3 vs phase 2 (tactics/list do not need OSSH — they can
be tested against local HTTP servers); phase 6 docs while phases 2-5 run.

**Blocked on wire details:** phase 2 OSSH requires WIRE-SPEC §2 + fixtures
(available); phase 4 requires the passthrough decision (probe the harness
first); phase 5 requires the cookie-crypto decision.

**Blocked on external decisions:** (a) whether to patch vendored rustls for the
TLS client random; (b) whether Desktop/Mobile enable the feature by default;
(c) whether to ship a bundled entry list — none of these blocks phase 1.

### 9.3 Pre-merge checklist for each phase

- [ ] `cargo test -p zero-psiphon --features test-util` and
      `cargo test -p zero-config` green.
- [ ] `cargo test -p zero-runtime --features psiphon --test psiphon_outbound`
      green, and the same test without the feature green (message path).
- [ ] `cargo check -p zray-cli` and `--no-default-features` green.
- [ ] No secret appears in `Debug`/`tracing` output: the log-privacy test
      covers a Psiphon outbound with a password and obfuscation key.
- [ ] `docs/config-compatibility.md` has the section for anything diverging in
      this phase, naming the pinning test.
- [ ] Ignored interop test green against `.research/psiphon-server-harness`
      (phase 2+), with the command in the PR body.
- [ ] Performance gates from §8.6 pass or the deviation is recorded.

---

## Appendix A — Dependency matrix (what exists vs what to add)

| Crate | Version in `Cargo.lock` | Used for | Where |
|---|---|---|---|
| `russh` | 0.64.1 | SSH client (feature `ring`, `rsa`) | workspace dep `Cargo.toml:120-125`; zero-psiphon |
| `ed25519-dalek` | 2.2.0 | server-entry / tactics signatures | workspace dep `Cargo.toml:126-129` |
| `ring` | 0.17.14 | RSA-PKCS1v15-SHA256 for remote-list package | workspace; zero-psiphon (add) |
| `flate2` | 1.1.10 | zlib for the remote-list package | workspace; zero-psiphon (add) |
| `hmac` / `sha2` / `sha1` / `hkdf` | 0.12.1 / 0.10.9 / 0.10.7 / 0.12.4 | OSSH KDF/framing, seed derivation, tags | workspace |
| `rand` | 0.8.8 | seeds, session ids, padding | workspace |
| `base64` / `hex` | 0.22.1 / 0.4 | wire encodings | workspace |
| `bytes` / `futures` | 1.x / 0.3 | stream plumbing | workspace |
| `serde` / `serde_json` | 1.x | config, entries, tactics | workspace |
| `thiserror` | 2.0.20 | `Error` | workspace |
| `tokio` / `tokio-rustls` / `rustls` | 1.x / 0.26 / 0.23 | async, TLS-OSSH, shaped fetch | workspace |
| `url` | 2.x | proxy/remote-list URL parsing | workspace |
| `zero-core`, `zero-protocol`, `zero-net` | path | streams, SOCKS/HTTP CONNECT, shaped fetch/dial | workspace |
| `rsa 0.9` (dev-only) | 0.9.10 | building signed remote-list packages in tests | zero-psiphon dev-deps (add) |

No crate outside this list is needed; in particular there is no Rust Psiphon
crate to reuse and no `salsa20` (see risk 5).

## Appendix B — Exact file-by-file change list

| Path | Change |
|---|---|
| `Cargo.toml` | done: member `crates/zero-psiphon` (`:22`), dep (`:58`), `russh`/`ed25519-dalek` (`:120-131`) |
| `crates/zero-psiphon/Cargo.toml` | add `zero-protocol`, `zero-net`, `flate2`, `ring`; dev-deps `rsa`, `zero-runtime`? no (cycle) — tests that need the runtime live in `zero-runtime/tests` |
| `crates/zero-psiphon/src/{lib,client,config,error,protocol,server_entry,json}.rs` | finish stubs / extend (§2) |
| `crates/zero-psiphon/src/{carrier,shared,upstream,datastore,remote_server_list,tactics}.rs` | new (§2.1) |
| `crates/zero-psiphon/src/obfuscator/{mod,cipher,seedmsg,framing,conn}.rs` | new (§2.1, WIRE-SPEC §2) |
| `crates/zero-psiphon/src/{meek,tls_tunnel}.rs` | new (phases 4-5) |
| `crates/zero-psiphon/src/mock.rs` | new, behind `test-util` (§7.2) |
| `crates/zero-psiphon/tests/{obfuscator_wire,meek_wire,egress,memory,real_server}.rs` | new/expand (§7) |
| `crates/zero-config/src/model.rs` | enum variant, `PsiphonConfig` + supporting types, `name`, `is_proxy`, validation block (§3.1) |
| `crates/zero-config/src/xray_json.rs` | `"psiphon"` arm + `parse_psiphon` + tests (§3.2) |
| `crates/zero-config/src/share_link.rs` | explicit `psiphon` rejection + test (§3.3) |
| `crates/zero-runtime/Cargo.toml` | `psiphon` feature + optional dep (§4.1) |
| `crates/zero-runtime/src/lib.rs` | `#[cfg(feature = "psiphon")] mod psiphon;` |
| `crates/zero-runtime/src/psiphon.rs` | new conversion + failure mapping (§4.2) |
| `crates/zero-runtime/src/outbound.rs` | dispatch in `connect`/`connect_with_resolver`, `connect_psiphon` pair, `protocol_header` arm (§4.3) |
| `crates/zero-runtime/src/server.rs` | 3 exhaustive match arms, UDP early refusal (§4.4) |
| `crates/zero-runtime/tests/psiphon_outbound.rs` | new (§7.4) |
| `crates/zero-runtime/tests/psiphon_interop.rs` | new, ignored (§7.5) |
| `crates/zero-runtime/tests/psiphon_throughput.rs` | new, release/ignored (§7.6, §8.6) |
| `crates/zray-cli/Cargo.toml` | `default = ["psiphon"]`, `psiphon = ["zero-runtime/psiphon"]` (§4.5) |
| `docs/config-compatibility.md` | new section (§5.3) |
| `docs/platforms.md`, `docs/embedding.md` | feature/default notes (phase 6) |
| `docs/benchmarks/README.md` | psiphon row once measured (phase 6) |

## Appendix C — Open decisions (need a Lead/owner call)

1. **TLS-OSSH passthrough**: probe `psiphond:20083` with a plain TLS 1.3
   any-cert client before adding a third vendored-rustls patch (risk 4).
2. **Meek cookie crypto**: decide between adding `salsa20` to the workspace for
   XSalsa20-Poly1305 (`crypto_box`) versus shipping unfronted meek only.
3. **Default `client_platform`/`client_version`**: use `"Other"`/`"1"` (valid
   per the server's validators) or mirror a real Psiphon platform string for
   parity? The credential is inside SSH, so this is a server-side stats
   question, not an anti-censorship one.
4. **`direct-tcpip-no-split-tunnel@psiphon.ca`**: needed only if split tunnel
   is ever exposed; `russh` would need a patch to send a custom channel type.
5. **Mobile default**: enable `zero-runtime/psiphon` on Android/iOS by default
   only after the phase-2 binary-size and RSS numbers are known.
