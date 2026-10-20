# The native Psiphon client: architecture

Status: **describes the code as it is**, not a plan. Every claim below is
anchored to a `path:line` in this repository or, where the behaviour is
defined by Psiphon rather than by this port, to a `path:line` in the Go
reference at `.research/psiphon-tunnel-core` (commit `5709017`).

A note on line numbers: `crates/zero-psiphon` grew four modules while these
documents were being written — `tactics.rs`, `mock.rs`, `nacl_box.rs` and the
unfronted meek carrier in `client.rs` — and the sections that describe them
were folded in afterwards. **Symbol names, not line numbers, are the stable
anchors** in that crate: the line numbers are a snapshot taken on 2026-10-19,
and the sentences around them say what the code does regardless.

Companion documents:

| Document | What it owns |
|---|---|
| [`WIRE-SPEC.md`](WIRE-SPEC.md) | byte-exact OSSH / meek / TLS spec and Go-derived vectors |
| [`INTEGRATION.md`](INTEGRATION.md) | the plan for wiring the crate into `zero-config` / `zero-runtime` |
| [`SERVER-HARNESS.md`](SERVER-HARNESS.md) | the real `psiphond` loopback harness and its interop recipe |
| [`PERFORMANCE.md`](PERFORMANCE.md) | what the client costs, measured |

> A divergence worth knowing about: `INTEGRATION.md:13` describes
> `ARCHITECTURE.md` as owning "Go client flow, config fields, dial selection,
> concurrency/RAM baseline", and `INTEGRATION.md:1643` says this document is
> "the authoritative baseline for the Go client". This document instead
> describes **the Rust crate**, because the Rust crate is what exists and what
> a reader of the crate needs. The Go baseline it would have carried is
> already tabulated in `INTEGRATION.md:1626-1641` with the same citations,
> so nothing is lost, but the two documents do not agree on what this file is
> for.

---

## 0. What the crate is, and what it is not

`zero-psiphon` is a **client for the transports Zray needs**: it reads
Psiphon server entries, dials a Psiphon server over a transport, performs
Psiphon's SSH session and tunnel handshake, and hands the caller a byte
stream to an arbitrary destination. The destination name is passed through
unresolved, exactly as Psiphon does it, so the local resolver never learns
where the user is going (`client.rs:96-100`).

It is deliberately **not** a proxy and **not** a piece of Zray:

- **No local SOCKS or HTTP listener.** The crate has no listener of any kind.
  `client.rs:11-13` states it outright: "it has no local SOCKS/HTTP listener —
  Zray's router is the proxy that uses these streams." The crate's public
  surface is `Client::dial(host, port) -> BoxStream`
  (`client.rs:100-116`) and the shared-registry `shared::dial`
  (`shared.rs:77-122`), and nothing else opens a socket to a caller.
- **No routing, no DNS, no policy, no stats.** `lib.rs:10-11`: "The crate is
  deliberately free of routing, DNS and policy: it hands out streams the way
  `zero-tor` does, and `zero-runtime` decides who gets one." `lib.rs:26`
  repeats it: "Nothing here knows about Zray's config file, its stats or its
  router."
- **No Psiphon-scale tunnel pool.** `client.rs:11-13` again: it "does not run
  Psiphon's large tunnel pool". The Go client keeps up to 32 tunnels
  (`psiphon/config.go:56-57`); this port keeps `tunnel_pool_size` tunnels,
  which `config.rs:256-261` caps at 4 and `config.rs:230` defaults to 1.
- **No configuration file format of its own.** `ClientConfig::from_value`
  (`config.rs:352-454`) reads a JSON object, and `config.rs:3-11` explains
  that the field names are Psiphon's own `config.json` names in snake case so
  a Go configuration can be translated without a lookup table.

What the crate *is* is a protocol port with a narrow surface: server entry
parsing and signature verification, the plain, OSSH, TLS-OSSH and unfronted
meek carriers, the SSH session with Psiphon's credential payload and
`psiphon-handshake`, and a `direct-tcpip` channel multiplexer.

---

## 1. The module map

`lib.rs:28-51` is the public surface. Every module is public except
`nacl_box`, which is `pub(crate)` (`lib.rs:33`) because it is a
reconstruction of a published construction rather than an API.

### 1.1 `lib.rs` — the crate's front door

`lib.rs:1-26` is the crate's own description, and it is accurate: it is a
port of the parts of `psiphon-tunnel-core` a proxy needs, it "fetches and
verifies tactics" (see §1.9 for how far that has actually gone), and it
"turns the resulting SSH connection into streams to arbitrary destinations".

The re-exports are the intended entry points for a caller
(`lib.rs:45-51`): `Client`, `ClientConfig`, `UpstreamProxy`,
`UpstreamProxyKind`, `Error`, `TunnelProtocol`, `ServerEntry`, `dial`
(the shared-registry entry point), `HandshakeParams`, `SshTunnel`,
`TunnelOptions` and `TunnelStream`.

### 1.2 `config.rs` — the client configuration

`ClientConfig` (`config.rs:174-211`) and `HandshakeIdentity`
(`config.rs:106-117`) are the whole configuration surface; §2 covers them in
detail. `UpstreamProxy` / `UpstreamProxyKind` (`config.rs:22-39`) model the
proxy Psiphon can be dialled through, with a `Debug` implementation that
redacts the credential (`config.rs:41-56`) and a `parse` that accepts
`socks5://host:port` and `http://user:password@host:port`
(`config.rs:58-101`).

### 1.3 `server_entry.rs` — one server, as the network publishes it

`ServerEntry` (`server_entry.rs:123-126`) holds a typed view of the entry's
fields plus **the exact JSON object the entry arrived as**, in a `BTreeMap`
(`server_entry.rs:125`). Keeping the raw object is what makes signature
verification possible: the signature covers fields this client does not know
about, so verification needs the original map rather than a re-serialisation
of the typed struct (`server_entry.rs:117-122`).

The public surface is accessors (`ip_address`, `region`, `provider_id`,
`fronting_provider_id`, `capabilities`, `configuration_version`,
`ssh_username`, `ssh_obfuscated_key`, `tactics_request_public_key`,
`tactics_request_obfuscated_key`, `meek_server_port`,
`meek_cookie_encryption_public_key`, `meek_obfuscated_key`, the three
`disable_*` switches), the transport selectors `port_for` / `host_for`
(`server_entry.rs:262-306`), the capability predicate `supports_protocol`
(`server_entry.rs:352-373`), the signature pair `verify_signature` / `sign`
(`server_entry.rs:379-453`), and the identity helpers `tag` /
`diagnostic_id` (`server_entry.rs:181-197`).

The `Debug` implementation prints the diagnostic id, the address, the region
and the capabilities, and nothing else (`server_entry.rs:128-138`) — the
password, the obfuscation key and the host key never reach a log.

### 1.4 `json.rs` — Go's `encoding/json`, byte for byte

This module exists for one reason, stated at `json.rs:3-8`: Psiphon signs its
server entries with Ed25519 over a Go `map[string]any` re-marshalled with
`encoding/json`, so the signature covers Go's *exact* output — keys sorted,
no spaces, Go's string escaping (including `\u003c` for `<`) and Go's float
formatting. `serde_json` writes a different, also-valid JSON for the same
values, so verification cannot reuse it.

`json::encode` (`json.rs:25-29`) reproduces that: objects are written with
their keys sorted by byte value (`json.rs:75-89`), numbers go through
`f64` and Go's `'f'`/`'e'` choice (`json.rs:94-133`), and strings are escaped
the way Go escapes them with HTML escaping on
(`json.rs:138-162`). `json.rs:173-219` pins the result against strings
produced by `json.Marshal` on the same values, and `json.rs:175-176` says
plainly that "a change here invalidates every existing signature".

### 1.5 `protocol.rs` — the transport names

`TunnelProtocol` (`protocol.rs:12-31`) enumerates the thirteen protocol
names Psiphon writes into server entries and tactics. The names are wire
identifiers and `protocol.rs:5-6` says they must not be edited.

Three methods carry the protocol semantics:

- `capability()` (`protocol.rs:59-75`) is the string the server entry
  carries for this protocol. Psiphon derives it by dropping an `-OSSH`
  suffix, which is why `OSSH` maps to `OSSH` and `TLS-OSSH` maps to `TLS`
  (`protocol.rs:56-58`).
- `supported()` (`protocol.rs:113-124`) is the list this port claims to
  implement. **It is wider than what the dial path can actually do**: the
  two fronted meek protocols are listed but have no carrier — see §7.1.
- `is_fronted()`, `uses_meek()` and `uses_obfuscated_ssh()`
  (`protocol.rs:89-109`) classify the protocol for the port and host
  selectors.

### 1.6 `tunnel.rs` — the SSH session and its Psiphon semantics

`russh` does the SSH; this module is the Psiphon meaning around it
(`tunnel.rs:15-16`). It owns:

- `TunnelOptions` (`tunnel.rs:51-69`) — the SSH identification line, the
  keepalive interval, the window size, the maximum packet size, the channel
  buffer size, the session id, the sponsor id and the advertised
  capabilities.
- `CredentialPayload` (`tunnel.rs:89-99`) and `credential_payload`
  (`tunnel.rs:113-126`) — the JSON that stands in for the SSH password.
- `HandshakeParams` (`tunnel.rs:137-148`) and `HandshakeParams::to_json`
  (`tunnel.rs:197-206`) — the payload of the `psiphon-handshake` global
  request.
- `SshTunnel` (`tunnel.rs:227-234`) — the established session:
  `establish` (`tunnel.rs:263-338`), `handshake` (`tunnel.rs:347-360`),
  `open` (`tunnel.rs:378-393`), `close` (`tunnel.rs:396-401`).
- `Pinned` (`tunnel.rs:210-224`) — the host-key check, which compares the
  key exchange's public key to the bytes in the server entry exactly.
- `TunnelStream` (`tunnel.rs:405-407`) — the `direct-tcpip` channel as an
  `AsyncRead`/`AsyncWrite`.

### 1.7 `obfuscator.rs` — the OSSH layer

`OsshClient<S>` (`obfuscator.rs:146-168`) is the obfuscated-SSH stream.
The scheme, as `obfuscator.rs:3-10` describes it: a random 16-byte seed in
the clear, RC4 keys derived from the seed and the server's keyword in both
directions, and everything after the seed's magic value encrypted until each
direction has passed `SSH_MSG_NEWKEYS`. During the key exchange the outgoing
SSH packets are rewritten with extra random padding so the exchange does not
have OpenSSH's characteristic sizes.

The cryptography is deliberately simple and says so: "RC4 provides
obfuscation, not security. Confidentiality and integrity come from SSH above
it" (`obfuscator.rs:11-13`).

`derive_key` (`obfuscator.rs:107-119`) is the reference key derivation,
`Rc4` (`obfuscator.rs:58-102`) is the cipher, and `release_kex_state`
(`obfuscator.rs:314-337`) is the state that is dropped once the key exchange
is over (§4 of `PERFORMANCE.md`).

### 1.8 `tls_ossh.rs` — TLS with the OSSH layer inside

`tls_ossh::wrap` (`tls_ossh.rs:277-311`) runs a TLS session and then the
OSSH layer over it. The TLS certificate is not verified, and the reason is
structural: Psiphon's server issues a self-signed certificate with a random
common name regenerated at every restart, so there is nothing to verify
against (`tls_ossh.rs:4-9`); `AcceptAnyCertificate`
(`tls_ossh.rs:172-220`) is safe here only because the real authentication is
the pinned RSA host key inside the SSH session (`tls_ossh.rs:165-170`).

The one detail that makes the camouflage hold is the **passthrough message**:
the 32 random bytes a TLS client normally puts in its `ClientHello.random` are
replaced by a nonce and an HMAC over it, keyed by a value derived from the
server entry's obfuscated key (`tls_ossh.rs:16-22`). `ClientHelloShaper`
(`tls_ossh.rs:137-163`) is the rustls hook that puts it there;
`passthrough_message` (`tls_ossh.rs:104-112`) and
`verify_passthrough_message` (`tls_ossh.rs:116-131`) are the client and
server halves; `derive_passthrough_key` (`tls_ossh.rs:59-70`) is the HKDF.

### 1.9 `meek.rs`, `nacl_box.rs`, `tactics.rs` — carrier, crypto, parameters

`meek.rs` is the HTTP request/response carrier: the cookie that identifies
the session (`make_cookie`, `meek.rs:119-179`), the request framing
(`request_head`, `meek.rs:371-395`), the response parser (`parse_response`,
`meek.rs:777-855`), and the polling behaviour that an idle connection needs
(`note_idle`, `meek.rs:426-446`). The carrier is built in `client.rs`
(§4.4) from the entry's three meek fields, which `ServerEntry` now exposes
as `meek_server_port`, `meek_cookie_encryption_public_key` and
`meek_obfuscated_key` (`server_entry.rs:326-338`).

`nacl_box.rs` is NaCl's `box` assembled from the three primitives the
workspace already has — `x25519-dalek`, `salsa20` and `poly1305` — because
`crypto_box` is not in the dependency set (`nacl_box.rs:14-19`). Nothing in
the file invents a construction: `before_nm` (`nacl_box.rs:40-43`),
`secretbox_seal` (`nacl_box.rs:63-87`) and `seal` (`nacl_box.rs:121-129`)
compose the published one, and `nacl_box.rs:196-251` checks each layer
against vectors generated by Go's own `nacl/box`, `nacl/secretbox` and
`salsa20/salsa`.

`tactics.rs` is the remote parameter set: the framing, the parameter model
and the fetch. Its own header is careful about what has been verified
(`tactics.rs:28-34`): "No live Psiphon tactics endpoint was available while
this was written, so the bytes have not been compared against a real
server's answer; the Go reference is the authority the implementation
follows."

### 1.10 `client.rs` — server selection, the dial loop, stream handout

`Client` (`client.rs:35-45`) owns a pool of established tunnels, hands out
streams, and accounts for the open channels. The pieces:

- `Client::connect` (`client.rs:49-94`) — validate, refuse an unsupported
  proxy, pick the session id, establish the first tunnel, then grow the pool.
- `Client::dial` / `dial_inner` (`client.rs:100-173`) — the channel
  accounting and the two-pass dial.
- `establish` (`client.rs:276-331`) — the racing dial loop.
- `candidate_list` (`client.rs:338-363`) — the (entry, transport) pairs, in
  preference order.
- `attempt` (`client.rs:369-410`) — one candidate: carrier, SSH session,
  tunnel handshake.
- `carrier` (`client.rs:413-513`) — the transport-specific byte stream.

### 1.11 `shared.rs` — one client per configuration

`shared::dial` (`shared.rs:77-122`) keeps a process-wide registry of
`Client`s keyed by `ClientConfig::key`, so two Zray outbounds with the same
tunnel configuration share one SSH session instead of building one each
(`shared.rs:1-19`). `forget` (`shared.rs:128-130`), `shutdown_all`
(`shared.rs:134-141`) and `instance_count` (`shared.rs:144-149`) are the
lifecycle hooks.

### 1.12 `error.rs` and `mock.rs`

`error.rs` groups the failures by what a caller can do about them:
`Error::is_retryable` (`error.rs:65-70`) says that a configuration, a
signature, a protocol or a "closed" error will not change on a retry, and
that everything else might.

`mock.rs` is an in-process Psiphon server, behind the `test-util` feature
(`lib.rs:44-45`), so it is not in a shipped build. It speaks the
client-facing half of the protocol: the JSON credential payload as the SSH
password, the `psiphon-handshake` global request, and `direct-tcpip`
channels forwarded to a real origin, over plain SSH or over the OSSH layer
(`mock.rs:1-17`, `mock.rs:186-250`). It deliberately does not implement the
server's API, its tactics endpoint or its rate limits
(`mock.rs:14-17`).

`mock.rs` and `tactics.rs` were three-line stubs when this document was
started and have both been filled in since; the crate is in flux and so is
this description.

---

## 2. Configuration

### 2.1 The fields

`ClientConfig` (`config.rs:174-211`) carries, in Psiphon's own names:

| Field | Meaning | Default |
|---|---|---|
| `server_entries` | the servers to try, in preference order | empty |
| `server_entry_signature_public_key` | the Ed25519 key (base64) that signed remote entries | none |
| `remote_server_list_urls` | where remote server lists are fetched from | empty |
| `tactics` / `tactics_url` | whether to fetch tactics, and from where | `false` / none |
| `data_dir` | where imported entries and tactics may be persisted | none |
| `upstream_proxy` | the proxy to reach Psiphon through | none |
| `egress_region` | the region to prefer (`"US"`, `"GB"`, …) | empty (any) |
| `protocols` | the transports to use; empty means every transport the entries support | empty |
| `establish_timeout` | the budget for one candidate's establishment | 20 s (`config.rs:225`) |
| `establish_concurrency` | how many candidates may be dialled at once | 3 (`config.rs:229`) |
| `tunnel_pool_size` | how many tunnels to keep, round-robin between | 1 (`config.rs:230`) |
| `channel_window_bytes` | the SSH channel window | 4 MiB (`config.rs:231`) |
| `max_channels` | the ceiling on simultaneously open channels | 128 (`config.rs:232`) |
| `keepalive_interval` | the `keepalive@openssh.com` interval; `None` disables it | 25 s (`config.rs:233`) |
| `handshake` | the identity the handshake announces | `HandshakeIdentity::default()` |
| `session_id` | the session id to use; a fresh random one when absent | none |

`HandshakeIdentity` (`config.rs:106-117`) carries
`propagation_channel_id` (16 hex characters), `sponsor_id` (16 hex
characters or empty), `client_version` and `client_platform`. Its defaults
are all zeros / `"1"` / `"Other"` (`config.rs:119-128`).

### 2.2 Validation

`ClientConfig::validate` (`config.rs:242-304`) rejects, with a message that
says why:

- no server entries at all (`config.rs:243-247`);
- an invalid identity (`config.rs:248`, delegated to
  `HandshakeIdentity::validate`, `config.rs:133-169`);
- `establish_concurrency` outside 1..=8 and `tunnel_pool_size` outside 1..=4
  (`config.rs:250-261`);
- `max_channels == 0` (`config.rs:262-264`) and a zero `establish_timeout`
  (`config.rs:265-267`);
- a `session_id` that is not 32 lowercase hex characters
  (`config.rs:268-277`).

It also verifies every **signed** entry against the configured public key
(`config.rs:279-288`), with a stated reason: "A bad signature is a
configuration emergency, not a reason to try the next entry, so it fails here
rather than during the dial loop."

What it deliberately does *not* do is reject an entry that offers none of the
configured transports; that is a `tracing::debug!` at
`config.rs:290-301`, because an entry that offers nothing is a property of
the entry, not of the configuration.

`HandshakeIdentity::validate` (`config.rs:133-169`) enforces Psiphon's rules
and explains one of them: the client version "must be a non-empty integer
string", because "The server rejects anything else with a bare 'invalid
parameter', which is a hard failure to diagnose from a dial log"
(`config.rs:162-166`).

### 2.3 `key()` — the cache key

`ClientConfig::key` (`config.rs:311-348`) is a SHA-256 over every field that
changes the tunnel: the egress region, the timeouts and limits, the
handshake identity, the keepalive, the session id, the upstream proxy
(including its credential), the protocol list, and for each server entry its
tag, its obfuscated key, its password and its host key
(`config.rs:339-346`).

Two properties matter. It is **not** printed: "it commits to the server entry
passwords and the obfuscation keys, so it is a secret itself"
(`config.rs:308-310`). And it **includes the secrets**, so two
configurations that differ only in a password cannot share a cached client
(`config.rs:670-677`).

What it does not include: `tactics`, `tactics_url`, `data_dir`,
`server_entry_signature_public_key` and `remote_server_list_urls`. Those do
not change the tunnel, and none of them is consulted on the dial path today
(§6.3), so the omission is currently harmless. It would stop being harmless
the moment tactics are applied to the dial.

### 2.4 `from_value` — reading a Zray outbound

`ClientConfig::from_value` (`config.rs:352-454`) reads the `"Psiphon"`
settings object. Its rules:

- `server_entries` may be an array of entries, a single entry, or a **JSON
  string** holding either (`config.rs:367-369`, `config.rs:459-473`).
- `limit_tunnel_protocols` wins over `protocols` when both are present
  (`config.rs:423-427`); an unknown protocol name is an error
  (`config.rs:479-497`).
- `propagation_channel_id`, `client_version`, `client_platform`,
  `sponsor_id`, `session_id`, `egress_region`, `tactics_url`, `data_dir`,
  `upstream_proxy_url` and `server_entry_signature_public_key` are read as
  strings (`config.rs:371-402`). `sponsor_id` is explicitly empty-able
  (`config.rs:398-402`).
- `remote_server_list_urls` may be a string or an array of strings
  (`config.rs:404-421`).
- The numeric settings are range-checked, and the ranges are the same ones
  `validate` enforces: `establish_timeout_seconds` 1..600
  (`config.rs:429-432`), `establish_concurrency` 1..8, `tunnel_pool_size`
  1..4, `max_channels` 1..4096, `channel_window_bytes` 32 KiB..64 MiB
  (`config.rs:433-445`), `keepalive_interval_seconds` 1..3600 with `0`
  meaning "no keepalive" (`config.rs:446-451`).

A `keepalive_interval_seconds` of `0` becomes `None` (`config.rs:447-450`),
which is how keepalives are switched off.

---

## 3. Server entries

### 3.1 Parsing

`ServerEntry::from_value` (`server_entry.rs:142-158`) deserialises the
entry through `serde_json::Value` "so numbers, unknown fields and all the
`omitempty` cases behave like the Go reference"
(`server_entry.rs:147-150`), and keeps the original map. An entry with no
`ipAddress` is rejected (`server_entry.rs:152-154`).

The typed view (`Fields`, `server_entry.rs:31-115`) is deliberately
incomplete. It models the fields this client acts on, and the comment at
`server_entry.rs:26-28` explains why the unknown ones are not lost: they stay
in the raw map, so "a signature over them still verifies and a newer client
can read them". The struct also models the fields for transports that are
recognised but not implemented — TapDance, Conjure, in-proxy
(`server_entry.rs:94-109`) — so that an entry listing them parses.

### 3.2 Tag derivation and the diagnostic id

`ServerEntry::tag` (`server_entry.rs:181-186`) returns the explicit `tag`
when the entry has one, and otherwise derives one: `derive_tag`
(`server_entry.rs:477-484`) is `HMAC-SHA256(webServerSecret, ipAddress)`,
base64-encoded. That is exactly Psiphon's `GenerateServerEntryTag`
(`psiphon/common/protocol/serverEntry.go:1020-1023`), whose purpose the Go
comment spells out: the tag must not let anyone reverse the server's IP
address from a database of tags.

`diagnostic_id` (`server_entry.rs:190-197`) is the first eight characters of
the tag, or `"<unknown>"` — Psiphon's `TagToDiagnosticID`
(`psiphon/common/protocol/serverEntry.go:1031-1036`). "Never the address
itself, so logs do not reveal where the user connects"
(`server_entry.rs:188-189`).

### 3.3 Capability rules

`ServerEntry::supports_protocol` (`server_entry.rs:352-373`) mirrors
Psiphon's `hasCapability`. The rules, in the order the code applies them:

- A `-PASSTHROUGH-v2` capability also implies TLS-OSSH, when the base is
  `UNFRONTED-MEEK-HTTPS` or `UNFRONTED-MEEK-SESSION-TICKET`
  (`server_entry.rs:353-360`).
- The capability string is stripped of a `-PASSTHROUGH-v2` suffix and then of
  a `-PASSTHROUGH` component (`server_entry.rs:362-363`), so
  `UNFRONTED-MEEK-HTTPS-PASSTHROUGH-v2` still names
  `UNFRONTED-MEEK-HTTPS`.
- `QUICv1` counts as `QUIC`, for older clients (`server_entry.rs:364-366`).

`supported_protocols` (`server_entry.rs:338-344`) filters the entry's
capabilities through `TunnelProtocol::supported()` in the order of
`TunnelProtocol::all()` — SSH, OSSH, TLS-OSSH, then the meeks
(`protocol.rs:127-143`).

The unit tests pin this: `server_entry.rs:540-554` (including `QUICv1`),
`server_entry.rs:557-565` (the passthrough implication) and
`protocol.rs:164-183` (the capability strings themselves).

### 3.4 Signature verification

`ServerEntry::verify_signature` (`server_entry.rs:381-426`) is the check
that decides whether an entry from the network may be used at all.

The shape of the signature field is Psiphon's: base64 of an 8-byte key
identifier followed by a 64-byte Ed25519 signature. The key identifier is
the first eight bytes of `SHA-256(public key)`
(`server_entry.rs:408-411`), which is how a client tells "signed by a
different key" from "tampered with" — Psiphon does the same
(`psiphon/common/protocol/serverEntry.go:414-419`).

The signed bytes are the trickier part, and the reason `json.rs` exists.
`signed_bytes` (`server_entry.rs:460-473`):

1. copies the raw map;
2. removes the unsigned bookkeeping fields — `localSource`, `localTimestamp`,
   `isLocalDerivedTag`, and `tag` when `isLocalDerivedTag` is true
   (`server_entry.rs:460-466`), which is Psiphon's `RemoveUnsignedFields`
   (`psiphon/common/protocol/serverEntry.go:455-465`);
3. removes the `signature` field itself (`server_entry.rs:452`);
4. encodes the rest with `json::encode` — Go's exact bytes
   (`server_entry.rs:469-470`).

The test `a_signature_covers_go_json_encoding` (`server_entry.rs:603-621`)
pins the consequence: two entries with the same fields in a different
insertion order must both verify, because the signature is over sorted-key
Go JSON.

`ServerEntry::sign` (`server_entry.rs:429-455`) is the inverse, used by the
harness and by the tests.

---

## 4. The dial sequence

### 4.1 Establishing one tunnel

`Client::connect` (`client.rs:49-94`):

1. `config.validate()` (`client.rs:50`).
2. Refuse an upstream proxy outright (`client.rs:52-60`): "Refusing beats
   silently ignoring a proxy the operator asked for: dialling directly would
   leak the traffic the proxy exists to hide, and would fail closed on the
   wrong network."
3. Pick the session id: the configured one, or a fresh random one
   (`client.rs:62-65`, `tunnel.rs:102-106`).
4. `establish(&config, &session_id)` (`client.rs:68`) — one tunnel before
   returning, "so `connect` means 'ready to dial'".
5. Grow the pool to `tunnel_pool_size` (`client.rs:79-91`). A failure to
   grow is logged and breaks the loop; it is not fatal.

`establish` (`client.rs:276-331`) is the racing dial loop. It builds the
candidate list, then:

- with `concurrency <= 1` it tries the candidates strictly in order
  (`client.rs:280-295`);
- otherwise it keeps up to `establish_concurrency` attempts in flight with a
  `FuturesUnordered`, refilling the window as results come in
  (`client.rs:300-325`), and returns the **first** success, dropping the
  others (`client.rs:311-315`).

The reason for racing rather than ordering is stated at
`client.rs:270-275`: "a filtered address accepts the TCP connection and then
says nothing, so a sequential client waits out the whole budget before trying
the next entry."

When every candidate fails, the error names all of them
(`client.rs:327-330`): "no psiphon tunnel could be established (...)" with
one `entry over protocol: error` clause per candidate
(`client.rs:375`).

`attempt` (`client.rs:369-410`) is one candidate:

1. the host and the port for the transport (`client.rs:377-378`);
2. the carrier (`client.rs:392-395`, §4.4);
3. the SSH session (`client.rs:397-400`) — `SshTunnel::establish` with the
   `establish_timeout` as its budget;
4. the tunnel handshake (`client.rs:402-407`) — the `psiphon-handshake` global
   request.

### 4.2 The candidate list

`candidate_list` (`client.rs:338-363`) produces the (entry, transport) pairs:

- an entry whose region is neither empty nor the configured `egress_region`
  is skipped (`client.rs:342-347`); an entry with no region is kept as a
  last resort, because "embedded entries can omit it"
  (`client.rs:334-337`);
- a transport the entry does not advertise is not offered
  (`server_entry.rs:338-344`);
- a transport outside the configured `protocols` is skipped
  (`client.rs:350-352`);
- an empty list is a configuration error (`client.rs:357-361`).

### 4.3 Where each bound applies

This is the part worth being exact about, because the bounds do not nest the
way the names suggest.

| Bound | Value | Applies to | Source |
|---|---|---|---|
| `TCP_TIMEOUT` | 10 s | the DNS lookup, and **each** address's connect | `client.rs:32`, `client.rs:526`, `client.rs:538` |
| `establish_timeout` | 20 s default | the SSH **key exchange** | `config.rs:225`, `client.rs:392`, `tunnel.rs:291-299` |
| `establish_timeout` | 20 s default | the SSH **authentication** — a second, independent budget | `config.rs:225`, `tunnel.rs:312-320` |
| `CHANNEL_TIMEOUT` | 10 s | one `direct-tcpip` channel open | `tunnel.rs:47`, `tunnel.rs:364-373` |
| `keepalive_interval` | 25 s default | `keepalive@openssh.com`, at most 3 unanswered | `config.rs:233`, `tunnel.rs:283-284` |
| *no bound* | — | the `psiphon-handshake` request | `tunnel.rs:347-360` |
| *no bound* | — | the meek carrier's poll interval (100 ms to 5 s) | `meek.rs:53-55`, `meek.rs:426-446` |

Two consequences follow, and both are worth stating because a reader will
otherwise assume a single deadline:

- The key exchange and the authentication each get the **full**
  `establish_timeout`, not a share of it, so one attempt can take up to
  `2 × establish_timeout` after the TCP phase.
- The TCP phase is bounded by `TCP_TIMEOUT` per address, not by
  `establish_timeout`. A host with several A records is tried one after the
  another at 10 s each (`client.rs:536-553`).

The `psiphon-handshake` request has no timeout of its own
(`tunnel.rs:347-360`); it is bounded only by whatever the SSH session's own
liveness rules impose.

### 4.4 The carriers

`carrier` (`client.rs:413-513`) maps a transport to a byte stream:

- **SSH** — a plain TCP connection (`client.rs:420-423`).
- **OSSH** — a TCP connection wrapped in `OsshClient`, keyed with the
  entry's `sshObfuscatedKey` (`client.rs:424-430`).
- **TLS-OSSH** — a TCP connection wrapped in TLS and then in the OSSH layer
  (`client.rs:431-440`). The options are the defaults, so no SNI is sent:
  "the Go client only sends a name when tactics provide one, and it dials the
  server's address rather than a domain" (`client.rs:433-435`).
- **the unfronted meek protocols** — a TCP connection to the entry's
  `meekServerPort`, wrapped in TLS for the HTTPS and session-ticket
  variants, then in a `MeekStream`, then in the OSSH layer
  (`client.rs:441-499`). The meek session's cookie is sealed to the entry's
  `meekCookieEncryptionPublicKey` (`client.rs:484-491`).
- **the fronted meek protocols** — `Error::Meek("the fronted meek carrier
  is not implemented in this build")` (`client.rs:500-502`).
- **QUIC, Shadowsocks, TapDance, Conjure, fronted-meek-over-QUIC** —
  `Error::Protocol("the {protocol} transport is not implemented in this
  build")` (`client.rs:503-509`).

The TCP helper `tcp` (`client.rs:521-559`) parses the host as an IP address
when it can, resolves it otherwise, tries each resolved address in turn, and
sets `TCP_NODELAY` on the socket that answers
(`client.rs:541-543`): "Proxy traffic is request/response: the latency of a
small request matters more than the cost of a small packet."

Every outbound socket goes through `zero_core::connect_protected`
(`client.rs:538`), which protects the descriptor *before* the SYN goes out
(`Zray-Core/crates/zero-core/src/platform.rs:283-300`).

### 4.5 Handing out a stream

`Client::dial` (`client.rs:100-116`) takes a channel slot
(`client.rs:101-107`), refuses the dial if the client is already at
`max_channels`, and returns a `BoxStream` whose drop releases the slot
(`CountedStream`, `client.rs:221-234`).

`dial_inner` (`client.rs:121-173`) is two passes over the same logic:

1. take the established tunnels, round-robin over them
   (`client.rs:128-134`) — "so the pool is used evenly, and so a busy tunnel
   does not take every new channel" (`client.rs:130-131`);
2. if a tunnel opens the channel, return it (`client.rs:135-142`);
3. if **every** tunnel refused the channel, the tunnels are stale rather
   than the destination being unreachable, so the pool is emptied
   (`client.rs:155-157`);
4. establish a fresh tunnel and push it (`client.rs:160-167`); if that
   fails, the error says so: "no psiphon tunnel could be established after a
   channel failure" (`client.rs:163-165`);
5. repeat from step 1, once.

After two passes the last channel error is returned
(`client.rs:170-172`).

So a tunnel that dies mid-dial is not fatal: the pool is dropped, a new
tunnel is established and the channel is retried on it, up to two
re-establishments per dial.

### 4.6 The SSH session itself

`SshTunnel::establish` (`tunnel.rs:263-338`):

- the host key is pinned by value: the key exchange must present exactly the
  bytes in the entry's `sshHostKey` (`tunnel.rs:209-224`,
  `server_entry.rs:251-259`);
- the SSH identification line is `TunnelOptions::client_version`, default
  `"SSH-2.0-OpenSSH_9.6"` (`tunnel.rs:44`, `tunnel.rs:279`);
- the window is `TunnelOptions::window_size` (4 MiB), the maximum packet
  32 KiB, the channel buffer 64 messages (`tunnel.rs:278-289`);
- `inactivity_timeout: None`, because "a dead peer must be noticed; an idle
  tunnel is not a dead one" (`tunnel.rs:285-287`);
- the password is the JSON credential payload (§5.2).

`SshTunnel::open` (`tunnel.rs:378-393`) opens a `direct-tcpip` channel with
the origin address `0.0.0.0:0` — the same origin the Go client sends
(`psiphon/common/crypto/ssh/tcpip.go:470-481`) — and the destination
**unresolved**, which the server resolves.

`SshTunnel::handshake` (`tunnel.rs:347-360`) sends the
`psiphon-handshake` global request. The server refuses every port forward
until this has succeeded (`tunnel.rs:342-345`; Psiphon:
`psiphon/server/tunnelServer.go:5059-5068` sets the state that allows
forwards), so it is part of bringing the tunnel up, not an optional extra.

---

## 5. Identity and credentials

Psiphon enforces a set of rules on the server side. This section states each
rule, says where the server enforces it, and says where this client sets the
value.

### 5.1 The rules

| Rule | Enforced by the server | Set by this client |
|---|---|---|
| The SSH user name must equal the server's configured `SSHUserName` | constant-time compare, `psiphon/server/tunnelServer.go:3052-3054` | `ServerEntry::ssh_username()` → `tunnel.rs:314` |
| The SSH password must be a JSON `SSHPasswordPayload` | `psiphon/server/tunnelServer.go:3030-3044` | `credential_payload`, `tunnel.rs:113-126` |
| `SessionId` must be hex digits and exactly 32 characters (16 bytes) | `psiphon/server/tunnelServer.go:3046-3050`, `psiphon/common/protocol/protocol.go:86` | `TunnelOptions::session_id` → `tunnel.rs:301-303` |
| `SshPassword` must equal the server's password | constant-time compare, `psiphon/server/tunnelServer.go:3056-3058` | `ServerEntry::ssh_password()` → `tunnel.rs:301-303` |
| `SponsorId`, when present, must be 16 hex characters | `psiphon/server/tunnelServer.go:3074-3077`, `psiphon/server/api.go:2161-2163` | `TunnelOptions::sponsor_id` → `tunnel.rs:304` |
| `ClientCapabilities` may name `server-requests` | `psiphon/server/tunnelServer.go:3069-3070` | *not advertised* — `TunnelOptions::capabilities` is empty (§5.4) |
| `propagation_channel_id` must be hex digits | `psiphon/server/api.go:1478` | `HandshakeParams::propagation_channel_id` → `tunnel.rs:199` |
| `sponsor_id` must be 16 hex characters | `psiphon/server/api.go:1479` | `HandshakeParams::sponsor_id` → `tunnel.rs:200` |
| `client_version` must be an **integer string** | `psiphon/server/api.go:1480` (`isIntString` → `strconv.Atoi`) | `HandshakeParams::client_version` → `tunnel.rs:201` |
| `client_platform` must contain no whitespace | `psiphon/server/api.go:1481` (`isClientPlatform`) | `HandshakeParams::client_platform` → `tunnel.rs:202` |
| `relay_protocol` must be a supported tunnel protocol | `psiphon/server/api.go:1496`, `psiphon/server/api.go:2205-2207`, `psiphon/common/protocol/protocol.go:221-235` | `HandshakeParams::relay_protocol` → `tunnel.rs:203` |

### 5.2 The credential payload

The SSH "password" is a JSON object with Psiphon's own field names
(`CredentialPayload`, `tunnel.rs:89-99`):

```json
{"SessionId":"…","SshPassword":"…","ClientCapabilities":["…"],"SponsorId":"…"}
```

Every field is omitted when empty, which is Go's `omitempty` behaviour
(`tunnel.rs:91-98`); the Go struct it mirrors is
`protocol.SSHPasswordPayload`
(`psiphon/common/protocol/protocol.go:901-906`). The unit test
`tunnel.rs:652-670` pins the field names and the omission rules.

The Go client always sends `ClientCapabilities: ["server-requests"]`
(`psiphon/tunnel.go:1173`); this client sends none. The reason is in
`tunnel.rs:110-112`: "advertising `CAPABILITY_SERVER_REQUESTS` makes the
server send its own SSH requests (OSL, alerts), which this client does not
handle yet." The constant exists (`tunnel.rs:41`) and is used by the tests,
but `TunnelOptions::capabilities` is never populated on the client path
(`client.rs:380-390` leaves it at the `Default::default()` of
`tunnel.rs:83`).

The Go server accepts a client that does not advertise the capability: it
records `supportsServerRequests` from the payload
(`psiphon/server/tunnelServer.go:3069-3070`) and behaves accordingly. The
interoperability evidence agrees: the harness server's `server_tunnel` events
record `handshake_completed: true` for a client that advertised no
capabilities (`.research/psiphon-server-harness/logs/psiphond-bench.log`).

### 5.3 The tunnel handshake payload

`HandshakeParams` (`tunnel.rs:137-148`) is the payload of the
`psiphon-handshake` global request, in Psiphon's snake_case names
(`tunnel.rs:197-206`):

```json
{"propagation_channel_id":"…","sponsor_id":"…","client_version":"…",
 "client_platform":"…","relay_protocol":"…"}
```

The defaults (`HandshakeParams::new`, `tunnel.rs:153-161`) are all zeros for
the two identifiers, `"1"` for the version, `"Other"` for the platform, and
the protocol that was actually dialled for `relay_protocol`.

The `with_*` builders deliberately refuse an empty value
(`tunnel.rs:164-195`): an empty `sponsor_id` would be rejected by the server
outright, because `sponsor_id` is a required handshake parameter
(`psiphon/server/api.go:1479`, no "optional" flag), so the default of
`"0000000000000000"` is kept instead.

### 5.4 The two version numbers

This is worth spelling out because the names are confusing and the two are
unrelated:

- **`client_version`** is the Psiphon client version the handshake
  announces, and it is validated by the server as an integer string. It is
  *not* the SSH identification line. `config.rs:111-114` says so
  explicitly, and `client.rs:381-384` repeats it at the point of use.
- **`TunnelOptions::client_version`** is the SSH identification line
  (`SSH-2.0-OpenSSH_9.6`, `tunnel.rs:44`). The Go client calls the
  equivalent `dialParams.SSHClientVersion` and sends it in the handshake as
  the optional `ssh_client_version` parameter
  (`psiphon/server/api.go:1497`); this client does not send
  that optional parameter at all, which the server allows
  (`requestParamOptional`).

### 5.5 The values the server actually saw

The harness's server log for the 8 MiB benchmark run records what the real
`psiphond` understood, and it matches this client exactly
(`.research/psiphon-server-harness/logs/psiphond-bench.log`):

```json
"client_platform":"Other","client_version":1,
"propagation_channel_id":"0000000000000000","sponsor_id":"0000000000000000",
"handshake_completed":true,"relay_protocol":"SSH"
```

`client_version` appears as the **number** 1 because the server logs an
integer string as an integer (`requestParamLogStringAsInt`,
`psiphon/server/api.go:1480`). That is the whole reason the client
configuration validates the version as digits rather than as a free string
(`config.rs:155-167`).

---

## 6. Status

The three tables below are the honest state of the crate. "Interop-verified"
means there is a passing run of the test against the real `psiphond` in this
repository's harness.

### 6.0 Implemented and verified without the harness

Everything below runs in one process — no server, no network, no Go
toolchain — which is what makes it the layer that runs on every change:

| What | Where the tests are |
|---|---|
| Go's `encoding/json` bytes | `json.rs:164-226` |
| Server entry parsing, tag derivation, capability rules, signature verify and sign | `server_entry.rs:495-638` |
| OSSH: RC4, key derivation, the seed message, the packet-padding rewrite, the state machine | `obfuscator.rs:617-803` |
| TLS-OSSH: the passthrough key and message, the `ClientHello` shaping, TLS-with-OSSH nesting | `tls_ossh.rs:313-740` |
| Meek: the sealed cookie, the request framing, the session cookie, the poll back-off, the response parser | `meek.rs:910-1226` |
| NaCl `box`, layer by layer against Go-generated vectors | `nacl_box.rs:169-288` |
| The SSH semantics, against an in-crate `russh` echo server: authentication, host-key pinning, a channel that echoes | `tunnel.rs:437-681` |
| The configuration: parsing, validation, the cache key, secret redaction | `config.rs:532-690` |
| The candidate list and the racing dial loop | `client.rs:561-685` |
| The shared registry and its idle reaping | `shared.rs:229-273` |
| The in-process mock Psiphon server (SSH and OSSH), driving both the client and the tunnel | `mock.rs:400-620` |
| The tactics exchange: framing, records, expiry, the server list encodings | `tactics.rs:1200-1600` |

### 6.1 Interop-verified against a real `psiphond`

| What | Evidence |
|---|---|
| Plain SSH: carrier, credential payload, `psiphon-handshake`, `direct-tcpip` channel, a request through the tunnel | `crates/zero-psiphon/tests/real_server.rs:126-134`, `:44-122` |
| OSSH: the same, under the obfuscation layer | `crates/zero-psiphon/tests/real_server.rs:137-145` |
| TLS-OSSH: the same, under TLS and the obfuscation layer | `crates/zero-psiphon/tests/real_server.rs:150-158` |
| The whole client — candidate selection, the dial loop, the credential payload, the handshake, a stream to a destination — over all three transports | `crates/zero-psiphon/tests/real_server.rs:162-215` |
| Unfronted meek over TLS: the meek session, the OSSH layer over it, the SSH session, the handshake, a request through the tunnel | `crates/zero-psiphon/tests/meek.rs:59-182`; evidence at `.research/psiphon-server-harness/logs/verify-meek-evidence.log:25-28` |
| Fronted meek: `FRONTED-MEEK-OSSH` and `FRONTED-MEEK-HTTP-OSSH` through a local CDN edge to the real `psiphond`, the obfuscated cookie and the SSH session inside | `crates/zero-psiphon/tests/fronted_meek.rs` (three tests), `./verify-fronted.sh` |
| The Zray outbound: `{"protocol":"psiphon"}` parses, dials, and carries a request to a loopback origin | `crates/zero-runtime/tests/psiphon_outbound.rs:130-215` |
| A run-time account's traffic metered *through a Psiphon tunnel*, a speed limit holding its session, and its session ending when the account is removed | `crates/zero-runtime/tests/psiphon_accounts.rs` (three tests) |

The passing run is recorded at
`.research/psiphon-server-harness/logs/verify-rust-evidence.log:19-25`:

```
running 4 tests
test plain_ssh_against_the_real_server_carries_a_request ... ok
test the_dial_loop_carries_a_request_end_to_end ... ok
test obfuscated_ssh_against_the_real_server_carries_a_request ... ok
test tls_obfuscated_ssh_against_the_real_server_carries_a_request ... ok
test result: ok. 4 passed; 0 failed
```

A separate out-of-tree check records the same thing from the server's side
(`.research/psiphon-server-harness/logs/rust-interop-evidence.log:1-17`):
the entry's signature verified, the SSH session authenticated, the handshake
accepted, and the tunnel carried a `direct-tcpip` request whose body was the
origin's marker.

The unfronted meek transport has its own passing run, recorded at
`.research/psiphon-server-harness/logs/verify-meek-evidence.log:25-28`:

```
running 1 test
test unfronted_meek_against_the_real_server_carries_a_request ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

with the summary line "meek interop:  PASS"
(`.research/psiphon-server-harness/logs/verify-meek-evidence.log:32`).

### 6.2 Implemented, with unit tests only

These have thorough unit tests — often against vectors taken from the Go
implementation — but no run against a real `psiphond` is recorded in this
repository.

| Server entry parsing, tag derivation, capability rules, signature verify and sign | `server_entry.rs:495-638` |
| OSSH: RC4, key derivation, the seed message, the packet-padding rewrite, the state machine | `obfuscator.rs:617-803` |
| TLS-OSSH: the passthrough key and message, the `ClientHello` shaping, TLS-with-OSSH nesting | `tls_ossh.rs:313-740` |
| Meek: the sealed cookie, the request framing, the session cookie, the poll back-off, the response parser | `meek.rs:910-1226` |
| NaCl `box`, layer by layer against Go-generated vectors | `nacl_box.rs:169-288` |
| The SSH semantics, against an in-crate `russh` echo server: authentication, host-key pinning, a channel that echoes | `tunnel.rs:437-681` |
| The configuration: parsing, validation, the cache key, secret redaction | `config.rs:532-690` |
| The candidate list and the racing dial loop | `client.rs:561-685` |
| The shared registry and its idle reaping | `shared.rs:229-273` |
| The in-process mock Psiphon server (SSH and OSSH), driving both the client and the tunnel | `mock.rs:400-620` |
| The tactics exchange: framing, records, expiry, the server list encodings | `tactics.rs:1200-1600` |
| The Zray outbound end to end through a real `psiphond` | `crates/zero-runtime/tests/psiphon_outbound.rs:130-215` |
| The in-crate mock Psiphon server: the credential payload, the `psiphon-handshake`, `direct-tcpip` forwarding, and the server side of the OSSH layer | `mock.rs:409-581` |
| Tactics: the framing, the parameter model, the record, the server list | `tactics.rs:1141-1600` |

### 6.3 Not implemented

| What | Where the absence is visible |
|---|---|
| **Fronted meek's certificate check.** The carrier works and is interop-verified, but it accepts the edge's certificate rather than verifying it (§7.1). | `client.rs`, the fronted arm of `carrier()` |
| **QUIC-OSSH, fronted-meek-over-QUIC** | `client.rs:503-509`; `protocol.rs:47-48` |
| **Shadowsocks-OSSH** | `client.rs:503-509`; `protocol.rs:46` |
| **TapDance-OSSH, Conjure-OSSH** | `client.rs:504-505`; `protocol.rs:29-30` |
| **An upstream proxy.** The configuration parses one; the client refuses it. | `client.rs:52-60` |
| **Remote server list fetching.** The decoder and the verifier exist in `tactics.rs`; nothing fetches. | `config.rs:180` (the field is read and never used) |
| **Tactics fetching and application.** The module exists; the dial path never calls it, and `TacticsParameters` is never applied to a dial. | `tactics.rs` is not referenced by `client.rs` or `config.rs`; `config.rs:181-184` |
| **Server-initiated SSH requests (OSL, alerts).** The capability is deliberately not advertised. | `tunnel.rs:110-112` |
| **`direct-tcpip-no-split-tunnel@psiphon.ca`** — Psiphon's split-tunnel channel type. | `tunnel.rs:18-21` |
| **Split tunnel.** The client always asks for `direct-tcpip`, so a server with split tunnel enabled may reject the channel. | `tunnel.rs:378-393` |
| **A local SOCKS/HTTP listener, routing, DNS, stats** | `client.rs:11-13`, `lib.rs:10-11` |
| **The mock server's API, tactics endpoint and rate limits.** The in-crate mock speaks the client-facing half of the protocol and no more. | `mock.rs:14-17` |
| **OSSH prefix / seed-transform variants.** Only the plain seed message is produced. | `obfuscator.rs:127-139` |

The meek case is the one that has moved most recently, so it is worth a
paragraph. All five meek protocols are listed as supported
(`protocol.rs:113-130`) and all five are carried: the unfronted ones dial the
entry's own meek port (`client.rs`, the unfronted arm), the two fronted ones
dial the entry's fronting address and ask for its fronting host through a TLS
session whose server name is that address (`client.rs`, the fronted arm) —
verified through a local CDN edge against the real `psiphond`
(`crates/zero-psiphon/tests/fronted_meek.rs`). `FRONTED-MEEK-QUIC-OSSH` is
not among them: it needs QUIC, which this port has no carrier for. An entry
that advertises only that
will therefore produce a candidate list that is non-empty and a dial that
always fails. See §7.1.

---

## 7. Risks and known deviations

Each item says what the reader should do about it.

### 7.1 The fronted hop is not authenticated

The fronted TLS session uses the same accept-any certificate verifier as the
TLS-OSSH carrier (`client.rs`, the `TlsOsshOptions`/`tls_config` pair), so the
edge is not authenticated: the SSH host key inside pins the *server*
(`tunnel.rs:601`, `a_wrong_host_key_is_refused`), but a fronting provider
whose own certificate is not verified offers no protection against an active
attacker at the edge.

That asymmetry is deliberate for TLS-OSSH — its certificate is self-signed and
carries no name, and identity is proven inside — but it is a real gap for a
fronted connection, whose peer is a public CDN with a publicly trusted
certificate that the Go client *does* check: `meekConn.go`'s `MeekConfig`
carries `VerifyServerName`, `VerifyPins` and `DisableSystemRootCAs`, and the
fronted dial sets them from dial parameters. None of the three is implemented
here.

**What to do.** Implement name and pin verification of the fronting **host**
(`meekFrontingHosts`, the `Host` header value — not the dial address we put in
SNI, which is usually an IP literal), with pins for entries whose
`meekFrontingDisableSNI` leaves nothing to verify, exactly as the Go client
does. The harness's local edge relies on the current behaviour on purpose: its
certificate is self-signed and points at a process the test started, so
verifying it would couple the interop test to certificate plumbing and prove
nothing about the client.

`UnfrontedMeekSessionTicket` is carried by the same TLS arm as
`UnfrontedMeekHttps`: a session-ticket server is an HTTPS server whose tickets
are obfuscated, which changes the TLS session cache the carrier would need to
use, not the framing around it.

### 7.2 The meek transport's cost is unmeasured

The unfronted meek carrier is implemented (`client.rs:441-499`) and
interop-verified against the real `psiphond`
(`.research/psiphon-server-harness/logs/verify-meek-evidence.log:25-28`).
What it does **not** have is a measurement. The throughput benchmark
covers SSH, OSSH and TLS-OSSH only (`tests/throughput.rs:224-230`), and
meek is not like the others: it is a request/response carrier that
**polls** — with nothing to send it still posts an empty body to give the
server a standing request to answer with downstream bytes
(`meek.rs:278-286`) — and it backs off from 100 ms to 5 s while idle
(`meek.rs:53-55`, `meek.rs:426-446`). Every downstream byte therefore
costs a round trip that the SSH transports do not.

**What to do.** Measure it before putting the meek transport in front of a
user: add it to the benchmark, and count the requests an idle meek tunnel
makes per minute. `PERFORMANCE.md` §5 lists this.

### 7.3 `port_for` and the frontiers of an entry

`ServerEntry::port_for` maps the unfronted meek protocols to the entry's
`meekServerPort`, which is a different listener from `sshObfuscatedPort`
(the harness's entry shows both: 20082 and 20087). The fronted transports are
special on purpose: they dial the *fronting* address, on 443 for
`FRONTED-MEEK-OSSH` and 80 for `FRONTED-MEEK-HTTP-OSSH`, which is the CDN's
port and not a field of the entry at all. That is why
`TunnelDialOptions::fronted_dial_port` exists — production leaves it unset and
gets 443/80, and the harness sets it to the port of its local CDN stand-in.

One frontier case is not handled: Psiphon falls back to `MeekServerPort` for
TLS-OSSH when `tlsOSSHPort` is zero
(`psiphon/common/protocol/serverEntry.go:766-795`). It does not arise with the
entries this port dials (a TLS-OSSH entry in the wild carries `tlsOSSHPort`),
so it is noted rather than guessed at.

### 7.4 The channel window is 32× the Go client's default

`TunnelOptions::window_size` defaults to 4 MiB (`tunnel.rs:76-79`), and
`ClientConfig::channel_window_bytes` to the same (`config.rs:231`). The code
comment calls 4 MiB "the Go client's ceiling", which is true of the
*configurable maximum* (`psiphon/common/crypto/ssh/channel.go:76-81` allows
up to 128 × 32 KiB), but the Go client's **default** is 4 × 32 KiB = 128 KiB
(`psiphon/common/crypto/ssh/channel.go:59-81`, and the same table in
`INTEGRATION.md:1628`).

With `max_channels: 128` (`config.rs:232`) the worst-case window credit is
therefore 512 MiB, against 16 MiB for the Go client. The window is a credit
and not a preallocated buffer, so this is a ceiling rather than an
allocation — but it is a ceiling that a malicious or misconfigured peer
could push towards.

**What to do.** Measure the memory of a busy channel before raising the
window further, and consider lowering the default to the Go client's 128 KiB.
`PERFORMANCE.md` lists this as the first thing to measure.

### 7.5 The keepalive is more aggressive than the Go client's

`keepalive_interval` defaults to 25 s (`config.rs:233`), against the Go
client's 60–120 s (`INTEGRATION.md:1635`). Each keepalive makes the server
record a speed-test sample, and on a phone 25 s is a measurable cost.

**What to do.** Raise the default to 60 s unless a harness test says
otherwise; `INTEGRATION.md:1722-1726` reaches the same conclusion.

### 7.6 The handshake identity is validated before the dial, not by the server

`HandshakeIdentity::validate` rejects an empty or whitespace-bearing
platform, a non-integer `client_version`, and identifiers that are not 16
hex characters (`config.rs:139-186`), which is what Psiphon's server checks
(`psiphon/server/api.go:2198-2203`, `:928`). The client therefore refuses a
configuration the server would refuse, instead of sending it and reading a
bare "invalid parameter" back from a global request that has no room to
explain itself.

The check is not identical to the server's: where the server trims and
compares case-insensitively, the client's is exact. That only means the
client can be stricter, never looser.

### 7.7 A missing `sshUsername` is an authentication failure, not a config error

`ServerEntry::ssh_username()` returns the entry's field, or the empty string
(`server_entry.rs:223-225`). The server compares the SSH user name with its
own in constant time (`psiphon/server/tunnelServer.go:3052-3054`), so an
entry without `sshUsername` authenticates as `""` and is refused. The Go
server always publishes the field (`psiphon/server/config.go:1555`), so this
only bites on a hand-written or truncated entry.

**What to do.** Validate that `sshUsername` is present when the entry is
parsed, or report the authentication failure with a hint that says so.

### 7.8 The `psiphon-handshake` request is unbounded

`SshTunnel::handshake` (`tunnel.rs:347-360`) has no timeout. A server that
accepts the TCP connection and then never answers leaves the dial hanging
indefinitely, past `establish_timeout`.

**What to do.** Bound the request with the same budget the key exchange
uses.

### 7.9 The `establish_timeout` is a per-stage budget, not a total

As §4.3 sets out, the key exchange and the authentication each get the full
budget, and the TCP phase is bounded separately at 10 s per address. A
caller who reads `establish_timeout` as "the whole attempt" will be
surprised by a dial that takes 2.5× as long.

**What to do.** Either rename it, or wrap the whole `attempt` in a single
`tokio::time::timeout` and let the inner budgets be the sub-limits.

### 7.10 Tactics are fetched only when a transport is supplied

`Client::connect_with_tactics` fetches before the first dial when
`config.tactics` is set, and applies the parameters this client uses — the
establishment budget and the obfuscated layer's padding range — through
`apply_tactics` (`client.rs:120-190`, `:365-395`). Everything else in a
tactics record concerns traffic shaping this port does not implement, and is
left unapplied rather than half-applied.

Two things a reader should know:

* The fetch needs an HTTP carrier, which this crate has no reason to carry:
  the caller passes one (a `TacticsTransport`). A caller that passes `None`
  gets the configured parameters and a debug log saying so, not a failure.
  `zero-runtime` does not pass one yet, so in Zray the configured parameters
  are what a dial uses.
* `ClientConfig::key()` deliberately does not cover tactics-derived values.
  It is computed from the configuration, and it keys the shared client: two
  connections to the same configured outbound must share a client, so the
  key cannot depend on what a server happened to say on one of them.

**What to do.** Pass a transport from whoever owns the HTTP stack when
tactics matter (a Zray build with a shaped HTTP client is the natural
place), and decide then whether a tactics-derived timeout belongs in the
key.

### 7.11 The remote server list is decoded but never fetched

`decode_server_list` and `verify_server_list` (`tactics.rs:872-923`) handle
the JSON, base64, hex and packed encodings and check every entry's
signature. Nothing calls them, and `config.remote_server_list_urls`
(`config.rs:180`) is read and never used: entries come from the
configuration.

**What to do.** Wire the fetch into the shared registry's first-dial path
if a remote list is configured. The verifier is the piece that matters for
safety, and it is already written.

### 7.12 The split-tunnel channel type is not used

The client always opens `direct-tcpip` (`tunnel.rs:378-393`). Psiphon's
server with split tunnel enabled can reject a `direct-tcpip` channel for a
destination in the client's own region — the Go client handles that
rejection specially (`psiphon/tunnel.go:637-641`). This client would report
it as an ordinary channel error.

**What to do.** When a split-tunnel rejection is seen, retry with
`direct-tcpip-no-split-tunnel@psiphon.ca`. The Go client picks the channel
type up front (`psiphon/tunnel.go:630-633`) and handles the rejection
separately (`psiphon/tunnel.go:637-641`). The variant needs a small `russh`
patch or a hand-rolled channel-open message (`tunnel.rs:18-21`).

### 7.13 The `ClientConfig::key()` does not cover the fields that do not
change the tunnel

`key()` covers the region, the limits, the identity, the proxy, the
protocols and the entries' secrets (`config.rs:311-348`). It does not cover
`tactics`, `tactics_url`, `data_dir`, `server_entry_signature_public_key`
or `remote_server_list_urls`. That is correct today, because none of those
changes the tunnel — but two of them change whether an entry may be used at
all, and §7.10 and §7.11 will make that true.

**What to do.** Revisit the key when tactics and remote lists are wired in.

### 7.14 The crate is in flux

`crates/zero-psiphon` is being written in parallel with these documents.
Four things changed **while this document was being written**, which is the
best possible illustration of the point:

- `tactics.rs` grew from three lines to over 1500, and a full tactics
  exchange appeared;
- the unfronted meek carrier was wired into the dial path
  (`client.rs:441-499`), along with the three `ServerEntry` accessors it
  needs;
- `tests/meek.rs` appeared, and then the unfronted meek interop passed
  against the real `psiphond`
  (`.research/psiphon-server-harness/logs/verify-meek-evidence.log:25-28`);
- `mock.rs` grew from three lines to a working in-process Psiphon server
  (`mock.rs:1-17`).

The descriptions above are a snapshot of 2026-10-19, taken between those
changes.

**What to do.** Treat the symbol names as the anchors and re-check the line
numbers when a claim matters. When the crate settles, this document should be
re-read against it — in particular §6.2's list of unit-tested components,
§6.3's list of gaps, and §7.1–§7.3, all of which move as the work
continues.
