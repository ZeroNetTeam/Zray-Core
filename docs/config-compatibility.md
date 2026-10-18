# Known divergences from Xray

Everything here is a place where Zray's behaviour is deliberately, knowably
different from the pinned Xray oracle (`v26.7.28`, commit `5ca6f4b`). Each entry
names the test that holds the divergence in place, because an undocumented
divergence and an unnoticed regression look identical from the outside.

## Fingerprint profiles that cannot carry REALITY

Profiles with no X25519 key share — the Android/okhttp shape, the 360 shapes,
several archived Chrome/Firefox/iOS versions — cannot carry a REALITY tag,
because REALITY derives its authentication key from the hello's own ephemeral
X25519 secret. These are refused at config-compile time rather than at connect
time, since a REALITY failure is a *silent* relay to the decoy site.

**Pinned by.** `zero-security/src/reality_compat.rs` and the cross-crate parity
test `zero-runtime/tests/reality_compatibility.rs`, which compares the config
compiler's independent copy of the rule against the wire corpus for every
profile in it.

## ClientHellos that are not browser-shaped

The uTLS profile is applied to TCP TLS hellos only. Three kinds of hello leave
as rustls writes them:

- **QUIC** (Hysteria2, TUIC, Juicity, XHTTP over HTTP/3, the WARP MASQUE HTTP/3
  leg, DoH3/DoQ). The shaping hook returns no plan when the connection is QUIC
  (`BrowserClientHelloCustomizer`), because a browser's QUIC hello carries
  `quic_transport_parameters` and a different extension set from its TCP one,
  and the TCP profile data is not that.
- **ECH.** With an ECH config list the shape is skipped (see
  `build_client_config`), because the hook cannot tell the outer hello from the
  inner one and reshaping broke Cloudflare ECH.
- **DoT** (port 853), which has no browser equivalent to copy.

Every other plain client (config and asset fetches, subscriptions, the update
check, WARP registration, the clean-IP probe, DoH over HTTP/2, the WARP MASQUE
HTTP/2 leg) uses the Chrome profile; the HTTP/1.1-only ones offer `http/1.1`
as their only ALPN because that is all they speak.

**Pinned by.** `zero-security` `the_https_helper_wears_chrome_and_offers_only_what_it_speaks`,
`zero-transport` `the_http2_leg_wears_a_browser_hello_and_offers_h2`, and
`zero-dns` `doh_is_browser_shaped_and_dot_is_not`.

## ECH GREASE payload length

uTLS draws the ECH GREASE payload length from four candidates per connection;
Zray pins the first. Recorded in `utls_profiles.rs` alongside the constant.
Unpinning it requires a fixture per candidate so the shape guard can accept any
of the four.

## Encrypted resolvers behind a private CA

`dns.certificates` accepts the same `usage: "verify"` entries an outbound's
`tlsSettings.certificates` does, and adds them to the trust store every
encrypted resolver transport shares (DoT, DoH, DoH3 and DoQ).

Xray has no equivalent: its DoQ nameserver builds a TLS config with no way to
name a trust anchor, so reaching a self-hosted resolver there means changing
the system store or the process environment. That is a divergence in Zray's
favour and it is deliberate — the alternative operators reach for is disabling
verification, and an anti-sanction or enterprise resolver behind a private CA
is a normal thing to have (PLAN-02 §3.5).

Anchors are additive: naming one never removes the public roots, and never
makes verification optional. An unusable anchor is logged and skipped rather
than taking DNS down for a typo.

**Pinned by.** `zero-runtime/tests/dns_oracle.rs`, which reaches a DoQ server
presenting the test CA, and would fail closed without the anchor.

## SOCKS5 outbound is TCP only

**What differs.** Xray's `socks` outbound can relay UDP through UDP ASSOCIATE.
Zray's speaks CONNECT only, so a UDP destination routed to it is refused.

**Why.** The point of this outbound is to put a local Tor, Orbot or Psiphon
client in the path, and Tor carries no UDP at all. A UDP flow that reaches it
fails at once instead of silently going nowhere.

**Accepted shapes.** `settings.servers[0]` with `users[0]` (`user`, `pass`), and
the flat form `settings.address/port/user/pass`. Names are sent to the upstream
unresolved (`socks5h` behaviour), so the upstream does the lookup.

**Pinned by.** `zero-protocol/src/socks.rs` (client handshake against RFC 1928
and 1929), `zero-config` (both JSON shapes, `socks://`, `socks5://`,
`socks5h://`) and `zero-runtime/tests/socks_upstream.rs` (a runtime through an
independent SOCKS5 server, including that a name that resolves nowhere still
arrives).

## The `tor` outbound has no Xray counterpart

`{"protocol": "tor"}` is Zray's own. It runs Arti inside the process and needs
a build with the `tor` cargo feature (`zero-runtime/tor`, or `--features tor`
on `zray` and `zeronet-tui`); without it the outbound parses, then every
connection fails with a message saying the build has no Tor.

`settings` are all optional: `bridges` (bridge lines), `transports`
(`{"obfs4": "/usr/bin/lyrebird"}`), `dataDir`, `memoryMiB` (default 64, minimum
32). A bridge that names a transport with no program set is rejected when the
config is read.

Limits worth knowing: TCP only, and desktop only for now (the Android library
is not built with the feature). Pluggable-transport programs (lyrebird,
snowflake-client) are separate processes that this build does not include; their
sockets are the program's own and are not exempted from a VPN. Tor's own
connections to relays and bridges are exempted through the same socket hook
every other outbound uses.

**Pinned by.** `zero-config` (settings and bridge/transport validation),
`zero-tor` (Arti configuration and the memory cap) and
`zero-runtime/tests/tor_outbound.rs` (the no-Tor-build message, UDP refusal,
and an ignored live check that needs the real Tor network: it opens a circuit to
check.torproject.org and reads the answer back). Arti buffers writes until they
are flushed, so a caller that writes and then only reads must flush first.

## Hysteria 2: Salamander, and certificate checks

A Hysteria 2 link reads `obfs=salamander&obfs-password=…` (the password also
as `obfs_password`). Every UDP datagram of the connection is then wrapped the
way the Hysteria 2 server does it: an 8-byte salt in front, the payload XORed
with `BLAKE2b-256(password || salt)`. The password must be at least 4 bytes;
another `obfs` type is refused, not ignored, because connecting without the
obfuscation to a server that wants it only looks like a dead server. sing-box
configs carry it as `"obfs": {"type": "salamander", "password": …}`, which the
subscription import turns into the same link. Verified against the
`apernet/hysteria` server: the right password carries traffic, a wrong or
missing one does not.

The Hysteria 2 *server* side of ZeroNet (the inbound) does not take a
Salamander password yet.

`insecure=1` (Hysteria 2), `allow_insecure=1` (TUIC, Juicity) and
`allowInsecure=1` (the TCP carriers) skip the certificate check for that one
link. Without them the certificate is verified, so a self-signed server needs
the flag or a trusted certificate. Skipping the check lets anyone on the path
pose as the server.

## The `juicity` outbound has no Xray counterpart

`{"protocol": "juicity"}` and the `juicity://<uuid>:<password>@host:port` link
are Zray's own, matching the `daeuniverse` reference and the `juicity` server.
Like TUIC it rides one authenticated QUIC connection per server (ALPN `h3`),
but each request is a trojan-style stream — `[network][addr][port]` then the
bytes — so a UDP flow is carried over a stream too, not a QUIC datagram.

**Certificate verification is mandatory.** Juicity deployments often front a
self-signed certificate pinned by `pinned_certchain_sha256`, and some share
links carry `allow_insecure`. Zray accepts both fields and honours neither: the
model refuses to disable verification for any outbound, and this client has no
pin-by-hash trust path, so it verifies the ordinary certificate chain. A
Juicity server must therefore present a chain Zray can verify (a public CA, or
one named through `tlsSettings.certificates`); a self-signed server that only a
hash would admit is refused at connect time rather than trusted blindly.

**Pinned by.** `zero-config` (the `juicity://` link and `{"protocol":
"juicity"}` JSON, uuid/password and the secure-by-default TLS block) and
`zero-transport/src/juicity.rs` (the trojan address framing and the
authentication command) and `zero-runtime/tests/juicity_loopback.rs` (the whole
client through a Juicity server written in the test from the reference's wire
contract: TCP, a destination sent as a name, twelve streams on one authenticated
connection, UDP over a stream, and a wrong password refused). That server is not
the reference binary, so interoperability with a real Juicity server is checked
against the reference source, not run.

## Plain WireGuard rides the AmneziaWG path

A plain WireGuard link (`wireguard://`, `wg://`) or `{"protocol": "wireguard"}`
config with no AmneziaWG obfuscation fields parses straight through the
AmneziaWG outbound with every junk and header-rewrite knob left at zero (and
`h1..h4` at the standard WireGuard message types `1..4`), which is byte-for-byte
plain WireGuard on the wire. There is no separate plain-WireGuard code path, and
none is needed.

**Pinned by.** `zero-config` (the `wireguard`/`wg` link schemes and the
`wireguard`/`amnezia-wg`/`amneziawg` JSON protocols both reaching
`parse_amnezia_wireguard`).

## ShadowTLS v3 is a `streamSettings.security`, not a separate outbound

sing-box models ShadowTLS as its own outbound that another outbound detours
through: a Shadowsocks outbound with `"detour": "shadowtls-out"`, and a
`{"type": "shadowtls"}` outbound carrying the password, version and decoy `tls`
block. Zray has no detour chain, so the two collapse into one outbound — a
Shadowsocks outbound whose `streamSettings.security` is `shadowtls`:

```json
{
  "protocol": "shadowsocks",
  "settings": {
    "servers": [{
      "address": "relay.example", "port": 443,
      "method": "2022-blake3-aes-128-gcm", "password": "<inner shadowsocks key>"
    }]
  },
  "streamSettings": {
    "network": "raw",
    "security": "shadowtls",
    "shadowtlsSettings": {
      "version": 3,
      "password": "<shadowtls password>",
      "tls": { "serverName": "www.microsoft.com", "alpn": ["h2", "http/1.1"] }
    }
  }
}
```

The mapping from a sing-box pair is direct: the Shadowsocks `method`/`password`
become the `servers[0]` entry, the ShadowTLS outbound's `password` and `version`
become `shadowtlsSettings.password`/`version`, and its `tls.server_name` /
`tls.alpn` become `shadowtlsSettings.tls.serverName` / `tls.alpn`. The relay
host and port are the Shadowsocks `address`/`port` (in sing-box they sit on the
ShadowTLS outbound; here the single outbound owns them). `alpn` defaults to
`["h2", "http/1.1"]` when omitted; it is camouflage carried in the decoy
ClientHello only and never changes which protocol rides inside.

**Only version 3.** `version` other than `3` is rejected at parse time rather
than silently downgraded — v1/v2 are a different wire contract this client does
not speak. The carrier must be `raw`: there is no ClientHello fragmentation,
TCP finalmask or raw-HTTP camouflage underneath, because splitting or reshaping
the hello would break the relay's frame extraction and the data-stream HMAC.

**No share link.** There is no standard `shadowtls://` scheme — reference
clients configure it through sing-box JSON, Surge, or the CLI — so inventing one
would interoperate with nothing. ShadowTLS comes in through JSON only.

**Simplified client, still fails closed.** The client sends a genuine,
browser-shaped ClientHello carrying the keyed HMAC the relay checks, reads the
ServerHello for its random, and then speaks the HMAC-framed data stream; it does
not run a full TLS handshake with the decoy the way a stock client does, because
the relay switches to the real backend on the first client data frame whose HMAC
matches and never requires the decoy handshake to finish. A wrong password means
the relay never switches, so the first real frame fails its HMAC check and the
stream errors out — it does not fall back to an unauthenticated tunnel.

**Pinned by.** `zero-config` (the `shadowtls` security in `parse_stream` and the
`Security::ShadowTls` model with its Shadowsocks-only, raw-carrier validation)
and `zero-transport/src/shadowtls.rs` (the ClientHello HMAC, the ServerHello
random, and the data-stream framing), and `zero-runtime/tests/singbox_oracle.rs`,
which runs the client against a real sing-box ShadowTLS v3 relay (a megabyte
echoed intact, six concurrent streams, and a wrong password refused). That test
is opt-in (`--ignored`) and needs a `sing-box` binary.

## `tlssni` is a second fragment mode

`fragment.packets` also takes `tlssni`, next to `tlshello` and a write range. It
re-frames the first ClientHello into two valid TLS records with the cut inside
the server name (the middle of its second-level label), for a filter that puts
TCP segments back together but reads the name out of one TLS record. With no
delay set both records go in one write. Xray has no such mode, so a config using
it is Zray-only; a server sees an ordinary hello split across two records.

**Pinned by.** `zero-evasion/src/fragment.rs` (the cut lands inside the name, the
records rebuild the hello, anything that is not a ClientHello with a name passes
through) and `zero-runtime/tests/xray_oracle.rs`
(`vless_over_tls_with_a_hello_split_inside_the_name_matches_the_oracle`, an
Xray server accepting the split hello and carrying traffic; opt-in, needs `xray`).

## `dns.leakPolicy` is Zray's own key, and only a server can use it

**What differs.** Xray has no such key. Zray's DNS is strict by default: it
refuses to fall back to the operating system's resolver, because on a client
that resolver would answer outside the tunnel. A server is the opposite case:
the machine's own resolver is the one that is always reachable from its own
network, so the installer writes `"leakPolicy": "fallback"` into the server
configuration it generates.

**Guard.** `fallback` is honoured only when every outbound of the configuration
exits directly (`freedom` or `blackhole`). A configuration with any proxy
outbound is a client, and the key is ignored there, so a configuration or
subscription from outside cannot make a client leak its DNS. Any other value
means strict.

**Pinned by.** `zero-config` (`the_dns_leak_policy_is_strict_unless_a_server_says_otherwise`)
and the preset test that a built preset cannot produce `fallback`.

## The server installer (`zero-provision`)

The apps' "My server" page and `zray-setup` set up a stranger's VPS over SSH and
write a server configuration of the shape the engine itself reads:

- `VLESS + REALITY` (Vision, TCP) on `reality-in`, and optionally
  `VLESS + XHTTP + REALITY` on `xhttp-in` (own port, a random request path, no
  flow). Both use one key pair, short id and user list, and the first block of
  the configuration sends private networks (loopback, LAN, link-local, cloud
  metadata) to a black hole so a client cannot reach services that trust the
  server.
- `GET /usage` on the loopback management API reports, per inbound, sessions,
  distinct devices now and in the last five minutes, and byte totals. Devices
  are counted from a per-process salted hash that never leaves memory; no
  address or key is stored, logged or returned.

**Pinned by.** `zero-provision` (the generated configuration compiles in the
engine, the links parse with the apps' own parser), `zero-runtime`
(`usage_reports_counts_and_no_address`), and an installation checked end to end
against an Ubuntu 24.04 container with systemd: both inbounds installed, a
client connected through each link, usage counted on the right inbound, and
removal left the machine clean.

## Per-account figures and the account API

**What differs.** Xray serves `StatsService` and `HandlerService` over gRPC;
Zray serves the same operations over its own management API
(`zray run --management ADDR`), as JSON:

| Request | What it does |
|---|---|
| `GET /stats/traffic` | Also lists `user>>>{email}>>>traffic>>>uplink` / `downlink`, Xray's names, for every account with an `email`. `?reset=true` zeroes them as they are read and forgets accounts with no open session. |
| `GET /accounts/online` | The accounts with a session open now, with the number of sessions, and their addresses when the server was started with `--account-addresses`. |
| `POST /accounts/end` | `{"email": …}`: ends every open session of that account. |
| `POST /accounts/add` | `{"inbound": tag, "clients": [...]}`, each client in the inbound's `settings.clients` shape: adds them, or replaces the account with the same `email`. |
| `POST /accounts/remove` | `{"inbound": tag, "emails": [...]}`: removes them and ends their sessions on that inbound. |
| `POST /accounts/limit` | `{"email": …, "uplink": B/s, "downlink": B/s}`: a speed limit shared by all the account's sessions; 0 or absent lifts that direction. |
| `GET /accounts/limits` | The accounts with a speed limit. |
| `GET /events` | Server-sent events, one JSON object per `data:` line: sessions opened and closed, refused connections, account and limit changes, reloads and inbound changes (`zero_runtime::events`). |

The same operations are methods on `zero_runtime::Server` (`add_accounts`,
`remove_accounts`, `parse_account`, `stats.accounts`, `stats.events()`) for a
host that embeds the engine, and `zero_runtime::keys` makes the keys an
inbound needs (REALITY, ML-DSA-65, WireGuard, VLESS Encryption, UUIDs, short
ids), as `zray x25519` and its siblings print them.

Three behaviours go further than Xray's:

- **Bytes are counted while they move**, not when the connection closes, so a
  quota is enforceable against a single long download.
- **A removed account's sessions end.** Removing it (over the API or with a
  `/reload` that no longer lists it on that inbound) ends the sessions it
  already had there; in Xray they run on until they close. Replacing an
  account with a different credential does the same; re-adding it unchanged
  does not.
- **Adding or removing an account rebuilds nothing else.** Routing, DNS
  caches, TLS session caches and other sessions are untouched, where a
  `/reload` rebuilds them all.

Accounts can be changed at run time on `vless`, `vmess`, `trojan`,
`shadowsocks`, `hysteria2`, `tuic`, `anytls`, `zerov1` and `wireguard`
inbounds. An account without an
`email` (or, for Hysteria2, TUIC and AnyTLS, a sing-box `name`) is not
metered. One credential cannot belong to
two accounts on an inbound, since the handshake could not tell them apart.
Addresses are off by default, keeping the promise of `/usage` that no client
address is held; with `--account-addresses` only those of sessions open now
are, never a history.

A speed limit is one token bucket per account and direction, so more
connections do not buy more speed; at most one second's worth builds up.
Streams wait for it. A datagram (Hysteria2, TUIC and ZeroV1 UDP, WireGuard
packets) cannot wait or be split, so one over the limit is dropped and not
counted, the way a policer drops, and the sender's congestion control slows
down.

WireGuard peers with an `email` are metered by the addresses they own
(`allowedIPs`): a packet from a peer counts by its source, one to it by its
destination, IP headers included. A peer is an account in the shape of an
entry of `settings.peers`; adding or removing one changes the running
server's peers, and the peers that stay keep their tunnels. A named peer is
online, from the address it last sent from, while it has sent anything in the
last three minutes (a connected client rekeys every two); ending its session
drops its packets until it falls quiet. An inbound may start with
`"peers": []`.

A ZeroV1 (Tide) account is `{"id": …, "name": …}`: the id as a Tide key or a
UUID, whose 16 bytes are the key, and the name it is metered under. Its
streams are metered and its UDP flows held to its limit; a session spans
connections, so it has no client address. A removed user's open session
opens no more streams. Users from `usersFile` and the Tide panel stay as they
are.

Hysteria2 and TUIC log in once per QUIC connection, which outlives account
changes, so every stream and datagram is checked against the current
accounts: a removed account's connection opens nothing more.

**Pinned by.** `zero-runtime/src/accounts.rs` (live counting, reset, ending a
parked session, shared speed limits), the `api` tests `accounts_are_reported_and_their_sessions_ended`
and `accounts_are_added_and_removed_over_the_api`, and
`zero-runtime/tests/account_metering.rs`, which drives real VLESS, VMess and
Trojan inbounds: bytes visible before the session closes, a reload or a
removal ending the session, a re-added account connecting again with no
reload, and a shared credential refused; the same for multi-user
Shadowsocks (legacy and 2022), plus events and a speed limit on a real
session. `zero-runtime/tests/account_metering_tls.rs` does it for Hysteria2,
TUIC and AnyTLS, including a removed account refused on a QUIC connection
that is still up. `zero-runtime/tests/wireguard_inbound.rs`
(`peers_come_and_go_while_the_inbound_runs`) and
`zero-runtime/tests/loopback_tls_interop.rs`
(`tide_accounts_come_and_go_and_are_metered`) do it for WireGuard and ZeroV1
with real clients.

## Multi-user Shadowsocks

`settings.clients` on a Shadowsocks inbound, as in Xray:

- **Legacy AEAD** (`aes-*-gcm`, `chacha20-ietf-poly1305`): each client has a
  `password`; the method is the inbound's (or the first client's) and every
  client must share it. The server finds the user by trying each key on the
  first chunk, as Xray does, so the cost grows with the number of users.
- **Shadowsocks 2022** (`2022-blake3-aes-*-gcm`): `settings.password` is the
  server key and each client's `password` its own key; clients connect with
  `serverKey:userKey`, and the server reads which user it is from the identity
  header (SIP023). `2022-blake3-chacha20-poly1305` has no multi-user form.

An inbound given `settings.clients`, even an empty list, serves accounts
only: with none left it admits nobody, rather than falling back to
`settings.password`, which in 2022 every user's key also holds.

**Pinned by.** `zero-protocol` (`identify_user`,
`a_multi_user_server_knows_which_user_connected`) and
`zero-runtime/tests/account_metering.rs` (`an_emptied_multi_user_inbound_admits_nobody`).

## Changing inbounds without a restart

`zero_runtime::host::Host` runs a server through any configuration change.
When the new configuration only changes what `/reload` can, it reloads. When
it adds, removes or re-binds an inbound, or changes what a listener took when
it started (a QUIC certificate, Hysteria2 obfuscation, WireGuard peers, socket
options), it hands over: the listeners close, a successor server binds the
new ones and carries on the same figures, accounts, limits and event
subscribers. TCP sessions already open run on to their end; QUIC connections
of the inbounds close, since their socket must be released. A port the change
newly needs that is taken refuses the change before anything closes; a
successor that fails later is replaced by the previous configuration. `zray
run --management` serves through a host, so `POST /reload` can do all of this
and answers with `"applied": "reloaded"` or `"restarted"`.

Between the old listeners closing and the new ones binding, new connections
are refused for a moment.

**Pinned by.** `zero-runtime/tests/host_handover.rs`: an inbound added and
removed with an open session kept and the figures carried on, a reloadable
change staying a reload, both rollbacks, and the management API adding an
inbound.

## Legacy Shadowsocks salt length

The salt of `aes-128-gcm` is 16 bytes, as SIP004 has it (the salt is as long
as the key); `aes-256-gcm` and `chacha20-ietf-poly1305` keep 32. Zray used to
send and expect 32 for every method, which only worked between two Zray ends.

**Pinned by.** `zero-protocol` `the_salt_is_as_long_as_the_key`.

## Server inbounds with no account yet

A `settings.clients` (or `settings.users`) list that is present but empty is
accepted on every account-taking inbound, as a panel makes an inbound before
its users: it admits nobody until accounts are added. With neither the list
nor a single password the configuration is still refused.

**Pinned by.** `zero-config` `server_inbounds_may_start_without_accounts` and
`tls_inbounds_may_start_without_accounts`.

## Proxies from the environment

The `freedom` outbound honours `HTTPS_PROXY`/`HTTP_PROXY` (and `NO_PROXY`).
Whether the proxy itself is reached over TLS follows the value's scheme, as
everywhere else: `HTTPS_PROXY=http://127.0.0.1:10809`, the usual form, is a
plain HTTP proxy that HTTPS traffic is tunnelled through with `CONNECT`. It
used to be read as a TLS proxy because of the variable's name, and every
direct connection then failed.

Tests that dial names only the test knows (`app.test`) fail when such a
proxy is set, since the proxy cannot resolve them; run them without the
proxy variables.

**Pinned by.** `zero-runtime` `an_environment_proxy_speaks_tls_only_when_its_url_says_so`.
