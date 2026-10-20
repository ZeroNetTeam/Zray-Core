# REALITY Server — Parity Specification

This document specifies the REALITY **server**: the side an operator runs, and the
side an unmodified Xray client must be able to complete a handshake against. It is
the mirror of `docs/specs/REALITY-client.md` and is written the same way: for each
behavior, what the pinned Go implementation does, what the Rust port does, the
status of the port, and the differential test that proves it (or the test that
still has to be written).

Citations are relative to the repository that holds them:

| Tag | Path | What it is |
|-----|------|------------|
| **RL** | `Zray-Stuff/ZeroNetTeam/.research/xtls-reality/` | `github.com/xtls/reality` at `9234c772ba8f181f31c3e81dc2b4177322e5a9a9` (2026-03-22) — the Go fork of `crypto/tls` that *is* the REALITY server, and the revision Xray-core 26.3.27 pins |
| **XC** | `~/.cache/paru/clone/xray/src/Xray-core-26.3.27/` | Xray-core 26.3.27: the wiring that turns JSON into an **RL** config |
| **RB** | `Zray-Core/crates/reality/src/` | the Rust port: `server.rs` (the handshake), `keys.rs`, `config.rs` (the settings reader), `fallback.rs` (the relay, moved here but not yet wired into the runtime); its integration tests are `crates/reality/tests/{config,fallback}.rs` |
| **ZS** | `Zray-Core/crates/zero-security/src/tls13/` | the Rust TLS 1.3 substrate the REALITY server is built on (`record.rs`, `kdf.rs`, `client.rs` = the post-handshake stream) |
| **ZR** | `Zray-Core/crates/zero-runtime/src/` | where the port becomes an inbound: `server.rs` (wiring, fallback relay), `relay.rs`, `throttle.rs` |
| **ZC** | `Zray-Core/crates/zero-config/src/` | `realitySettings` parsing (`model.rs`, `xray_json.rs`) |
| **OR** | `Zray-Core/crates/zero-runtime/tests/xray_oracle.rs` | the differential harness against a real `xray` binary |

`/usr/bin/xray` on this machine is `Xray 26.3.27 (d2758a0, go1.26.1)`, i.e. exactly
the release that pins **RL** above, so a green oracle run is a real comparison and
not a guess about versions.

Status vocabulary, used per behaviour and never as a summary:

* **PORTED** — the Rust code does the same thing on the wire, and a differential
  test against the Xray binary exercises it.
* **PORTED-UNVERIFIED** — the code is there and agrees with the Go source by
  reading, but no test drives the difference against the oracle.
* **MISSING** — the Go behaviour has no Rust counterpart.
* **DIVERGENT** — the Rust code does something different, deliberately or not;
  the difference is named.

**Every divergence and gap in one place**, so an operator does not have to read the
whole document to find them. Each item is expanded, with its consequence, in the
section that names it.

### Closed since the first pass

Each of these was found by the first pass and is now implemented; the test named
is the one that fails without it.

| Item | What changed | Proof |
|---|---|---|
| Useless-record budget (§5) | Go's rule, a *consecutive* counter reset by any record that advances the stream, fatal past 32 | `zero-security/src/tls13/client.rs` (`MAX_USELESS_RECORDS`, `count_useless_record`) + `crates/zero-runtime/tests/xray_oracle.rs::an_idle_reality_flow_with_keepalive_probes_survives_the_servers_empty_record_limit` |
| SNI exactness (§1, §7) | `serverNames` is compared as sent, not case-folded | `crates/reality/src/server.rs` + `server::tests::a_server_name_in_another_case_is_not_the_advertised_one` and the oracle's `a_case_folded_server_name_is_not_the_advertised_one` |
| `supported_versions` (§1) | a hello that does not offer TLS 1.3 there takes the fallback path | `server::tests::a_hello_without_supported_versions_is_not_tls13_enough`, `every_official_client_hello_shape_still_offers_tls13` |
| Duplicate key share (§1) | the *first* share of a group wins, as both of Go's scans do | `server::tests::the_first_share_of_a_duplicated_group_is_the_one_that_counts` |
| Gate order (§1) | seal, then client version, then clock, then short id, in Go's order | `server::tests::a_hello_that_fails_several_gates_is_refused_for_go_s_first_one` |
| Cleartext record cap (§3) | 16384 + 2048 before the keys are negotiated, as `maxCiphertext` is | `zero-security/src/tls13/record.rs` (`MAX_CIPHERTEXT_BEFORE_TLS13`) + `server::tests::a_record_at_go_s_pre_negotiation_bound_is_read_then_relayed` and the oracle's `the_record_size_limit_is_the_oracles_at_the_edges` |
| `shortIds: []`, `mldsa65Seed == privateKey`, 1–3 part versions, bare-port and unix `dest` (§7) | the rules Xray's JSON layer enforces, in both readers | `crates/reality/tests/config.rs` (four parity tests) + `crates/reality/src/config.rs` unit tests |
| The fallback relay written twice (§6) | the runtime calls `reality::fallback::relay`; one implementation | `--test fallback` 8/8, `--test loopback_tls_interop` 26/26, `the_reality_server_limits_hold_against_the_oracles_client` |

What is *not* closed is what the rows below still say: the per-decoy
ChangeCipherSpec probe, the first-flight padding, the decoy being dialled on the
accepting path, and `type: unix`, `masterKeyLog` and `show`.

*MISSING (no Rust counterpart at all):*

* the consecutive-useless-record counter (Go's `maxUselessRecords = 32`) and the
  per-decoy budget learned by probing the site — `RL/common.go:70`,
  `RL/conn.go:827-839`, `RL/record_detect.go:137-185`, `RL/tls.go:425-427` (§5);
* `type`, and with it unix-socket `dest` and a bare-port `dest`
  (`XC/infra/conf/transport_internet.go:824-843`; both Rust readers go through
  `crates/zero-core/src/address.rs:173-186`) (§7);
* `masterKeyLog` for the REALITY handshake
  (`XC/transport/internet/reality/config.go:34`,
  `RL/handshake_server_tls13.go:884-893`; the port's key log is rustls-only,
  `crates/zero-security/src/tls.rs:607-631`) (§7);
* `show` diagnostics (`RL/tls.go:164-166`, `:238-256`) — parse-and-ignore (§7);
* `"shortIds": []` is refused by Xray (`XC/infra/conf/transport_internet.go:884-886`)
  and by `crates/reality/src/config.rs:144-150`, but accepted by the inbound path
  `crates/zero-config/src/xray_json.rs:907-930` (§7);
* `mldsa65Seed == privateKey` is refused by Xray
  (`XC/infra/conf/transport_internet.go:904-906`) and unchecked by both Rust
  readers (`crates/reality/src/config.rs:159-162`) (§7).

*DIVERGENT (present but different):*

* SNI matching is ASCII-case-insensitive — `crates/reality/src/server.rs:190-194`
  against `RL/tls.go:211` (§1);
* no `supported_versions` check — `crates/reality/src/server.rs:559-567` against
  `RL/tls.go:211` with `RL/handshake_server.go:180-196` (§1);
* the camouflage target is not dialled on the accepting path —
  `crates/reality/src/server.rs:144-258` against `RL/tls.go:168` (§1, §6);
* the cleartext-record cap is 16640 — `crates/zero-security/src/tls13/record.rs:74-79`
  against `RL/conn.go:707-711` with `RL/common.go:64-66` (§1);
* a duplicated key share: last wins — `crates/reality/src/server.rs:653-662` against
  `RL/tls.go:214-228` (§2);
* gate order: shortId before version and clock —
  `crates/reality/src/server.rs:232-251` against `RL/tls.go:257-262` (§2);
* cipher-suite choice follows the client, not the decoy or a server list —
  `crates/reality/src/server.rs:559-567`, `:675-700` against
  `RL/handshake_server_tls13.go:102` (§3);
* no padding of the first flight to the decoy's record lengths —
  `crates/reality/src/server.rs:716-748` against `RL/conn.go:526-557` (§3);
* the ML-DSA-65 extension uses OID 1.3 at a computed offset instead of Go's
  placeholder OID 0.0 at a fixed one — `crates/reality/src/server.rs:835-843`
  against `RL/handshake_server_tls13.go:82`; invisible to both clients (§3, §4);
* empty-record tolerance is 256, not 32-or-learned —
  `crates/zero-security/src/tls13/client.rs:838-846` against `RL/conn.go:803-811`,
  `:827-839` (§5);
* a session ticket or unknown post-handshake type from the peer is ignored, not
  alerted — `crates/zero-security/src/tls13/client.rs:925` against
  `RL/conn.go:1387-1398` (§5);
* a KeyUpdate body longer than one byte is accepted —
  `crates/zero-security/src/tls13/client.rs:905` against `RL/conn.go:1237-1238` (§5);
* a fallback session has a 300 s idle deadline where Go has none —
  `crates/zero-runtime/src/relay.rs:39`, `:47` against `RL/tls.go:271-286`, `:442` (§6);
* `burstBytesPerSec` below `bytesPerSec` is used as written instead of being raised —
  `crates/zero-runtime/src/throttle.rs:60-66`, documented at
  `crates/reality/src/fallback.rs:102-105`, against `RL/tls.go:127-130` (§6);
* a missing `dest`/`target` is accepted silently —
  `crates/zero-config/src/xray_json.rs:931-936` with
  `crates/zero-runtime/src/server.rs:2407-2415` against
  `XC/infra/conf/transport_internet.go:841-843` (§7);
* `minClientVer`/`maxClientVer` require three dotted parts —
  `crates/zero-config/src/xray_json.rs:951-968`, `crates/reality/src/config.rs:270-278`
  against `XC/infra/conf/transport_internet.go:856-883` (§7);
* both readers accept standard base64 as well as unpadded base64url for
  `privateKey` — `crates/zero-config/src/xray_json.rs:6581-6590` against
  `XC/infra/conf/transport_internet.go:850-855`: a superset, so no valid Xray config
  breaks (§7);
* the fallback relay exists twice, in `crates/reality/src/fallback.rs:26-46` (moved,
  with ten tests) and `crates/zero-runtime/src/server.rs:2395-2489` (what the runtime
  runs) — duplication to remove, not a difference in bytes (§6).

> The crate split matters for reading the rest: the server handshake now lives in
> `crates/reality/src/server.rs` (it was moved there out of
> `zero-security/src/tls13/server.rs`, which no longer exists), and it reaches the
> TLS 1.3 record layer in `zero-security` only through `Tls13Stream::new`
> (`ZS/client.rs:737-759`) and `queue_empty_records` (`ZS/client.rs:767-773`).

## 1. ClientHello intake

The server's first job is to decide, without ever telling the peer what it decided,
whether the first flight is a REALITY hello. Everything in this section is a gate
that leads to *the same visible outcome on failure*: the bytes go to the camouflage
site and the peer gets that site's answers (§6). There is no error record, no
alert, and no close — a REALITY server that answered differently on a bad tag would
be a REALITY oracle, which is the whole point of the design.

### What the official Go code does

`Server` dials `config.Dest` *before* it reads a byte (`RL/tls.go:168-172`) and
wraps the client socket in a `MirrorConn` whose `Read` forwards everything it
returns to the target (`RL/tls.go:64-82`). Its `Write` always fails
(`RL/tls.go:84-86`), which is the mechanism behind "never a wire error": any alert
REALITY's own TLS stack tries to emit while inspecting the hello cannot leave the
process. The hello is read in a goroutine, and the gate that decides the connection
is REALITY at all is one four-clause `break`:

```go
if copying || err != nil || hs.c.vers != VersionTLS13 || !config.ServerNames[hs.clientHello.serverName] {
    break
}
```

`RL/tls.go:207-213`. `err != nil` covers the entire reading path: an oversized
record (`alertRecordOverflow`, `RL/conn.go:707-711`), a non-ClientHello first
message (`RL/handshake_server.go:143-147`), a hello that negotiates no TLS 1.3
(`alertProtocolVersion`, `RL/handshake_server.go:192-196`). `copying` covers "the
target already spoke first", in which case the connection is already a plain pipe.

**Buffering limits.** One handshake message is reassembled from as many records as
it takes (`RL/conn.go:1145-1160`, buffering into `c.hand`), bounded by
`maxHandshake = 65536` (`RL/common.go:68`; 262144 for a server certificate message,
`RL/common.go:69`, which is a client-side limit). Per record the bound is
`maxCiphertextTLS13 = 16384 + 256` once TLS 1.3 is negotiated and
`maxCiphertext = 16384 + 2048` before that (`RL/common.go:64-66`, checked at
`RL/conn.go:707-711`) — so a ClientHello record is allowed to be up to 18432 wire
bytes, because at that moment `c.vers` is still unset. A zero-length handshake
record is refused (`RL/conn.go:817-820`) and, being an error, becomes a fallback.

**`legacy_session_id` layout.** The client writes it (`XC/transport/internet/reality/reality.go:141-148`):

```go
hello.SessionId = make([]byte, 32)
copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
hello.SessionId[0] = core.Version_x
hello.SessionId[1] = core.Version_y
hello.SessionId[2] = core.Version_z
hello.SessionId[3] = 0 // reserved
binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
copy(hello.SessionId[8:], config.ShortId)
```

and the server reads exactly that back after opening the seal (`RL/tls.go:249-251`):

```go
copy(hs.c.ClientVer[:], plainText)
hs.c.ClientTime = time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)
copy(hs.c.ClientShortId[:], plainText[8:])
```

So the plaintext is `[0..3]` client version, `[3]` reserved (must be zero on the
client side; the server never checks it), `[4..8]` big-endian Unix seconds,
`[8..16]` the 8-byte shortId selector, `[16..32]` zero padding that never reaches
the wire as plaintext because the GCM tag overwrites it (§2).

**The four allowlist/scalar rules**, all evaluated in one `&&` after a successful
open (`RL/tls.go:257-262`):

```go
if (config.MinClientVer == nil || Value(hs.c.ClientVer[:]...) >= Value(config.MinClientVer...)) &&
    (config.MaxClientVer == nil || Value(hs.c.ClientVer[:]...) <= Value(config.MaxClientVer...)) &&
    (config.MaxTimeDiff == 0 || time.Since(hs.c.ClientTime).Abs() <= config.MaxTimeDiff) &&
    (config.ShortIds[hs.c.ClientShortId]) {
    hs.c.conn = conn
}
```

* `minClientVer`/`maxClientVer` are compared as big-endian integers
  (`Value`, `RL/tls.go:153-158`) against three bytes Xray built from a dotted
  string, parts in order, missing parts left zero (`XC/infra/conf/transport_internet.go:856-883`).
  `nil` means "no gate at all".
* `maxTimeDiff` is *milliseconds in the JSON config* and an `RL` `time.Duration`
  (`XC/transport/internet/reality/config.go:29`: `time.Duration(c.MaxTimeDiff) * time.Millisecond`);
  the comparison is symmetric (`time.Since(...).Abs()`), and `0` disables it.
  Xray's default is 0, i.e. no clock check (`XC/infra/conf/transport_internet.go:901`).
* `serverNames` is an exact `map[string]bool` lookup, built one key per configured
  name (`XC/transport/internet/reality/config.go:50-53`).
* `shortIds` is a `map[[8]byte]bool` (`RL/tls.go:260`) built from hex strings:
  `make([]byte, 8)` then `hex.Decode` — left-aligned, zero-padded on the right
  (`XC/infra/conf/transport_internet.go:884-896`), and re-typed as `[8]byte` per
  entry (`XC/transport/internet/reality/config.go:54-57`). There is no wildcard and
  no prefix match, so `""` selects the all-zero selector and `"ab"` is the same
  selector as `"ab000000000000"`.

Failure of any of the four leaves `hs.c.conn != conn`, which is the only thing the
rest of `Server` tests. The goroutine that read the hello falls into
`io.Copy(target, NewRatelimitedConn(underlying, &config.LimitFallbackUpload))`
(`RL/tls.go:271-286`) and the other goroutine forwards the target's bytes back
(`RL/tls.go:441-446`): the peer's session simply continues against the real site.
`Server` then returns an error to its caller (`RL/tls.go:456-475`) — that is for
Xray's log, not for the wire; the socket is already a pipe.

### What the Rust code does

`handshake_or_fallback` (`RB/server.rs:159-258`) reads the hello itself and never
dials anything before it decides (`RB/server.rs:166-179`). Intake is
`read_client_hello_record` (`RB/server.rs:468-525`): it consumes records until one
handshake message is complete, accumulating the record bytes in `record` (which is
what a fallback replays) and the message bytes in `message`. A record whose type is
not `handshake`, or whose header does not parse, returns
`ClientHelloRead::NotTls { consumed, failure }` and the consumed bytes are replayed
verbatim (`RB/server.rs:480-494`); a zero-length handshake record does the same
(`RB/server.rs:501-507`). The message-size bound is `MAX_CLIENT_HELLO = 65536`
(`RB/server.rs:456`, enforced at `RB/server.rs:513-518`), and the per-record bound
is `MAX_CIPHERTEXT = 16384 + 256` in `parse_header` (`ZS/record.rs:74-79`).

`parse_client_hello` (`RB/server.rs:527-609`) then reads `random` at offset 6, the
session id at 38/39 — requiring exactly 32 bytes (`RB/server.rs:548-550`), which is
REALITY's own requirement, not TLS's — the cipher-suite list, and only two
extensions: SNI (0) and key_share (51) (`RB/server.rs:591-598`). The version, clock
and shortId rules are `check_client_limits` (`RB/server.rs:263-290`) and the
constant-time shortId fold (`RB/server.rs:232-244`), both covered in §2.

Every rejection above is `HandshakeOutcome::Fallback` (`RB/server.rs:172-251`);
only an I/O failure while reading is `Rejected` (`RB/server.rs:178`), and that is
also how a peer that vanishes mid-hello is handled. The runtime turns `Fallback`
into `Secured::Fallback` (`ZR/server.rs:2375-2383`) and calls
`relay_reality_fallback` (`ZR/server.rs:2395-2489`), which is §6.

**Status: PORTED**, with four named differences:

1. **SNI comparison is a superset.** Rust matches with
   `name.eq_ignore_ascii_case(&hello.sni)` (`RB/server.rs:190-194`) where Go does an
   exact map lookup (`RL/tls.go:211`). A config listing `www.example.com` therefore
   also accepts `WWW.EXAMPLE.COM`. Harmless in practice (the selector that matters
   is the sealed shortId) but it is a real difference in the accepted set.
2. **No `supported_versions` check.** The Rust port never reads the extension; it
   infers TLS 1.3 from finding a cipher suite it knows in the offered list
   (`RB/server.rs:559-567`). Go requires `c.vers == VersionTLS13` from
   `mutualVersion` (`RL/tls.go:211` with `RL/handshake_server.go:180-196`). A peer
   offering `TLS_AES_128_GCM_SHA256` without `supported_versions: 0x0304` is
   authenticated by Rust and handed to the decoy by Go.
3. **The decoy is not dialled on this path.** `RL/tls.go:168` dials `dest` for every
   connection, authenticated or not; the Rust intake reaches
   `HandshakeOutcome::Accepted` without ever touching the target. The consequences
   are spelled out in §3 (record shaping) and §6 (what a prober sees).
4. **Per-record bound before version negotiation.** Rust applies 16640
   (`ZS/record.rs:75`) where Go allows 18432 until the version is known
   (`RL/conn.go:707`). Both bounds end in a fallback for anything larger, so the
   only visible difference is where the refusal happens.

**Proved by.** `OR:1177-1187` (`vless_over_reality_raw_tcp_matches_the_oracle`) runs
both mixed directions over a real Xray REALITY server and asserts payload came
*back* through the tunnel, which is the only assertion that can distinguish "the
tag was where Go expects it" from "the connection was quietly relayed to the decoy"
(`OR:631-638`). `OR:1214-1301`
(`a_wrong_reality_public_key_is_refused_rather_than_silently_relayed`) pins the
failure direction from the client side, and `OR:2132-2154`
(`the_reality_server_limits_hold_against_the_oracles_client`) drives an Xray client
past `minClientVer`/`maxClientVer` and asserts it is *not* let through
(`OR:819-849`) while a config inside the limits is (`OR:2137-2146`). The gates that
have no differential test are the record-size bound and the SNI case rule: both are
unit-level only (`RB/server.rs:1251-1259` for shortIds, `RB/server.rs:1264-1273`
for a non-TLS first record).

**Still worth a test.** A hello naming an SNI outside `serverNames` — Zray's own
client cannot produce one, so this needs a raw socket: write a syntactically valid
ClientHello with the wrong SNI at a Zray REALITY inbound and assert the *decoy*
answered (the same shape as `OR:819-849`), then repeat it with the right SNI, a
wrong shortId, and a clock outside `maxTimeDiff`. Nothing in the suite currently
proves that a Zray REALITY inbound falls back rather than closing, for the SNI and
clock cases.

## 2. Authentication

This is the one part of the server that is genuinely REALITY and not TLS: the
client's ephemeral key share and the static key in the server's config produce a
secret; that secret, keyed through HKDF with material from the ClientHello, opens
the sealed session id. Everything the four gates of §1 look at comes out of that
open. A server that gets any of it wrong does not fail loudly — it falls back —
which is why the oracle test asserts payload came back rather than that the socket
opened.

### What the official Go code does

**Key share selection.** At the pinned revision, the *standalone* `x25519` share is
the primary choice and the hybrid is the fallback, in that order
(`RL/tls.go:214-228`):

```go
var peerPub []byte
for _, keyShare := range hs.clientHello.keyShares {
    if keyShare.group == X25519 && len(keyShare.data) == 32 {
        peerPub = keyShare.data
        break
    }
}
if peerPub == nil {
    for _, keyShare := range hs.clientHello.keyShares {
        if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
            peerPub = keyShare.data[mlkem.EncapsulationKeySize768:]
            break
        }
    }
}
```

`mlkem.EncapsulationKeySize768` is 1184, so the hybrid branch accepts exactly
1184 + 32 = 1216 bytes and authenticates against the **last 32 bytes** — the X25519
half of the share, not the ML-KEM encapsulation key. Note what this revision does
*not* have: there is no "exactly one share of each group" rule and no ordering
requirement (both arrived later; the client spec's §4 checklist describes a newer
server). If no share matches, `peerPub` stays `nil` and the `for peerPub != nil`
loop at `RL/tls.go:229` never runs — no decryption attempt, straight to fallback.

**ECDH and the auth key** (`RL/tls.go:230-237`):

```go
if hs.c.AuthKey, err = curve25519.X25519(config.PrivateKey, peerPub); err != nil {
    break
}
if _, err = hkdf.New(sha256.New, hs.c.AuthKey, hs.clientHello.random[:20], []byte("REALITY")).Read(hs.c.AuthKey); err != nil {
    break
}
block, _ := aes.NewCipher(hs.c.AuthKey)
aead, _ := cipher.NewGCM(block)
```

* `curve25519.X25519` is a thin wrapper over `crypto/ecdh` in this family of
  `x/crypto` releases (v0.49 and v0.57 were read locally; `RL/go.mod:10` pins
  v0.48): X25519 scalars are clamped per RFC 7748, and a share that is a low-order
  point makes `ECDH` fail ("bad X25519 remote ECDH input: low order point"), so a
  degenerate share falls back instead of authenticating anything.
* HKDF is **SHA-256** for both extract and expand, `salt = client_random[0:20]`,
  `info = "REALITY"` (7 ASCII bytes), output 32 bytes, read into the same slot —
  so `AuthKey` is the OKM, and it is still 32 bytes for `aes.NewCipher`.
* With a 32-byte key, `cipher.NewGCM` over `aes.Block` is **AES-256-GCM**, a
  12-byte nonce and a 16-byte tag: a 16-byte plaintext seals to exactly the 32
  bytes of `legacy_session_id`.

**Opening the seal** (`RL/tls.go:241-247`):

```go
ciphertext := make([]byte, 32)
plainText := make([]byte, 32)
copy(ciphertext, hs.clientHello.sessionId)
copy(hs.clientHello.sessionId, plainText) // hs.clientHello.sessionId points to hs.clientHello.raw[39:]
if _, err = aead.Open(plainText[:0], hs.clientHello.random[20:], ciphertext, hs.clientHello.original); err != nil {
    break
}
copy(hs.clientHello.sessionId, ciphertext)
```

The line to read twice is the second `copy`: `hs.clientHello.sessionId` is a
cryptobyte subslice of `hs.clientHello.original` at offset 39, so zeroing it mutates
the buffer that is about to be used as **AAD**. That is not a bug — it is the
contract: the client computed the same tag over its own hello with the session id
zeroed (`XC/transport/internet/reality/reality.go:141-142`, `:174-175`), and the
addition is over `AAD = ClientHello message with bytes 39..71 zeroed`,
`nonce = client_random[20:32]`, `ciphertext = the 32 bytes that arrived`.
`cipher.GCM.Open` performs the tag comparison in constant time; the copy back
restores the wire bytes so the transcript of §3 hashes what really arrived.

**Decision order.** `RL/tls.go:211` (SNI, TLS version) → key share → ECDH → HKDF →
GCM open → `minClientVer` → `maxClientVer` → `maxTimeDiff` → `shortIds`
(`RL/tls.go:257-262`). Only the first two can be decided before any crypto, and all
of them fail into the same silent fallback. The shortId comparison is a Go map
lookup on `[8]byte` (`RL/tls.go:260`) — the *tag* is the primary gate, so the Go
implementation does not treat the selector as needing a constant-time compare.

### What the Rust code does

The same five steps, in `RB/server.rs`:

* key shares — `parse_key_shares` (`RB/server.rs:637-673`) recognises `0x001d` with
  32 bytes as the standalone share and `0x11ec` with 1216 bytes as the hybrid,
  splitting the hybrid into `mlkem_key: share[..1184]` and
  `x25519: share[1184..]` (`RB/server.rs:655-662`), then falls back to the
  hybrid's X25519 half when there is no standalone share ("secondary choice: X25519
  in X25519MLKEM768", `RB/server.rs:665-671`). A hello with neither is a fallback
  (`RB/server.rs:603-604`).
* ECDH — `x25519_dalek::x25519(params.private_key, hello.auth_key_share)`
  (`RB/server.rs:202`), with the all-zero shared secret made an explicit fallback
  (`RB/server.rs:203-209`) rather than left to fail later in the AEAD.
* HKDF — `derive_auth_key(&shared, &hello.random[..20])` (`RB/server.rs:210`), which
  is `hkdf::Hkdf::<Sha256>::new(Some(salt), shared)` + `expand(b"REALITY", …)`
  into 32 bytes (`RB/server.rs:406-411`).
* GCM open — `zero_session_id(&hello.message)` builds the AAD by copying the
  message and filling `[39..71]` with zeros (`RB/server.rs:446-453`), then
  `decrypt_session_id(&auth_key, &hello.random[20..], &hello.session_id, &aad)`
  opens it with `Aes256Gcm` and returns the 16-byte plaintext
  (`RB/server.rs:221-231`, `RB/server.rs:413-432`). Unlike Go, the wire message is
  never mutated: the AAD is a copy, which is why `RB/server.rs:341-342` can hash
  `hello.message` unchanged into the transcript of §3.
* the four gates — `check_client_limits` (`RB/server.rs:263-290`) for version
  (big-endian byte order compare on `[u8; 3]`) and clock (seconds, symmetric
  difference, skipped when `max_time_diff` is zero), and the shortId fold
  (`RB/server.rs:232-244`).

**Constant-time comparisons.** The tag comparison is inside `aes-gcm`'s `decrypt`,
and the port adds two constant-time compares the Go code does not make: the shortId
selector (`short_id_matches`, `RB/server.rs:436-444`, folded over every configured
id with `Choice` and no early exit, `RB/server.rs:232-237`) and the client Finished
(`RB/server.rs:386`). The Rust docstring states the reason plainly — "anyone with
the public key can produce a valid seal", so the selector is the secret being
compared (`RB/server.rs:232-234`). This is a hardening of the same decision, not a
change to it: both implementations accept exactly the selectors configured, and
`RB/server.rs:1251-1259` (`short_id_matching_is_exact_and_zero_padded`) pins the
zero-padding rule that makes `"ab"` and `"ab000000000000"` one selector and `""`
the all-zero one.

**Status: PORTED**, with two differences worth naming:

1. **Duplicate key shares: first wins in Go, last wins in Rust.** Both loops in
   `RL/tls.go:214-228` `break` on the first acceptable share; `parse_key_shares`
   assigns on every match, so the *last* standalone share (and the last hybrid) is
   the one used (`RB/server.rs:653-662`). RFC 8446 §4.2.8 forbids offering a group
   twice, so no honest client can reach the difference, but a probe could: the two
   implementations would authenticate against different points and only one would
   accept.
2. **Order and explicitness of the gates.** Rust checks the shortId *before* the
   version and clock (`RB/server.rs:232-251`); Go checks version and clock first
   (`RL/tls.go:257-259`). It also refuses a session id that is not exactly 32 bytes
   at parse time (`RB/server.rs:548-550`) where Go would try to open a
   zero-filled 32-byte buffer — same outcome (fallback), clearer reason.
   Because every failure is silent, the difference is observable only in timing and
   in the server's own logs.

**Proved by.** `OR:1177-1187` and `OR:2115-2125`
(`reality_with_the_mldsa65_binding_matches_the_oracle`) drive an unmodified Xray
client through a Zray REALITY server and back; the tag is the only thing that can
make that succeed, since a wrong tag means the connection is handed to the decoy
and the assertion is on returned payload, not on the socket. The negative direction
is `OR:1214-1301`: a Zray client pointed at an Xray REALITY server with a public key
the server does not hold must *not* get a round trip. Purely local coverage of the
same decision: `RB/server.rs:959-1001` (round trip through the Rust server),
`RB/server.rs:1233-1248` (an unauthorised shortId falls back, and a *prefix* of a
configured selector must not authorise), `RB/server.rs:1251-1259` (selector shape).

**Not covered by a test.** No test feeds the server a hello whose key share is
deliberately degenerate (all-zero X25519), or one carrying two `x25519` shares, so
the Rust-side check at `RB/server.rs:203-209` and the first/last divergence above
are read from the source rather than exercised.


## 3. ServerHello + certificate substitute

An authenticated connection gets a genuine TLS 1.3 handshake from REALITY — real
ephemeral ECDHE, real HKDF key schedule, real Finished — and one lie: the leaf
certificate is a per-process self-signed Ed25519 object whose *signature field* is
an HMAC only the client and the server can compute. Everything else is arranged to
look like the camouflage site's handshake, including, in Go, the exact record sizes
the site sent.

### What the official Go code does

**The ServerHello is the decoy's, with the key share rewritten in place.** The
target's ServerHello is parsed from the mirrored bytes (`RL/tls.go:353-362`) and
validated: it must unmarshal, be legacy version `0x0303`, negotiate `0x0304`, use a
known TLS 1.3 suite, and carry an `x25519` (32-byte) or `X25519MLKEM768`
(1088 + 32-byte) share. Then `handshake()` takes over
(`RL/handshake_server_tls13.go:101-132`):

```go
hs.suite = cipherSuiteTLS13ByID(hs.hello.cipherSuite)
...
key, _ := generateECDHEKey(c.config.rand(), X25519)
copy(hs.hello.serverShare.data, key.PublicKey().Bytes())
peerKey, _ := key.Curve().NewPublicKey(peerPub)
hs.sharedKey, _ = key.ECDH(peerKey)

if hs.hello.serverShare.group == X25519MLKEM768 {
    k, _ := mlkem.NewEncapsulationKey768(peerData[:mlkem.EncapsulationKeySize768])
    mlkemSharedSecret, ciphertext := k.Encapsulate()
    hs.sharedKey = append(mlkemSharedSecret, hs.sharedKey...)
    copy(hs.hello.serverShare.data, append(ciphertext, hs.hello.serverShare.data[:32]...))
}
```

`hs.hello.serverShare.data` is a slice *into* `hs.hello.original`, the wire buffer,
so this `copy` rewrites the ServerHello in place: same length, same random, same
session-id echo, same extensions, new ephemeral key. For the hybrid group the
X25519 half is appended after the 1088-byte ML-KEM ciphertext, and the shared secret
is `mlkemSharedSecret || x25519SharedSecret` — the concatenation order is
load-bearing and must match the client's.

* **Cipher suite**: the suite is whatever the *decoy* chose, not what REALITY would
  prefer (`RL/handshake_server_tls13.go:102`). The client's own preferences only
  mattered as far as they were acceptable to the decoy.
* **Ephemeral key**: one fresh X25519 key per connection from `config.rand()`
  (`:119`), plus a fresh ML-KEM encapsulation when the target selected the hybrid
  (`:126`).
* **Key schedule** (RFC 8446 §7.1, in `RL`'s fork):
  `hs.handshakeSecret = earlySecret.HandshakeSecret(hs.sharedKey)`
  (`:869`), then `ClientHandshakeTrafficSecret` / `ServerHandshakeTrafficSecret`
  from the transcript through ServerHello (`:871-874`), the server Finished
  (`:1004-1013`), then the master secret and both application secrets
  (`:1017-1021`). The transcript is `hash(ClientHello || ServerHello)`
  (`:855`), where the ClientHello is the message with its *sealed* session id —
  `hs.clientHello.original` was restored after the `Open` of §2
  (`RL/tls.go:248`).
* **Finished**: `hs.suite.finishedHash(c.out.trafficSecret, hs.transcript)`
  (`:1008`), i.e. HMAC over the transcript hash with the handshake traffic secret.

**The certificate substitute** (`RL/handshake_server_tls13.go:80-86`, `:141-165`).
Once per process, `init()` builds an Ed25519 key and two self-signed certificates
with `SerialNumber: &big.Int{}` — the second one carrying a single extension whose
value is a 3309-byte placeholder (`ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: empty[:3309]}}`),
the ML-DSA-65 signature size. Per connection:

```go
var cert []byte
if len(c.config.Mldsa65Key) > 0 {
    cert = bytes.Clone(signedCertMldsa65)
} else {
    cert = bytes.Clone(signedCert)
}

h := hmac.New(sha512.New, c.AuthKey)
h.Write(ed25519Priv[32:])
h.Sum(cert[:len(cert)-64])
```

`h.Sum(cert[:len(cert)-64])` appends the HMAC-SHA512 tag into the DER's final 64
bytes — exactly the `signatureValue` octets of the certificate's own Ed25519
signature — so the certificate stays structurally valid DER (Xray's Go parser must
be able to parse it, `:824-826` in the port says the same thing) while its
signature is replaced by `HMAC-SHA512(AuthKey, ed25519_public_key)`. The client
checks exactly that (`XC/transport/internet/reality/reality.go:84-87`), which is why
§2's AuthKey has to be identical on both sides.

**CertificateVerify** is emitted normally and is a *real* Ed25519 signature by the
same key whose public key is inside the certificate
(`RL/handshake_server_tls13.go:970-999`): input
`0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash`.
It never has to verify for a REALITY client — Xray sets `InsecureSkipVerify: true`
and does REALITY's own check in `VerifyPeerCertificate`
(`XC/transport/internet/reality/reality.go:76-115`, `:125`) — it exists so the flight
looks like a browser-trusting handshake to anything that is not the client.

**The record-length rule.** REALITY's own records are padded to the lengths the
decoy used for the same message types. The target's flight is parsed record by
record while it is being relayed, and each record's *wire length* is remembered per
message type (`RL/tls.go:315-366`): `handshakeLen = recordHeaderLen + Value(s2cSaved[3:5]...)`
(`:329`), with structural checks — the ChangeCipherSpec record must be exactly 6
bytes (`:337-339`), the target's ServerHello must parse and be TLS 1.3
(`:353-361`), an EncryptedExtensions record longer than 512 bytes is accepted on its
length alone (`:340-344`), a session-ticket record likewise (`:345-348`). Those
lengths are then applied when REALITY writes its own handshake records
(`RL/conn.go:526-557`):

```go
padding := 0
if recordType(record[0]) == recordTypeHandshake && hc.handshakeLen[1] != 0 {
    switch payload[0] {
    case typeEncryptedExtensions:
        padding = hc.handshakeLen[2]
        hc.handshakeLen[2] = 0
    case typeCertificate:
        padding = hc.handshakeLen[3]
        ...
    case typeNewSessionTicket:
        padding = hc.handshakeLen[6]
        hc.handshakeLen[6] = 0
        record[5] = byte(recordTypeApplicationData)
        record[6] = 0
    }
    padding -= len(record) + c.Overhead()
    if padding < 0 {
        return nil, fmt.Errorf("payload[0]: %v, padding: %v", payload[0], padding)
    }
    record = append(record, empty[:padding]...)
}
```

Three consequences, all verified in the Go source:

1. Padding is only applied when the decoy sent a CCS record at all — the guard is
   `hc.handshakeLen[1] != 0`, and index 1 is CCS. A TLS 1.3 decoy always sends one,
   so in practice the rule always applies.
2. The ServerHello record is written *before* the handshake traffic secret exists
   (`RL/handshake_server_tls13.go:854-874`), so `hc.encrypt` returns the payload
   untouched (`RL/conn.go:487-490`) and the ServerHello keeps the decoy's own size.
   Everything after CCS is padded: EncryptedExtensions, Certificate,
   CertificateVerify, Finished, and the session-ticket mimic.
3. **A decoy whose Certificate record is smaller than REALITY's own breaks the
   handshake**: `padding` goes negative and the record never gets written, so
   `handshake()` fails, the connection is closed, and the server returns
   `REALITY: processed invalid connection from …` (`RL/tls.go:372-374`, `:456-475`)
   — note this is *after* authentication succeeded, so it is a hard failure, not a
   fallback. REALITY's own certificate is a fixed size per process: a few hundred
   bytes of DER for the plain Ed25519 wrapper built at
   `RL/handshake_server_tls13.go:81-85`, and about 3.5 KB once the 3309-byte ML-DSA-65
   placeholder is in the extensions (the figure the oracle harness records at
   `OR:39-42`). The same rule with the same consequence applies to the
   EncryptedExtensions / CertificateVerify / Finished records, which is why that
   same fixture uses an almost 5 KB decoy certificate for the ML-DSA-65 test
   (`OR:652-661`).

Post-handshake, the same idea continues: if the decoy sent session tickets, the
server writes a one-byte NewSessionTicket fragment that the record layer pads to
the decoy's record length and rewrites into an empty application-data record
(`RL/handshake_server_tls13.go:176-180`; `RL/conn.go:546-556`, which sets the
plaintext's content-type byte to `0x17` and the trailing inner type to 0 so the
peer's backward scan finds `0x17` — an empty app-data record of the decoy's size).
Xray disables real tickets outright (`SessionTicketsDisabled: true`,
`XC/transport/internet/reality/config.go:32`), and resumption is compiled out of
the fork (`RL/handshake_server_tls13.go:133-140`), so a REALITY connection never
resumes and never has to send a real ticket.

### What the Rust code does

The port builds its own ServerHello instead of borrowing the decoy's
(`build_server_hello`, `RB/server.rs:675-700`): legacy version `0x0303`, 32 fresh
random bytes, a 32-byte session-id echo, the suite chosen at intake, compression 0,
and exactly two extensions — `supported_versions` (`0x0304`) and `key_share`. It is
written as a cleartext handshake record of its own size (`RB/server.rs:338-339`,
`write_clear_record` at `:702-714`), then the dummy CCS and the whole encrypted
flight go out in a single write (`RB/server.rs:367-377`), which is the same record
sequence a real server produces (`RB/server.rs:1129-1164` asserts
`ServerHello, CCS, application-data` on the wire).

* **Ephemeral key**: 32 bytes of `OsRng` per connection (`RB/server.rs:302-306`);
  for a hybrid share, ML-KEM-768 encapsulation against the client's key, with
  `share = mlkem_ciphertext || server_x25519_public` and
  `shared = mlkem_shared || x25519_shared` (`RB/server.rs:307-331`) — the same
  concatenation order as Go. The group in the ServerHello is derived from the share
  length (1088 + 32 ⇒ `0x11ec`, otherwise `0x001d`, `RB/server.rs:333-337`).
* **Cipher suite**: the first suite in the client's list that
  `CipherSuite::by_id` knows (`RB/server.rs:559-567`) — client preference, not the
  decoy's choice and not a server preference list. See the divergences below.
* **Key schedule**: `Transcript::new` → ClientHello → ServerHello
  (`RB/server.rs:341-343`), then `establish_handshake_secrets` (`:344-345`) and,
  after the server Finished, `establish_application_secrets` (`:393`); the Finished
  verify_data is `finished_verify_data(suite.hash, secret, transcript)`
  (`:743-746` for the server, `:381-385` for the client's). Both interop
  directions pass, so the schedule agrees with Go's byte for byte; the
  implementations are in `ZS/kdf.rs` (`establish_handshake_secrets`,
  `establish_application_secrets`, `finished_verify_data`).
* **The certificate substitute**: `reality_certificate` (`RB/server.rs:804-862`)
  builds the DER from scratch every handshake — version, serial, a CN from the SNI,
  fixed validity, an Ed25519 SPKI for a fresh per-connection signing key
  (`:348-351`), and, as the last field of the outer SEQUENCE, the
  HMAC-SHA512 tag over the public key (`:857-861`). It is deliberately shaped like
  a real certificate because Go's parser has to accept it.
* **CertificateVerify**: input built the same way (`certificate_verify_input`,
  `RB/server.rs:894-901`), signed with the per-connection Ed25519 key, algorithm
  `0x0807` (Ed25519) and a 64-byte signature (`:734-742`).
* **Post-handshake shapes**: the server sends empty records of the sizes the site
  sends, learned at startup by `zero_security::tls13::post_handshake::observe`
  (`ZS/post_handshake.rs:161-178`, called from `ZR/server.rs:8956-9008`, storing into
  `PostHandshakeShapes`) and replayed by `queue_empty_records`
  (`RB/server.rs:395-402`, `ZS/client.rs:767-773`, `ZS/record.rs:237-260`). The
  generated bytes are the same trick as Go's: inner type `0x17` followed by zero
  padding, so the peer's backward scan finds `0x17` and reads an empty app-data
  record of exactly the learned size.

**Status: DIVERGENT** on the wire shape, **PORTED** on the crypto. The handshake
completes against real Xray clients in both directions, so every secret and every
hash is right; what differs is what an observer comparing the connection to the real
site would see:

1. **No decoy ServerHello.** Rust's ServerHello is generated locally, so it carries
   Go's two extensions rather than the decoy's extension set, its own random, and
   the suite this port chose. A decoy that sends anything else in its ServerHello
   (a cookie, ECH keys, its own extension order) is not mirrored.
2. **Cipher-suite choice is the client's, not the decoy's.** Go takes the decoy's
   suite outright (`RL/handshake_server_tls13.go:102`), and the decoy picked it from
   its own preference list — for Go's TLS 1.3 defaults,
   `TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256`
   (`RL/defaults.go:107-111`), with the ChaCha-first list when the client's own order
   says so (`isAESGCMPreferred`, `RL/cipher_suites.go:390-403`). Rust takes the
   client's first known suite (`RB/server.rs:559-567`). Chrome-style clients offer
   `0x1301, 0x1302, 0x1303` and both rules land on `0x1301`, so the common case
   agrees; a client offering `0x1302` before `0x1301` gets `0x1302` from Rust and
   `0x1301` from Go.
3. **No first-flight record padding.** `build_encrypted_flight`
   (`RB/server.rs:716-748`) seals the four messages back to back with no padding,
   so the record sizes are REALITY's own, not the decoy's. The mechanism of
   `RL/conn.go:526-557` has no counterpart; the port replays the decoy's
   post-handshake record *sizes* only (`RB/server.rs:395-402`). This is the largest
   remaining fingerprinting gap: an observer who compares the byte lengths of the
   first flight against the real site sees different sizes, and the port cannot be
   hurt by a small decoy certificate the way Go can (see point 5).
4. **The ML-DSA extension's OID differs.** Go uses the placeholder OID `0.0` with a
   fixed 3309-byte value at `cert[126:]` (`RL/handshake_server_tls13.go:82`, `:157`);
   Rust emits OID `1.3` (`06 01 2b`, `RB/server.rs:835-842`). Both clients read the
   *first extension's value*, never the OID
   (`XC/transport/internet/reality/reality.go:92-93`, `ZS/reality.rs:334-339`), so
   the difference is invisible to them.
5. **A negative padding can abort an authenticated connection in Go and cannot in
   Rust.** This is the flip side of point 3 and worth stating explicitly for the
   operator: with a decoy whose certificate record is smaller than REALITY's own,
   the Go server closes an *authenticated* connection with `padding: -N`
   (`RL/conn.go:553-555`) while the Rust server completes it — and then differs from
   the decoy site in size instead. Neither behaviour is "more correct"; they are
   different failure modes and the operator should choose a decoy with a
   certificate at least as large as REALITY's (the oracle fixtures do: `OR:39-42`).

**Proved by.** Both mixed directions in `OR:1177-1187` (plain REALITY), and
`OR:2115-2125` (REALITY with the ML-DSA-65 certificate, i.e. the ~3.5 KB shape and
the extension) — an Xray client accepting a Rust server's ServerHello, certificate
substitute and Finished is the assertion, and it fails if any of the three is
shaped differently enough to be rejected. Locally:
`RB/server.rs:959-1001` (application data round trip through the Rust server) and
`RB/server.rs:1129-1164` (the record sequence `ServerHello, CCS, encrypted flight`
in both directions).

**Still unproven.** Nothing in the suite measures the *record sizes* of the Rust
server's first flight against the decoy's, so point 3 is documented from reading
both implementations rather than caught by a test. A test that would catch it is a
raw-socket client that records the wire lengths of the first flight of an Xray
REALITY server and of a Zray one behind the same decoy and compares them; the
harness already has the pieces (`spawn_decoy`, `OR:520-550`, and the record walker in
`ZS/post_handshake.rs:44-73`).

## 4. ML-DSA-65 binding

The HMAC in the certificate (§3) proves the peer holds the auth key derived from
the *public* key a client was configured with. That is a shared secret: an operator
who obtained a working share link knows it, and so does anyone who ever saw the
server's `privateKey`. `mldsa65Seed` closes that hole from the server side — the
server signs each handshake with a post-quantum key it holds, and a client that
pins `mldsa65Verify` can tell the real server from one that merely knows the X25519
key.

### What the official Go code does

**Seed to key.** Xray turns the 32-byte `mldsa65Seed` into a private key at config
build time: `_, key := mldsa65.NewKeyFromSeed((*[32]byte)(c.Mldsa65Seed))` and
`config.Mldsa65Key = key.Bytes()` (`XC/transport/internet/reality/config.go:36-39`).
The JSON field is unpadded base64url and must be 32 bytes
(`XC/infra/conf/transport_internet.go:903-910`), and it must not be the same value
as `privateKey` (`:904-906`) — the whole point is that it is a *different* secret.
Doing the expansion once at config time is why the handshake path here never pays
`ExpandA`: the seed is expanded once per process, not once per connection.

**What is signed.** After the certificate's own signature field has been replaced by
the §3 HMAC, the *same* HMAC state is continued with both hello messages, and the
result is signed (`RL/handshake_server_tls13.go:149-158`):

```go
h := hmac.New(sha512.New, c.AuthKey)
h.Write(ed25519Priv[32:])
h.Sum(cert[:len(cert)-64])          // §3: the HMAC replaces the cert signature

if len(c.config.Mldsa65Key) > 0 {
    h.Write(hs.clientHello.original)
    h.Write(hs.hello.original)
    key, _ := mldsa65.Scheme().UnmarshalBinaryPrivateKey(c.config.Mldsa65Key)
    mldsa65.SignTo(key.(*mldsa65.PrivateKey), h.Sum(nil), nil, false, cert[126:]) // fixed location
}
```

Read precisely, the signed message is the 64-byte digest

```
m = HMAC-SHA512( AuthKey, ed25519_public_key || ClientHello || ServerHello )
```

* The prefix is not zeroed between the two uses: `h.Write(ed25519Priv[32:])` happens
  once, and `h.Sum(cert[:len(cert)-64])` *appends* without resetting. So the
  ML-DSA message starts with the Ed25519 public key and ends with the two hellos,
  which is what binds the signature to this handshake (and to this server's auth
  key) rather than to the server alone.
* `ClientHello` is the whole handshake message — 4-byte header included — with the
  **sealed** session id (it was restored at `RL/tls.go:248`), and `ServerHello` is
  `hs.hello.original`, i.e. the decoy's ServerHello with the ephemeral key share
  rewritten in place. Both are exactly the bytes the client saw.
* `ctx = nil` (empty context string) and `randomize = false`, so the signature is
  deterministic — the same handshake can be verified from a capture.
* The signature goes to `cert[126:]`: the value of the 3309-byte placeholder
  extension `ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: empty[:3309]}}`
  that `signedCertMldsa65` was built with at process start
  (`RL/handshake_server_tls13.go:82`). "Fixed location" is the reason the
  certificate is built once and cloned per connection: the DER layout, and hence
  the offset, never changes.

**When it is used.** The switch is `len(c.config.Mldsa65Key) > 0` and nothing else
(`:143-147`): the server always uses the ML-DSA certificate variant when it was
configured with a seed, regardless of what the client offered. There is no
negotiation, no `signature_algorithms` check, and no way for a client to ask for it
or opt out. A client that does *not* check simply ignores the extra extension: the
HMAC check of §3 still decides the connection.

**Client side** (`XC/transport/internet/reality/reality.go:88-101`): with
`mldsa65Verify` set, the client requires at least one extension on the leaf,
continues its own HMAC state with `Hello.Raw` and `ServerHello.Raw`, and calls
`mldsa65.Verify(verify, h.Sum(nil), nil, certs[0].Extensions[0].Value)`. Note the
two ways to fail: an extension that does not verify leaves `Verified` false, and
so does a *missing* one; either way the client logs "received real certificate
(potential MITM or redirection)" and fails the connection
(`:183-185`, `:274`).

### What the Rust code does

The seed arrives as `mldsa65_seed: Option<[u8; 32]>` (`RB/server.rs:39-42`), decoded
from unpadded base64url at `ZC/xray_json.rs:937-950` and copied into the server
parameters at `ZR/server.rs:485`. The signature is built inside
`reality_certificate` (`RB/server.rs:827-843`):

```rust
let mut signed = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("fixed HMAC key");
signed.update(&public);
signed.update(client_hello);
signed.update(server_hello);
let key = MlDsaKey::<MlDsa65>::from_seed(&(*seed).into());
let signature = key.sign(signed.finalize().into_bytes().as_slice());
```

* Same three inputs, same order, same hash: `public` is the per-connection Ed25519
  verifying key (`RB/server.rs:810`), `client_hello` and `server_hello` are the
  handshake *messages* — the reassembled ClientHello including its header
  (`message`, `RB/server.rs:500`, `:511-512`) and the locally built ServerHello
  (`RB/server.rs:338`) — passed in from `RB/server.rs:356-358`.
* The signing key is derived with `MlDsaKey::from_seed` per handshake
  (`RB/server.rs:833`). That is the same key material Xray expands once at config
  time, and the Rust side pays only the cheap seed expansion here: the expensive
  direction (`ExpandA` on the *verifying* key) is the client's, and §4 of
  `REALITY-client.md` covers its cache. The bug that made it expensive on this side
  is worth recording here because it was a *process abort*, not a slow path: the
  ML-DSA-65 verification used to expand its key inside a ~1.5–1.9 MB deep debug-build
  async chain and overflowed the worker's stack (SIGABRT). It now happens once per
  pinned key on a thread with an explicit 1 MiB stack,
  `expand_mldsa65_verifying_key` (`ZS/reality.rs:261-278`), cached per exact key
  bytes by `decoding_mldsa65_verifying_key` (`ZS/reality.rs:216-245`, cache
  `:182-209`).
* The signature sits in a certificate extension exactly like Go's, but as a real
  OCTET STRING under OID `1.3` inside the `[3]` extensions field
  (`RB/server.rs:835-843`) instead of Go's placeholder OID `0.0` at a fixed offset.
  Both clients read "the first extension's value"
  (`XC/transport/internet/reality/reality.go:92-93` and `ZS/reality.rs:334-339`),
  so the OID is invisible on the wire.
* The Rust client's verification mirrors the server byte for byte: HMAC over
  `spki_key || client_hello || server_hello`, then `VerifyingKey::verify`
  (`ZS/reality.rs:329-353`).

**Status: PORTED.** This is the strongest parity claim in this document, because it
is proven in *both* directions against two independent implementations: `circl`'s
ML-DSA verifier accepting a signature made by the Rust port, and the Rust port
accepting `circl`'s signature.

**Behaviour when the client does not ask for it — pinned by tests, not by prose.**
`RB/server.rs:1056-1064` asserts all three combinations that a deployment can
produce: server with seed + client with verify key (accepts), neither side (plain
REALITY as before), and server with seed + client without a key (accepts — the
client simply ignores the extension). `RB/server.rs:1066-1072` asserts the two
negative cases a pinning client must not accept: a server that does not sign at
all, and a server that signs with a *different* seed. On the Go side the equivalent
behaviour is that a pinning Xray client against a non-signing server fails with
`Verified == false` (`XC/transport/internet/reality/reality.go:88-101`, `:183-185`).

**Proved by.** `OR:2115-2125`
(`reality_with_the_mldsa65_binding_matches_the_oracle`) runs both directions with a
seed/verify pair generated by the oracle's own `xray mldsa65` (`OR:552-568`):
Zray client → Xray server (Xray signs, Rust verifies) and Xray client → Zray server
(Rust signs, Xray verifies). Both directions use a decoy certificate of almost
5 KB (`OR:652-661`) because of the record-length rule of §3: the ML-DSA-65
certificate is ~3.5 KB, and an Xray server cannot pad its flight up to a decoy whose
certificate record is smaller.

**Not covered.** No test drives `mldsa65Seed == privateKey` (which Xray refuses at
config time, `XC/infra/conf/transport_internet.go:904-906`) against the Rust config
parser, and no test asserts that a Zray client without `mldsa65Verify` still accepts
a Zray server that holds a seed — that combination is only covered locally
(`RB/server.rs:1062-1063`) and by symmetry with Xray's client.


## 5. Post-handshake record counters

TLS 1.3 lets a peer write records that advance nothing: a compatibility
ChangeCipherSpec, a warning alert, an empty application-data record. They are
required for interop and useless for progress, so every implementation bounds how
many it will ignore before deciding the peer is not a peer. REALITY goes one step
further: it *measures the camouflage site's own tolerance* and copies it, so a
prober cannot count records to tell the two apart.

### What the official Go code does

**The counter.** `Conn.MaxUselessRecords` (`RL/conn.go:32`) with a default of
`maxUselessRecords = 32` (`RL/common.go:70`), applied by `retryReadRecord`
(`RL/conn.go:827-839`):

```go
c.retryCount++
if c.MaxUselessRecords <= 0 {
    c.MaxUselessRecords = maxUselessRecords
}
if c.retryCount > c.MaxUselessRecords {
    c.sendAlert(alertUnexpectedMessage)
    return c.in.setErrorLocked(errors.New("tls: too many ignored records"))
}
return c.readRecordOrCCS(expectChangeCipherSpec)
```

What reaches `retryReadRecord`: an empty application-data record (`RL/conn.go:803-811`),
a ChangeCipherSpec record in TLS 1.3 before the handshake completes
(`:793-795`), a warning-level alert (`:770-773`), and `alertUserCanceled` in TLS 1.3
(`:758-767`). Anything that *does* advance state resets the count: `if typ !=
recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
c.retryCount = 0 }` (`:734-737`). So the limit is on a *consecutive* run, and a
single byte of real traffic is enough to start over.

**The other counter.** Post-handshake *handshake* messages have their own check in
`handlePostHandshakeMessage` (`RL/conn.go:1372-1399`): one message is read, then
`c.retryCount++` and `if c.retryCount > c.MaxUselessRecords { alertUnexpectedMessage;
"tls: too many non-advancing records" }`. Note the difference from the path above:
there is no `< 0` defaulting here, so a `MaxUselessRecords` that was never set makes
the *first* post-handshake message fatal. In practice it is always set (below).

**Where the number comes from.** At listener setup Xray calls
`go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)`
(`XC/transport/internet/tcp/hub.go:82`), which realises `RL`'s requirement to do it
"in advance manually" if the REALITY listener is not used (`RL/tls.go:160-161`).
The probe speaks to the decoy as Chrome (`RL/record_detect.go:21-102`) and, after
its own ChangeCipherSpec, sends runs of CCS records to see how many the site
tolerates (`RL/record_detect.go:137-185`): a reply after 2 probes means the site
allows 1, after 15 means 16, after 16 means 32, and no alert at all means
`math.MaxInt`. Both numbers are filed under `dest + " " + sni + " " + alpn`
(`RL/tls.go:396-403`), and the accepting connection picks them up while it finishes
its handshake (`RL/tls.go:404-428`), including `hs.c.MaxUselessRecords =
maxUseless.(int)` (`:425-427`). The same loop also writes the decoy's
post-handshake record sizes as empty records before it breaks (`:406-421`), and
`isHandshakeComplete` is only set afterwards (`:429`) — so a REALITY server that has
learned its decoy's shapes emits them before any application data can flow.

**Resumption, tickets, KeyUpdate.** Xray disables tickets
(`SessionTicketsDisabled: true`, `XC/transport/internet/reality/config.go:32`), the
fork never sends one (`shouldSendSessionTickets`, `RL/handshake_server_tls13.go:1056-1068`)
and never accepts a resumption (`checkForResumption` is commented out,
`RL/handshake_server_tls13.go:133-140`). A KeyUpdate *is* handled, and answered if
the peer asked for one: `handleKeyUpdate` rolls the read secret and, when
`updateRequested`, writes a KeyUpdate reply and rolls the write secret
(`RL/conn.go:1401-1436`). A NewSessionTicket arriving *from* a client is an error
in Go (`handleNewSessionTicket` rejects it on a non-client connection with "tls:
received new session ticket from a client",
`RL/handshake_client_tls13.go:855-859`).

**Replay.** There is no replay memory in this revision and no session-id cache:
`RL/cache.go:14-43` is a weak-pointer cache of *parsed x509 certificates* keyed by
DER bytes, nothing else. A replayed ClientHello authenticates again, and the only
defence is the `maxTimeDiff` window of §2 — which is off by default.

### What the Rust code does

The record stream that both ends use after the handshake (`Tls13Stream`,
`ZS/client.rs:704-729`) implements the same *kinds* of tolerance, with different
bounds:

* **CCS**: ignored at any time, and **not counted** (`ZS/client.rs:815`).
* **Alerts**: `close_notify` ends the stream (`:816-824`); anything else is a hard
  failure (`:823`).
* **Empty application-data records**: tolerated as REALITY's ticket mimicry, bounded
  at 256 consecutive records — `self.empty_records += 1; if self.empty_records > 256
  { malformed("peer sent an implausible run of empty records") }`
  (`ZS/client.rs:838-846`) — and reset by any record that carries data (`:847-848`).
* **A cleartext handshake record after the handshake** is a hard failure
  (`:825-828`), where Go would try to decrypt it; both end the connection.
* **Post-handshake handshake messages** (`ZS/client.rs:893-929`): a KeyUpdate rolls
  the read secret and is answered with a not-requesting KeyUpdate when the peer set
  `update_requested`, rolling the write secret as well (`:905-923`) — the same
  behaviour as `RL/conn.go:1401-1436`. NewSessionTicket and unknown types are
  ignored silently (`:925`, "no resumption, ignored"), where Go alerts on a ticket
  from a client and on any unexpected type.
* **During the handshake**, `read_encrypted_handshake` skips CCS records with *no*
  bound (`RB/server.rs:769-774`) and refuses anything that is not app-data
  (`:775-777`). The unbounded loop is not unbounded in time: the whole inbound
  handshake runs under `timeout(handshake_timeout(), …)` (`ZR/server.rs:2230-2234`),
  default 60 s (`ZR/server.rs:208-216`), so a peer spamming CCS records is
  eventually closed by the deadline rather than by a counter.

**The per-decoy budget has no counterpart.** `DetectPostHandshakeRecordsLens`'s CCS
probing is not ported: the Rust port learns only the decoy's post-handshake record
*sizes* (`ZS/post_handshake.rs:161-178`, `ZR/server.rs:8956-9008`) and has no
`GlobalMaxCSSMsgCount` equivalent, so a Zray REALITY server cannot match a decoy
whose tolerance is not 32. Nothing in `crates/reality/src/` mentions a useless-record
budget at all.

**Status:**

| Behaviour | Status | Evidence |
|---|---|---|
| Default budget of 32 consecutive useless records | **PORTED** | `RL/common.go:70`, `RL/conn.go:827-839` have no Rust counterpart; the only imported bound is 256 empty records (`ZS/client.rs:842`) |
| Per-decoy learned budget (CCS probe) | **MISSING** | `RL/record_detect.go:137-185`, `RL/tls.go:425-427`; the Rust port has no probe and no field |
| Empty-record handling | **PORTED** | Go counts them against `MaxUselessRecords` (32 by default, `RL/conn.go:803-811`); Rust allows 256 consecutive (`ZS/client.rs:838-846`) |
| Session-ticket tolerance | **DIVERGENT** | Go never issues one (`XC/…/reality/config.go:32`) and alerts if a client sends one; Rust ignores any post-handshake type it does not know (`ZS/client.rs:925`) |
| KeyUpdate | **PORTED** | `RL/conn.go:1401-1436` vs `ZS/client.rs:905-923`; Rust accepts `mlen >= 1` where Go requires exactly one byte, which is a widening, not a disagreement on the reply |
| Replay / session-id cache | **PORTED (both absent)** | `RL/cache.go:14-43` is an x509 cache only; no cache exists in `crates/reality` |

**Proved by.** `OR:1519-1601`
(`an_idle_reality_flow_with_keepalive_probes_survives_the_servers_empty_record_limit`)
runs a Zray client with 50 ms keepalive probes against a *real Xray REALITY server*,
idles for 3 s, and then sends data twice — this pins the **client's** side of the
budget: the Zray client must not spend the server's allowance on empty records, and
the client's own politeness rule is written down at `ZS/client.rs:987-994` with the
Go limits quoted in the comment. `ZS/post_handshake.rs:226-248` pins the read-side
rules locally (only post-Finished application-data records count, and alerts are not
record sizes).

**Not proven, in either direction.** No test sends a long run of empty records or
CCS records *to* a Zray REALITY server, so nothing exercises the 256-record bound or
the absence of a 32-record budget; and no test compares a Zray server's tolerance
with its decoy's. Both need a raw-socket client that completes a REALITY handshake
and then sends N empty records, run against a Zray inbound and against an Xray one
behind the same decoy, comparing the record count at which each closes. This is
the clearest remaining divergence in §5 and the one a censor could measure: an
observer who spams ChangeCipherSpec records at both the real site and a REALITY
server learns nothing from Go's REALITY (the tolerance is copied from the site), but
after 257 empty records against a Zray server it has learned that the ceiling is 256
rather than whatever the site it claims to be would have allowed.

_Note to the operator:_ `maxUselessRecords` is not configurable from `realitySettings`
in either implementation — Go derives it from the decoy, and the Rust port does not
have one.


## 6. Fallback

Fallback is what makes REALITY a camouflage protocol rather than a secret one: a
peer that does not authenticate must end up talking to the real site, with the same
bytes it already sent, so the failure is indistinguishable from the site's ordinary
behaviour. Both implementations do that; they differ in *when* the target is dialled
and in how long the resulting session may live.

### What the official Go code does

**Dialling `dest`.** Once, at the very top of `Server`, for every connection,
authenticated or not (`RL/tls.go:168-172`):

```go
target, err := config.DialContext(ctx, config.Type, config.Dest)
if err != nil {
    conn.Close()
    return nil, errors.New("REALITY: failed to dial dest: " + err.Error())
}
```

Two operator-visible facts follow from this: a decoy that is down makes the REALITY
server *close* connections (there is no local fallback), and every authenticated
connection also holds a socket to the decoy for as long as it lives — the target
connection is what the server shapes its own handshake against (§3) and it is closed
only when `waitGroup.Wait()` returns (`RL/tls.go:451-452`).

**The PROXY header** is written immediately after dialling, before any mirrored
byte, and only when `xver` is 1 or 2 (`RL/tls.go:174-180`):
`proxyproto.HeaderProxyFromAddrs(config.Xver, conn.RemoteAddr(), conn.LocalAddr())`,
which is v1 (`PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n`, or
`PROXY UNKNOWN\r\n` when the family cannot be expressed) for 1 and the binary v2
signature form for 2. Xray refuses `xver > 2` at config time
(`XC/infra/conf/transport_internet.go:844-846`). A failure to write it closes both
sockets (`RL/tls.go:176-179`).

**Replaying the ClientHello.** Go does not buffer-and-replay; it *mirrors*: the
`MirrorConn` wrapping the client writes every byte it reads to the target
immediately (`RL/tls.go:64-82`), and its `Read` also releases the mutex so the
intake goroutine and the relay goroutine take turns rather than racing. By the time
the authentication decision is made, the target has already seen the ClientHello and
may already have answered. On the fallback path the remaining traffic is two plain
copies with per-direction rate limits (`RL/tls.go:271-286` for client → target,
`:433-447` for target → client), and the target's bytes that were buffered while the
decision was being made are written to the client first (`conn.Write(s2cSaved)`,
`:441`) so no byte is lost or reordered.

**Half-close.** `raw` is the client socket as a `CloseWriteConn` (`RL/tls.go:182-186`).
When the client→target copy ends cleanly, the server calls `target.CloseWrite()` and
leaves the other direction running; on a reset or error it closes the target
(`RL/tls.go:276-285`). The download side does the same to the client socket:
`io.Copy(underlying, …)` then `underlying.CloseWrite()` (`RL/tls.go:442-446`). A
peer therefore sees a FIN, not a RST, in both directions. There is **no idle timeout
and no overall deadline** on the fallback copies: to a prober, this is an ordinary
long-lived TCP session with the site.

**Rate limits.** `LimitFallback{AfterBytes, BytesPerSec, BurstBytesPerSec}`
(`RL/common.go:540-544`) are applied through `NewRatelimitedConn`
(`RL/tls.go:122-137`): a zero `BytesPerSec` disables the limit entirely, otherwise a
token bucket of `BytesPerSec` with a burst of at least `BytesPerSec`
(`burstBytesPerSec` is clamped *up* to `BytesPerSec`, `:127-130`). Only the *read*
side of the wrapped connection is charged (`RatelimitedConn.Read`, `:110-120`), so
wrapping the client socket limits uploads and wrapping the target socket limits
downloads — the wrap sites are `io.Copy(target, NewRatelimitedConn(underlying, &config.LimitFallbackUpload))`
(`:275`, `:437`) and `io.Copy(underlying, NewRatelimitedConn(target, &config.LimitFallbackDownload))`
(`:442`). Counting starts at the first byte read through the wrapper, i.e. **after**
the ClientHello, which was already mirrored to the target unthrottled; the first
`AfterBytes` bytes of each direction are free (`:113-117`). Xray's defaults are all
zeros — no limit (`XC/infra/conf/transport_internet.go:918-925`).

### What the Rust code does

**Dialling `dest`.** Only on the fallback path, in `relay_reality_fallback`
(`ZR/server.rs:2395-2489`), called after `secure_inbound` returns
`Secured::Fallback` (`ZR/server.rs:2237-2242`). An inbound with no `dest`/`target`
logs and drops the connection (`ZR/server.rs:2407-2415`); a dial that fails logs and
drops it (`:2418-2431`). An authenticated connection never dials the target at all
(§3, divergence 1).

**The PROXY header** is `zero_protocol::proxy_protocol::encode(reality.fallback_xver,
Some(peer), local)` when `fallback_xver != 0` (`ZR/server.rs:2433-2441`), written
before the replayed hello. `encode` (`crates/zero-protocol/src/proxy_protocol.rs:32-70`)
produces for v1 `PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n` or
`PROXY UNKNOWN\r\n` when the pair cannot be expressed, and for v2 the 12-byte
signature, `0x21` (PROXY, STREAM), a family byte (`0x11` TCP4 / `0x21` TCP6), the
2-byte address length and the addresses — the same layout go-proxyproto writes.
`local` is the inbound's configured listen address and port
(`ZR/server.rs:2219-2225`), i.e. the analogue of Go's `conn.LocalAddr()`. `xver`
values outside 0..=2 are refused at parse time (`ZC/xray_json.rs:985-993`), and a
PROXY header that cannot be written drops the connection (`ZR/server.rs:2436-2440`).

**Replaying the ClientHello.** The port buffers deliberately: intake keeps every
record byte it consumed while reassembling the hello (`RB/server.rs:472-522`) and
`HandshakeOutcome::Fallback { client_hello }` carries them to the relay
(`RB/server.rs:135-142`), which writes them to the target before starting the copies
(`ZR/server.rs:2442-2451`). Bytes the client sent *after* the hello are still in the
socket and follow in order, so the target sees exactly the stream it would have seen
if it had been dialled first — which is what
`crates/reality/tests/fallback.rs:284-319`
(`the_hello_and_every_byte_after_it_reach_the_target_in_order`) asserts from both
ends.

**There are two copies of this relay at HEAD.** `crates/reality/src/fallback.rs` is
the port moved into the REALITY crate, with its own `relay`
(`RB/fallback.rs:286-356`), `FallbackLimit` (`:96-127`) and the same two defaults
(`:60-75`), and it says so itself: "The Rust moved here is `zero-runtime/src/server.rs`
→ `relay_reality_fallback` … The runtime still runs its own copy of all three for
now" (`RB/fallback.rs:34-41`). The runtime copy (`ZR/server.rs:2395-2489`,
`ZR/throttle.rs`, `ZR/relay.rs`) is the one an inbound actually executes today and
the one the differential tests exercise; the new module has ten focused tests
(`crates/reality/tests/fallback.rs`) but no caller in `zero-runtime` — a
`grep` for `reality::fallback` in the runtime finds nothing. The two differ only in
the two places `RB/fallback.rs:43-46` names: the moved `Throttle` reads through a
zeroed window instead of the runtime's `unsafe { buf.assume_init }`
(`ZR/throttle.rs:98-100`), and the moved relay keeps one read buffer per direction
instead of the runtime's pooled, self-growing pair. This is duplication to be
removed, not a behavioural divergence — but a reader of the code must know which
copy their inbound runs.

**Half-close.** `relay(client, remote)` (`ZR/server.rs:2468`, `ZR/relay.rs:501-507`)
copies both directions and, when one side reaches EOF, flushes and calls
`poll_shutdown` on the other (`ZR/relay.rs:325-356`) — the equivalent of
`CloseWrite()`. The remaining direction keeps running until it finishes, or until
the half-close idle limit (1 s by default, `ZR/relay.rs:41-47`) fires once it has
gone quiet (`ZR/relay.rs:460-476`).

**Rate limits.** The same two wrap sites, in the same direction semantics
(`ZR/server.rs:2455-2467`): `Throttle::new(stream, fallback_limit_up)` charges what
the *client* sends, `Throttle::new(remote, fallback_limit_down)` what the target
sends. `Throttle` (`ZR/throttle.rs:34-79`, `:81-140`) charges only reads
(`:91-104`), makes `bytes_per_sec == 0` mean "no limit at all" (`:88-90`), treats a
zero burst as one second's worth of credit (`:60-66`) and guarantees a throttled
read still makes progress (`:111-116`). Counting starts at the first byte read
through the wrapper, i.e. after the replayed hello — the same rule as Go.

**Status: PORTED** for dialling, the PROXY header, the hello replay and the rate
limits, with two named differences:

1. **When the target is dialled.** Rust dials on fallback only
   (`ZR/server.rs:2395-2431`); Go dials on every connection (`RL/tls.go:168`). For a
   prober the visible difference is that a Zray fallback connection has no decoy
   handshake already in progress, and the *timing* of the first bytes from the site
   differs by the dial. For an operator it means a Zray inbound keeps working while
   its decoy is down for *authenticated* clients, and fails the same way Go does for
   everyone else (connection dropped, `ZR/server.rs:2426-2431`).
2. **An idle fallback session has a deadline.** The Rust relay uses
   `DEFAULT_IDLE_TIMEOUT = 300 s` (`ZR/relay.rs:39`, overridable by `policy.connIdle`,
   `ZR/relay.rs:52-64`) plus a 1 s half-close limit (`ZR/relay.rs:47`); Go's
   fallback copies have no timeout at all (`RL/tls.go:271-286`, `:442`). A prober
   that opens a session and says nothing therefore sees it closed after five minutes
   by a Zray server and held open indefinitely by an Xray one.
3. **Burst is not clamped up to the rate.** Go raises `burstBytesPerSec` to
   `bytesPerSec` when it is smaller (`RL/tls.go:127-130`); Rust uses the configured
   burst as given (`ZR/throttle.rs:60-66`), so a config with
   `burstBytesPerSec < bytesPerSec` behaves differently — a smaller allowance in
   Rust.

**Proved by.** The fallback path is exercised by the differential suite in the
failure direction: `OR:1214-1301` (a client with the wrong public key must not get a
round trip, and the decoy answers instead) and `OR:2132-2154` (a client outside the
version limits is relayed, `OR:819-849`). Because the oracle's decoy is another Xray
instance (`OR:505-550`), "relayed" means a real TLS session with a real Go TLS
server, not a mock. The replay, PROXY header, half-close and rate limits are pinned
by ten focused tests over the moved relay (`crates/reality/tests/fallback.rs`), one
per behaviour: `a_prober_meets_the_version_one_proxy_header_then_its_own_hello`
(`:175-213`), `a_prober_meets_the_version_two_proxy_header_byte_for_byte`
(`:214-251`), `a_visitor_with_no_known_address_is_announced_as_local` (`:252-283`),
`the_hello_and_every_byte_after_it_reach_the_target_in_order` (`:284-319`),
`the_relay_half_closes_the_target_and_keeps_the_response_flowing` (`:320-359`),
`the_upload_limit_holds_the_visitor_to_the_configured_rate` (`:360-404`),
`the_bytes_before_after_bytes_pass_at_once` (`:405-440`),
`the_download_limit_shapes_the_target_and_leaves_the_visitor_alone` (`:441-489`),
`a_visitor_that_says_nothing_is_closed_at_the_idle_limit` (`:490-523`) and
`a_visit_the_site_has_finished_with_is_closed_soon_after` (`:524-553`). Note what
those tests do *not* do: they call the moved module, not the inbound, so they pin
the bytes rather than the wiring of the copy the runtime runs.

**Not proved against the oracle.** No differential test drives `xver` 1 or 2 against
a real decoy that inspects the header, and none compares a Zray fallback session's
lifetime with an Xray one. Both are covered by the local tests named above and by
reading the Go source; the difference in point 2 is the one a censor could measure.


## 7. Config surface

Everything a server operator can write lives in one object, `streamSettings.realitySettings`,
and both Xray and the port read it with the same field names. Xray's proto is the
authority on the field set (`XC/transport/internet/reality/config.proto:9-34`) and
`XC/infra/conf/transport_internet.go:807-925` is the authority on the JSON: which
fields are required, what units they are in, and what is refused. The port reads the
same JSON twice: `zero_config` as part of compiling a whole config
(`ZC/xray_json.rs:885-1009`, what an inbound actually runs) and a standalone reader
in the REALITY crate (`RB/config.rs:99-190`), with
`crates/reality/tests/config.rs` comparing the two parses field by field
(`both_readers_agree_on_one_reality_block`, `crates/reality/tests/config.rs:90-155`;
`the_readers_agree_on_which_blocks_are_refused`, `:157-228`).

Server-side fields, in proto order. "Unit" is the JSON unit; "Rust" says whether the
port reads the field and honours it on the server path. In this section only,
`XC/…:line` is short for `XC/infra/conf/transport_internet.go:line` (the file that
turns JSON into the fields Xray hands to REALITY).

| # | Field | Xray semantics, default, unit | Rust |
|---|---|---|---|
| 1 | `show` | bool, default `false`; enables `RL`'s diagnostics, which include `AuthKey[:16]`, the decoded client version/shortId and record lengths (`RL/tls.go:164-166`, `:238-256`, `:331-333`) | **parsed, carried, not yet printed** — both readers read the switch and refuse a non-bool, as Xray's decode does; the report line is `keys::ClientReport`, the one shape it takes here, and Xray's `AuthKey[:16]` is deliberately absent from it (`crates/zero-runtime/tests/log_privacy.rs`). The per-connection call site is the handshake's (`RB/server.rs`, a separate workstream) |
| 2 | `dest` (alias `target`) | string, required for a server; bare port ⇒ `localhost:PORT` (`XC/…:818-822`, `:833-835`); `@`/`/` prefix ⇒ `type: "unix"` (`:824-832`) | **host:port and bare port honoured** (`ZC/xray_json.rs`, `RB/config.rs`), and a missing `dest` is now refused by **both** readers, as Xray refuses it (`XC/…:841-843`); a `/path` or `@name` unix socket is refused **by name** rather than dialled, with the reason in the message — the fallback relay speaks TCP only (`crates/reality/tests/config.rs`) |
| 3 | `type` | `"tcp"` or `"unix"`, inferred from `dest`, handed to `DialContext` (`RL/tls.go:168`) | **MISSING, and refused instead** — `type` is not read; a `dest` shape that would make Xray set `"unix"` is refused by both readers, each naming the shape it saw |
| 4 | `xver` | uint64, default `0`; `1`/`2` write a PROXY header to the target (`RL/tls.go:174-180`); `>2` refused at parse time (`XC/…:844-846`) | **honoured** (`ZC/xray_json.rs:985-993`, `RB/config.rs:178-186`, used at `ZR/server.rs:2433-2441`) |
| 5 | `server_names` | repeated string, must be non-empty (`XC/…:847-849`), compared exactly (`RL/tls.go:211`) | **honoured**, non-empty enforced (`ZC/xray_json.rs:896-906`, `RB/config.rs:109-119`); compared exactly — **PORTED** (§1) |
| 6 | `private_key` | bytes(32), unpadded base64url (`XC/…:850-855`) | **honoured** (`ZC/xray_json.rs:6581-6590`, `RB/config.rs:231-241`); both readers also accept standard base64, a widening of the accepted set |
| 7 | `min_client_ver` | bytes(3); JSON `"1.2.3"`, 1–3 dotted parts, each < 256 (`XC/…:856-869`); compared big-endian (`RL/tls.go:257`) | **honoured** (`RB/server.rs:265-267`); parsing requires exactly three parts — **DIVERGENT**, stricter (`ZC/xray_json.rs:951-968`, `RB/config.rs:260-278`) |
| 8 | `max_client_ver` | as above (`XC/…:870-883`, `RL/tls.go:258`) | as above |
| 9 | `max_time_diff` | uint64 **milliseconds**, default `0` meaning *no clock check*; converted to a `Duration` at `XC/transport/internet/reality/config.go:29`, compared symmetrically at `RL/tls.go:259` | **honoured, same unit** (`ZC/xray_json.rs:1000-1003`, `RB/config.rs:170-175`, `ZR/server.rs:486`, check at `RB/server.rs:272-288`) |
| 10 | `short_ids` | repeated bytes(8); JSON hex ≤ 16 chars, decoded into eight zero-padded bytes (`XC/…:887-896`); must be non-empty (`:884-886`); exact map match (`RL/tls.go:260`) | **honoured, exact and zero-padded** (`ZC/xray_json.rs:907-930`, `RB/config.rs:121-143`, `RB/server.rs:235-244`); the *non-empty* rule is **MISSING** on the inbound path (§ below) |
| 11 | `mldsa65_seed` | bytes(32) unpadded base64url; must differ from `privateKey` (`XC/…:903-910`) | **honoured** (`ZC/xray_json.rs:937-950`, `RB/config.rs:159-162`, `ZR/server.rs:485`); the "must differ" rule is **MISSING** |
| 12 | `limit_fallback_upload` | `{after_bytes, bytes_per_sec, burst_bytes_per_sec}`, all default `0` = unlimited (`XC/…:918-921`) | **honoured** (`ZC/xray_json.rs:969-984`, `RB/config.rs:280-299`, `ZR/server.rs:2455-2467`) with the burst-clamp difference of §6 |
| 13 | `limit_fallback_download` | as above (`XC/…:922-925`) | as above |

**Status: PORTED for 11 of the 13 server-side fields** — `dest` (host:port and bare
port, with the shapes that cannot be dialled refused by name), `xver`,
`server_names`, `private_key`, `min_client_ver`, `max_client_ver`, `max_time_diff`,
`short_ids` (exactly), `mldsa65_seed`, and both fallback limits — plus the two
diagnostics switches `show` and `masterKeyLog`, which both readers now *read* (a
wrong shape is refused) while the handshake call sites that would print the line
and write the file are still to come; `type` stays **MISSING**. The client-only
fields of the same proto are
accepted and ignored on purpose. The five validation
gaps below matter more than the field list, because each of them lets a
configuration run that Xray would have refused.

Client-only fields, which a server must accept and ignore — operators copy whole
blocks between roles, so failing on the harmless half would be worse than accepting
it. The port says this explicitly in `CLIENT_ONLY_FIELDS` (`RB/config.rs:213-222`):
`fingerprint` (#21), `server_name` (#22), `public_key` (#23), `short_id` (#24),
`mldsa65_verify` (#25), `spider_x` (#26) — and `spider_y` (#27) is not even a JSON
field an operator writes, Xray computes it from `spiderX`
(`XC/…:961-975`). `password` is Xray's alias for `publicKey` (`XC/…:937-939`) and is
ignored for the same reason. Both Rust readers ignore these silently;
`a_client_half_copied_into_a_server_block_is_ignored_not_refused`
(`RB/config.rs:387-402`) pins that, and the server fields still apply.

One field is *not* client-only: `master_key_log` (#31). Xray passes it to
`KeyLogWriterFromConfig` for both roles (`XC/transport/internet/reality/config.go:34`)
and REALITY writes NSS key-log lines from the handshake
(`RL/handshake_server_tls13.go:884-893`, `:1031-1040`) — a debugging aid for
decrypting one's own traffic. The port has the equivalent for its rustls path
(`zero-security/src/tls.rs:607-631`, tested by `zero-runtime/tests/tls_options.rs`)
and now the writer for the REALITY handshake too: both readers read the field
(`"none"`, empty and absent all mean off), `RB/keys.rs::KeyLog` appends the four
NSS lines and says what writing them exposes, and
`RB/config.rs::RealityServerConfig::key_log()` opens one per listener. What is
still missing is the *call*: the two derivation points
(`RL/handshake_server_tls13.go:884-893`, `:1031-1040`) are in `RB/server.rs`, which
a separate workstream owns, so nothing writes a line yet. **PARTIAL.**

### Validation gaps, each with its consequence

* **`"shortIds": []` is accepted on the inbound path.** Xray refuses an empty list
  with ``empty "shortIds"`` (`XC/…:884-886`) and the standalone Rust reader refuses
  it too (`RB/config.rs:144-150`), but `ZC/xray_json.rs:907-930` only requires the
  key to be an array and never tests emptiness. A server started with
  `"shortIds": []` comes up healthy and sends *every* client to the decoy, because
  the fold over an empty list is `Choice::from(0)` (`RB/server.rs:235-237`). This is
  the most consequential gap in this section: it is a silent misconfiguration with
  the same shape as a censor's probe succeeding.
* **`mldsa65Seed == privateKey` is not refused.** Xray rejects it at parse time
  (`XC/…:904-906`); neither reader compares the two, so an operator can configure a
  server whose ML-DSA binding adds nothing (the seed is the HMAC key material's
  neighbour, and reusing one secret in two roles is exactly what the check exists to
  prevent). **MISSING.**
* **A missing `dest`/`target` is now refused by both readers.** Xray requires it on
  a server block (`XC/…:841-843`) — and chooses the *role* by its presence (`:812`,
  `:926`). The compiler used to accept the block and leave the target unset, and the
  runtime then dropped every fallback connection (`ZR/server.rs:2407-2415`): a
  REALITY inbound that answers nothing to a prober, which is the opposite of the
  protocol's purpose. `crates/reality/tests/config.rs::the_readers_agree_about_a_camouflage_target_they_cannot_dial`
  drives it, and the shapes below, through both readers. **PORTED.**
* **A `dest` this port cannot dial is refused by name, not resolved as a host.**
  Xray accepts `@`/`/` unix sockets and dials them (`XC/…:824-832`, `type: "unix"`);
  the fallback relay here speaks TCP only, so both readers refuse both unix shapes,
  and any `dest` that is neither `host:port` nor a bare port, with a message that
  names the shape and the reason — resolving `/run/decoy.sock` as a host name would
  fail at DNS time, for a reason that names nothing. A bare-port `dest` *is*
  supported, by both
  (`crates/reality/tests/config.rs::both_readers_treat_a_bare_port_dest_as_localhost`).
  **REFUSED, deliberately.**
* **Unknown keys are ignored** by both readers (no key-set validation), which
  matches `encoding/json`'s behaviour in Xray (`XC/infra/conf/transport_internet.go:780-805`
  is a struct decoded field by field) — a typo in a field name is silent on both
  sides, so this is parity, not a gap.

**Proved by.** `the_reality_server_limits_hold_against_the_oracles_client`
(`OR:2130-2154`) is the only differential test that feeds `realitySettings` server
fields to Zray and checks behaviour: `minClientVer`/`maxClientVer` inside the limits
must let an Xray client through, and outside them must not. `xver: 2` is set in the
same call (`OR:2143`) but with a decoy that ignores the header, so it proves the
field is accepted rather than that the bytes are right — the byte layout is covered
by `crates/reality/tests/fallback.rs:175-251` instead. `maxTimeDiff` is exercised
only locally (`RB/server.rs:272-288`) and by the source-level correspondence in the
table above.

**Still to test.** A missing `dest` is no longer one of them: it is driven through
both readers by `the_readers_agree_about_a_camouflage_target_they_cannot_dial`
(`crates/reality/tests/config.rs`), together with both unix shapes and a target that
is not `host:port`. Nothing yet drives `"shortIds": []` or
`mldsa65Seed == privateKey` through `zero_config` and asserts that the config is
refused, though both readers refuse them today. The rest of the table is either
proven or read.

_Unit reminder for operators:_ `maxTimeDiff` is **milliseconds** in JSON (both
implementations), and `afterBytes` / `bytesPerSec` / `burstBytesPerSec` are **bytes
and bytes per second**, with `0` meaning "unlimited" rather than "none".

## 8. How to prove parity

A Zray-to-Zray handshake proves that Zray agrees with itself, which is worth
nothing to an operator whose clients run Xray. The proof is therefore always a
*mixed* run: an unmodified `xray` binary on one end and Zray on the other, asserting
that payload came back through the tunnel — the only assertion that can tell "the
server authenticated" apart from "the server quietly handed the connection to the
decoy".

### The commands

```bash
cd Zray-Core

# 1. The REALITY differential suite: both mixed directions, ML-DSA-65, the
#    limits, and the idle-keepalive case. Seven tests.
ZRAY_XRAY_BINARY=/usr/bin/xray \
  cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1 reality

# 2. One direction at a time (each test runs both, so these isolate a case,
#    not a direction).
ZRAY_XRAY_BINARY=/usr/bin/xray \
  cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1 \
  vless_over_reality_raw_tcp_matches_the_oracle
ZRAY_XRAY_BINARY=/usr/bin/xray \
  cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1 \
  reality_with_the_mldsa65_binding_matches_the_oracle

# 3. The whole differential suite, every protocol. Needs the binary; takes
#    minutes because most tests do two directions each.
ZRAY_XRAY_BINARY=/usr/bin/xray \
  cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1

# 4. The port's own tests, no binary needed.
cargo test -p reality                       # the server crate: handshake, keys, config
cargo test -p zero-runtime --test loopback_tls_interop   # Zray TLS/QUIC, incl. two REALITY cases

# 5. A live camouflage site's post-handshake shapes (the §3 replay), opt-in.
ZRAY_LIVE_TLS_HOST=www.example.com \
  cargo test -p zero-security live_site -- --ignored --nocapture
```

`ZRAY_XRAY_BINARY` is optional if `xray` is on `PATH`; the harness reports the
version it found before each test (`OR:67-76`, printed at `OR:1128-1133`) and
**panics rather than skipping** when it cannot find one (`OR:20-24`, `OR:1124-1127`)
— a differential suite that silently does nothing is worse than none. `/usr/bin/xray`
on this machine is `Xray 26.3.27 (d2758a0, go1.26.1)`, the release that pins the
REALITY revision this document is written against, which is what makes the
comparison meaningful. `--test-threads=1` is part of the command (`OR:16`): every
test binds ports and spawns an `xray` process, and the module docs name it that way.

### The two directions, and what each one proves

* **`zray_client_to_xray_reality_server`** (`OR:639-724`) — a Zray client through an
  **Xray REALITY server** to a loopback echo. It proves the *client* half (the tag
  layout, the key share, the certificate check) and, incidentally, that Zray's
  client accepts everything the Go server emits: the decoy's ServerHello with a
  rewritten share, the padded flight, the HMAC certificate, the post-handshake
  records. Two payloads are exchanged, 64 bytes and 96 KiB, so the record layer is
  exercised past a single record.
* **`xray_client_to_zray_reality_server`** (`OR:727-859`) — an unmodified **Xray
  client** through a **Zray REALITY inbound** to the same echo. This is the
  direction that proves *this document*: the Rust server's intake, its seal
  verification, its own ServerHello, its certificate substitute, its ML-DSA-65
  binding and its record layer all have to be acceptable to Go's parser
  (`crypto/tls` and uTLS), which is the strictest consumer of the two. It is driven
  with `expect_through = false` at `OR:819-849` for the cases that *must* end in the
  decoy, so the same helper pins both the accept and the hand-off.

Skip direction 2 and the whole document is unverified: a Rust server that falls
back on every connection would pass direction 1 perfectly.

### What actually passed, when this was written

`cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1 reality`
with `ZRAY_XRAY_BINARY=/usr/bin/xray`, run in this workspace:
**7 passed, 0 failed, 17 filtered out, 20.31 s** — `a_wrong_reality_public_key_is_refused_rather_than_silently_relayed`,
`an_idle_reality_flow_with_keepalive_probes_survives_the_servers_empty_record_limit`,
`reality_with_the_mldsa65_binding_matches_the_oracle`,
`the_reality_server_limits_hold_against_the_oracles_client`,
`vless_over_reality_raw_tcp_matches_the_oracle`,
`vless_vision_over_reality_matches_the_oracle`,
`zerov1_runs_through_an_xray_reality_vision_hop`.

The neighbouring numbers, measured the same way, because they are easy to
misremember: `cargo test -p reality` passes **29** lib tests plus **12**
integration tests in two files (`tests/config.rs`: 2, `tests/fallback.rs`: 10), i.e.
41 across the crate's targets; `cargo test -p zero-runtime --test loopback_tls_interop`
passes **26** in ~0.6 s on three consecutive runs, though one run of it under load
failed `tide_carries_udp_datagrams` (a UDP timing test — flaky under load, not a
REALITY result; it has since passed three times out of three).

### Two harness bugs that had to be fixed first, and why they matter here

* **A deliberate refusal was invisible.** `socks_connect` asserts a zero SOCKS5
  reply code (`OR:278-282`), which is right for every test that expects a tunnel and
  wrong for the ones that expect the decoy: the failure the test is *looking for*
  arrived as a panic from the wrong place. `socks_try_connect` (`OR:284-295`) returns
  the code as a value so the caller can assert on it, and
  `a_wrong_reality_public_key_is_refused_rather_than_silently_relayed` uses exactly
  that one call site with a comment saying so (`OR:1279-1280`). Without it, "the
  server refused a client it should not authenticate" and "the harness could not
  tell" read the same.
* **ML-DSA-65 verification used to abort the process.** Expanding a pinned
  `mldsa65Verify` key ran inside a ~1.5–1.9 MB deep debug-build async chain and
  overflowed the worker's stack (SIGABRT, "has overflowed its stack"), so
  `reality_with_the_mldsa65_binding_matches_the_oracle` could not run at all with
  default stacks. The fix is on the client side of the binding, in
  `zero-security::reality`: expand once per pinned key on a thread with an explicit
  1 MiB stack (`expand_mldsa65_verifying_key`, `ZS/reality.rs:261-278`) and cache the
  result per exact key bytes (`decoding_mldsa65_verifying_key`, `ZS/reality.rs:216-245`,
  cache limit 8 at `:182-209`). Caching alone was not enough — the *first* decode
  overflowed too — which is why both halves are needed. Iterating on this is
  documented in the project's memory as a lesson: when a dependency's crypto
  allocates large stack frames, measure the budget per phase and then choose
  caching, a dedicated thread, or boxing.

### Interop cases that are still unproven

Each of these is a real difference named in an earlier section, with no differential
test behind it. In rough order of how much they matter:

1. **A hello that offers only `X25519MLKEM768`, with no standalone `X25519`.**
   `RB/server.rs:665-671` authenticates against the hybrid's X25519 half, matching
   `RL/tls.go:221-228`, but no oracle test drives such a client: uTLS's Chrome
   fingerprints send both shares, so the Zray-side fallback choice is only covered
   by reading (§1, §2).
2. **A ClientHello without `supported_versions: 0x0304`** that still names a TLS 1.3
   cipher suite: Go hands it to the decoy (`RL/tls.go:211`), Rust authenticates it
   (§1 divergence 2). A one-line probe test would settle it.
3. **Duplicate key shares** — Go takes the first, Rust the last (§2 divergence 1).
   Only a crafted hello can show it.
4. **A pre-1.3 record between 16641 and 18432 bytes** — Go reads it, Rust falls back
   (§1 divergence 4). Harmless, but it is a measurable difference in behaviour at the
   edge of the record limit.
5. **First-flight record sizes** (§3 divergence 3): nothing compares the wire lengths
   a Zray server emits with the decoy's, so the largest fingerprinting gap in the
   port has no test. The pieces are all there (`spawn_decoy`, `OR:520-550`;
   `RecordWalker`, `ZS/post_handshake.rs:44-73`).
6. **A decoy whose certificate record is smaller than REALITY's** (§3 point 5):
   Xray closes an authenticated connection, Zray completes it. A test with a small
   decoy certificate — the fixtures already have an oversized one
   (`OR:39-42`) — would pin both behaviours and is the direct expression of the
   record-length rule.
7. **The useless-record budget** (§5): no test sends a run of empty records or CCS
   records *to* a Zray REALITY server, so neither the absence of the 32-record budget
   nor the 256-record bound is exercised, and no test compares a Zray server's
   tolerance with its decoy's.
8. **`xver` 1 and 2 against a decoy that inspects the header.** The byte layout is
   pinned locally (`crates/reality/tests/fallback.rs:175-251`) and the field is
   accepted in the differential run (`OR:2143`), but no Xray-side test asserts the
   header arrived correctly formatted at the target.
9. **A fallback session's lifetime** (§6 divergence 2): Zray's 300 s idle timeout
   against Go's unbounded copy. A prober-measurable difference with no test.
10. **A fragmenting client with ML-DSA-65.** The binding hashes the reassembled
    ClientHello (§4), and the Rust server is tested with a fragmenting client
    *without* ML-DSA (`RB/server.rs:1169-1199`); the oracle ML-DSA test uses a
    client that is not fragmenting. If the two implementations reassembled
    differently, only the combination would show it.
11. **Vision *and* ML-DSA-65 together.** `OR:1197-1210` covers Vision over REALITY
    and `OR:2115-2125` covers ML-DSA-65, but not both in one connection.
12. **`masterKeyLog` on a REALITY inbound** (§7): untested because unimplemented.

A useful discipline for whoever writes these: for cases 1–4, the test is a raw
socket that writes a hand-built ClientHello (no TLS stack) and asserts the *decoy*
answered — the same shape as `OR:819-849` — because the interesting property is the
fallback, not the bytes.

