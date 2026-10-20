# Psiphon client wire specification (OSSH / meek / fronted HTTP / TLS tunnel)

Status: byte-exact spec for implementing the **client** side in Rust, plus replayable
test vectors. Source of truth: clone at `.research/psiphon-tunnel-core`, commit
`5709017dd1624b8f2f4c1585604458ef75656a12` (Go module
`github.com/Psiphon-Labs/psiphon-tunnel-core`, `go 1.26.0`). All `path:line`
citations are relative to that clone.

Legend:

- **[V]** verified from source in the cited lines.
- **[I]** inferred (e.g. from an external dependency or from comments), not proven
  by the cited Go code alone.
- **[W]** test vector; concrete bytes are in `.research/wire-vectors/fixtures/`.

Terminology: “client” = the component we are reimplementing; “server” = Psiphon
tunnel server. “OSSH layer” = the obfuscated-SSH byte transform, independent of
the SSH protocol itself (which sits above it, unmodified except for the padding
rewrite described in §2.6).

---

## 0. Layer stack and protocol selection

The client selects `TunnelProtocol` from the server entry / tactics, then stacks
transports. Only these four stacks are in scope (all carry stock SSH):

| `TunnelProtocol` string | Underlying transport | Extra layer | OSSH? |
|---|---|---|---|
| `OSSH` | TCP to server IP:`SshObfuscatedPort` | — | yes |
| `TLS-OSSH` | TLS (uTLS) to server IP:`TlsOSSHPort` | TLS passthrough + padding ext | yes |
| `FRONTED-MEEK-OSSH`, `UNFRONTED-MEEK-*`, `FRONTED-MEEK-HTTP-OSSH` | HTTP(S) via `MeekConn` | meek cookie/padding | yes |
| `SHADOWSOCKS-OSSH` | TCP + shadowsocks AEAD | salt prefix | yes |

Protocol strings and helpers: `psiphon/common/protocol/protocol.go:36-52`,
`:313-331` (`TunnelProtocolIsObfuscatedSSH` is true only for `"OSSH"`,
`TunnelProtocolUsesObfuscatedSSH` is true for every protocol except `"SSH"`),
`:398-401` (shadowsocks). Port selection from the server entry:
`psiphon/common/protocol/serverEntry.go:757` (`GetDialPortNumber`), key material
fields `:59-88`.

OSSH layer construction: `psiphon/tunnel.go:1122-1142`:

```go
if protocol.TunnelProtocolUsesObfuscatedSSH(dialParams.TunnelProtocol) {
    obfuscatedSSHConn, err := obfuscator.NewClientObfuscatedSSHConn(
        throttledConn,
        dialParams.ServerEntry.SshObfuscatedKey,   // keyword: raw ASCII bytes
        dialParams.ObfuscatorPaddingSeed,          // 32-byte prng seed
        dialParams.OSSHObfuscatorSeedTransformerParameters,
        dialParams.OSSHPrefixSpec,
        dialParams.OSSHPrefixSplitConfig,
        &obfuscatedSSHMinPadding, &obfuscatedSSHMaxPadding)
```

Keyword is used as **raw string bytes**, not hex-decoded (`obfuscator.go:307-312`
passes `[]byte(config.Keyword)`), even though the server entry value looks like
hex. [V]

Transport selection and dial wrappers: `psiphon/tunnel.go:1020-1075` (TLS tunnel
/ shadowsocks / plain TCP, then `NewActivityMonitoredConn`,
`NewBurstMonitoredConn`, `NewThrottledConn`, then OSSH). [V]

### 0.1 On “probability” fallbacks (clarification)

There is **no probability field or fallback byte in the OSSH seed message** in
this implementation. The original `obfuscated-openssh` “probability” notion is
replaced by client-side tactical coin flips that choose one of two *on-wire*
shapes:

1. plain seed message, or
2. prefix + terminator before a seed message (with a prefix header after its
   padding).

Selection happens before the connection is opened:
`psiphon/dialParameters.go:2575-2601` (`OSSHPrefixProbability`, default `0.0`
at `parameters.go:1055`), `:2547-2573`
(`OSSHObfuscatorSeedTransformProbability`, default `0.0` at
`parameters.go:1047`). `OSSHPrefixSpec` supersedes the seed transform
(`dialParameters.go:1325-1328`). Server-entry flags force both off:
`DisableOSSHTransforms` (`serverEntry.go:87`, `dialParameters.go:1268-1274`) and
`DisableOSSHPrefix` (`serverEntry.go:88`, `dialParameters.go:1290-1294`).
Also from `packed.go:953-954`. [V]

A Rust implementation must support both shapes and pick per attempt; a client
that only ever emits the plain seed message is protocol-valid unless tactics
require the prefix. The server auto-detects the shape (§2.3). [V]

---

## 1. Shared primitives

### 1.1 PRNG (`psiphon/common/prng`)

`prng.Seed` is `[32]byte` (`prng.go:64-66`). A PRNG is ChaCha20 keyed by the seed
with a 12-byte nonce whose first 8 bytes are the big-endian rekey counter,
starting at 0 (`prng.go:115-123`, `:162-190`; stream limit `2^38-64`).
`Intn` uses Go `math/rand` semantics, `Range(min,max)` is inclusive and maps to
`Intn(max-min+1)`, `Bytes(n)` is a raw stream read, and
`Padding(min,max) = Bytes(Range(min,max))` (`prng.go:230-237`, `:277-289`,
`:300-312`).

`NewSaltedSeed(seed, salt)` = `HKDF-SHA256(ikm = seed[32], salt = ASCII salt,
info = nil)` → 32 bytes (`prng.go:81-94`). Used by OSSH as
`GetDerivedPRNG("obfuscated-ssh-padding")` and
`GetDerivedPRNG("obfuscated-ssh-prefix-split")`
(`obfuscatedSshConn.go:207`, `:308`; `obfuscator.go:261-276`).

**Rust guidance.** Random padding lengths/bytes need only be *valid*, not
Go-reproducible. Exact reproduction of Go’s `PRNG.Intn`/`Range` requires
ChaCha20 plus Go `math/rand.Int63n` rejection sampling; only needed to replay a
recorded Go dial bit-for-bit. The fixture `derivedPRNGSeeds` contains the salted
seed bytes so the raw stream can be reproduced, but vectors below are designed
so tests do not need `Intn` (expected bytes are given).

### 1.2 OSSH stream ciphers

For a 16-byte obfuscator seed `S`, keyword `K` (raw bytes), direction strings
`D = "client_to_server"` or `"server_to_client"` (`obfuscator.go:39-46`):

```text
digest = SHA1(S || K || ASCII(D))
repeat 6000 times: digest = SHA1(digest)
key = digest[0:16]                       // 16-byte RC4 key
cipher = RC4(key)                        // one stream per connection per direction
```

[V] `obfuscator.go:304-345`. The key length is 16, the seed message’s clear seed
field is 16 bytes, and the hash-iteration count is 6000, including the first
SHA1 pass. [V] Both ciphers start at byte offset 0 of the client seed message /
server’s first obfuscated byte, and are never reset before the OSSH layer is
torn down. [V]

### 1.3 TLS passthrough message (`obfuscator/passthrough.go`)

32-byte value that replaces the TLS `ClientHello.random` (see §5).

```text
key = HKDF-SHA256(ikm = obfuscatedKey, salt = "passthrough-obfuscation-key",
                  info = nil) -> 32 bytes
nonce = 16 random bytes
msg = nonce || HMAC-SHA256(key, nonce)[0:16]       // 32 bytes
verify: recompute HMAC over msg[0:16], constant-time compare msg[16:32]
```

With the time factor (`useTimeFactor=true`, used by TLS-OSSH and modern meek):
salt = `"passthrough-obfuscation-key" || LE64(period)` where
`period = (unixNow + timePeriod/2 + shift*timePeriod) / timePeriod`,
`timePeriod = 1200 s`, integer division; `shift ∈ {-1,0,1}` is checked by the
server (`passthrough.go:35-41`, `:52-77`, `:79-150`, `:157-199`). [V]
`timePeriodSeconds` is a test-overridable var (`passthrough.go:152-155`). [W]
fixture `tlsPassthrough` has exact key/msg bytes for a fixed nonce and time.

### 1.4 Transforms and prefix generation (tactics)

Two distinct uses:

1. **OSSH seed transform** (`transforms/obfuscatorSeedTransform.go:29-61`): the
   16-byte seed is hex-encoded to 32 ASCII chars, a `transforms.Spec` (list of
   `{regex, regex-generator}` pairs) is applied as a string replacement, output
   is hex-decoded and must be exactly 16 bytes, else the dial fails. [V]
   Example from tests: spec `{"^.{8}", "00000000"}` makes the first 4 seed bytes
   zero (`obfuscator_test.go:184-205`). [V]
2. **OSSH prefix** (`obfuscator.go:699-719`,
   `transforms/transforms.go:158-195`): a Spec with exactly one entry is
   evaluated **as a generator** (`ApplyPrefix(seed, minLength=24)`, byte mode),
   producing arbitrary prefix bytes; if generation yields `< 24` bytes, random
   padding from the prefix-seeded PRNG is appended up to 24. The returned
   `prefixLen` is the generator’s raw length, not 24. [V]

Spec generator syntax is Go regexp-generator syntax from
`psiphon/common/regen`; scoped spec selection uses `transforms.Specs.Select`
with `prng.Intn` (`transforms.go:121-156`). **Rust risk:** reimplementing the
`regen` grammar is a real porting task. If only plain OSSH (no prefix / no seed
transform) is required, none of this is needed. Prefix specs currently reach the
client only via signed tactics and default probability 0.0. [V]

### 1.5 Fragmentor (optional, innermost)

`fragmentor.Conn` (`psiphon/common/fragmentor/fragmentor.go:145-426`) wraps the
TCP conn **below** the OSSH/throttle layers (`psiphon/TCPConn.go:98-107`), so it
fragments already-obfuscated wire bytes. When enabled, on the first `Write` it
flips a weighted coin with `FragmentorProbability`; if true it selects
`bytesToFragment = Range(minTotalBytes,maxTotalBytes)`, then repeatedly writes
`Range(minWriteBytes,maxWriteBytes)` slices, sleeping
`Period(minDelay,maxDelay)` between slices, and writes the remainder unbounded
once the budget is exhausted (`fragmentor.go:291-407`). Defaults: probability
0.5 but `FragmentorMaxTotalBytes = 0`, which makes `NewUpstreamConfig` return
nil → fragmentation is **off by default** (`parameters.go:703-711`,
`fragmentor.go:110-118`). [V] It is a pure write-splitting/timing transform; it
never changes bytes and is irrelevant to a mock-peer test.

---

## 2. OSSH transport

Files: `psiphon/common/obfuscator/{obfuscator.go,obfuscatedSshConn.go,skipReader.go}`.

### 2.1 Server-side detection (what the client must produce)

Server `readPreamble` (`obfuscator.go:496-668`):

1. Read exactly `PREAMBLE_HEADER_LENGTH = 24` bytes (`obfuscator.go:50`,
   `:512-516`).
2. Treat bytes `[0:16]` as seed `S`; derive both RC4 ciphers; decrypt bytes
   `[16:24]` → `magic uint32 BE`, `paddingLength uint32 BE` (`:518-543`).
3. If `magic == 0x0BF5CA7E`: parse the plain seed-message form.
4. Else, if this is the first pass: compute the client prefix terminator
   `HKDF-SHA256(ikm=keyword, salt=first24bytes, info="client_to_server")` →
   16 bytes and `SkipUpToToken` (server-side scanning max `PREFIX_MAX_LENGTH =
   65536`, read buffer `PREFIX_TERM_SEARCH_BUF_SIZE = 8192`,
   `obfuscator.go:52-55`, `skipReader.go:52-114`); then restart at step 1 on the
   remaining stream (`obfuscator.go:634-664`). If no terminator is found the
   connection is rejected.
5. Validate `0 <= paddingLength <= OBFUSCATE_MAX_PADDING = 8192`
   (`:579-588`).
6. Read and RC4-decrypt `paddingLength` bytes (`:590-595`). If
   `paddingLength >= 32`, the first 32 padding bytes become the server’s
   downstream padding PRNG seed; otherwise the server picks a random seed
   (`:612-629`).
7. If a prefix was stripped, read and decrypt the prefix header (`:597-610`,
   `:744-787`).

**Important ordering:** the magic value is validated *before* acting on the
padding length, to avoid a chosen-ciphertext probing attack
(`obfuscator.go:529-533`). [V]

Seed replay rejection: with `SeedHistory` (default 24 h TTL, 1M entries,
`history.go:30-35`), a repeated seed is rejected unless
`DisableStrictHistoryMode` and the client IP matches a previous one
(`history.go:133-181`). OSSH dials use strict mode (`obfuscatedSshConn.go:178-182`);
the meek cookie path permits same-IP replay for retries
(`server/meek.go:1600-1603`). A Rust client must generate a fresh
`MakeSecureRandomBytes(16)` seed per dial and must not replay a seed after a
failed dial. [V]

If the preamble is invalid, the server discards all further bytes until the
client closes (`obfuscatedSshConn.go:193-201`). The client sees nothing
actionable: close and retry elsewhere. [V]

### 2.2 Client seed message (plain form)

Constants: `obfuscator.go:39-56`.

```text
offset  size  field
0       16    seed S                      (plaintext, random per dial)
16       4    magic 0x0BF5CA7E            (BE uint32) ┐
20       4    paddingLength (BE uint32)               ├ RC4(client_to_server)
24       N    padding bytes, N = paddingLength         ┘
total = 24 + N
```

Padding: `N = Range(minPadding, maxPadding)` inclusive, where the caller’s
requested min is clamped **up** to `prng.SEED_LENGTH = 32` if it is smaller,
max is clamped to `OBFUSCATE_MAX_PADDING = 8192`, and max must be `>= min`
(`obfuscator.go:170-190`). Real dials pass `ObfuscatedSSHMinPadding = 0` and
`ObfuscatedSSHMaxPadding = 8192` (`parameters.go:725-726`,
`tunnel.go:865-869`), so the effective range is `[32, 8192]`. Padding bytes come
from `prng.NewPRNGWithSeed(config.PaddingPRNGSeed).Padding(min,max)`
(`obfuscator.go:148`, `:390`). [V]

The RC4 keystream encrypts from the magic value onward, **not** the seed:
`clientToServerCipher.XORKeyStream(preamble[magicValueStartIndex:], ...)` where
`magicValueStartIndex = 16` (+ prefix region length when prefixed)
(`obfuscator.go:444-447`). [V]

Client writes this message on the first `Write()` call, before any SSH byte
(`obfuscatedSshConn.go:548-586`). `Write()` reports `len(buffer)` even though
bytes may be buffered (`:351-361`). [V]

### 2.3 Client seed message (prefixed form)

Layout (`obfuscator.go:347-450`, `:699-719`, `:721-742`):

```text
[ prefix[L] | terminator[16] ]        plaintext; L = max(24, P)
[ seed S (16) ]                       plaintext
[ RC4( magic(4) | paddingLength(4) | padding(N) | prefixHeader ) ]
```

- `P` = generated prefix length returned by `Spec.ApplyPrefix`; if `P < 24` the
  generated bytes are right-padded with PRNG padding to exactly 24, so
  `L = max(24, P)`. Prefix bytes are arbitrary. For the common short-prefix
  case `L = 24` and the plaintext region before the seed is 40 bytes; a long
  prefix (`P > 24`) makes it `P + 16`.
- terminator = `HKDF-SHA256(ikm=keyword ASCII, salt=first 24 bytes of prefix
  (including its padding), info="client_to_server")` → 16 bytes
  (`obfuscator.go:670-697`). The salt is exactly `prefix[0:24]`.
- The encrypted region starts at index `16 + L + 16` in the preamble
  (`magicValueStartIndex = 16 + len(prefix+terminator)`,
  `obfuscator.go:392`, `:409`). [V]
- prefix header, also encrypted, is written **after the padding**:

```text
offset  size  field
0       2     version = 0x0001 (BE uint16)
2       2     spec name length L (BE uint16)
4       L     spec name bytes (UTF-8/ASCII)
```

  `writePrefixHeader` (`obfuscator.go:721-742`); the comment above it says
  “4 byte spec-length” but the code writes `uint16 version` then `uint16
  length` — the code is authoritative: 2+2+name. [V] This discrepancy matters;
  a Rust implementation must emit `0001 000L name`.
- `PREFIX_MAX_HEADER_LENGTH = 4096` caps the name (`obfuscator.go:55`,
  `:726-728`, `:772-774`).

Client write split: it first writes `preamble[:prefixLen]` (the raw generated
prefix, i.e. only `P` bytes, *not* the 24-byte padded region), optionally sleeps
`OSSHPrefixSplitConfig`-derived delay, then writes `preamble[prefixLen:]`
(`${P...}` covered above). With no prefix, `prefixLen = 0` and the whole
preamble is written at once (`obfuscatedSshConn.go:548-586`). [V] The split delay is `PRNG(NewSaltedSeed(splitSeed, "obfuscated-ssh-prefix-split"))
.Period(minDelay,maxDelay)` and is client-side traffic shaping only; the server
concatenates the stream (`skipReader.SkipUpToToken` tolerates arbitrary
fragmentation) (`obfuscatedSshConn.go:560-579`, `dialParameters.go:2603-2619`). [V]

Server reply, when the client used a prefix: the server **always** answers with
its own prefix + terminator before the SSH version line. `makeServerPreamble`
uses the server spec named by the client’s prefix header; if unknown, it
generates a random 24-byte prefix (`obfuscator.go:452-483`), terminated with
`info="server_to_client"`. This reply is plaintext. Then the server’s
identification-line padding and SSH bytes are RC4(server_to_client)
(`obfuscatedSshConn.go:588-639`). [V]

Client prefix read (`obfuscatedSshConn.go:416-439`): if the client’s own
preamble had a prefix (`obfuscator.osshPrefixHeader != nil`), the client reads
24 bytes, computes the same terminator with `info="server_to_client"` over
those 24 bytes, and skips up to and including it, discarding the server prefix.
`SkipUpToToken` bounds: max 65536 bytes searched, 8192-byte read chunks
(`obfuscator.go:52-55`). Any bytes over-read while scanning must be buffered for
subsequent reads (Go implements this with `SkipReader`, `skipReader.go:18-50`);
a Rust implementation can use a `BufReader` plus its buffer as the pushback.
[V] [W] `serverPrefixReply` gives exact bytes for a fixed server spec/seed,
which is what a Rust mock-server test needs; the client must land exactly at
the terminator end.

### 2.4 SSH identification line / extra lines

Client write state `OBFUSCATION_WRITE_STATE_IDENTIFICATION_LINE` (`:97-105`):
bytes are buffered until the first `\r\n`; that line is RC4-encrypted and
written, then state becomes `KEX_PACKETS` (`:649-656`, `:807-815`). [V]

The server’s pre-version padding lines are generated as all-`0x00` bytes except
for the `\r\n` at each line end, with each line at most 512 bytes including the
CRLF (`obfuscatedSshConn.go:772-805`). [V]

Client read state `OBFUSCATION_READ_STATE_IDENTIFICATION_LINES` (`:444-464`):
reads one byte at a time with `SSH_MAX_SERVER_LINE_LENGTH = 1024` cap,
deobfuscating each byte, until a `\r\n`; lines are discarded until one starts
with `"SSH-"`. If the accepted line contains `"Ganymed"`, the client sets
`legacyPadding = true` (`:454-459`). [V] The extra pre-version lines are
permitted by RFC 4253 §4.2 and are RC4-encrypted like everything else
(`:772-805`). [V]

### 2.5 SSH packet framing and padding rewrite

Packet wire form (RFC 4253 §6) as parsed by this layer
(`obfuscatedSshConn.go:526-538`, `:888-905`):

```text
uint32 BE packet_length          // 1 .. SSH_MAX_PACKET_LENGTH = 262144
byte        padding_length       // must be < packet_length
byte[]      payload              // length = packet_length - padding_length - 1
byte[]      padding              // length = padding_length
messageLength = 4 + packet_length
```

Write path `extractSSHPackets` (`:817-886`):

1. While >= 5 buffered bytes: parse prefix; wait unless the full packet is
   present.
2. Detect `SSH_MSG_NEWKEYS = 21` as `payload[0]` (`:838-843`).
3. Compute extra padding:
   - normal (non-legacy): `extra = Intn(255 - padding_length + 1)` →
     `0..(255-padding_length)` inclusive (`:853-863`);
   - legacy (server version line contained `"Ganymed"`):
     `possible = (255 - padding_length) / 16`;
     `extra = Intn(possible) * 16` → `{0,16,...,(possible-1)*16}`
     (`:864-873`; this keeps the RFC 4253 block-size constraint).
4. Rewrite in place: `packet_length += extra`, `padding_length += extra`
   (`:877-880`); append `extra` random bytes from the derived padding PRNG
   (`:875`, `:882`).
5. RC4-encrypt the whole transformed packet and write it; the RC4 stream is
   continuous across packets (`:674-681`). [V]

Consequences for a Rust client:

- The SSH peer sees padding it did not generate — that is intentional, and both
  ends implement the same rewrite (the server does the same transform). The
  payload length is preserved (`payloadLength = packetLength - paddingLength -
  1` is invariant under the rewrite), so stock SSH parsing still works. [V]
- Padding can reach 255 bytes; `packet_length` grows by the same amount.
- Never apply the rewrite to packets after the client’s first `NEWKEYS`: when
  the client sends `NEWKEYS`, `writeState` becomes `FINISHED`; the NEWKEYS
  packet itself is rewritten, and any buffered bytes after it are written
  **unobfuscated** in the same `Write` (`:666-694`). Later `Write` calls go
  straight to the underlying conn (`:351-361`). [V]
- Read side: the client reads a packet as `5 + packet_length - 1` bytes total,
  deobfuscating the 5-byte prefix and then the remainder separately (two RC4
  calls on the same stream), and sets `readState = FLUSH` when payload[0] == 21
  (`:725-770`, `:466-476`). After buffered bytes drain, `readState = FINISHED`
  and subsequent reads pass through raw (`:478-499`, `:338-341`). [V]
- Read and write directions finish independently; the client may be reading
  plaintext SSH while still obfuscating its own writes until it sends NEWKEYS.

### 2.6 SSH version line and start-of-stream sequence

The OSSH layer does not generate SSH bytes; the SSH library above it does.
A standard client emits `SSH-2.0-<software>\r\n` as its first write
(RFC 4253 §4.2), and the Go client library builds KEXINIT after it has read the
server version. Practical ordering that both the Go implementation and a Rust
implementation should preserve:

1. `Write("SSH-2.0-...\r\n")` → sends OSSH preamble, then obfuscated version
   line.
2. Read server prefix (if any), then extra lines, then server `SSH-...` line;
   derive `legacyPadding` from the version line.
3. Send KEXINIT and other KEX packets (each rewritten as in §2.5).
4. Send `SSH_MSG_NEWKEYS`; obfuscation ends for writes.
5. Continue SSH; the layer is transparent from here.

Step 2 before step 3 matters only for the Ganymed workaround; the framing itself
is tolerant of interleaving, but `legacyPadding` must be known before the first
KEX packet is written. [V] (Comment at `obfuscatedSshConn.go:376-397` explains
why extra lines are tolerated by the Psiphon client.)

### 2.7 First bytes summary (client → server)

```text
no prefix:   seed16 | rc4c2s(magic4 | padlen4 | padding) | rc4c2s(SSH ident line) | rc4c2s(rewritten packets...) | plaintext-after-NEWKEYS
with prefix: prefix[L=max(24,P)] | term16 | seed16 | rc4c2s(magic4 | padlen4 | padding | prefixHeader) | ...same...
```

Server → client:

```text
[client-prefixed case] serverPrefix(>=24) | serverTerm16 | rc4s2c(ident-line padding lines) | rc4s2c(SSH ident line) | rc4s2c(rewritten packets...) | plaintext-after-server-NEWKEYS
[no-prefix case]                                           rc4s2c(SSH ident line) | ...
```

### 2.8 Errors / EOF / close

- `ObfuscatedSSHConn.Close()` cancels internal work and closes the underlying
  conn (`obfuscatedSshConn.go:364-367`). Once both states are `FINISHED`, the
  layer is byte-transparent. [V]
- Invalid packet prefixes (length out of range, `padding_length >=
  packet_length`) return errors and tear down the conn (`:888-905`). [V]
- A server that rejects the preamble sends nothing more and discards the
  stream; there is no error message on the wire. [V]

### 2.9 Rust implementation checklist (OSSH)

1. Fresh random 16-byte seed; optional seed transform (tactics).
2. Derive `RC4(SHA1^6001(S||keyword||dir)[0:16])` per direction.
3. Build seed message (optionally with prefix+terminator+header); encrypt from
   magic onward; write on first outbound write; optionally split prefix write.
4. If prefixed, read+discard server prefix+terminator before the server version
   line.
5. Parse/rewrite outbound SSH packets with extra padding until NEWKEYS sent;
   then raw.
6. Read: skip lines until `SSH-`, track Ganymed, deobfuscate KEX packets, stop
   at NEWKEYS; then raw.
7. Choose padding lengths using a CSPRNG in `[max(32,min), min(max,8192)]`
   (client), and extra padding per §2.5; no wire-visible PRNG compatibility
   needed.
8. Never reuse a seed; close and retry on any framing error.

---

## 3. Meek transport

Files: `psiphon/meekConn.go`, `psiphon/common/protocol/meek.go`,
`psiphon/server/meek.go` (server checks).

Meek tunnels a byte stream over sequential HTTP request/response bodies:
upstream bytes are request bodies, downstream bytes are response bodies, and a
cookie ties the requests into one server session. `MeekConn` implements
`net.Conn`; the OSSH layer sits on top of it. [V] `meekConn.go:59-62`:
`MEEK_PROTOCOL_VERSION = 4`, `MEEK_MAX_REQUEST_PAYLOAD_LENGTH = 65536`.

### 3.1 Modes relevant to the client

`meekConn.go:64-72`, `:74-260`:

- `MeekModeRelay` — tunnel protocol; cookie + payload padding; used for all
  `*-MEEK-*` tunnel protocols. [V]
- `MeekModeObfuscatedRoundTrip` — one-off request (tactics) with an obfuscated
  cookie and `EndPoint` in JSON. [V]
- `MeekModePlaintextRoundTrip` / `MeekModeWrappedPlaintextRoundTrip` — used by
  fronted HTTP (§4): no cookie, caller supplies the URL/request; additional
  headers are added. [V]

### 3.2 Obfuscated meek cookie (relay mode)

Built in `makeMeekObfuscationValues` (`meekConn.go:1924-2084`):

1. JSON (`encoding/json`, struct order, `omitempty`) of
   `protocol.MeekCookieData` (`protocol/protocol.go:907-912`):
   `{"v":4,"p":true,"t":"FRONTED-MEEK-OSSH","e":"tactics"}` — fields `v`, `p`,
   `t`, `e`; `p` present only when payload padding is enabled; `e` only for
   round-trip modes. [V] [W]
2. NaCl `box.Seal` with **24 zero bytes as nonce**, recipient = server entry
   `meekCookieEncryptionPublicKey` (base64 StdEncoding → 32 bytes), ephemeral
   X25519 keypair generated per cookie. Output = `ephemeralPub[32] ||
   ciphertext[16+len(json)]` (NaCl box overhead 16). [V]
3. Prepend an OSSH-style obfuscator seed message, built with
   `obfuscator.NewClientObfuscator{Keyword: meekObfuscatedKey,
   PaddingPRNGSeed: MeekObfuscatorPaddingSeed, MaxPadding:
   MeekCookieMaxPadding}` (`meekConn.go:1982-1993`). `IsOSSH` is false so no
   seed transform applies, but the same 16-byte seed + magic + padding-length +
   padding format and RC4 key derivation are used; min padding is still clamped
   to 32 (`obfuscator.go:177-190`), max defaults to 256
   (`parameters.go:828`). The encrypted cookie ciphertext is appended and
   RC4(client_to_server)-encrypted in the same stream:
   `cookieBytes = seedMsg[24+N] || RC4(box)`
   (`meekConn.go:1990-1994`). [V]
4. Base64 StdEncoding. Cookie name: either a uniformly random single letter
   `A`–`Z`, or a generated name from `values.GetCookieName`
   (`[a-z_]{2,10}`) — chosen by `MeekAlternateCookieNameProbability` (default
   0.5) with a PRNG derived from the padding seed
   (`GetDerivedPRNG("meek-cookie-name")`, `meekConn.go:1995-2012`,
   `values/values.go:238-246`). [V]
5. Content-Type: `application/octet-stream` or one of
   `audio/mpeg|image/jpeg|video/mpeg` via
   `values.GetContentType` with derived PRNG salt `"meek-content-type"` and
   probability 0.5 (`meekConn.go:2016-2024`, `values.go:256-264`). [V]
6. Traffic-shaping-derived values, all derived from the padding seed
   (`meekConn.go:2032-2080`):
   - `limitRequestPayloadLength`: `Range(min,max)` with salt
     `"meek-limit-request-payload-length"`; defaults both 65536 so it stays
     65536 unless tactics lower it. Bounds `[1, 65536]`; if payload padding is
     enabled and the limit equals 1 (prefix size), it is raised to 2. [V]
   - `tlsPadding`: `Range(min,max)` with salt `"meek-tls-padding"`, max clamped
     to 65535; defaults 0. [V]
   - `redialTLSProbability`: default 0.0. [V]

Server decode (`server/meek.go:1571-1639`): base64 StdEncoding; run
`NewServerObfuscator` over the bytes to consume the seed message, note the
reader offset, RC4-decrypt the rest with the same stream; take first 32 bytes as
ephemeral pubkey; `box.Open` with all-zero nonce and the server’s private key;
JSON parse. `DisableStrictHistoryMode` is set so same-IP cookie replay is
allowed for retries (`server/meek.go:1600-1603`). [V] [W] fixture `cookie` gives a complete
test instance (server private key is test-only).

### 3.3 HTTP request format (relay mode)

`meekConn.go:1528-1562` (`newRequest`) with `meek.url` built at `meekConn.go:695-702`:

```http
POST / HTTP/1.1
Host: <HostHeader>                      ; meek.url Host, e.g. fronting host
User-Agent: <dialConfig.CustomHeaders User-Agent, optional>
Content-Length: <exact body length>
Content-Type: <cookie-time content type>
Cookie: <name>=<base64 obfuscator+cookie value>
Range: bytes=<n>-                       ; only on retry
X-Psiphon-Fronting-Address: <IP>        ; optional, fronted only
<additional custom headers>
```

- Method is always `POST`; URL path is always `/` for relay mode (no query).
- Scheme is `https` for HTTPS/QUIC transports, `http` for
  `FRONTED-MEEK-HTTP-OSSH`.
- Header names are canonicalized by Go for HTTP/1.1; for HTTP/2 they are
  lowercased and `:method POST`, `:path /`, `:scheme https`,
  `:authority <HostHeader>` replace the request line. [I/V] (Go `net/http` +
  `x/net/http2`; the spec here fixes semantics, not HPACK byte layout.)
- `Content-Length` is always set explicitly for relay requests. Go adds
  `Content-Length: 0` for a `POST` with no body; a Rust client must do the same
  (the server reads the body as the upstream payload; it does not use chunked
  request bodies). The Go `MeekConn` sets `request.ContentLength` when > 0 and
  passes a `*readCloseSignaller` body otherwise (`meekConn.go:1640-1662`). [V]
  [W] exact HTTP/1.1 bytes in fixture `httpRequests`.
- Cookie is added on every request (`request.AddCookie`); the value changes to
  the server session ID after the first response (§3.4).
- `Range` is set only when retrying and only to `bytes=<receivedPayloadSize>-`
  (`meekConn.go:1672-1680`, `server/meek.go:960-984`); the expected status is
  then `206`, but `200` is also accepted (`meekConn.go:1708-1725`).
- Additional headers: `dialConfig.CustomHeaders` (HTTP only), `User-Agent`
  always copied for HTTP(S) fronted transports, optional
  `X-Psiphon-Fronting-Address`, plus `Config.MeekAdditionalHeaders`
  (`meekConn.go:705-745`, `:1857-1873`). For HTTPS, custom headers other than
  `User-Agent` are not added (comment `meekConn.go:705-720`). [V]

### 3.4 Response handling / session cookie / retries

`relayRoundTrip` (`meekConn.go:1573-1852`):

- Status: first attempt expects `200`; retries expect `206` (accepts `200`);
  anything else is fatal (`meekConn.go:1708-1725`). [V]
- Cookie update: for every `Set-Cookie` in the response whose name equals the
  meek cookie name, replace `meek.cookie.Value` (`meekConn.go:1724-1731`). The server sends
  this exactly once per session, with a random raw-base64 session ID of
  8–20 bytes (`server/meek.go:818-823`, `server/meek.go:2400-2412`). The client keeps the
  original cookie **name**; all later requests carry the session ID. The
  session-ID value is opaque (raw-base64, no padding) and must be sent back
  verbatim — do not base64-decode/re-encode it (`server/meek.go:2400-2412`). [V]
- Payload padding (if enabled): consume the padding header/padding from the
  **start of the response body** before relaying bytes (`meekConn.go:1748-1800`). Empty
  body is valid (`ErrMeekPaddingStateImmediateEOF` → success, zero payload).
  `receivedPayloadSize` includes consumed padding bytes so a retry `Range`
  position remains correct (`meekConn.go:1770-1782`). [V]
- Payload: body is read in chunks up to `readPayloadChunkLength` (default
  65536; limited mode 4096) and handed to `Read()` as it arrives
  (`meekConn.go:1875-1922`, `parameters.go:829-830`, `:830-831`). An empty body
  means “no downstream bytes now”. [V]
- Retry policy: at least one retry; retries while within
  `MeekRoundTripRetryDeadline` (default 5 s); delay starts at 50 ms, multiplied
  by 2.0 up to 1 s (`meekConn.go:1618-1662`, `:1820-1852`;
  `parameters.go:840-844`). If a payload was already accepted (status code
  received), retries omit the request body; if only part of the response body
  was read, the `Range` position resumes it. Server-side dedupe: the server
  checksums the request body and skips relaying an identical repeated body
  (`server/meek.go:2646-2656`). [V]
- The same padding cipher-stream state must persist across retries; padding is
  generated once per payload, not per attempt (`meekConn.go:1360-1395` comment
  and flow). [V] [W] padding vectors.

### 3.5 Polling, timeouts, flow control

- One HTTP request in flight per `MeekConn`; `Write` buffers upstream bytes into
  a send buffer capped at `limitRequestPayloadLength`; `relay` sends when data
  is available or when the poll timer fires (`meekConn.go:1285-1475`,
  `:1186-1217`). [V]
- Poll interval starts at `Jitter(MeekMinPollInterval=100 ms, jitter 0.3)` =
  `[70,130] ms`; after activity it becomes 0 (immediate next request); when
  idle it decays: with probability 0.5 multiply by 1.5, apply ±10 % jitter,
  and cap at 5 s ±10 % (`meekConn.go:1448-1470`, `parameters.go:833-839`).
  [V] These are heuristics; exact values are not wire-protocol.
- Response body read may be very large; downstream is streamed, not buffered
  whole. Upstream request body is at most 64 KiB (or lower when traffic shaping
  sets the limit).
- Timeouts: `MeekRoundTripTimeout` 20 s per request (soft; server session
  staleness 45 s) (`parameters.go:844`, server `meek.go:89`); HTTP server I/O
  timeouts are server-side. [V]
- Multiplexing: each tunnel protocol dial creates one `MeekConn` = one HTTP
  session (one cookie). Multiple tunnels = multiple `MeekConn`s. A single
  `MeekConn` is not shared between layers. [V]

### 3.6 Request payload padding (protocol v4, optional)

`protocol/meek.go`; enabled only when tactics set
`MeekPayloadPaddingProbability > 0`, default 0.0
(`dialParameters.go:1137-1156`, `parameters.go:1279-1283`). When enabled, the
cookie JSON has `"p":true` and both request and response bodies are prefixed.

Key derivation per direction (`protocol/meek.go:131-191`):

```text
key = HKDF-SHA256(ikm = obfuscatedMeekKey, salt = obfuscatedMeekCookie
                  (the ORIGINAL cookie value, before session-ID replacement),
                  info = "meek-payload-padding-requests"
                       | "meek-payload-padding-responses") -> 32 bytes
AES-256-CTR with a 16-byte all-zero IV; a single continuous stream per direction
```

[V] The padding header is the ciphertext of:

```text
0x00                       NoPadding prefix (1 byte)
--- or ---
0x01 || uint16 BE size     Padding prefix; followed by `size` random bytes
```

Sender behavior per payload (`protocol/meek.go:193-242`): with
`omitPaddingProbability`, an empty payload may produce an *entirely empty* body.
For a non-empty payload the sender emits just the 1-byte NoPadding prefix and
then the real payload; for an empty payload it emits a full padding header +
padding (or nothing). Receiver (`:244-383`) consumes exactly one padding unit at
the start of the body, holding state across 1-byte reads; empty body yields
`ErrMeekPaddingStateImmediateEOF` (valid). [V] [W] fixture `payloadPadding`
contains the AES key/keystream, the deterministic NoPadding header byte, and a
captured padded header (random size) plus a full sender→receiver feed.

Important: padding states are created once per `MeekConn` from the **initial
cookie value**; after the cookie is replaced by a session ID, do **not**
re-derive. Server does the same (`server/meek.go:1303-1318`). [V]

### 3.7 Server checks / client musts (meek)

Server (`server/meek.go`):

- optional required headers must match configured values, else the TCP
  connection is terminated (`server/meek.go:544-580`);
- exactly the expected cookie must be present; requests without a cookie are
  rejected (except in-proxy broker mode) (`:583-609`);
- prohibited headers are rejected (`:611-623`);
- cookie decode/decrypt must succeed (§3.2); `MeekProtocolVersion` gates v1 vs
  v2+ session-ID behavior (`:1349-1355`);
- rate limit for new tunnel sessions/tactics; `CheckEstablishTunnels`;
  server-side fronting-provider restrictions (`:1160-1260`);
- relay requests must carry the session-ID cookie; unknown cookies are
  re-attempted as meek cookies (`:995-1045`).

Client must: send cookie on every request, update it from `Set-Cookie`,
use `POST /`, correct `Content-Length`, accept `200`/`206`, retry with
`Range` only after partial response, treat empty bodies as valid, and keep
padding-stream state across retries.

---

## 4. Fronted HTTP (`psiphon/frontedHTTP.go` + `frontingDialParameters.go`)

`frontedHTTPClientInstance` is an `http.RoundTripper` used for non-tunnel HTTP
requests (“untunneled” API, server-list and upgrade downloads; it may also be
tunneled through a `Tunnel`). It **does not invent a new wire protocol**: it
builds fronted-meek dial parameters and delegates to a `MeekConn` in
`MeekModePlaintextRoundTrip` (or `WrappedPlaintextRoundTrip`) then calls
`conn.RoundTrip(request)` (`frontedHTTP.go:163-229`, `net.go:485-535`). [V]
Each `RoundTrip` establishes a **new** `MeekConn` (new TLS/TCP dial, request
context bound), and the connection is closed when the response body is closed
(`frontedHTTP.go:174-206`, `net.go:536-570`). [V]

Per-request behavior:

- The caller’s URL/method/headers/body are used, except that headers from the
  dial config are added and a configured `Host` overrides `request.Host`
  (`MeekConn.RoundTrip` clones the request and calls `addAdditionalHeaders`;
  `meekConn.go:1139-1160`, `:1857-1873`). [V]
- Dial/TLS destination = `FrontingDialAddress` from the fronting spec, port 443
  if absent (`frontingDialParameters.go:119-155`, `:149-155`). The HTTP request
  line/Host do not reveal the real server IP. [V]
- SNI = `SNIServerName` from the fronting spec; it may be `""` to omit SNI
  (`serverEntry.MeekFrontingDisableSNI`, `dialParameters.go:1575-1589`), may be
  transformed to a random plausible hostname with probability 0.5
  (`TransformedHostName`, `frontingDialParameters.go:166-176`), and is omitted
  for IP literals (`dialParameters.go:1600-1615`). [V]
- `Host` header = fronting spec `HostHeader` (a CDN virtual host). For
  `FRONTED-MEEK-HTTP` the Host header is never transformed
  (`dialParameters.go:1585-1592`). [V]
- Optional `X-Psiphon-Fronting-Address: <real fronting dial host/IP>` header
  when enabled by tactics (`meekConn.go:727-745`,
  `frontingDialParameters.go:387-405`). [V]
- TLS verification: `SkipVerify` when no `VerifyServerName`; pinning by
  base64 SHA-256 SPKI via `VerifyPins` is possible; `payloadSecure` (wrapped
  mode) permits verification skipping because the payload has its own
  security layer (`frontingDialParameters.go:106-108`, `:287-289`). [V]
- TLS fingerprint: uTLS profile chosen by `tlsdialer.SelectTLSProfile`; ALPN
  `h2` or `http/1.1` is negotiated on a pre-dial and selects
  `http2.Transport` vs `http.Transport` (`meekConn.go:540-620`). [V] A Rust
  client using rustls will have a different ClientHello fingerprint; this is a
  blocking risk to note, not a wire-spec requirement.
- ClientHello may be fragmented at the SNI boundary (probability-gated,
  `TLSFragmentClientHello`, `tlsdialer/clientHelloFragmentation.go`), and the
  TLS passthrough message is inserted when `MeekObfuscatedKey != ""`
  (`meekConn.go:518-545`). [V]

Tunnel dial parameters for fronted meek (`MeekDialAddress`, `HostHeader`,
`SNIServerName`) are selected in `dialParameters.go:1569-1615`; fronting
address/host from the server entry in `dialParameters.go:2260-2305`
(`MeekFrontingAddresses`, `MeekFrontingAddressesRegex`, `MeekFrontingHosts`,
`MeekFrontingHost`), overridable by signed fronting specs
(`frontingDialParameters.go:88-155`). [V]

---

## 5. TLS tunnel (TLS-OSSH)

`psiphon/tlsTunnelConn.go`, selected for `TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH`
(`"TLS-OSSH"`), port `TlsOSSHPort` (`tunnel.go:1042-1053`,
`serverEntry.go:71`).

1. TCP to the direct server IP:port (`dialParameters.go:1569-1580`).
2. TLS handshake with uTLS: `SNIServerName = TLSOSSHSNIServerName`, which may be
   a transformed random hostname (probability 0.5) or omitted for IP literals;
   certificate verification is **disabled** (`SkipVerify: true`); TLS profile
   from tactics; optional ClientHello fragmentation; optional obfuscated
   session tickets with key = `ServerEntry.MeekObfuscatedKey` and probability
   0.5 (`dialParameters.go:996-1020`, `:1961-1992`;
   `tlsTunnelConn.go:77-96`). [V]
3. The 32-byte TLS passthrough message replaces `ClientHello.random`:
   `MakeTLSPassthroughMessage(useTimeFactor=true, ObfuscatedKey =
   ServerEntry.MeekObfuscatedKey)` (`tlsTunnelConn.go:98-109`; §1.3). [V]
4. Optional TLS padding extension (RFC 7685, extension type 21): length
   `TLSPadding` computed as
   `PRNG(NewSaltedSeed(ObfuscatorPaddingSeed, "tls-padding")).Range(min,max)`
   when `TLSTunnelTrafficShapingProbability` coin succeeds; `max` clamped to
   65535; defaults min=max=0 so no padding unless tactics change them
   (`tlsTunnelConn.go:125-159`, `tunnel.go:871-874`,
   `parameters.go:1067-1070`). The extension is moved/added **first** in the
   extension list, and its body is `paddingLength` zero bytes
   (`tlsdialer/dialer.go:644-679`; uTLS `UtlsPaddingExtension`;
   `tlsdialer/dialer.go:169-172`, `:182-185`). [V] [W] `tlsTunnel` fixture.
5. After the TLS conn is established, the OSSH layer of §2 is applied on top
   (keyword = `SshObfuscatedKey`, fresh padding seed) — from OSSH’s point of
   view TLS is just a byte pipe. [V]

There is no application-level framing in `TLSTunnelConn` itself; `Read`/`Write`
are inherited from the embedded `net.Conn` (`tlsTunnelConn.go:50-54`). [V]
EOF/close is the TLS conn’s close semantics; metrics expose `tls_padding`
(`:161-180`).

---

## 6. Shadowsocks-OSSH (brief)

`psiphon/shadowsocksConn.go`, protocol `"SHADOWSOCKS-OSSH"`
(`protocol.go:39`, `:398-401`), port `SshShadowsocksPort`.

- Cipher is `CHACHA20-IETF-POLY1305` with password = `ServerEntry.SshShadowsocksKey`
  (used as a shadowsocks password string, not base64/hex decoded)
  (`shadowsocksConn.go:54-58`). The framing is the standard shadowsocks AEAD
  stream (vendor: `github.com/Jigsaw-Code/outline-sdk v0.0.16`,
  `go.mod:19`): per direction `salt[32] || AEAD(chunk_len)[tag] ||
  AEAD(payload)[tag]`, 16-byte tags, little-endian uint16 chunk length, max
  chunk 0x3FFF. [I] (external dependency, not in this repo).
- Optional prefix: a generated `ShadowsocksPrefixSpec` of at most 16 bytes is
  installed with `NewPrefixSaltGenerator` and prepended to each direction’s
  salt (`shadowsocksConn.go:68-84`, `:119-135`); longer prefixes are a fatal
  error. [V] Prefix probability defaults to 0.0 (`parameters.go:1063`).
- OSSH runs on top of the shadowsocks conn exactly as in §2. [V]

---

## 7. Test vectors (Rust-ready)

Location: `.research/wire-vectors/fixtures/`.

| file | contents | covers |
|---|---|---|
| `ossh-vectors.json` | key derivation, RC4 keystream, plain/prefixed seed messages, prefix terminator, server prefix reply, index/string constants, TLS passthrough messages, **complete client→server OSSH wire capture** of ident line + KEXINIT + NEWKEYS + post-KEX plaintext | OSSH handshake, framing, padding rewrite, state transitions |
| `meek-vectors.json` | full obfuscated cookie (value + decoded layout + NaCl plaintext JSON), payload-padding cookie variant, obfuscated-round-trip cookie JSON, exact HTTP/1.1 request bytes (initial/poll/retry), payload-padding key/keystream/headers, TLS tunnel padding cases | meek cookie codec, request format, retry `Range`, padding, TLS-OSSH padding |
| `README.md` | schema + how to regenerate/replay | — |

Every vector states its fixed inputs and expected output bytes; the generator is
deterministic for everything except fields that Go itself generates randomly
(OSSH seed, NaCl ephemeral key, cookie padding sizes); those are captured and
validated against the algorithm’s invariants (magic value, box open, lengths,
prefix/size fields). All generated by overlay tests that call the real Go code
(see `README.md`); the source files under `.research/wire-vectors/go/` are the
generators and double as executable documentation.

Recommended Rust tests derived from the fixtures:

1. `obfuscator::derive_key` — compare `keyDerivation` keys and first 64 bytes
   of each RC4 stream.
2. `obfuscator::build_plain_preamble` — feed fixed seed/keyword/padding PRNG
   stream (or simply assert the parsed structure of the captured bytes) and
   compare `preambleHex`; assert decrypted `magic`/`paddingLength`.
3. `obfuscator::build_prefixed_preamble` — compare `preambleHex`,
   `terminatorHex`, and that the prefix header decrypts to
   `0001 0007 "zero-24"`.
4. `obfuscator::client_read_server_prefix` — feed `serverPrefixReply.replyHex`
   to the client prefix-reader; it must land exactly after the 16-byte
   terminator.
5. `obfuscator::framing` — replay `osshFraming.wireHex` through a mock server
   decoder: decrypt, parse ident line, parse the two rewritten packets, assert
   `packetLength`/`paddingLength`/`payloadHex`, assert trailing plaintext; then
   re-encode from `inputs` + padding choices and get identical bytes.
6. `obfuscator::state_machine` — assert `writeTrace[i].writeStateAfter` for each
   step (enum values: `CLIENT_SEND_PREAMBLE=0`,
   `SERVER_SEND_PREFIX_AND_IDENTIFICATION_LINE_PADDING=1`,
   `IDENTIFICATION_LINE=2`, `KEX_PACKETS=3`, `FINISHED=4`).
7. `tls_passthrough` — recompute nonce||HMAC from fixed inputs and compare both
   time-factor variants.
8. `meek::cookie_decode` — base64 → seed message (parse magic/padlen) →
   RC4-decrypt → split ephemeral pub → NaCl box open with the fixture’s
   test-only private key → compare JSON bytes exactly; also compare cookie
   name/content-type for the fixed padding seed.
9. `meek::http_request` — build the request from the fixture inputs and compare
   byte-for-byte with `httpRequests.*` (HTTP/1.1; CRLF; header order as Go
   emits it: `Host`, `User-Agent`, `Content-Length`, `Content-Type`, `Cookie`,
   `Range`, `X-Psiphon-Fronting-Address`). Treat header-order/HTTP/2
   differences as acceptable only if the test normalizes; the fixture is the
   Go order.
10. `meek::payload_padding` — derive AES-256-CTR key from the fixture, assert
    `noPaddingHeaderHex`, decrypt `capturedPaddedHeaderHex` to prefix 1 and the
    stated size, and run the receiver state machine over `consumeFeed*Hex`.
11. `tls_tunnel::padding` — reproduce `tlsTunnel.cases[*].paddingLength` with a
    ChaCha20+Go-`rand` implementation if exact replay is wanted (otherwise use
    only as documentation of ranges).

---

## 8. Risk register and Rust module boundaries

### 8.1 Riskiest ambiguities / porting risks

1. **`regen` (regex generator) parity** for tactics-driven OSSH prefixes and
   seed transforms. The prefix bytes are arbitrary, so a wrong generator only
   breaks the dial, but the engine (Go regexp syntax + generator flags
   `OneLine|NonGreedy`, byte mode) must match. Mitigation: ship without prefix
   transforms first (valid), add a limited generator for known tactics specs.
   [V/I]
2. **Go `math/rand` + ChaCha20 replay parity.** Not needed for interop; needed
   only for bit-exact re-execution of a recorded Go dial. The wire accepts any
   valid padding. [V]
3. **HTTP header/host details on the CDN path.** `Host` = fronting host, SNI =
   fronting SNI (possibly empty/transformed), `X-Psiphon-Fronting-Address`
   optional, TLS fingerprint from uTLS. CDNs may require EXACT header casing
   /HTTP version behavior; HTTP/2 converts to lowercase headers/HPACK, which is
   transport-defined rather than protocol-defined. [V/I]
4. **Doc/code mismatch** in the prefix header: comment says 4-byte spec length,
   code writes `uint16 version` + `uint16 name length`. Trust the code. [V]
5. **`MEEK_PROTOCOL_VERSION` coupling:** cookie must be v4 for payload padding
   (`p:true`); server rejects padding on tunnels whose protocol is excluded by
   `MeekPayloadPaddingLimitTunnelProtocols`, and rejects payload padding when
   server tactics are absent (`server/meek.go:1283-1301`). [V]
6. **Padding-stream state across retries/cookies:** if a retry re-generates the
   padding header instead of resending the same bytes, the AES-CTR streams
   desynchronize and the server sees garbage padding → disconnect. Generate
   padding once per payload and cache it for retries. [V]
7. **Seed replay detection:** server rejects duplicate OSSH seeds (24 h,
   cross-IP strict). Any client retry must be a brand-new connection with a
   new seed (and new padding seed). [V]
8. **TLS fingerprint / certificate verification:** Psiphon accepts any cert for
   fronted/TLS-OSSH payloads (payload has its own security), but uTLS profile
   parity and ClientHello fragmentation/padding/passthrough must be emitted for
   censorship resistance; not needed for byte-level correctness against the
   origin server. [V/I]
9. **Ports/flags:** `disableOSSHPrefix` / `disableOSSHTransforms` on the server
   entry override tactics; `TlsOSSHPort == 0` fallback logic exists for legacy
   entries (`serverEntry.go:760-830`). [V]

### 8.2 Recommended Rust module boundaries

```text
zray-transport/
  prng/            Seed[32], ChaCha20 stream, HKDF-SHA256 salted seeds,
                   optional Go-rand-compatible Range/Intn (replay-only feature)
  ossh/
    cipher.rs      RC4 (vetted crate) + derive_key,
                   direction ciphers, stream ordering
    seedmsg.rs     plain + prefixed seed message, magic/padding validation,
                   prefix header codec, prefix terminator HKDF
    framing.rs     SSH packet parse/rewrite, extra-padding policy (normal/legacy),
                   NEWKEYS detection, read/write state machine
    conn.rs        AsyncRead/AsyncWrite wrapper: preamble on first write,
                   prefix read/skip, ident-line scan/skip, buffering/flush
  transforms/      (optional) regen-compatible prefix/seed transform engine;
                   server-entry flag gating; probability selection
  prefix.rs        OSSHPrefixSpec / ShadowsocksPrefixSpec evaluation + terminator
  fragmentor.rs    write splitting/timing transform (client policy)
  meek/
    cookie.rs      MeekCookieData JSON, NaCl box (all-zero nonce), seed-message
                   obfuscation + base64, cookie name/content-type derivation
    padding.rs     MeekPayloadPaddingState: AES-256-CTR key/stream, sender,
                   receiver state machine (1-byte-at-a-time capable)
    http.rs        request builder (POST /, Host, Content-Type, Cookie, Range,
                   Content-Length), HTTP/1.1 + h2 client, response status/cookie
                   handling, body streaming chunks
    relay.rs       net.Conn semantics: single in-flight request, send/receive
                   buffers, poll loop/jitter/timeouts, retry policy + Range,
                   padding-stream lifecycle
  fronted_http.rs  fronted-meek dial-parameter mapping over meek RoundTrip;
                   SNI vs Host, X-Psiphon-Fronting-Address, TLS verification policy
  tls_tunnel.rs    TLS dial with passthrough ClientHello random + optional
                   RFC 7685 padding extension + obfuscated tickets; returns
                   a byte pipe consumed by ossh::conn
  shadowsocks.rs   chacha20-ietf-poly1305 stream + <=16-byte salt prefix
  protocol.rs      tunnel protocol table, server-entry field accessors,
                   port selection, layer-stack construction (the only module
                   that knows which transports combine)
```

Keep `ossh` transport-agnostic (it takes any `AsyncRead+AsyncWrite`), and keep
meek/TLS/shadowsocks as byte pipes: this mirrors the Go layering
(`tunnel.go:1020-1142`) and lets one `ossh` implementation serve all four
protocol stacks. Put all server-entry flag/probability decisions in
`protocol.rs`/`transforms`, never inside `ossh`.

---

## Appendix A — Constants (exhaustive, with citations)

| constant | value | source |
|---|---|---|
| `OBFUSCATE_SEED_LENGTH` | 16 | `obfuscator.go:40` |
| `OBFUSCATE_KEY_LENGTH` | 16 | `:41` |
| `OBFUSCATE_HASH_ITERATIONS` | 6000 | `:42` |
| `OBFUSCATE_MAX_PADDING` | 8192 | `:43` |
| `OBFUSCATE_MAGIC_VALUE` | `0x0BF5CA7E` | `:44` |
| direction strings | `client_to_server`, `server_to_client` | `:45-46` |
| `PREAMBLE_HEADER_LENGTH` | 24 | `:50` |
| `PREFIX_TERMINATOR_LENGTH` | 16 | `:52` |
| `PREFIX_TERM_SEARCH_BUF_SIZE` | 8192 | `:53` |
| `PREFIX_MAX_LENGTH` | 65536 | `:54` |
| `PREFIX_MAX_HEADER_LENGTH` | 4096 | `:55` |
| prefix header version | `0x0001` (BE u16) | `:729` |
| `prng.SEED_LENGTH` | 32 | `prng.go:65` |
| `TLS_PASSTHROUGH_MESSAGE_SIZE` | 32 | `passthrough.go:40` |
| `TLS_PASSTHROUGH_NONCE_SIZE` | 16 | `:36` |
| `TLS_PASSTHROUGH_KEY_SIZE` | 32 | `:37` |
| `TLS_PASSTHROUGH_TIME_PERIOD` | 20 min (1200 s) | `:38` |
| `SSH_MAX_SERVER_LINE_LENGTH` | 1024 | `obfuscatedSshConn.go:39` |
| `SSH_PACKET_PREFIX_LENGTH` | 5 | `:40` |
| `SSH_MAX_PACKET_LENGTH` | 262144 | `:41` |
| `SSH_MSG_NEWKEYS` | 21 | `:42` |
| `SSH_MAX_PADDING_LENGTH` | 255 | `:43` |
| `SSH_PADDING_MULTIPLE` | 16 | `:44` |
| `MEEK_PROTOCOL_VERSION` | 4 | `meekConn.go:60` |
| `MEEK_MAX_REQUEST_PAYLOAD_LENGTH` | 65536 | `:61` |
| padding prefixes / directions | 0 / 1; `meek-payload-padding-requests` / `-responses` | `protocol/meek.go:37-41` |
| `MeekPayloadPaddingPrefixSize` | 1 | `:48` |
| server session-ID length | 8–20 bytes raw, base64 RawStd | `server/meek.go:90-91`, `:2400-2412` |
| `MEEK_MAX_REQUEST_PAYLOAD_LENGTH` (server) | 65536 | `server/meek.go:89` |
| server `MEEK_DEFAULT_MAX_SESSION_STALENESS` | 45 s | `server/meek.go:95` |

## Appendix B — State enums (client-side)

Write states (`obfuscatedSshConn.go:97-105`):

| value | name | meaning |
|---|---|---|
| 0 | `CLIENT_SEND_PREAMBLE` | first write: emit seed message (client only) |
| 1 | `SERVER_SEND_PREFIX_AND_IDENTIFICATION_LINE_PADDING` | server-only initial state |
| 2 | `IDENTIFICATION_LINE` | buffering/encrypting the SSH version line until CRLF |
| 3 | `KEX_PACKETS` | parse/rewrite/encrypt packets until the first `NEWKEYS` written |
| 4 | `FINISHED` | byte-transparent |

Read states (`:87-95`):

| value | name | meaning |
|---|---|---|
| 0 | `CLIENT_READ_PREFIX` | client-only, when it sent a prefix: skip server prefix+terminator |
| 1 | `IDENTIFICATION_LINES` | read/deobfuscate lines, drop non-`SSH-` lines, set Ganymed flag |
| 2 | `KEX_PACKETS` | read/deobfuscate packets until peer `NEWKEYS` |
| 3 | `FLUSH` | peer NEWKEYS seen; return buffered bytes |
| 4 | `FINISHED` | byte-transparent |

## Appendix C — Vector generator provenance

Generators (not part of the reference repo):

- `.research/wire-vectors/go/obfuscator_wiregen_test.go` — injected into
  `package obfuscator` via `go test -overlay` and writes `ossh-vectors.json`.
- `.research/wire-vectors/go/meek_wiregen_test.go` — injected into
  `package psiphon` and writes `meek-vectors.json`.
- `.research/wire-vectors/overlay-*.json` — Go `-overlay` maps; the reference
  clone is never modified.
- `.research/wire-vectors/generate.sh` — pinned command lines (Go 1.26.9
  required because Psiphon vendors a patched `crypto/tls` and the module can
  panic on other toolchain versions).

Vectors were generated against the reference commit named at the top; the Go
code paths exercised are the same ones used by the real client.
