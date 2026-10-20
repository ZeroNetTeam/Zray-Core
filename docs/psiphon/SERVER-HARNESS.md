# Local Psiphon server harness (real `psiphond` on loopback)

Status: **working**. A real `psiphond` built from the pinned
`psiphon-tunnel-core` checkout runs on `127.0.0.1`, accepts tunnels over
`SSH`, `OSSH` and `TLS-OSSH`, and a client (tested with the Go ConsoleClient
*and* with `Zray-Core/crates/zero-psiphon`) can carry a TCP stream through it
to a loopback origin and back.

Everything lives in `.research/psiphon-server-harness/` (scripts, generated
configs, keys, certs, signed server entry, evidence logs). This document is the
recipe and the interop notes.

No Zray-Core source is modified by the harness, and nothing here is committed;
`.research/psiphon-server-harness/.gitignore` excludes generated keys and
state.

---

## 1. What works (verified)

| Check | Result |
| --- | --- |
| `psiphond` starts and listens on loopback | yes: SSH `127.0.0.1:20081`, OSSH `127.0.0.1:20082`, TLS-OSSH `127.0.0.1:20083`, unfronted meek-over-TLS `127.0.0.1:20087`, fronted meek (behind a local CDN stand-in) `127.0.0.1:20091` |
| Signed server entry verifies in the Go client | yes (negative test with the wrong key is rejected) |
| Go ConsoleClient over **SSH** → origin | yes, marker `psiphon-harness-marker` |
| Go ConsoleClient over **OSSH** → origin | yes |
| Go ConsoleClient over **TLS-OSSH** → origin | yes |
| Go ConsoleClient over **unfronted meek** → origin | yes (§9.5) |
| Rust `zero-psiphon` plain-SSH carrier → real `psiphond` | yes: entry signature verified in Rust, RSA host key pinned, JSON credential payload accepted, `psiphon-handshake` accepted, `direct-tcpip` to the origin returned the marker |
| Rust `zero-psiphon` **meek** carrier → real `psiphond` | yes (§9.5): `tests/meek.rs`, `./verify-meek.sh` |
| Rust `zero-psiphon` **fronted meek** carriers (`FRONTED-MEEK-OSSH`, `FRONTED-MEEK-HTTP-OSSH`) through a local fronting provider → real `psiphond` | yes (§9.6): `tests/fronted_meek.rs`, `./verify-fronted.sh` |
| Internet egress through the tunnel (`https://example.com/`) | yes (HTTP 200) when the host has egress |
| Non-interactive one-shot verification | `./verify.sh` (add `--internet` for the egress check) |

Reproduce all of it with:

```bash
cd .research/psiphon-server-harness
./setup.sh
./verify.sh --internet
# =>  PASS SSH / OSSH / TLS-OSSH / signature-rejection / internet-egress
```

---

## 2. Harness layout

```
.research/psiphon-server-harness/
├── setup.sh              # build + generate config/keys + sign entry + write client configs + capture certs
├── run.sh                # start psiphond (--origin: also start the loopback HTTP origin)
├── stop.sh               # idempotent teardown (client, origin, psiphond, fronting providers)
├── status.sh             # pids / listeners / last log lines
├── run-client.sh         # run the Go ConsoleClient against the harness (foreground or --daemon)
├── verify.sh             # start -> per-protocol end-to-end test -> signature negative test -> stop
├── verify-rust.sh        # same, against the Rust client (tests/real_server.rs)
├── verify-meek.sh        # same, against the Rust meek carrier (tests/meek.rs, §9.5)
├── verify-fronted.sh     # same, against the Rust fronted meek carriers through a local CDN edge (§9.6)
├── capture-certs.sh      # capture live TLS-OSSH cert + SSH host key into certs/
├── env.sh                # shared paths, ports, process helpers (sourced, not executed)
├── tools/
│   └── fronting-provider.py  # local stand-in for a CDN edge: TLS (or plain) in, HTTP to psiphond (§9.6)
├── gotools/
│   ├── go.mod
│   └── sign-server-entry/  # stdlib-only re-signer for server entries
├── config/               # generated: psiphond.config, keys, entries, client configs
│   ├── psiphond.config
│   ├── psiphond-traffic-rules.config
│   ├── psiphond-osl.config
│   ├── psiphond-tactics.config
│   ├── server-entry.dat                     # unsigned, hex (what `psiphond generate` writes)
│   ├── server-entry.json                    # unsigned, decoded JSON object (Rust `from_json`)
│   ├── server-entry-signed.dat              # signed, hex (Go ConsoleClient -serverList)
│   ├── server-entry-signed.json             # signed, one-element JSON array (Rust `from_json_array`)
│   ├── server-entry-signature.key / .pub    # harness Ed25519 signing key pair (test-only)
│   └── psiphon-client-{SSH,OSSH,TLS-OSSH,UNFRONTED-MEEK-HTTPS-OSSH}.config
├── certs/
│   ├── tls-ossh-cert.pem / .full.txt / .info.txt
│   ├── ssh-host-key-keyscan.pub
│   └── server-entry-signature.pub
├── origin/               # docroot of the loopback test origin (marker.txt)
├── rustcheck/            # out-of-tree Rust interop checker (path-dep on zero-psiphon)
├── bin/                  # built binaries (psiphond, psiphon-tunnel-core-client)
├── logs/                 # psiphond.log, origin.log, verify-client-*.log, evidence
├── run/                  # pid files
├── clientdata/           # ConsoleClient data stores (one per test)
└── .cache/               # Go toolchain/module/build caches (self-contained, 300+ MB)
```

Ports (all loopback, deliberately in 20000–29999, away from Zray-Core test
ports; override with `PSH_*_PORT` before running the scripts):

| Purpose | Port | Override |
| --- | --- | --- |
| Plain SSH tunnel | `20081` | `PSH_SSH_PORT` |
| Obfuscated SSH (OSSH) tunnel | `20082` | `PSH_OSSH_PORT` |
| TLS-obfuscated SSH (TLS-OSSH) tunnel | `20083` | `PSH_TLS_OSSH_PORT` |
| Go client SOCKS (OSSH config) | `20084` | `PSH_SOCKS_PORT` |
| Loopback HTTP origin (test destination) | `20085` | `PSH_ORIGIN_PORT` |
| Go client SOCKS (SSH config) | `20086` | `PSH_SOCKS_PORT + 2` |
| Unfronted meek-over-TLS tunnel | `20087` | `PSH_MEEK_PORT` |
| Go client SOCKS (signature negative test) | `20088` | `PSH_SOCKS_PORT + 4` |
| Go client SOCKS (TLS-OSSH config) | `20089` | `PSH_SOCKS_PORT + 5` |
| Go client SOCKS (meek config) | `20090` | `PSH_SOCKS_PORT + 6` |
| Fronted meek listener (`FRONTED-MEEK-OSSH`, TLS: the CDN's origin hop) | `20091` | `PSH_FRONTED_MEEK_OSSH_PORT` |
| `FRONTED-MEEK-HTTP-OSSH`: configured, deliberately no listener (§9.6) | `20092` | `PSH_FRONTED_MEEK_HTTP_OSSH_PORT` |
| Local fronting provider, TLS (the CDN edge a fronted client dials in place of `:443`) | `20443` | `PSH_FRONTING_PORT` |
| Local fronting provider, plain TCP (in place of `:80`) | `20480` | `PSH_FRONTING_HTTP_PORT` |
| Local fronting provider → origin (edge self-check, §9.6) | `20445` | `PSH_FRONTING_SELFCHECK_PORT` |

A client's SOCKS proxy must not share a port with a server listener: the
meek listener takes `PSH_MEEK_PORT` (20087), so the TLS-OSSH client's SOCKS
proxy moved from `PSH_SOCKS_PORT + 3` to `+ 5` and the meek client's to `+ 6`.

The origin serves `origin/marker.txt`, whose content is
`psiphon-harness-marker` (`PSH_MARKER_TEXT`).

---

## 3. Prerequisites, and the Go toolchain blocker

The harness needs: `bash`, `go` (any recent version; see below), `jq`,
`python3`, `curl`, `openssl` + `ssh-keyscan` (only for `certs/`), `ss`
(iproute2) or bash `/dev/tcp` for readiness checks, and a depth-1
`psiphon-tunnel-core` checkout at `.research/psiphon-tunnel-core` (override
with `PSIPHON_CLONE_DIR`).

**The checkout must be built with Go 1.26.x, not Go 1.27.** `go.mod` pins
`go 1.26.0` / `toolchain go1.26.9`
(`.research/psiphon-tunnel-core/go.mod:3,5`), and the vendored
`github.com/Psiphon-Labs/psiphon-tls` re-implements `crypto/tls` with an
`unsafe` cast between its `ConnectionState` and the standard library's. Its
`init()` asserts the two structs are identical
(`vendor/github.com/Psiphon-Labs/psiphon-tls/unsafe.go:44`). Go 1.27 added a
field, so a Go 1.27 build compiles but panics on every startup, including
`generate`:

```
panic: tls: ConnectionState is not equal to tls.ConnectionState: struct field count mismatch: 18 vs 17
goroutine 1 [running]:
github.com/Psiphon-Labs/psiphon-tls.init.0()
        .../vendor/github.com/Psiphon-Labs/psiphon-tls/unsafe.go:44 +0xf9
```

`env.sh` therefore exports `GOTOOLCHAIN=go1.26.9` (override: `PSH_GO_TOOLCHAIN`;
set `GOTOOLCHAIN=local` only if your `go` really is 1.26.x). Go downloads the
pinned toolchain into `GOMODCACHE` on first use. If the user-level
`GOPATH`/`GOMODCACHE`/`GOCACHE` are not writable (common in sandboxes), the
scripts fall back to `.research/psiphon-server-harness/.cache/`. All script
builds use `-mod=vendor`, so no module downloads are needed.

---

## 4. Building the binaries

`setup.sh` does this; the equivalent manual commands are:

```bash
cd .research/psiphon-tunnel-core
export GOTOOLCHAIN=go1.26.9
go build -mod=vendor -o ../psiphon-server-harness/bin/psiphond ./Server
go build -mod=vendor -o ../psiphon-server-harness/bin/psiphon-tunnel-core-client ./ConsoleClient
```

The upstream build scripts are `Server/make.bash` / `ConsoleClient/make.bash`;
they add `-ldflags` build info and static linking, neither of which the harness
needs.

---

## 5. Server configuration: generation and required fields

`psiphond` has two subcommands, `generate` and `run`
(`.research/psiphon-tunnel-core/Server/main.go:63-271`). `generate` calls
`server.GenerateConfig` (`psiphon/server/config.go:1157`), which generates *all*
secret key material and a matching client server entry, and writes:

| File | Contents | Citation |
| --- | --- | --- |
| `psiphond.config` | server config incl. SSH private key, obfuscation keys, ports, `OwnEncodedServerEntries` | `Server/main.go:185-190`, `psiphon/server/config.go:1157` |
| `psiphond-traffic-rules.config` | per-client rate/port rules | `psiphon/server/config.go` (GenerateConfig) |
| `psiphond-osl.config` | OSL schemes | idem |
| `psiphond-tactics.config` | tactics request key pair + default tactics | idem |
| `server-entry.dat` | hex-encoded client server entry (unsigned) | `Server/main.go:209-213` |

Exact harness invocation (run from `config/`):

```bash
../bin/psiphond --ipaddress 127.0.0.1 \
  --protocol SSH:20081 \
  --protocol OSSH:20082 \
  --protocol TLS-OSSH:20083 \
  --protocol UNFRONTED-MEEK-HTTPS-OSSH:20087 \
  generate
```

Notes:
* No `--web` port is set, so no web/API HTTP server runs. Tunnels use the SSH
  API only (the entry advertises the `ssh-api-requests` capability).
* `--logFilename` is left empty: `psiphond` logs JSON to stderr, and `run.sh`
  redirects it to `logs/psiphond.log`.
* The relative filenames in the config (`TrafficRulesFilename`, `OSLConfigFilename`,
  `TacticsConfigFilename`) are resolved against the process working directory,
  which is why `run.sh` starts `psiphond` from `config/`.

What `GenerateConfig` puts in the config (and why it is required) — citations
are to `.research/psiphon-tunnel-core/psiphon/server/config.go`:

| Config field | Generated value | Why / validation |
| --- | --- | --- |
| `ServerIPAddress` | `127.0.0.1` | required (`LoadConfig`, `config.go:790`) |
| `SSHPrivateKey` | RSA-2048 PEM host key (`rsa.GenerateKey`, `config.go:1209`; `SSH_RSA_HOST_KEY_BITS=2048`, `config.go:63`) | required for any SSH-based protocol (`config.go:880`) |
| `SSHServerVersion` | `SSH-2.0-Psiphon`, but overridden when `ObfuscatedSSHKey` is set (`LoadConfig`, `config.go:842-856`) | required for SSH-based protocols (`config.go:880`) |
| `SSHUserName` | `psiphon_<16 hex>` (`config.go:1234`) | required (`config.go:880`) |
| `SSHPassword` | 32 random bytes, hex (64 chars; `config.go:1236-1240`) | required (`config.go:880`) |
| `ObfuscatedSSHKey` | 32 random bytes, hex (`config.go:1246-1250`) | required for OSSH and TLS-OSSH (`config.go:887`) |
| `MeekObfuscatedKey` | 32 random bytes, hex | required for TLS-OSSH (`config.go:896`; used for legacy session-ticket reasons) |
| `ShadowsocksKey`, discovery/tactics keys | random | not used by the harness protocols |
| `TunnelProtocolPorts` | `{"SSH":20081,"OSSH":20082,"TLS-OSSH":20083}` | drives listeners |
| `OwnEncodedServerEntries` | the server entry, for the SSH handshake | `config.go:1616-1618` |

The harness then patches the generated config with one testing-only field:

```json
"AllowBogons": true
```

The generated traffic rules leave `AllowTCPPorts` null, which the server treats
as "allow all ports" (`psiphon/server/trafficRules.go:956-961`), but port
forwards to bogon destinations (`127.0.0.0/8`, `10/8`, ...) are refused unless
`AllowBogons` is set (`psiphon/server/config.go:507-509`,
`psiphon/server/tunnelServer.go:5036`). The test destination is loopback, so
the harness enables it. **This is for local testing only.**

Annotated shape of the generated config (values abbreviated; private keys are
in the generated file, not in this doc):

```json
{
    "LogLevel": "info",
    "LogFormat": "json",
    "LogFileCreateMode": 438,
    "HostID": "example-host-id",
    "ServerIPAddress": "127.0.0.1",
    "TunnelProtocolPorts": { "SSH": 20081, "OSSH": 20082, "TLS-OSSH": 20083 },
    "SSHPrivateKey": "-----BEGIN RSA PRIVATE KEY-----\n...",
    "SSHServerVersion": "SSH-2.0-psiphon...",
    "SSHUserName": "psiphon_<16 hex>",
    "SSHPassword": "<64 hex>",
    "ObfuscatedSSHKey": "<64 hex>",
    "ShadowsocksKey": "<64 hex>",
    "MeekObfuscatedKey": "<64 hex>",
    "MeekProxyForwardedForHeaders": ["X-Forwarded-For"],
    "UDPInterceptUdpgwServerAddress": "127.0.0.1:7300",
    "DNSResolverIPAddress": "8.8.8.8",
    "TrafficRulesFilename": "psiphond-traffic-rules.config",
    "OSLConfigFilename": "psiphond-osl.config",
    "TacticsConfigFilename": "psiphond-tactics.config",
    "OwnEncodedServerEntries": { "<tag>": "<hex entry>" },
    "AllowBogons": true
}
```

`UDPInterceptUdpgwServerAddress` points at a UDP gateway that the harness does
not run; UDP is unused in these tests. TCP tunnels are unaffected.

---

## 6. The server entry: format, ports, and signing

### 6.1 Encoding

`server-entry.dat` is **hex text**. Hex-decoded, it is the legacy Psiphon
encoding: four space-separated prefix fields followed by the entry JSON
(`psiphon/common/protocol/serverEntry.go:1040` `EncodeServerEntry`, and
`encodeServerEntry`). When there is no web-server certificate the prefix is
compacted to `"0 0 0 0 "`:

```
30 20 30 20 30 20 30 20  ...   =>  "0 0 0 0 {json}"
```

Helpers in the harness produce:

* `config/server-entry.json` — the unsigned entry as a single JSON object
  (for Rust's `ServerEntry::from_json`);
* `config/server-entry-signed.json` — the signed entry as a one-element JSON
  array (for Rust's `ServerEntry::from_json_array`);
* `config/server-entry-signed.dat` — the signed entry in the hex transport
  encoding (for the Go ConsoleClient `-serverList`).

Decode by hand:

```bash
xxd -r -p config/server-entry-signed.dat | cut -d' ' -f5- | jq .
```

### 6.2 The entry the harness generates (exact JSON, signed)

This is the output of `setup.sh` for the default ports. Keys/passwords here are
**disposable local test credentials**, regenerated by `./setup.sh --force`; the
Ed25519 `signature` is over the Go-encoded JSON, and `signature: null` is not
present. Full file: `config/server-entry-signed.json`.

```json
[
  {
    "capabilities": ["ssh-api-requests", "SSH", "OSSH", "TLS", "UNFRONTED-MEEK-HTTPS"],
    "ipAddress": "127.0.0.1",
    "meekCookieEncryptionPublicKey": "UzPn0GNnzqdTsko45g5iwWNhKUhJZlwOJMouuw+2JVM=",
    "meekFrontingAddresses": ["127.0.0.1"],
    "meekFrontingHosts": ["127.0.0.1"],
    "meekObfuscatedKey": "8c95e21c3ed953fdafb9368e728ac2da9c575496bcf36a7c1a066d97f5fca0a8",
    "meekServerPort": 20087,
    "signature": "gfjtuI5Wz6wJa/twYSa6Uy+IZmZKBby2Sm3h8/tTfjG1smKOv78/AWpLwy05xODWyuLPTadyMbDw6AwwVCbLZpOvY34oQx0C",
    "sshHostKey": "AAAAB3NzaC1yc2EAAAADAQABAAABAQC0vcGiX10W748E67PNEUZgiHDy5iZR6yO5FfGQ2EKwpEEVqFg+IFzPXWbR+4psXE4uAjxigKc65Sw4Jcjw6qI7gxRRj1oQ6SaFOitm4NrNmNvK8W7mkuB9sU9ZYO5Xrnxtp86ybubP/VIdqzN56LkPoBqqo/Tjz0bSVZ8mHFV5loeO0xulOTULDWuCSa8YupQDK3B3AYpapb4D3byWgxM5Cff9LK53Bwgo9frToFoG5t/qmzY8VWCbqfGa3kfzEen9TtW+PesLVt2+7z2yvFqGSXyCFil3Tm0TIvai9YcE/5n0yuDPEZsvrN0GPQhUNHnS3yALmzoBXL2N1+KdgKtf",
    "sshObfuscatedKey": "5f478555c35f0ce50135bdc8198192dbf250570ea8da7721e990595a24a54005",
    "sshObfuscatedPort": 20082,
    "sshPassword": "0a7fdb76b82813be615005218973836ff105f4ab606504f7e2bfadfccf440184",
    "sshPort": 20081,
    "sshShadowsocksKey": "ed1b231196ad41a32aa7522629a57b237a6107b42994c7b25964d7025a35af69",
    "sshUsername": "psiphon_07ace6e4dd0ce16f",
    "tacticsRequestObfuscatedKey": "FjjUyhdjq7nubmN8Yt0VLmrFHbmLk+CYEDz4imtefbk=",
    "tacticsRequestPublicKey": "GwEjmxo1sGkENenxm1cPQEHWGmfX7Wt1lvIiwgB8tHI=",
    "tag": "a3bMYzWPzr1AvDE4bBvcgpBX1JWTueKN3Z9GPyul4QE=",
    "tlsOSSHPort": 20083,
    "webServerSecret": "f856e44dfc63a8ba658cc939f20f953c3fee023960331e1dabdaeb80d044b0ee"
  }
]
```

Ports per protocol (the Rust client never parses ports from capabilities; it
picks the field for the protocol it dials — `zero-psiphon`'s
`ServerEntry::port_for`):

| `TunnelProtocol` | Entry field | Harness value | Carrier | Server capability |
| --- | --- | --- | --- | --- |
| `SSH` | `sshPort` | `20081` | plain TCP | `SSH` |
| `OSSH` | `sshObfuscatedPort` | `20082` | RC4 obfuscated SSH | `OSSH` |
| `TLS-OSSH` | `tlsOSSHPort` | `20083` | TLS 1.3, then OSSH | `TLS` |
| `UNFRONTED-MEEK-HTTPS-OSSH` | `meekServerPort` | `20087` | TLS 1.3, then HTTP bodies, then OSSH | `UNFRONTED-MEEK-HTTPS` |
| `SHADOWSOCKS-OSSH` | `sshShadowsocksPort` | absent | not enabled | — |

One entry covers all enabled protocols; there is no per-protocol entry.

### 6.3 Why the stock CLI is not enough: signing

`server.GenerateConfig` *can* sign (parameters
`ServerEntrySignaturePublicKey`/`ServerEntrySignaturePrivateKey`,
`psiphon/server/config.go:1157-1161` and `:1587-1605`), but the `psiphond`
CLI in `Server/main.go` never sets them, so `server-entry.dat` from `generate`
is unsigned. The harness re-signs it with a stdlib-only re-implementation of
the exact protocol (`gotools/sign-server-entry`, used by `setup.sh`):

```
signature = ed25519.Sign(priv, json.Marshal(entry minus {signature,
            localSource, localTimestamp, isLocalDerivedTag, and `tag` when
            isLocalDerivedTag==true}))
signature = base64(sha256(pubkey)[:8] || signature)
```

That mirrors `ServerEntryFields.AddSignature` / `VerifySignature`
(`psiphon/common/protocol/serverEntry.go:320-450`). The signer also emits the
one-element JSON array and self-verifies before writing. Regenerate:

```bash
cd .research/psiphon-server-harness/gotools
go run ./sign-server-entry \
  -in  ../config/server-entry.dat \
  -out ../config/server-entry-signed.dat \
  -json-out ../config/server-entry-signed.json \
  -keydir ../config
```

The key pair lives in `config/server-entry-signature.key/.pub` (test-only,
0600). The public key — the value to configure in a client as
`ServerEntrySignaturePublicKey` — is printed on setup:

```
OVzO3tr8I9gYeHGg38h1eKDjoV3a5Mqkb4QxmNdG/YM=
```

Signature enforcement is opt-in on the Go side: the client verifies an entry
only when its own `ServerEntrySignaturePublicKey` is set **and** the entry has a
signature (`psiphon/config.go:618`, `psiphon/dataStore.go:1280-1298`). An
unsigned entry is therefore silently accepted by a Go client even when a key is
configured; `zero-psiphon`'s `verify_signature` instead rejects unsigned
entries, so use the **signed** JSON for Rust. The harness's negative test
(`verify.sh`) flips the configured public key and shows the Go client deleting
the entry with `verify signature failed` and never connecting.

---

## 7. Keys, host key, and certificates

* **SSH host key** — RSA-2048 generated into `SSHPrivateKey` by
  `GenerateConfig` (`psiphon/server/config.go:1209`). Its public part is
  embedded in the entry as `sshHostKey` (base64 of the SSH wire encoding of the
  key). Clients must pin those exact bytes (see §9). Evidence:
  `certs/ssh-host-key-keyscan.pub` from `ssh-keyscan -t rsa -p 20081
  127.0.0.1` matches `sshHostKey` (`capture-certs.sh` asserts this).
* **OSSH key** — `ObfuscatedSSHKey` (32 random bytes, hex) in the config; the
  entry carries the same value as `sshObfuscatedKey`. Both `OSSH` and
  `TLS-OSSH` use it (`TunnelProtocolUsesObfuscatedSSH` is true for every
  protocol except plain `SSH`: `psiphon/common/protocol/protocol.go:318-321`).
* **TLS-OSSH certificate** — there is **no user-supplied certificate**. The
  server generates a fresh self-signed certificate on every start
  (`psiphon/server/tlsTunnel.go:97-116`: `common.GenerateWebServerCertificate(values.GetHostName())`),
  with a random hostname CN/SAN, and enforces TLS 1.3 minimum
  (`tlsTunnel.go:113-116`). Clients do not and cannot verify it: the Go client
  sets `InsecureSkipVerify` for this transport
  (`psiphon/common/tlsdialer/dialer.go:298-333`). Captured example
  (`certs/tls-ossh-cert.info.txt`):

  ```
  subject=CN=dztf.net
  issuer=CN=dztf.net
  notBefore=Apr 19 16:00:00 2026 GMT
  notAfter=Apr 19 16:00:00 2028 GMT
  X509v3 Subject Alternative Name: DNS:dztf.net
  ```

  A second capture produced `CN=hwom.net` — the CN changes per restart, which
  is the expected behavior. Do not pin this certificate; do not serve a real
  certificate expectation against TLS-OSSH.

`capture-certs.sh` refreshes all of `certs/`; it starts the server if needed
and stops it again if it started it.

---

## 8. Running the harness

### 8.1 Scripts

```bash
./setup.sh                 # idempotent; --force regenerates configs+keys, --rebuild rebuilds Go bins
./run.sh                   # start psiphond only
./run.sh --origin          # also start http://127.0.0.1:20085/ (origin/marker.txt)
./status.sh                # pids, listeners, last log lines
./run-client.sh            # Go ConsoleClient, OSSH, SOCKS 127.0.0.1:20084, foreground
./run-client.sh --protocol SSH --daemon   # SSH, SOCKS 127.0.0.1:20086, background
./run-client.sh --protocol TLS-OSSH       # TLS-OSSH, SOCKS 127.0.0.1:20089
./run-client.sh --protocol UNFRONTED-MEEK-HTTPS-OSSH   # meek, SOCKS 127.0.0.1:20090
./verify-meek.sh           # unfronted meek interop (Rust tests/meek.rs), one shell
./verify-fronted.sh        # fronted meek interop through a local CDN edge (§9.6), one shell
./stop.sh                  # stops client, origin, psiphond, fronting providers; safe to repeat
```

`tools/fronting-provider.py` is the local stand-in for a CDN edge that
`verify-fronted.sh` uses; `--help` documents its options (§9.6).

`run-client.sh` prints the client config and SOCKS port and passes
`-formatNotices`; with `--daemon` it waits for the local SOCKS listener and
writes `run/client.pid` / `logs/client-<protocol>.log`. Note that the local
SOCKS listener opens before a tunnel is established — wait for the
`Tunnels {"count":1}` notice.

### 8.2 Use the SOCKS proxy

```bash
curl -x socks5h://127.0.0.1:20084 http://127.0.0.1:20085/marker.txt
# psiphon-harness-marker
curl -x socks5h://127.0.0.1:20084 https://example.com/    # needs host egress
```

SOCKS5 with remote DNS (`socks5h`) is important if you want the client to
resolve names; a direct `http://127.0.0.1:20085/` destination is forwarded by
the server to the origin on the server side (loopback in this harness).

### 8.3 Non-interactive / CI

```bash
./verify.sh                                   # SSH,OSSH,TLS-OSSH + signature negative test
./verify.sh --internet                        # + https://example.com/ through the tunnel
./verify.sh --internet --require-internet     # make egress failure fatal
./verify.sh --protocols OSSH --keep           # subset; leave services running
./verify.sh --timeout 45 --curl-timeout 30
```

`verify.sh` starts psiphond and the origin, runs one ConsoleClient per
protocol with a fresh `DataRootDirectory`, waits for the tunnel, curls
`http://127.0.0.1:20085/marker.txt` through the client's SOCKS proxy, asserts
the marker, runs the wrong-signature negative test, and tears everything down
(with `--keep`: leaves it up). Exit status is 0 only if every check passed.
It does start+test+stop in a single shell on purpose: sandboxed execution
environments commonly kill background children when the step's shell exits, so
a `run.sh` in one step + client in the next step will not work there.

Observed output:

```
[harness] [SSH] PASS: tunnel=SSH, origin returned psiphon-harness-marker
[harness] [OSSH] PASS: tunnel=OSSH, origin returned psiphon-harness-marker
[harness] [TLS-OSSH] PASS: tunnel=TLS-OSSH, origin returned psiphon-harness-marker
[harness] [signature] PASS: wrong key rejected (verify signature failed, no tunnel)
[harness] [internet] PASS: https://example.com/ returned 200 through the tunnel

==================== harness verification summary ====================
  PASS  SSH  (tunnel=SSH, SOCKS 127.0.0.1:20086)
  PASS  OSSH  (tunnel=OSSH, SOCKS 127.0.0.1:20084)
  PASS  TLS-OSSH  (tunnel=TLS-OSSH, SOCKS 127.0.0.1:20089)
  PASS  UNFRONTED-MEEK-HTTPS-OSSH  (tunnel=UNFRONTED-MEEK-HTTPS-OSSH, SOCKS 127.0.0.1:20090)
  PASS  signature-rejection  (verify signature failed, no tunnel)
  PASS  internet-egress  (https://example.com/ -> 200)
---------------------------------------------------------------------
  origin requests: 3 this run (logs/origin.log)
  server_tunnel events: 3 (relay_protocol: 1 OSSH 1 SSH 1 TLS-OSSH)
```

### 8.4 Go ConsoleClient config (annotated)

`config/psiphon-client-<PROTOCOL>.config`, generated by `setup.sh`:

```json
{
    "DataRootDirectory": "<harness>/clientdata/OSSH",
    "PropagationChannelId": "0000000000000000",
    "SponsorId": "0000000000000000",
    "ClientVersion": "1",
    "ClientPlatform": "Linux",
    "DisableRemoteServerListFetcher": true,
    "DisableTactics": true,
    "DisableLocalHTTPProxy": true,
    "LocalSocksProxyPort": 20084,
    "EmitDiagnosticNotices": true,
    "LogLevel": "debug",
    "ServerEntrySignaturePublicKey": "OVzO3tr8I9gYeHGg38h1eKDjoV3a5Mqkb4QxmNdG/YM=",
    "LimitTunnelProtocols": ["OSSH"]
}
```

* `PropagationChannelId` / `SponsorId` / `ClientVersion` are mandatory:
  `psiphon.LoadConfig` rejects an empty channel/sponsor and a non-integer client
  version (`psiphon/config.go`, config validation), and the server's handshake
  validates channel/sponsor as 16 hex characters and version as an integer
  string (`psiphon/server/api.go:1477-1490`). All zeros is fine for a local
  server.
* `DataRootDirectory` must exist; the client stores server entries there.
* `DisableRemoteServerListFetcher` avoids touching real Psiphon infrastructure.
* `ServerEntrySignaturePublicKey` enables signature verification; `verify.sh`
  also runs a config with a wrong key.
* `LimitTunnelProtocols` pins one protocol per config so every transport is
  exercised explicitly.

The client is launched as
`psiphon-tunnel-core-client -config <config> -serverList config/server-entry-signed.dat -formatNotices`.
`-serverList` imports an embedded server-entry list
(`ConsoleClient/main.go:51-52,370-380`, `psiphon/dataStore.go:495`); the hex
`server-entry-signed.dat` is a valid one-entry list for that code path.

---

## 9. Rust client interop (`Zray-Core/crates/zero-psiphon`)

### 9.1 What is proven today

The harness is enough to drive the real Rust client over **plain SSH**. The
out-of-tree checker `rustcheck/` (a scratch crate with a path dependency on
`Zray-Core/crates/zero-psiphon`; it does not modify Zray-Core) performs the
whole path:

```bash
cd .research/psiphon-server-harness
./run.sh --origin
(cd rustcheck && cargo run --offline)
./stop.sh
```

Observed:

```
parsed entry: tag=/xTWPrJN ip=127.0.0.1
capabilities: ["ssh-api-requests", "TLS", "SSH", "OSSH"]
supported protocols: [Ssh, Ossh, TlsOssh]
signature: VERIFIED against OVzO3tr8I9gYeHGg38h1eKDjoV3a5Mqkb4QxmNdG/YM=
dialing SSH 127.0.0.1:20081
ssh: AUTHENTICATED, session_id=aab0aac7d90b13c43d253749ff11a601
handshake: ACCEPTED (200 byte response): {"client_region":"None", ...}
direct-tcpip: OK (209 bytes)
  HTTP/1.0 200 OK
  ...
  psiphon-harness-marker
RESULT: PASS - Rust zero-psiphon carried a stream through the real psiphond
```

That covers: signed-entry parsing + signature verification in Rust, RSA host-key
pinning, the JSON credential-payload password, the `psiphon-handshake` request,
and `direct-tcpip` forwarding. `rustcheck/` also contains
`src/bin/raw_handshake.rs`, a hand-rolled `russh` version of the same recipe
useful as a reference when changing the client.

### 9.2 Exact recipe for the Rust client

Inputs: `config/server-entry-signed.json` (one-element JSON array) and the
base64 public key `config/server-entry-signature.pub`.

1. **Parse + verify the entry.** `ServerEntry::from_json_array(...)` (or
   `from_json` for `server-entry.json`), then
   `entry.verify_signature(public_key)` when the client config has a
   `server_entry_signature_public_key`. The signature covers Go-encoded JSON
   (sorted keys, Go escaping), which `zero-psiphon::json` already reproduces.
   The hex `server-entry.dat` form must be decoded first:
   `xxd -r -p config/server-entry-signed.dat | cut -d' ' -f5-`.
2. **Pick the protocol and port.**
   `entry.port_for(TunnelProtocol::Ssh | Ossh | TlsOssh)` returns
   `20081` / `20082` / `20083` respectively (`sshPort`, `sshObfuscatedPort`,
   `tlsOSSHPort`). For no options (`LimitTunnelProtocols` empty) a client would
   prefer per `supported_protocols()`; the harness supports all three.
3. **Build the carrier to `entry.ip_address():port`.**
   * `SSH`: plain TCP.
   * `OSSH`: obfuscated SSH. Client writes
     `[16-byte random seed][4-byte magic 0x0BF5CA7E][4-byte padding length][padding]`,
     derives two RC4 keys and the padding PRNG from the seed with the
     obfuscated-openssh scheme (`OBFUSCATE_HASH_ITERATIONS=6000`,
     `psiphon/common/obfuscator/obfuscator.go:38-52`), and stops obfuscating
     after `SSH_MSG_NEWKEYS`; the password-equivalent secret is
     **`entry.sshObfuscatedKey`** (hex) used as the OSSH "keyword". The Rust
     crate has `obfuscator.rs` as a stub today — this carrier is not implemented
     yet.
   * `TLS-OSSH`: TLS **1.3 only**, **any certificate accepted** (self-signed,
     random CN, regenerated per server start), then the same OSSH layer as
     above with `entry.sshObfuscatedKey`, then SSH
     (`psiphon/server/tlsTunnel.go:97-116`,
     `psiphon/common/tlsdialer/dialer.go:298-333`). Rust: `rustls` with a
     `ServerCertVerifier` that accepts anything, TLS 1.3 only, then the OSSH
     wrapper. Not implemented in the crate yet.
4. **SSH with Psiphon semantics.**
   * Client version line: any `SSH-2.0-...`.
   * Host key: pin the exact bytes from `entry.ssh_host_key_bytes()`
     (`sshHostKey` is base64 of the wire-encoded RSA key). The server uses that
     key for every carrier (the SSH handshake happens after OSSH/TLS).
   * Username: `entry.ssh_username()`.
   * Password: **not** `entry.ssh_password()` alone — it is a JSON payload
     (`psiphon/common/protocol/protocol.go:900`,
     `psiphon/server/tunnelServer.go:3026-3060`):
     ```json
     {"SessionId":"<32 lowercase hex, 16 random bytes>","SshPassword":"<entry.sshPassword>","ClientCapabilities":["server-requests"],"SponsorId":"..."}
     ```
     (`SessionId` length is `2*PSIPHON_API_CLIENT_SESSION_ID_LENGTH`, i.e. 32
     hex chars; `psiphon/common/protocol/protocol.go:86`.)
5. **Send the `psiphon-handshake` global SSH request before any port
   forward.** This is mandatory. The server rejects `direct-tcpip` with
   `ssh: rejected: administratively prohibited ("administratively prohibited")`
   until `handshakeState.completed` is true
   (`psiphon/server/tunnelServer.go:5059-5067`); the state is set only by this
   request (`psiphon/server/api.go:92-95,353-356`; request handler dispatch at
   `psiphon/server/tunnelServer.go:3275-3297`). Request name:
   `"psiphon-handshake"` (`psiphon/common/protocol/protocol.go:72`), payload is
   JSON (CBOR is optional on the wire; the server accepts plain JSON):
   ```json
   {"propagation_channel_id":"0000000000000000","sponsor_id":"0000000000000000","client_version":"1","client_platform":"Linux","relay_protocol":"SSH"}
   ```
   Validations (`psiphon/server/api.go:1477-1490,2159-2211`): channel hex;
   sponsor exactly 16 hex chars; version integer string; platform non-empty
   without whitespace; `relay_protocol` one of the tunnel-protocol names
   (`"SSH"`, `"OSSH"`, `"TLS-OSSH"`, ...). Other params (padding, dial metrics,
   tactics) are optional. The response is JSON and includes the tactics payload;
   it can be ignored for a basic interop test.
6. **`direct-tcpip` channels.** The server accepts `direct-tcpip`
   (`psiphon/server/tunnelServer.go:3220-3240`), dials the destination, and
   refuses bogons unless `AllowBogons: true` (harness sets it). `zero-psiphon`'s
   `SshTunnel::open(host, port)` does exactly this. The server also has the
   split-tunnel `direct-tcpip-no-split-tunnel@psiphon.ca` channel type, which
   the Rust crate notes as not yet implemented and which is not needed here.

### 9.3 API sketch against this harness

```rust
let entries = ServerEntry::from_json_array(&std::fs::read_to_string(
    ".research/psiphon-server-harness/config/server-entry-signed.json")?)?;
let entry = &entries[0];
entry.verify_signature(&std::fs::read_to_string(
    ".research/psiphon-server-harness/config/server-entry-signature.pub")?.trim())?;

let port = entry.port_for(TunnelProtocol::Ssh)?;             // 20081
let tcp = tokio::net::TcpStream::connect((entry.ip_address(), port)).await?;

let mut tunnel = SshTunnel::establish(tcp, entry, &TunnelOptions::default(),
                                      Duration::from_secs(15)).await?;
let response = tunnel.handshake(&HandshakeParams::new(TunnelProtocol::Ssh)).await?;
let mut stream = tunnel.open("127.0.0.1", 20085).await?;     // origin
```

(For `OSSH`/`TLS-OSSH` the first argument becomes the OSSH/TLS-wrapped stream;
everything from `SshTunnel::establish` onward is identical.)

### 9.4 Client config (`zero-psiphon::ClientConfig`)

```rust
ClientConfig {
    server_entries: entries,                       // from server-entry-signed.json
    server_entry_signature_public_key: Some(pubkey),
    remote_server_list_url: None,
    tactics_url: None,
    upstream_proxy_url: None,
    egress_region: String::new(),                  // any region
    establish_timeout: Duration::from_secs(15),
}
```

The harness server has no region and an empty tactics payload; the Rust client
must treat both as optional. `remote_server_list_url` should stay `None` (the
harness tests the embedded/signed list only).

### 9.5 The meek transport (unfronted, over TLS)

The harness also serves **unfronted meek over TLS**, so the meek carrier can
be interop-tested against the real server like SSH, OSSH and TLS-OSSH.

**Enabling it.** `PSH_MEEK_PORT` (default `20087`) is passed to
`psiphond generate` as the `UNFRONTED-MEEK-HTTPS-OSSH` protocol, like the other
ports:

```bash
cd .research/psiphon-server-harness
PSH_MEEK_PORT=20087 ./setup.sh --force
```

`psiphon/server/config.go:1503-1545` maps that protocol name to the entry's
`meekServerPort`, and `psiphond generate` creates the two keys the protocol
needs (`MeekObfuscatedKey`, `MeekCookieEncryptionPrivateKey`) by itself. The
generated `config/psiphond.config` then carries

```json
"TunnelProtocolPorts": { "SSH": 20081, "OSSH": 20082, "TLS-OSSH": 20083, "UNFRONTED-MEEK-HTTPS-OSSH": 20087 }
```

and the generated `config/server-entry.json` carries `meekServerPort`,
`meekCookieEncryptionPublicKey`, `meekObfuscatedKey` and the `UNFRONTED-MEEK-HTTPS`
capability.

**Evidence that it listens** (`logs/psiphond.log` and `ss -ltn`):

```
{"level":"info","localAddress":"127.0.0.1:20087","msg":"listening","tunnelProtocol":"UNFRONTED-MEEK-HTTPS-OSSH"}
LISTEN 0 4096 127.0.0.1:20087 0.0.0.0:*
```

**The Rust interop test** is `Zray-Core/crates/zero-psiphon/tests/meek.rs`
(ignored by default, like `tests/real_server.rs`). It builds the stack the Go
client builds: TLS (any certificate accepted, no SNI for an IP literal) →
`meek::MeekStream` (cookie sealed to the entry's
`meekCookieEncryptionPublicKey`, obfuscated with `meekObfuscatedKey`) →
`obfuscator::OsshClient` (the entry's `sshObfuscatedKey`) → `tunnel::SshTunnel`
→ `psiphon-handshake` → `direct-tcpip` → `GET /marker.txt`.

```bash
cd .research/psiphon-server-harness
./verify-meek.sh          # one shell: server + origin + test + teardown
```

or by hand:

```bash
ZERO_PSIPHON_SERVER_ENTRY=.research/psiphon-server-harness/config/server-entry.json \
ZERO_PSIPHON_TARGET=127.0.0.1:20085 \
  cargo test -p zero-psiphon --test meek -- --ignored --nocapture
```

Observed:

```
test unfronted_meek_against_the_real_server_carries_a_request ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.51s
```

with, in the server log, the tunnel event the client produced:

```json
{"event_name":"server_tunnel","relay_protocol":"UNFRONTED-MEEK-HTTPS-OSSH",
 "handshake_completed":true,"bytes_up_tcp":64,"bytes_down_tcp":209,"duration":470,
 "meek_cookie_name":"Z","meek_content_type":"application/octet-stream"}
```

(`bytes_down_tcp: 209` is the origin's marker response, i.e. the request really
travelled through the meek tunnel.)

**The Go client is the oracle for the server side.** A ConsoleClient limited to
the meek protocol tunnels through the same listener; `setup.sh` writes that
config (`config/psiphon-client-UNFRONTED-MEEK-HTTPS-OSSH.config`, SOCKS
`127.0.0.1:20090`) and `verify.sh` runs it:

```bash
# config/psiphon-client-UNFRONTED-MEEK-HTTPS-OSSH.config
LimitTunnelProtocols: ["UNFRONTED-MEEK-HTTPS-OSSH"]
curl -x socks5h://127.0.0.1:20090 http://127.0.0.1:20085/marker.txt
# => psiphon-harness-marker
```

**Three wire details worth knowing** (all observed against this harness):

1. *The first request is much larger than the SSH version line.* The Go OSSH
   server sends **identification-line padding before the version line**
   (`psiphon/common/obfuscator/obfuscatedSshConn.go`,
   `makeServerIdentificationLinePadding`): random bytes, in lines of at most 512
   bytes, each terminated by CRLF, a different amount on every connection. The
   server's event reports it as `downstream_ossh_padding` (8062 bytes in one
   run). It is not an error, and a client that reads the server's version line
   line-by-line skips it. Over meek those bytes ride inside the first HTTP
   request body, so its `Content-Length` is in the thousands.
2. *The response is chunked.* `psiphond` answers with
   `Transfer-Encoding: chunked`; the chunk size line and the CRLF after the
   data are framing and must not be handed to the SSH layer.
3. *A response can have an empty body.* When the server has no new downstream
   data it answers `Content-Length: 0`. Such a response is **complete**: the
   server answers and then waits for the next request, so a client that waits
   for more bytes of a zero-length body waits for the very request it has to
   send. The client must treat it as an empty round trip and poll again.

**Not covered here:** the *fronted* meek protocols (`FRONTED-MEEK-OSSH`,
`FRONTED-MEEK-HTTP-OSSH`), which need a fronting provider — a CDN edge — in
front of the server. The harness now runs one locally: see §9.6.

---

### 9.6 The fronted meek transports (through a local CDN edge)

A fronted connection has three parties, and the client only knows the first:

```text
client ──TLS :443 (FRONTED-MEEK-OSSH) ─▶ fronting provider ──HTTPS──▶ psiphond
       ──plain HTTP :80 (FRONTED-MEEK-HTTP-OSSH)  (CDN edge)          (FRONTED-MEEK-OSSH listener)
       Host: <fronting host>, SNI: <fronting address>
```

The client dials the *fronting address* on 443 (or 80), asks for the fronting
host in the `Host` header, and never names the server's own address; the CDN
forwards the HTTP request to the server it fronts. The bodies and the cookie
framing are identical to unfronted meek (`psiphon/dialParameters.go:1570-1600`,
`psiphon/common/protocol/serverEntry.go` `GetDialPortNumber`: 443 for
`FRONTED-MEEK-OSSH`, 80 for `FRONTED-MEEK-HTTP-OSSH`).

**The edge.** `tools/fronting-provider.py` is a local stand-in for the CDN
(Python standard library only: `ssl` + `socket` + `socketserver`). It
terminates TLS with an embedded self-signed certificate, or accepts plain TCP
with `--plain`, forwards every HTTP request byte for byte to its upstream, and
streams the response back — including `Transfer-Encoding: chunked` framing, the
`Content-Length: 0` responses an idle poll gets, and one persistent client
connection carrying many requests (the characteristic shape of meek; the run below
carried 22 requests on the TLS edge and 12 on the plain one):

```bash
tools/fronting-provider.py --listen 127.0.0.1:20443 --upstream 127.0.0.1:20091 \
    --upstream-tls            # the FRONTED-MEEK-OSSH edge (:443 stand-in)
tools/fronting-provider.py --listen 127.0.0.1:20480 --upstream 127.0.0.1:20091 \
    --plain --upstream-tls    # the FRONTED-MEEK-HTTP-OSSH edge (:80 stand-in)
```

`--upstream-tls` is not optional for this server: `FRONTED-MEEK-OSSH` is an
HTTPS-fronted protocol on the server side too
(`TunnelProtocolUsesMeekHTTPS`), so psiphond's fronted listener wraps accepted
connections in TLS — the edge-to-origin hop of a real fronted connection is
HTTPS, even for the plainly-fronted client. The origin's certificate is
self-signed and regenerated per server start, so the edge does not verify it,
exactly as the TLS-OSSH carrier does not.

**What the server needs.** The server runs the fronted protocols
(`setup.sh` passes them to `psiphond generate`; an already-generated config is
patched in place, so no `--force` is needed):

```json
"TunnelProtocolPorts": { ..., "FRONTED-MEEK-OSSH": 20091, "FRONTED-MEEK-HTTP-OSSH": 20092 }
```

Both entries are required, and only the first listens:

* A client reports the protocol it believes it is using inside its meek cookie
  (`MeekCookieData.ClientTunnelProtocol` — the Rust client writes it, §9.5), and
  the server accepts the value only if it is running that protocol:
  `protocol.IsValidClientTunnelProtocol` requires the reported protocol to be in
  `config.GetRunningProtocols()`, i.e. in `TunnelProtocolPorts`. **A fronted
  client cannot tunnel into the unfronted-meek listener**: the server resets the
  connection before the SSH handshake
  (`invalid client tunnel protocol: FRONTED-MEEK-OSSH`), and logs nothing at
  `info` level, so the symptom is the client's
  `ssh: key exchange: Broken pipe (os error 32)` and an edge log line saying
  the upstream closed without a response head.
* `FRONTED-MEEK-HTTP-OSSH` has no listener of its own
  (`TunnelProtocolUsesFrontedMeekNonHTTPS` → `continue` in
  `TunnelServer.Run`): its edge-to-server hop is HTTPS too, and the client's
  reported protocol is what tells the two apart on the shared listener. It is
  configured so that a client reporting it is accepted, and so `--force` also
  advertises it in the entry.

**The Rust interop test** is `Zray-Core/crates/zero-psiphon/tests/fronted_meek.rs`
(ignored by default). It builds the fronted entry itself — the harness entry is
an unfronted one — from the harness entry plus `meekFrontingAddresses:
["127.0.0.1"]`, `meekFrontingHosts: ["localhost"]` and the fronted capability
(`FRONTED-MEEK`, i.e. the protocol name minus `-OSSH`, as Psiphon's
`GetCapability` derives it), then points the dial at the local edge with
`ClientConfig::dial_options.fronted_dial_port` — a local edge cannot bind 443
or 80. Three tests:

1. `fronted_meek_over_tls_through_a_local_edge_carries_a_request` —
   `FRONTED-MEEK-OSSH` through `Client::connect` + `Client::dial`.
2. `fronted_meek_over_plain_http_through_a_local_edge_carries_a_request` —
   the same for `FRONTED-MEEK-HTTP-OSSH`, through the plain-TCP edge (the
   second forwarding port is the same script with `--plain`, so this variant
   *is* testable locally).
3. `the_fronted_carrier_carries_the_stack_through_the_tls_edge` — the carrier
   built by hand, the way `tests/meek.rs` builds the unfronted one, so a broken
   carrier and a transport the client's server selection would not offer are
   told apart.

```bash
cd .research/psiphon-server-harness
./verify-fronted.sh          # one shell: server + origin + edges + tests + teardown
```

or by hand (absolute paths: cargo runs a test with the crate directory as its
working directory):

```bash
ZERO_PSIPHON_SERVER_ENTRY=$PWD/.research/psiphon-server-harness/config/server-entry.json \
ZERO_PSIPHON_TARGET=127.0.0.1:20085 \
ZERO_PSIPHON_FRONTING_PORT=20443 ZERO_PSIPHON_FRONTING_HTTP_PORT=20480 \
  cargo test -p zero-psiphon --test fronted_meek -- --ignored --nocapture
```

Observed (`./verify-fronted.sh`):

```text
test fronted_meek_over_plain_http_through_a_local_edge_carries_a_request ... ok
test fronted_meek_over_tls_through_a_local_edge_carries_a_request ... ok
test the_fronted_carrier_carries_the_stack_through_the_tls_edge ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.82s
================== Fronted meek verification summary ==================
  edge self-check (TLS, no psiphond): PASS
  fronted interop tests:              PASS
  tunneled GET /marker.txt this run:  3 (logs/origin.log)
  edge requests:  TLS 22 (22 answered), HTTP 12 (12 answered)
  server_tunnel events this run:      3 (FRONTED-MEEK-OSSH 2, FRONTED-MEEK-HTTP-OSSH 1)
```

with, in the server log, one event per tunnel (209 bytes down = the origin's
marker response) and no warning or irregular-tunnel line:

```json
{"event_name":"server_tunnel","relay_protocol":"FRONTED-MEEK-OSSH",
 "handshake_completed":true,"bytes_up_tcp":64,"bytes_down_tcp":209,
 "total_port_forward_count_tcp":1,"meek_cookie_name":"zjxpbrct",
 "meek_server_http_version":"HTTP/1.1","meek_underlying_connection_count":11}
```

and, in the edge's log, the same request/response pairs the unfronted test
produces — a `req#` line per request and a `res#` line per answer, the first
request carrying the server's OSSH identification padding in its body:

```text
req#1: POST / HTTP/1.1 host=localhost body=3308B cookie-name=rpe range=- fronting-address=-
res#1: -> 200 chunked 4536B payload
req#2: POST / HTTP/1.1 host=localhost body=861B cookie-name=rpe range=-
res#2: -> 200 content-length=0 0B payload
```

`meek_underlying_connection_count: 11` is the edge's doing, and the shape a
CDN gives a meek session: the client keeps one connection, the edge opens a
fresh origin connection per request, and the session is keyed by the cookie, so
the server reassembles it.

**The self-check.** Before blaming the client, `verify-fronted.sh` proves the
edge itself: a `curl -k` through a third edge pointed at the origin returns
`psiphon-harness-marker`, so TLS termination, request forwarding and response
relay are known good without psiphond in the path; then a probe request (with a
deliberately bogus cookie, which the server always refuses) through each test
edge confirms it forwards into psiphond. Both edges share one script and one
code path, so a failure in the tests is a failure of the *client's* fronted
carrier.

**Notes and gotchas.** The single-shell rule of §8.3 applies (`./verify-fronted.sh`
starts, tests and stops in one invocation; `--keep` leaves the services up and
`./stop.sh` now stops the fronting providers too). `psh_start_fronting` treats a
pid file as valid only while its port is actually listening: a pid file left by
an earlier shell names a process in a pid namespace that no longer exists.
Fronted protocols are now advertised by `psiphond generate`, so a regenerated
entry offers them; until this run they were not, and `verify-meek.sh` and
`verify.sh` pin their protocols, so the addition does not change what they
prove.

---

## 10. Known blockers, gotchas, and their evidence

1. **Go 1.27 cannot run a build of this checkout** — panic
   `tls: ConnectionState is not equal to tls.ConnectionState: struct field
   count mismatch: 18 vs 17` at `psiphon-tls/unsafe.go:44`. Fixed by forcing
   `GOTOOLCHAIN=go1.26.9` (pinned in the checkout's `go.mod`). The harness
   scripts do this automatically. If `GOTOOLCHAIN` is set to `local` in the
   environment and the local Go is 1.27, every `psiphond` invocation panics.
2. **Stock `psiphond generate` produces an unsigned entry** — the CLI never sets
   the signature-key parameters that `server.GenerateConfig` supports. Fixed by
   `gotools/sign-server-entry` (re-implements
   `ServerEntryFields.AddSignature` with stdlib only and self-verifies).
3. **Loopback destinations are bogons** — without `"AllowBogons": true`,
   `direct-tcpip` to `127.0.0.1` is rejected (the observable symptom is the
   client's `LocalProxyError ... administratively prohibited`). Harness configs
   enable it. This is a test-only switch; never ship it.
4. **Port forwards before the handshake are rejected** — even with valid SSH
   auth, the server refuses `direct-tcpip` until the `psiphon-handshake` global
   request completes (`tunnelServer.go:5059-5067`). `rustcheck`'s
   `src/bin/raw_handshake.rs` documents the SSH-level flow; `SshTunnel::handshake`
   implements it now.
5. **Sandbox process lifecycle** — in agent sandboxes that kill the step's
   process tree, `run.sh` (start) followed by a client in another step does not
   work; `setsid` alone is not enough. Use `verify.sh`, which starts, tests and
   stops inside one invocation. Outside a sandbox, `run.sh`/`stop.sh` persist
   normally.
6. **Rust carriers**: plain TCP/SSH works end to end today. `OSSH` and
   `TLS-OSSH` are **not implemented in `zero-psiphon` yet** (`obfuscator.rs`
   and the TLS carrier are stubs); the server side is ready and the entry
   carries `sshObfuscatedKey`, `sshObfuscatedPort` (20082) and `tlsOSSHPort`
   (20083) for them. Meek is enabled and interop-tested (see §9.5); QUIC and
   Shadowsocks are not enabled in the harness (the server supports them; add
   `--protocol ...` to the generate command and re-run the signer).
7. **Unsigned entries are accepted by the Go client even with a configured
   key** (verification is skipped when the entry has no signature:
   `dataStore.go:1280-1298`). `zero-psiphon` treats unsigned as an error. Always
   point Rust at `server-entry-signed.json`.
8. **Config regeneration changes credentials and the `tag`** — old client data
   stores cache entries by tag; a stale `DataRootDirectory` can keep using a
   removed entry. `verify.sh` uses a fresh data dir per protocol. If you run
   `./setup.sh --force`, delete `clientdata/` (the script does).
9. **`psiphond` is wrapped by `panicwrap`** — two processes per server (parent +
   re-exec'd child). Kill via `./stop.sh` (it sweeps the harness binary path);
   don't manage it with a bare `kill` on an arbitrary pid.
10. **No web server / web certificate** — the harness intentionally omits
    `--web`; the entry has no `webServerCertificate`, and SSH API requests are
    used instead (`ssh-api-requests` capability). A client that only implements
    the legacy web API will not work; implement the SSH API.
11. **A fronted client needs the server to run the fronted protocol** — the
    client reports its tunnel protocol inside the meek cookie and the server
    accepts the value only when that protocol is in `TunnelProtocolPorts`
    (`IsValidClientTunnelProtocol`). Reporting `FRONTED-MEEK-OSSH` to the
    unfronted-meek listener therefore ends in a *silent* reset: no server log
    line at `info`, the edge logs that the upstream closed without a response
    head, and the client sees `ssh: key exchange: Broken pipe (os error 32)`
    (§9.6). `setup.sh` adds `FRONTED-MEEK-OSSH` (listener, TLS) and
    `FRONTED-MEEK-HTTP-OSSH` (no listener — its edge-to-origin hop is HTTPS
    too, so the client's reported protocol is what distinguishes it) to both a
    generated and an already-generated config.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `psiphond` prints usage instead of running | missing `run` subcommand: `psiphond --config psiphond.config run` (the scripts do this) |
| `panic: tls: ConnectionState ... 18 vs 17` | built/run with Go 1.27; `GOTOOLCHAIN=go1.26.9`, rebuild (`./setup.sh --rebuild`) |
| `failed to listen ... address already in use` | stale harness processes from a previous shell; `./stop.sh`, check `ss -ltnp \| grep 2008` |
| Client connects but curl through SOCKS fails with `administratively prohibited` | loopback destination without `AllowBogons`/handshake — check server config has `"AllowBogons": true` and use a client that sends `psiphon-handshake` |
| Client exits with `DataRootDirectory does not exist` | create the directory or use `./setup.sh` configs |
| Client never establishes; log has `verify signature failed` | wrong `ServerEntrySignaturePublicKey`; use `config/server-entry-signature.pub` |
| TLS-OSSH capture shows a different CN after restart | expected: certificate is regenerated per server start |
| `verify.sh` internet test warns but harness passes | host has no egress; use `--require-internet` only when egress is expected |

Logs: `logs/psiphond.log` (JSON server log, `server_tunnel` events include
`relay_protocol`), `logs/origin.log` (GET lines = proof the request traversed
the tunnel), `logs/verify-client-<PROTOCOL>.log` (client notices), and
`logs/verify-evidence.log` / `logs/rust-interop-evidence.log` (saved
transcripts from this session).

---

## 12. Regenerating with different ports / protocols

Ports come from env vars (`PSH_*_PORT`) or edit the `generate` command. The
server entry embeds the ports, so regenerate everything:

```bash
cd .research/psiphon-server-harness
PSH_SSH_PORT=21081 PSH_OSSH_PORT=21082 PSH_TLS_OSSH_PORT=21083 ./setup.sh --force
```

Adding meek (example; it needs no extra files because `GenerateConfig` creates
the cookie/obfuscation keys and server certificate itself):

```bash
cd config
../bin/psiphond --ipaddress 127.0.0.1 \
  --protocol SSH:20081 --protocol OSSH:20082 --protocol TLS-OSSH:20083 \
  --protocol UNFRONTED-MEEK-HTTPS-OSSH:20088 generate
jq '.AllowBogons = true' psiphond.config > t && mv t psiphond.config
cd ..
./setup.sh    # re-signs and rewrites client configs; add the protocol to verify.sh
```

Keep `--ipaddress 127.0.0.1` for loopback. Regenerating changes all secrets and
the entry tag; clients must reload the new signed entry (fresh data directory).

---

## 13. Security notes

* This is a **local-only test harness**: every listener binds `127.0.0.1`,
  keys/certs are generated for the test, and `AllowBogons` is enabled.
  `AllowBogons` disables the server's safety check against internal
  destinations, so do not expose this server or reuse this config anywhere real.
* The generated RSA private key, OSSH keys, SSH password, server-entry signature
  private key, and signed entries are local test material. They are ignored by
  `.gitignore` and should never be committed or reused.
* `verify.sh`'s wrong-key test intentionally exercises rejection; it is not a
  security evaluation of production Psiphon.

---

## 14. Source citations (checkout: `psiphon-tunnel-core` commit `5709017`)

| Topic | File:line |
| --- | --- |
| CLI `generate`/`run`, flags | `Server/main.go:63-271` |
| `GenerateConfig` (keys, entry, config) | `psiphon/server/config.go:1105-1700` |
| Config validation, required SSH fields | `psiphon/server/config.go:768-960` (`:790`, `:880`, `:887`, `:896`) |
| `AllowBogons` | `psiphon/server/config.go:507-509` |
| SSH key size / password length constants | `psiphon/server/config.go:62-64` |
| Bogon refusal for port forwards | `psiphon/server/tunnelServer.go:5036` |
| Handshake required before forwards | `psiphon/server/tunnelServer.go:5059-5067`; `psiphon/server/api.go:92-95,353-356` |
| SSH global request dispatch | `psiphon/server/tunnelServer.go:3275-3297` |
| SSH password callback / credential JSON | `psiphon/server/tunnelServer.go:3026-3060`; `psiphon/common/protocol/protocol.go:900` |
| Session ID length / handshake request name | `psiphon/common/protocol/protocol.go:72,86` |
| `direct-tcpip` support | `psiphon/server/tunnelServer.go:3220-3240` |
| Server entry encode/decode | `psiphon/common/protocol/serverEntry.go:1040-1210` |
| Signature sign/verify | `psiphon/common/protocol/serverEntry.go:320-450` |
| Signature key pair generator | `psiphon/common/protocol/serverEntry.go:479-489` |
| Client verifies only signed entries when key set | `psiphon/dataStore.go:1280-1298`; `psiphon/config.go:618` |
| TLS-OSSH self-signed TLS 1.3 cert | `psiphon/server/tlsTunnel.go:97-116` |
| Client skips TLS verification | `psiphon/common/tlsdialer/dialer.go:298-333` |
| OSSH obfuscation constants/scheme | `psiphon/common/obfuscator/obfuscator.go:38-52` |
| OSSH used by all but plain SSH | `psiphon/common/protocol/protocol.go:318-321` |
| Embedded server list import | `psiphon/dataStore.go:495`; `ConsoleClient/main.go:51-52,370-380` |
| Traffic rules port allowance | `psiphon/server/trafficRules.go:945-968` |
| Go toolchain pin / psiphon-tls panic | `go.mod:3,5`; `vendor/github.com/Psiphon-Labs/psiphon-tls/unsafe.go:44` |

---

## 15. Appendix: raw verification transcript (this session)

`./verify.sh --internet` (trimmed):

```
[harness] starting psiphond (log: .../logs/psiphond.log)
[harness] psiphond listening on 127.0.0.1: SSH=20081 OSSH=20082 TLS-OSSH=20083
[harness] starting test origin on http://127.0.0.1:20085/ (docroot: origin/)
[harness] signature public key: OVzO3tr8I9gYeHGg38h1eKDjoV3a5Mqkb4QxmNdG/YM=
[harness] [SSH] PASS: tunnel=SSH, origin returned psiphon-harness-marker
[harness] [OSSH] PASS: tunnel=OSSH, origin returned psiphon-harness-marker
[harness] [TLS-OSSH] PASS: tunnel=TLS-OSSH, origin returned psiphon-harness-marker
[harness] [signature] PASS: wrong key rejected (verify signature failed, no tunnel)
[harness] [internet] PASS: https://example.com/ returned 200 through the tunnel
```

Rust checker (trimmed) — see `logs/rust-interop-evidence.log`:

```
signature: VERIFIED against OVzO3tr8I9gYeHGg38h1eKDjoV3a5Mqkb4QxmNdG/YM=
ssh: AUTHENTICATED, session_id=aab0aac7d90b13c43d253749ff11a601
handshake: ACCEPTED (200 byte response): {"client_region":"None", ...}
direct-tcpip: OK (209 bytes)
  psiphon-harness-marker
RESULT: PASS - Rust zero-psiphon carried a stream through the real psiphond
```
