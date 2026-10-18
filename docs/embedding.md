# Using Zray Core from another repository

Zray Core is a Cargo workspace of libraries plus one program (`zray`). The apps
that sit on top of it live in their own repositories:

| Repository | What it is | How it uses the core |
|---|---|---|
| ZeroNet-Desktop | the terminal app | Rust crates as git dependencies |
| ZeroNet-Mobile | the Android app | Rust crates through its own `native/zray-mobile` library (JNI) |
| Z-UI | the graphical app | the same as the desktop app: Rust crates as git dependencies |

This page is the recipe, so a new front end starts from the same place the
existing ones did.

## 1. Depend on the crates

Every crate in `crates/` can be named on its own. A front end takes only the
ones it calls. The terminal app uses these, which is a good starting list:

```toml
# Cargo.toml of the front end
[workspace.dependencies]
zero-core      = { git = "https://github.com/ZeroNetTeam/Zray-Core", version = "0.1.0", branch = "main" }
zero-config    = { git = "https://github.com/ZeroNetTeam/Zray-Core", version = "0.1.0", branch = "main" }
zero-runtime   = { git = "https://github.com/ZeroNetTeam/Zray-Core", version = "0.1.0", branch = "main" }
zero-tun       = { git = "https://github.com/ZeroNetTeam/Zray-Core", version = "0.1.0", branch = "main" }
zero-discovery = { git = "https://github.com/ZeroNetTeam/Zray-Core", version = "0.1.0", branch = "main" }
zero-provision = { git = "https://github.com/ZeroNetTeam/Zray-Core", version = "0.1.0", branch = "main" }
# ... zero-scanner, zero-evasion, zero-security, zero-transport as needed

# Cargo ignores a dependency's own [patch] and [profile], so a front end repeats
# them. Leave the patch out and the core is built against stock rustls instead
# of the vendored fork (ClientHello shaping) and without the netstack fix.
[patch.crates-io]
rustls           = { git = "https://github.com/ZeroNetTeam/Zray-Core", branch = "main" }
netstack-smoltcp = { git = "https://github.com/ZeroNetTeam/Zray-Core", branch = "main" }
```

The `version` is there for cargo-deny, which rejects wildcard requirements.
Commit the front end's `Cargo.lock`: it is what pins the core revision; `cargo update -p zero-core` moves it forward on purpose.

Copy `[profile.release]` and its three per-package overrides from this
repository's `Cargo.toml`. They are what the size and speed numbers in
`docs/benchmarks` were measured with.

## 2. Pick how the front end drives the engine

* **As a library.** Build a config (`zero-config`), start a `zero_runtime::Server`,
  read its `stats`, stop it. Find servers with `zero-discovery`, set one up on
  the person's own machine with `zero-provision`, bring the TUN device up with
  `zero-tun`. `zero_runtime::api` is a small loopback management API
  (statistics and an authenticated whole-config reload) if the engine runs
  in a separate process from the window.
* **As a sidecar.** Ship the `zray` binary from the Releases page and run
  `zray run config.json`. Nothing to link, the cost is a second process.
* **Through a C ABI or JSON jobs.** What a host that is not Rust does. The
  Android app's `zray-mobile` is the working example: a thin C ABI over the
  runtime, plus string-in, events-out jobs for discovery and server setup.
  It lives in ZeroNet-Mobile (`native/zray-mobile`).

## 3. Work on the core and a front end together

Clone the repositories side by side, then point the front end at the local core:

```sh
Zray-Core/tools/link-local.sh ../ZeroNet-Desktop    # or ../Z-UI
```

That writes `.cargo/config.toml` in the front end with a `[patch]` for every
crate here, and deleting the file goes back to the pinned revision. While it
exists, Cargo also rewrites the front end's `Cargo.lock` to match your
checkout, so `git checkout Cargo.lock` before committing there. Land the
core change first, then run `cargo update -p zero-core` in the front end so
its `Cargo.lock` records the new revision.

## 4. What the core publishes

* `rankings.json`, `verified.txt` (signed), `domestic-sni.txt` and the harvest
  state, on this repository's `crowd-data` branch, written by the `harvest`,
  `fresh` and `crowd` workflows. The apps read them from
  `raw.githubusercontent.com` and the jsDelivr mirrors.
* `ZrayCore-*` binaries and a signed `SHA256SUMS.txt` on each release, which
  the apps' "My server" installer downloads. The public half of the signing key
  is compiled into `zero-discovery` (`sign.rs`).
