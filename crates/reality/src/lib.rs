//! `reality` — the REALITY **server**, in Rust.
//!
//! REALITY is the layer Xray puts under VLESS and Trojan so that a proxy
//! connection is indistinguishable from a browser talking to a real site: the
//! client's ClientHello hides an authentication tag in its session id, and a
//! peer that cannot produce that tag is quietly handed to the site the
//! attacker expects to see. This crate is the server half of that protocol —
//! the half a *server* operator runs, whether the clients connecting to it run
//! Xray or Zray.
//!
//! The wire behavior is the Go implementation's, checked item by item against
//! `github.com/xtls/reality` at the revision Xray 26.3.27 pins, with
//! `Xray client → Zray server` differential tests as the proof
//! (`zero-runtime/tests/xray_oracle.rs`) and the port described in
//! `docs/specs/REALITY-server.md`.
//!
//! Layout:
//!
//! * [`server`] — the handshake: ClientHello intake, the session seal, the
//!   ServerHello flight, the HMAC "certificate", the ML-DSA-65 binding, and
//!   the decision to accept or to fall back to the camouflage target.
//! * [`fallback`] — what the server does with a visitor that is *not* REALITY:
//!   the PROXY protocol header the target asked for, the ClientHello replayed
//!   exactly as it arrived, and a rate-limited relay to the camouflage site.
//! * [`keys`] — the server's key material, in the encodings `xray x25519`,
//!   `xray mldsa65` and a `shortIds` entry use.
//!
//! The TLS 1.3 record layer underneath is not REALITY's: it is the same
//! minimal substrate the client uses, in `zero-security::tls13`, and it stays
//! there so a REALITY protocol change cannot destabilise ordinary TLS and the
//! other way round.

pub mod config;
pub mod fallback;
pub mod keys;
pub mod server;

pub use config::RealityServerConfig;
pub use fallback::{FallbackError, FallbackLimit, FallbackOutcome, FallbackPolicy, Transferred};
pub use server::{
    handshake_or_fallback, HandshakeOutcome, PostHandshakeShapes, RealityServerParams,
};
