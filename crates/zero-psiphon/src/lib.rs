//! A native Psiphon client.
//!
//! Psiphon is a circumvention system whose client is a Go program
//! (`psiphon-tunnel-core`). This crate is a port of the parts a proxy needs:
//! it reads the same client configuration and server entries, fetches and
//! verifies tactics, dials a Psiphon server over the same transports
//! (obfuscated SSH, TLS-obfuscated SSH, meek, and plain SSH), and turns the
//! resulting SSH connection into streams to arbitrary destinations.
//!
//! The crate is deliberately free of routing, DNS and policy: it hands out
//! streams the way `zero-tor` does, and `zero-runtime` decides who gets one.
//!
//! Layout:
//!
//! * [`server_entry`] — the signed, self-describing record of one server.
//! * [`json`] — the exact JSON encoding Go's `encoding/json` produces, which
//!   the server-entry signature covers.
//! * [`config`] — the client configuration (`"Psiphon"` in a Zray outbound).
//! * [`tactics`] — remote parameter fetch and signature verification.
//! * [`obfuscator`] — the obfuscated SSH (OSSH) layer.
//! * [`meek`] — the HTTP request/response carrier Psiphon calls meek.
//! * [`tunnel`] — the SSH client and its `direct-tcpip` channels.
//! * [`shared`] — one client per configuration, shared by its connections.
//! * [`client`] — server selection, the dial loop and stream handout.
//!
//! Nothing here knows about Zray's config file, its stats or its router.

pub mod client;
pub mod config;
pub mod error;
pub mod json;
pub mod meek;
pub(crate) mod nacl_box;
pub mod obfuscator;
pub mod protocol;
pub mod server_entry;
pub mod shared;
pub mod tactics;
pub mod tls_ossh;
pub mod tunnel;

/// The in-process mock server. Behind a feature so the shipped binary
/// carries none of it.
#[cfg(feature = "test-util")]
pub mod mock;

/// The self-signed certificate the crate's own TLS test servers use. Test
/// material only, and only compiled for tests.
#[cfg(test)]
pub(crate) mod test_certificate;

pub use client::Client;
pub use config::{ClientConfig, UpstreamProxy, UpstreamProxyKind};
pub use error::Error;
pub use protocol::TunnelProtocol;
pub use server_entry::ServerEntry;
pub use shared::dial;
pub use tunnel::{HandshakeParams, SshTunnel, TunnelOptions, TunnelStream};
