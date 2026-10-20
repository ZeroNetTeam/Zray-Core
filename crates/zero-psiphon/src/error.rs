//! The errors this crate returns.
//!
//! Every variant says what stage failed. A caller deciding whether to try the
//! next server entry needs to tell "this server refused us" from "this network
//! is blocked" from "our configuration is wrong", so the variants are grouped
//! that way rather than flattened into a string.

use std::fmt;

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A server entry, tactics record or client configuration could not be
    /// read. Retrying will not help.
    #[error("configuration: {0}")]
    Config(String),

    /// A server entry's signature did not verify against the configured
    /// signing key. The entry must not be used.
    #[error("server entry signature: {0}")]
    Signature(String),

    /// The dial failed below the Psiphon layer: refused, unreachable, reset.
    #[error("connect: {0}")]
    Connect(String),

    /// The obfuscated-SSH layer refused or desynchronised.
    #[error("obfuscated ssh: {0}")]
    Obfuscation(String),

    /// The meek carrier failed (HTTP status, framing, cookie).
    #[error("meek: {0}")]
    Meek(String),

    /// The SSH handshake or authentication failed.
    #[error("ssh: {0}")]
    Ssh(String),

    /// The SSH connection is up but the destination could not be opened
    /// through it.
    #[error("tunnel channel: {0}")]
    Channel(String),

    /// The server answered, but with something this client does not
    /// understand (a protocol version, a field, a size).
    #[error("protocol: {0}")]
    Protocol(String),

    /// The operation ran out of time.
    #[error("timed out during {stage}")]
    Timeout { stage: &'static str },

    /// The client was shut down.
    #[error("closed")]
    Closed,

    /// An I/O error from the underlying stream.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// True when another server entry is worth trying, as opposed to a
    /// configuration or signature problem that will not change.
    pub fn is_retryable(&self) -> bool {
        !matches!(
            self,
            Error::Config(_) | Error::Signature(_) | Error::Protocol(_) | Error::Closed
        )
    }

    /// A short label for logs and metrics; never contains a secret.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Config(_) => "config",
            Error::Signature(_) => "signature",
            Error::Connect(_) => "connect",
            Error::Obfuscation(_) => "obfuscation",
            Error::Meek(_) => "meek",
            Error::Ssh(_) => "ssh",
            Error::Channel(_) => "channel",
            Error::Protocol(_) => "protocol",
            Error::Timeout { .. } => "timeout",
            Error::Closed => "closed",
            Error::Io(_) => "io",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which step of a dial or request was running when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Resolve,
    Tcp,
    Tls,
    Meek,
    Obfuscation,
    SshKex,
    SshAuth,
    Channel,
    Tactics,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Resolve => "resolve",
            Stage::Tcp => "connect",
            Stage::Tls => "tls",
            Stage::Meek => "meek",
            Stage::Obfuscation => "obfuscated ssh",
            Stage::SshKex => "ssh key exchange",
            Stage::SshAuth => "ssh authentication",
            Stage::Channel => "tunnel channel",
            Stage::Tactics => "tactics",
        }
    }
}

/// Shorthand used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Wrap a `Display` error as [`Error::Config`].
pub fn config<T, E: fmt::Display>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|error| Error::Config(error.to_string()))
}

/// Wrap a `Display` error as [`Error::Protocol`].
pub fn protocol<T, E: fmt::Display>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|error| Error::Protocol(error.to_string()))
}
