//! The tunnel protocols a Psiphon server entry can advertise.
//!
//! Psiphon names a tunnel protocol by the transport stack it runs, and
//! records which ones a server speaks in the server entry's `capabilities`.
//! The names are wire identifiers: the strings below are the ones Psiphon
//! writes into server entries and tactics, so they must not be edited.

use std::fmt;

/// One Psiphon tunnel protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TunnelProtocol {
    /// SSH with no obfuscation. Looks like ordinary SSH on the wire.
    Ssh,
    /// SSH under the obfuscated-SSH stream cipher (OSSH).
    Ossh,
    /// OSSH under TLS (a self-signed certificate, not a real TLS name).
    TlsOssh,
    /// OSSH carried in an HTTP request/response exchange (meek), plain HTTP.
    UnfrontedMeek,
    UnfrontedMeekHttps,
    UnfrontedMeekSessionTicket,
    /// Meek through a CDN: the peer is a fronting domain, not the server.
    FrontedMeek,
    FrontedMeekHttp,
    ShadowsocksOssh,
    QuicOssh,
    FrontedMeekQuicOssh,
    TapdanceOssh,
    ConjureOssh,
}

impl TunnelProtocol {
    /// The protocol's wire name, as found in `capabilities` and tactics.
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelProtocol::Ssh => "SSH",
            TunnelProtocol::Ossh => "OSSH",
            TunnelProtocol::TlsOssh => "TLS-OSSH",
            TunnelProtocol::UnfrontedMeek => "UNFRONTED-MEEK-OSSH",
            TunnelProtocol::UnfrontedMeekHttps => "UNFRONTED-MEEK-HTTPS-OSSH",
            TunnelProtocol::UnfrontedMeekSessionTicket => "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
            TunnelProtocol::FrontedMeek => "FRONTED-MEEK-OSSH",
            TunnelProtocol::FrontedMeekHttp => "FRONTED-MEEK-HTTP-OSSH",
            TunnelProtocol::ShadowsocksOssh => "SHADOWSOCKS-OSSH",
            TunnelProtocol::QuicOssh => "QUIC-OSSH",
            TunnelProtocol::FrontedMeekQuicOssh => "FRONTED-MEEK-QUIC-OSSH",
            TunnelProtocol::TapdanceOssh => "TAPDANCE-OSSH",
            TunnelProtocol::ConjureOssh => "CONJURE-OSSH",
        }
    }

    /// The `capabilities` entry a server entry carries when it speaks this
    /// protocol.
    ///
    /// Psiphon derives it by dropping an `-OSSH` suffix (`protocol.go`
    /// `GetCapability`), which is why `OSSH` maps to `OSSH` while
    /// `TLS-OSSH` maps to `TLS`.
    pub fn capability(self) -> &'static str {
        match self {
            TunnelProtocol::Ssh => "SSH",
            TunnelProtocol::Ossh => "OSSH",
            TunnelProtocol::TlsOssh => "TLS",
            TunnelProtocol::UnfrontedMeek => "UNFRONTED-MEEK",
            TunnelProtocol::UnfrontedMeekHttps => "UNFRONTED-MEEK-HTTPS",
            TunnelProtocol::UnfrontedMeekSessionTicket => "UNFRONTED-MEEK-SESSION-TICKET",
            TunnelProtocol::FrontedMeek => "FRONTED-MEEK",
            TunnelProtocol::FrontedMeekHttp => "FRONTED-MEEK-HTTP",
            TunnelProtocol::ShadowsocksOssh => "SHADOWSOCKS",
            TunnelProtocol::QuicOssh => "QUIC",
            TunnelProtocol::FrontedMeekQuicOssh => "FRONTED-MEEK-QUIC",
            TunnelProtocol::TapdanceOssh => "TAPDANCE",
            TunnelProtocol::ConjureOssh => "CONJURE",
        }
    }

    /// Whether the protocol puts the obfuscated-SSH layer under SSH.
    pub fn uses_obfuscated_ssh(self) -> bool {
        !matches!(self, TunnelProtocol::Ssh)
    }

    /// Whether the protocol ends in an SSH session. Every protocol here does.
    pub fn uses_ssh(self) -> bool {
        true
    }

    /// Whether the peer is a CDN fronting domain rather than the server's own
    /// address.
    pub fn is_fronted(self) -> bool {
        matches!(
            self,
            TunnelProtocol::FrontedMeek
                | TunnelProtocol::FrontedMeekHttp
                | TunnelProtocol::FrontedMeekQuicOssh
        )
    }

    /// Whether the carrier is the HTTP (meek) exchange.
    pub fn uses_meek(self) -> bool {
        matches!(
            self,
            TunnelProtocol::UnfrontedMeek
                | TunnelProtocol::UnfrontedMeekHttps
                | TunnelProtocol::UnfrontedMeekSessionTicket
                | TunnelProtocol::FrontedMeek
                | TunnelProtocol::FrontedMeekHttp
                | TunnelProtocol::FrontedMeekQuicOssh
        )
    }

    /// The protocols this port of the client implements, best first. The
    /// order is a preference order among equally reachable candidates.
    pub fn supported(self) -> bool {
        // The transports this client can actually carry. A fronted
        // transport is carried the same way as an unfronted one, through a
        // CDN instead of the server's own address, so both are offered; a
        // fronted server entry that names no fronting address or host is
        // refused where it is dialled, with an error that says which field is
        // missing.
        matches!(
            self,
            TunnelProtocol::Ssh
                | TunnelProtocol::Ossh
                | TunnelProtocol::TlsOssh
                | TunnelProtocol::UnfrontedMeek
                | TunnelProtocol::UnfrontedMeekHttps
                | TunnelProtocol::UnfrontedMeekSessionTicket
                | TunnelProtocol::FrontedMeek
                | TunnelProtocol::FrontedMeekHttp
        )
    }

    /// Every protocol, for iterating a server entry's offers.
    pub fn all() -> &'static [TunnelProtocol] {
        &[
            TunnelProtocol::Ssh,
            TunnelProtocol::Ossh,
            TunnelProtocol::TlsOssh,
            TunnelProtocol::UnfrontedMeek,
            TunnelProtocol::UnfrontedMeekHttps,
            TunnelProtocol::UnfrontedMeekSessionTicket,
            TunnelProtocol::FrontedMeek,
            TunnelProtocol::FrontedMeekHttp,
            TunnelProtocol::ShadowsocksOssh,
            TunnelProtocol::QuicOssh,
            TunnelProtocol::FrontedMeekQuicOssh,
            TunnelProtocol::TapdanceOssh,
            TunnelProtocol::ConjureOssh,
        ]
    }

    /// Parse a wire name, e.g. `"OSSH"`.
    pub fn parse(name: &str) -> Option<TunnelProtocol> {
        TunnelProtocol::all()
            .iter()
            .copied()
            .find(|protocol| protocol.as_str() == name)
    }
}

impl fmt::Display for TunnelProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_drop_only_the_ossh_suffix() {
        // These are the strings Psiphon's `GetCapability` produces; a server
        // entry that lists them must select these protocols.
        assert_eq!(TunnelProtocol::Ssh.capability(), "SSH");
        assert_eq!(TunnelProtocol::Ossh.capability(), "OSSH");
        assert_eq!(TunnelProtocol::TlsOssh.capability(), "TLS");
        assert_eq!(TunnelProtocol::UnfrontedMeek.capability(), "UNFRONTED-MEEK");
        assert_eq!(
            TunnelProtocol::UnfrontedMeekHttps.capability(),
            "UNFRONTED-MEEK-HTTPS"
        );
        assert_eq!(TunnelProtocol::FrontedMeek.capability(), "FRONTED-MEEK");
        assert_eq!(TunnelProtocol::ShadowsocksOssh.capability(), "SHADOWSOCKS");
        assert_eq!(TunnelProtocol::QuicOssh.capability(), "QUIC");
        assert_eq!(
            TunnelProtocol::FrontedMeekQuicOssh.capability(),
            "FRONTED-MEEK-QUIC"
        );
    }

    #[test]
    fn names_round_trip() {
        for protocol in TunnelProtocol::all() {
            assert_eq!(
                TunnelProtocol::parse(protocol.as_str()),
                Some(*protocol),
                "{}",
                protocol.as_str()
            );
        }
        assert_eq!(TunnelProtocol::parse("NOT-A-PROTOCOL"), None);
    }
}
