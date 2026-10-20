//! The Psiphon client configuration.
//!
//! This is the `"Psiphon"` object of a Zray outbound minus everything that is
//! Zray's business (routing, DNS, stats): where the server entries are, which
//! signing key to trust, whether to fetch tactics, how to reach the network (a
//! direct socket or an upstream SOCKS/HTTP proxy), and how many tunnels to
//! keep.
//!
//! The field names are Psiphon's own `config.json` names in snake case, so a
//! configuration can be translated from a Go client's config without a
//! lookup table (see `docs/psiphon/INTEGRATION.md` §6.3).

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::protocol::TunnelProtocol;
use crate::server_entry::ServerEntry;

/// How an upstream proxy is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamProxyKind {
    /// A SOCKS5 proxy, with remote name resolution.
    Socks5,
    /// An HTTP `CONNECT` proxy.
    Http,
}

/// The proxy this client reaches Psiphon through.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UpstreamProxy {
    pub kind: UpstreamProxyKind,
    /// Host or IP, unresolved.
    pub host: String,
    pub port: u16,
    /// `user:password`, when the proxy wants credentials.
    pub credential: Option<String>,
}

impl std::fmt::Debug for UpstreamProxy {
    /// Proxy credentials never reach a log: the rendering says that one is
    /// present and nothing more.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamProxy")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl UpstreamProxy {
    /// Parse Psiphon's `UpstreamProxyUrl` form: `socks5://host:port` or
    /// `http://user:password@host:port`.
    pub fn parse(url: &str) -> Result<UpstreamProxy> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| Error::Config(format!("upstream proxy URL {url:?} has no scheme")))?;

        let kind = match scheme.to_ascii_lowercase().as_str() {
            "socks5" | "socks" | "socks5h" => UpstreamProxyKind::Socks5,
            "http" => UpstreamProxyKind::Http,
            other => {
                return Err(Error::Config(format!(
                    "upstream proxy scheme {other:?} is not supported"
                )))
            }
        };

        // Credentials, then the authority.
        let (credential, authority) = match rest.rsplit_once('@') {
            Some((credentials, authority)) => (Some(credentials.to_string()), authority),
            None => (None, rest),
        };
        let authority = authority.trim_end_matches('/');

        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| Error::Config(format!("upstream proxy URL {url:?} has no port")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| Error::Config(format!("upstream proxy URL {url:?} has a bad port")))?;
        if host.is_empty() {
            return Err(Error::Config(format!(
                "upstream proxy URL {url:?} has no host"
            )));
        }

        Ok(UpstreamProxy {
            kind,
            host: host.to_string(),
            port,
            credential: credential.filter(|value| !value.is_empty()),
        })
    }
}

/// The client identity the tunnel handshake announces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeIdentity {
    /// Psiphon's `PropagationChannelId`: 16 hex characters.
    pub propagation_channel_id: String,
    /// Psiphon's `SponsorId`: 16 hex characters, or empty for none.
    pub sponsor_id: String,
    /// The Psiphon client version the handshake announces. Psiphon's server
    /// validates this as an integer string, and it is *not* the SSH
    /// identification line, which `TunnelOptions::client_version` carries.
    pub client_version: String,
    /// Psiphon's `ClientPlatform` (`Windows`, `Android`, `Linux`, `Other`).
    pub client_platform: String,
}

impl Default for HandshakeIdentity {
    fn default() -> Self {
        HandshakeIdentity {
            propagation_channel_id: "0000000000000000".into(),
            sponsor_id: String::new(),
            client_version: "1".into(),
            client_platform: "Other".into(),
        }
    }
}

impl HandshakeIdentity {
    /// Validate Psiphon's rules for the identifiers: 16 hex characters each,
    /// sponsor optional, platform non-empty.
    pub fn validate(&self) -> Result<()> {
        if self.propagation_channel_id.len() != 16
            || !self
                .propagation_channel_id
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::Config(
                "PropagationChannelId must be 16 hex characters".into(),
            ));
        }
        if !self.sponsor_id.is_empty()
            && (self.sponsor_id.len() != 16
                || !self.sponsor_id.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(Error::Config(
                "SponsorId must be empty or 16 hex characters".into(),
            ));
        }
        if self.client_platform.is_empty()
            || self.client_platform.chars().any(|c| c.is_whitespace())
        {
            // The server rejects a platform with whitespace in it, and a
            // client that is refused at the handshake has no way to say why.
            return Err(Error::Config(
                "ClientPlatform must not be empty or contain whitespace".into(),
            ));
        }
        if self.client_version.trim().is_empty()
            || !self
                .client_version
                .trim()
                .chars()
                .all(|c| c.is_ascii_digit())
        {
            // The server rejects anything else with a bare "invalid parameter",
            // which is a hard failure to diagnose from a dial log.
            return Err(Error::Config(
                "ClientVersion must be a non-empty integer string".into(),
            ));
        }
        Ok(())
    }
}

/// A configured Psiphon client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server entries to try, in preference order.
    pub server_entries: Vec<ServerEntry>,
    /// The Ed25519 public key (base64) that signed remote server entries.
    pub server_entry_signature_public_key: Option<String>,
    /// Where remote server lists are fetched from.
    pub remote_server_list_urls: Vec<String>,
    /// Whether to fetch and apply tactics before the first dial.
    pub tactics: bool,
    /// Where tactics are fetched from, when the client fetches them.
    pub tactics_url: Option<String>,
    /// Where imported entries and tactics may be persisted. Zray keeps this
    /// in memory; the field exists so a caller can record where it would go.
    pub data_dir: Option<std::path::PathBuf>,
    /// An upstream proxy to reach Psiphon through.
    pub upstream_proxy: Option<UpstreamProxy>,
    /// Egress region (`"US"`, `"GB"`, …), empty for any.
    pub egress_region: String,
    /// Tunnel transports the client may use. Empty means every transport the
    /// entries support, in Psiphon's preference order.
    pub protocols: Vec<TunnelProtocol>,
    /// Budget for one candidate's tunnel establishment.
    pub establish_timeout: Duration,
    /// How many candidates may be dialled at once.
    pub establish_concurrency: usize,
    /// How many tunnels to keep established and round-robin between.
    pub tunnel_pool_size: usize,
    /// Channel window size for TLS/OSSH-transported sessions.
    pub channel_window_bytes: u32,
    /// Refuse to open more than this many channels at once.
    pub max_channels: u32,
    /// `keepalive@openssh.com` interval; `None` disables keepalives.
    pub keepalive_interval: Option<Duration>,
    /// The identity announced in the handshake and the credential payload.
    pub handshake: HandshakeIdentity,
    /// Session ID to use; a fresh random one when absent.
    pub session_id: Option<String>,
    /// The padding range the obfuscated layer uses, `(minimum, maximum)`.
    /// `None` means the layer's own defaults; tactics may set it.
    pub ossh_padding: Option<(usize, usize)>,
    /// Where the carriers get the parts of a dial that a server entry does
    /// not carry, chiefly so a test can point a fronted transport at a local
    /// stand-in for a CDN.
    pub dial_options: TunnelDialOptions,
}

/// The dial details a server entry does not state.
#[derive(Debug, Clone, Default)]
pub struct TunnelDialOptions {
    /// The port a fronted transport dials. `None` uses the transport's own
    /// default: 443 for the HTTPS fronting, 80 for the plain-HTTP one.
    pub fronted_dial_port: Option<u16>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            server_entries: Vec::new(),
            server_entry_signature_public_key: None,
            remote_server_list_urls: Vec::new(),
            tactics: false,
            tactics_url: None,
            data_dir: None,
            upstream_proxy: None,
            egress_region: String::new(),
            protocols: Vec::new(),
            establish_timeout: Duration::from_secs(20),
            // Psiphon dials several candidates at once so a slow or blocked
            // address does not delay the tunnel; four is its own ceiling for
            // the client.
            establish_concurrency: 3,
            tunnel_pool_size: 1,
            channel_window_bytes: 4 * 1024 * 1024,
            max_channels: 128,
            keepalive_interval: Some(Duration::from_secs(25)),
            handshake: HandshakeIdentity::default(),
            session_id: None,
            ossh_padding: None,
            dial_options: TunnelDialOptions::default(),
        }
    }
}

impl ClientConfig {
    /// Reject what would fail later anyway, with a message that says why.
    pub fn validate(&self) -> Result<()> {
        if self.server_entries.is_empty() {
            return Err(Error::Config(
                "the psiphon outbound has no server entries".into(),
            ));
        }
        self.handshake.validate()?;

        if !(1..=8).contains(&self.establish_concurrency) {
            return Err(Error::Config(format!(
                "establish_concurrency must be between 1 and 8, not {}",
                self.establish_concurrency
            )));
        }
        if !(1..=4).contains(&self.tunnel_pool_size) {
            return Err(Error::Config(format!(
                "tunnel_pool_size must be between 1 and 4, not {}",
                self.tunnel_pool_size
            )));
        }
        if self.max_channels == 0 {
            return Err(Error::Config("max_channels must not be zero".into()));
        }
        if self.establish_timeout.is_zero() {
            return Err(Error::Config("establish_timeout must not be zero".into()));
        }
        if let Some(session_id) = self.session_id.as_deref() {
            if session_id.len() != 2 * crate::tunnel::SESSION_ID_BYTES
                || !session_id.chars().all(|c| c.is_ascii_hexdigit())
                || session_id.chars().any(|c| c.is_ascii_uppercase())
            {
                return Err(Error::Config(
                    "session_id must be 32 lowercase hex characters".into(),
                ));
            }
        }

        for entry in &self.server_entries {
            if let Some(key) = self.server_entry_signature_public_key.as_deref() {
                if entry.has_signature() {
                    // A bad signature is a configuration emergency, not a
                    // reason to try the next entry, so it fails here rather
                    // than during the dial loop.
                    entry.verify_signature(key)?;
                }
            }
        }

        if !self.protocols.is_empty() {
            for entry in &self.server_entries {
                let supported = entry.supported_protocols();
                if !supported.iter().any(|p| self.protocols.contains(p)) {
                    tracing::debug!(
                        target: "zero_psiphon",
                        entry = %entry.diagnostic_id(),
                        "server entry offers none of the configured transports"
                    );
                }
            }
        }

        Ok(())
    }

    /// A hash over every field that changes the tunnel, secrets included.
    ///
    /// Callers use it as a cache key for one established client per
    /// configuration. It is never printed: it commits to the server entry
    /// passwords and the obfuscation keys, so it is a secret itself.
    pub fn key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zero-psiphon-client-config-v1");
        hasher.update(self.egress_region.as_bytes());
        hasher.update(self.establish_timeout.as_millis().to_le_bytes());
        hasher.update(self.establish_concurrency.to_le_bytes());
        hasher.update(self.tunnel_pool_size.to_le_bytes());
        hasher.update(self.channel_window_bytes.to_le_bytes());
        hasher.update(self.max_channels.to_le_bytes());
        hasher.update(self.handshake.propagation_channel_id.as_bytes());
        hasher.update(self.handshake.sponsor_id.as_bytes());
        hasher.update(self.handshake.client_version.as_bytes());
        hasher.update(self.handshake.client_platform.as_bytes());
        if let Some(interval) = self.keepalive_interval {
            hasher.update(interval.as_millis().to_le_bytes());
        }
        if let Some(session_id) = self.session_id.as_deref() {
            hasher.update(session_id.as_bytes());
        }
        if let Some(proxy) = &self.upstream_proxy {
            hasher.update(format!("{:?}:{}:{}", proxy.kind, proxy.host, proxy.port).as_bytes());
            if let Some(credential) = &proxy.credential {
                hasher.update(credential.as_bytes());
            }
        }
        for protocol in &self.protocols {
            hasher.update(protocol.as_str().as_bytes());
        }
        // The entries themselves: an entry's identity is its tag plus the key
        // material, and the tag is derived from exactly those fields.
        for entry in &self.server_entries {
            hasher.update(entry.tag().as_bytes());
            hasher.update(entry.ssh_obfuscated_key().as_bytes());
            hasher.update(entry.ssh_password().as_bytes());
            hasher.update(entry.ssh_host_key_bytes().unwrap_or_default());
        }
        hasher.finalize().into()
    }

    /// Read a client configuration from the `"Psiphon"` settings object of a
    /// Zray outbound.
    pub fn from_value(value: serde_json::Value) -> Result<ClientConfig> {
        let object = value.as_object().ok_or_else(|| {
            Error::Config("the Psiphon outbound settings must be an object".into())
        })?;

        let mut config = ClientConfig {
            tactics: object
                .get("tactics")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            ..Default::default()
        };

        // Server entries: an array of objects, a single object, a signed
        // array, or a JSON string holding any of those.
        if let Some(entries) = object.get("server_entries") {
            config.server_entries = parse_entries(entries)?;
        }

        if let Some(key) = string_field(object, &["server_entry_signature_public_key"])? {
            config.server_entry_signature_public_key = Some(key);
        }
        if let Some(url) = string_field(object, &["tactics_url"])? {
            config.tactics_url = Some(url);
        }
        if let Some(dir) = string_field(object, &["data_dir"])? {
            config.data_dir = Some(std::path::PathBuf::from(dir));
        }
        if let Some(region) = string_field(object, &["egress_region"])? {
            config.egress_region = region;
        }
        if let Some(url) = string_field(object, &["upstream_proxy_url"])? {
            config.upstream_proxy = Some(UpstreamProxy::parse(&url)?);
        }
        if let Some(session_id) = string_field(object, &["session_id"])? {
            config.session_id = Some(session_id);
        }
        if let Some(channel) = string_field(object, &["propagation_channel_id"])? {
            config.handshake.propagation_channel_id = channel;
        }
        if let Some(version) = string_field(object, &["client_version"])? {
            config.handshake.client_version = version;
        }
        if let Some(platform) = string_field(object, &["client_platform"])? {
            config.handshake.client_platform = platform;
        }
        // `sponsor_id` is settable and explicitly empty-able.
        if object.contains_key("sponsor_id") {
            config.handshake.sponsor_id =
                string_field(object, &["sponsor_id"])?.unwrap_or_default();
        }

        if let Some(urls) = object.get("remote_server_list_urls") {
            config.remote_server_list_urls = match urls {
                serde_json::Value::String(url) => vec![url.clone()],
                serde_json::Value::Array(list) => list
                    .iter()
                    .map(|value| {
                        value.as_str().map(str::to_string).ok_or_else(|| {
                            Error::Config("remote_server_list_urls entries must be strings".into())
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                _ => {
                    return Err(Error::Config(
                        "remote_server_list_urls must be a string or an array of strings".into(),
                    ))
                }
            };
        }

        if let Some(protocols) = object.get("limit_tunnel_protocols") {
            config.protocols = parse_protocols(protocols)?;
        } else if let Some(protocols) = object.get("protocols") {
            config.protocols = parse_protocols(protocols)?;
        }

        if let Some(value) = object.get("establish_timeout_seconds") {
            config.establish_timeout =
                Duration::from_millis(number(value, 1.0, 600.0)?.round() as u64 * 1000);
        }
        if let Some(value) = object.get("establish_concurrency") {
            config.establish_concurrency = number(value, 1.0, 8.0)? as usize;
        }
        if let Some(value) = object.get("tunnel_pool_size") {
            config.tunnel_pool_size = number(value, 1.0, 4.0)? as usize;
        }
        if let Some(value) = object.get("max_channels") {
            config.max_channels = number(value, 1.0, 4096.0)? as u32;
        }
        if let Some(value) = object.get("channel_window_bytes") {
            config.channel_window_bytes =
                number(value, 32.0 * 1024.0, 64.0 * 1024.0 * 1024.0)? as u32;
        }
        if let Some(value) = object.get("keepalive_interval_seconds") {
            config.keepalive_interval = match number(value, 1.0, 3600.0)? {
                0.0 => None,
                seconds => Some(Duration::from_millis((seconds * 1000.0) as u64)),
            };
        }

        Ok(config)
    }
}

/// Server entries may arrive as an object, an array, a signed array (the Go
/// client's `serverList` array of objects with `data`), or a JSON string.
fn parse_entries(value: &serde_json::Value) -> Result<Vec<ServerEntry>> {
    match value {
        serde_json::Value::Array(entries) => entries.iter().map(entry_from_value).collect(),
        serde_json::Value::Object(_) => Ok(vec![entry_from_value(value)?]),
        serde_json::Value::String(text) => {
            let parsed: serde_json::Value = serde_json::from_str(text).map_err(|error| {
                Error::Config(format!("server_entries is not valid JSON: {error}"))
            })?;
            parse_entries(&parsed)
        }
        _ => Err(Error::Config(
            "server_entries must be a server entry object, an array of them, or their JSON".into(),
        )),
    }
}

fn entry_from_value(value: &serde_json::Value) -> Result<ServerEntry> {
    ServerEntry::from_value(value.clone())
}

fn parse_protocols(value: &serde_json::Value) -> Result<Vec<TunnelProtocol>> {
    let list = value
        .as_array()
        .ok_or_else(|| Error::Config("protocols must be an array of names".into()))?;

    let mut protocols = Vec::with_capacity(list.len());
    for name in list {
        let name = name
            .as_str()
            .ok_or_else(|| Error::Config("protocol names must be strings".into()))?;
        let protocol = TunnelProtocol::parse(name).ok_or_else(|| {
            Error::Config(format!(
                "protocol {name:?} is not a Psiphon tunnel protocol"
            ))
        })?;
        protocols.push(protocol);
    }
    Ok(protocols)
}

/// A field that may be absent, or a string, or (invalid) something else.
fn string_field(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Result<Option<String>> {
    for name in names {
        if let Some(value) = object.get(*name) {
            if value.is_null() {
                return Ok(None);
            }
            let text = value
                .as_str()
                .ok_or_else(|| Error::Config(format!("{name} must be a string")))?;
            return Ok(Some(text.to_string()));
        }
    }
    Ok(None)
}

/// A number inside an inclusive range. Floats are accepted because JSON has
/// no integer type.
fn number(value: &serde_json::Value, minimum: f64, maximum: f64) -> Result<f64> {
    let number = value
        .as_f64()
        .ok_or_else(|| Error::Config("a numeric setting was not a number".into()))?;
    if number < minimum || number > maximum {
        return Err(Error::Config(format!(
            "a numeric setting is outside {minimum}..={maximum}: {number}"
        )));
    }
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::TunnelProtocol;

    fn entry(region: &str, capabilities: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "ipAddress": "127.0.0.1",
            "region": region,
            "sshPort": 20081,
            "sshObfuscatedPort": 20082,
            "tlsOSSHPort": 20083,
            "sshHostKey": "AAAA",
            "sshPassword": "password",
            "capabilities": capabilities,
        })
    }

    #[test]
    fn a_minimal_configuration_parses_and_validates() {
        let config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH", "OSSH"])],
        }))
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.server_entries.len(), 1);
        assert_eq!(config.establish_timeout, Duration::from_secs(20));
        assert!(!config.tactics, "tactics are off unless asked for");
    }

    #[test]
    fn a_single_entry_and_a_json_string_both_work() {
        let single = ClientConfig::from_value(serde_json::json!({
            "server_entries": entry("GB", &["SSH"]),
        }))
        .unwrap();
        assert_eq!(single.server_entries.len(), 1);
        assert_eq!(single.server_entries[0].region(), "GB");

        let encoded = serde_json::json!({
            "server_entries": serde_json::to_string(&vec![entry("US", &["OSSH"])]).unwrap(),
        });
        let from_string = ClientConfig::from_value(encoded).unwrap();
        assert_eq!(from_string.server_entries.len(), 1);
    }

    #[test]
    fn transports_and_settings_are_read() {
        let config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH", "OSSH", "TLS-OSSH"])],
            "protocols": ["OSSH", "TLS-OSSH"],
            "egress_region": "US",
            "establish_timeout_seconds": 12,
            "establish_concurrency": 2,
            "tunnel_pool_size": 2,
            "keepalive_interval_seconds": 15,
            "upstream_proxy_url": "socks5://127.0.0.1:1080",
            "tactics": true,
        }))
        .unwrap();
        config.validate().unwrap();

        assert_eq!(
            config.protocols,
            vec![TunnelProtocol::Ossh, TunnelProtocol::TlsOssh]
        );
        assert_eq!(config.establish_timeout, Duration::from_secs(12));
        assert_eq!(config.establish_concurrency, 2);
        assert_eq!(config.tunnel_pool_size, 2);
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(
            config.upstream_proxy.as_ref().unwrap().kind,
            UpstreamProxyKind::Socks5
        );
        assert!(config.tactics);
    }

    #[test]
    fn bad_settings_are_rejected_with_a_reason() {
        // No entries at all.
        let error = ClientConfig::default().validate().unwrap_err();
        assert!(error.to_string().contains("no server entries"), "{error}");

        // An out-of-range dial concurrency.
        let config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH"])],
            "establish_concurrency": 99,
        }));
        assert!(config.is_err(), "99 is outside the accepted range");

        // An unknown transport name.
        let config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH"])],
            "protocols": ["SSH", "I2P"],
        }));
        assert!(config.is_err(), "I2P is not a Psiphon transport");

        // An uppercase session id, which Psiphon never sends.
        let config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH"])],
            "session_id": "00112233445566778899AABBCCDDEEFF",
        }))
        .unwrap();
        assert!(config.validate().is_err());

        // A proxy URL with an unsupported scheme.
        assert!(UpstreamProxy::parse("ftp://127.0.0.1:21").is_err());
        assert!(UpstreamProxy::parse("socks5://127.0.0.1").is_err());
    }

    #[test]
    fn the_identity_rules_are_psiphons() {
        let mut config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH"])],
            "propagation_channel_id": "not-hex-at-all!",
        }))
        .unwrap();
        assert!(config.validate().is_err());

        config.handshake.propagation_channel_id = "0123456789abcdef".into();
        config.handshake.sponsor_id = "fedcba9876543210".into();
        config.validate().unwrap();
    }

    #[test]
    fn the_key_tracks_the_fields_that_change_the_tunnel() {
        let base = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH"])],
        }))
        .unwrap();
        let same = base.clone();
        assert_eq!(base.key(), same.key());

        let mut different = base.clone();
        different.egress_region = "GB".into();
        assert_ne!(base.key(), different.key());

        // Secrets are part of the key: two entries that differ only in a
        // password must not share a cached client.
        let mut other_entry = entry("US", &["SSH"]);
        other_entry["sshPassword"] = "different".into();
        let rekeyed = ClientConfig::from_value(serde_json::json!({
            "server_entries": [other_entry],
        }))
        .unwrap();
        assert_ne!(base.key(), rekeyed.key());
    }

    #[test]
    fn the_debug_output_does_not_print_secrets() {
        let config = ClientConfig::from_value(serde_json::json!({
            "server_entries": [entry("US", &["SSH"])],
            "upstream_proxy_url": "http://user:secret-password@127.0.0.1:8080",
        }))
        .unwrap();
        let printed = format!("{config:?}");
        assert!(!printed.contains("secret-password"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
}
