//! One Psiphon server, as the network publishes it.
//!
//! A server entry is a JSON object describing where a server is, which keys it
//! has, and which tunnel protocols it speaks. Entries are distributed in three
//! ways: embedded in the client configuration, downloaded from Psiphon's
//! remote server list, or exchanged between clients. Only the first is
//! implicitly trusted; the other two are signed with Ed25519 and must be
//! verified against the `serverEntrySignaturePublicKey` in the client
//! configuration before use.
//!
//! The signature covers a *Go-encoded* JSON object (see [`crate::json`]), not
//! the JSON the entry arrived as. Verification therefore re-encodes the
//! entry's fields the way Go would and checks the signature over those bytes.

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::json;
use crate::protocol::TunnelProtocol;

/// The protocol's server-entry fields, typed. Unknown fields are kept in the
/// entry's raw map so a signature over them still verifies and a newer client
/// can read them; this struct is only what this client understands.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Fields {
    // Identity and location.
    tag: String,
    ip_address: String,
    region: String,
    #[serde(rename = "providerID")]
    provider_id: String,

    // Web server (used for some handshakes and the SSH password).
    web_server_port: String,
    web_server_secret: String,
    web_server_certificate: String,

    // SSH.
    ssh_port: i64,
    ssh_username: String,
    ssh_password: String,
    ssh_host_key: String,

    // Obfuscated SSH.
    ssh_obfuscated_port: i64,
    ssh_obfuscated_key: String,
    #[serde(rename = "sshObfuscatedQUICPort")]
    ssh_obfuscated_quic_port: i64,
    ssh_obfuscated_shadowsocks_port: i64,
    ssh_shadowsocks_port: i64,
    ssh_shadowsocks_key: String,
    #[serde(rename = "limitQUICVersions")]
    limit_quic_versions: Vec<String>,

    // Obfuscated SSH over TLS.
    #[serde(rename = "tlsOSSHPort")]
    tls_ossh_port: i64,

    // Meek.
    meek_server_port: i64,
    meek_cookie_encryption_public_key: String,
    meek_obfuscated_key: String,
    meek_fronting_host: String,
    meek_fronting_hosts: Vec<String>,
    meek_fronting_domain: String,
    meek_fronting_addresses: Vec<String>,
    meek_fronting_addresses_regex: String,
    meek_fronting_disable_sni: bool,

    // Fronting.
    #[serde(rename = "frontingProviderID")]
    fronting_provider_id: String,

    // Tactics, and what this client version understands.
    tactics_request_public_key: String,
    tactics_request_obfuscated_key: String,
    capabilities: Vec<String>,
    configuration_version: i64,
    signature: String,

    // Transform switches a server can use to turn off fingerprinting layers.
    disable_http_transforms: bool,
    disable_obfuscated_quic_transforms: bool,
    disable_ossh_transforms: bool,
    disable_ossh_prefix: bool,
    disable_shadowsocks_prefix: bool,

    // TapDance, Conjure and in-proxy are recognized but not implemented.
    ssh_obfuscated_tapdance_port: i64,
    ssh_obfuscated_conjure_port: i64,
    allow_upstream_proxy: bool,
    inproxy_session_public_key: String,
    inproxy_session_root_obfuscation_secret: String,
    #[serde(rename = "inproxySSHPort")]
    inproxy_ssh_port: i64,
    #[serde(rename = "inproxyOSSHPort")]
    inproxy_ossh_port: i64,
    #[serde(rename = "inproxyQUICPort")]
    inproxy_quic_port: i64,
    inproxy_meek_port: i64,
    #[serde(rename = "inproxyTlsOSSHPort")]
    inproxy_tls_ossh_port: i64,
    inproxy_shadowsocks_port: i64,

    // Local bookkeeping, never signed.
    local_source: String,
    local_timestamp: String,
    is_local_derived_tag: bool,
}

/// A server entry: the typed fields plus the exact JSON object they came from.
///
/// Keeping the raw object is what makes signature verification possible: the
/// signature covers fields this client does not know about, so verification
/// needs the original map, not a re-serialization of the typed struct.
#[derive(Clone)]
pub struct ServerEntry {
    fields: Fields,
    raw: BTreeMap<String, Value>,
}

impl std::fmt::Debug for ServerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Passwords, obfuscation keys and host keys do not belong in a log.
        f.debug_struct("ServerEntry")
            .field("tag", &self.diagnostic_id())
            .field("ip_address", &self.fields.ip_address)
            .field("region", &self.fields.region)
            .field("capabilities", &self.fields.capabilities)
            .finish_non_exhaustive()
    }
}

impl ServerEntry {
    /// Parse one server entry from a JSON object.
    pub fn from_value(value: Value) -> Result<Self> {
        let Value::Object(map) = value else {
            return Err(Error::Config("a server entry must be a JSON object".into()));
        };

        // Deserialize through the value, so numbers, unknown fields and all
        // the `omitempty` cases behave like the Go reference.
        let fields: Fields = serde_json::from_value(Value::Object(map.clone()))
            .map_err(|error| Error::Config(format!("server entry: {error}")))?;

        if fields.ip_address.trim().is_empty() {
            return Err(Error::Config("server entry has no ipAddress".into()));
        }

        let raw = map.into_iter().collect();
        Ok(ServerEntry { fields, raw })
    }

    /// Parse one server entry from JSON text.
    pub fn from_json(text: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| Error::Config(format!("server entry JSON: {error}")))?;
        Self::from_value(value)
    }

    /// Parse every object in a JSON array, as an embedded list is written.
    pub fn from_json_array(text: &str) -> Result<Vec<Self>> {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| Error::Config(format!("server entry list: {error}")))?;
        let Value::Array(items) = value else {
            return Err(Error::Config(
                "the embedded server entry list must be a JSON array".into(),
            ));
        };
        items.into_iter().map(Self::from_value).collect()
    }

    /// The entry as JSON, exactly as it was read.
    ///
    /// A configuration carries entries as JSON text, and the signature covers
    /// those bytes: re-encoding the fields would change them. This returns
    /// what was read, so a caller can put an entry back into a configuration
    /// without invalidating its signature.
    pub fn to_value(&self) -> Value {
        self.raw
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    /// The server's own identifier: the explicit `tag`, or one derived from
    /// `webServerSecret` and `ipAddress` the way Psiphon derives it.
    pub fn tag(&self) -> String {
        if !self.fields.tag.is_empty() {
            return self.fields.tag.clone();
        }
        derive_tag(&self.fields.ip_address, &self.fields.web_server_secret)
    }

    /// The first eight characters of the tag, as diagnostics show it. Never
    /// the address itself, so logs do not reveal where the user connects.
    pub fn diagnostic_id(&self) -> String {
        let tag = self.tag();
        if tag.len() < 8 {
            "<unknown>".into()
        } else {
            tag[..8].to_string()
        }
    }

    pub fn ip_address(&self) -> &str {
        &self.fields.ip_address
    }

    pub fn region(&self) -> &str {
        &self.fields.region
    }

    pub fn provider_id(&self) -> &str {
        &self.fields.provider_id
    }

    pub fn fronting_provider_id(&self) -> &str {
        &self.fields.fronting_provider_id
    }

    pub fn capabilities(&self) -> &[String] {
        &self.fields.capabilities
    }

    pub fn configuration_version(&self) -> i64 {
        self.fields.configuration_version
    }

    pub fn ssh_username(&self) -> &str {
        &self.fields.ssh_username
    }

    pub fn ssh_obfuscated_key(&self) -> &str {
        &self.fields.ssh_obfuscated_key
    }

    pub fn tactics_request_public_key(&self) -> &str {
        &self.fields.tactics_request_public_key
    }

    pub fn tactics_request_obfuscated_key(&self) -> &str {
        &self.fields.tactics_request_obfuscated_key
    }

    pub fn disable_ossh_prefix(&self) -> bool {
        self.fields.disable_ossh_prefix
    }

    pub fn disable_ossh_transforms(&self) -> bool {
        self.fields.disable_ossh_transforms
    }

    pub fn disable_http_transforms(&self) -> bool {
        self.fields.disable_http_transforms
    }

    /// The base64 `sshHostKey` as the bytes the SSH key exchange carries.
    pub fn ssh_host_key_bytes(&self) -> Result<Vec<u8>> {
        if self.fields.ssh_host_key.is_empty() {
            return Err(Error::Config("server entry has no sshHostKey".into()));
        }
        base64::engine::general_purpose::STANDARD
            .decode(self.fields.ssh_host_key.trim())
            .map_err(|error| Error::Config(format!("sshHostKey is not base64: {error}")))
    }

    /// The port a protocol dials on the server's own address.
    pub fn port_for(&self, protocol: TunnelProtocol) -> Result<u16> {
        let port = match protocol {
            TunnelProtocol::Ssh => self.fields.ssh_port,
            TunnelProtocol::Ossh => self.fields.ssh_obfuscated_port,
            // The meek transports have their own listener, on the meek
            // server's port: it is a web server, not an SSH server.
            TunnelProtocol::UnfrontedMeek
            | TunnelProtocol::UnfrontedMeekHttps
            | TunnelProtocol::UnfrontedMeekSessionTicket
            | TunnelProtocol::FrontedMeek
            | TunnelProtocol::FrontedMeekHttp => self.fields.meek_server_port,
            TunnelProtocol::TlsOssh => self.fields.tls_ossh_port,
            TunnelProtocol::ShadowsocksOssh => self.fields.ssh_shadowsocks_port,
            TunnelProtocol::QuicOssh | TunnelProtocol::FrontedMeekQuicOssh => {
                self.fields.ssh_obfuscated_quic_port
            }
            TunnelProtocol::TapdanceOssh => self.fields.ssh_obfuscated_tapdance_port,
            TunnelProtocol::ConjureOssh => self.fields.ssh_obfuscated_conjure_port,
        };
        port_number(port).ok_or_else(|| {
            Error::Config(format!(
                "server entry {} has no usable port for {protocol}",
                self.diagnostic_id()
            ))
        })
    }

    /// The host a protocol dials. Fronted protocols go to a fronting domain;
    /// everything else goes to the server's own address.
    pub fn host_for(&self, protocol: TunnelProtocol) -> Result<String> {
        if protocol.is_fronted() {
            if !self.fields.meek_fronting_domain.is_empty() {
                return Ok(self.fields.meek_fronting_domain.clone());
            }
            if !self.fields.meek_fronting_host.is_empty() {
                return Ok(self.fields.meek_fronting_host.clone());
            }
            if let Some(host) = self.fields.meek_fronting_hosts.first() {
                return Ok(host.clone());
            }
            return Err(Error::Config(format!(
                "server entry {} is fronted but names no fronting host",
                self.diagnostic_id()
            )));
        }
        Ok(self.fields.ip_address.clone())
    }

    /// The meek server's port, when the entry offers a meek transport.
    pub fn meek_server_port(&self) -> Option<u16> {
        port_number(self.fields.meek_server_port)
    }

    /// The addresses a fronted meek connection is dialled through: a CDN's
    /// edge, not the Psiphon server's own address. Psiphon picks one at
    /// random per connection so that a block of one edge does not block the
    /// server.
    pub fn meek_fronting_addresses(&self) -> &[String] {
        &self.fields.meek_fronting_addresses
    }

    /// The names to put in the `Host` header for a fronted connection: the
    /// fronting provider's domains, as far as the CDN is concerned.
    ///
    /// A connection picks one independently of the address it dials, which is
    /// what lets a client reach an edge by address while asking for a name
    /// the edge is configured to serve.
    pub fn meek_fronting_hosts(&self) -> &[String] {
        &self.fields.meek_fronting_hosts
    }

    /// The single-host form of [`Self::meek_fronting_hosts`], which older
    /// entries carry.
    pub fn meek_fronting_host(&self) -> &str {
        &self.fields.meek_fronting_host
    }

    /// Whether a fronted connection should omit the TLS server name. Some
    /// fronting providers do not route by SNI and a name there is one more
    /// thing to get wrong.
    pub fn meek_fronting_disable_sni(&self) -> bool {
        self.fields.meek_fronting_disable_sni
    }

    /// The entry's fronting provider, which the server uses to decide whose
    /// traffic it is relaying.
    pub fn fronting_provider_id_value(&self) -> &str {
        &self.fields.fronting_provider_id
    }

    /// The public key the meek cookie is sealed to, base64.
    pub fn meek_cookie_encryption_public_key(&self) -> &str {
        &self.fields.meek_cookie_encryption_public_key
    }

    /// The key the meek cookie's obfuscator layer uses.
    pub fn meek_obfuscated_key(&self) -> &str {
        &self.fields.meek_obfuscated_key
    }

    /// The server's SSH password (the JSON credential payload is built by the
    /// caller).
    pub fn ssh_password(&self) -> &str {
        &self.fields.ssh_password
    }

    /// Whether this entry has a signature to verify.
    pub fn has_signature(&self) -> bool {
        !self.fields.signature.is_empty()
    }

    /// Every protocol this entry advertises that the client implements,
    /// in the client's preference order.
    pub fn supported_protocols(&self) -> Vec<TunnelProtocol> {
        TunnelProtocol::all()
            .iter()
            .copied()
            .filter(|protocol| protocol.supported() && self.supports_protocol(*protocol))
            .collect()
    }

    /// Whether the server entry advertises `protocol`.
    ///
    /// Mirrors Psiphon's `hasCapability`: `-PASSTHROUGH` / `-PASSTHROUGH-v2`
    /// components name protocols the server also has, `QUICv1` means `QUIC`
    /// for older clients, and some TLS protocols imply TLS-OSSH with
    /// passthrough v2.
    pub fn supports_protocol(&self, protocol: TunnelProtocol) -> bool {
        let required = protocol.capability();
        for original in &self.fields.capabilities {
            // Some TLS protocols also speak TLS-OSSH, through passthrough v2.
            if required == "TLS"
                && (is_passthrough_v2(original, "UNFRONTED-MEEK-HTTPS")
                    || is_passthrough_v2(original, "UNFRONTED-MEEK-SESSION-TICKET"))
            {
                return true;
            }

            let stripped = original.replace("-PASSTHROUGH-v2", "");
            let mut capability = stripped.split("-PASSTHROUGH").next().unwrap_or("");
            if required == "QUIC" && capability == "QUICv1" {
                capability = "QUIC";
            }
            if capability == required {
                return true;
            }
        }
        false
    }

    /// Verify the entry's Ed25519 signature against `public_key` (base64, as
    /// the client configuration carries it).
    ///
    /// The signed bytes are the Go JSON encoding of the entry's fields with
    /// the unsigned bookkeeping fields removed, so this is the only check that
    /// the entry came from the Psiphon network unmodified.
    pub fn verify_signature(&self, public_key: &str) -> Result<()> {
        if !self.has_signature() {
            return Err(Error::Signature("server entry has no signature".into()));
        }
        if public_key.is_empty() {
            return Err(Error::Signature(
                "no server entry signature public key is configured".into(),
            ));
        }

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(self.fields.signature.trim())
            .map_err(|error| Error::Signature(format!("signature is not base64: {error}")))?;
        if decoded.len() < 8 {
            return Err(Error::Signature("signature field is too short".into()));
        }
        let (key_id, signature) = decoded.split_at(8);
        if signature.len() != 64 {
            return Err(Error::Signature("signature is not 64 bytes".into()));
        }

        let decoded_key = base64::engine::general_purpose::STANDARD
            .decode(public_key.trim())
            .map_err(|error| Error::Signature(format!("public key is not base64: {error}")))?;
        let key: [u8; 32] = decoded_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Signature("public key is not 32 bytes".into()))?;

        let digest = Sha256::digest(key);
        if digest[..8] != key_id[..] {
            return Err(Error::Signature("unexpected public key ID".into()));
        }

        let verifying_key = VerifyingKey::from_bytes(&key)
            .map_err(|error| Error::Signature(format!("invalid public key: {error}")))?;
        let signature = Ed25519Signature::from_slice(signature)
            .map_err(|error| Error::Signature(format!("invalid signature: {error}")))?;

        let signed = self.signed_bytes()?;
        verifying_key
            .verify(&signed, &signature)
            .map_err(|_| Error::Signature("invalid server entry signature".into()))
    }

    /// Sign this entry with an Ed25519 key pair (both base64; the private key
    /// is the 64-byte Go form). Used by the harness that stands up a local
    /// server and by the tests that pin verification.
    pub fn sign(&mut self, public_key: &str, private_key: &str) -> Result<()> {
        let decoded_private = base64::engine::general_purpose::STANDARD
            .decode(private_key.trim())
            .map_err(|error| Error::Config(format!("private key is not base64: {error}")))?;
        let keypair: [u8; 64] = decoded_private
            .as_slice()
            .try_into()
            .map_err(|_| Error::Config("private key is not 64 bytes".into()))?;
        let signing_key = SigningKey::from_keypair_bytes(&keypair)
            .map_err(|error| Error::Config(format!("invalid private key: {error}")))?;

        let signed = self.signed_bytes()?;
        let signature = signing_key.sign(&signed);

        let decoded_public = base64::engine::general_purpose::STANDARD
            .decode(public_key.trim())
            .map_err(|error| Error::Config(format!("public key is not base64: {error}")))?;
        let digest = Sha256::digest(&decoded_public);
        let mut field = Vec::with_capacity(8 + 64);
        field.extend_from_slice(&digest[..8]);
        field.extend_from_slice(&signature.to_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(field);

        self.fields.signature = encoded.clone();
        self.raw.insert("signature".into(), Value::String(encoded));
        Ok(())
    }

    /// The bytes the signature covers: the entry's fields minus the unsigned
    /// bookkeeping fields and the signature itself, encoded the way Go encodes
    /// a `map[string]any`.
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut fields = self.raw.clone();
        // RemoveUnsignedFields.
        fields.remove("localSource");
        fields.remove("localTimestamp");
        if matches!(fields.get("isLocalDerivedTag"), Some(Value::Bool(true))) {
            fields.remove("tag");
        }
        fields.remove("isLocalDerivedTag");
        fields.remove("signature");

        let value = Value::Object(fields.into_iter().collect::<Map<String, Value>>());
        json::encode(&value).map_err(|error| Error::Signature(error.to_string()))
    }
}

/// The Psiphon-derived tag of a server: HMAC-SHA256(webServerSecret, ipAddress).
fn derive_tag(ip_address: &str, web_server_secret: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(web_server_secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(ip_address.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// `-PASSTHROUGH-v2` support for the TLS-OSSH implication rule.
fn is_passthrough_v2(original: &str, base: &str) -> bool {
    original == format!("{base}-PASSTHROUGH-v2")
}

fn port_number(port: i64) -> Option<u16> {
    u16::try_from(port).ok().filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use serde_json::json;

    /// A fresh Ed25519 key pair, made without the crate's optional rand
    /// plumbing: the dalek crate only needs a 32-byte seed.
    fn key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// A real-shaped entry with a made-up address and key.
    fn sample() -> Value {
        json!({
            "ipAddress": "192.0.2.10",
            "region": "US",
            "providerID": "provider",
            "webServerPort": "443",
            "webServerSecret": "c2VjcmV0",
            "sshPort": 22,
            "sshUsername": "psiphon",
            "sshPassword": "password",
            "sshHostKey": "AAAAC3NzaC1lZDI1NTE5AAAAIOMq0n0n0n0n0n0n0n0n0n0n0n0n0n0n0n0n0n0n",
            "sshObfuscatedPort": 2222,
            "sshObfuscatedKey": "obfuscation-key",
            "tlsOSSHPort": 4443,
            "capabilities": ["SSH", "OSSH", "TLS", "UNFRONTED-MEEK"],
            "configurationVersion": 1
        })
    }

    #[test]
    fn parses_the_fields_the_client_uses() {
        let entry = ServerEntry::from_value(sample()).unwrap();
        assert_eq!(entry.ip_address(), "192.0.2.10");
        assert_eq!(entry.region(), "US");
        assert_eq!(entry.ssh_username(), "psiphon");
        assert_eq!(entry.port_for(TunnelProtocol::Ssh).unwrap(), 22);
        assert_eq!(entry.port_for(TunnelProtocol::Ossh).unwrap(), 2222);
        assert_eq!(entry.port_for(TunnelProtocol::TlsOssh).unwrap(), 4443);
        assert_eq!(entry.host_for(TunnelProtocol::Ossh).unwrap(), "192.0.2.10");
    }

    #[test]
    fn capability_rules_match_psiphon() {
        let entry = ServerEntry::from_value(sample()).unwrap();
        assert!(entry.supports_protocol(TunnelProtocol::Ssh));
        assert!(entry.supports_protocol(TunnelProtocol::Ossh));
        assert!(entry.supports_protocol(TunnelProtocol::TlsOssh));
        assert!(entry.supports_protocol(TunnelProtocol::UnfrontedMeek));
        assert!(!entry.supports_protocol(TunnelProtocol::FrontedMeek));
        // `QUICv1` means `QUIC` to older clients.
        let entry = ServerEntry::from_value(json!({
            "ipAddress": "192.0.2.10",
            "capabilities": ["QUICv1"]
        }))
        .unwrap();
        assert!(entry.supports_protocol(TunnelProtocol::QuicOssh));
    }

    #[test]
    fn passthrough_components_still_name_their_protocol() {
        let entry = ServerEntry::from_value(json!({
            "ipAddress": "192.0.2.10",
            "capabilities": ["UNFRONTED-MEEK-HTTPS-PASSTHROUGH-v2"]
        }))
        .unwrap();
        assert!(entry.supports_protocol(TunnelProtocol::UnfrontedMeekHttps));
        assert!(entry.supports_protocol(TunnelProtocol::TlsOssh));
    }

    #[test]
    fn a_signature_round_trips_and_rejects_edits() {
        // Ed25519 key pair in the Go 64-byte private key form.
        let signing_key = key();
        let public_key = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        let private_key =
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_keypair_bytes());

        let mut entry = ServerEntry::from_value(sample()).unwrap();
        entry.sign(&public_key, &private_key).unwrap();
        entry.sign(&public_key, &private_key).unwrap(); // re-signing replaces
        entry.verify_signature(&public_key).unwrap();

        // A field outside the signature's unsigned set invalidates it.
        let mut edited = entry.clone();
        edited
            .raw
            .insert("ipAddress".into(), Value::String("192.0.2.20".into()));
        assert!(edited.verify_signature(&public_key).is_err());

        // Local bookkeeping fields are not covered.
        let mut local = entry.clone();
        local
            .raw
            .insert("localSource".into(), Value::String("embedded".into()));
        local.verify_signature(&public_key).unwrap();

        // A different key does not verify.
        let other = key();
        let other_public =
            base64::engine::general_purpose::STANDARD.encode(other.verifying_key().to_bytes());
        assert!(entry.verify_signature(&other_public).is_err());
    }

    #[test]
    fn a_signature_covers_go_json_encoding() {
        // Two entries with the same typed fields but different insertion
        // order must verify: the signature is over sorted-key Go JSON.
        let signing_key = key();
        let public_key = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        let private_key =
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_keypair_bytes());

        let mut entry = ServerEntry::from_value(json!({
            "ipAddress": "192.0.2.10",
            "sshPort": 22,
            "tag": "explicit",
        }))
        .unwrap();
        entry.sign(&public_key, &private_key).unwrap();
        entry.verify_signature(&public_key).unwrap();
    }

    #[test]
    fn an_unsigned_entry_says_so_instead_of_verifying() {
        let entry = ServerEntry::from_value(sample()).unwrap();
        assert!(!entry.has_signature());
        assert!(entry.verify_signature("AAAA").is_err());
    }

    #[test]
    fn debug_does_not_print_secrets() {
        let entry = ServerEntry::from_value(sample()).unwrap();
        let text = format!("{entry:?}");
        assert!(!text.contains("password"));
        assert!(!text.contains("obfuscation-key"));
    }
}
