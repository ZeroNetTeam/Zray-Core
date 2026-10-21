//! A REALITY server's configuration, in Xray's own JSON shape.
//!
//! A server that wants REALITY should not have to hand-build
//! [`RealityServerParams`](crate::server::RealityServerParams), and it should
//! not have to depend on the whole configuration compiler to read one block of
//! settings. This module turns the `realitySettings` object Xray documents —
//! the same one `xray run` reads — into a typed value, with Xray's field names,
//! units and defaults, and with the mistakes that must not be silent made loud:
//!
//! * a `privateKey` that is not 32 bytes of base64, a `shortIds` entry that is
//!   not hex or longer than the 8 bytes the session id carries, a `maxTimeDiff`
//!   that is not a number of milliseconds, a `xver` outside `0 | 1 | 2`, a
//!   client-version bound that is not `major.minor.patch`;
//! * using a client's block on a server: `publicKey`, `fingerprint`,
//!   `serverName`, `spiderX` and `mldsa65Verify` are recognised and ignored,
//!   because the same JSON is copied between the two roles in practice and
//!   failing on the harmless half would be worse than accepting it.
//!
//! What is *not* ignored: a missing `privateKey`, missing `serverNames` or
//! missing `shortIds`. Xray refuses those too, and a REALITY server that
//! accepted an empty `shortIds` would authenticate nobody while looking
//! healthy — every client would be quietly handed to the camouflage site.
//!
//! The fields map one to one onto
//! [`zero_config::InboundRealityConfig`], and `crates/reality/tests/config.rs`
//! compares the two parses field by field so the copies cannot drift.
//!
//! Both of Xray's diagnostic switches are read as well: `show` (#1) and
//! `masterKeyLog` (#31), the two fields an operator turns on to see inside a
//! handshake. What they may reveal is documented where it belongs — with the key
//! material they are about, in [`crate::keys`]: a key log hands out session
//! secrets on purpose, and a `show` line must never carry one at all.

use std::time::Duration;

use serde_json::Value;

use crate::keys::KeyLog;
use crate::server::RealityServerParams;

/// The type of `limitFallbackUpload` / `limitFallbackDownload` is
/// [`FallbackLimit`], the relay's own: the settings reader produces exactly the
/// value the relay consumes, so there is no mapping step for a server to get
/// wrong. See that type for what the three numbers mean and for Xray's
/// defaults.
pub use crate::fallback::FallbackLimit;

/// The camouflage site, in whichever of the two kinds Xray dials.
///
/// `type: "unix"` makes the target a path; anything else makes it a host and
/// a port (`infra/conf/transport_internet.go:820-838`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CamouflageTarget {
    /// A host and a port.
    Host(Box<str>, u16),
    /// A unix socket: a filesystem path, or an abstract socket's `@name`.
    Unix(Box<str>),
}

/// Everything a REALITY server listener needs, parsed from `realitySettings`.
#[derive(Clone)]

pub struct RealityServerConfig {
    /// Xray's `show`: report, per connection that gets as far as opening a
    /// REALITY seal, the peer's address and the client fields its session id
    /// carried — Xray's per-connection diagnostics (`RL/tls.go:164-166`,
    /// `:252-256`). Default `false`.
    ///
    /// What the report may *not* carry is as much a part of this field as what
    /// it may: Xray's `show` also prints the first 16 bytes of the
    /// authentication key it derived (`RL/tls.go:238-240`), and this port prints
    /// no key material of any kind (`crates/zero-runtime/tests/log_privacy.rs`).
    /// [`ClientReport`](crate::keys::ClientReport) is the only shape a report
    /// takes here, and it has no field a key could go in.
    ///
    /// The handshake writes the line; this reader carries the switch for it.
    pub show: bool,
    /// The names the server will camouflage itself as. At least one; Xray
    /// compares the client's SNI against this list exactly.
    pub server_names: Box<[Box<str>]>,
    /// The X25519 private key (`xray x25519` prints it as `PrivateKey`).
    /// Never printed.
    pub private_key: [u8; 32],
    /// The selectors accepted, each already zero-padded to the 8 bytes the
    /// session id carries, exactly as Xray's JSON layer pads them. Empty is a
    /// configuration error, not "accept anyone".
    pub short_ids: Box<[Box<[u8]>]>,
    /// The camouflage site: `dest` (or `target`) as written, host and port.
    ///
    /// Always `Some` in a configuration this reader produced: a block with no
    /// `dest` is refused, exactly as Xray refuses it
    /// (`infra/conf/transport_internet.go:841-843`). It stays an `Option` only
    /// for a caller that builds the struct by hand, who is then saying that
    /// something else in front of this listener handles the fallback — a REALITY
    /// server with nowhere to send an unauthenticated visitor answers a probe
    /// with a silent nothing, which is the opposite of the protocol's purpose.
    pub target: Option<CamouflageTarget>,
    /// Xray's `mldsa65Seed`: 32 secret bytes that make the server sign every
    /// handshake with an ML-DSA-65 key, so a client holding the matching
    /// `mldsa65Verify` key can tell the real server from one that merely knows
    /// the X25519 key. Never printed.
    pub mldsa65_seed: Option<[u8; 32]>,
    /// How far the client's clock may differ from this server's before the
    /// hello is treated as not REALITY, in milliseconds. Zero means no check.
    pub max_time_diff: Duration,
    /// The oldest and newest client versions accepted, as `[major, minor,
    /// patch]`; `None` means any.
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    /// The PROXY protocol version (1 or 2) to send to `target` when a
    /// connection is handed to it; 0 sends none.
    pub fallback_xver: u8,
    pub fallback_limit_up: FallbackLimit,
    pub fallback_limit_down: FallbackLimit,
    /// Xray's `masterKeyLog`: the file the handshake appends its TLS 1.3 traffic
    /// secrets to, so that a capture of this server's traffic can be decrypted.
    /// `None` — the default — when the field is absent, empty or `"none"`, the
    /// three spellings Xray treats as off
    /// (`XC/transport_internet/reality/config.go:61-64`).
    ///
    /// This is a debugging switch and not a diagnostic trail:
    /// [`KeyLog`](crate::keys::KeyLog) documents what a reader of that file can
    /// do, which is decrypt every session of every user of this server for as
    /// long as it is being written. Open it once per listener with
    /// [`Self::key_log`] rather than once per connection, and delete the file
    /// when the investigation is over.
    pub master_key_log: Option<Box<str>>,
}

impl std::fmt::Debug for RealityServerConfig {
    /// Neither the private key nor the ML-DSA-65 seed is ever printed; a
    /// configuration debug-printed into a log must not be a key disclosure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("server_names", &self.server_names)
            .field("short_ids", &self.short_ids.len())
            .field("target", &self.target)
            .field("mldsa65", &self.mldsa65_seed.is_some())
            .field("max_time_diff", &self.max_time_diff)
            .field("min_client_ver", &self.min_client_ver)
            .field("max_client_ver", &self.max_client_ver)
            .field("fallback_xver", &self.fallback_xver)
            // Whether the evidence trail is on, not where it goes: a path is
            // not a secret, but a key log's location is nobody else's business
            // either.
            .field("master_key_log", &self.master_key_log.is_some())
            .field("show", &self.show)
            .finish_non_exhaustive()
    }
}

impl RealityServerConfig {
    /// Read one `realitySettings` object.
    ///
    /// The result is the settings, not a running server: the caller decides
    /// what to do about the camouflage site and the post-handshake shapes.
    pub fn from_xray_settings(settings: &Value) -> Result<Self, String> {
        let object = settings
            .as_object()
            .ok_or_else(|| "realitySettings must be an object".to_string())?;

        let private_key = match object.get("privateKey").and_then(Value::as_str) {
            Some(text) => decode_x25519_private_key(text)?,
            None => return Err("realitySettings.privateKey is required".into()),
        };

        let server_names = object
            .get("serverNames")
            .and_then(Value::as_array)
            .ok_or_else(|| "realitySettings.serverNames is required".to_string())?
            .iter()
            .filter_map(Value::as_str)
            .map(Box::from)
            .collect::<Vec<_>>();
        if server_names.is_empty() {
            return Err("realitySettings.serverNames must not be empty".into());
        }

        let short_ids = object
            .get("shortIds")
            .and_then(Value::as_array)
            .ok_or_else(|| "realitySettings.shortIds is required".to_string())?
            .iter()
            .map(|id| {
                let text = id.as_str().unwrap_or_default();
                let bytes = hex::decode(text)
                    .map_err(|e| format!("realitySettings.shortId {text:?}: {e}"))?;
                // Xray decodes into a fixed eight-byte selector, so anything
                // longer than the session id's field could never match and is
                // a configuration mistake rather than a long selector.
                if bytes.len() > 8 {
                    return Err(format!(
                        "realitySettings.shortId {text:?} is {} bytes, more than the 8 the session id carries",
                        bytes.len()
                    ));
                }
                let mut padded = [0u8; 8];
                padded[..bytes.len()].copy_from_slice(&bytes);
                Ok(padded.to_vec().into_boxed_slice())
            })
            .collect::<Result<Vec<_>, String>>()?;
        if short_ids.is_empty() {
            return Err(
                "realitySettings.shortIds must not be empty: with no selector the server \
                 would authenticate nobody and hand every client to the camouflage site"
                    .into(),
            );
        }

        // Xray requires a camouflage target for a REALITY inbound: `dest` (or
        // its alias `target`), inferring the kind from the text — an `@` or `/`
        // path is a unix socket, a bare number is a port on localhost, anything
        // else must be host:port (`infra/conf/transport_internet.go:820-843`).
        // A server whose fallback has nowhere to go answers a probe with a
        // silent nothing, so the missing case is refused here rather than
        // discovered by an operator under censorship.
        let dest = match object.get("dest").or_else(|| object.get("target")) {
            None | Some(Value::Null) => {
                return Err(
                    "realitySettings.dest is required: an unauthenticated visitor has to be \
                     handed to the real site"
                        .into(),
                )
            }
            Some(value) => {
                let text = value
                    .as_str()
                    .ok_or_else(|| "realitySettings.dest must be a string".to_string())?;
                text.to_string()
            }
        };
        // Xray takes the kind from `type` when the operator wrote one, and
        // infers it from the dest's shape when they did not
        // (`infra/conf/transport_internet.go:820-838`).
        let kind = match object.get("type") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => Some(text.clone()),
            Some(_) => return Err("realitySettings.type must be \"tcp\" or \"unix\"".into()),
        };
        let target = Some(parse_target(&dest, kind.as_deref())?);

        let mldsa65_seed = match object.get("mldsa65Seed").and_then(Value::as_str) {
            None | Some("") => None,
            Some(text) => {
                let seed = decode_base64_32(text, "mldsa65Seed")?;
                // Xray refuses this pair (`infra/conf/transport_internet.go:904-906`),
                // and it is worth refusing for a stronger reason than it gives:
                // the seed is what makes the ML-DSA-65 half a *different*
                // secret from the X25519 half, so reusing one for the other
                // collapses the two factors into one an attacker who ever saw
                // the private key already holds. Xray compares the strings; the
                // bytes are compared here, so the same key written in another
                // base64 spelling cannot slip through.
                if seed == private_key {
                    return Err(
                        "realitySettings.mldsa65Seed and privateKey must not be the same value"
                            .into(),
                    );
                }
                Some(seed)
            }
        };

        // Xray decodes this object into a Go struct with a `bool` and a
        // `string` field, so a `show` of the wrong shape and a `masterKeyLog`
        // that is not a path are configuration errors there too
        // (`XC/infra/conf/transport_internet.go:781-782`).
        let show = match object.get("show") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(other) => {
                return Err(format!(
                    "realitySettings.show must be true or false, not {other}"
                ))
            }
        };
        let master_key_log = match object.get("masterKeyLog") {
            None | Some(Value::Null) => None,
            Some(Value::String(path)) if path.is_empty() || path == "none" => None,
            Some(Value::String(path)) => Some(Box::from(&**path)),
            Some(other) => {
                return Err(format!(
                    "realitySettings.masterKeyLog must be a file path, not {other}"
                ))
            }
        };

        Ok(Self {
            show,
            server_names: server_names.into_boxed_slice(),
            private_key,
            short_ids: short_ids.into_boxed_slice(),
            target,
            mldsa65_seed,
            max_time_diff: Duration::from_millis(
                object
                    .get("maxTimeDiff")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            min_client_ver: client_version(object, "minClientVer")?,
            max_client_ver: client_version(object, "maxClientVer")?,
            fallback_xver: match object.get("xver").and_then(Value::as_u64) {
                None | Some(0) => 0,
                Some(version @ (1 | 2)) => version as u8,
                Some(other) => {
                    return Err(format!(
                        "realitySettings.xver must be 0, 1 or 2, not {other}"
                    ))
                }
            },
            fallback_limit_up: fallback_limit(object, "limitFallbackUpload")?,
            fallback_limit_down: fallback_limit(object, "limitFallbackDownload")?,
            master_key_log,
        })
    }

    /// The handshake parameters these settings describe.
    ///
    /// The post-handshake shapes are what the server sends after a handshake
    /// to look like the site it is imitating; they are learned by talking to
    /// that site, so they start empty and
    /// [`PostHandshakeShapes`](crate::server::PostHandshakeShapes) fills them
    /// in.
    pub fn server_params(&self) -> RealityServerParams {
        RealityServerParams {
            site_writes: None,
            private_key: self.private_key,
            server_names: self.server_names.clone(),
            short_ids: self.short_ids.clone(),
            mldsa65_seed: self.mldsa65_seed,
            max_time_diff: self.max_time_diff,
            min_client_ver: self.min_client_ver,
            max_client_ver: self.max_client_ver,
            post_handshake: Default::default(),
            show: self.show,
            key_log: None,
            decoy: None,
        }
    }

    /// The key log this configuration asks for, or `None` when `masterKeyLog` is
    /// off. The file is opened here, once per listener, so that every handshake
    /// appends to the same one.
    ///
    /// A path that cannot be opened comes back as an error for the caller to
    /// decide about. Xray logs the error and runs with no key log rather than
    /// refusing to start (`XC/transport_internet/reality/config.go:66-71`), and
    /// that is the right shape for this feature: a debugging aid is not a reason
    /// for a REALITY listener to be down.
    pub fn key_log(&self) -> Result<Option<KeyLog>, String> {
        match &self.master_key_log {
            None => Ok(None),
            Some(path) => KeyLog::open(path).map(Some),
        }
    }
}

/// The client fields Xray accepts in the same object. Present so a server can
/// read a block that was copied from a client config without failing on it.
pub const CLIENT_ONLY_FIELDS: &[&str] = &[
    "publicKey",
    "shortId",
    "serverName",
    "fingerprint",
    "spiderX",
    "mldsa65Verify",
];

/// Xray's `xray x25519` private key: 32 bytes, base64url without padding.
///
/// The bytes are kept exactly as written. X25519 clamps every scalar it
/// multiplies — Go's `curve25519.X25519` and `x25519-dalek` alike — so a key
/// that is stored unclamped behaves identically to its clamped form, and
/// rewriting it here would only make the value differ from the one the
/// operator pasted and from `zero_config`'s parse of the same text.
fn decode_x25519_private_key(text: &str) -> Result<[u8; 32], String> {
    decode_base64_any(text)
        .ok_or_else(|| "realitySettings.privateKey must be base64".to_string())?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            format!(
                "realitySettings.privateKey must decode to 32 bytes, not {}",
                bytes.len()
            )
        })
}

/// The one encoding Xray accepts: URL-safe base64 without padding, which is
/// what `base64.RawURLEncoding` decodes (`XC/infra/conf/transport_internet.go:853`,
/// `:907`, `:943`, `:957`).
///
/// The standard alphabet and the padded form are *not* accepted, because Xray
/// refuses them: a key that is valid here and invalid there is a config that
/// works on one and breaks on the other, and the operator finds out when they
/// move it.
fn decode_base64_any(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
}

fn decode_base64_32(text: &str, field: &str) -> Result<[u8; 32], String> {
    decode_base64_any(text)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("realitySettings.{field} must be 32 bytes of base64"))
}

/// Xray's `minClientVer` / `maxClientVer`: one to three dot-separated
/// decimal bytes, right-padded with zeros, so `"1.2"` is `1.2.0` and `"26"`
/// is `26.0.0` (`infra/conf/transport_internet.go:856-883`). A fourth part is
/// refused there and here; a part that is not a byte, or that carries a sign —
/// which Go's `ParseUint` rejects and Rust's `parse` would accept — is refused
/// too.
fn client_version(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<[u8; 3]>, String> {
    let Some(text) = object.get(field).and_then(Value::as_str) else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    let mut version = [0u8; 3];
    let mut parts = text.split('.');
    for slot in version.iter_mut() {
        match parts.next() {
            None => break,
            Some(part) if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) => {
                return Err(format!(
                    "realitySettings.{field} {text:?} is not a dotted byte, like 1.2.3"
                ))
            }
            Some(part) => {
                *slot = part.parse().map_err(|_| {
                    format!("realitySettings.{field} {text:?} has a part above 255")
                })?;
            }
        }
    }
    if parts.next().is_some() {
        return Err(format!(
            "realitySettings.{field} {text:?} has more than three parts"
        ));
    }
    Ok(Some(version))
}

/// `dest` as Xray reads it: `host:port`, a bare port on localhost, or a unix
/// socket path — which this port refuses by name rather than resolving as a host
/// name (`XC/infra/conf/transport_internet.go:812-843`).
fn parse_target(text: &str, kind: Option<&str>) -> Result<CamouflageTarget, String> {
    let text = text.trim();
    let unix = match kind {
        Some("unix") => true,
        Some("tcp") => false,
        Some(other) => {
            return Err(format!(
                "realitySettings.type {other:?} is not \"tcp\" or \"unix\", which are the only \
                 kinds Xray dials"
            ))
        }
        // No `type` written: the shape of the dest decides, as Xray decides
        // (`infra/conf/transport_internet.go:823-838`).
        None => text.starts_with('@') || text.starts_with('/'),
    };
    if unix {
        // An abstract socket is `@name` on Linux; a path is `/path`. Xray
        // keeps the text as written and hands it to `net.Dial`
        // (`RL/tls.go:168`).
        if text.is_empty() {
            return Err("realitySettings.dest is empty, so there is no socket to dial".into());
        }
        return Ok(CamouflageTarget::Unix(Box::from(text)));
    }
    if text.bytes().all(|byte| byte.is_ascii_digit()) && !text.is_empty() {
        // Xray turns a bare port into `localhost:<port>`
        // (`infra/conf/transport_internet.go:834-836`).
        let port: u16 = text
            .parse()
            .map_err(|_| format!("realitySettings.dest {text:?} is not a port"))?;
        return Ok(CamouflageTarget::Host(Box::from("localhost"), port));
    }
    match zero_core::address::split_host_port(text) {
        Some((host, port)) => Ok(CamouflageTarget::Host(Box::from(host), port)),
        None => Err(format!(
            "realitySettings.dest {text:?} is not host:port, a port, or a unix socket path"
        )),
    }
}

fn fallback_limit(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<FallbackLimit, String> {
    let Some(value) = object.get(field).filter(|value| !value.is_null()) else {
        return Ok(FallbackLimit::unlimited());
    };
    let number = |name: &str| -> Result<u64, String> {
        value.get(name).map_or(Ok(0), |value| {
            value
                .as_u64()
                .ok_or_else(|| format!("realitySettings.{field}.{name} must be a number"))
        })
    };
    Ok(FallbackLimit::new(
        number("afterBytes")?,
        number("bytesPerSec")?,
        number("burstBytesPerSec")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A server block as Xray's own documentation writes it.
    fn settings() -> Value {
        json!({
            "show": false,
            "dest": "example.com:443",
            "xver": 1,
            "serverNames": ["example.com", "www.example.com"],
            "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
            "shortIds": ["", "ab12", "0011223344556677"],
            "maxTimeDiff": 60000,
            "minClientVer": "1.0.0",
            "maxClientVer": "26.3.27",
            "limitFallbackUpload": {"afterBytes": 10, "bytesPerSec": 20, "burstBytesPerSec": 30},
            "limitFallbackDownload": {"afterBytes": 40, "bytesPerSec": 50, "burstBytesPerSec": 60}
        })
    }

    #[test]
    fn a_documented_server_block_parses_field_by_field() {
        let config = RealityServerConfig::from_xray_settings(&settings()).expect("parses");
        assert_eq!(
            config.server_names.as_ref(),
            &[Box::from("example.com"), Box::from("www.example.com")]
        );
        match config.target.clone().expect("dest was read") {
            CamouflageTarget::Host(host, port) => assert_eq!((&*host, port), ("example.com", 443)),
            other => panic!("the target is {other:?}"),
        }
        assert_eq!(config.max_time_diff, Duration::from_millis(60_000));
        assert_eq!(config.min_client_ver, Some([1, 0, 0]));
        assert_eq!(config.max_client_ver, Some([26, 3, 27]));
        assert_eq!(config.fallback_xver, 1);
        assert_eq!(config.fallback_limit_up, FallbackLimit::new(10, 20, 30));
        assert_eq!(config.fallback_limit_down, FallbackLimit::new(40, 50, 60));
    }

    #[test]
    fn a_short_id_is_hex_then_right_padded_to_the_session_id_width() {
        let config = RealityServerConfig::from_xray_settings(&settings()).expect("parses");
        assert_eq!(config.short_ids[0].as_ref(), &[0u8; 8]);
        assert_eq!(
            config.short_ids[1].as_ref(),
            &[0xab, 0x12, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            config.short_ids[2].as_ref(),
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
    }

    #[test]
    fn a_version_field_is_zero_filled_the_way_xray_fills_it() {
        // Xray accepts one to three parts and pads the rest with zeros
        // (`transport_internet.go:856-883`), so `"1.2"` means `1.2.0`. A server
        // that insisted on three parts would refuse a config Xray runs.
        let mut value = settings();
        value
            .as_object_mut()
            .expect("object")
            .insert("minClientVer".into(), json!("1.2"));
        let config = RealityServerConfig::from_xray_settings(&value).expect("1.2 is 1.2.0");
        assert_eq!(config.min_client_ver, Some([1, 2, 0]));
    }

    #[test]
    fn a_bare_port_dest_means_localhost() {
        // `dest: "443"` is `localhost:443` in Xray, and resolving "443" as a
        // host name would hand every visitor to a DNS failure instead.
        let mut value = settings();
        value
            .as_object_mut()
            .expect("object")
            .insert("dest".into(), json!("8443"));
        let config = RealityServerConfig::from_xray_settings(&value).expect("a bare port");
        match config.target.expect("dest is required, so it is set") {
            CamouflageTarget::Host(host, port) => assert_eq!((&*host, port), ("localhost", 8443)),
            other => panic!("the target is {other:?}"),
        }
    }

    #[test]
    fn a_server_without_a_camouflage_target_is_refused() {
        // Xray refuses it (`transport_internet.go:841-843`); a server without a
        // target answers a probe with nothing at all, which is itself a
        // fingerprint.
        let mut value = settings();
        value.as_object_mut().expect("object").remove("dest");
        let error = RealityServerConfig::from_xray_settings(&value)
            .expect_err("a missing dest is a configuration error");
        assert!(error.contains("dest"), "{error}");
    }

    #[test]
    fn the_two_unix_socket_shapes_are_read_as_their_own_shapes() {
        // Xray dials both (`transport_internet.go:824-832`): a filesystem
        // socket and, on Linux, an abstract one. The kind comes from the
        // dest's shape when no `type` is written, and from `type` when one
        // is, so a dest that names a path is a path — not a host name that
        // would fail at DNS time, minutes later, for a reason that names
        // nothing.
        for (written, expected) in [("/run/decoy.sock", "/run/decoy.sock"), ("@decoy", "@decoy")] {
            let mut value = settings();
            value
                .as_object_mut()
                .expect("object")
                .insert("dest".into(), json!(written));
            let config = RealityServerConfig::from_xray_settings(&value)
                .expect("a unix socket target is read, not refused");
            assert_eq!(
                config.target,
                Some(CamouflageTarget::Unix(expected.into())),
                "{written}: the socket is carried as written"
            );
        }
    }

    /// `type` says which kind the dest is, and it is honoured.
    #[test]
    fn the_type_field_says_which_kind_the_dest_is() {
        // `type: "unix"` with a path: the path, as written.
        let mut value = settings();
        {
            let object = value.as_object_mut().expect("object");
            object.insert("dest".into(), json!("/run/decoy.sock"));
            object.insert("type".into(), json!("unix"));
        }
        let config = RealityServerConfig::from_xray_settings(&value).expect("parses");
        assert_eq!(
            config.target,
            Some(CamouflageTarget::Unix("/run/decoy.sock".into()))
        );

        // `type: "tcp"` with a host:port: the host and the port.
        let mut value = settings();
        {
            let object = value.as_object_mut().expect("object");
            object.insert("dest".into(), json!("example.com:443"));
            object.insert("type".into(), json!("tcp"));
        }
        let config = RealityServerConfig::from_xray_settings(&value).expect("parses");
        assert_eq!(
            config.target,
            Some(CamouflageTarget::Host("example.com".into(), 443))
        );

        // A kind Xray does not have is refused by name.
        let mut value = settings();
        value
            .as_object_mut()
            .expect("object")
            .insert("type".into(), json!("udp"));
        let error = RealityServerConfig::from_xray_settings(&value)
            .expect_err("udp is not a kind Xray dials");
        assert!(error.contains("type"), "{error}");
    }

    #[test]
    fn the_diagnostic_switches_are_read_the_way_xray_reads_them() {
        // `show` defaults to false and is carried as written.
        let config = RealityServerConfig::from_xray_settings(&settings()).expect("parses");
        assert!(
            !config.show,
            "a block that says nothing about show is quiet"
        );
        assert_eq!(config.master_key_log, None, "and writes no key log");

        let mut loud = settings();
        loud.as_object_mut()
            .expect("object")
            .insert("show".into(), json!(true));
        assert!(
            RealityServerConfig::from_xray_settings(&loud)
                .expect("parses")
                .show
        );

        // The three spellings Xray treats as "off"
        // (`transport_internet/reality/config.go:61-64`), and the one that turns
        // it on. `key_log()` is the caller's way in, so it is what the test
        // uses: a switch that parses but cannot be honoured is the bug this
        // catches.
        for off in [json!("none"), json!(""), json!(null)] {
            let mut value = settings();
            value
                .as_object_mut()
                .expect("object")
                .insert("masterKeyLog".into(), off.clone());
            let config = RealityServerConfig::from_xray_settings(&value).expect("parses");
            assert_eq!(config.master_key_log, None, "masterKeyLog {off} is off");
            assert!(
                config.key_log().expect("nothing to open").is_none(),
                "masterKeyLog {off} must not create a file"
            );
        }

        let path = crate::keys::scratch_path("config-keylog");
        let mut on = settings();
        on.as_object_mut()
            .expect("object")
            .insert("masterKeyLog".into(), json!(path.to_string_lossy()));
        let config = RealityServerConfig::from_xray_settings(&on).expect("parses");
        assert_eq!(
            config.master_key_log.as_deref(),
            Some(path.to_string_lossy().as_ref())
        );
        assert!(
            !path.exists(),
            "reading the setting must not create the file: only opening it does"
        );
        let log = config
            .key_log()
            .expect("the target directory is writable")
            .expect("the path was named");
        assert_eq!(log.path(), path.to_string_lossy());
        log.log(
            crate::keys::CLIENT_TRAFFIC_SECRET_0,
            &[0x11u8; 32],
            &[0x22u8; 32],
        )
        .expect("the file was created for appending");
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("the key log was written")
                .lines()
                .count(),
            1
        );
        std::fs::remove_file(&path).expect("the test's own key log is removable");
    }

    #[test]
    fn every_rejected_shape_is_rejected_for_its_own_reason() {
        let cases: &[(&str, Value)] = &[
            ("privateKey", json!({"privateKey": "not base64!!"})),
            ("privateKey", json!({"privateKey": "AAAA"})),
            ("serverNames", json!({"serverNames": []})),
            ("serverNames", json!({"serverNames": null})),
            ("shortIds", json!({"shortIds": []})),
            ("shortId", json!({"shortIds": ["xyz"]})),
            ("shortId", json!({"shortIds": ["001122334455667788"]})),
            ("mldsa65Seed", json!({"mldsa65Seed": "AAAA"})),
            ("minClientVer", json!({"minClientVer": "1.2.3.4"})),
            ("minClientVer", json!({"minClientVer": "1.two"})),
            ("minClientVer", json!({"minClientVer": "+1.2.3"})),
            ("minClientVer", json!({"minClientVer": "1.2.300"})),
            ("xver", json!({"xver": 3})),
            (
                "limitFallbackUpload",
                json!({"limitFallbackUpload": {"afterBytes": "ten"}}),
            ),
            // A camouflage target that is neither a host and a port nor a
            // socket is refused as its own shape, not as a host name that
            // failed to resolve: the difference is what an operator reads at
            // startup.
            ("dest", json!({"dest": null})),
            ("dest", json!({"dest": "example.com"})),
            ("dest", json!({"dest": 8443})),
            ("show", json!({"show": "yes"})),
            ("show", json!({"show": 1})),
            ("masterKeyLog", json!({"masterKeyLog": 5})),
            ("masterKeyLog", json!({"masterKeyLog": ["/tmp/keys.log"]})),
        ];
        for (field, extra) in cases {
            let mut value = settings();
            let object = value.as_object_mut().expect("object");
            for (key, replacement) in extra.as_object().expect("object") {
                object.insert(key.clone(), replacement.clone());
            }
            let error = RealityServerConfig::from_xray_settings(&value)
                .expect_err(&format!("{field} should have been refused"));
            assert!(
                error.contains(field),
                "{field} was refused for the wrong reason: {error}"
            );
        }
    }

    /// Only the encoding Xray accepts is accepted: unpadded base64url.
    ///
    /// Xray decodes `privateKey` and `mldsa65Seed` with
    /// `base64.RawURLEncoding` (`XC/infra/conf/transport_internet.go:853`,
    /// `:907`), so the standard alphabet, the padded form and hex are all
    /// refused there. A key that is valid here and invalid there is a config
    /// that works on one and breaks on the other.
    #[test]
    fn only_the_encoding_xray_accepts_is_accepted() {
        // The key the other tests use, which is what `xray x25519` prints.
        const KEY: &str = "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0";
        let mut value = settings();
        value
            .as_object_mut()
            .expect("object")
            .insert("privateKey".into(), json!(KEY));
        RealityServerConfig::from_xray_settings(&value).expect("the url-safe key is accepted");

        // The same 32 bytes, in the standard alphabet — padded and unpadded.
        let standard = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode([
                0x38, 0x50, 0xf9, 0x23, 0xbc, 0xf5, 0x9c, 0xdd, 0xab, 0x27, 0x40, 0x01, 0xd7, 0x3f,
                0x40, 0xff, 0xd5, 0xb7, 0x3e, 0x93, 0x6b, 0xea, 0xe0, 0xa4, 0x3a, 0x80, 0xe8, 0xe0,
                0x46, 0xb4, 0x94, 0x6d,
            ])
        };
        for written in [standard.as_str(), standard.trim_end_matches('=')] {
            let mut value = settings();
            value
                .as_object_mut()
                .expect("object")
                .insert("privateKey".into(), json!(written));
            RealityServerConfig::from_xray_settings(&value)
                .expect_err("the standard alphabet is refused, as Xray refuses it");
        }
    }

    #[test]
    fn a_client_half_copied_into_a_server_block_is_ignored_not_refused() {
        let mut value = settings();
        let object = value.as_object_mut().expect("object");
        object.insert(
            "publicKey".into(),
            json!("S3aX1kz1nN2rJ0AB1z8o9W3PpNr6uCkOoDo4Ea0lG0"),
        );
        object.insert("shortId".into(), json!("ab12"));
        object.insert("serverName".into(), json!("example.com"));
        object.insert("fingerprint".into(), json!("chrome"));
        object.insert("spiderX".into(), json!("/"));
        object.insert("mldsa65Verify".into(), json!("AAAA"));
        let config = RealityServerConfig::from_xray_settings(&value)
            .expect("a client's extra fields do not break a server");
        assert_eq!(config.fallback_xver, 1, "the server fields still applied");
        for field in CLIENT_ONLY_FIELDS {
            assert!(value.get(*field).is_some(), "{field} was in the input");
        }
    }

    #[test]
    fn the_private_key_is_read_the_way_xray_wrote_it() {
        use base64::Engine as _;
        // What `xray x25519` prints, read back byte for byte: the handshake
        // derives the same shared secret only if the stored scalar is the one
        // the operator's public key belongs to.
        let pair = zero_security::keys::x25519();
        let json = json!({
            "dest": "example.com:443",
            "privateKey": pair.private_key,
            "serverNames": ["example.com"],
            "shortIds": [""],
        });
        let config = RealityServerConfig::from_xray_settings(&json).expect("parses");
        let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&pair.private_key)
            .expect("the generator writes unpadded base64url");
        assert_eq!(config.private_key.to_vec(), written);
        let public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(config.private_key));
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes()),
            pair.public_key,
            "the stored key must be the one the clients' public key belongs to"
        );
    }

    #[test]
    fn the_server_params_carry_every_field_that_decides_a_handshake() {
        let config = RealityServerConfig::from_xray_settings(&settings()).expect("parses");
        let params = config.server_params();
        assert_eq!(params.private_key, config.private_key);
        assert_eq!(params.server_names, config.server_names);
        assert_eq!(params.short_ids, config.short_ids);
        assert_eq!(params.max_time_diff, config.max_time_diff);
        assert_eq!(params.min_client_ver, config.min_client_ver);
        assert_eq!(params.max_client_ver, config.max_client_ver);
        assert!(params.mldsa65_seed.is_none());
        // A seed in the settings is a seed the handshake will sign with.
        let mut seeded = config.clone();
        seeded.mldsa65_seed = Some([7u8; 32]);
        assert_eq!(seeded.server_params().mldsa65_seed, Some([7u8; 32]));
    }

    #[test]
    fn the_client_shape_of_a_seed_round_trips_into_the_server_params() {
        // `mldsa65Seed` is the one field that changes what the server sends on
        // the wire, so it is worth checking that what the config reads is what
        // the handshake signs with.
        let pair = zero_security::keys::mldsa65();
        let mut value = settings();
        value
            .as_object_mut()
            .expect("object")
            .insert("mldsa65Seed".into(), json!(pair.seed));
        let config = RealityServerConfig::from_xray_settings(&value).expect("parses");
        let seed = config.mldsa65_seed.expect("the seed was read");
        use base64::Engine as _;
        assert_eq!(
            seed.to_vec(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&pair.seed)
                .expect("the generator writes unpadded base64url"),
            "the handshake signs with exactly the seed the operator pasted"
        );
    }
}
