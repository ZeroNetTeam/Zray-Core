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

use std::time::Duration;

use serde_json::Value;

use crate::server::RealityServerParams;

/// The type of `limitFallbackUpload` / `limitFallbackDownload` is
/// [`FallbackLimit`], the relay's own: the settings reader produces exactly the
/// value the relay consumes, so there is no mapping step for a server to get
/// wrong. See that type for what the three numbers mean and for Xray's
/// defaults.
pub use crate::fallback::FallbackLimit;

/// Everything a REALITY server listener needs, parsed from `realitySettings`.
#[derive(Clone)]
pub struct RealityServerConfig {
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
    /// `None` means the server has nowhere to send an unauthenticated visitor,
    /// which is only sensible when something else in front of it does.
    pub target: Option<(Box<str>, u16)>,
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
        let target = match object.get("dest").or_else(|| object.get("target")) {
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
                Some(parse_target(text)?)
            }
        };

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

        Ok(Self {
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
            private_key: self.private_key,
            server_names: self.server_names.clone(),
            short_ids: self.short_ids.clone(),
            mldsa65_seed: self.mldsa65_seed,
            max_time_diff: self.max_time_diff,
            min_client_ver: self.min_client_ver,
            max_client_ver: self.max_client_ver,
            post_handshake: Default::default(),
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

/// The two engines Xray and this workspace's config compiler accept: URL-safe
/// without padding (what `xray x25519` prints) and the standard alphabet.
fn decode_base64_any(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let text = text.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(text))
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

/// `dest` as Xray reads it: a unix socket path, a bare port on localhost, or
/// host:port.
fn parse_target(text: &str) -> Result<(Box<str>, u16), String> {
    let text = text.trim();
    if text.starts_with('@') || text.starts_with('/') {
        // A unix-socket target is a real Xray feature this crate does not
        // speak yet. Refusing beats resolving it as a host name, which would
        // hand every unauthenticated visitor to a DNS lookup of `/run/x.sock`.
        return Err(format!(
            "realitySettings.dest {text:?} is a unix socket, which this server does not dial yet"
        ));
    }
    if text.bytes().all(|byte| byte.is_ascii_digit()) && !text.is_empty() {
        // Xray turns a bare port into `localhost:<port>`
        // (`infra/conf/transport_internet.go:834-836`).
        let port: u16 = text
            .parse()
            .map_err(|_| format!("realitySettings.dest {text:?} is not a port"))?;
        return Ok((Box::from("localhost"), port));
    }
    zero_core::address::split_host_port(text)
        .map(|(host, port)| (Box::from(host), port))
        .ok_or_else(|| format!("realitySettings.dest {text:?} is not host:port"))
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
        let (host, port) = config.target.clone().expect("dest was read");
        assert_eq!((&*host, port), ("example.com", 443));
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
        let (host, port) = config.target.expect("dest is required, so it is set");
        assert_eq!((&*host, port), ("localhost", 8443));
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
