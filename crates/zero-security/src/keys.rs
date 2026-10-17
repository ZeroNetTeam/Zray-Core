//! Keys and identifiers a server operator makes for an inbound, in the text
//! forms the configuration reads.
//!
//! These are what `zray x25519`, `zray wg`, `zray mldsa65` and `zray uuid`
//! print (and Xray's tools of the same names), plus a REALITY short id, as a
//! library: a panel that builds inbounds needs them and must not have to shell
//! out to a binary to get them. Every function draws from the operating
//! system's random source and returns text; nothing is stored or sent.
//!
//! Encodings match what the configuration parser accepts, so a key made here
//! always reads back: REALITY keys and ML-DSA-65 material are unpadded
//! URL-safe base64, short ids are lowercase hex.

use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A REALITY key pair. The private key goes in the server's
/// `realitySettings.privateKey`; the public one is the clients' `pbk`
/// (`publicKey`, which `xray x25519` prints as `Password`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519Pair {
    pub private_key: String,
    pub public_key: String,
}

/// A fresh REALITY key pair. The private key is clamped before it is
/// written, as Xray writes it, so the same key reads the same in both.
pub fn x25519() -> X25519Pair {
    pair_of(
        clamp(random()),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    )
}

/// The pair of an existing private key, as `xray x25519 -i <key>` gives it.
/// Accepts unpadded URL-safe or standard base64, like the configuration.
pub fn x25519_from_private(private_key: &str) -> Result<X25519Pair, String> {
    let bytes = decode_key(private_key)?;
    Ok(pair_of(
        bytes,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ))
}

/// A fresh WireGuard key pair, in WireGuard's standard base64: the private
/// key for the server's `secretKey` or a peer's `privateKey`, the public one
/// for the other side's `publicKey`.
pub fn wireguard() -> X25519Pair {
    pair_of(clamp(random()), &base64::engine::general_purpose::STANDARD)
}

/// The WireGuard pair of an existing private key (`xray wg -i <key>`).
pub fn wireguard_from_private(private_key: &str) -> Result<X25519Pair, String> {
    let bytes = decode_key(private_key)?;
    Ok(pair_of(bytes, &base64::engine::general_purpose::STANDARD))
}

fn decode_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(text.trim()))
        .map_err(|_| "the private key is not valid base64".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "the private key must decode to 32 bytes".to_string())
}

/// RFC 7748 clamping, which X25519 applies anyway; done up front so the
/// written key is the one actually used.
fn clamp(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

fn pair_of(private: [u8; 32], engine: &impl base64::Engine) -> X25519Pair {
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    X25519Pair {
        private_key: engine.encode(private),
        public_key: engine.encode(public.as_bytes()),
    }
}

/// REALITY's post-quantum signature material. The seed goes in the server's
/// `realitySettings.mldsa65Seed` and is a secret; the verify key is the
/// clients' `mldsa65Verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsa65Pair {
    pub seed: String,
    pub verify: String,
}

/// Fresh ML-DSA-65 material.
pub fn mldsa65() -> MlDsa65Pair {
    mldsa65_of(random::<32>())
}

/// The verify key of an existing seed (`xray mldsa65 -i <seed>`).
pub fn mldsa65_from_seed(seed: &str) -> Result<MlDsa65Pair, String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seed.trim())
        .map_err(|_| "the seed is not valid base64url".to_string())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "the seed must decode to 32 bytes".to_string())?;
    Ok(mldsa65_of(bytes))
}

fn mldsa65_of(seed: [u8; 32]) -> MlDsa65Pair {
    use ml_dsa::{Keypair, MlDsa65, SigningKey};
    let verify = SigningKey::<MlDsa65>::from_seed(&seed.into())
        .verifying_key()
        .encode();
    MlDsa65Pair {
        seed: b64(&seed),
        verify: b64(verify.as_slice()),
    }
}

/// A random version 4 UUID, the form VLESS and VMess take as an account id.
pub fn uuid() -> String {
    let mut b = random::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// A REALITY short id of `bytes` random bytes (1 to 8), as lowercase hex.
pub fn short_id(bytes: usize) -> Result<String, String> {
    if !(1..=8).contains(&bytes) {
        return Err("a REALITY short id is 1 to 8 bytes".into());
    }
    let mut raw = [0u8; 8];
    OsRng.fill_bytes(&mut raw[..bytes]);
    Ok(hex::encode(&raw[..bytes]))
}

/// A random secret of `bytes` bytes as unpadded URL-safe base64: a Trojan,
/// Hysteria2 or TUIC password, or a management API token.
pub fn password(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes.max(1)];
    OsRng.fill_bytes(&mut raw);
    b64(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_x25519_pair_rebuilds_from_its_private_key() {
        let pair = x25519();
        assert_eq!(pair.private_key.len(), 43);
        assert_eq!(x25519_from_private(&pair.private_key).unwrap(), pair);
        assert_ne!(x25519().private_key, pair.private_key);
    }

    #[test]
    fn a_known_x25519_key_gives_its_known_public_half() {
        // RFC 7748 §6.1, Alice's key pair.
        let private =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let pair = x25519_from_private(&b64(&private)).unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(pair.public_key)
                .unwrap(),
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap()
        );
    }

    #[test]
    fn wireguard_keys_are_standard_base64_and_clamped() {
        let pair = wireguard();
        let private = base64::engine::general_purpose::STANDARD
            .decode(&pair.private_key)
            .unwrap();
        assert_eq!(private[0] & 7, 0);
        assert_eq!(private[31] & 0xc0, 0x40);
        assert_eq!(wireguard_from_private(&pair.private_key).unwrap(), pair);
    }

    #[test]
    fn malformed_private_keys_are_refused() {
        assert!(x25519_from_private("not base64 !").is_err());
        assert!(x25519_from_private(&b64(&[1, 2, 3])).is_err());
    }

    #[test]
    fn mldsa65_material_has_the_sizes_the_config_wants() {
        let pair = mldsa65();
        let decode = |text: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .unwrap()
        };
        assert_eq!(decode(&pair.seed).len(), 32);
        assert_eq!(decode(&pair.verify).len(), 1952);
        assert_eq!(mldsa65_from_seed(&pair.seed).unwrap(), pair);
    }

    #[test]
    fn uuids_are_version_4() {
        let id = uuid();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(uuid(), id);
    }

    #[test]
    fn short_ids_have_the_asked_length() {
        assert_eq!(short_id(8).unwrap().len(), 16);
        assert_eq!(short_id(1).unwrap().len(), 2);
        assert!(short_id(0).is_err() && short_id(9).is_err());
    }
}
