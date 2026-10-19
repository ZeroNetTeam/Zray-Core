//! The key material a REALITY server needs, in Xray's encodings.
//!
//! A server's `realitySettings` carries three secrets and one selector: an
//! X25519 private key (`privateKey`), an optional ML-DSA-65 seed
//! (`mldsa65Seed`), an optional allowlist of `shortIds`, and the allowlist of
//! `serverNames` it is willing to camouflage. Everything here is the same
//! arithmetic the client's share link carries, so the primitives live in
//! `zero-security::keys` — one implementation for both sides — and this module
//! is the server-facing name for them, so a server crate can depend on
//! `reality` alone.
//!
//! The encodings are Xray's, byte for byte:
//!
//! * `xray x25519` prints the private key as unpadded URL-safe base64 of the
//!   32-byte scalar, and the public key the same way. The private key is
//!   clamped before it is written, so the key in the config is the key that is
//!   used.
//! * `xray mldsa65` prints a seed and the verify key derived from it, both
//!   unpadded URL-safe base64. The seed is a secret and stays on the server;
//!   only the verify key goes to clients as `mldsa65Verify`.
//! * A `shortIds` entry is lowercase hex of up to 8 bytes, and Xray pads it on
//!   the right with zeros to the 8 bytes the session id carries, so `"ab"` and
//!   `"ab000000000000"` are the same selector and `""` selects the all-zero
//!   one. There is no wildcard: a server accepts exactly the selectors it
//!   lists, which is why a fresh deployment usually writes one of each.

pub use zero_security::keys::{
    mldsa65, mldsa65_from_seed, short_id, x25519, x25519_from_private, MlDsa65Pair, X25519Pair,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_pair_reads_back_as_the_key_it_was_made_from() {
        let pair = x25519();
        let again = x25519_from_private(&pair.private_key).expect("the private key parses back");
        assert_eq!(again.public_key, pair.public_key);
    }

    #[test]
    fn a_generated_short_id_is_hex_and_fits_the_session_id() {
        for bytes in 1..=8 {
            let id = short_id(bytes).expect("1 to 8 bytes is a valid short id");
            assert_eq!(id.len(), bytes * 2);
            assert!(id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        // The generator will not make a selector that cannot be told apart
        // from an unwritten one; a config that wants the all-zero selector
        // writes `""` by hand, as Xray's own docs do.
        assert!(short_id(0).is_err());
        assert!(short_id(9).is_err(), "9 bytes cannot fit the session id");
    }

    #[test]
    fn mldsa65_material_round_trips_through_its_seed() {
        let pair = mldsa65();
        let again = mldsa65_from_seed(&pair.seed).expect("the seed parses back");
        assert_eq!(again.verify, pair.verify);
    }
}
