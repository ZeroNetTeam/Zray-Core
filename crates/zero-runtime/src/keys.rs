//! Every key and identifier an inbound is configured with, in one place for a
//! host that builds inbounds (a panel), in the text forms the configuration
//! reads. See [`zero_security::keys`] for REALITY, ML-DSA-65 and ids.

pub use zero_security::keys::{
    mldsa65, mldsa65_from_seed, password, short_id, uuid, wireguard, wireguard_from_private,
    x25519, x25519_from_private, MlDsa65Pair, X25519Pair,
};

/// A matching VLESS Encryption pair, `(encryption, decryption)`, as `xray
/// vlessenc` prints them: the clients' `encryption` and the server's
/// `decryption`. `mlkem` picks an ML-KEM-768 key over an X25519 one; `mode`
/// is `native`, `xorpub` or `random`; `rtt` is `0rtt` or `1rtt`; `seconds`
/// (like `600s`) is how long the server keeps a 0-RTT ticket.
pub fn vless_encryption(mlkem: bool, mode: &str, rtt: &str, seconds: &str) -> (String, String) {
    zero_protocol::vless_encryption::generate_pair(mlkem, mode, rtt, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is made here is what the configuration reads: a REALITY inbound
    /// built only from these keys compiles, and so does a VLESS Encryption
    /// one.
    #[test]
    fn generated_keys_make_a_configuration_that_compiles() {
        let reality = x25519();
        let pq = mldsa65();
        let config = serde_json::json!({
            "inbounds": [{
                "tag": "reality-in", "listen": "127.0.0.1", "port": 1, "protocol": "vless",
                "settings": {"clients": [{"id": uuid(), "flow": "xtls-rprx-vision"}], "decryption": "none"},
                "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                    "target": "example.com:443", "serverNames": ["example.com"],
                    "privateKey": reality.private_key, "shortIds": [short_id(8).unwrap()],
                    "mldsa65Seed": pq.seed,
                }},
            }, {
                "tag": "enc-in", "listen": "127.0.0.1", "port": 2, "protocol": "vless",
                "settings": {"clients": [{"id": uuid()}], "decryption": vless_encryption(true, "native", "0rtt", "600s").1},
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        });
        zero_config::compile_config(&config, zero_core::GenerationId(1))
            .unwrap_or_else(|error| panic!("generated keys rejected: {error}"));

        let client = serde_json::json!({
            "outbounds": [{
                "tag": "out", "protocol": "vless",
                "settings": {"vnext": [{"address": "example.com", "port": 443, "users": [{"id": uuid(), "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                    "serverName": "example.com", "fingerprint": "chrome",
                    "publicKey": reality.public_key, "shortId": short_id(4).unwrap(),
                    "mldsa65Verify": pq.verify,
                }},
            }],
        });
        zero_config::compile_config(&client, zero_core::GenerationId(1))
            .unwrap_or_else(|error| panic!("generated client keys rejected: {error}"));
    }
}
