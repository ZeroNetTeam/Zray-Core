//! Xray's `finalmask.udp` layers for mKCP datagrams.
//!
//! Since Xray 24.9.30 the old `kcpSettings.header`/`seed` fields are removed:
//! obfuscation is requested with `finalmask.udp` layers instead. Every layer
//! wraps a whole datagram, segment header included, and the kinds mKCP uses
//! fall into two families:
//!
//! - **`mkcp-original`** — the pre-finalmask frame: a 4-byte big-endian
//!   FNV-1a hash of `len || payload`, the 2-byte big-endian length, the
//!   payload, zero padding to a multiple of four, and an XOR chain with a
//!   stride of four. The padding is dropped again after the XOR, so the
//!   datagram is only as long as `6 + payload`.
//! - **`mkcp-aes128gcm`** — AES-128-GCM under the key
//!   `SHA256(password)[0..16]`, with no additional data. The wire is
//!   `nonce(12) || ciphertext || tag(16)`; the nonce is random per datagram.
//! - **`header-srtp`, `header-utp`, `header-wechat`, `header-dtls`,
//!   `header-wireguard`, `header-dns`** — a fixed-shape prefix that makes the
//!   datagram look like another UDP protocol. The peer never validates it, so
//!   its changing fields (sequence numbers, transaction ids) are cosmetic;
//!   they are still reproduced the way `finalmask/header/*/conn.go` writes
//!   them. `header-dns` is the one with a setting: the queried domain.
//!
//! All of these are `HeaderConn` masks in Xray (`finalmask/*/config.go`), so
//! they compose through `headerManagerConn` rather than owning the socket:
//! each one seals in place and hands the result to the next layer. The
//! **first** entry in `finalmask.udp` is the outermost layer, so it is
//! written last and read first — the order [`Masks::wrap`] and
//! [`Masks::unwrap`] reproduce.
//!
//! With no mask configured Xray sends the raw KCP segments, which is what an
//! empty [`Masks`] does.

use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::{Digest, Sha256};

/// The fixed prefixes Xray can put in front of an mKCP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    Srtp,
    Utp,
    Wechat,
    Dtls,
    Wireguard,
    Dns,
}

/// The masks mKCP understands, in config order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mask {
    /// `mkcp-original`.
    Original,
    /// `mkcp-aes128gcm`, with the shared password.
    Aes128Gcm(Arc<str>),
    /// One `header-*` layer. `domain` is the `header-dns` query name and is
    /// ignored by every other kind.
    Header {
        kind: HeaderKind,
        domain: Option<Arc<str>>,
    },
}

/// The prepared layers of one carrier: keys derived once, wrappers applied in
/// order to every datagram.
#[derive(Clone)]
pub struct Masks {
    layers: Arc<[Layer]>,
}

#[derive(Clone)]
enum Layer {
    Original,
    Aes(Aes128Gcm),
    Header(Header),
}

#[derive(Clone)]
struct Header {
    kind: HeaderKind,
    /// The prebuilt DNS question (header, qname, type A, class IN).
    dns: Option<Arc<[u8]>>,
    /// DTLS's random epoch, constant for the layer's life.
    epoch: u16,
    /// uTP's random connection id.
    connection_id: u16,
    /// The fields that advance per datagram. Shared by every session using
    /// this layer: Xray gives each wrapped connection its own counters, but
    /// the peer ignores them, so monotonic values are enough here.
    state: Arc<Mutex<HeaderState>>,
}

struct HeaderState {
    srtp: u16,
    wechat: u32,
    dtls_sequence: u32,
    dtls_length: u16,
}

impl Default for HeaderState {
    fn default() -> Self {
        Self {
            // Xray seeds the first packet's counters with a random value and
            // increments before writing (`header/*/conn.go`).
            srtp: rand::random(),
            wechat: u32::from(rand::random::<u16>()),
            dtls_sequence: 0,
            // `NewConnClient` starts the DTLS record length at 17.
            dtls_length: 17,
        }
    }
}

impl Header {
    fn new(kind: HeaderKind, domain: Option<&str>) -> Self {
        let dns = (kind == HeaderKind::Dns).then(|| {
            let domain = domain.filter(|name| !name.is_empty()).unwrap_or("www.baidu.com");
            Arc::from(dns_header(domain).into_boxed_slice())
        });
        Self {
            kind,
            dns,
            epoch: rand::random(),
            connection_id: rand::random(),
            state: Arc::new(Mutex::new(HeaderState::default())),
        }
    }

    fn size(&self) -> usize {
        match self.kind {
            HeaderKind::Srtp | HeaderKind::Utp | HeaderKind::Wireguard => 4,
            HeaderKind::Wechat | HeaderKind::Dtls => 13,
            HeaderKind::Dns => self.dns.as_deref().map_or(0, <[u8]>::len),
        }
    }

    fn prefix(&self) -> Vec<u8> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut prefix = Vec::with_capacity(16);
        match self.kind {
            HeaderKind::Srtp => {
                // `srtp.Serialize`: a constant RTP header and a 16-bit number.
                state.srtp = state.srtp.wrapping_add(1);
                prefix.extend_from_slice(&0xB5E8u16.to_be_bytes());
                prefix.extend_from_slice(&state.srtp.to_be_bytes());
            }
            HeaderKind::Utp => {
                // `utp.Serialize`: connection id, then the version-1 byte and
                // no extensions.
                prefix.extend_from_slice(&self.connection_id.to_be_bytes());
                prefix.extend_from_slice(&[1, 0]);
            }
            HeaderKind::Wechat => {
                state.wechat = state.wechat.wrapping_add(1);
                prefix.extend_from_slice(&[0xa1, 0x08]);
                prefix.extend_from_slice(&state.wechat.to_be_bytes());
                prefix.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            HeaderKind::Dtls => {
                let sequence = state.dtls_sequence;
                state.dtls_sequence = state.dtls_sequence.wrapping_add(1);
                let length = state.dtls_length;
                state.dtls_length = state.dtls_length.wrapping_add(17);
                if state.dtls_length > 100 {
                    state.dtls_length -= 50;
                }
                prefix.extend_from_slice(&[23, 254, 253]);
                prefix.extend_from_slice(&self.epoch.to_be_bytes());
                prefix.extend_from_slice(&[0, 0]);
                prefix.extend_from_slice(&sequence.to_be_bytes());
                prefix.extend_from_slice(&length.to_be_bytes());
            }
            HeaderKind::Wireguard => prefix.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]),
            HeaderKind::Dns => {
                let mut header = self.dns.as_deref().unwrap_or(&[]).to_vec();
                // A fresh transaction id per packet; the question is fixed.
                let transaction: u16 = rand::random();
                if header.len() >= 2 {
                    header[..2].copy_from_slice(&transaction.to_be_bytes());
                }
                prefix = header;
            }
        }
        prefix
    }
}

impl Masks {
    pub fn new(masks: &[Mask]) -> Self {
        let layers: Vec<Layer> = masks
            .iter()
            .map(|mask| match mask {
                Mask::Original => Layer::Original,
                Mask::Aes128Gcm(password) => {
                    let key = Sha256::digest(password.as_bytes());
                    // `new_from_slice` only fails on a wrong key length, and
                    // the digest's first 16 bytes are a valid AES-128 key.
                    let cipher = Aes128Gcm::new_from_slice(&key[..16])
                        .expect("SHA-256's first 16 bytes are an AES-128 key");
                    Layer::Aes(cipher)
                }
                Mask::Header { kind, domain } => {
                    Layer::Header(Header::new(*kind, domain.as_deref()))
                }
            })
            .collect();
        Self {
            layers: layers.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Apply every layer, outermost first: the last configured mask seals the
    /// payload first and the first configured mask seals the result.
    pub fn wrap(&self, payload: &[u8]) -> Vec<u8> {
        if self.layers.is_empty() {
            return payload.to_vec();
        }
        let mut current = payload.to_vec();
        for layer in self.layers.iter().rev() {
            current = layer.seal(&current);
        }
        current
    }

    /// Undo [`Masks::wrap`]. `None` means the datagram is not authentic under
    /// this key (or is too short to be shaped at all); the caller drops it.
    pub fn unwrap(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        if self.layers.is_empty() {
            return Some(datagram.to_vec());
        }
        let mut current = datagram.to_vec();
        for layer in self.layers.iter() {
            current = layer.open(&current)?;
        }
        Some(current)
    }
}

impl Layer {
    fn seal(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            Layer::Original => seal_original(payload),
            Layer::Aes(cipher) => seal_aes(cipher, payload),
            Layer::Header(header) => {
                let prefix = header.prefix();
                let mut out = Vec::with_capacity(prefix.len() + payload.len());
                out.extend_from_slice(&prefix);
                out.extend_from_slice(payload);
                out
            }
        }
    }

    fn open(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        match self {
            Layer::Original => open_original(datagram),
            Layer::Aes(cipher) => open_aes(cipher, datagram),
            // The peer only strips the fixed prefix; nothing in it is
            // authenticated, which is exactly why it is cosmetic.
            Layer::Header(header) => {
                let size = header.size();
                (datagram.len() >= size).then(|| datagram[size..].to_vec())
            }
        }
    }
}

/// The original mask's overhead: hash and length.
const ORIGINAL_OVERHEAD: usize = 6;
/// AES-GCM's nonce size, which Xray puts in front of the ciphertext.
const AES_NONCE: usize = 12;
/// AES-GCM's tag, which `aes-gcm` appends.
const AES_TAG: usize = 16;

fn seal_original(payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len()).expect("an mKCP datagram fits a u16 length");
    let mut out = Vec::with_capacity(ORIGINAL_OVERHEAD + payload.len() + 3);
    // The hash covers the length and the payload, so it is written after
    // both are in place.
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    let hash = fnv1a32(&out[4..]);
    out[..4].copy_from_slice(&hash.to_be_bytes());

    // Xray pads to a word boundary for the XOR chain and then truncates the
    // padding away again; the receiver pads the same way before undoing it.
    let padded = out.len() + (4 - out.len() % 4) % 4;
    out.resize(padded, 0);
    xor_forward(&mut out);
    out.truncate(ORIGINAL_OVERHEAD + payload.len());
    out
}

fn open_original(datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < ORIGINAL_OVERHEAD {
        return None;
    }
    let padded = datagram.len() + (4 - datagram.len() % 4) % 4;
    let mut buf = datagram.to_vec();
    buf.resize(padded, 0);
    xor_backward(&mut buf);
    buf.truncate(datagram.len());

    let expected = u32::from_be_bytes(buf[..4].try_into().expect("four bytes"));
    if fnv1a32(&buf[4..]) != expected {
        return None;
    }
    let claimed = u16::from_be_bytes(buf[4..6].try_into().expect("two bytes")) as usize;
    if claimed != buf.len() - ORIGINAL_OVERHEAD {
        return None;
    }
    Some(buf[ORIGINAL_OVERHEAD..].to_vec())
}

fn seal_aes(cipher: &Aes128Gcm, payload: &[u8]) -> Vec<u8> {
    let nonce: [u8; AES_NONCE] = rand::random();
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .expect("AES-GCM seals into a fresh buffer");
    let mut out = Vec::with_capacity(AES_NONCE + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

fn open_aes(cipher: &Aes128Gcm, datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < AES_NONCE + AES_TAG {
        return None;
    }
    let (nonce, ciphertext) = datagram.split_at(AES_NONCE);
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}

/// FNV-1a, 32-bit, which is what Go's `fnv.New32a` computes.
fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in bytes {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn xor_forward(buffer: &mut [u8]) {
    for index in 4..buffer.len() {
        buffer[index] ^= buffer[index - 4];
    }
}

fn xor_backward(buffer: &mut [u8]) {
    for index in (4..buffer.len()).rev() {
        buffer[index] ^= buffer[index - 4];
    }
}

/// The fixed part of a DNS query: header, the name as length-prefixed labels,
/// then type A and class IN. The transaction id is overwritten per packet.
fn dns_header(domain: &str) -> Vec<u8> {
    let mut header = Vec::with_capacity(32);
    header.extend_from_slice(&0u16.to_be_bytes()); // transaction id
    header.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query
    header.extend_from_slice(&1u16.to_be_bytes()); // one question
    header.extend_from_slice(&0u16.to_be_bytes()); // answers
    header.extend_from_slice(&0u16.to_be_bytes()); // authority
    header.extend_from_slice(&0u16.to_be_bytes()); // additional
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let take = bytes.len().min(63);
        header.push(take as u8);
        header.extend_from_slice(&bytes[..take]);
    }
    header.push(0);
    header.extend_from_slice(&0x0001u16.to_be_bytes()); // type A
    header.extend_from_slice(&0x0001u16.to_be_bytes()); // class IN
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_round_trips_at_every_padding_length() {
        let masks = Masks::new(&[Mask::Original]);
        for length in 0..=17usize {
            let payload: Vec<u8> = (0..length).map(|i| (i * 7 + 3) as u8).collect();
            let sealed = masks.wrap(&payload);
            assert_eq!(sealed.len(), payload.len() + 6);
            assert_eq!(masks.unwrap(&sealed).unwrap(), payload);
        }
    }

    #[test]
    fn original_refuses_a_broken_datagram() {
        let masks = Masks::new(&[Mask::Original]);
        let mut sealed = masks.wrap(b"an mKCP segment");
        let middle = sealed.len() / 2;
        sealed[middle] ^= 0x40;
        assert!(masks.unwrap(&sealed).is_none());
        assert!(masks.unwrap(&sealed[..5]).is_none());
    }

    #[test]
    fn aes_round_trips_and_refuses_another_key() {
        let masks = Masks::new(&[Mask::Aes128Gcm("a password".into())]);
        let payload = vec![0xAB; 1200];
        let sealed = masks.wrap(&payload);
        assert_eq!(sealed.len(), payload.len() + 12 + 16);
        assert_eq!(masks.unwrap(&sealed).unwrap(), payload);

        let other = Masks::new(&[Mask::Aes128Gcm("another password".into())]);
        assert!(other.unwrap(&sealed).is_none());
        assert!(masks.unwrap(&sealed[..20]).is_none());
    }

    #[test]
    fn the_first_mask_is_the_outermost_layer() {
        let masks = Masks::new(&[Mask::Original, Mask::Aes128Gcm("a password".into())]);
        let payload = b"the wire, inside out";
        let sealed = masks.wrap(payload);
        assert_eq!(masks.unwrap(&sealed).unwrap(), payload);

        // The outermost frame is `mkcp-original`: its length covers the AES
        // layer's nonce, ciphertext and tag. Every byte after the hash is
        // XOR-chained on the wire, so the shape is checked by reopening it.
        let inner = open_original(&sealed).expect("the original frame authenticates");
        assert_eq!(inner.len(), payload.len() + 12 + 16);
        assert!(open_aes(
            &Aes128Gcm::new_from_slice(&Sha256::digest(b"a password")[..16]).unwrap(),
            &inner
        )
        .is_some());
    }

    #[test]
    fn header_layers_have_xray_shapes_and_round_trip() {
        for (kind, size) in [
            (HeaderKind::Srtp, 4usize),
            (HeaderKind::Utp, 4),
            (HeaderKind::Wechat, 13),
            (HeaderKind::Dtls, 13),
            (HeaderKind::Wireguard, 4),
        ] {
            let masks = Masks::new(&[Mask::Header { kind, domain: None }]);
            let payload = b"a segment";
            let first = masks.wrap(payload);
            assert_eq!(first.len(), size + payload.len(), "{kind:?} size");
            assert_eq!(&first[size..], payload, "{kind:?} payload");
            assert_eq!(masks.unwrap(&first).unwrap(), payload, "{kind:?} strip");
        }

        // The constants each shape starts with, from `finalmask/header/*`.
        let srtp = Masks::new(&[Mask::Header {
            kind: HeaderKind::Srtp,
            domain: None,
        }]);
        let wire = srtp.wrap(b"x");
        assert_eq!(&wire[..2], &[0xB5, 0xE8]);
        let number = u16::from_be_bytes([wire[2], wire[3]]);
        let wire = srtp.wrap(b"x");
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), number.wrapping_add(1));

        let utp = Masks::new(&[Mask::Header {
            kind: HeaderKind::Utp,
            domain: None,
        }]);
        let wire = utp.wrap(b"x");
        assert_eq!(&wire[2..4], &[1, 0]);

        let wechat = Masks::new(&[Mask::Header {
            kind: HeaderKind::Wechat,
            domain: None,
        }]);
        let wire = wechat.wrap(b"x");
        assert_eq!(&wire[..2], &[0xa1, 0x08]);
        assert_eq!(&wire[6..], &[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30, b'x']);

        let dtls = Masks::new(&[Mask::Header {
            kind: HeaderKind::Dtls,
            domain: None,
        }]);
        let wire = dtls.wrap(b"x");
        assert_eq!(&wire[..3], &[23, 254, 253]);
        assert_eq!(&wire[5..7], &[0, 0]);
        assert_eq!(u16::from_be_bytes([wire[11], wire[12]]), 17);
        let wire = dtls.wrap(b"x");
        assert_eq!(u32::from_be_bytes([wire[7], wire[8], wire[9], wire[10]]), 1);
        assert_eq!(u16::from_be_bytes([wire[11], wire[12]]), 34);

        let wireguard = Masks::new(&[Mask::Header {
            kind: HeaderKind::Wireguard,
            domain: None,
        }]);
        assert_eq!(wireguard.wrap(b"x"), b"\x04\x00\x00\x00x");
    }

    #[test]
    fn the_dns_header_is_a_query_with_the_configured_name() {
        let masks = Masks::new(&[Mask::Header {
            kind: HeaderKind::Dns,
            domain: Some("example.com".into()),
        }]);
        let wire = masks.wrap(b"payload");
        let size = wire.len() - 7;
        assert_eq!(size, dns_header("example.com").len());
        assert_eq!(size, 12 + 13 + 4);
        assert_eq!(&wire[2..size], &dns_header("example.com")[2..]);
        assert_eq!(masks.unwrap(&wire).unwrap(), b"payload");

        // An empty or absent domain falls back to Xray's `www.baidu.com`.
        let default = Masks::new(&[Mask::Header {
            kind: HeaderKind::Dns,
            domain: None,
        }]);
        assert_eq!(default.wrap(b"x").len() - 1, dns_header("www.baidu.com").len());
    }

    #[test]
    fn a_header_stack_peels_in_reverse() {
        let masks = Masks::new(&[
            Mask::Header {
                kind: HeaderKind::Srtp,
                domain: None,
            },
            Mask::Aes128Gcm("a password".into()),
            Mask::Original,
        ]);
        let payload = vec![7u8; 33];
        let wire = masks.wrap(&payload);
        // SRTP is first, so it is the four bytes on the outside.
        assert_eq!(&wire[..2], &[0xB5, 0xE8]);
        assert_eq!(masks.unwrap(&wire).unwrap(), payload);

        // A short datagram is rejected by whichever layer cannot be stripped.
        let header_only = Masks::new(&[Mask::Header {
            kind: HeaderKind::Srtp,
            domain: None,
        }]);
        assert!(header_only.unwrap(&[0u8; 3]).is_none());
        assert!(header_only.unwrap(&[]).is_none());
    }

    #[test]
    fn no_mask_passes_the_datagram_through() {
        let masks = Masks::new(&[]);
        assert!(masks.is_empty());
        assert_eq!(masks.wrap(b"raw"), b"raw");
        assert_eq!(masks.unwrap(b"raw").unwrap(), b"raw");
    }
}
