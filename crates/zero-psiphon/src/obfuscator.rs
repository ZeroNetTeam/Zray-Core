//! The obfuscated SSH (OSSH) layer.
//!
//! Psiphon wraps its SSH session in the obfuscation scheme used by
//! `obfuscated-openssh`: a random 16-byte seed is sent in the clear, both
//! directions derive an RC4 key from it and a per-server keyword, and
//! everything after the seed's magic value is encrypted until each direction
//! has passed `SSH_MSG_NEWKEYS`. During the key exchange the outgoing SSH
//! packets are rewritten with extra random padding so the exchange does not
//! have OpenSSH's characteristic sizes.
//!
//! The cryptography here is deliberately simple: RC4 provides obfuscation,
//! not security. Confidentiality and integrity come from SSH above it, which
//! is exactly how Psiphon uses it.
//!
//! Compatibility is with Psiphon's `common/obfuscator` Go package, in the
//! client role: the seed message, the packet padding rewrite and the
//! tolerance for extra server lines before the version line.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Size of the clear seed at the start of the stream.
pub const SEED_LENGTH: usize = 16;
/// The fixed value that tells the server this is an OSSH stream.
pub const MAGIC_VALUE: u32 = 0x0BF5_CA7E;
/// How many times the key's SHA-1 digest is re-hashed.
pub const HASH_ITERATIONS: usize = 6000;
/// The derived RC4 key length.
pub const KEY_LENGTH: usize = 16;
/// Largest padding the seed message may carry.
pub const MAX_PADDING: usize = 8192;
/// Smallest padding the client may send (the server uses it as its PRNG seed).
pub const MIN_PADDING: usize = 32;
/// The OpenSSH packet length ceiling Psiphon accepts.
pub const MAX_PACKET_LENGTH: usize = 256 * 1024;
/// The longest server identification line.
pub const MAX_IDENTIFICATION_LINE: usize = 1024;
/// The SSH message type whose passage ends obfuscation.
const SSH_MSG_NEWKEYS: u8 = 21;
/// The default cipher block size, used only for the legacy Ganymed padding.
const SSH_PADDING_MULTIPLE: usize = 16;
/// The largest SSH padding length field value.
const SSH_MAX_PADDING_LENGTH: usize = 255;

/// RC4, as the OSSH obfuscator uses it.
///
/// Kept crate-visible but not public: the client needs it, the mock server
/// that tests the client needs it, and nothing outside the crate should be
/// reaching for a cipher this weak. The only requirement is that it is the
/// standard algorithm, which the RFC 6229 test vector below pins.
pub(crate) struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Rc4 {
        assert!(!key.is_empty(), "RC4 needs a non-empty key");
        let mut state = [0u8; 256];
        for (index, byte) in state.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Rc4 { state, i: 0, j: 0 }
    }

    /// A cipher that has been thrown away. Applying it is a no-op, which is
    /// what the obfuscated phase wants once it is over: the connection is
    /// plain SSH from both ends.
    pub(crate) fn forgotten() -> Rc4 {
        Rc4 {
            state: [0; 256],
            i: 0,
            j: 0,
        }
    }

    /// XOR the keystream into `data`, continuing this cipher's position.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            let i = self.i as usize;
            self.j = self.j.wrapping_add(self.state[i]);
            let j = self.j as usize;
            self.state.swap(i, j);
            let key_byte = self.state[(self.state[i] as usize + self.state[j] as usize) & 0xFF];
            *byte ^= key_byte;
        }
    }
}

/// Derive one direction's RC4 key the way the Go client does:
/// `SHA1(seed || keyword || direction)` re-hashed `HASH_ITERATIONS` times,
/// truncated to 16 bytes.
pub fn derive_key(seed: &[u8], keyword: &[u8], direction: &[u8]) -> [u8; KEY_LENGTH] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(keyword);
    hasher.update(direction);
    let mut digest: [u8; 20] = hasher.finalize().into();
    for _ in 0..HASH_ITERATIONS {
        digest = Sha1::digest(digest).into();
    }
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&digest[..KEY_LENGTH]);
    key
}

/// The direction labels both sides hash into the key derivation.
pub(crate) const CLIENT_TO_SERVER: &[u8] = b"client_to_server";
pub(crate) const SERVER_TO_CLIENT: &[u8] = b"server_to_client";

/// Build the client's seed message: `seed | magic | padding_length | padding`,
/// with everything from the magic onward encrypted.
fn build_preamble(keyword: &[u8], seed: [u8; SEED_LENGTH], padding: &[u8]) -> (Vec<u8>, Rc4, Rc4) {
    let mut client_to_server = Rc4::new(&derive_key(&seed, keyword, CLIENT_TO_SERVER));
    let server_to_client = Rc4::new(&derive_key(&seed, keyword, SERVER_TO_CLIENT));

    let mut preamble = Vec::with_capacity(SEED_LENGTH + 8 + padding.len());
    preamble.extend_from_slice(&seed);
    preamble.extend_from_slice(&MAGIC_VALUE.to_be_bytes());
    preamble.extend_from_slice(&(padding.len() as u32).to_be_bytes());
    preamble.extend_from_slice(padding);
    client_to_server.apply(&mut preamble[SEED_LENGTH..]);

    (preamble, client_to_server, server_to_client)
}

/// A stream whose bytes are the Psiphon OSSH layer's, over `S`.
///
/// Reads and writes finish obfuscation independently, exactly as the protocol
/// does: the client may still be obfuscating its own writes while reading the
/// server's plaintext SSH.
pub struct OsshClient<S> {
    inner: S,
    client_to_server: Rc4,
    server_to_client: Rc4,
    preamble: Vec<u8>,
    /// Obfuscated bytes waiting to go out.
    out: BytesMut,
    /// Bytes the caller has written that are not yet framed into packets.
    kex: BytesMut,
    /// Deobfuscated bytes waiting for the caller.
    ready: BytesMut,
    /// Bytes read from the wire that are not yet framed (already deobfuscated).
    incoming: BytesMut,
    /// Framed, still-plaintext packets on their way to `out`. Reused across
    /// writes so a busy connection does not allocate per call.
    scratch: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    /// Whether the key exchange's state has already been handed back.
    released: bool,
    legacy_padding: bool,
    padding: StdRng,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    IdentificationLines,
    KexPackets,
    AfterNewKeys,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteState {
    SendPreamble,
    IdentificationLine,
    KexPackets,
    Finished,
}

impl<S> OsshClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Wrap `inner` in the OSSH client layer with Psiphon's default padding.
    pub fn new(inner: S, keyword: &[u8]) -> Self {
        Self::with_padding(inner, keyword, MIN_PADDING, MAX_PADDING)
    }

    /// Wrap `inner` with a padding range of the caller's choosing, which is
    /// how tactics set it.
    pub fn with_padding_range(inner: S, keyword: &[u8], range: Option<(usize, usize)>) -> Self {
        match range {
            Some((minimum, maximum)) if minimum <= maximum => {
                Self::with_padding(inner, keyword, minimum, maximum)
            }
            _ => Self::new(inner, keyword),
        }
    }

    /// Wrap `inner`, choosing the seed message's padding in `[min, max]`.
    pub fn with_padding(inner: S, keyword: &[u8], min: usize, max: usize) -> Self {
        let mut rng = StdRng::from_entropy();
        let min = min.max(MIN_PADDING);
        let max = max.min(MAX_PADDING).max(min);
        let padding_length = rng.gen_range(min..=max);
        let mut padding = vec![0u8; padding_length];
        rng.fill(&mut padding[..]);

        let mut seed = [0u8; SEED_LENGTH];
        rng.fill(&mut seed);

        let (preamble, client_to_server, server_to_client) =
            build_preamble(keyword, seed, &padding);

        OsshClient {
            inner,
            client_to_server,
            server_to_client,
            preamble,
            // The key exchange carries an identification line and a handful of
            // packets; a modest reservation keeps the whole phase allocation
            // free without holding memory the connection will not use.
            out: BytesMut::with_capacity(1024),
            kex: BytesMut::with_capacity(4096),
            ready: BytesMut::with_capacity(1024),
            incoming: BytesMut::with_capacity(4096),
            scratch: BytesMut::with_capacity(4096),
            read_state: ReadState::IdentificationLines,
            write_state: WriteState::SendPreamble,
            released: false,
            legacy_padding: false,
            // Only this side's source of the random lengths in the packet
            // rewrite; the protocol requires unpredictability, not a
            // particular sequence.
            padding: StdRng::from_entropy(),
        }
    }

    /// Recover the wrapped stream. Only meaningful once both directions have
    /// finished the key exchange.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for OsshClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.ready.is_empty() {
                let take = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready.split_to(take));
                return Poll::Ready(Ok(()));
            }

            if this.read_state == ReadState::Finished {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            match this.frame_incoming() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            // Framing may have just finished the obfuscated phase; the rest
            // of the connection is plaintext and must bypass the cipher.
            if this.read_state == ReadState::Finished {
                continue;
            }

            // Need more bytes. Never over-read in the obfuscated phase: bytes
            // after the server's NEWKEYS are plaintext SSH and must not be
            // passed through RC4.
            let need = this.bytes_needed();
            let start = this.incoming.len();
            this.incoming.resize(start + need, 0);
            let mut read = ReadBuf::new(&mut this.incoming[start..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Pending => {
                    this.incoming.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => {
                    this.incoming.truncate(start);
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) => {
                    let filled = read.filled().len();
                    if filled == 0 {
                        this.incoming.truncate(start);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the server closed during the obfuscated key exchange",
                        )));
                    }
                    this.incoming.truncate(start + filled);
                    this.server_to_client.apply(&mut this.incoming[start..]);
                }
            }
        }
    }
}

impl<S> OsshClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Drop what the key exchange needed once both directions carry plain
    /// SSH: the ciphers, the seed message and the padding source are all dead
    /// weight for the rest of the connection's life.
    fn release_kex_state(&mut self) {
        if self.write_state != WriteState::Finished || self.read_state != ReadState::Finished {
            return;
        }
        if self.released {
            return;
        }
        self.released = true;
        self.client_to_server = Rc4::forgotten();
        self.server_to_client = Rc4::forgotten();
        self.preamble = Vec::new();
        self.padding = StdRng::from_seed([0u8; 32]);

        // Buffers that still hold bytes are left alone: `out` may be waiting
        // on the socket, and the scratch buffer is handed back by the code
        // that borrowed it. The empty ones give their capacity back now
        // (`BytesMut` has no `shrink_to_fit`).
        if self.kex.is_empty() {
            self.kex = BytesMut::new();
        }
        if self.incoming.is_empty() {
            self.incoming = BytesMut::new();
        }
    }

    /// How many more wire bytes the current read state needs before it can
    /// make progress.
    fn bytes_needed(&self) -> usize {
        match self.read_state {
            // One byte at a time, as the Go client does, so a line boundary
            // followed by post-NEWKEYS plaintext is never over-read.
            ReadState::IdentificationLines => 1,
            ReadState::KexPackets => {
                if self.incoming.len() < 5 {
                    5 - self.incoming.len()
                } else {
                    let packet_length = u32::from_be_bytes([
                        self.incoming[0],
                        self.incoming[1],
                        self.incoming[2],
                        self.incoming[3],
                    ]) as usize;
                    (4 + packet_length)
                        .saturating_sub(self.incoming.len())
                        .max(1)
                }
            }
            ReadState::AfterNewKeys | ReadState::Finished => 1,
        }
    }

    /// Consume whatever complete frames `self.incoming` holds. Returns whether
    /// anything was consumed.
    fn frame_incoming(&mut self) -> std::result::Result<bool, io::Error> {
        match self.read_state {
            ReadState::IdentificationLines => {
                let Some(end) = find_crlf(&self.incoming) else {
                    if self.incoming.len() > MAX_IDENTIFICATION_LINE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "server identification line too long",
                        ));
                    }
                    return Ok(false);
                };
                let line = self.incoming.split_to(end + 2);
                if line.starts_with(b"SSH-") {
                    if line.windows(7).any(|window| window == b"Ganymed") {
                        self.legacy_padding = true;
                    }
                    self.ready.extend_from_slice(&line);
                    self.read_state = ReadState::KexPackets;
                }
                // RFC 4253 lets a server send other lines first; discard them.
                Ok(true)
            }
            ReadState::KexPackets => {
                if self.incoming.len() < 5 {
                    return Ok(false);
                }
                let packet_length = u32::from_be_bytes([
                    self.incoming[0],
                    self.incoming[1],
                    self.incoming[2],
                    self.incoming[3],
                ]) as usize;
                if !(1..=MAX_PACKET_LENGTH).contains(&packet_length) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid SSH packet length in the OSSH stream",
                    ));
                }
                let padding_length = self.incoming[4] as usize;
                if padding_length >= packet_length {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid SSH packet padding length in the OSSH stream",
                    ));
                }
                let message_length = 4 + packet_length;
                if self.incoming.len() < message_length {
                    return Ok(false);
                }
                let packet = self.incoming.split_to(message_length);
                let payload_length = packet_length - padding_length - 1;
                let is_new_keys = payload_length > 0 && packet[5] == SSH_MSG_NEWKEYS;
                self.ready.extend_from_slice(&packet);
                if is_new_keys {
                    self.read_state = ReadState::AfterNewKeys;
                }
                Ok(true)
            }
            ReadState::AfterNewKeys => {
                if self.ready.is_empty() {
                    self.read_state = ReadState::Finished;
                    self.release_kex_state();
                }
                Ok(false)
            }
            ReadState::Finished => Ok(false),
        }
    }
}

impl<S> AsyncWrite for OsshClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // After the key exchange this is a plain byte pipe.
        if this.write_state == WriteState::Finished && this.out.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // Respect backpressure before accepting more: a full `out` means the
        // peer is not reading.
        if !this.out.is_empty() {
            match this.flush_out(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }

        if this.write_state == WriteState::SendPreamble {
            this.out.extend_from_slice(&this.preamble);
            this.write_state = WriteState::IdentificationLine;
        }

        if this.write_state != WriteState::Finished {
            this.kex.extend_from_slice(buf);
            this.transform_kex();
        } else {
            // Reached NEWKEYS while buffering earlier writes: send raw.
            this.out.extend_from_slice(buf);
        }

        match this.flush_out(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> OsshClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Write as much of `out` as the inner stream accepts.
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.out.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the carrier accepted no OSSH bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => self.out.advance(written),
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Frame buffered caller bytes into rewritten SSH packets and obfuscate
    /// the result into `out`.
    fn transform_kex(&mut self) {
        let mut plaintext = std::mem::take(&mut self.scratch);
        plaintext.clear();

        if self.write_state == WriteState::IdentificationLine {
            if let Some(end) = find_crlf(&self.kex) {
                plaintext.extend_from_slice(&self.kex.split_to(end + 2));
                self.write_state = WriteState::KexPackets;
            }
        }

        while self.write_state == WriteState::KexPackets {
            if self.kex.len() < 5 {
                break;
            }
            let packet_length =
                u32::from_be_bytes([self.kex[0], self.kex[1], self.kex[2], self.kex[3]]) as usize;
            if !(1..=MAX_PACKET_LENGTH).contains(&packet_length) {
                break;
            }
            let padding_length = self.kex[4] as usize;
            if padding_length >= packet_length {
                break;
            }
            let message_length = 4 + packet_length;
            if self.kex.len() < message_length {
                break;
            }
            let mut packet = self.kex.split_to(message_length);

            let payload_length = packet_length - padding_length - 1;
            let is_new_keys = payload_length > 0 && packet[5] == SSH_MSG_NEWKEYS;

            let extra = self.extra_padding(padding_length);
            let new_packet_length = packet_length + extra;
            packet[..4].copy_from_slice(&(new_packet_length as u32).to_be_bytes());
            packet[4] = (padding_length + extra) as u8;
            plaintext.extend_from_slice(&packet);
            if extra > 0 {
                let start = plaintext.len();
                plaintext.resize(start + extra, 0);
                self.padding.fill(&mut plaintext[start..]);
            }

            if is_new_keys {
                self.write_state = WriteState::Finished;
                self.client_to_server.apply(&mut plaintext);
                self.out.extend_from_slice(&plaintext);
                plaintext.clear();
                // Anything after NEWKEYS is not obfuscated.
                self.out.extend_from_slice(&self.kex);
                self.kex.clear();
                self.scratch = plaintext;
                self.release_kex_state();
                return;
            }
        }

        if !plaintext.is_empty() {
            self.client_to_server.apply(&mut plaintext);
            self.out.extend_from_slice(&plaintext);
        }
        self.scratch = plaintext;
    }

    /// How much extra padding to add to a packet whose own padding is
    /// `padding_length`, in Psiphon's distribution.
    fn extra_padding(&mut self, padding_length: usize) -> usize {
        if self.legacy_padding {
            let possible = (SSH_MAX_PADDING_LENGTH - padding_length) / SSH_PADDING_MULTIPLE;
            if possible == 0 {
                0
            } else {
                self.padding.gen_range(0..possible) * SSH_PADDING_MULTIPLE
            }
        } else {
            let possible = SSH_MAX_PADDING_LENGTH - padding_length;
            if possible == 0 {
                0
            } else {
                self.padding.gen_range(0..=possible)
            }
        }
    }
}

/// The first CRLF in `bytes`, as the index of the `\r`.
fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn apply_rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut cipher = Rc4::new(key);
        let mut out = data.to_vec();
        cipher.apply(&mut out);
        out
    }

    #[test]
    fn rc4_matches_rfc_6229() {
        // Key 0x0102030405: the first 16 keystream bytes, per RFC 6229 §2.
        let keystream = apply_rc4(&[1, 2, 3, 4, 5], &[0u8; 16]);
        assert_eq!(hex::encode(keystream), "b2396305f03dc027ccc3524a0a1118a8");
        // "Key" / "Plaintext" from the original RC4 test vector.
        assert_eq!(
            hex::encode(apply_rc4(b"Key", b"Plaintext")),
            "bbf316e8d940af0ad3"
        );
    }

    #[test]
    fn key_derivation_matches_the_reference() {
        // Values produced with the reference algorithm:
        // SHA1(seed||keyword||direction), 6000 re-hashes, first 16 bytes.
        let seed: Vec<u8> = (0u8..16).collect();
        let key = derive_key(&seed, b"obfuscation-key", CLIENT_TO_SERVER);
        assert_eq!(hex::encode(key), "f9f47b718a70ff9e59920315d7af005c");
        let key = derive_key(&seed, b"obfuscation-key", SERVER_TO_CLIENT);
        assert_eq!(hex::encode(key), "83f1cbb7a38ff209b925528d3f6074a2");
    }

    #[test]
    fn the_seed_message_encrypts_from_the_magic_onwards() {
        let seed = [7u8; SEED_LENGTH];
        let padding = vec![0xAA; 40];
        let (preamble, _, _) = build_preamble(b"kw", seed, &padding);
        assert_eq!(&preamble[..SEED_LENGTH], &seed);
        // The magic value is encrypted, so it must not appear in the clear.
        assert_ne!(
            &preamble[SEED_LENGTH..SEED_LENGTH + 4],
            &MAGIC_VALUE.to_be_bytes()
        );
        assert_eq!(preamble.len(), SEED_LENGTH + 8 + padding.len());

        // A server that derives the same ciphers recovers the fields.
        let mut cipher = Rc4::new(&derive_key(&seed, b"kw", CLIENT_TO_SERVER));
        let mut fixed = preamble[SEED_LENGTH..SEED_LENGTH + 8].to_vec();
        cipher.apply(&mut fixed);
        assert_eq!(
            u32::from_be_bytes(fixed[..4].try_into().unwrap()),
            MAGIC_VALUE
        );
        assert_eq!(
            u32::from_be_bytes(fixed[4..8].try_into().unwrap()) as usize,
            padding.len()
        );
        let mut payload = preamble[SEED_LENGTH + 8..].to_vec();
        cipher.apply(&mut payload);
        assert_eq!(payload, padding);
    }

    #[tokio::test]
    async fn the_layer_round_trips_against_a_mock_server() {
        // A scripted server: it accepts the seed message, deobfuscates the
        // client's version line and two packets, then answers with its own
        // version line, NEWKEYS and trailing plaintext.
        let (client, mut server) = tokio::io::duplex(256 * 1024);

        let server_task = tokio::spawn(async move {
            // Preamble: the seed is clear, the rest is encrypted.
            let mut header = [0u8; SEED_LENGTH + 8];
            server.read_exact(&mut header).await.unwrap();
            let seed: [u8; SEED_LENGTH] = header[..SEED_LENGTH].try_into().unwrap();
            let mut c2s = Rc4::new(&derive_key(&seed, b"kw", CLIENT_TO_SERVER));
            c2s.apply(&mut header[SEED_LENGTH..]);
            assert_eq!(
                u32::from_be_bytes(header[SEED_LENGTH..SEED_LENGTH + 4].try_into().unwrap()),
                MAGIC_VALUE
            );
            let padding_length =
                u32::from_be_bytes(header[SEED_LENGTH + 4..SEED_LENGTH + 8].try_into().unwrap())
                    as usize;
            assert!((MIN_PADDING..=MAX_PADDING).contains(&padding_length));

            // The padding carries the server's PRNG seed; consume it so the
            // cipher positions stay in step.
            let mut padding = vec![0u8; padding_length];
            server.read_exact(&mut padding).await.unwrap();
            c2s.apply(&mut padding);

            let mut server_to_client = Rc4::new(&derive_key(&seed, b"kw", SERVER_TO_CLIENT));

            // Client identification line, one byte at a time.
            let mut line = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                server.read_exact(&mut byte).await.unwrap();
                c2s.apply(&mut byte);
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    break;
                }
            }
            assert_eq!(line, b"SSH-2.0-test\r\n");

            // Two packets: KEXINIT and NEWKEYS, possibly extended with extra
            // padding. The lengths stay consistent with the rewrite.
            let mut payloads = Vec::new();
            for _ in 0..2 {
                let mut prefix = [0u8; 5];
                server.read_exact(&mut prefix).await.unwrap();
                c2s.apply(&mut prefix);
                let packet_length = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
                let padding_length = prefix[4] as usize;
                let mut rest = vec![0u8; 4 + packet_length - 5];
                server.read_exact(&mut rest).await.unwrap();
                c2s.apply(&mut rest);
                let payload_length = packet_length - padding_length - 1;
                payloads.push(rest[..payload_length].to_vec());
            }
            assert_eq!(payloads[0], b"KEXINIT");
            assert_eq!(payloads[1], vec![SSH_MSG_NEWKEYS]);

            // Anything after the client's NEWKEYS is plaintext.
            let mut after = [0u8; 5];
            server.read_exact(&mut after).await.unwrap();
            assert_eq!(&after, b"AFTER");

            // Answer: obfuscated version line and NEWKEYS, then plaintext.
            let mut line = b"SSH-2.0-mock\r\n".to_vec();
            server_to_client.apply(&mut line);
            server.write_all(&line).await.unwrap();

            // packet_length = padding_length byte + payload + padding:
            // 1 + 1 + 1 = 3; total on the wire = 4 + 3.
            let mut newkeys = [0u8; 7];
            newkeys[0..4].copy_from_slice(&3u32.to_be_bytes());
            newkeys[4] = 1;
            newkeys[5] = SSH_MSG_NEWKEYS;
            newkeys[6] = 0;
            server_to_client.apply(&mut newkeys);
            server.write_all(&newkeys).await.unwrap();
            server.write_all(b"TAIL").await.unwrap();
        });

        let mut client = OsshClient::new(client, b"kw");
        client.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        client.write_all(&ssh_packet(b"KEXINIT")).await.unwrap();
        client
            .write_all(&ssh_packet(&[SSH_MSG_NEWKEYS]))
            .await
            .unwrap();
        client.write_all(b"AFTER").await.unwrap();

        // Let the server finish its assertions first, so a mismatch there is
        // reported as itself rather than as the client seeing EOF.
        server_task.await.unwrap();

        // Server identification line.
        let mut line = vec![0u8; b"SSH-2.0-mock\r\n".len()];
        client.read_exact(&mut line).await.unwrap();
        assert_eq!(&line, b"SSH-2.0-mock\r\n");

        // Server NEWKEYS packet.
        let mut packet = [0u8; 7];
        client.read_exact(&mut packet).await.unwrap();

        // Post-NEWKEYS bytes are plaintext.
        let mut tail = [0u8; 4];
        client.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"TAIL");
    }

    fn ssh_packet(payload: &[u8]) -> Vec<u8> {
        let padding = 4;
        let packet_length = payload.len() + padding + 1;
        let mut packet = Vec::new();
        packet.extend_from_slice(&(packet_length as u32).to_be_bytes());
        packet.push(padding as u8);
        packet.extend_from_slice(payload);
        packet.extend_from_slice(&[0u8; 4]);
        packet
    }
}
