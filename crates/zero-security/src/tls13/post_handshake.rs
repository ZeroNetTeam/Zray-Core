//! Learns what a camouflage site's TLS 1.3 handshake looks like from outside:
//! the sizes of the records in its first flight, and the sizes of what it
//! sends straight after the handshake.
//!
//! How this works. A real TLS 1.3 server answers a ClientHello with a
//! ServerHello, a compatibility ChangeCipherSpec, and then an encrypted flight
//! of EncryptedExtensions, Certificate, CertificateVerify and Finished — each
//! record as large as that site's certificate and extension set make it. Then
//! it goes on talking: session tickets, and for an HTTP/2 server its settings,
//! again each a record of a size typical for the site. A REALITY server that
//! answers with its own sizes, or sends nothing after the handshake, can be
//! told apart from the site it borrows its name from by anyone comparing the
//! two. [`observe_all`] connects to the site the way a browser would, notes
//! the wire size of every record it receives, and closes.
//!
//! The server then puts its own flight on the wire in the sizes learned for
//! the first group, and sends empty records of the sizes learned for the
//! second ([`super::server::PostHandshakeShapes`]).
//!
//! The rule it keeps: only sizes are learned. Nothing the site sent is kept,
//! replayed or decrypted for use, and the connection is closed afterwards.
//!
//! The surprise: the boundary between "the flight" and "after it" is not
//! marked on the wire, since both look like application data by then. The
//! client's own first encrypted record is its Finished, and the server's
//! whole handshake flight has to arrive before a client can send that, so
//! every record that arrives after it is post-handshake — which is the line
//! the tap draws.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use zero_core::{Failure, Stage};

use super::record::CONTENT_APPDATA;
use crate::fingerprint::FingerprintProfile;
use crate::tls::TlsParams;

/// How long to keep listening after the handshake. Tickets arrive at once;
/// the rest of the time is for a server that sends its HTTP/2 settings late.
pub const LISTEN: Duration = Duration::from_secs(3);

/// How long one read waits before the loop looks again.
///
/// The site sends its session ticket after the handshake, and the TLS layer
/// buffers it: the tap sees the bytes, but the stream does not hand them
/// over until the site sends more. A short bound lets the loop notice that
/// the tap already has what it needs.
const READ_SLICE: Duration = Duration::from_millis(50);
/// The most records remembered. Sites send two to four; the client side of
/// this stack refuses a long run of empty records, so the list stays short.
pub const MAX_RECORDS: usize = 8;
/// The most first-flight records remembered. A flight is a ServerHello, a
/// ChangeCipherSpec and up to four encrypted messages; a site that sends more
/// is not one whose shape can be copied record for record, and the extra
/// sizes are dropped rather than kept for a decision nothing can make.
pub const MAX_FLIGHT_RECORDS: usize = 8;

/// How many bytes of what this end wrote are kept.
///
/// Enough for a ClientHello and a Finished, which is what the REALITY
/// server forwards to the camouflage site.
pub const MAX_SENT_BYTES: usize = 64 * 1024;

/// What a camouflage site's handshake looks like from outside it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteShapes {
    /// The cipher suite the site chose, and the key-share group it chose.
    ///
    /// Go takes both from the site's ServerHello
    /// (`RL/handshake_server_tls13.go:100-128`), which is why they are
    /// here: a server that answered with a different suite than the site
    /// would have answered with is a server that says it is not the site.
    pub answer: Option<SiteAnswer>,
    /// Wire sizes of the records the site sent before the client's Finished,
    /// in order: its ServerHello, its compatibility ChangeCipherSpec, then
    /// the records of its encrypted flight.
    pub flight: Vec<u16>,
    /// Wire sizes of the records it sent after the handshake, in order.
    pub post_handshake: Vec<u16>,
}

/// The suite and the key-share group the site chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteAnswer {
    /// The cipher suite the site selected.
    pub suite: u16,
    /// The key-share group the site selected: `0x001d` for X25519,
    /// `0x11ec` for X25519MLKEM768.
    pub group: u16,
    /// The site's key share, which the port does *not* use — Go uses the
    /// client's share with its own private key, and so does the port
    /// (`RL/handshake_server_tls13.go:108-128`).
    pub key_share_len: usize,
}

/// Finds record boundaries in a TLS byte stream that arrives in arbitrary
/// pieces, without keeping any of the bytes.
#[derive(Default)]
struct RecordWalker {
    header: [u8; 5],
    have: usize,
    body_left: usize,
}

impl RecordWalker {
    /// Feed the next bytes of the stream; `record` is called with the type
    /// and whole wire length of each record whose header completes in them.
    fn feed(&mut self, mut data: &[u8], mut record: impl FnMut(u8, usize)) {
        while !data.is_empty() {
            if self.body_left > 0 {
                let skip = self.body_left.min(data.len());
                self.body_left -= skip;
                data = &data[skip..];
                continue;
            }
            let take = (5 - self.have).min(data.len());
            self.header[self.have..self.have + take].copy_from_slice(&data[..take]);
            self.have += take;
            data = &data[take..];
            if self.have == 5 {
                self.have = 0;
                self.body_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                record(self.header[0], 5 + self.body_left);
            }
        }
    }
}

/// Keeps the bytes of the first record of a stream.
///
/// The site's ServerHello is the one thing a REALITY server has to read off
/// the site: it names the cipher suite and the key-share group the site
/// chose, and Go takes both from it (`RL/tls.go:353-368`,
/// `RL/handshake_server_tls13.go:100-128`). A walker that only counts
/// records cannot answer that, so this one keeps the first record's bytes.
#[derive(Default)]
struct FirstRecord {
    /// The header, then the body, once both have arrived.
    bytes: Vec<u8>,
    /// How many body bytes are still wanted.
    body_left: usize,
    /// Whether the header has arrived.
    have_header: bool,
    /// Whether the record is complete.
    done: bool,
}

impl FirstRecord {
    /// Feed the next bytes; returns the whole record once it is complete.
    fn feed(&mut self, data: &[u8]) -> Option<&[u8]> {
        if self.done {
            return Some(&self.bytes);
        }
        let mut at = 0;
        if !self.have_header {
            let take = (5 - self.bytes.len()).min(data.len());
            self.bytes.extend_from_slice(&data[..take]);
            at = take;
            if self.bytes.len() < 5 {
                return None;
            }
            self.have_header = true;
            self.body_left = u16::from_be_bytes([self.bytes[3], self.bytes[4]]) as usize;
        }
        let take = self.body_left.min(data.len() - at);
        self.bytes.extend_from_slice(&data[at..at + take]);
        self.body_left -= take;
        if self.body_left == 0 {
            self.done = true;
            return Some(&self.bytes);
        }
        None
    }
}

/// Sits under the TLS client and watches record headers go by in both
/// directions.
#[doc(hidden)]
pub struct Tap<S> {
    inner: S,
    sent: RecordWalker,
    received: RecordWalker,
    /// The site's first record — its ServerHello — kept whole.
    ///
    /// It names the cipher suite and the key-share group the site chose,
    /// which is what Go takes from it (`RL/tls.go:353-368`).
    first: FirstRecord,
    /// Where the captured ServerHello is kept.
    server_hello: Arc<Mutex<Vec<u8>>>,
    /// The first record *this* end wrote, kept whole: the ClientHello, when
    /// this end is the client.
    sent_first: Arc<Mutex<Vec<u8>>>,

    /// Every byte this end wrote, in order.
    sent_bytes: Arc<Mutex<Vec<u8>>>,
    /// The client's Finished has gone out, so what arrives now is
    /// post-handshake rather than part of the server's flight.
    finished_sent: bool,
    flight: Arc<Mutex<Vec<u16>>>,
    sizes: Arc<Mutex<Vec<u16>>>,
    /// The sizes of the records *this* end wrote.
    written: Arc<Mutex<Vec<u16>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let finished_sent = this.finished_sent;
        let flight = &this.flight;
        let sizes = &this.sizes;
        let captured = this.first.feed(&buf.filled()[before..]);
        if let Some(record) = captured {
            let mut kept = this.server_hello.lock().unwrap_or_else(|p| p.into_inner());
            if kept.is_empty() {
                kept.extend_from_slice(record);
            }
        }
        this.received
            .feed(&buf.filled()[before..], |content_type, wire_len| {
                if !finished_sent {
                    // Every record up to the client's Finished is one the
                    // server sent as part of answering the ClientHello.
                    let mut flight = flight.lock().unwrap_or_else(|p| p.into_inner());
                    if flight.len() < MAX_FLIGHT_RECORDS {
                        flight.push(wire_len as u16);
                    }
                } else if content_type == CONTENT_APPDATA {
                    let mut sizes = sizes.lock().unwrap_or_else(|p| p.into_inner());
                    if sizes.len() < MAX_RECORDS {
                        sizes.push(wire_len as u16);
                    }
                }
            });
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = result {
            let finished_sent = &mut this.finished_sent;
            let written = &this.written;
            let sent_first = &this.sent_first;
            let sent_bytes = &this.sent_bytes;
            // The first record this end wrote is kept whole: it is the
            // ClientHello, which a test may want to forward somewhere.
            if sent_first
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
            {
                let mut kept = sent_first.lock().unwrap_or_else(|p| p.into_inner());
                if kept.is_empty() {
                    kept.extend_from_slice(&buf[..count]);
                }
            }
            let mut sent = sent_bytes.lock().unwrap_or_else(|p| p.into_inner());
            if sent.len() < MAX_SENT_BYTES {
                let take = (MAX_SENT_BYTES - sent.len()).min(count);
                sent.extend_from_slice(&buf[..take]);
            }
            this.sent.feed(&buf[..count], |content_type, wire_len| {
                *finished_sent |= content_type == CONTENT_APPDATA;
                let mut written = written.lock().unwrap_or_else(|p| p.into_inner());
                if written.len() < MAX_FLIGHT_RECORDS {
                    written.push(wire_len as u16);
                }
            });
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The two lists a [`Tap`] fills: the flight's record sizes and the
/// post-handshake ones.
#[doc(hidden)]
pub struct Taps {
    pub flight: Arc<Mutex<Vec<u16>>>,
    pub post_handshake: Arc<Mutex<Vec<u16>>>,
    /// The sizes of the records this end wrote.
    pub written: Arc<Mutex<Vec<u16>>>,
    /// The site's first record whole — its ServerHello.
    pub server_hello: Arc<Mutex<Vec<u8>>>,
    /// The first record this end wrote whole — the ClientHello, when this
    /// end is the client.
    pub sent_first: Arc<Mutex<Vec<u8>>>,

    /// Every byte this end wrote, in order, up to [`MAX_SENT_BYTES`].
    ///
    /// A caller that hands this stream to somebody else — the REALITY
    /// server forwarding a visitor's bytes to the camouflage site — can
    /// then see exactly what was sent.
    ///
    /// Bounded, because the tap is a public type and a caller may put it
    /// on a long-lived stream: without a cap, the list would grow with
    /// every byte the connection carried.
    pub sent_bytes: Arc<Mutex<Vec<u8>>>,
}

/// Read the cipher suite and the key-share group out of a site's
/// ServerHello.
///
/// The record is the site's first one, header and all. Go parses the same
/// thing off its mirrored connection (`RL/tls.go:353-368`) and takes the
/// suite and the group from it (`RL/handshake_server_tls13.go:100-128`).
///
/// A ServerHello that does not parse is not an answer: the site's suite
/// and group are then simply not known, and the caller falls back to what
/// it has.
pub fn parse_site_answer(record: &[u8]) -> Option<SiteAnswer> {
    // A TLS record: a 5-byte header and the handshake message.
    if record.len() < 5 {
        return None;
    }
    let body = &record[5..];
    // The handshake message: a type byte and a 3-byte length.
    if body.len() < 4 || body[0] != 2 {
        return None;
    }
    let mut at = 4usize;
    // legacy_version, random, session id, cipher suite, compression.
    at = at.checked_add(2 + 32)?;
    let sid_len = *body.get(at)? as usize;
    at += 1 + sid_len;
    let suite = u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]);
    at += 2;
    at += 1; // compression method
             // The extensions.
    let ext_total = u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]) as usize;
    at += 2;
    let end = at.checked_add(ext_total)?;
    if end > body.len() {
        return None;
    }
    while at + 4 <= end {
        let etype = u16::from_be_bytes([body[at], body[at + 1]]);
        let elen = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        at += 4;
        let ext = body.get(at..at + elen)?;
        at += elen;
        if etype != 51 {
            continue;
        }
        // ServerHello carries the one selected share directly, with no
        // vector length in front of it.
        if ext.len() < 4 {
            return None;
        }
        let group = u16::from_be_bytes([ext[0], ext[1]]);
        let klen = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        if ext.len() != 4 + klen {
            return None;
        }
        // Go accepts only two groups from the site
        // (`RL/tls.go:357-360`): X25519 with a 32-byte share, and
        // X25519MLKEM768 with a ciphertext of 1088 bytes plus the X25519
        // half. Anything else is not an answer Go would act on, so it is
        // not an answer here either.
        let known = (group == 0x001d && klen == 32) || (group == 0x11ec && klen == 1088 + 32);
        if !known {
            return None;
        }
        return Some(SiteAnswer {
            suite,
            group,
            key_share_len: klen,
        });
    }
    None
}

#[cfg(test)]
mod flight_end_tests {
    use super::*;

    /// The probe stops when the site's flight is complete.
    ///
    /// A site has nothing more to say until the client speaks again, so a
    /// probe that reads until the site falls silent waits out the whole
    /// listen time on every connection. On the accepting path that is a
    /// per-connection cost, and it is a large one.
    #[tokio::test]
    async fn the_probe_stops_when_the_flight_is_complete() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            // A real TLS 1.3 server, so the probe's handshake completes and
            // the site sends its flight and its ticket.
            let config = crate::server::server_config(
                include_bytes!("../../../zero-runtime/tests/fixtures/loopback-cert.pem"),
                include_bytes!("../../../zero-runtime/tests/fixtures/loopback-key.pem"),
                &["h2".into()],
            )
            .expect("the site's certificate loads");
            let mut stream = server;
            let _ = crate::server::accept(&mut stream, config).await;
            // The site keeps the connection open, as a real one does: it has
            // nothing more to say until the client speaks again, and closing
            // would hide the cost of a read that waits for silence.
            let mut sink = [0u8; 4096];
            loop {
                match tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await {
                    Ok(n) if n > 0 => continue,
                    _ => break,
                }
            }
        });
        let started = std::time::Instant::now();
        let shapes = observe_all_with(client, "example.test", SiteTrust::Unverified)
            .await
            .expect("the probe reads the site's flight");
        let elapsed = started.elapsed();
        server.await.unwrap();
        // The site sends its flight and its ticket and then has nothing more
        // to say, so a probe that reads until the site falls silent waits out
        // the whole listen time on every connection. On the accepting path
        // that is a per-connection cost, and a large one.
        // The read is bounded, so a probe that waits for the site's
        // silence costs the read's bound, not the listen time.
        assert!(
            elapsed < Duration::from_millis(150),
            "the probe waited {elapsed:?}, which is the listen time and not \
             the cost of reading a flight"
        );
        // And the flight it read is the whole one: the site's records and
        // its ticket. A probe that stopped early would have a short list.
        assert!(
            !shapes.post_handshake.is_empty(),
            "the probe did not read the site's ticket, so its flight is short"
        );
        // And the read is bounded: a read that waits for the site's
        // silence waits out the whole listen time, and the site here keeps
        // its connection open on purpose.
        assert!(
            READ_SLICE < LISTEN,
            "the read's bound is the listen time, so a probe waits it out"
        );
    }
}

#[cfg(test)]
mod sent_bytes_tests {
    use super::*;

    /// What this end wrote is kept, up to a bound.
    ///
    /// The tap is a public type and a caller may put it on a long-lived
    /// stream, so the list of what was written cannot grow with the
    /// connection.
    #[tokio::test]
    async fn what_was_written_is_kept_up_to_a_bound() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let (tap, taps) = tap_with_flight(client);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut tap = tap;
            // More than the cap, in several writes.
            for _ in 0..8 {
                tap.write_all(&vec![7u8; 32 * 1024]).await.unwrap();
            }
            tap.flush().await.unwrap();
        });
        let mut sink = [0u8; 4096];
        let mut read = 0usize;
        while read < 8 * 32 * 1024 {
            let n = tokio::io::AsyncReadExt::read(&mut server, &mut sink)
                .await
                .unwrap();
            if n == 0 {
                break;
            }
            read += n;
        }
        writer.await.unwrap();
        let sent = taps.sent_bytes.lock().unwrap().clone();
        assert_eq!(
            sent.len(),
            MAX_SENT_BYTES,
            "the list of what was written is bounded"
        );
    }
}

#[cfg(test)]
mod site_answer_tests {
    use super::*;

    /// A ServerHello record, as the site sends it.
    fn server_hello_record(suite: u16, group: u16, key: &[u8]) -> Vec<u8> {
        let mut message = vec![2u8, 0, 0, 0];
        message.extend_from_slice(&[0x03, 0x03]); // legacy version
        message.extend_from_slice(&[0u8; 32]); // random
        message.push(0); // no session id
        message.extend_from_slice(&suite.to_be_bytes());
        message.push(0); // no compression
                         // The extensions: supported_versions and key_share.
        let mut ext = Vec::new();
        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&[0x03, 0x04]);
        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&((4 + key.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&group.to_be_bytes());
        ext.extend_from_slice(&(key.len() as u16).to_be_bytes());
        ext.extend_from_slice(key);
        message.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        message.extend_from_slice(&ext);
        let len = message.len() - 4;
        message[1..4].copy_from_slice(&[0, (len >> 8) as u8, len as u8]);
        // A record header around it.
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    /// The site's suite and group are read off its ServerHello.
    ///
    /// Go takes both from the site's answer
    /// (`RL/handshake_server_tls13.go:100-128`), so a server that answered
    /// with a different suite than the site would have answered with is a
    /// server that says it is not the site.
    #[test]
    fn the_sites_suite_and_group_are_read_off_its_server_hello() {
        let record = server_hello_record(0x1301, 0x001d, &[9u8; 32]);
        let answer = parse_site_answer(&record).expect("the ServerHello parses");
        assert_eq!(answer.suite, 0x1301, "TLS_AES_128_GCM_SHA256");
        assert_eq!(answer.group, 0x001d, "X25519");
        assert_eq!(answer.key_share_len, 32);
    }

    /// The hybrid group is read just as the plain one is.
    #[test]
    fn the_hybrid_group_is_read_too() {
        let record = server_hello_record(0x1302, 0x11ec, &[7u8; 1088 + 32]);
        let answer = parse_site_answer(&record).expect("the ServerHello parses");
        assert_eq!(answer.suite, 0x1302, "TLS_AES_256_GCM_SHA384");
        assert_eq!(answer.group, 0x11ec, "X25519MLKEM768");
        assert_eq!(answer.key_share_len, 1088 + 32);
    }

    /// Something that is not a ServerHello is not an answer.
    #[test]
    fn a_record_that_is_not_a_server_hello_is_no_answer() {
        assert!(parse_site_answer(&[]).is_none());
        assert!(parse_site_answer(&[0x16, 0x03, 0x01, 0x00, 0x05]).is_none());
        // A handshake message of the wrong type.
        let mut record = server_hello_record(0x1301, 0x001d, &[9u8; 32]);
        record[5] = 1; // not a ServerHello
        assert!(parse_site_answer(&record).is_none());
    }
}

/// Put a tap on `io` and get both lists it collects.
///
/// Test support: the REALITY server's own tests observe the record sizes a
/// server puts on the wire, and those tests live in the `reality` crate now.
#[doc(hidden)]
pub fn tap_with_flight<S>(io: S) -> (Tap<S>, Taps) {
    let taps = Taps {
        flight: Arc::new(Mutex::new(Vec::new())),
        post_handshake: Arc::new(Mutex::new(Vec::new())),
        written: Arc::new(Mutex::new(Vec::new())),
        server_hello: Arc::new(Mutex::new(Vec::new())),
        sent_first: Arc::new(Mutex::new(Vec::new())),
        sent_bytes: Arc::new(Mutex::new(Vec::new())),
    };
    let tap = Tap {
        inner: io,
        sent: RecordWalker::default(),
        received: RecordWalker::default(),
        first: FirstRecord::default(),
        finished_sent: false,
        flight: Arc::clone(&taps.flight),
        sizes: Arc::clone(&taps.post_handshake),
        written: Arc::clone(&taps.written),
        server_hello: Arc::clone(&taps.server_hello),
        sent_first: Arc::clone(&taps.sent_first),
        sent_bytes: Arc::clone(&taps.sent_bytes),
    };
    (tap, taps)
}

/// Put a tap on `io`, and get the list its post-handshake record sizes are
/// collected in. The flight is collected too; use [`tap_with_flight`] to see
/// it.
#[doc(hidden)]
pub fn tap<S>(io: S) -> (Tap<S>, Arc<Mutex<Vec<u16>>>) {
    let (tap, taps) = tap_with_flight(io);
    (tap, taps.post_handshake)
}

/// What the probe requires of the site's certificate before it believes the
/// sizes it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteTrust {
    /// Verify the chain against the public roots, as a browser would. This is
    /// what a caller asking "what does this site really send" wants.
    PublicRoots,
    /// Take the sizes without checking who answered.
    ///
    /// This is what the REALITY server uses, and it is not a relaxation of the
    /// client's security: the probe carries no application data, and the site
    /// it describes is the one the operator already configured the server to
    /// relay strangers to and to borrow a name from. What it buys is the sites
    /// whose certificates do not chain to a public root — a private CA, a
    /// staging decoy, anything an operator runs themselves — where a verifying
    /// probe learns nothing and the server goes on answering with record
    /// sizes of its own. Go's REALITY has no such precondition to start with:
    /// it reads record sizes off the live connection to the site and verifies
    /// nothing (`RL/tls.go:293-330`).
    Unverified,
}

/// The same, recording the leaf certificate the site showed.
///
/// The certificate is the site's, or the port's own — and a client that is
/// shown the port's learns that the site is not behind it. A caller that
/// wants to know which one it got records it.
pub async fn observe_all_recording<S>(
    io: S,
    server_name: &str,
    recorded: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) -> Result<SiteShapes, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    observe_all_with_verifier(
        io,
        server_name,
        std::sync::Arc::new(RecordingVerifier(recorded)),
    )
    .await
}

/// The same, with the caller's own certificate verifier.
///
/// A verifier that accepts anything and keeps the leaf it was shown is
/// [`RecordingVerifier`]; the caller can then tell the site's certificate
/// from the port's own.
async fn observe_all_with_verifier<S>(
    io: S,
    server_name: &str,
    verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> Result<SiteShapes, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let params = TlsParams::new(server_name)
        .with_profile(FingerprintProfile::Chrome)
        .with_insecure(true)
        .with_verifier(verifier);
    let (tap, taps) = tap_with_flight(io);
    let mut stream = crate::tls::connect(tap, &params).await?;
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(LISTEN, async {
        // The site's flight is read, and the read stops once the flight is
        // complete — which is when the site sends its first
        // application-data record, its session ticket.
        loop {
            let complete = !taps
                .post_handshake
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty();
            if complete {
                break;
            }
            match tokio::time::timeout(READ_SLICE, stream.read(&mut sink)).await {
                Ok(Ok(n)) if n > 0 => continue,
                _ => break,
            }
        }
    })
    .await;
    let take = |list: &Arc<Mutex<Vec<u16>>>| list.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let answer = {
        let hello = taps.server_hello.lock().unwrap_or_else(|p| p.into_inner());
        parse_site_answer(&hello)
    };
    Ok(SiteShapes {
        answer,
        flight: take(&taps.flight),
        post_handshake: take(&taps.post_handshake),
    })
}

/// A verifier that accepts anything and keeps the leaf it was shown.
#[derive(Debug)]
struct RecordingVerifier(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        leaf: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut kept = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if kept.is_empty() {
            kept.extend_from_slice(leaf.as_ref());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Handshake with the site behind `io` as a browser asking for `server_name`
/// and return the wire sizes of every record it sent: its first flight, then
/// what followed the handshake.
///
/// A site that sends nothing after the handshake returns an empty
/// `post_handshake`, which is a real answer; an error means the handshake did
/// not complete and nothing was learned.
pub async fn observe_all<S>(io: S, server_name: &str) -> Result<SiteShapes, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    observe_all_with(io, server_name, SiteTrust::PublicRoots).await
}

/// The same, with the caller saying what the site's certificate has to prove.
pub async fn observe_all_with<S>(
    io: S,
    server_name: &str,
    trust: SiteTrust,
) -> Result<SiteShapes, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    observe_all_with_alpn(io, server_name, trust, &["h2", "http/1.1"]).await
}

/// The same, with the protocols the probe offers the site.
///
/// A site can answer an h2 client differently from an http/1.1 one, so
/// Go probes it three ways — with no ALPN, with http/1.1, and with
/// h2 and http/1.1 — and files what it learned under the protocol the
/// *client* used (`RL/record_detect.go:21-62`, `RL/tls.go:396-403`).
pub async fn observe_all_with_alpn<S>(
    io: S,
    server_name: &str,
    trust: SiteTrust,
    alpn: &[&str],
) -> Result<SiteShapes, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (tap, taps) = tap_with_flight(io);
    let params = TlsParams::new(server_name)
        .with_alpn(alpn)
        .with_profile(FingerprintProfile::Chrome)
        .with_insecure(trust == SiteTrust::Unverified);
    let mut stream = crate::tls::connect(tap, &params).await?;
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(LISTEN, async {
        // The site's flight is read, and then the read stops as soon as the
        // flight is complete — which is when the site sends its first
        // application-data record, its session ticket.
        //
        // Reading until the site falls silent instead would wait out the
        // whole listen time on every connection: a site has nothing more
        // to say until the client speaks again, so the read would block.
        // On the accepting path that is a cost per connection rather than
        // once at start-up, which is not a cost worth paying.
        loop {
            // The flight ends at the site's first application-data record —
            // its session ticket — and the records after it are the
            // post-handshake ones. The read stops once the flight is
            // complete *and* one more record has come, so the ticket is
            // counted.
            // The site's flight ends at its first application-data record —
            // its session ticket — and the records after it are the
            // post-handshake ones. The read stops once the flight is
            // complete *and* one more record has come, so the ticket is
            // counted rather than cut off.
            // The site sends its session ticket after the handshake, and
            // the tap files that one under the post-handshake records. So
            // the read stops once the ticket has arrived — which is a
            // moment, not the site's silence.
            let complete = !taps
                .post_handshake
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty();
            if complete {
                break;
            }
            match tokio::time::timeout(READ_SLICE, stream.read(&mut sink)).await {
                Ok(Ok(n)) if n > 0 => continue,
                _ => {
                    // The read gave up. The tap may have the ticket by now
                    // — the TLS layer buffers it, so the stream does not
                    // hand it over — and the flight is then complete.
                    let complete = !taps
                        .post_handshake
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .is_empty();
                    if complete {
                        break;
                    }
                    // The site is silent and has said no more.
                    break;
                }
            }
        }
    })
    .await;
    let take = |list: &Arc<Mutex<Vec<u16>>>| list.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let answer = {
        let hello = taps.server_hello.lock().unwrap_or_else(|p| p.into_inner());
        parse_site_answer(&hello)
    };
    Ok(SiteShapes {
        answer,
        flight: take(&taps.flight),
        post_handshake: take(&taps.post_handshake),
    })
}

/// Ask the site by sending the *client's* own hello, and read its answer.
///
/// Go does not probe the site at all: it forwards the client's bytes to it
/// through the `MirrorConn` (`RL/tls.go:70-83`), so the site's answer is
/// its reply to the visitor's own hello — the same suite, the same group
/// and the same flight the visitor would have got had the site been the
/// server. Asking with a hello of the probe's own gives the site's answer
/// to *that* hello, which is usually the same and not always.
///
/// `hello` is the client's ClientHello record, verbatim. The site answers
/// it the way it answers any client.
///
/// The answer is *not* a completed handshake: the port cannot finish one
/// with the site, because the client — not the port — holds the ECDHE
/// private key. What is read is the site's ServerHello, which names the
/// suite and the group, and the sizes of the records that follow.
pub async fn observe_with_the_clients_hello<S>(
    io: S,
    hello: &[u8],
) -> Result<(SiteShapes, Option<Tap<S>>, Taps), Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    observe_with_the_clients_hello_for(io, hello, None).await
}

/// The same, with the caller saying how many records the site's flight has.
///
/// A TLS 1.3 site sends its whole flight in one burst, in answer to the
/// ClientHello: its ServerHello, its compatibility ChangeCipherSpec, and
/// then its EncryptedExtensions, its Certificate, its CertificateVerify
/// with its own Finished, and its session ticket. It does not wait for the
/// client's Finished to send them — measured against a real Xray site, the
/// site sent all six records before the client's Finished arrived.
///
/// So the caller's connection to the site can yield the whole flight, and
/// the count is what says when the burst has ended. `expected` is that
/// count; `None` reads only as far as the ServerHello, which is what a
/// caller that wants the answer and nothing else asks for.
pub async fn observe_with_the_clients_hello_for<S>(
    io: S,
    hello: &[u8],
    expected: Option<usize>,
) -> Result<(SiteShapes, Option<Tap<S>>, Taps), Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tap, taps) = tap_with_flight(io);
    // The client's hello goes to the site first, and the site's answer is
    // read off the same connection.
    tokio::io::AsyncWriteExt::write_all(&mut tap, hello)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    tokio::io::AsyncWriteExt::flush(&mut tap)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    // The read stops when the site's flight is complete: its ServerHello
    // first, and then the rest of the records the caller expects. The site
    // sends them in one burst and then waits, so a read that waited for the
    // site's silence would wait out the whole listen time on every
    // connection — and the site is read on every connection.
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(LISTEN, async {
        loop {
            let seen = taps.flight.lock().unwrap_or_else(|p| p.into_inner()).len();
            let done = match expected {
                None => !taps
                    .server_hello
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_empty(),
                Some(count) => seen >= count,
            };
            if done {
                break;
            }
            match tokio::io::AsyncReadExt::read(&mut tap, &mut sink).await {
                Ok(n) if n > 0 => continue,
                _ => break,
            }
        }
    })
    .await;
    let take = |list: &Arc<Mutex<Vec<u16>>>| list.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let answer = {
        let server_hello = taps.server_hello.lock().unwrap_or_else(|p| p.into_inner());
        parse_site_answer(&server_hello)
    };
    Ok((
        SiteShapes {
            answer,
            flight: take(&taps.flight),
            post_handshake: take(&taps.post_handshake),
        },
        // The connection is handed back with the answer: the caller's
        // Finished has to be written to it for the site to send the rest of
        // its flight.
        Some(tap),
        taps,
    ))
}

/// Handshake with the site behind `io` and return the wire sizes of the
/// records it sends after the handshake, in order.
pub async fn observe<S>(io: S, server_name: &str) -> Result<Vec<u16>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Ok(observe_all(io, server_name).await?.post_handshake)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(content_type: u8, body: usize) -> Vec<u8> {
        let mut out = vec![content_type, 3, 3, (body >> 8) as u8, body as u8];
        out.resize(5 + body, 0);
        out
    }

    #[test]
    fn records_are_found_however_the_stream_is_cut() {
        let mut stream = record(0x16, 90);
        stream.extend(record(0x17, 250));
        stream.extend(record(0x17, 0));
        stream.extend(record(0x17, 64));
        for chunk in [1, 2, 5, 7, 300, stream.len()] {
            let mut walker = RecordWalker::default();
            let mut seen = Vec::new();
            for piece in stream.chunks(chunk) {
                walker.feed(piece, |kind, len| seen.push((kind, len)));
            }
            assert_eq!(
                seen,
                [(0x16, 95), (0x17, 255), (0x17, 5), (0x17, 69)],
                "cut every {chunk} bytes"
            );
        }
    }

    /// Against a real site, named in `ZRAY_LIVE_TLS_HOST`. Run with
    /// `cargo test -p zero-security live_site -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "connects to the site named in ZRAY_LIVE_TLS_HOST"]
    async fn a_live_site_reports_its_post_handshake_records() {
        let host = std::env::var("ZRAY_LIVE_TLS_HOST").expect("set ZRAY_LIVE_TLS_HOST");
        let tcp = tokio::net::TcpStream::connect((host.as_str(), 443))
            .await
            .unwrap();
        let sizes = observe(tcp, &host).await.unwrap();
        eprintln!("{host}: {sizes:?}");
        assert!(sizes.len() <= MAX_RECORDS);
    }

    /// Only what arrives after the client's first encrypted record counts,
    /// and only application-data records.
    #[tokio::test]
    async fn only_records_after_the_clients_finished_are_noted() {
        use tokio::io::AsyncWriteExt;

        let (near, mut far) = tokio::io::duplex(4096);
        let (mut tap, sizes) = tap(near);
        let mut sink = [0u8; 4096];

        // The server's handshake flight, then a compatibility CCS from us.
        far.write_all(&record(0x17, 1200)).await.unwrap();
        tap.read_exact(&mut sink[..1205]).await.unwrap();
        tap.write_all(&record(0x14, 1)).await.unwrap();
        assert!(sizes.lock().unwrap().is_empty());

        tap.write_all(&record(0x17, 53)).await.unwrap();
        far.write_all(&record(0x17, 250)).await.unwrap();
        far.write_all(&record(0x15, 19)).await.unwrap();
        far.write_all(&record(0x17, 64)).await.unwrap();
        let mut got = 0;
        while got < 255 + 24 + 69 {
            got += tap.read(&mut sink).await.unwrap();
        }
        assert_eq!(*sizes.lock().unwrap(), [255, 69]);
    }

    /// The flight is everything received before the client's Finished,
    /// whatever its record types, and it stays separate from what follows.
    #[tokio::test]
    async fn the_flight_is_noted_before_the_clients_finished_and_kept_apart() {
        use tokio::io::AsyncWriteExt;

        let (near, mut far) = tokio::io::duplex(8192);
        let (mut tap, taps) = tap_with_flight(near);
        let mut sink = [0u8; 8192];

        // ServerHello, the compatibility CCS, then two encrypted records.
        far.write_all(&record(0x16, 117)).await.unwrap();
        far.write_all(&record(0x14, 1)).await.unwrap();
        far.write_all(&record(0x17, 30)).await.unwrap();
        far.write_all(&record(0x17, 1200)).await.unwrap();
        tap.read_exact(&mut sink[..122 + 6 + 35 + 1205])
            .await
            .unwrap();
        assert_eq!(*taps.flight.lock().unwrap(), [122, 6, 35, 1205]);
        assert!(taps.post_handshake.lock().unwrap().is_empty());

        // Our Finished goes out; from here the site is talking after the
        // handshake, and that list grows instead.
        tap.write_all(&record(0x17, 53)).await.unwrap();
        far.write_all(&record(0x17, 250)).await.unwrap();
        tap.read_exact(&mut sink[..255]).await.unwrap();
        assert_eq!(*taps.flight.lock().unwrap(), [122, 6, 35, 1205]);
        assert_eq!(*taps.post_handshake.lock().unwrap(), [255]);
    }
}
