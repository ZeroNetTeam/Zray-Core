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
use zero_core::Failure;

use super::record::CONTENT_APPDATA;
use crate::fingerprint::FingerprintProfile;
use crate::tls::TlsParams;

/// How long to keep listening after the handshake. Tickets arrive at once;
/// the rest of the time is for a server that sends its HTTP/2 settings late.
pub const LISTEN: Duration = Duration::from_secs(3);
/// The most records remembered. Sites send two to four; the client side of
/// this stack refuses a long run of empty records, so the list stays short.
pub const MAX_RECORDS: usize = 8;
/// The most first-flight records remembered. A flight is a ServerHello, a
/// ChangeCipherSpec and up to four encrypted messages; a site that sends more
/// is not one whose shape can be copied record for record, and the extra
/// sizes are dropped rather than kept for a decision nothing can make.
pub const MAX_FLIGHT_RECORDS: usize = 8;

/// What a camouflage site's handshake looks like from outside it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteShapes {
    /// Wire sizes of the records the site sent before the client's Finished,
    /// in order: its ServerHello, its compatibility ChangeCipherSpec, then
    /// the records of its encrypted flight.
    pub flight: Vec<u16>,
    /// Wire sizes of the records it sent after the handshake, in order.
    pub post_handshake: Vec<u16>,
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

/// Sits under the TLS client and watches record headers go by in both
/// directions.
#[doc(hidden)]
pub struct Tap<S> {
    inner: S,
    sent: RecordWalker,
    received: RecordWalker,
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
    };
    let tap = Tap {
        inner: io,
        sent: RecordWalker::default(),
        received: RecordWalker::default(),
        finished_sent: false,
        flight: Arc::clone(&taps.flight),
        sizes: Arc::clone(&taps.post_handshake),
        written: Arc::clone(&taps.written),
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
        // Whatever the site says is read only so its records keep arriving.
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
    let take = |list: &Arc<Mutex<Vec<u16>>>| list.lock().unwrap_or_else(|p| p.into_inner()).clone();
    Ok(SiteShapes {
        flight: take(&taps.flight),
        post_handshake: take(&taps.post_handshake),
    })
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
