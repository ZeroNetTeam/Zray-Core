//! Asks a camouflage site how many useless records it tolerates.
//!
//! A TLS 1.3 server counts the records that advance nothing — a
//! compatibility ChangeCipherSpec, an empty application-data record, a
//! warning alert — and once the run of them passes its limit it answers with
//! an alert and closes (`RL/conn.go:827-839`). The limit is the site's own,
//! and a REALITY server that answers a client differently from the site it
//! borrows its name from is a REALITY server that can be told apart.
//!
//! So the limit is learned rather than assumed. Go learns it by writing a
//! run of compatibility ChangeCipherSpec records at the site and watching
//! for the alert (`RL/record_detect.go:137-185`, `CCSDetectConn`): the
//! records go out in the middle of the handshake, where the site counts
//! them, and the run that draws the alert says the limit.
//!
//! The records have to go in the middle of the handshake, not after it. A
//! ChangeCipherSpec that arrives after the handshake is a protocol error
//! rather than a counted record (`RL/conn.go:796-798`), so a probe that sent
//! them late would learn nothing. Go puts them there by intercepting the
//! client's own compatibility record; this probe puts them there by
//! intercepting the client's first *encrypted* record, which is the same
//! point in the handshake: the client has read the server's flight and is
//! about to send its Finished.
//!
//! The runs are the ones Go sends, and they are cumulative: two records, then
//! fifteen more, then sixteen more (`RL/record_detect.go:174-186`). A site
//! that tolerates thirty-two useless records answers the third run and not
//! the second, so the run that draws the alert is what names the limit.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::record::{CONTENT_APPDATA, CONTENT_CCS};

/// The compatibility ChangeCipherSpec record a TLS 1.3 client sends for
/// middleboxes: `0x14 0x03 0x03 0x00 0x01 0x01` (`RL/record_detect.go:137`).
const CCS_MESSAGE: [u8; 6] = [CONTENT_CCS, 0x03, 0x03, 0x00, 0x01, 0x01];

/// The runs Go sends, and the limit each one means.
///
/// Go sends two records and waits; if the site has not objected, fifteen
/// more, and waits; if it still has not, sixteen more. The limits are what a
/// site tolerating that many records would show: a site that tolerates one
/// useless record objects at the second, one that tolerates sixteen objects
/// at the seventeenth, and one that tolerates thirty-two at the
/// thirty-third. A site that objects at none of them tolerates all of them.
pub const RUNS: [(usize, u64); 3] = [(2, 1), (17, 16), (33, 32)];

/// The limit a site that tolerates every run shows.
pub const UNLIMITED: u64 = u64::MAX;

/// How long a site is given to answer a run. Go waits a second
/// (`RL/record_detect.go:157`), and a second is long enough for a site that
/// is going to answer at all.
pub const WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// A stream that writes a run of compatibility ChangeCipherSpec records just
/// before the client's first encrypted record.
///
/// The records go out at the point the client's Finished would, which is
/// where the site counts them.
pub struct InjectCcs<S> {
    inner: S,
    /// The records still to be written.
    pending: Vec<u8>,
    /// Whether the records have gone out. Once they have, the stream is the
    /// plain stream it wraps.
    injected: bool,
}

impl<S> InjectCcs<S> {
    /// Wrap `inner`, so that `count` compatibility records go out just
    /// before the client's first encrypted record.
    pub fn new(inner: S, count: usize) -> Self {
        let mut pending = Vec::with_capacity(count * CCS_MESSAGE.len());
        for _ in 0..count {
            pending.extend_from_slice(&CCS_MESSAGE);
        }
        Self {
            inner,
            pending,
            injected: false,
        }
    }

    /// Whether the records have gone out.
    pub fn injected(&self) -> bool {
        self.injected
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for InjectCcs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for InjectCcs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // The client's first encrypted record is the one that carries its
        // Finished. Nothing before it is protected, so a record of another
        // kind is the handshake's own flight and must not be disturbed.
        let is_encrypted = buf.len() >= 3 && buf[0] == CONTENT_APPDATA && buf[1] == 0x03;
        if !this.injected && is_encrypted && !this.pending.is_empty() {
            let records = std::mem::take(&mut this.pending);
            match Pin::new(&mut this.inner).poll_write(cx, &records) {
                Poll::Ready(Ok(written)) if written == records.len() => {
                    this.injected = true;
                }
                Poll::Ready(Ok(written)) => {
                    // A short write means the stream took part of the run.
                    // The rest goes out with the next attempt, and the client
                    // is not told until then.
                    this.pending = records[written..].to_vec();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    this.pending = records;
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read what the site says about a run of useless records.
///
/// `true` means the site objected: it answered with an alert, or it closed
/// the connection, which is what a site that has run out of patience does.
/// Go treats both the same way (`RL/record_detect.go:143-152`: the reader
/// stops on an alert, and on an error the same flag is set).
pub async fn site_objects<S>(stream: &mut S) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut sink = [0u8; 512];
    let mut objected = false;
    let _ = tokio::time::timeout(WAIT, async {
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => {
                    objected = true;
                    break;
                }
                Ok(n) => {
                    // An alert record is `0x15` at the head of the record.
                    if sink[..n].first() == Some(&0x15) {
                        objected = true;
                        break;
                    }
                }
            }
        }
    })
    .await;
    objected
}

/// Learn how many useless records the site tolerates.
///
/// The site is asked with the runs Go sends, and the run that draws the
/// site's objection names the limit. `None` means the question could not be
/// answered — the site could not be reached, or its answer was not one the
/// probe could read — and the caller should keep the default rather than
/// guess.
///
/// `connect` opens a connection to the site. It is called once per run,
/// because a run is a whole handshake: the records go out in the middle of
/// it, and a handshake that the site ended cannot carry the next run.
///
/// The probe asks the site as a browser would, so the answer describes the
/// site as a client would meet it. The site's certificate is not verified:
/// the probe carries no application data, and the site is the one the
/// operator chose as the camouflage, so requiring a public chain would leave
/// every private-CA decoy unmeasured — which is the same reason the
/// record-shape probe does not verify either.
pub async fn probe_budget<C, Fut, S>(mut connect: C, server_name: &str) -> Option<u64>
where
    C: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<S, zero_core::Failure>>,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let params = crate::tls::TlsParams::new(server_name)
        .with_alpn(&["h2", "http/1.1"])
        .with_profile(crate::fingerprint::FingerprintProfile::Chrome)
        .with_insecure(true);
    for (count, budget) in RUNS {
        let io = connect().await.ok()?;
        let wrapped = InjectCcs::new(io, count);
        // The handshake is what puts the records in the middle of it, where
        // the site counts them. A site that objects ends the handshake, and
        // that is the answer.
        match crate::tls::connect(wrapped, &params).await {
            Ok(_) => continue,
            Err(_) => return Some(budget),
        }
    }
    Some(UNLIMITED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A site that objects after `tolerates` useless records, as Go's server
    /// does: it counts the records that advance nothing and answers with an
    /// alert once the run passes its limit (`RL/conn.go:827-839`).
    #[tokio::test]
    async fn a_site_that_objects_is_told_apart_from_one_that_does_not() {
        let (client, mut site) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // The site's alert, once the run passes its limit.
            site.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02])
                .await
                .ok();
        });
        let mut stream = client;
        assert!(
            site_objects(&mut stream).await,
            "a site that answers with an alert must be read as objecting"
        );
    }

    /// A site that says nothing is not objecting.
    #[tokio::test]
    async fn a_silent_site_is_not_read_as_objecting() {
        let (client, _site) = tokio::io::duplex(4096);
        let mut stream = client;
        assert!(
            !site_objects(&mut stream).await,
            "a site that says nothing must not be read as objecting"
        );
    }

    /// The records go out before the client's first encrypted record, and
    /// nowhere else.
    #[tokio::test]
    async fn the_records_go_out_before_the_clients_first_encrypted_record() {
        let (client, mut site) = tokio::io::duplex(4096);
        let mut wrapped = InjectCcs::new(client, 2);
        // The client's own flight: a handshake record, which must pass
        // through untouched.
        wrapped
            .write_all(&[0x16, 0x03, 0x01, 0x00, 0x01, 0x00])
            .await
            .unwrap();
        // Then its first encrypted record, which is where the records go.
        wrapped
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00])
            .await
            .unwrap();
        drop(wrapped);

        let mut seen = Vec::new();
        site.read_to_end(&mut seen).await.unwrap();
        assert_eq!(
            seen,
            vec![
                // The handshake record, untouched.
                0x16, 0x03, 0x01, 0x00, 0x01, 0x00, //
                // Then the two compatibility records.
                0x14, 0x03, 0x03, 0x00, 0x01, 0x01, //
                0x14, 0x03, 0x03, 0x00, 0x01, 0x01, //
                // Then the encrypted record.
                0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
            ],
            "the records must go out between the flight and the first encrypted record"
        );
    }

    /// The run a site objects at is the one that names the limit, and the
    /// runs are cumulative.
    #[test]
    fn the_runs_are_the_ones_go_sends() {
        assert_eq!(RUNS[0], (2, 1));
        assert_eq!(RUNS[1], (17, 16));
        assert_eq!(RUNS[2], (33, 32));
    }
}
