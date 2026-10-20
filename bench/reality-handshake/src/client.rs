//! The one client every server in the table is measured with: Zray's own
//! REALITY client.
//!
//! The same client for both sides is the whole reason the comparison means
//! anything. Zray's client is the one under this project's control, it speaks
//! the same ClientHello to either server, and — unlike the Go client — it can
//! be driven in-process, one handshake per connection, with its bytes counted
//! on the way past.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use zero_core::{Address, Destination};
use zero_protocol::vless;

/// What one handshake put on the wire, from the client's side.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bytes {
    pub sent: u64,
    pub read: u64,
}

/// A socket that counts the bytes crossing it.
///
/// Two uses: the report can say what a handshake costs on the wire, and the
/// harness can check that both servers answered with the same shape of flight
/// rather than comparing two different amounts of work.
pub struct CountingStream {
    inner: TcpStream,
    sent: Arc<AtomicU64>,
    read: Arc<AtomicU64>,
}

impl CountingStream {
    fn new(inner: TcpStream) -> (Self, Arc<AtomicU64>, Arc<AtomicU64>) {
        let sent = Arc::new(AtomicU64::new(0));
        let read = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                sent: Arc::clone(&sent),
                read: Arc::clone(&read),
            },
            sent,
            read,
        )
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let outcome = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &outcome {
            let read = buf.filled().len() - before;
            self.read.fetch_add(read as u64, Ordering::Relaxed);
        }
        outcome
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let outcome = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(wrote)) = &outcome {
            self.sent.fetch_add(*wrote as u64, Ordering::Relaxed);
        }
        outcome
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A client pointed at one server, ready to be run against it any number of
/// times.
pub struct Client {
    pub address: SocketAddr,
    pub params: zero_security::RealityParams,
}

impl Client {
    pub fn new(address: SocketAddr, params: zero_security::RealityParams) -> Self {
        Self { address, params }
    }

    /// One measured handshake: open a loopback connection, run the REALITY
    /// handshake to completion, drop it.
    ///
    /// Success means the server's certificate verified against the client's
    /// `publicKey` — a REALITY server that did not recognise this client
    /// answers by relaying it to the camouflage site instead, which the client
    /// reports as a fallback error rather than as a completed handshake. So a
    /// count of successes is a count of *authenticated* handshakes.
    pub async fn handshake(&self) -> Result<Bytes, String> {
        let socket = TcpStream::connect(self.address)
            .await
            .map_err(|error| format!("connect to {}: {error}", self.address))?;
        // Both servers get the same treatment, and a proxy client sets this.
        let _ = socket.set_nodelay(true);
        let (counted, sent, read) = CountingStream::new(socket);
        let outcome = zero_security::reality_connect(counted, &self.params).await;
        let bytes = Bytes {
            sent: sent.load(Ordering::Relaxed),
            read: read.load(Ordering::Relaxed),
        };
        outcome.map_err(|failure| format!("REALITY handshake: {failure}"))?;
        Ok(bytes)
    }

    /// The same handshake, followed by one VLESS request to `echo` and its
    /// answer, to prove that the endpoint in the table really is a proxy
    /// carrying traffic rather than something that merely completes
    /// handshakes.
    ///
    /// This is the harness's own check, run once per server before the table
    /// is measured; its cost is not part of any number reported.
    pub async fn vless_round_trip(&self, echo: SocketAddr, uuid: &[u8; 16]) -> Result<(), String> {
        let socket = TcpStream::connect(self.address)
            .await
            .map_err(|error| format!("connect to {}: {error}", self.address))?;
        let _ = socket.set_nodelay(true);
        let mut sealed = zero_security::reality_connect(socket, &self.params)
            .await
            .map_err(|failure| format!("REALITY handshake: {failure}"))?;

        let destination = Destination::tcp(Address::Ip(echo.ip()), echo.port());
        let request = vless::encode_request(uuid, "", &destination);
        sealed
            .write_all(&request)
            .await
            .map_err(|error| format!("VLESS request header: {error}"))?;
        let payload: Vec<u8> = (0..64u16).map(|index| index as u8).collect();
        sealed
            .write_all(&payload)
            .await
            .map_err(|error| format!("VLESS request payload: {error}"))?;
        sealed
            .flush()
            .await
            .map_err(|error| format!("VLESS request flush: {error}"))?;

        // The response is the two-byte VLESS header, then the echoed bytes.
        // Both may arrive in pieces.
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 256];
        let deadline = Duration::from_secs(10);
        loop {
            let read = tokio::time::timeout(deadline, sealed.read(&mut chunk))
                .await
                .map_err(|_| "the echoed payload never came back".to_string())?
                .map_err(|error| format!("reading the VLESS response: {error}"))?;
            if read == 0 {
                return Err("the server closed before answering".into());
            }
            buffer.extend_from_slice(&chunk[..read]);
            match vless::parse_response(&buffer) {
                Ok(vless::ResponseParse::Complete { consumed }) => {
                    let body = &buffer[consumed..];
                    if body.len() >= payload.len() {
                        return if body[..payload.len()] == payload[..] {
                            Ok(())
                        } else {
                            Err(format!(
                                "the echoed payload came back changed: {:?}",
                                &body[..payload.len().min(body.len())]
                            ))
                        };
                    }
                }
                Ok(vless::ResponseParse::Incomplete) => {}
                Err(error) => return Err(format!("VLESS response header: {error}")),
            }
        }
    }
}
