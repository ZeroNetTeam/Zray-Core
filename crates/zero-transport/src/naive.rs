//! NaiveProxy: an HTTP/2 CONNECT tunnel behind an ordinary TLS site.
//!
//! The client dials the server, completes a browser-shaped TLS handshake
//! offering `h2`, then opens one HTTP/2 stream with a `CONNECT` request that
//! names the destination in authority form. Everything on that stream after
//! the server's `200` is the tunnel: request bodies carry what the user
//! sends, response bodies carry what comes back. To a middlebox the
//! connection is an ordinary HTTP/2 session to the front domain — there is
//! no proxy marker on the wire, and the `Proxy-Authorization` (HTTP Basic)
//! is the same credential a Caddy `forwardproxy` frontend checks.
//!
//! Padding (NaiveProxy's README): when the client's CONNECT request carries
//! a `padding` header, the first eight units in each direction are shaped
//! as `[size_hi][size_lo][pad_len][payload][zeros]`, with the padding length
//! uniform in `[0, 255]` and a payload of at most 65535 bytes. The server
//! confirms it speaks the protocol by putting a `padding` header on its
//! `200`; a server that does not gets plain payloads, so the same client
//! works either way. The padding header's own value is a run of printable
//! symbols of random length, chosen so its cost under HPACK Huffman coding
//! is flat like every length in that range.
//!
//! The first tunnel payload deliberately does not travel in the same flight
//! as the CONNECT request: NaiveProxy's `Fast Open` piggybacks writes, but
//! its README warns the first CONNECT cannot carry payload before the
//! response, so every write here waits for the `200` first.
//!
//! ```text
//! client                          front domain                     proxy
//!   |── TLS(h2, browser hello) ──────►|                              |
//!   |── HEADERS: CONNECT host:443 ───►|──── CONNECT proxied ────────►|
//!   |   padding: <random>             |                              |
//!   |◄─ HEADERS: 200, padding: <..> ──|◄─── 200 ─────────────────────|
//!   |══ DATA: padded unit ═══════════►|══════════════════════════════►|
//!   |◄═ DATA: padded unit ════════════|◄══════════════════════════════|
//! ```

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Units padded after the stream is established, per direction. The
/// NaiveProxy README fixes this at 8.
const PADDED_UNITS: u8 = 8;

/// Largest padding a unit may carry (README: `kMaxPaddingSize`).
const MAX_PADDING: usize = 255;

/// Largest payload a unit may carry (its size field is two bytes).
const MAX_UNIT: usize = 65535;

/// A tunnel over one HTTP/2 stream. Reads return tunnel bytes only; the
/// unit framing is stripped inside.
pub struct NaiveStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// The h2 session future. It must be driven alongside every read and
    /// write or no frame ever moves.
    connection: h2::client::Connection<zero_core::BoxStream>,
    /// Raw response bytes that have not been resolved into units yet: a
    /// unit header may split across HTTP/2 frames.
    staging: BytesMut,
    /// Decoded tunnel bytes waiting for the caller.
    ready: BytesMut,
    /// Units still to be padded in each direction, counted down as they
    /// pass. Zero means the rest of the direction is raw payload.
    reads_padded: u8,
    writes_padded: u8,
    /// Whether the server confirmed it speaks the padding protocol.
    padded: bool,
}

impl NaiveStream {
    /// Open a tunnel through an HTTP/2 session already established on
    /// `connection`. The caller owns the TLS/h2 setup (`client_handshake`
    /// below does both).
    pub async fn connect(
        mut connection: h2::client::Connection<zero_core::BoxStream>,
        mut send_request: h2::client::SendRequest<Bytes>,
        username: &str,
        password: &str,
        destination: &zero_core::Destination,
        padding: bool,
    ) -> Result<Self, String> {
        use base64::Engine as _;
        if destination.network != zero_core::Network::Tcp {
            return Err("NaiveProxy carries TCP only".into());
        }
        let authority = match &destination.address {
            zero_core::Address::Ip(std::net::IpAddr::V6(ip)) => {
                format!("[{ip}]:{}", destination.port)
            }
            other => format!("{}:{}", other.host_string(), destination.port),
        };
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            // Authority form (`host:port`): HTTP/2 carries it as
            // `:authority` with no `:path`, which is the CONNECT shape.
            .uri(authority)
            .header("proxy-authorization", format!("Basic {token}"));
        if padding {
            request = request.header("padding", padding_header_value());
        }
        let request = request
            .body(())
            .map_err(|error| format!("CONNECT request: {error}"))?;
        let (response, send) = send_request
            .send_request(request, false)
            .map_err(|error| format!("CONNECT request: {error}"))?;
        // The session has to be driven for the response to arrive.
        let response = tokio::select! {
            response = response => response.map_err(|error| format!("CONNECT response: {error}"))?,
            result = &mut connection => {
                return Err(match result {
                    Ok(()) => "the front closed the connection".to_string(),
                    Err(error) => format!("HTTP/2: {error}"),
                });
            }
        };
        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(format!("the front refused the tunnel with {status}"));
        }
        // The server's `padding` header is the protocol's confirmation:
        // only when it is present do both sides frame their first units.
        let padded = padding && response.headers().contains_key("padding");
        let reads_padded = if padded { PADDED_UNITS } else { 0 };
        let writes_padded = if padded { PADDED_UNITS } else { 0 };
        Ok(Self {
            send,
            recv: response.into_body(),
            connection,
            staging: BytesMut::new(),
            ready: BytesMut::new(),
            reads_padded,
            writes_padded,
            padded,
        })
    }

    /// Poll the session future once: it is what actually reads and writes
    /// the socket. Returns an error once the session is gone.
    fn drive(&mut self, cx: &mut Context<'_>) -> Result<(), std::io::Error> {
        match Pin::new(&mut self.connection).poll(cx) {
            Poll::Ready(Ok(())) => Err(std::io::Error::other("the HTTP/2 session closed")),
            Poll::Ready(Err(error)) => Err(std::io::Error::other(error)),
            Poll::Pending => Ok(()),
        }
    }

    /// Resolve what is in `staging` into whole units while any are due.
    /// After the padded units, whatever remains is raw payload.
    fn decode_staged(&mut self) {
        while self.reads_padded > 0 {
            match parse_unit(&mut self.staging) {
                Some(payload) => {
                    self.ready.extend_from_slice(&payload);
                    self.reads_padded -= 1;
                }
                None => return,
            }
        }
        if !self.staging.is_empty() {
            let rest = self.staging.split();
            self.ready.unsplit(rest);
        }
    }
}

/// Frame one outgoing unit: `[hi][lo][pad]`, payload, then `pad` zeros.
/// Pure so the layout is testable without a session.
fn frame_unit(payload: &[u8], pad: usize) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_UNIT && pad <= MAX_PADDING);
    let mut out = Vec::with_capacity(payload.len() + 3 + pad);
    out.push((payload.len() >> 8) as u8);
    out.push(payload.len() as u8);
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.resize(out.len() + pad, 0);
    out
}

/// Parse one whole unit out of `staging`, or `None` while it is still
/// short. On success `staging` is advanced past the unit.
fn parse_unit(staging: &mut BytesMut) -> Option<Vec<u8>> {
    if staging.len() < 3 {
        return None;
    }
    let size = (usize::from(staging[0]) << 8) | usize::from(staging[1]);
    let pad = usize::from(staging[2]);
    if staging.len() < 3 + size + pad {
        return None;
    }
    staging.advance(3);
    let payload = staging.split_to(size).to_vec();
    staging.advance(pad);
    Some(payload)
}

/// The `padding` header's value: random printable symbols, 16 to 32 of
/// them. Any value in that range costs the same under HPACK's Huffman
/// coding, so the header carries no readable length signal.
fn padding_header_value() -> String {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(16..=32);
    (0..len).map(|_| char::from(rng.gen_range(b'!'..=b'~'))).collect()
}

/// Bring up a NaiveProxy tunnel over `secured` (a TLS stream whose ALPN
/// negotiated `h2`): HTTP/2 handshake, one CONNECT, then the tunnel.
pub async fn client_handshake(
    secured: zero_core::BoxStream,
    username: &str,
    password: &str,
    destination: &zero_core::Destination,
    padding: bool,
) -> Result<NaiveStream, String> {
    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(1 << 20)
        .initial_connection_window_size(4 << 20)
        .handshake::<_, Bytes>(secured)
        .await
        .map_err(|error| format!("HTTP/2: {error}"))?;
    NaiveStream::connect(
        connection,
        send_request,
        username,
        password,
        destination,
        padding,
    )
    .await
}

/// Move what is ready into the caller's buffer. `true` when any byte went
/// in; a poll that hands the caller zero bytes reads as end-of-stream, so a
/// read must never return without this succeeding whenever payload is
/// available.
fn take_ready(ready: &mut BytesMut, buf: &mut ReadBuf<'_>) -> bool {
    if ready.is_empty() {
        return false;
    }
    let take = ready.len().min(buf.remaining());
    buf.put_slice(&ready.split_to(take));
    true
}

impl AsyncRead for NaiveStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // The session future is what moves the socket, so a pending stream
        // is driven once before the task is yielded; a second `driven` pass
        // would spin, so one is the rule.
        let mut driven = false;
        loop {
            if take_ready(&mut self.ready, buf) {
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    if self.reads_padded == 0 && self.staging.is_empty() {
                        self.ready.extend_from_slice(&chunk);
                    } else {
                        // A padded unit can split across frames; keep polling
                        // until one whole unit is in hand.
                        self.staging.extend_from_slice(&chunk);
                        self.decode_staged();
                    }
                    let _ = self.recv.flow_control().release_capacity(len);
                    driven = false;
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                // The response body ended: the tunnel is closed.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => {
                    if driven {
                        return Poll::Pending;
                    }
                    if let Err(error) = self.drive(cx) {
                        return Poll::Ready(Err(error));
                    }
                    driven = true;
                }
            }
        }
    }
}

impl AsyncWrite for NaiveStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let take = data.len().min(MAX_UNIT);
        let framed = if self.padded && self.writes_padded > 0 {
            let pad = {
                use rand::Rng as _;
                let mut rng = rand::thread_rng();
                rng.gen_range(0..=MAX_PADDING)
            };
            frame_unit(&data[..take], pad)
        } else {
            data[..take].to_vec()
        };
        // Ask for the room, then wait until the session grants it. The
        // session future is polled alongside so inbound WINDOW_UPDATEs that
        // release capacity are read even when the caller never reads.
        self.send.reserve_capacity(framed.len());
        loop {
            let capacity = self.send.capacity();
            if capacity >= framed.len() {
                break;
            }
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "the HTTP/2 session is gone",
                    )));
                }
                Poll::Pending => {
                    // Driving the session may read in a WINDOW_UPDATE that
                    // grants the capacity this write is waiting for, so the
                    // capacity is checked once more before yielding.
                    if let Err(error) = self.drive(cx) {
                        return Poll::Ready(Err(error));
                    }
                    if self.send.capacity() >= framed.len() {
                        break;
                    }
                    return Poll::Pending;
                }
            }
        }
        if let Err(error) = self.send.send_data(Bytes::from(framed), false) {
            return Poll::Ready(Err(std::io::Error::other(error)));
        }
        if self.padded && self.writes_padded > 0 {
            self.writes_padded -= 1;
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.drive(cx) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Half-close: an empty DATA frame with END_STREAM. A closed send
        // side is not an error here — the caller is done either way.
        let _ = self.send.send_data(Bytes::new(), true);
        let _ = self.drive(cx);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn a_unit_carries_its_size_then_its_zeros() {
        assert_eq!(frame_unit(b"hello", 3), b"\x00\x05\x03hello\x00\x00\x00");
        assert_eq!(frame_unit(b"", 0), b"\x00\x00\x00");
    }

    #[test]
    fn units_parse_across_split_frames() {
        let mut staging = BytesMut::new();
        let unit = frame_unit(b"payload", 4);
        for byte in &unit[..unit.len() - 1] {
            staging.extend_from_slice(&[*byte]);
            // One byte short: never a whole unit yet until the last zero.
        }
        assert_eq!(parse_unit(&mut staging).as_deref(), None);
        staging.extend_from_slice(&[unit[unit.len() - 1]]);
        assert_eq!(parse_unit(&mut staging).as_deref(), Some(&b"payload"[..]));
        assert!(staging.is_empty());
    }

    /// A stand-in front: plain h2 over a duplex pair, every CONNECT
    /// accepted, and each request-body chunk answered with `echo(chunk)`.
    /// Returns the client end of the pair.
    async fn front(padding_reply: bool, echo: fn(&[u8]) -> Vec<u8>) -> zero_core::BoxStream {
        let (client, server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            // Requests are handled in tasks of their own: reading a request
            // body here would stop this loop from driving the session, and
            // no frame would move.
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                tokio::spawn(async move {
                    assert_eq!(request.method(), http::Method::CONNECT);
                    let padded = request.headers().contains_key("padding");
                    let mut response = http::Response::builder().status(200);
                    if padding_reply && padded {
                        response = response.header("padding", "abcdefgh12345678");
                    }
                    let mut send = respond
                        .send_response(response.body(()).unwrap(), false)
                        .unwrap();
                    let mut body = request.into_body();
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        let out = echo(&chunk);
                        if !out.is_empty() {
                            send.send_data(Bytes::from(out), false).unwrap();
                        }
                    }
                });
            }
        });
        Box::pin(client)
    }

    fn destination() -> zero_core::Destination {
        zero_core::Destination::tcp(zero_core::Address::parse_host("example.com"), 443)
    }

    #[tokio::test]
    async fn a_raw_tunnel_carries_bytes_both_ways() {
        let io = front(false, |chunk| chunk.to_vec()).await;
        let mut stream = client_handshake(io, "user", "pass", &destination(), false)
            .await
            .expect("tunnel");
        stream.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        // A second round trip proves the tunnel is not one-shot.
        stream.write_all(b"pong").await.unwrap();
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }

    #[tokio::test]
    async fn a_padded_tunnel_unframes_what_the_server_sends() {
        // The echo returns exactly what came in, which in padded mode is
        // the framed unit; the client must decode its own frames to see
        // the payload again.
        let io = front(true, |chunk| chunk.to_vec()).await;
        let mut stream = client_handshake(io, "user", "pass", &destination(), true)
            .await
            .expect("tunnel");
        assert!(stream.padded, "the server confirmed padding");
        stream.write_all(b"hello padded").await.unwrap();
        let mut back = vec![0u8; b"hello padded".len()];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello padded");
    }

    #[tokio::test]
    async fn a_server_without_the_padding_header_gets_plain_payloads() {
        // padding=on was asked for, but the response carries no `padding`
        // header: the tunnel must stay raw in both directions.
        let io = front(false, |chunk| chunk.to_vec()).await;
        let mut stream = client_handshake(io, "user", "pass", &destination(), true)
            .await
            .expect("tunnel");
        assert!(!stream.padded);
        stream.write_all(b"raw after all").await.unwrap();
        let mut back = vec![0u8; b"raw after all".len()];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"raw after all");
    }

    #[tokio::test]
    async fn a_refused_connect_says_the_status() {
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            if let Some(Ok((_request, mut respond))) = connection.accept().await {
                let denied = http::Response::builder().status(407).body(()).unwrap();
                let _ = respond.send_response(denied, true);
                // `accept` is what drives the session; it must keep being
                // called until the client hangs up, or the queued 407 is
                // never written out.
                while let Some(Ok(_)) = connection.accept().await {}
            }
        });
        let error = client_handshake(Box::pin(client), "user", "pass", &destination(), false)
            .await
            .err()
            .expect("a 407 must fail");
        assert!(error.contains("407"), "{error}");
    }
}
