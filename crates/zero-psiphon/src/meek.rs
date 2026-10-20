//! The meek transport.
//!
//! Meek carries a byte stream inside a sequence of HTTP request and response
//! bodies: what the client writes becomes the body of one `POST /`, and what
//! the server answers with becomes what the client reads. Nothing about the
//! connection says "tunnel": to an observer it is an application posting
//! opaque blobs to a host whose name is the only thing that stands out, which
//! is why Psiphon puts meek behind a CDN or a fronting provider, where it
//! looks like one more client of a busy site.
//!
//! Three pieces make it work:
//!
//! * A **cookie** identifies the session. It is a small record — protocol
//!   version, whether payload padding is on, which tunnel protocol — sealed
//!   with NaCl's `box` to a public key the server publishes in its entry, then
//!   wrapped in an OSSH-style obfuscator seed message and base64-encoded. Only
//!   the server can open it, and a filter cannot tell it from a blob of
//!   session data.
//! * The server answers the first request with a `Set-Cookie` naming a session
//!   ID; every later request carries that instead, so the expensive public-key
//!   work happens once per tunnel.
//! * Because HTTP is request/response, the client **polls**: with nothing to
//!   send it still posts an empty body, which gives the server a standing
//!   request to answer with downstream bytes.
//!
//! The OSSH layer of [`crate::obfuscator`] runs on top of this, over the same
//! SSH session as every other transport.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::{Buf, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::nacl_box;
use crate::obfuscator::{derive_key, Rc4, CLIENT_TO_SERVER, MAGIC_VALUE, SEED_LENGTH};
use crate::protocol::TunnelProtocol;

/// The protocol revision Psiphon speaks.
pub const MEEK_PROTOCOL_VERSION: u32 = 4;
/// Largest request body, matching `MEEK_MAX_REQUEST_PAYLOAD_LENGTH`.
pub const MAX_REQUEST_PAYLOAD_LENGTH: usize = 65536;
/// Largest padding the cookie's seed message may carry.
pub const MAX_COOKIE_PADDING: usize = 256;
/// Smallest padding, as the obfuscator requires.
pub const MIN_COOKIE_PADDING: usize = 32;
/// The first poll interval before jitter, from Psiphon's parameters.
pub const MIN_POLL_INTERVAL_MS: u64 = 100;
/// The idle poll interval before jitter.
pub const MAX_POLL_INTERVAL_MS: u64 = 5_000;
/// The content type used when traffic shaping names none.
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Everything a meek connection needs that comes from the server entry and the
/// client's configuration.
#[derive(Debug, Clone)]
pub struct MeekOptions {
    /// The tunnel protocol this connection carries, which goes into the cookie
    /// so the server knows what to expect inside.
    pub protocol: TunnelProtocol,
    /// The entry's `meekObfuscatedKey`: the OSSH keyword the cookie is wrapped
    /// with.
    pub obfuscated_key: String,
    /// The entry's `meekCookieEncryptionPublicKey`, base64, which the cookie
    /// is sealed to.
    pub cookie_encryption_public_key: String,
    /// The `Host` header. Unfronted servers are addressed by address and port;
    /// fronted ones by the fronting host.
    pub host_header: String,
    /// Whether payload padding is in use (the cookie's `p` field).
    pub payload_padding: bool,
    /// Largest request body the server will accept, from tactics.
    pub limit_request_payload_length: usize,
    /// The `User-Agent`, when one was configured.
    pub user_agent: Option<String>,
    /// Extra headers the client's configuration adds.
    pub additional_headers: Vec<(String, String)>,
}

impl MeekOptions {
    /// The options a fronted connection needs: the same carrier, reached
    /// through a CDN, with the fronting host — not the server's address — in
    /// the `Host` header.
    pub fn fronted(
        protocol: TunnelProtocol,
        obfuscated_key: &str,
        cookie_encryption_public_key: &str,
        fronting_host: String,
    ) -> MeekOptions {
        MeekOptions::unfronted(
            protocol,
            obfuscated_key,
            cookie_encryption_public_key,
            fronting_host,
        )
    }

    /// The options an unfronted connection to a server entry needs.
    pub fn unfronted(
        protocol: TunnelProtocol,
        obfuscated_key: &str,
        cookie_encryption_public_key: &str,
        host_header: String,
    ) -> MeekOptions {
        MeekOptions {
            protocol,
            obfuscated_key: obfuscated_key.to_string(),
            cookie_encryption_public_key: cookie_encryption_public_key.to_string(),
            host_header,
            payload_padding: false,
            limit_request_payload_length: MAX_REQUEST_PAYLOAD_LENGTH,
            user_agent: None,
            additional_headers: Vec::new(),
        }
    }
}

/// The cookie a session starts with.
#[derive(Debug, Clone)]
pub struct MeekCookie {
    /// The cookie's name, which never changes once chosen.
    pub name: String,
    /// The cookie's value: the sealed record at first, the server's session ID
    /// afterwards.
    pub value: String,
    /// The body content type the cookie's traffic shaping chose.
    pub content_type: String,
}

/// Build the cookie a relay-mode session starts with.
pub fn make_cookie(options: &MeekOptions, rng: &mut impl Rng) -> Result<MeekCookie> {
    // 1. The record the server decodes, in Psiphon's field order.
    let mut encoded = Vec::new();
    encoded.push(b'{');
    encoded.extend_from_slice(b"\"v\":");
    encoded.extend_from_slice(MEEK_PROTOCOL_VERSION.to_string().as_bytes());
    if options.payload_padding {
        encoded.extend_from_slice(b",\"p\":true");
    }
    encoded.extend_from_slice(b",\"t\":");
    go_string(options.protocol.as_str(), &mut encoded);
    encoded.push(b'}');

    // 2. Seal it to the server's public key with an ephemeral key pair and a
    //    zero nonce: the key pair is fresh per cookie, which is what a
    //    zero nonce assumes.
    let recipient: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(options.cookie_encryption_public_key.trim())
        .map_err(|error| Error::Meek(format!("meekCookieEncryptionPublicKey: {error}")))?
        .try_into()
        .map_err(|_| Error::Meek("meekCookieEncryptionPublicKey is not 32 bytes".into()))?;

    let mut secret = [0u8; 32];
    rng.fill(&mut secret);
    let public = nacl_box::public_key(&secret);
    let sealed = nacl_box::seal(&[0u8; 24], &encoded, &recipient, &secret);

    let mut cookie_bytes = Vec::with_capacity(32 + sealed.len());
    cookie_bytes.extend_from_slice(&public);
    cookie_bytes.extend_from_slice(&sealed);

    // 3. Wrap it in an obfuscator seed message and continue that cipher over
    //    the sealed cookie: the server consumes the seed message and decrypts
    //    the rest with the same stream.
    let padding_length = rng.gen_range(MIN_COOKIE_PADDING..=MAX_COOKIE_PADDING);
    let mut padding = vec![0u8; padding_length];
    rng.fill(&mut padding[..]);
    let mut seed = [0u8; SEED_LENGTH];
    rng.fill(&mut seed);

    let mut cipher = Rc4::new(&derive_key(
        &seed,
        options.obfuscated_key.as_bytes(),
        CLIENT_TO_SERVER,
    ));

    let mut out = Vec::with_capacity(SEED_LENGTH + 8 + padding.len() + cookie_bytes.len());
    out.extend_from_slice(&seed);
    out.extend_from_slice(&MAGIC_VALUE.to_be_bytes());
    out.extend_from_slice(&(padding.len() as u32).to_be_bytes());
    out.extend_from_slice(&padding);
    cipher.apply(&mut out[SEED_LENGTH..]);
    cipher.apply(&mut cookie_bytes);
    out.extend_from_slice(&cookie_bytes);

    Ok(MeekCookie {
        name: cookie_name(rng),
        value: base64::engine::general_purpose::STANDARD.encode(&out),
        content_type: DEFAULT_CONTENT_TYPE.to_string(),
    })
}

/// Unwrap a cookie the way the server does, for tests and for the mock server.
///
/// Returns the record's JSON text. This is the server's side of the scheme and
/// exists so a test can prove the client produced something a server can read.
pub fn open_cookie(
    options: &MeekOptions,
    server_secret: &[u8; 32],
    cookie_value: &str,
) -> Result<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(cookie_value.trim())
        .map_err(|error| Error::Meek(format!("cookie is not base64: {error}")))?;
    if raw.len() < SEED_LENGTH + 8 {
        return Err(Error::Meek("cookie is shorter than a seed message".into()));
    }

    let seed: [u8; SEED_LENGTH] = raw[..SEED_LENGTH].try_into().unwrap();
    let mut cipher = Rc4::new(&derive_key(
        &seed,
        options.obfuscated_key.as_bytes(),
        CLIENT_TO_SERVER,
    ));

    let mut header = raw[SEED_LENGTH..SEED_LENGTH + 8].to_vec();
    cipher.apply(&mut header);
    if u32::from_be_bytes(header[..4].try_into().unwrap()) != MAGIC_VALUE {
        return Err(Error::Meek("cookie has no obfuscator magic value".into()));
    }
    let padding_length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if raw.len() < SEED_LENGTH + 8 + padding_length + 32 + nacl_box::BOX_OVERHEAD {
        return Err(Error::Meek("cookie is shorter than its padding".into()));
    }

    let mut padding = raw[SEED_LENGTH + 8..SEED_LENGTH + 8 + padding_length].to_vec();
    cipher.apply(&mut padding);

    let mut body = raw[SEED_LENGTH + 8 + padding_length..].to_vec();
    cipher.apply(&mut body);

    let ephemeral: [u8; 32] = body[..32].try_into().unwrap();
    let opened = nacl_box::open(&[0u8; 24], &body[32..], &ephemeral, server_secret)
        .ok_or_else(|| Error::Meek("the cookie did not open".into()))?;
    String::from_utf8(opened).map_err(|_| Error::Meek("the cookie is not UTF-8".into()))
}

/// A plausible cookie name: one upper-case letter, or a lowercase word, which
/// is what Psiphon's own generator produces (it is chosen by probability).
fn cookie_name(rng: &mut impl Rng) -> String {
    if rng.gen_bool(0.5) {
        return ((b'A' + rng.gen_range(0..26)) as char).to_string();
    }
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let length = rng.gen_range(2..=10);
    (0..length)
        .map(|_| LETTERS[rng.gen_range(0..LETTERS.len())] as char)
        .collect()
}

/// Write a JSON string the way Go's `encoding/json` does.
fn go_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => out.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            b'<' => out.extend_from_slice(b"\\u003c"),
            b'>' => out.extend_from_slice(b"\\u003e"),
            b'&' => out.extend_from_slice(b"\\u0026"),
            other => out.push(other),
        }
    }
    out.push(b'"');
}

/// How far the response head and body have been parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseState {
    /// Nothing read yet.
    Idle,
    /// The response head has not been read.
    ReadingHead,
    /// The body length is known; the value is what remains.
    Body(usize),
    /// The body is chunked.
    Chunked,
}

/// A byte stream carried in HTTP request and response bodies.
///
/// `S` is the connection to the server: plain TCP for `UNFRONTED-MEEK`, TLS
/// for the HTTPS variants. One request is in flight at a time, which is what
/// the server's session model expects, and the two directions are driven by
/// whichever of the caller's reads or writes makes progress:
///
/// * Writing buffers bytes; a flush sends them as one request body.
/// * Reading with nothing buffered polls with an empty body, so the server
///   always has a standing request to answer with downstream bytes. Polls back
///   off from 100 ms to 5 s while the connection is idle, so an idle tunnel
///   costs a handful of requests a minute rather than a busy loop.
pub struct MeekStream<S> {
    inner: S,
    options: MeekOptions,
    cookie: MeekCookie,
    /// Bytes the caller wrote that have not been sent yet.
    pending_out: Vec<u8>,
    /// Response payload waiting for the caller.
    pending_in: BytesMut,
    /// Raw response bytes read from the socket.
    incoming: BytesMut,
    /// The request head waiting to be written.
    head: Vec<u8>,
    phase: Phase,
    /// How far the response head and body have been parsed.
    body_state: ResponseState,
    /// Body bytes still to write for the request in flight.
    body_remaining: usize,
    /// Downstream payload bytes received in this session, which a retry's
    /// `Range` resumes from.
    received_payload: u64,
    /// Payload bytes the current round trip brought, which decides whether
    /// the next poll waits or goes out at once.
    round_trip_payload: u64,
    /// Attempts spent on the current round trip.
    attempts: u32,
    /// When the idle poll timer expires.
    poll_at: Option<Instant>,
    sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    closed: bool,
}

/// Where a round trip is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing in flight.
    Idle,
    /// The request head is being written.
    WritingHead,
    /// The request body is being written.
    WritingBody,
    /// The response is being read.
    ReadingResponse,
}

impl<S> MeekStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Wrap `inner`, choosing a cookie for this session.
    pub fn new(inner: S, options: MeekOptions, rng: &mut impl Rng) -> Result<MeekStream<S>> {
        if options.limit_request_payload_length == 0
            || options.limit_request_payload_length > MAX_REQUEST_PAYLOAD_LENGTH
        {
            return Err(Error::Meek(format!(
                "limit_request_payload_length must be between 1 and {MAX_REQUEST_PAYLOAD_LENGTH}"
            )));
        }
        let cookie = make_cookie(&options, rng)?;
        Ok(MeekStream {
            inner,
            options,
            cookie,
            pending_out: Vec::new(),
            pending_in: BytesMut::new(),
            incoming: BytesMut::new(),
            head: Vec::new(),
            phase: Phase::Idle,
            body_state: ResponseState::Idle,
            body_remaining: 0,
            received_payload: 0,
            round_trip_payload: 0,
            attempts: 0,
            poll_at: None,
            sleep: None,
            closed: false,
        })
    }

    /// The session cookie in use, for diagnostics and tests.
    pub fn cookie(&self) -> &MeekCookie {
        &self.cookie
    }

    /// The request head for a body of `length` bytes. A retry that has already
    /// received part of the response asks the server to resume from there and
    /// carries no body, because an upstream payload the server may already
    /// have relayed must not be sent twice.
    fn request_head(&self, length: usize, resume: bool) -> Vec<u8> {
        let mut head = Vec::with_capacity(256);
        head.extend_from_slice(b"POST / HTTP/1.1\r\n");
        head.extend_from_slice(format!("Host: {}\r\n", self.options.host_header).as_bytes());
        if let Some(agent) = &self.options.user_agent {
            head.extend_from_slice(format!("User-Agent: {agent}\r\n").as_bytes());
        }
        head.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        head.extend_from_slice(
            format!("Content-Type: {}\r\n", self.cookie.content_type).as_bytes(),
        );
        head.extend_from_slice(
            format!("Cookie: {}={}\r\n", self.cookie.name, self.cookie.value).as_bytes(),
        );
        if resume && self.received_payload > 0 {
            head.extend_from_slice(
                format!("Range: bytes={}-\r\n", self.received_payload).as_bytes(),
            );
        }
        for (name, value) in &self.options.additional_headers {
            head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        head
    }

    /// Begin a round trip: the buffered upstream bytes, or an empty body when
    /// the only reason to ask is to collect downstream bytes.
    fn begin_request(&mut self, resume: bool) {
        let take = self
            .pending_out
            .len()
            .min(self.options.limit_request_payload_length);
        let (length, body) = if resume && self.received_payload > 0 {
            (0, 0)
        } else {
            (take, take)
        };
        self.head = self.request_head(length, resume);
        self.body_remaining = body;
        self.incoming.clear();
        self.body_state = ResponseState::ReadingHead;
        self.phase = Phase::WritingHead;
    }

    /// Finish the round trip: the body was fully read, and the connection is
    /// idle again — the next write or read starts a new request.
    fn finish_request(&mut self) {
        self.phase = Phase::Idle;
        self.attempts = 0;
        self.round_trip_payload = 0;
    }

    /// Whether the payload of the last response was empty, which is when the
    /// client backs off before polling again.
    fn note_idle(&mut self, saw_payload: bool) {
        let base = if saw_payload {
            0
        } else {
            self.poll_at
                .map(|at| {
                    let previous = at.saturating_duration_since(Instant::now());
                    (previous.as_millis().max(MIN_POLL_INTERVAL_MS as u128) as u64)
                        .min(MAX_POLL_INTERVAL_MS)
                })
                .unwrap_or(MIN_POLL_INTERVAL_MS)
        };
        // Psiphon multiplies the interval by 1.5 with a coin flip; the effect
        // is a backoff, and a fixed factor avoids a random walk test authors
        // cannot reason about.
        let next = if saw_payload {
            MIN_POLL_INTERVAL_MS
        } else {
            (base.saturating_mul(3) / 2).clamp(MIN_POLL_INTERVAL_MS, MAX_POLL_INTERVAL_MS)
        };
        self.poll_at = Some(Instant::now() + Duration::from_millis(next));
    }

    /// One step of the round trip. `poll_idle` distinguishes a read (which may
    /// ask the server for bytes) from a flush (which has nothing to say).
    fn pump(&mut self, cx: &mut Context<'_>, poll_idle: bool) -> Poll<std::io::Result<()>> {
        loop {
            match self.phase {
                Phase::Idle => {
                    let has_out = !self.pending_out.is_empty();
                    if !has_out {
                        if !poll_idle {
                            return Poll::Ready(Ok(()));
                        }
                        // An idle connection polls, but not at full speed.
                        if let Some(at) = self.poll_at {
                            let now = Instant::now();
                            if now < at {
                                let sleep = self.sleep.get_or_insert_with(|| {
                                    Box::pin(tokio::time::sleep_until(at.into()))
                                });
                                match sleep.as_mut().poll(cx) {
                                    Poll::Pending => return Poll::Pending,
                                    Poll::Ready(()) => {
                                        self.sleep = None;
                                        self.poll_at = None;
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    self.begin_request(false);
                }

                Phase::WritingHead => {
                    if self.head.is_empty() {
                        self.phase = if self.body_remaining > 0 {
                            Phase::WritingBody
                        } else {
                            Phase::ReadingResponse
                        };
                        continue;
                    }
                    match Pin::new(&mut self.inner).poll_write(cx, &self.head) {
                        Poll::Ready(Ok(0)) => return Poll::Ready(Err(write_zero())),
                        Poll::Ready(Ok(written)) => {
                            self.head.drain(..written);
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                Phase::WritingBody => {
                    if self.body_remaining == 0 {
                        // Everything is on the wire; make sure it left.
                        match Pin::new(&mut self.inner).poll_flush(cx) {
                            Poll::Ready(Ok(())) => {
                                self.phase = Phase::ReadingResponse;
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                        continue;
                    }
                    let chunk = &self.pending_out[..self.body_remaining];
                    match Pin::new(&mut self.inner).poll_write(cx, chunk) {
                        Poll::Ready(Ok(0)) => return Poll::Ready(Err(write_zero())),
                        Poll::Ready(Ok(written)) => {
                            self.pending_out.drain(..written);
                            self.body_remaining -= written;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                Phase::ReadingResponse => match self.read_response(cx) {
                    Poll::Ready(Ok(())) => {
                        let saw_payload = self.round_trip_payload > 0;
                        self.finish_request();
                        self.note_idle(saw_payload);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => {
                        if let Some(retry) = self.retry(&error) {
                            self.begin_request(retry);
                            continue;
                        }
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }

    /// Whether an attempt is worth retrying, and whether the retry resumes.
    fn retry(&mut self, error: &std::io::Error) -> Option<bool> {
        // A protocol answer that will not change is not worth another request;
        // a connection that broke might be worth one.
        if matches!(error.kind(), std::io::ErrorKind::InvalidData) {
            return None;
        }
        if self.attempts >= 3 {
            return None;
        }
        self.attempts += 1;
        Some(self.received_payload > 0)
    }

    /// Read the response head and then its body, streaming body bytes into
    /// `pending_in` as they arrive.
    fn read_response(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match parse_response(&self.incoming, self.body_state) {
                Parsed::NeedMore => {}
                Parsed::Head {
                    status,
                    content_length,
                    chunked,
                    set_cookie,
                    body_start,
                } => {
                    if status != 200 && status != 206 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("the meek server answered {status}"),
                        )));
                    }
                    // The session ID arrives once and replaces the sealed
                    // cookie; the value is opaque and is echoed verbatim.
                    if let Some((name, value)) = set_cookie {
                        if name == self.cookie.name {
                            self.cookie.value = value;
                        }
                    }
                    self.incoming.advance(body_start);
                    self.body_state = if chunked {
                        ResponseState::Chunked
                    } else {
                        ResponseState::Body(content_length.unwrap_or(usize::MAX))
                    };
                    continue;
                }
                Parsed::Body {
                    skip_before,
                    payload,
                    skip_after,
                    done,
                } => {
                    // A chunk's framing surrounds its data: the size line
                    // comes first and the trailing CRLF comes after.
                    if skip_before > 0 {
                        self.incoming.advance(skip_before);
                    }
                    if payload > 0 {
                        let chunk = self.incoming.split_to(payload);
                        self.pending_in.extend_from_slice(&chunk);
                        self.received_payload += payload as u64;
                        self.round_trip_payload += payload as u64;
                    }
                    if skip_after > 0 {
                        self.incoming.advance(skip_after);
                    }
                    if done {
                        return Poll::Ready(Ok(()));
                    }
                    // More of the body may already be buffered.
                    continue;
                }
                Parsed::Invalid(message) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        message,
                    )))
                }
            }

            let start = self.incoming.len();
            self.incoming.resize(start + 16 * 1024, 0);
            let mut read = ReadBuf::new(&mut self.incoming[start..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Pending => {
                    self.incoming.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => {
                    self.incoming.truncate(start);
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) => {
                    let filled = read.filled().len();
                    self.incoming.truncate(start + filled);
                    if filled == 0 {
                        if self.body_state == ResponseState::Body(0) {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "the meek server closed mid-response",
                        )));
                    }
                }
            }
        }
    }
}

fn write_zero() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WriteZero,
        "the meek server accepted no request bytes",
    )
}

impl<S> AsyncRead for MeekStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending_in.is_empty() {
                let take = this.pending_in.len().min(buf.remaining());
                buf.put_slice(&this.pending_in.split_to(take));
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // A new round trip is needed for every read that finds the buffer
            // empty: that is the poll, and it is why an idle connection still
            // receives the server's bytes.
            match this.pump(cx, true) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for MeekStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the meek connection is closed",
            )));
        }

        let room = this
            .options
            .limit_request_payload_length
            .saturating_sub(this.pending_out.len());
        if room == 0 {
            // The buffer is full: send what is there so the caller can hand
            // over the rest rather than being told to come back later.
            match this.pump(cx, false) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            return Poll::Ready(Ok(0));
        }

        let take = room.min(buf.len());
        this.pending_out.extend_from_slice(&buf[..take]);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        this.pump(cx, false)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.closed = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// What a look at the buffered bytes says.
enum Parsed {
    NeedMore,
    Head {
        status: u16,
        content_length: Option<usize>,
        chunked: bool,
        set_cookie: Option<(String, String)>,
        body_start: usize,
    },
    Body {
        /// Framing bytes before the payload (a chunk's size line).
        skip_before: usize,
        /// Payload bytes to hand to the caller.
        payload: usize,
        /// Framing bytes after the payload (a chunk's trailing CRLF).
        skip_after: usize,
        done: bool,
    },
    Invalid(String),
}

/// Parse the response head, or as much of the body as the buffer holds.
///
/// The head is looked for only while the state says so; once the body length
/// is known this only reports body bytes, which is what lets a response stream
/// through without buffering the whole thing.
fn parse_response(buffer: &BytesMut, state: ResponseState) -> Parsed {
    match state {
        ResponseState::Idle | ResponseState::ReadingHead => {
            let Some(header_end) = find_header_end(buffer) else {
                if buffer.len() > 64 * 1024 {
                    return Parsed::Invalid("the meek response head is too long".into());
                }
                return Parsed::NeedMore;
            };
            let head = &buffer[..header_end];
            let text = match std::str::from_utf8(head) {
                Ok(text) => text,
                Err(_) => return Parsed::Invalid("the meek response head is not text".into()),
            };

            let mut lines = text.split("\r\n");
            let status_line = lines.next().unwrap_or_default();
            let status = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or(0);

            let mut content_length = None;
            let mut chunked = false;
            let mut set_cookie = None;
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let name = name.trim().to_ascii_lowercase();
                let value = value.trim();
                match name.as_str() {
                    "content-length" => content_length = value.parse::<usize>().ok(),
                    "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
                    "set-cookie" => {
                        // Only the name and the value matter; the attributes
                        // after the first `;` are for browsers.
                        let pair = value.split(';').next().unwrap_or_default();
                        if let Some((name, value)) = pair.split_once('=') {
                            set_cookie = Some((name.trim().to_string(), value.trim().to_string()));
                        }
                    }
                    _ => {}
                }
            }

            Parsed::Head {
                status,
                content_length,
                chunked,
                set_cookie,
                body_start: header_end + 4,
            }
        }
        ResponseState::Body(remaining) => {
            // A body of no bytes is already complete. Treating it as "need
            // more" would wait for bytes the server has no reason to send:
            // the server answers a request and then waits for the next one,
            // so the client would never poll again.
            if remaining == 0 {
                return Parsed::Body {
                    skip_before: 0,
                    payload: 0,
                    skip_after: 0,
                    done: true,
                };
            }
            if buffer.is_empty() {
                return Parsed::NeedMore;
            }
            let take = buffer.len().min(remaining);
            Parsed::Body {
                skip_before: 0,
                payload: take,
                skip_after: 0,
                done: take == remaining,
            }
        }
        ResponseState::Chunked => parse_chunk(buffer),
    }
}

/// One chunk of a chunked body, if the buffer holds a whole one.
fn parse_chunk(buffer: &BytesMut) -> Parsed {
    let Some(size_end) = buffer.windows(2).position(|window| window == b"\r\n") else {
        return Parsed::NeedMore;
    };
    let size_text = match std::str::from_utf8(&buffer[..size_end]) {
        Ok(text) => text,
        Err(_) => return Parsed::Invalid("a chunk size is not text".into()),
    };
    // A chunk may carry extensions after the size, separated by `;`.
    let size_text = size_text.split(';').next().unwrap_or_default().trim();
    let size = match usize::from_str_radix(size_text, 16) {
        Ok(size) => size,
        Err(_) => return Parsed::Invalid(format!("bad chunk size {size_text:?}")),
    };

    if size == 0 {
        // The last chunk, then the trailer that ends the body.
        let chunk_start = size_end + 2;
        if buffer.len() < chunk_start + 2 {
            return Parsed::NeedMore;
        }
        return Parsed::Body {
            skip_before: chunk_start,
            payload: 0,
            skip_after: 2,
            done: true,
        };
    }

    let chunk_start = size_end + 2;
    if buffer.len() < chunk_start + size + 2 {
        return Parsed::NeedMore;
    }
    Parsed::Body {
        // The size line comes before the data, the CRLF after it.
        skip_before: chunk_start,
        payload: size,
        skip_after: 2,
        done: false,
    }
}

/// The index of the `\r\n\r\n` that ends a response head.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SERVER_SECRET: [u8; 32] = [0x11u8; 32];

    fn options() -> MeekOptions {
        let public = nacl_box::public_key(&SERVER_SECRET);
        MeekOptions::unfronted(
            TunnelProtocol::UnfrontedMeekHttps,
            "obfuscation-key",
            &base64::engine::general_purpose::STANDARD.encode(public),
            "192.0.2.10:20087".to_string(),
        )
    }

    #[test]
    fn the_cookie_is_a_record_a_server_can_open() {
        let mut rng = StdRng::seed_from_u64(7);
        let options = options();
        let cookie = make_cookie(&options, &mut rng).unwrap();

        let record = open_cookie(&options, &SERVER_SECRET, &cookie.value).unwrap();
        assert_eq!(record, "{\"v\":4,\"t\":\"UNFRONTED-MEEK-HTTPS-OSSH\"}");
        assert!(cookie.name.len() <= 10 && !cookie.name.is_empty());
        assert_eq!(cookie.content_type, DEFAULT_CONTENT_TYPE);
    }

    #[test]
    fn payload_padding_is_announced_and_the_cookie_still_opens() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut options = options();
        options.payload_padding = true;
        let cookie = make_cookie(&options, &mut rng).unwrap();
        let record = open_cookie(&options, &SERVER_SECRET, &cookie.value).unwrap();
        assert_eq!(
            record,
            "{\"v\":4,\"p\":true,\"t\":\"UNFRONTED-MEEK-HTTPS-OSSH\"}"
        );
    }

    #[test]
    fn a_cookie_sealed_to_another_server_does_not_open() {
        let mut rng = StdRng::seed_from_u64(13);
        let options = options();
        let cookie = make_cookie(&options, &mut rng).unwrap();
        assert!(open_cookie(&options, &[0x22u8; 32], &cookie.value).is_err());
        // Nor does a tampered one.
        let mut edited = cookie.value.clone().into_bytes();
        let last = edited.len() - 2;
        edited[last] = if edited[last] == b'A' { b'B' } else { b'A' };
        let edited = String::from_utf8(edited).unwrap();
        assert!(open_cookie(&options, &SERVER_SECRET, &edited).is_err());
    }

    #[test]
    fn cookie_names_look_like_session_data() {
        let mut rng = StdRng::seed_from_u64(3);
        let (mut letters, mut words) = (0, 0);
        for _ in 0..64 {
            let name = cookie_name(&mut rng);
            assert!(!name.is_empty() && name.len() <= 10);
            if name.len() == 1 {
                assert!(name.chars().all(|c| c.is_ascii_uppercase()));
                letters += 1;
            } else {
                assert!(name.chars().all(|c| c.is_ascii_lowercase()));
                words += 1;
            }
        }
        assert!(letters > 0 && words > 0, "{letters} letters, {words} words");
    }

    #[test]
    fn go_string_escapes_the_way_psiphons_encoder_does() {
        let mut out = Vec::new();
        go_string("a<b>&\"\\\n", &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\"a\\u003cb\\u003e\\u0026\\\"\\\\\\n\""
        );
    }

    #[test]
    fn responses_parse_either_way_the_server_can_write_them() {
        // A body of known length.
        let buffered = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: A=abc123; Path=/\r\n\r\nhello"[..],
        );
        match parse_response(&buffered, ResponseState::ReadingHead) {
            Parsed::Head {
                status,
                content_length,
                chunked,
                set_cookie,
                body_start,
            } => {
                assert_eq!(status, 200);
                assert_eq!(content_length, Some(5));
                assert!(!chunked);
                assert_eq!(set_cookie.unwrap().1, "abc123");
                assert_eq!(&buffered[body_start..], b"hello");
            }
            _ => panic!("expected a parsed head"),
        }

        // A chunked body, which is what a streaming server sends.
        let buffered =
            BytesMut::from(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        match parse_response(&buffered, ResponseState::ReadingHead) {
            Parsed::Head { chunked, .. } => assert!(chunked),
            _ => panic!("expected a parsed head"),
        }

        let chunk = BytesMut::from(&b"5\r\nhello\r\n0\r\n\r\n"[..]);
        match parse_response(&chunk, ResponseState::Chunked) {
            Parsed::Body {
                skip_before,
                payload,
                skip_after,
                done,
            } => {
                // The payload is the chunk's data; the framing surrounds it.
                assert_eq!(skip_before, 3, "the size line");
                assert_eq!(payload, 5);
                assert_eq!(skip_after, 2, "the trailing CRLF");
                assert!(!done);
            }
            _ => panic!("expected a chunk"),
        }

        let last = BytesMut::from(&b"0\r\n\r\n"[..]);
        match parse_response(&last, ResponseState::Chunked) {
            Parsed::Body { done, .. } => assert!(done),
            _ => panic!("expected the last chunk"),
        }
    }

    /// The mock server of §3.7 of the wire spec: it enforces the checks the
    /// real one does, so a client that passes here is speaking the protocol.
    async fn serve_mock<S>(stream: S, options: &MeekOptions, responses: Vec<&str>) -> Vec<String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut stream = stream;
        let mut requests = Vec::new();
        let mut session: Option<String> = None;
        let mut buffered = BytesMut::new();

        for (index, response_body) in responses.into_iter().enumerate() {
            // Read one request: head, then the declared body.
            let (head, _request_body) = loop {
                if let Some(end) = find_header_end(&buffered) {
                    let text = String::from_utf8(buffered[..end].to_vec()).unwrap();
                    let length: usize = text
                        .to_lowercase()
                        .split("content-length:")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .and_then(|value| value.trim().parse().ok())
                        .expect("every meek request declares its length");
                    if buffered.len() >= end + 4 + length {
                        let request_body = buffered[end + 4..end + 4 + length].to_vec();
                        buffered.advance(end + 4 + length);
                        break (text, request_body);
                    }
                }
                let mut chunk = vec![0u8; 8192];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "the client closed before its request");
                buffered.extend_from_slice(&chunk[..read]);
            };

            requests.push(head.clone());

            // The cookie must be present, and after the first response it must
            // be the session ID the server handed out.
            let cookie_line = head
                .split("\r\n")
                .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
                .expect("every meek request carries a cookie");
            let (_, value) = cookie_line["Cookie:".len()..]
                .trim()
                .split_once('=')
                .expect("a cookie is name=value");
            match &session {
                Some(expected) => assert_eq!(value, expected, "the client echoed the session ID"),
                None => {
                    // The first request carries the sealed record, which the
                    // server decrypts here.
                    let record = open_cookie(options, &SERVER_SECRET, value)
                        .expect("the first cookie opens");
                    assert!(record.contains("\"v\":4"), "{record}");
                }
            }

            // Answer: the session ID once, then the payload.
            let mut response = "HTTP/1.1 200 OK\r\n".to_string();
            if index == 0 {
                let id = "c2Vzc2lvbi1pZA";
                session = Some(id.to_string());
                response.push_str(&format!(
                    "Set-Cookie: {}={id}; Path=/\r\n",
                    cookie_name_of(&head)
                ));
            }
            let mut response = response.into_bytes();
            response.extend_from_slice(
                format!(
                    "Transfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                    response_body.len()
                )
                .as_bytes(),
            );
            response.extend_from_slice(response_body.as_bytes());
            response.extend_from_slice(b"\r\n0\r\n\r\n");
            stream.write_all(&response).await.unwrap();
            stream.flush().await.unwrap();
        }

        requests
    }

    fn cookie_name_of(head: &str) -> String {
        head.split("\r\n")
            .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
            .and_then(|line| line["Cookie:".len()..].trim().split_once('='))
            .map(|(name, _)| name.to_string())
            .expect("a cookie name")
    }

    #[tokio::test]
    async fn a_round_trip_carries_bytes_each_way_and_adopts_the_session_cookie() {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let options = options();

        let server_task = tokio::spawn({
            let options = options.clone();
            async move { serve_mock(server, &options, vec!["hello", "again"]).await }
        });

        let mut rng = StdRng::seed_from_u64(23);
        let mut stream = MeekStream::new(client, options, &mut rng).unwrap();

        // Write, flush: that is one request, answered with "hello".
        stream.write_all(b"upstream-1").await.unwrap();
        stream.flush().await.unwrap();
        let mut down = vec![0u8; 5];
        stream.read_exact(&mut down).await.unwrap();
        assert_eq!(&down, b"hello");

        // The server's Set-Cookie replaced the sealed value with a session ID.
        assert_eq!(stream.cookie().value, "c2Vzc2lvbi1pZA");

        // A second round trip carries the next batch.
        stream.write_all(b"upstream-2").await.unwrap();
        stream.flush().await.unwrap();
        let mut down = vec![0u8; 5];
        stream.read_exact(&mut down).await.unwrap();
        assert_eq!(&down, b"again");

        let requests = server_task.await.unwrap();
        assert_eq!(requests.len(), 2);
        for head in &requests {
            assert!(head.starts_with("POST / HTTP/1.1\r\n"), "{head}");
            assert!(head.contains("Host: 192.0.2.10:20087"), "{head}");
            assert!(
                head.contains("Content-Type: application/octet-stream"),
                "{head}"
            );
            assert!(!head.contains("Range:"), "a first attempt never resumes");
        }
        assert!(
            requests[0].contains("Content-Length: 10"),
            "{}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn a_poll_with_nothing_to_send_reads_downstream_bytes() {
        // The SSH banner arrives before the client has anything to say: the
        // read side has to poll with an empty body.
        let (client, server) = tokio::io::duplex(256 * 1024);
        let options = options();
        let server_task = tokio::spawn({
            let options = options.clone();
            async move { serve_mock(server, &options, vec!["SSH-2.0-psiphond\r\n"]).await }
        });

        let mut rng = StdRng::seed_from_u64(29);
        let mut stream = MeekStream::new(client, options, &mut rng).unwrap();

        let mut banner = vec![0u8; "SSH-2.0-psiphond\r\n".len()];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(banner, b"SSH-2.0-psiphond\r\n");

        let requests = server_task.await.unwrap();
        assert!(requests[0].contains("Content-Length: 0"), "{}", requests[0]);
    }

    #[tokio::test]
    async fn a_server_error_ends_the_connection_with_the_status() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let options = options();
        tokio::spawn(async move {
            let mut server = server;
            let mut head = vec![0u8; 4096];
            let _ = server.read(&mut head).await;
            server
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let mut rng = StdRng::seed_from_u64(31);
        let mut stream = MeekStream::new(client, options, &mut rng).unwrap();
        let error = stream.read(&mut [0u8; 16]).await.unwrap_err();
        assert!(error.to_string().contains("403"), "{error}");
    }
}
