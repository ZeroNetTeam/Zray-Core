//! The unauthenticated path: what the server does with a visitor that is not
//! REALITY.
//!
//! REALITY's disguise is that the port behaves like the site it borrows. So
//! when [`crate::server::handshake_or_fallback`] decides the ClientHello on the
//! wire is not REALITY — a censor probing the port, a client with the wrong
//! key, a server name this server does not serve — the answer must not be an
//! error, a reset or a dropped connection. The connection is handed to the
//! camouflage target (`dest`), and from that point on the prober is talking to
//! that site's own TLS.
//!
//! How this works. [`relay`] takes the socket the hello was consumed from and
//! an already-connected target, and then puts on the wire exactly what Go puts
//! there, in this order:
//!
//! 1. the PROXY protocol header, when `xver` asks for one, so the target learns
//!    who really connected;
//! 2. the bytes already consumed (`buffered_hello`), because the target must
//!    see the ClientHello the visitor sent and not a truncated one;
//! 3. both directions, with the unauthenticated visitor held to
//!    `limitFallbackUpload` and `limitFallbackDownload`;
//! 4. a half-close in the direction the peer closed — Go's `CloseWrite` — so
//!    the target sees the request's end-of-stream while the response still
//!    flows back.
//!
//! Deliberately not in this module: connecting to the target (the caller owns
//! the resolver, the dial and its deadline) and the decision that a connection
//! *is* a fallback ([`crate::server`]). This module is the relay a server calls
//! once it knows it has a visitor to get rid of.
//!
//! Provenance. The wire behavior is `xtls/reality`'s server path in `tls.go`:
//! the `NewRatelimitedConn` read limit, the two `io.Copy` pumps, the
//! `xver`/`proxyproto.HeaderProxyFromAddrs` write, and the `CloseWrite`
//! half-close. The Rust moved here is `zero-runtime/src/server.rs` →
//! `relay_reality_fallback`, with the two helpers it used,
//! `zero-runtime::throttle::{Limit, Throttle}` and `zero-runtime::relay`, kept
//! in step by construction: the runtime depends on this crate, so this crate
//! cannot call back into it, and one documented port beats two copies that
//! drift. The runtime still runs its own copy of all three for now — its
//! `Xray client → Zray server` differential tests are what prove the behavior —
//! and should be switched over to this module next.
//!
//! The one place this port differs from the runtime's, both noted where they
//! are made: [`Throttle`] reads through a zeroed window instead of carrying the
//! runtime's `unsafe { assume_init }`, and the relay keeps one read buffer per
//! direction instead of the runtime's pooled, self-growing pair.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, Sleep};

use zero_core::Stage;

/// How long a fallback relay may move nothing in either direction before it is
/// closed: Xray's `connIdle`, and the limit the runtime's `relay` gives a
/// fallback (`zero-runtime::relay::DEFAULT_IDLE_TIMEOUT`'s value).
///
/// Without it, a prober that sends its hello, falls back and then vanishes
/// without a FIN — a NAT rebinding, a middlebox that silently drops the flow —
/// pins a task, two sockets and two buffers until the process ends.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Once one direction has finished, how long the other may stay silent before
/// the flow is closed (`HALF_CLOSE_IDLE` in the runtime's `relay`).
///
/// A visitor that answered a FIN with nothing held both sockets for the whole
/// idle period before this existed, which is a cheap way for a prober to
/// accumulate connections.
pub const HALF_CLOSE_IDLE: Duration = Duration::from_secs(1);

/// Once one direction has failed, how long the other may keep delivering
/// before the relay closes both sockets.
///
/// A failed direction is usually the target hanging up on a visitor it will
/// not serve, and the answer it already sent — an alert, a `400`, a redirect —
/// is on its way to a visitor that is still being written to. Go reads the
/// target in its own goroutine and writes what it read to the visitor before
/// the other goroutine's failure can close anything (`RL/tls.go:437-442`), so
/// that answer survives; a single future that returns as soon as either side
/// errors loses it, and the visitor sees a bare close where the real site
/// answered. The grace is short because the bytes are already on the wire: it
/// only has to cover reading and writing what the peer has sent.
pub const DRAIN_AFTER_ERROR: Duration = Duration::from_millis(250);

/// One read buffer per direction. The runtime's *small* relay buffer: the
/// fallback carries a prober's traffic, not a bulk transfer, so there is no
/// promotion to the large one.
const RELAY_BUFFER_SIZE: usize = 16 * 1024;

/// A rate limit on what an unauthenticated visitor may move through the
/// fallback, as Xray's JSON writes it.
///
/// The first `after_bytes` of the flow pass untouched, so that the bytes a real
/// browser exchange needs arrive at the speed the site expects; beyond that the
/// flow is held to `bytes_per_sec`, with `burst_bytes_per_sec` of credit that
/// refills over time. A `bytes_per_sec` of zero is no limit at all, which is
/// what Xray's own default for both fallback limits is.
///
/// The same three fields [`crate::config::RealityServerConfig`] parses out of
/// `limitFallbackUpload` / `limitFallbackDownload` — the same *value*, not a
/// copy of the shape: the settings reader produces this type directly, so a
/// server cannot pass the upload limit where the download limit belongs and
/// notice later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FallbackLimit {
    /// Xray's `afterBytes`: how much may pass before the rate is applied.
    pub after_bytes: u64,
    /// Xray's `bytesPerSec`: the rate after that; zero means unlimited.
    pub bytes_per_sec: u64,
    /// Xray's `burstBytesPerSec`: how much credit may build up. Zero means one
    /// second's worth (`bytes_per_sec`), the rule the runtime's limiter keeps;
    /// Go instead raises a burst below `bytesPerSec` up to one second's worth.
    pub burst_bytes_per_sec: u64,
}

impl FallbackLimit {
    /// The limit Xray's `limitFallbackUpload` / `limitFallbackDownload` object
    /// describes, field for field.
    pub const fn new(after_bytes: u64, bytes_per_sec: u64, burst_bytes_per_sec: u64) -> Self {
        Self {
            after_bytes,
            bytes_per_sec,
            burst_bytes_per_sec,
        }
    }

    /// No limit: what a config with no `limitFallback*` block gets.
    pub const fn unlimited() -> Self {
        Self::new(0, 0, 0)
    }

    /// Whether this limit lets everything through, which is also the condition
    /// under which no shaping is installed at all.
    pub const fn is_unlimited(&self) -> bool {
        self.bytes_per_sec == 0
    }
}

/// What a REALITY server does with a visitor it did not authenticate: the
/// `realitySettings` fields that decide it, and nothing else.
///
/// Built from the same three fields Xray's JSON uses — `xver`,
/// `limitFallbackUpload`, `limitFallbackDownload` — so a config layer can hand
/// them over one for one; there is no serde dependency here, and no validation
/// either, because Xray's parser has already refused an `xver` other than 0, 1
/// or 2 by the time a server has a configuration in hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FallbackPolicy {
    /// Xray's `xver`: the PROXY protocol version to send the target, so it sees
    /// the real client. 0 sends no header, 1 and 2 send that version.
    pub xver: u8,
    /// Xray's `limitFallbackUpload`: what the visitor may send the target.
    pub upload: FallbackLimit,
    /// Xray's `limitFallbackDownload`: what the visitor may take from it.
    pub download: FallbackLimit,
}

impl FallbackPolicy {
    /// The policy Xray's JSON describes.
    pub const fn new(xver: u8, upload: FallbackLimit, download: FallbackLimit) -> Self {
        Self {
            xver,
            upload,
            download,
        }
    }

    /// The PROXY protocol header this policy puts in front of the replayed
    /// hello, or `None` when `xver` is 0.
    ///
    /// `peer` and `local` are the addresses the *target* should be told about:
    /// the visitor's real address (which behind a load balancer is the one the
    /// inbound's own PROXY header named, not the socket's) and the address the
    /// visitor believed it was connecting to. Either may be unknown, and then
    /// the header says so rather than inventing an address
    /// ([`zero_protocol::proxy_protocol::encode`]).
    pub fn proxy_header(
        &self,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> Option<Vec<u8>> {
        (self.xver != 0).then(|| zero_protocol::proxy_protocol::encode(self.xver, peer, local))
    }
}

/// What one fallback moved, in the runtime's accounting: `uploaded` is
/// visitor→target and `downloaded` target→visitor.
///
/// The PROXY header and the replayed hello are *not* counted: they are written
/// before the relay starts, exactly as the runtime counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Transferred {
    pub uploaded: u64,
    pub downloaded: u64,
}

impl Transferred {
    /// Everything that moved, both directions together.
    pub const fn total(&self) -> u64 {
        self.uploaded + self.downloaded
    }
}

/// How one fallback went.
///
/// This is the runtime's `RelayOutcome` under a public name, so the statistics
/// a server keeps — bytes each way, and whether the session counts as useful —
/// are carried over unchanged when the runtime switches to this module.
#[derive(Debug, Clone)]
pub struct FallbackOutcome {
    /// The bytes the relay itself moved, each way.
    pub transferred: Transferred,
    /// The furthest stage the flow reached ([`Stage`]).
    pub stage: Stage,
    /// How long the relay ran, after the hello had been replayed.
    pub elapsed: Duration,
    /// The relay's own end-of-life failure, if any; `None` for an ordinary end.
    ///
    /// A visitor never being REALITY is not an error — it is the point of this
    /// path — so a flow that closes cleanly reports nothing here. A peer that
    /// went quiet for a whole idle period *after* moving bytes does, because
    /// that is a flow that was cut short.
    pub error: Option<String>,
}

impl FallbackOutcome {
    /// Whether the flow moved enough to count as a working path: the visitor
    /// got bytes back from the target, the runtime's rule for a useful session.
    ///
    /// The bytes a visitor *sent* alone do not count. A site that accepts a
    /// request and answers nothing is the shape of a broken camouflage target,
    /// not of a working one, and the runtime counts it as a failure for that
    /// reason.
    pub fn is_useful(&self) -> bool {
        self.stage.is_useful_progress()
    }
}

/// A fallback that could not be *started*: the target never saw a well-formed
/// opening, so there is nothing to report but the attempt.
///
/// A relay that started and then broke is not this: it reports through
/// [`FallbackOutcome::error`] instead, so the bytes that did move are kept.
#[derive(Debug)]
pub enum FallbackError {
    /// The PROXY protocol header could not be written, so the target would read
    /// the hello's bytes as the start of a header it never got.
    ProxyHeader { version: u8, source: io::Error },
    /// The bytes already consumed from the visitor could not be handed to the
    /// target, so the target would see a truncated ClientHello and answer it
    /// with a TLS alert the prober would read as "something is wrong here".
    HelloReplay(io::Error),
}

impl std::fmt::Display for FallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProxyHeader { version, source } => write!(
                f,
                "the version {version} PROXY protocol header could not be sent to the target: {source}"
            ),
            Self::HelloReplay(source) => write!(
                f,
                "the ClientHello already consumed from the visitor could not be replayed to the target: {source}"
            ),
        }
    }
}

impl std::error::Error for FallbackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProxyHeader { source, .. } | Self::HelloReplay(source) => Some(source),
        }
    }
}

/// Hand a visitor that is not REALITY to the camouflage target.
///
/// The caller has already connected to `dest` and passes that connection as
/// `target`; `client` is the socket the ClientHello was consumed from, and
/// `buffered_hello` is exactly those consumed bytes. `peer` and `local` are the
/// addresses the target should be told about when `policy.xver` asks for a
/// PROXY header. `client` and `target` are closed when the relay returns, which
/// is what the caller wants: this connection is over either way.
///
/// Errors are *before* anything is relayed ([`FallbackError`]); once the first
/// byte has been copied, the outcome carries the failure instead.
///
/// The relay runs outside any handshake deadline — to a prober it is an
/// ordinary long-lived session — and is bounded only by
/// [`DEFAULT_IDLE_TIMEOUT`] and, after one direction has finished,
/// [`HALF_CLOSE_IDLE`].
pub async fn relay<C, T>(
    client: C,
    target: T,
    policy: &FallbackPolicy,
    buffered_hello: &[u8],
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
) -> Result<FallbackOutcome, FallbackError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    relay_with_idle_timeout(
        client,
        target,
        policy,
        buffered_hello,
        peer,
        local,
        Some(DEFAULT_IDLE_TIMEOUT),
    )
    .await
}

/// [`relay`] with an explicit idle limit; `None` lets a silent flow live as
/// long as both sockets do.
///
/// The half-close limit stays [`HALF_CLOSE_IDLE`] either way, as in the
/// runtime's `relay_with_idle_timeout`.
pub async fn relay_with_idle_timeout<C, T>(
    client: C,
    target: T,
    policy: &FallbackPolicy,
    buffered_hello: &[u8],
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    idle_timeout: Option<Duration>,
) -> Result<FallbackOutcome, FallbackError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let mut target = target;

    // The target learns who is really connecting, if it asked to.
    if let Some(header) = policy.proxy_header(peer, local) {
        target
            .write_all(&header)
            .await
            .map_err(|source| FallbackError::ProxyHeader {
                version: policy.xver,
                source,
            })?;
    }
    // Then the hello the visitor sent, byte for byte, so the target answers the
    // handshake it thinks it received. Both writes are flushed together: a
    // target that got the header but not the hello would be waiting for a
    // ClientHello that the relay would never repeat.
    target
        .write_all(buffered_hello)
        .await
        .map_err(FallbackError::HelloReplay)?;
    target.flush().await.map_err(FallbackError::HelloReplay)?;

    // An unauthenticated visitor is held to the configured rates, so a probe
    // cannot pull a large file through us from the target or push traffic at
    // it. The wrapper belongs to the direction the stream is *read* in: the
    // client's reads are its uploads, the target's reads are the downloads.
    let mut client = Throttle::new(client, policy.upload);
    let mut target = Throttle::new(target, policy.download);

    let copy = Copy {
        client: &mut client,
        target: &mut target,
        upload: Direction::new(),
        download: Direction::new(),
        idle: idle_timeout
            .filter(|period| !period.is_zero())
            .map(IdleTimer::new),
        half_closed: None,
        // A caller that asked for no idle limit gets no half-close limit
        // either.
        half_close_limit: idle_timeout.map(|_| HALF_CLOSE_IDLE),
        error: None,
        draining: None,
    };
    let CopyResult {
        uploaded,
        downloaded,
        error,
    } = copy.await;

    Ok(FallbackOutcome {
        transferred: Transferred {
            uploaded,
            downloaded,
        },
        stage: stage_of(uploaded, downloaded),
        elapsed: started.elapsed(),
        error,
    })
}

/// The stage a fallback's byte counts reach: the runtime's mapping, so a
/// server's "was this session useful" answer does not change when it switches
/// over.
fn stage_of(uploaded: u64, downloaded: u64) -> Stage {
    match (uploaded, downloaded) {
        (0, 0) => Stage::RequestSent,
        (_, 0) => Stage::UploadConfirmed,
        (0, _) => Stage::PayloadTransferred,
        _ => Stage::BidirectionalConfirmed,
    }
}

/// A rate limit on what is read from a stream, for the traffic of a visitor
/// that has not proved who it is.
///
/// How this works. [`Throttle`] wraps a stream and counts what is read from it.
/// The first `after_bytes` pass untouched, so a real browser-sized exchange with
/// the camouflage site looks normal; beyond that the stream is held to
/// `bytes_per_sec`, with `burst_bytes_per_sec` bytes of credit that refills over
/// time (a token bucket). Writes pass straight through: the limit belongs to the
/// direction the wrapped stream is *read* in, so wrapping the client limits its
/// uploads and wrapping the target limits its downloads.
///
/// The rule it keeps: a limit of zero is no limit, and a throttled read always
/// makes progress (at least one byte per refill tick), so a stream is slowed,
/// never stuck.
///
/// This is `zero-runtime::throttle::Throttle` under a public name, taking
/// [`FallbackLimit`] directly instead of that crate's separate `Limit` type
/// with its renamed `burst` field. The difference from the runtime's copy is
/// that a bounded read here goes through [`ReadBuf::initialize_unfilled`] and so
/// needs no `unsafe`: the runtime instead tells the compiler to
/// `assume_init` the bytes its window read. Zeroing one read window is noise on
/// a prober's traffic, and a fresh crate is a bad place to add an `unsafe` the
/// safe API already covers.
pub struct Throttle<S> {
    inner: S,
    limit: FallbackLimit,
    /// Bytes read so far, to know when `after_bytes` has passed.
    read: u64,
    /// Credit in bytes, and when it was last topped up.
    credit: f64,
    refilled: Instant,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<S> Throttle<S> {
    /// Read from `inner` under `limit`.
    pub fn new(inner: S, limit: FallbackLimit) -> Self {
        let capacity = Self::capacity_of(&limit);
        Self {
            inner,
            limit,
            read: 0,
            credit: capacity,
            refilled: Instant::now(),
            wait: None,
        }
    }

    /// The credit that can build up: the burst, or a second's worth when no
    /// burst is named.
    fn capacity_of(limit: &FallbackLimit) -> f64 {
        if limit.burst_bytes_per_sec == 0 {
            limit.bytes_per_sec as f64
        } else {
            limit.burst_bytes_per_sec as f64
        }
    }

    fn capacity(&self) -> f64 {
        Self::capacity_of(&self.limit)
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let earned =
            now.duration_since(self.refilled).as_secs_f64() * self.limit.bytes_per_sec as f64;
        self.credit = (self.credit + earned).min(self.capacity());
        self.refilled = now;
    }
}

/// Read at most `window` bytes of `buf`'s unfilled space from `reader`, and
/// return how many arrived.
///
/// `initialize_unfilled` is what makes a *bounded* read safe: the slice the
/// inner stream writes into is part of the region `buf` already counts as
/// initialized, so `advance` is sound without telling the compiler anything.
fn read_window<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    window: usize,
) -> Poll<io::Result<usize>>
where
    R: AsyncRead + Unpin,
{
    let unfilled = buf.initialize_unfilled();
    let window = window.min(unfilled.len());
    if window == 0 {
        return Poll::Ready(Ok(0));
    }
    let mut limited = ReadBuf::new(&mut unfilled[..window]);
    ready!(Pin::new(reader).poll_read(cx, &mut limited))?;
    let got = limited.filled().len();
    buf.advance(got);
    Poll::Ready(Ok(got))
}

impl<S: AsyncRead + Unpin> AsyncRead for Throttle<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.limit.is_unlimited() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if this.read < this.limit.after_bytes {
            // Only as much as is still free, so the free part ends where it was
            // said to.
            let free = (this.limit.after_bytes - this.read).min(buf.remaining() as u64) as usize;
            let got = ready!(read_window(&mut this.inner, cx, buf, free))?;
            this.read += got as u64;
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(wait) = this.wait.as_mut() {
                ready!(wait.as_mut().poll(cx));
                this.wait = None;
            }
            this.refill();
            if this.credit < 1.0 {
                // Come back when one byte has been earned, so the stream slows
                // rather than stops.
                let secs = (1.0 - this.credit) / this.limit.bytes_per_sec as f64;
                this.wait = Some(Box::pin(tokio::time::sleep(Duration::from_secs_f64(secs))));
                continue;
            }
            let allowed = (this.credit as usize).min(buf.remaining());
            let got = ready!(read_window(&mut this.inner, cx, buf, allowed))?;
            this.credit -= got as f64;
            this.read += got as u64;
            return Poll::Ready(Ok(()));
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Throttle<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// One direction of a relay: what has been read, what is still to be written
/// out, and whether that end of the flow is finished.
struct Direction {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
    read_done: bool,
    need_flush: bool,
    total: u64,
    /// Bumped on every successful read or write, so the idle timer can tell a
    /// quiet flow from a busy one without touching the clock per chunk.
    activity: u64,
    shut_down: bool,
    done: bool,
    error: Option<String>,
}

impl Direction {
    fn new() -> Self {
        Self {
            buf: vec![0u8; RELAY_BUFFER_SIZE].into_boxed_slice(),
            pos: 0,
            cap: 0,
            read_done: false,
            need_flush: false,
            total: 0,
            activity: 0,
            shut_down: false,
            done: false,
            error: None,
        }
    }

    fn fail(&mut self, error: io::Error) -> Poll<io::Result<()>> {
        self.error = Some(error.to_string());
        self.done = true;
        Poll::Ready(Err(error))
    }

    /// Move as much as the reader and writer will take right now. `Ready` means
    /// this direction is finished, either way.
    fn poll_copy_step<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        if self.done {
            return Poll::Ready(Ok(()));
        }

        loop {
            // 1. If the buffer has data, write it out.
            while self.pos < self.cap {
                match writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap])
                {
                    Poll::Ready(Ok(0)) => {
                        return self.fail(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into writer",
                        ));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.pos += n;
                        self.total += n as u64;
                        self.activity = self.activity.wrapping_add(1);
                        self.need_flush = true;
                    }
                    Poll::Ready(Err(e)) => return self.fail(e),
                    Poll::Pending => return Poll::Pending,
                }
            }
            self.pos = 0;
            self.cap = 0;

            // 2. If the read is not done, try to read into the buffer.
            if !self.read_done {
                let mut read_buf = ReadBuf::new(&mut self.buf);
                match reader.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cap = n;
                            self.activity = self.activity.wrapping_add(1);
                            // Loop around to write immediately without
                            // yielding.
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return self.fail(e),
                    Poll::Pending => {
                        // The reader has nothing right now. If data was written
                        // earlier, flush it so the peer receives it without
                        // waiting for a second write.
                        if self.need_flush {
                            match writer.as_mut().poll_flush(cx) {
                                Poll::Ready(Ok(())) => self.need_flush = false,
                                Poll::Ready(Err(e)) => return self.fail(e),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        return Poll::Pending;
                    }
                }
            }

            // 3. Read done and buffer empty: flush, then half-close the writer,
            //    so the peer sees end-of-stream while the other direction keeps
            //    running. This is Go's `CloseWrite` in `tls.go`, and the reason
            //    a visitor that has finished its request still receives the
            //    whole response.
            if self.need_flush {
                match writer.as_mut().poll_flush(cx) {
                    Poll::Ready(Ok(())) => self.need_flush = false,
                    Poll::Ready(Err(e)) => return self.fail(e),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if !self.shut_down {
                match writer.as_mut().poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        // The peer may be gone entirely, which is not worth a
                        // failure: the flow is over either way.
                        if !matches!(
                            e.kind(),
                            io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe
                        ) {
                            self.error = Some(e.to_string());
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
                self.shut_down = true;
            }

            self.done = true;
            return Poll::Ready(Ok(()));
        }
    }
}

/// Idle detection that does not re-arm a timer per chunk: the timer is armed
/// once per period, and when it fires the activity counters decide whether the
/// flow was quiet for the whole period or merely needs the timer pushed out. A
/// flow is therefore closed between one and two periods after its last byte.
struct IdleTimer {
    period: Duration,
    sleep: Pin<Box<Sleep>>,
    seen: u64,
}

impl IdleTimer {
    fn new(period: Duration) -> Self {
        Self {
            period,
            sleep: Box::pin(tokio::time::sleep(period)),
            seen: 0,
        }
    }

    /// `true` once the flow has been idle for a full period.
    fn poll_expired(&mut self, cx: &mut Context<'_>, activity: u64) -> bool {
        loop {
            if self.sleep.as_mut().poll(cx).is_pending() {
                return false;
            }
            if activity == self.seen {
                return true;
            }
            self.seen = activity;
            let next = Instant::now() + self.period;
            self.sleep.as_mut().reset(next);
        }
    }
}

/// Both directions at once, without `tokio::io::split` or a mutex: one future
/// drives two copies, so a half-closed flow keeps the other side alive.
struct Copy<'a, C, T> {
    client: &'a mut Throttle<C>,
    target: &'a mut Throttle<T>,
    upload: Direction,
    download: Direction,
    idle: Option<IdleTimer>,
    /// Armed when exactly one direction has finished; see [`HALF_CLOSE_IDLE`].
    half_closed: Option<IdleTimer>,
    half_close_limit: Option<Duration>,
    /// The failure that ended one direction, kept so the outcome can report
    /// it once the other direction has had its chance.
    error: Option<String>,
    /// Armed when one direction failed and the other may still deliver; see
    /// [`DRAIN_AFTER_ERROR`].
    draining: Option<IdleTimer>,
}

struct CopyResult {
    uploaded: u64,
    downloaded: u64,
    error: Option<String>,
}

impl<C, T> Future for Copy<'_, C, T>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = CopyResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        // Target to visitor first, then visitor to target.
        //
        // The order is the point. A target that has already answered — a
        // camouflage site's alert, a `400`, a redirect — is waiting to be
        // read, and the answer is on the wire whether or not this side
        // failed. Reading it first gives it the best chance of being
        // delivered: a target that hangs up while its answer is in flight
        // makes the kernel reset the connection, and a reset discards
        // whatever was queued but not yet read. Go reads the target in its
        // own goroutine, armed from the first moment, so the answer is
        // taken off the socket before the reset can take it away.
        let _ = this.download.poll_copy_step(
            cx,
            Pin::new(&mut *this.target),
            Pin::new(&mut *this.client),
        );
        let _ = this.upload.poll_copy_step(
            cx,
            Pin::new(&mut *this.client),
            Pin::new(&mut *this.target),
        );

        // A failure in one direction does not silence the other: the peer
        // may already have sent the answer the visitor is waiting for.
        if this.error.is_none() {
            this.error = this
                .upload
                .error
                .clone()
                .or_else(|| this.download.error.clone());
            if this.error.is_some() {
                this.draining = Some(IdleTimer::new(DRAIN_AFTER_ERROR));
            }
        }
        if (this.upload.done && this.download.done) || (this.error.is_some() && this.drained(cx)) {
            return Poll::Ready(CopyResult {
                uploaded: this.upload.total,
                downloaded: this.download.total,
                error: this.error.take(),
            });
        }

        let activity = this.upload.activity.wrapping_add(this.download.activity);
        if this.upload.done != this.download.done {
            if let Some(limit) = this.half_close_limit {
                let timer = this
                    .half_closed
                    .get_or_insert_with(|| IdleTimer::new(limit));
                if timer.poll_expired(cx, activity) {
                    // The remaining side had its chance to finish; this is an
                    // ordinary end of the flow, not a failure.
                    return Poll::Ready(CopyResult {
                        uploaded: this.upload.total,
                        downloaded: this.download.total,
                        error: self.error.take(),
                    });
                }
            }
        }
        if let Some(idle) = this.idle.as_mut() {
            if idle.poll_expired(cx, activity) {
                let (uploaded, downloaded) = (this.upload.total, this.download.total);
                // A flow on which nothing ever moved says nothing about the
                // path — the visitor simply never used it — so it closes
                // exactly like a visitor that hung up. A flow that sent and
                // then heard nothing for a whole period was cut short.
                let error = (uploaded > 0 || downloaded > 0)
                    .then(|| format!("relay idle timeout after {}s", idle.period.as_secs()));
                return Poll::Ready(CopyResult {
                    uploaded,
                    downloaded,
                    error,
                });
            }
        }

        Poll::Pending
    }
}

impl<C, T> Copy<'_, C, T> {
    /// Has the surviving direction had its grace to deliver what the peer
    /// already sent?
    ///
    /// The timer is armed when a direction fails, and it expires
    /// [`DRAIN_AFTER_ERROR`] later unless the surviving direction moves
    /// something in the meantime — an answer that arrives late still counts,
    /// so the timer is pushed out while the flow is alive.
    fn drained(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(timer) = self.draining.as_mut() else {
            return true;
        };
        let activity = self.upload.activity.wrapping_add(self.download.activity);
        timer.poll_expired(cx, activity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a socket address literal")
    }

    /// The bytes one direction takes to move something at a rate, with no
    /// socket in the way: the limiter's own behavior, without a relay's.
    async fn time_to_move(total: usize, limit: FallbackLimit) -> Duration {
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            writer.write_all(&vec![7u8; total]).await.unwrap();
        });
        let mut throttled = Throttle::new(reader, limit);
        let started = std::time::Instant::now();
        let mut got = 0;
        let mut buffer = [0u8; 4096];
        while got < total {
            let n = throttled.read(&mut buffer).await.unwrap();
            assert!(n > 0, "the stream ended early");
            got += n;
        }
        started.elapsed()
    }

    #[test]
    fn xver_zero_is_no_header_and_a_zero_rate_is_no_limit() {
        let policy = FallbackPolicy::default();
        assert_eq!(policy.xver, 0);
        assert_eq!(policy.upload, FallbackLimit::unlimited());
        assert!(policy.upload.is_unlimited() && policy.download.is_unlimited());
        // The failure this prevents: a server with no `xver` in its config
        // sending the target a header it never asked for, which that target
        // would read as the first bytes of the ClientHello.
        assert_eq!(
            policy.proxy_header(Some(addr("192.0.2.1:1")), Some(addr("198.51.100.7:2"))),
            None
        );
    }

    #[test]
    fn the_version_one_header_is_the_specification_line() {
        let policy = FallbackPolicy::new(1, FallbackLimit::unlimited(), FallbackLimit::unlimited());
        let (peer, local) = (addr("192.0.2.1:56324"), addr("198.51.100.7:443"));
        let header = policy
            .proxy_header(Some(peer), Some(local))
            .expect("a header");
        assert_eq!(header, b"PROXY TCP4 192.0.2.1 198.51.100.7 56324 443\r\n");
        // The same bytes the workspace encoder writes, so that what the target
        // reads and what the rest of the tree would write cannot drift apart.
        assert_eq!(
            header,
            zero_protocol::proxy_protocol::encode(1, Some(peer), Some(local))
        );
    }

    #[test]
    fn the_version_two_header_is_the_signature_and_the_addresses() {
        let policy = FallbackPolicy::new(2, FallbackLimit::unlimited(), FallbackLimit::unlimited());
        let (peer, local) = (addr("192.0.2.1:56324"), addr("198.51.100.7:443"));
        let header = policy
            .proxy_header(Some(peer), Some(local))
            .expect("a header");
        assert_eq!(
            header,
            zero_protocol::proxy_protocol::encode(2, Some(peer), Some(local))
        );

        // Hand-written from the specification: the 12-byte signature, then
        // version 2 with the PROXY command, the INET stream family and twelve
        // bytes of address, then the four address bytes each way and the two
        // ports.
        let mut literal = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        literal.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        literal.extend_from_slice(&[192, 0, 2, 1]);
        literal.extend_from_slice(&[198, 51, 100, 7]);
        literal.extend_from_slice(&56324u16.to_be_bytes());
        literal.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(header, literal);
        assert_eq!(header.len(), 28);
    }

    #[test]
    fn addresses_that_cannot_be_one_connection_are_announced_as_unknown() {
        // Behind a load balancer, or with an inbound that never learned where
        // the client was, a header must say so rather than claim an address.
        let v1 = FallbackPolicy::new(1, FallbackLimit::unlimited(), FallbackLimit::unlimited());
        assert_eq!(
            v1.proxy_header(None, None).expect("a header"),
            b"PROXY UNKNOWN\r\n"
        );
        // A visitor and a destination of different families are not one
        // connection either.
        assert_eq!(
            v1.proxy_header(Some(addr("192.0.2.1:1")), Some(addr("[2001:db8::2]:2")))
                .expect("a header"),
            b"PROXY UNKNOWN\r\n"
        );
        let v2 = FallbackPolicy::new(2, FallbackLimit::unlimited(), FallbackLimit::unlimited());
        let local_command = v2.proxy_header(None, None).expect("a header");
        assert_eq!(
            local_command,
            zero_protocol::proxy_protocol::encode(2, None, None)
        );
        assert_eq!(&local_command[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&local_command[12..16], &[0x20, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn usefulness_still_follows_the_runtime_rule() {
        let outcome = |uploaded, downloaded| FallbackOutcome {
            transferred: Transferred {
                uploaded,
                downloaded,
            },
            stage: stage_of(uploaded, downloaded),
            elapsed: Duration::ZERO,
            error: None,
        };
        assert_eq!(outcome(0, 0).stage, Stage::RequestSent);
        // A visitor that sent a request the target never answered is the shape
        // of a broken camouflage target, not a working one.
        assert!(!outcome(9, 0).is_useful());
        assert_eq!(outcome(9, 0).stage, Stage::UploadConfirmed);
        assert!(outcome(0, 9).is_useful());
        assert!(outcome(9, 9).is_useful());
        assert_eq!(outcome(9, 9).stage, Stage::BidirectionalConfirmed);
        assert_eq!(outcome(9, 9).transferred.total(), 18);
    }

    #[tokio::test]
    async fn a_zero_rate_leaves_the_stream_alone() {
        // The failure this prevents: a "limit" nobody configured slowing every
        // visitor's exchange with the camouflage site.
        let elapsed = time_to_move(64 * 1024, FallbackLimit::unlimited()).await;
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn the_bytes_before_after_bytes_are_not_slowed() {
        // A real browser-sized exchange has to look ordinary, so the free part
        // must not be shaped: 1 byte per second here would hold this test for
        // days if `after_bytes` were ignored.
        let limit = FallbackLimit::new(32 * 1024, 1, 1);
        let elapsed = time_to_move(32 * 1024, limit).await;
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn after_the_free_prefix_the_rate_is_held() {
        // The failure this prevents: a limit a probe walks straight through.
        // 1000 bytes free, then 4000 more at 2000 per second with a 500 byte
        // burst: 500 go at once and the other 3500 take about 1.75 seconds.
        let limit = FallbackLimit::new(1000, 2000, 500);
        let elapsed = time_to_move(5000, limit).await;
        assert!(
            elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(4),
            "{elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_named_burst_is_the_credit_that_builds_up() {
        // No burst means one second's worth; a smaller burst must mean a
        // smaller burst, or a configured burst is a lie.
        let limit = FallbackLimit::new(0, 8000, 1000);
        let elapsed = time_to_move(3000, limit).await;
        // 1000 at once, the other 2000 at 8000 per second: a quarter second.
        assert!(
            elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
    }
}
