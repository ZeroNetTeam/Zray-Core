//! Per-account figures and control, for a server that sells accounts.
//!
//! A panel in front of a server needs three things the per-inbound figures
//! cannot give it: how much each account (its `email`) has moved, which
//! accounts are connected now, and a way to end an account's sessions the
//! moment its quota or its time runs out.
//!
//! How this works. Once an inbound has authenticated an account, the client
//! stream is wrapped in [`Metered`]. Every byte read from it is added to the
//! account's uplink and every byte written to it to its downlink *as it
//! moves*, so an hours-long download is visible while it runs rather than
//! when it closes. The wrapper also registers its session with the account
//! for as long as it lives, which is what [`Accounts::online`] reads and what
//! [`Accounts::end_sessions`] reaches: ending a session marks it and wakes
//! its task, and its next read or write fails, which ends the relay the way
//! any broken connection does.
//!
//! A speed limit ([`Accounts::set_limit`]) is one token bucket per account
//! and direction, shared by all its sessions, so opening more connections
//! does not buy more speed. Each read or write takes what the bucket holds
//! (at most one second's worth builds up) and, when it is empty, waits until
//! a byte has been earned. Concurrent sessions may overdraw the bucket by one
//! read each; the debt is paid back before the next byte moves.
//!
//! The rules it keeps:
//!  * an account without an `email` is not metered: there is no name to
//!    report it under;
//!  * client addresses are not kept unless the host asks for them
//!    ([`Accounts::set_track_addresses`]). The usage figures promise that no
//!    address is stored ([`crate::usage`]); a panel that enforces per-account
//!    address limits has to opt in to knowing them, and only the addresses of
//!    sessions open *now* are held, never a history.
//!
//! What it cannot do: a session whose relay is waiting on the remote side in
//! both directions is not polled on the client side, so it ends when the
//! remote next moves or the idle limit closes it, not at once.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Every account the server has metered, by `email`.
#[derive(Default)]
pub struct Accounts {
    entries: RwLock<HashMap<Arc<str>, Arc<Account>>>,
    /// Speed limits by `email`. Kept apart from `entries`, which forgets an
    /// account with no session, so a limit outlives the account's sessions.
    limits: Mutex<HashMap<Arc<str>, Arc<RateLimit>>>,
    track_addresses: AtomicBool,
    next_session: AtomicU64,
    events: Arc<crate::events::Events>,
}

impl std::fmt::Debug for Accounts {
    // Account names and addresses do not belong in a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Accounts { .. }")
    }
}

struct Account {
    uplink: AtomicU64,
    downlink: AtomicU64,
    sessions: Mutex<HashMap<u64, Arc<Session>>>,
    limit: Arc<RateLimit>,
}

/// The longest a read or write waits on a speed limit before looking again.
const LIMIT_RECHECK: Duration = Duration::from_millis(100);

/// An account's speed limit, one bucket per direction.
#[derive(Default)]
struct RateLimit {
    uplink: Bucket,
    downlink: Bucket,
}

/// A token bucket shared by every session of an account. A rate of zero is
/// no limit, and costs one atomic load per read or write.
#[derive(Default)]
struct Bucket {
    /// Bytes per second; 0 is unlimited.
    rate: AtomicU64,
    /// Credit in bytes (negative while in debt) and when it was last topped
    /// up; `None` until first used, when it starts full.
    state: Mutex<(f64, Option<Instant>)>,
}

impl Bucket {
    fn set(&self, rate: u64) {
        self.rate.store(rate, Ordering::Relaxed);
        *lock(&self.state) = (0.0, None);
    }

    fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    /// How many of `want` bytes may move now, or how long until one may.
    fn allowance(&self, want: usize) -> Result<usize, Duration> {
        let rate = self.rate();
        if rate == 0 || want == 0 {
            return Ok(want);
        }
        let capacity = rate as f64;
        let now = Instant::now();
        let mut state = lock(&self.state);
        let (credit, refilled) = &mut *state;
        *credit = match refilled {
            None => capacity,
            Some(then) => {
                (*credit + now.duration_since(*then).as_secs_f64() * capacity).min(capacity)
            }
        };
        *refilled = Some(now);
        if *credit < 1.0 {
            // Never more than LIMIT_RECHECK at a time, so a limit that is
            // raised or lifted reaches a waiting session promptly even when
            // the debt under the old one would take far longer to repay.
            let wait = Duration::from_secs_f64((1.0 - *credit) / capacity);
            return Err(wait.clamp(Duration::from_millis(1), LIMIT_RECHECK));
        }
        Ok((*credit as usize).min(want))
    }

    fn charge(&self, bytes: usize) {
        if bytes == 0 || self.rate() == 0 {
            return;
        }
        lock(&self.state).0 -= bytes as f64;
    }
}

/// Wait until `bucket` lets at least one of `want` bytes move, then say how
/// many may.
fn poll_allowance(
    bucket: &Bucket,
    wait: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
    want: usize,
) -> Poll<usize> {
    loop {
        if let Some(sleep) = wait.as_mut() {
            ready!(sleep.as_mut().poll(cx));
            *wait = None;
        }
        match bucket.allowance(want) {
            Ok(allowed) => return Poll::Ready(allowed),
            Err(delay) => *wait = Some(Box::pin(tokio::time::sleep(delay))),
        }
    }
}

struct Session {
    inbound: Arc<str>,
    address: Option<IpAddr>,
    ended: AtomicBool,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl Session {
    fn end(&self) {
        self.ended.store(true, Ordering::Release);
        self.read_waker.wake();
        self.write_waker.wake();
    }

    fn is_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }
}

/// One account's bytes, as [`Accounts::traffic`] reports them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AccountTraffic {
    pub email: String,
    /// Client → destination.
    pub uplink: u64,
    /// Destination → client.
    pub downlink: u64,
}

/// One account's speed limit, as [`Accounts::limits`] reports it, in bytes
/// per second; 0 is unlimited.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AccountLimit {
    pub email: String,
    pub uplink: u64,
    pub downlink: u64,
}

/// One connected account, as [`Accounts::online`] reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OnlineAccount {
    pub email: String,
    pub sessions: u64,
    /// The distinct addresses of its open sessions, sorted; empty unless
    /// address tracking is on.
    pub addresses: Vec<IpAddr>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Accounts {
    /// Keep the client address of each open session, so that
    /// [`Accounts::online`] can report it. Applies to sessions opened from
    /// now on.
    pub fn set_track_addresses(&self, on: bool) {
        self.track_addresses.store(on, Ordering::Relaxed);
    }

    pub fn tracks_addresses(&self) -> bool {
        self.track_addresses.load(Ordering::Relaxed)
    }

    /// The server's live events ([`crate::events`]).
    pub fn events(&self) -> &Arc<crate::events::Events> {
        &self.events
    }

    /// Meter `stream` as a session of `email` on `inbound`, from `peer`. The
    /// session counts as open until the returned stream is dropped.
    pub fn meter<S>(
        &self,
        email: &Arc<str>,
        inbound: &Arc<str>,
        peer: IpAddr,
        stream: S,
    ) -> Metered<S> {
        let session = Arc::new(Session {
            inbound: Arc::clone(inbound),
            address: self.tracks_addresses().then_some(peer),
            ended: AtomicBool::new(false),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        });
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        // Registered under the map's read lock, so that `traffic(true)`, which
        // drops idle accounts under the write lock, cannot drop this one
        // between finding it and registering the session.
        let account = {
            let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
            entries.get(email).cloned().inspect(|account| {
                lock(&account.sessions).insert(id, Arc::clone(&session));
            })
        };
        let account = account.unwrap_or_else(|| {
            let limit = self.limit_of(email);
            let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
            let account = Arc::clone(entries.entry(Arc::clone(email)).or_insert_with(|| {
                Arc::new(Account {
                    uplink: AtomicU64::new(0),
                    downlink: AtomicU64::new(0),
                    sessions: Mutex::default(),
                    limit,
                })
            }));
            lock(&account.sessions).insert(id, Arc::clone(&session));
            account
        });
        self.events.emit(|| crate::events::Event::SessionOpened {
            email: email.to_string(),
            inbound: inbound.to_string(),
            address: session.address,
        });
        Metered {
            inner: stream,
            account,
            session,
            id,
            read_wait: None,
            write_wait: None,
            email: Arc::clone(email),
            events: Arc::clone(&self.events),
            opened: Instant::now(),
            uplink: 0,
            downlink: 0,
        }
    }

    fn limit_of(&self, email: &Arc<str>) -> Arc<RateLimit> {
        Arc::clone(lock(&self.limits).entry(Arc::clone(email)).or_default())
    }

    /// Hold `email` to `uplink` and `downlink` bytes per second across all its
    /// sessions; 0 lifts that direction's limit. Applies at once, to sessions
    /// already open too.
    pub fn set_limit(&self, email: &str, uplink: u64, downlink: u64) {
        let email: Arc<str> = Arc::from(email);
        let limit = self.limit_of(&email);
        // Updated in place, never replaced: open sessions hold these buckets.
        limit.uplink.set(uplink);
        limit.downlink.set(downlink);
        self.events.emit(|| crate::events::Event::LimitChanged {
            email: email.to_string(),
            uplink,
            downlink,
        });
    }

    /// The accounts with a speed limit, sorted by `email`.
    pub fn limits(&self) -> Vec<AccountLimit> {
        let mut limits: Vec<AccountLimit> = lock(&self.limits)
            .iter()
            .map(|(email, limit)| AccountLimit {
                email: email.to_string(),
                uplink: limit.uplink.rate(),
                downlink: limit.downlink.rate(),
            })
            .filter(|limit| limit.uplink > 0 || limit.downlink > 0)
            .collect();
        limits.sort_by(|a, b| a.email.cmp(&b.email));
        limits
    }

    /// Count bytes moved for `email` outside a metered stream: a UDP
    /// datagram and its answer.
    pub fn count(&self, email: &Arc<str>, uplink: usize, downlink: usize) {
        let account = {
            let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
            entries.get(email).cloned()
        };
        let account = account.unwrap_or_else(|| {
            let limit = self.limit_of(email);
            let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
            Arc::clone(entries.entry(Arc::clone(email)).or_insert_with(|| {
                Arc::new(Account {
                    uplink: AtomicU64::new(0),
                    downlink: AtomicU64::new(0),
                    sessions: Mutex::default(),
                    limit,
                })
            }))
        });
        account.uplink.fetch_add(uplink as u64, Ordering::Relaxed);
        account
            .downlink
            .fetch_add(downlink as u64, Ordering::Relaxed);
    }

    /// Bytes per account, sorted by `email`. `reset` zeroes each counter as it
    /// is read (Xray's `QueryStats reset=true`) and forgets accounts with no
    /// open session, so a removed account does not linger in the report.
    pub fn traffic(&self, reset: bool) -> Vec<AccountTraffic> {
        let read = |counter: &AtomicU64| {
            if reset {
                counter.swap(0, Ordering::Relaxed)
            } else {
                counter.load(Ordering::Relaxed)
            }
        };
        let report = |(email, account): (&Arc<str>, &Arc<Account>)| AccountTraffic {
            email: email.to_string(),
            uplink: read(&account.uplink),
            downlink: read(&account.downlink),
        };
        let mut traffic: Vec<AccountTraffic> = if reset {
            let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
            let traffic = entries.iter().map(report).collect();
            entries.retain(|_, account| !lock(&account.sessions).is_empty());
            traffic
        } else {
            let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
            entries.iter().map(report).collect()
        };
        traffic.retain(|t| t.uplink > 0 || t.downlink > 0);
        traffic.sort_by(|a, b| a.email.cmp(&b.email));
        traffic
    }

    /// The accounts with at least one session open now, sorted by `email`.
    pub fn online(&self) -> Vec<OnlineAccount> {
        let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
        let mut online: Vec<OnlineAccount> = entries
            .iter()
            .filter_map(|(email, account)| {
                let sessions = lock(&account.sessions);
                let open: Vec<&Arc<Session>> =
                    sessions.values().filter(|s| !s.is_ended()).collect();
                if open.is_empty() {
                    return None;
                }
                let mut addresses: Vec<IpAddr> = open.iter().filter_map(|s| s.address).collect();
                addresses.sort_unstable();
                addresses.dedup();
                Some(OnlineAccount {
                    email: email.to_string(),
                    sessions: open.len() as u64,
                    addresses,
                })
            })
            .collect();
        online.sort_by(|a, b| a.email.cmp(&b.email));
        online
    }

    /// End every open session of `email`. Returns how many were ended.
    pub fn end_sessions(&self, email: &str) -> usize {
        let sessions = self.end_where(|session_email, _| session_email == email);
        if sessions > 0 {
            self.events.emit(|| crate::events::Event::SessionsEnded {
                email: email.to_string(),
                sessions,
            });
        }
        sessions
    }

    /// End the open sessions for which `stale(email, inbound)` is true.
    /// Returns how many were ended.
    pub fn end_where(&self, stale: impl Fn(&str, &str) -> bool) -> usize {
        let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
        let mut ended = 0;
        for (email, account) in entries.iter() {
            for session in lock(&account.sessions).values() {
                if !session.is_ended() && stale(email, &session.inbound) {
                    session.end();
                    ended += 1;
                }
            }
        }
        ended
    }
}

/// A client stream metered for one account (see [`Accounts::meter`]).
pub struct Metered<S> {
    inner: S,
    account: Arc<Account>,
    session: Arc<Session>,
    id: u64,
    /// Set while a read or a write waits for the speed limit.
    read_wait: Option<Pin<Box<Sleep>>>,
    write_wait: Option<Pin<Box<Sleep>>>,
    /// For the event that reports this session when it closes.
    email: Arc<str>,
    events: Arc<crate::events::Events>,
    opened: Instant,
    uplink: u64,
    downlink: u64,
}

impl<S> Metered<S> {
    /// Count `bytes` the inbound read from this client before the account was
    /// known: the payload that arrived in the same packets as the request
    /// header and is replayed ahead of the stream.
    pub fn with_early_payload(mut self, bytes: usize) -> Self {
        self.account
            .uplink
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.uplink += bytes as u64;
        self
    }
}

impl<S> Drop for Metered<S> {
    fn drop(&mut self) {
        lock(&self.account.sessions).remove(&self.id);
        self.events.emit(|| crate::events::Event::SessionClosed {
            email: self.email.to_string(),
            inbound: self.session.inbound.to_string(),
            uplink: self.uplink,
            downlink: self.downlink,
            seconds: self.opened.elapsed().as_secs_f64(),
            ended: self.session.is_ended(),
        });
    }
}

fn ended_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the account's sessions were ended",
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.session.is_ended() {
            return Poll::Ready(Err(ended_error()));
        }
        let bucket = &this.account.limit.uplink;
        let allowed = match poll_allowance(bucket, &mut this.read_wait, cx, buf.remaining()) {
            Poll::Ready(allowed) => allowed,
            Poll::Pending => return this.parked_read(cx),
        };
        let got = if allowed < buf.remaining() {
            // Read only what the limit allows, through a window onto `buf`.
            let mut window = buf.take(allowed);
            match Pin::new(&mut this.inner).poll_read(cx, &mut window) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return this.parked_read(cx),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
            let got = window.filled().len();
            // SAFETY: `got` bytes of the unfilled part were just written by
            // the inner read, through the window onto the same memory.
            unsafe { buf.assume_init(got) };
            buf.advance(got);
            got
        } else {
            let before = buf.filled().len();
            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return this.parked_read(cx),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
            buf.filled().len() - before
        };
        bucket.charge(got);
        this.account.uplink.fetch_add(got as u64, Ordering::Relaxed);
        this.uplink += got as u64;
        Poll::Ready(Ok(()))
    }
}

impl<S> Metered<S> {
    /// A read is waiting (for the client or for the speed limit): make sure
    /// ending the session wakes it.
    fn parked_read<T>(&self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        // Registered after the first check, so re-checked: an end that landed
        // in between would otherwise wake nobody.
        self.session.read_waker.register(cx.waker());
        if self.session.is_ended() {
            return Poll::Ready(Err(ended_error()));
        }
        Poll::Pending
    }

    fn parked_write<T>(&self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        self.session.write_waker.register(cx.waker());
        if self.session.is_ended() {
            return Poll::Ready(Err(ended_error()));
        }
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> Metered<S> {
    /// Write what the speed limit allows of `data`.
    fn limited_write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.session.is_ended() {
            return Poll::Ready(Err(ended_error()));
        }
        let bucket = &self.account.limit.downlink;
        let allowed = match poll_allowance(bucket, &mut self.write_wait, cx, data.len()) {
            Poll::Ready(allowed) => allowed,
            Poll::Pending => return self.parked_write(cx),
        };
        match Pin::new(&mut self.inner).poll_write(cx, &data[..allowed]) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(self.written(n))),
            Poll::Pending => self.parked_write(cx),
            other => other,
        }
    }

    fn written(&mut self, n: usize) -> usize {
        self.account.limit.downlink.charge(n);
        self.account.downlink.fetch_add(n as u64, Ordering::Relaxed);
        self.downlink += n as u64;
        n
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.limited_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.account.limit.downlink.rate() != 0 {
            // Limited: one slice at a time is simplest to hold to the rate.
            let first = bufs
                .iter()
                .find(|buf| !buf.is_empty())
                .map_or(&[][..], |b| &**b);
            return self.limited_write(cx, first);
        }
        if self.session.is_ended() {
            return Poll::Ready(Err(ended_error()));
        }
        match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(self.written(n))),
            Poll::Pending => self.parked_write(cx),
            other => other,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    fn name(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    #[tokio::test]
    async fn bytes_are_counted_while_the_session_is_still_open() {
        let accounts = Accounts::default();
        let (client, mut far) = tokio::io::duplex(1024);
        let mut metered = accounts.meter(&name("alice"), &name("vless-in"), PEER, client);

        far.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        metered.read_exact(&mut buf).await.unwrap();
        metered.write_all(b"0123456789").await.unwrap();

        // Still open: the figures are already there.
        assert_eq!(
            accounts.traffic(false),
            vec![AccountTraffic {
                email: "alice".into(),
                uplink: 5,
                downlink: 10
            }]
        );
        drop(metered);
    }

    #[tokio::test]
    async fn reset_zeroes_and_forgets_accounts_with_no_session() {
        let accounts = Accounts::default();
        let (client, _far) = tokio::io::duplex(64);
        let mut metered = accounts.meter(&name("bob"), &name("in"), PEER, client);
        metered.write_all(b"abc").await.unwrap();
        drop(metered);

        assert_eq!(accounts.traffic(true)[0].downlink, 3);
        assert!(accounts.traffic(false).is_empty());
        assert!(accounts.entries.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn online_lists_open_sessions_and_addresses_only_when_asked() {
        let accounts = Accounts::default();
        let (a, _fa) = tokio::io::duplex(64);
        let first = accounts.meter(&name("carol"), &name("in"), PEER, a);
        let online = accounts.online();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].sessions, 1);
        assert!(
            online[0].addresses.is_empty(),
            "no address without opting in"
        );

        accounts.set_track_addresses(true);
        let (b, _fb) = tokio::io::duplex(64);
        let second = accounts.meter(&name("carol"), &name("in"), PEER, b);
        let online = accounts.online();
        assert_eq!(online[0].sessions, 2);
        assert_eq!(online[0].addresses, vec![PEER]);

        drop(first);
        drop(second);
        assert!(accounts.online().is_empty());
    }

    #[tokio::test]
    async fn ending_wakes_a_session_that_is_waiting_to_read() {
        let accounts = Arc::new(Accounts::default());
        let (client, _far) = tokio::io::duplex(64);
        let mut metered = accounts.meter(&name("dave"), &name("in"), PEER, client);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            metered.read(&mut buf).await
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        assert_eq!(accounts.end_sessions("dave"), 1);
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .expect("an ended session must not stay parked")
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn end_where_reaches_only_the_matching_inbound() {
        let accounts = Accounts::default();
        let (a, _fa) = tokio::io::duplex(64);
        let (b, _fb) = tokio::io::duplex(64);
        let mut on_a = accounts.meter(&name("erin"), &name("a"), PEER, a);
        let mut on_b = accounts.meter(&name("erin"), &name("b"), PEER, b);

        assert_eq!(accounts.end_where(|_, inbound| inbound == "a"), 1);
        assert!(on_a.write_all(b"x").await.is_err());
        assert!(on_b.write_all(b"x").await.is_ok());
    }

    /// Write `total` bytes into a metered stream of `email` and say how long
    /// the far end took to receive them.
    async fn time_to_send(accounts: &Arc<Accounts>, email: &str, total: usize) -> Duration {
        let (client, mut far) = tokio::io::duplex(256 * 1024);
        let mut metered = accounts.meter(&name(email), &name("in"), PEER, client);
        let started = std::time::Instant::now();
        let writer = tokio::spawn(async move {
            metered.write_all(&vec![1u8; total]).await.unwrap();
            metered
        });
        let mut got = 0;
        let mut buf = vec![0u8; 64 * 1024];
        while got < total {
            got += far.read(&mut buf).await.unwrap();
        }
        drop(writer.await.unwrap());
        started.elapsed()
    }

    #[tokio::test]
    async fn a_speed_limit_holds_the_account_to_its_rate() {
        let accounts = Arc::new(Accounts::default());
        // 40 KB at 20 KB/s with 20 KB of burst: about one second.
        accounts.set_limit("slow", 0, 20_000);
        let elapsed = time_to_send(&accounts, "slow", 40_000).await;
        assert!(elapsed >= Duration::from_millis(800), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(2500), "{elapsed:?}");
        // Another account is not slowed.
        let elapsed = time_to_send(&accounts, "fast", 400_000).await;
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
        assert_eq!(
            accounts.limits(),
            vec![AccountLimit {
                email: "slow".into(),
                uplink: 0,
                downlink: 20_000
            }]
        );
    }

    #[tokio::test]
    async fn sessions_of_one_account_share_its_limit() {
        let accounts = Arc::new(Accounts::default());
        accounts.set_limit("shared", 0, 20_000);
        // Two sessions of 20 KB each: together 40 KB, about a second, where
        // a per-session limit would let both finish at once.
        let started = std::time::Instant::now();
        let a = tokio::spawn({
            let accounts = Arc::clone(&accounts);
            async move { time_to_send(&accounts, "shared", 20_000).await }
        });
        let b = tokio::spawn({
            let accounts = Arc::clone(&accounts);
            async move { time_to_send(&accounts, "shared", 20_000).await }
        });
        a.await.unwrap();
        b.await.unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(800), "{elapsed:?}");
    }

    #[tokio::test]
    async fn the_uplink_limit_slows_reads_and_lifting_it_applies_at_once() {
        let accounts = Arc::new(Accounts::default());
        accounts.set_limit("up", 10_000, 0);
        let (client, mut far) = tokio::io::duplex(256 * 1024);
        let mut metered = accounts.meter(&name("up"), &name("in"), PEER, client);
        far.write_all(&vec![2u8; 100_000]).await.unwrap();
        let mut buf = vec![0u8; 100_000];
        // The first second's worth comes at once, the rest is held back.
        let first = tokio::time::timeout(Duration::from_millis(300), async {
            let mut got = 0;
            loop {
                got += metered.read(&mut buf).await.unwrap();
                if got >= 30_000 {
                    return got;
                }
            }
        })
        .await;
        assert!(first.is_err(), "30 KB went through a 10 KB/s limit at once");
        accounts.set_limit("up", 0, 0);
        assert!(accounts.limits().is_empty());
        tokio::time::timeout(
            Duration::from_millis(500),
            metered.read_exact(&mut buf[..50_000]),
        )
        .await
        .expect("lifting the limit applies to an open session")
        .unwrap();
    }

    #[tokio::test]
    async fn lifting_a_tiny_limit_frees_a_session_deep_in_debt() {
        let accounts = Arc::new(Accounts::default());
        accounts.set_limit("tiny", 0, 1);
        let (client, mut far) = tokio::io::duplex(256 * 1024);
        let mut metered = accounts.meter(&name("tiny"), &name("in"), PEER, client);
        let writer = tokio::spawn(async move { metered.write_all(&[0u8; 10_000]).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        accounts.set_limit("tiny", 0, 0);
        let mut buf = vec![0u8; 10_000];
        tokio::time::timeout(Duration::from_secs(1), far.read_exact(&mut buf))
            .await
            .expect("a lifted limit must not leave the session waiting out its debt")
            .unwrap();
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_ended_session_waiting_on_its_limit_is_woken() {
        let accounts = Arc::new(Accounts::default());
        accounts.set_limit("parked", 0, 1);
        let (client, _far) = tokio::io::duplex(1024);
        let mut metered = accounts.meter(&name("parked"), &name("in"), PEER, client);
        let writer = tokio::spawn(async move { metered.write_all(&[0u8; 100]).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        accounts.end_sessions("parked");
        let result = tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .expect("a session parked on its limit must still end")
            .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_session_is_reported_when_it_opens_and_closes() {
        use crate::events::Event;
        let accounts = Accounts::default();
        let mut events = accounts.events().subscribe();
        let (client, _far) = tokio::io::duplex(64);
        let mut metered = accounts.meter(&name("frank"), &name("in"), PEER, client);
        metered.write_all(b"abc").await.unwrap();
        accounts.end_sessions("frank");
        drop(metered);

        let opened = events.recv().await.unwrap().event;
        assert_eq!(
            opened,
            Event::SessionOpened {
                email: "frank".into(),
                inbound: "in".into(),
                address: None
            }
        );
        assert!(matches!(
            events.recv().await.unwrap().event,
            Event::SessionsEnded { sessions: 1, .. }
        ));
        match events.recv().await.unwrap().event {
            Event::SessionClosed {
                downlink, ended, ..
            } => {
                assert_eq!(downlink, 3);
                assert!(ended);
            }
            other => panic!("{other:?}"),
        }
    }
}
