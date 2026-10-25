//! The mKCP carrier (Xray `network: "kcp"`).
//!
//! mKCP is a reliable, ordered byte stream over UDP: the KCP automatic-repeat
//! request protocol Xray rewrote in 24.9.30. It trades the kernel's TCP stack
//! for one that lives in user space and can be tuned (MTU, tick interval,
//! uplink and downlink capacity), and it survives on networks that throttle or
//! block long-lived TCP flows.
//!
//! The pieces:
//!
//! - [`segment`] — the framing inside one UDP datagram.
//! - [`session`] — one conversation: send/receive windows, acknowledgements,
//!   retransmission, the open/close state machine, and the `AsyncRead` +
//!   `AsyncWrite` face the rest of the proxy sees.
//! - [`Listener`] — one UDP socket shared by every conversation, keyed by
//!   (peer address, conversation id) exactly as Xray keys its sessions.
//!
//! This speaks the protocol current Xray speaks. It is not wire-compatible
//! with Xray 24.8 and older, which used a different KCP implementation with
//! header obfuscation; current Xray refuses those `header`/`seed` settings and
//! points at `finalmask.udp`, and so does this parser (see [`Options`]).
//!
//! ```text
//! let options = Options::default();
//! let mut listener = Listener::bind("0.0.0.0:443".parse()?, options).await?;
//! let server = listener.accept().await?;          // then TLS/protocol on top
//! let client = dial("example.com:443".parse()?, options).await?;
//! ```

pub mod mask;
pub mod segment;
mod session;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub use mask::{HeaderKind, Mask};
pub use session::Connection;

use segment::{Segment, CMD_TERMINATE};

/// Tunables for one mKCP carrier, matching Xray's `kcpSettings`.
///
/// Defaults are Xray's defaults. The two fields Xray removed in 24.9.30
/// (`header`, `seed`) have no field here on purpose: obfuscation now comes
/// from `finalmask.udp`, and [`Mask`] carries the layers that replaced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Largest segment, including the 18-byte header.
    pub mtu: u32,
    /// Tick interval in milliseconds: retransmission granularity.
    pub tti: u32,
    /// Sender capacity in MiB/s, translated to an in-flight segment count.
    pub uplink_capacity: u32,
    /// Receiver capacity in MiB/s, translated to a reorder window size.
    pub downlink_capacity: u32,
    /// Xray's `congestion`: adapt the send window to observed loss.
    pub congestion: bool,
    /// Receiver reorder memory in bytes. Xray parses it and never reads it;
    /// kept so a config that sets it round-trips.
    pub read_buffer: u32,
    /// Bytes accepted into the send window before a write blocks.
    pub write_buffer: u32,
    /// `finalmask.udp` layers, outermost first. Empty sends raw segments.
    pub masks: Arc<[Mask]>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            read_buffer: 2 * 1024 * 1024,
            write_buffer: 2 * 1024 * 1024,
            masks: Arc::from([]),
        }
    }
}

impl Options {
    /// Payload bytes per segment.
    pub fn mss(&self) -> u32 {
        self.mtu.saturating_sub(segment::DATA_OVERHEAD as u32)
    }

    /// How many segments may be in flight before acknowledgements must return.
    pub fn sending_in_flight(&self) -> u32 {
        let rate = self.tti.max(1);
        ((self.uplink_capacity as u64 * 1024 * 1024) / (self.mtu.max(1) as u64 * (1000 / rate) as u64))
            .max(8) as u32
    }

    /// How many segments may be queued waiting for their first transmission.
    pub fn sending_buffer(&self) -> u32 {
        (self.write_buffer / self.mtu.max(1)).max(1)
    }

    /// How far out of order a receiver accepts before dropping.
    pub fn receiving_in_flight(&self) -> u32 {
        let rate = self.tti.max(1);
        ((self.downlink_capacity as u64 * 1024 * 1024) / (self.mtu.max(1) as u64 * (1000 / rate) as u64))
            .max(8) as u32
    }

    /// The limits Xray's config builder enforces (TTI 10..=5000), plus the
    /// minimum MTU that leaves room for the 18-byte header and a byte.
    pub fn validate(&self) -> Result<(), String> {
        if !(10..=5000).contains(&self.tti) {
            return Err(format!("invalid mKCP TTI: {}", self.tti));
        }
        if self.mtu < 19 {
            return Err(format!("invalid mKCP MTU: {}", self.mtu));
        }
        Ok(())
    }
}

/// One UDP socket serving every conversation dialled to it.
///
/// The listener never creates a socket per peer. A background task reads
/// datagrams, uses each datagram's first segment to find or create the
/// conversation for (source address, conversation id), and hands the segments
/// over. A session that sends a terminating segment first is ignored rather
/// than tracked: it is a closing connection whose state is already gone.
pub struct Listener {
    shared: Arc<Shared>,
    incoming: mpsc::UnboundedReceiver<Connection>,
    reader: tokio::task::JoinHandle<()>,
}

struct Shared {
    socket: Arc<UdpSocket>,
    config: Options,
    masks: mask::Masks,
    sessions: Mutex<HashMap<(SocketAddr, u16), session::Handle>>,
    incoming: mpsc::UnboundedSender<Connection>,
    closed: AtomicBool,
    dispatch_since_prune: Mutex<usize>,
}

impl Listener {
    pub async fn bind(addr: SocketAddr, config: Options) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Self::from_socket(socket, config)
    }

    pub fn from_socket(socket: UdpSocket, config: Options) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let (incoming_tx, incoming) = mpsc::unbounded_channel();
        let masks = mask::Masks::new(&config.masks);
        let shared = Arc::new(Shared {
            socket: Arc::new(socket),
            config,
            masks: masks.clone(),
            sessions: Mutex::new(HashMap::new()),
            incoming: incoming_tx,
            closed: AtomicBool::new(false),
            dispatch_since_prune: Mutex::new(0),
        });
        let reading = Arc::clone(&shared);
        let reader = tokio::spawn(async move { read_loop(reading).await });
        Ok(Self {
            shared,
            incoming,
            reader,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Wait for the next distinct conversation to say something. There is no
    /// handshake at this layer, so a conversation exists as soon as its first
    /// data-bearing datagram arrives.
    pub async fn accept(&mut self) -> io::Result<Connection> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }

    /// How many conversations the listener currently tracks. Test-facing.
    pub fn active_sessions(&self) -> usize {
        let sessions = self
            .shared
            .sessions
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        sessions.values().filter(|handle| handle.is_live()).count()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        self.reader.abort();
        let sessions = std::mem::take(
            &mut *self
                .shared
                .sessions
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        );
        for (_, handle) in sessions {
            handle.abort();
        }
    }
}

async fn read_loop(shared: Arc<Shared>) {
    // One allocation for the listener's whole life; a datagram is parsed into
    // owned segments before the dispatch, so the buffer is free again
    // immediately.
    let mut buffer = vec![0u8; 65_536];
    loop {
        if shared.closed.load(Ordering::Acquire) {
            return;
        }
        let (length, source) = match shared.socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            // A datagram that could not be delivered is not a reason to tear
            // the listener down; the sender retransmits.
            Err(_) => continue,
        };
        // A masked carrier authenticates every datagram, so a stray packet
        // (a scanner, a wrong password) is dropped before it can create a
        // session of its own.
        let Some(datagram) = shared.masks.unwrap(&buffer[..length]) else {
            continue;
        };
        let segments = segment::parse(&datagram);
        dispatch(&shared, source, segments);
    }
}

fn dispatch(shared: &Shared, source: SocketAddr, segments: Vec<Segment>) {
    let Some(first) = segments.first() else {
        return;
    };
    let conv = first.conv();
    let first_is_terminate =
        matches!(first, Segment::Command(command) if command.command == CMD_TERMINATE);
    let key = (source, conv);

    let mut sessions = shared
        .sessions
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = sessions.get(&key) {
        if existing.feed(segments) {
            return;
        }
        sessions.remove(&key);
        // The session died between datagrams. The sender retransmits, and
        // the retransmission starts a fresh session.
        return;
    }
    // A lone terminating segment from an address we have no state for is the
    // tail of a session that is already gone.
    if first_is_terminate {
        return;
    }

    let connection = session::server_session(
        Arc::clone(&shared.socket),
        source,
        conv,
        shared.config.clone(),
        shared.masks.clone(),
    );
    connection.feed(segments);
    sessions.insert(key, connection.handle());
    // The queue is unbounded: dropping a `Connection` here would leave a
    // session table entry nobody can serve. If the server is gone, the session
    // still times out on its own.
    let _ = shared.incoming.send(connection);

    let mut dispatched = shared
        .dispatch_since_prune
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *dispatched += 1;
    if *dispatched >= 256 {
        *dispatched = 0;
        sessions.retain(|_, handle| handle.is_live());
    }
}

/// Dial an mKCP session to `target` over a freshly bound UDP socket.
pub async fn dial(target: SocketAddr, config: Options) -> io::Result<Connection> {
    session::dial(target, config).await
}

/// Dial over a socket the caller bound, so a mobile client can protect it
/// before any datagram leaves.
pub async fn dial_socket(socket: UdpSocket, target: SocketAddr, config: Options) -> io::Result<Connection> {
    session::dial_socket(socket, target, config).await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn options() -> Options {
        Options {
            tti: 10,
            ..Options::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_carries_a_megabyte_both_ways() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), options())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut connection = listener.accept().await.unwrap();
            let mut received = vec![0u8; 1024 * 1024];
            connection.read_exact(&mut received).await.unwrap();
            let original = received.clone();
            for byte in &mut received {
                *byte ^= b'c';
            }
            connection.write_all(&received).await.unwrap();
            connection.flush().await.unwrap();
            // The listener owns the session table; returning it keeps the
            // session (and its socket) alive until the echo has been read.
            (original, connection, listener)
        });

        let mut client = dial(addr, options()).await.unwrap();
        let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let expected: Vec<u8> = payload.iter().map(|byte| byte ^ b'c').collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.flush().await.unwrap();
            let mut back = vec![0u8; 1024 * 1024];
            client.read_exact(&mut back).await.unwrap();
            back
        });

        let returned = tokio::time::timeout(Duration::from_secs(60), writer)
            .await
            .expect("the client side did not finish in a minute")
            .unwrap();
        assert_eq!(returned, expected);
        let (received, _server_connection, _listener) =
            tokio::time::timeout(Duration::from_secs(30), server)
                .await
                .expect("the server side did not finish")
                .unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_small_write_arrives() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), options())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connection = listener.accept().await.unwrap();
            let mut buffer = [0u8; 5];
            connection.read_exact(&mut buffer).await.unwrap();
            buffer
        });
        let mut client = dial(addr, options()).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server did not read")
            .unwrap();
        assert_eq!(&got, b"hello");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn several_conversations_share_one_socket() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), options())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..4 {
                let mut connection = listener.accept().await.unwrap();
                connection.write_all(b"hello").await.unwrap();
                connections.push(connection);
            }
            (connections, listener)
        });

        let mut clients = Vec::new();
        for _ in 0..4 {
            clients.push(dial(addr, options()).await.unwrap());
        }
        for client in &mut clients {
            let mut buffer = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer, b"hello");
        }
        let (connections, _listener) = server.await.unwrap();
        assert_eq!(connections.len(), 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_client_closes_the_server_side() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), options())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connection = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4];
            connection.read_exact(&mut buffer).await.unwrap();
            // The peer's close should surface as EOF here, not a timeout.
            let mut rest = Vec::new();
            tokio::time::timeout(Duration::from_secs(20), connection.read_to_end(&mut rest))
                .await
                .unwrap()
                .unwrap();
            rest
        });

        let mut client = dial(addr, options()).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);
        assert!(server.await.unwrap().is_empty());
    }
}
