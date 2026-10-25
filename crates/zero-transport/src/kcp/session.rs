//! One mKCP session: the reliable stream, its windows, timers and state.
//!
//! The shapes here follow Xray's `transport/internet/kcp` closely, because the
//! wire is what other implementations speak: the same wraparound-safe sequence
//! comparisons, the same acknowledgement batching, the same state machine and
//! the same flush cadence. The port is written as a tokio `AsyncRead` +
//! `AsyncWrite` instead of a blocking `net.Conn`, so the differences are in
//! how the mutex and wakers are held, not in what goes on the wire.
//!
//! One session belongs to one conversation id (`conv`) and one peer address.
//! A UDP datagram carries segments from exactly one conversation; the listener
//! uses the first segment to pick the session, then hands the whole datagram to
//! it. Everything a session sends goes back to the address the datagram came
//! from.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use super::mask::Masks;
use super::segment::{
    ack_limit, AckSegment, CommandSegment, DataSegment, Segment, CMD_PING, CMD_TERMINATE,
    OPTION_CLOSE,
};
use super::Options;

/// How often the sender retransmits what the peer has not acknowledged, and
/// the base of every timer below (Xray's `tti`, default 50 ms).
const IDLE_TICK: Duration = Duration::from_secs(5);
/// The same 1 s cadence Xray switches to once a session is closing.
const CLOSING_TICK: Duration = Duration::from_secs(1);

const PING_INTERVAL_MS: u32 = 3000;
const NO_INCOMING_CLOSE_MS: u32 = 30_000;
const READY_TO_CLOSE_LIMIT_MS: u32 = 15_000;
const TERMINATING_LIMIT_MS: u32 = 8_000;
const PEER_TERMINATING_LIMIT_MS: u32 = 4_000;
const PEER_RTO_MIN_INTERVAL_MS: u32 = 3000;

/// One already-sent piece of the stream, kept until the peer acknowledges it.
struct OutSegment {
    number: u32,
    payload: Bytes,
    /// When this copy is due for retransmission, in session milliseconds.
    timeout: u32,
    /// How many times it has gone out; 0 means never.
    transmit: u32,
}

/// The sender's half of the window.
///
/// Invariants that matter: `window` holds every segment between
/// `first_unacknowledged` and `next_number`, in order; `remote_next_number`
/// never shrinks, so the peer can only grow the room it grants us.
struct Sending {
    window: VecDeque<OutSegment>,
    total_in_flight: u32,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    window_size: u32,
    congestion: bool,
    max_in_flight: u32,
    first_unacknowledged_updated: bool,
}

impl Sending {
    fn new(options: &Options) -> Self {
        let max_in_flight = options.sending_in_flight();
        Self {
            window: VecDeque::new(),
            total_in_flight: 0,
            first_unacknowledged: 0,
            next_number: 0,
            // Xray starts with 32 segments of credit before the first
            // acknowledgement arrives (`remoteNextNumber: 32`), which lets the
            // opening handshake go out without a round trip of discovery.
            remote_next_number: 32,
            control_window: max_in_flight,
            window_size: options.sending_buffer(),
            congestion: options.congestion,
            max_in_flight,
            first_unacknowledged_updated: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// Queue one payload. `false` means the buffer is full and the caller must
    /// wait for acknowledgements; the write path uses that as backpressure.
    fn push(&mut self, payload: Bytes) -> bool {
        if self.window.len() as u32 > self.window_size {
            return false;
        }
        self.window.push_back(OutSegment {
            number: self.next_number,
            payload,
            timeout: 0,
            transmit: 0,
        });
        self.next_number = self.next_number.wrapping_add(1);
        true
    }

    /// Drop everything below `una` and recompute the first hole.
    fn clear(&mut self, una: u32) {
        while let Some(segment) = self.window.front() {
            if !before(segment.number, una) {
                break;
            }
            self.window.pop_front();
            self.total_in_flight = self.total_in_flight.saturating_sub(1);
        }
        self.find_first_unacknowledged();
    }

    fn clear_all(&mut self) {
        self.window.clear();
        self.total_in_flight = 0;
        self.find_first_unacknowledged();
    }

    fn find_first_unacknowledged(&mut self) {
        let first = self.first_unacknowledged;
        self.first_unacknowledged = self
            .window
            .front()
            .map_or(self.next_number, |segment| segment.number);
        if first != self.first_unacknowledged {
            self.first_unacknowledged_updated = true;
        }
    }

    /// Apply one acknowledgement segment. Returns whether this packet also
    /// carried new round-trip information worth feeding to the RTT estimate.
    fn process_ack(&mut self, current: u32, ack: &AckSegment, rto: u32) -> Option<u32> {
        if self.remote_next_number < ack.receiving_window {
            self.remote_next_number = ack.receiving_window;
        }
        self.clear(ack.receiving_next);

        let mut max_ack = 0u32;
        let mut max_ack_removed = false;
        for &number in &ack.numbers {
            let removed = self.process_number(number);
            if max_ack < number {
                max_ack = number;
                max_ack_removed = removed;
            }
        }
        if !max_ack_removed {
            return None;
        }
        self.handle_fast_ack(max_ack, rto);
        let elapsed = current.wrapping_sub(ack.timestamp);
        (elapsed < 10_000).then_some(elapsed)
    }

    fn process_number(&mut self, number: u32) -> bool {
        // Accept only numbers in [first_unacknowledged, next_number).
        if number.wrapping_sub(self.first_unacknowledged) > 0x7FFF_FFFF
            || number.wrapping_sub(self.next_number) < 0x7FFF_FFFF
        {
            return false;
        }
        let Some(index) = self
            .window
            .iter()
            .position(|segment| segment.number == number)
        else {
            return false;
        };
        let segment = self.window.remove(index).expect("position was just found");
        drop(segment);
        if self.total_in_flight > 0 {
            self.total_in_flight -= 1;
        }
        self.find_first_unacknowledged();
        true
    }

    /// A fast acknowledgement for `number` tells us the peer received it while
    /// earlier segments are still unacknowledged: make those earlier ones due
    /// sooner instead of waiting a full RTO for each.
    fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        let step = rto / 3;
        for segment in &mut self.window {
            if segment.number == number || before(number, segment.number) {
                break;
            }
            if segment.transmit > 0 && segment.timeout > step {
                segment.timeout -= step;
            }
        }
    }

    /// Retransmit everything that is due, up to the congestion window. Returns
    /// whether the peer should be pinged with the new `first_unacknowledged`.
    fn flush(
        &mut self,
        current: u32,
        rto: u32,
        conv: u16,
        option: u8,
        out: &mut Vec<DataSegment>,
    ) -> bool {
        if !self.window.is_empty() {
            let mut cwnd = self.max_in_flight;
            let remote_room = self.remote_next_number.wrapping_sub(self.first_unacknowledged);
            if cwnd > remote_room {
                cwnd = remote_room;
            }
            if self.congestion && cwnd > self.control_window {
                cwnd = self.control_window;
            }
            // Xray's "magic" 20: one acknowledgment can open room for a
            // burst, which is what lets a large write leave in one tick.
            cwnd = cwnd.saturating_mul(20);

            let mut lost = 0u32;
            let mut in_flight = 0u32;
            for segment in &mut self.window {
                // Unsigned distance: a timeout "in the future" by less than
                // half the space is not due yet.
                if current.wrapping_sub(segment.timeout) >= 0x7FFF_FFFF {
                    continue;
                }
                if segment.transmit == 0 {
                    self.total_in_flight += 1;
                } else {
                    lost += 1;
                }
                segment.timeout = current.wrapping_add(rto);
                segment.transmit = segment.transmit.saturating_add(1);
                out.push(DataSegment {
                    conv,
                    option,
                    timestamp: current,
                    number: segment.number,
                    sending_next: self.first_unacknowledged,
                    payload: segment.payload.clone(),
                });
                in_flight += 1;
                if in_flight >= cwnd {
                    break;
                }
            }
            if in_flight > 0 && self.total_in_flight != 0 {
                let rate = lost.saturating_mul(100) / self.total_in_flight;
                self.on_packet_loss(rate);
            }
            // Xray clears the flag here, so the ping below only goes out when
            // the window was already empty. Reproduced as written: peers watch
            // for that ping to learn the new `first_unacknowledged`, and
            // sending it in more cases would change the packet count.
            self.first_unacknowledged_updated = false;
        }
        let updated = self.first_unacknowledged_updated;
        self.first_unacknowledged_updated = false;
        updated
    }

    fn on_packet_loss(&mut self, rate: u32) {
        // Xray only adapts the window when the configuration asks for
        // congestion control (`Config.Congestion`), which defaults to off.
        if !self.congestion {
            return;
        }
        if rate >= 15 {
            self.control_window = 3 * self.control_window / 4;
        } else if rate <= 5 {
            self.control_window += self.control_window / 4;
        }
        self.control_window = self
            .control_window
            .max(16)
            .min(2 * self.max_in_flight);
    }
}

/// One acknowledgement still owed to the peer.
struct AckEntry {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

/// The receiver's half of the window: reorder buffer plus the acknowledgements
/// it still has to send.
struct Receiving {
    window: HashMap<u32, Bytes>,
    next_number: u32,
    window_size: u32,
    acks: Vec<AckEntry>,
    dirty: bool,
    limit: u32,
}

impl Receiving {
    fn new(options: &Options) -> Self {
        Self {
            window: HashMap::new(),
            next_number: 0,
            window_size: options.receiving_in_flight(),
            acks: Vec::with_capacity(128),
            dirty: false,
            limit: ack_limit(options.mtu),
        }
    }

    fn process(&mut self, segment: &DataSegment) {
        let index = segment.number.wrapping_sub(self.next_number);
        if index >= self.window_size {
            return;
        }
        self.clear(segment.sending_next);
        self.acks.push(AckEntry {
            number: segment.number,
            timestamp: segment.timestamp,
            next_flush: 0,
        });
        self.dirty = true;
        self.window
            .entry(segment.number)
            .or_insert_with(|| segment.payload.clone());
    }

    /// Forget acknowledgements for data the peer has already seen acknowledged
    /// elsewhere (it told us its `sending_next`).
    fn clear(&mut self, una: u32) {
        let before = self.acks.len();
        self.acks.retain(|entry| entry.number >= una);
        if self.acks.len() < before {
            self.dirty = true;
        }
    }

    /// Move every segment that is now contiguous onto the read queue.
    fn drain(&mut self, queue: &mut VecDeque<Bytes>) {
        while let Some(payload) = self.window.remove(&self.next_number) {
            self.next_number = self.next_number.wrapping_add(1);
            queue.push_back(payload);
        }
    }

    fn update_necessary(&self) -> bool {
        !self.acks.is_empty()
    }

    /// Build the acknowledgement segments due now. Numbers that are not due
    /// yet still ride along in the last segment; Xray does the same so a quiet
    /// receiver keeps the peer's window moving.
    fn flush(&mut self, current: u32, rto: u32) -> Vec<AckSegment> {
        let mut out = Vec::new();
        let mut segment = AckSegment {
            numbers: Vec::with_capacity(self.limit as usize),
            ..AckSegment::default()
        };
        let mut candidates: Vec<u32> = Vec::new();
        let timeout = (rto / 2).max(20);

        for entry in &mut self.acks {
            if entry.next_flush > current {
                candidates.push(entry.number);
                continue;
            }
            put_timestamp(&mut segment, entry.timestamp);
            segment.numbers.push(entry.number);
            entry.next_flush = current.wrapping_add(timeout);
            if segment.numbers.len() as u32 >= self.limit {
                out.push(std::mem::replace(
                    &mut segment,
                    AckSegment {
                        numbers: Vec::with_capacity(self.limit as usize),
                        ..AckSegment::default()
                    },
                ));
                self.dirty = false;
            }
        }

        if self.dirty || !segment.numbers.is_empty() {
            for number in candidates {
                if segment.numbers.len() as u32 >= self.limit {
                    break;
                }
                segment.numbers.push(number);
            }
            if !segment.numbers.is_empty() {
                out.push(segment);
            }
            self.dirty = false;
        }
        out
    }
}

fn put_timestamp(segment: &mut AckSegment, timestamp: u32) {
    // Keep the newest timestamp seen in this segment; older entries still
    // acknowledge their number, only the RTT sample uses the newest.
    if timestamp.wrapping_sub(segment.timestamp) < 0x7FFF_FFFF {
        segment.timestamp = timestamp;
    }
}

/// Milliseconds of silence since the last datagram, never negative.
///
/// `last_incoming` is recorded under the state lock and sampled under the same
/// lock, so it cannot really lie in the future. This guard keeps the
/// subtraction monotone-in-`current` anyway: a timestamp that looks newer than
/// `current` (a stale sample from a caller that has since been fixed) means
/// zero silence, which can only postpone a close, never cause one. Without it,
/// `current - last_incoming` wraps to ~4.29e9 and a live session is closed the
/// moment it opens.
fn silence(current: u32, last_incoming: u32) -> u32 {
    let silence = current.wrapping_sub(last_incoming);
    if silence >= 0x8000_0000 {
        0
    } else {
        silence
    }
}

/// Wrap-safe `a < b`. Strict: a segment whose number equals `una` is still
/// unacknowledged and must stay in the window, which is exactly the boundary
/// Xray's `Clear(una)` keeps.
fn before(a: u32, b: u32) -> bool {
    let distance = b.wrapping_sub(a);
    distance != 0 && distance < 0x8000_0000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

/// Smoothed round-trip time and the retransmission timeout derived from it,
/// following RFC 6298 as Xray does.
struct RoundTrip {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated: u32,
}

impl RoundTrip {
    fn new(tti: u32) -> Self {
        Self {
            variation: 0,
            srtt: 0,
            rto: 100,
            min_rtt: tti,
            updated: 0,
        }
    }

    fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7FFF_FFFF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            self.variation = (3 * self.variation + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let rto = if self.min_rtt < 4 * self.variation {
            self.srtt + 4 * self.variation
        } else {
            self.srtt + self.variation
        };
        self.rto = rto.min(10_000) * 5 / 4;
        self.updated = current;
    }

    fn update_peer(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated) < PEER_RTO_MIN_INTERVAL_MS {
            return;
        }
        self.updated = current;
        self.rto = rto;
    }

    fn timeout(&self) -> u32 {
        self.rto
    }
}

struct State {
    phase: Phase,
    phase_begin: u32,
    last_incoming: u32,
    last_ping: u32,
    sending: Sending,
    receiving: Receiving,
    round_trip: RoundTrip,
    read_queue: VecDeque<Bytes>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

/// Where a session's datagrams go.
enum Sink {
    /// A connected client socket: one destination, the one it was dialled to.
    Connected(Arc<UdpSocket>),
    /// A listener socket shared by every session: each send names its peer.
    Shared {
        socket: Arc<UdpSocket>,
        peer: std::net::SocketAddr,
    },
}

impl Sink {
    fn send(&self, bytes: &[u8]) {
        // A full socket buffer is packet loss, and loss is what KCP is for;
        // blocking a shared driver on it would stall every other session.
        let _ = match self {
            Sink::Connected(socket) => socket.try_send(bytes),
            Sink::Shared { socket, peer } => socket.try_send_to(bytes, *peer),
        };
    }
}

struct Inner {
    conv: u16,
    config: Options,
    masks: Masks,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    sink: Sink,
    start: Instant,
    state: Mutex<State>,
    driver: Notify,
    dead: AtomicBool,
    dead_notify: Notify,
}

/// One mKCP conversation, usable wherever a byte stream is.
pub struct Connection {
    inner: Arc<Inner>,
}

impl Connection {
    fn new(
        config: Options,
        masks: Masks,
        conv: u16,
        local: std::net::SocketAddr,
        remote: std::net::SocketAddr,
        sink: Sink,
    ) -> Self {
        let sending = Sending::new(&config);
        let receiving = Receiving::new(&config);
        let round_trip = RoundTrip::new(config.tti);
        let inner = Arc::new(Inner {
            conv,
            config,
            masks,
            local,
            remote,
            sink,
            start: Instant::now(),
            state: Mutex::new(State {
                phase: Phase::Active,
                phase_begin: 0,
                last_incoming: 0,
                last_ping: 0,
                sending,
                receiving,
                round_trip,
                read_queue: VecDeque::new(),
                read_waker: None,
                write_waker: None,
            }),
            driver: Notify::new(),
            dead: AtomicBool::new(false),
            dead_notify: Notify::new(),
        });
        let driven = Arc::clone(&inner);
        tokio::spawn(async move { drive(driven).await });
        Self { inner }
    }

    pub fn conversation(&self) -> u16 {
        self.inner.conv
    }

    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.inner.remote
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.inner.local
    }

    /// Whether the driver has finished and the conversation is gone.
    pub fn is_dead(&self) -> bool {
        self.inner.dead.load(Ordering::Acquire)
    }

    /// Stop immediately, without the terminating handshake. Used when a
    /// listener shuts down and there is no point being polite.
    pub fn abort(&self) {
        self.inner.abort();
    }
}

impl Inner {
    fn abort(&self) {
        {
            let mut state = self.lock();
            state.phase = Phase::Terminated;
            state.sending.clear_all();
            state.read_queue.clear();
            wake_all(&mut state);
        }
        self.dead.store(true, Ordering::Release);
        self.driver.notify_one();
        self.dead_notify.notify_waiters();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn elapsed(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    fn next_wait(&self) -> Duration {
        let state = self.lock();
        let work = !state.sending.is_empty() || state.receiving.update_necessary();
        match state.phase {
            Phase::Terminated => Duration::ZERO,
            Phase::Terminating | Phase::PeerTerminating => CLOSING_TICK,
            _ if work => Duration::from_millis(self.config.tti.max(10) as u64),
            _ => IDLE_TICK,
        }
    }

    fn tick(&self) -> bool {
        // The timestamp must be taken under the same lock `input` records
        // `last_incoming` with. Taken first, there is a window where a segment
        // arrives and records a later elapsed value before this thread gets the
        // lock; the inactivity test below then subtracts a "future" timestamp
        // from a stale one, wraps to ~4.29e9 and closes a live session. That
        // fired at 3 ms into a transfer under load (`last_incoming` 4 ms), which
        // is the concurrent-flow EOF this ordering closes.
        let mut state = self.lock();
        let current = self.elapsed();
        let mut outgoing = Vec::with_capacity(self.config.mtu as usize);

        if state.phase == Phase::Terminated {
            return true;
        }
        if state.phase == Phase::Active
            && silence(current, state.last_incoming) >= NO_INCOMING_CLOSE_MS
        {
            close_locked(&mut state, current);
        }
        if state.phase == Phase::ReadyToClose && state.sending.is_empty() {
            transition(&mut state, Phase::Terminating, current);
        }

        if state.phase == Phase::Terminating {
            self.ping(&mut state, current, CMD_TERMINATE, &mut outgoing);
            if current.wrapping_sub(state.phase_begin) > TERMINATING_LIMIT_MS {
                transition(&mut state, Phase::Terminated, current);
            }
            send_all(self, &outgoing);
            return state.phase == Phase::Terminated;
        }

        if state.phase == Phase::PeerTerminating
            && current.wrapping_sub(state.phase_begin) > PEER_TERMINATING_LIMIT_MS
        {
            transition(&mut state, Phase::Terminating, current);
        }
        if state.phase == Phase::ReadyToClose
            && current.wrapping_sub(state.phase_begin) > READY_TO_CLOSE_LIMIT_MS
        {
            transition(&mut state, Phase::Terminating, current);
        }

        // Acknowledgements first: they cost the peer nothing to drop and keep
        // its send window open.
        let option = if state.phase == Phase::ReadyToClose {
            OPTION_CLOSE
        } else {
            0
        };
        let rto = state.round_trip.timeout();
        let mut acks = state.receiving.flush(current, rto);
        for ack in &mut acks {
            ack.conv = self.conv;
            ack.option = option;
            ack.receiving_next = state.receiving.next_number;
            ack.receiving_window = state
                .receiving
                .next_number
                .wrapping_add(state.receiving.window_size);
            outgoing.push(Segment::Ack(ack.clone()));
        }

        let mut data = Vec::new();
        let updated = state
            .sending
            .flush(current, rto, self.conv, option, &mut data);
        outgoing.extend(data.into_iter().map(Segment::Data));

        if updated || current.wrapping_sub(state.last_ping) >= PING_INTERVAL_MS {
            self.ping(&mut state, current, CMD_PING, &mut outgoing);
        }
        send_all(self, &outgoing);
        state.phase == Phase::Terminated
    }

    fn ping(
        &self,
        state: &mut State,
        current: u32,
        command: u8,
        outgoing: &mut Vec<Segment>,
    ) {
        outgoing.push(Segment::Command(CommandSegment {
            conv: self.conv,
            command,
            option: if state.phase == Phase::ReadyToClose {
                OPTION_CLOSE
            } else {
                0
            },
            sending_next: state.sending.first_unacknowledged,
            receiving_next: state.receiving.next_number,
            peer_rto: state.round_trip.timeout(),
        }));
        state.last_ping = current;
    }

    /// Feed one datagram's worth of segments into the session.
    fn input(&self, segments: Vec<Segment>) {
        if segments.is_empty() {
            return;
        }
        let mut wake_read = false;
        let mut wake_write = false;
        {
            let mut state = self.lock();
            let current = self.elapsed();
            state.last_incoming = current;
            for segment in segments {
                if segment.conv() != self.conv {
                    break;
                }
                let option = segment.option();
                let close = option & OPTION_CLOSE != 0;
                match segment {
                    Segment::Data(data) => {
                        if close {
                            peer_closed(&mut state, current);
                        }
                        state.receiving.process(&data);
                        let before = state.read_queue.len();
                        {
                            // The reorder buffer and the read queue are two
                            // fields of the same state; name them separately
                            // so the drain can borrow both.
                            let State {
                                receiving,
                                read_queue,
                                ..
                            } = &mut *state;
                            receiving.drain(read_queue);
                        }
                        if state.read_queue.len() != before {
                            wake_read = true;
                        }
                    }
                    Segment::Ack(ack) => {
                        if close {
                            peer_closed(&mut state, current);
                        }
                        let rto = state.round_trip.timeout();
                        if let Some(rtt) = state.sending.process_ack(current, &ack, rto) {
                            state.round_trip.update(rtt, current);
                        }
                        wake_write = true;
                    }
                    Segment::Command(command) => {
                        if close {
                            peer_closed(&mut state, current);
                        }
                        if command.command == CMD_TERMINATE {
                            match state.phase {
                                Phase::Active | Phase::PeerClosed => {
                                    transition(&mut state, Phase::PeerTerminating, current)
                                }
                                Phase::ReadyToClose => {
                                    transition(&mut state, Phase::Terminating, current)
                                }
                                Phase::Terminating => {
                                    transition(&mut state, Phase::Terminated, current)
                                }
                                _ => {}
                            }
                        }
                        if close || command.command == CMD_TERMINATE {
                            wake_read = true;
                            wake_write = true;
                        }
                        state.sending.clear(command.receiving_next);
                        state.receiving.clear(command.sending_next);
                        state.round_trip.update_peer(command.peer_rto, current);
                    }
                }
            }
            if wake_read || wake_write || state.phase == Phase::Terminated {
                wake_all(&mut state);
            }
        }
        self.driver.notify_one();
    }

    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.lock();
        if let Some(front) = state.read_queue.front_mut() {
            let take = front.len().min(buf.remaining());
            buf.put_slice(&front[..take]);
            front.advance(take);
            if front.is_empty() {
                state.read_queue.pop_front();
            }
            return Poll::Ready(Ok(()));
        }
        if read_finished(&state) {
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.lock();
        if state.phase != Phase::Active {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mss = self.config.mss().max(1) as usize;
        let mut written = 0;
        while written < buf.len() {
            let take = mss.min(buf.len() - written);
            let payload = Bytes::copy_from_slice(&buf[written..written + take]);
            if !state.sending.push(payload) {
                break;
            }
            written += take;
        }
        if written > 0 {
            drop(state);
            self.driver.notify_one();
            Poll::Ready(Ok(written))
        } else {
            state.write_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_flush(&self) -> Poll<io::Result<()>> {
        // Every byte handed to `poll_write` is already in the retransmission
        // window, which is as far as a datagram transport can promise.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(&self) -> Poll<io::Result<()>> {
        {
            let mut state = self.lock();
            let current = self.elapsed();
            close_locked(&mut state, current);
            wake_all(&mut state);
        }
        self.driver.notify_one();
        Poll::Ready(Ok(()))
    }
}

fn close_locked(state: &mut State, current: u32) {
    match state.phase {
        Phase::Active => transition(state, Phase::ReadyToClose, current),
        Phase::PeerClosed => transition(state, Phase::Terminating, current),
        Phase::PeerTerminating => transition(state, Phase::Terminated, current),
        _ => {}
    }
}

fn peer_closed(state: &mut State, current: u32) {
    match state.phase {
        Phase::ReadyToClose => transition(state, Phase::Terminating, current),
        Phase::Active => transition(state, Phase::PeerClosed, current),
        _ => {}
    }
    // The peer will not send more data. It may still read what we send until
    // it terminates, so this is not EOF yet.
    state.sending.clear_all();
}

fn transition(state: &mut State, to: Phase, current: u32) {
    state.phase = to;
    state.phase_begin = current;
    wake_all(state);
}

fn wake_all(state: &mut State) {
    if let Some(waker) = state.read_waker.take() {
        waker.wake();
    }
    if let Some(waker) = state.write_waker.take() {
        waker.wake();
    }
}

fn read_finished(state: &State) -> bool {
    matches!(
        state.phase,
        Phase::ReadyToClose | Phase::Terminating | Phase::Terminated
    ) || state.phase == Phase::PeerTerminating
}

fn send_all(inner: &Inner, outgoing: &[Segment]) {
    let mut buffer = Vec::with_capacity(inner.config.mtu as usize);
    for segment in outgoing {
        buffer.clear();
        segment.encode(&mut buffer);
        if inner.masks.is_empty() {
            inner.sink.send(&buffer);
        } else {
            // One datagram per segment, as Xray's `SegmentWriter` writes, with
            // the configured mask layers around it.
            inner.sink.send(&inner.masks.wrap(&buffer));
        }
    }
}

async fn drive(inner: Arc<Inner>) {
    loop {
        let wait = inner.next_wait();
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = inner.driver.notified() => {}
        }
        let done = inner.tick();
        if done || inner.dead.load(Ordering::Acquire) {
            break;
        }
    }
    {
        let mut state = inner.lock();
        state.sending.clear_all();
        state.read_queue.clear();
        wake_all(&mut state);
    }
    inner.dead.store(true, Ordering::Release);
    inner.dead_notify.notify_waiters();
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_flush()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_shutdown()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        {
            let mut state = self.inner.lock();
            let current = self.inner.elapsed();
            close_locked(&mut state, current);
        }
        self.inner.driver.notify_one();
    }
}

/// Bind a connected UDP socket to `target`, dial the session, and keep a reader
/// task alive for as long as the session is.
pub async fn dial(
    target: std::net::SocketAddr,
    config: Options,
) -> io::Result<Connection> {
    let local: std::net::SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().expect("a literal address")
    } else {
        "[::]:0".parse().expect("a literal address")
    };
    let socket = UdpSocket::bind(local).await?;
    dial_socket(socket, target, config).await
}

/// Dial over a socket the caller already bound (so a mobile client can apply
/// its socket protection first).
pub async fn dial_socket(
    socket: UdpSocket,
    target: std::net::SocketAddr,
    config: Options,
) -> io::Result<Connection> {
    socket.connect(target).await?;
    let local = socket.local_addr()?;
    let socket = Arc::new(socket);
    let conv: u16 = rand::random();
    let masks = Masks::new(&config.masks);
    let connection = Connection::new(
        config,
        masks.clone(),
        conv,
        local,
        target,
        Sink::Connected(Arc::clone(&socket)),
    );
    let inner = Arc::clone(&connection.inner);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_536];
        loop {
            if inner.dead.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                _ = inner.dead_notify.notified() => break,
                received = socket.recv(&mut buffer) => match received {
                    Ok(n) => {
                        // A datagram that does not authenticate under the mask
                        // is dropped like packet loss; the peer retransmits.
                        if let Some(datagram) = masks.unwrap(&buffer[..n]) {
                            inner.input(super::segment::parse(&datagram));
                        }
                    }
                    // One refused datagram (an ICMP unreachable surfacing on
                    // Linux) must not end a session that is otherwise alive.
                    Err(_) => continue,
                },
            }
        }
    });
    Ok(connection)
}

/// The server side of a session, owned by a [`super::Listener`].
pub(super) fn server_session(
    socket: Arc<UdpSocket>,
    peer: std::net::SocketAddr,
    conv: u16,
    config: Options,
    masks: Masks,
) -> Connection {
    let local = socket
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("a literal address"));
    Connection::new(
        config,
        masks,
        conv,
        local,
        peer,
        Sink::Shared { socket, peer },
    )
}

/// Read accessors used by the listener and tests without exposing internals.
impl Connection {
    pub(super) fn feed(&self, segments: Vec<Segment>) {
        self.inner.input(segments);
    }

    /// A cheap reference the listener keeps in its table. It does not keep the
    /// session alive: when the serving task drops its [`Connection`], the
    /// table's entry goes stale and the next datagram for that conversation
    /// starts a fresh session.
    pub(super) fn handle(&self) -> Handle {
        Handle(Arc::downgrade(&self.inner))
    }
}

/// A listener's reference to a session it handed out.
pub(super) struct Handle(std::sync::Weak<Inner>);

impl Handle {
    /// True while the session still owns live state. Feeds the segments in
    /// and returns true; a stale or already-dead session refuses them.
    pub(super) fn feed(&self, segments: Vec<Segment>) -> bool {
        match self.0.upgrade() {
            Some(inner) if !inner.dead.load(Ordering::Acquire) => {
                inner.input(segments);
                true
            }
            _ => false,
        }
    }

    pub(super) fn is_live(&self) -> bool {
        self.0
            .upgrade()
            .is_some_and(|inner| !inner.dead.load(Ordering::Acquire))
    }

    pub(super) fn abort(&self) {
        if let Some(inner) = self.0.upgrade() {
            inner.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            mtu: 1350,
            tti: 10,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            read_buffer: 2 * 1024 * 1024,
            write_buffer: 2 * 1024 * 1024,
            masks: Arc::from([]),
        }
    }

    #[test]
    fn a_timestamp_from_the_future_is_not_silence() {
        // The regression this guards: a tick sampled `current` = 3 ms a moment
        // before a concurrent input recorded `last_incoming` = 4 ms, and the
        // unsigned subtraction wrapped to 4.29e9, closing a live session 3 ms
        // after it opened.
        assert_eq!(silence(3, 4), 0);
        assert_eq!(silence(30_001, 0), 30_001);
        // Sequence wraparound after ~49 days of uptime: the age is still right.
        assert_eq!(silence(0, u32::MAX - 1), 2);
    }

    #[test]
    fn a_window_survives_sequence_wraparound() {
        let mut sending = Sending::new(&options());
        sending.next_number = u32::MAX - 1;
        sending.first_unacknowledged = u32::MAX - 1;
        assert!(sending.push(Bytes::from_static(b"a")));
        assert!(sending.push(Bytes::from_static(b"b")));
        assert!(sending.push(Bytes::from_static(b"c")));
        assert_eq!(sending.window.len(), 3);
        assert!(sending.process_number(u32::MAX - 1));
        assert!(sending.process_number(u32::MAX));
        assert!(sending.process_number(0));
        assert!(sending.is_empty());
    }

    #[test]
    fn an_ack_below_the_window_is_ignored() {
        let mut sending = Sending::new(&options());
        sending.push(Bytes::from_static(b"a"));
        sending.clear(1);
        assert!(!sending.process_number(0));
    }

    #[test]
    fn acknowledgements_are_batched_and_then_cleared() {
        let mut receiving = Receiving::new(&options());
        let accepted = receiving.window_size.min(200);
        for number in 0..200u32 {
            receiving.process(&DataSegment {
                conv: 1,
                option: 0,
                timestamp: number,
                number,
                sending_next: 0,
                payload: Bytes::from_static(b"x"),
            });
        }
        let segments = receiving.flush(1000, 100);
        let total: usize = segments.iter().map(|s| s.numbers.len()).sum();
        assert_eq!(total, accepted as usize);
        assert_eq!(segments[0].numbers.len(), receiving.limit as usize);
        receiving.clear(101);
        assert!(receiving.acks.iter().all(|entry| entry.number >= 101));
    }

    #[test]
    fn reading_stops_at_the_first_missing_segment() {
        let mut receiving = Receiving::new(&options());
        let mut queue = VecDeque::new();
        for number in [0u32, 2, 3] {
            receiving.process(&DataSegment {
                conv: 1,
                option: 0,
                timestamp: 0,
                number,
                sending_next: 0,
                payload: Bytes::from_static(b"x"),
            });
        }
        receiving.drain(&mut queue);
        assert_eq!(queue.len(), 1);
        assert_eq!(receiving.next_number, 1);
        receiving.process(&DataSegment {
            conv: 1,
            option: 0,
            timestamp: 0,
            number: 1,
            sending_next: 0,
            payload: Bytes::from_static(b"y"),
        });
        receiving.drain(&mut queue);
        assert_eq!(queue.len(), 4);
        assert_eq!(receiving.next_number, 4);
    }
}
