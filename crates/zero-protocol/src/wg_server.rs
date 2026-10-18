//! A WireGuard server: the responder side of the protocol, for the
//! `wireguard` inbound.
//!
//! It owns one UDP socket and one `boringtun` tunnel per configured peer, and
//! shows the rest of the program a plain IP-packet link:
//!
//! * [`WgLink::from_peers`] yields the packets peers sent, already decrypted,
//!   with where each came from;
//! * [`WgLink::to_peers`] takes packets to send, and finds the peer that
//!   should get each one;
//! * [`WgLink::peers`] replaces the list of peers while it runs.
//!
//! Changing the peers: each peer has a slot whose number is the high bits of
//! the receiver indexes its tunnel gives out. A peer that stays in the new
//! list keeps its slot and its tunnel, so its session goes on untouched; a
//! peer that leaves frees its slot, and a new one takes a free slot or a new
//! one. A late packet for a peer that left lands on whoever took its slot,
//! and fails to decrypt there like any forged packet.
//!
//! How packets find their peer (WireGuard's "cryptokey routing"):
//!
//! * **Inbound:** a handshake names its peer by its static key, which is
//!   readable once the message is parsed with our private key. Every later
//!   message carries the receiver index we gave out, whose high bits are the
//!   peer's number here.
//! * **Decrypted packets** are accepted only when their source address is in
//!   that peer's `allowed` list. Without this a peer could pose as any other.
//! * **Outbound:** the peer whose `allowed` list holds the packet's
//!   destination wins, the longest prefix first. A peer that has not yet
//!   spoken has no endpoint to send to, and a packet for it is dropped:
//!   a server cannot start a conversation with a client it has never heard.
//!
//! The one task owns every tunnel, so no tunnel is locked. Trade-off: all
//! peers share that task's time; one core carries a few hundred Mbit/s of
//! ChaCha20, which is what a proxy inbound needs.
//!
//! Not done: cookie-based load shedding for handshake floods beyond what
//! `boringtun` does for each peer's own tunnel.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{handshake::parse_handshake_anon, Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How often each tunnel's timers (keepalives, rekeys) are driven.
const TICK: Duration = Duration::from_millis(250);
/// Largest datagram or IP packet handled.
const MAX_PACKET: usize = 65_535;
/// Packets queued between the socket task and its user, each way.
const QUEUE: usize = 1024;

/// One peer the server accepts.
#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Source addresses this peer may use, and destinations sent to it, as
    /// `(network, prefix length)`.
    pub allowed: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
}

/// The packet side of a running server.
pub struct WgLink {
    /// Decrypted IP packets from peers, with the address each came from.
    pub from_peers: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    /// IP packets to encrypt and send to whichever peer owns the destination.
    pub to_peers: mpsc::Sender<Vec<u8>>,
    /// A new list of peers, in place of the current one.
    pub peers: mpsc::UnboundedSender<Vec<PeerSpec>>,
    /// The task that drives the socket; aborting it stops the server.
    pub task: tokio::task::JoinHandle<()>,
}

struct Peer {
    tunn: Tunn,
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    allowed: Vec<(IpAddr, u8)>,
    /// Where this peer's last authenticated packet came from.
    endpoint: Option<SocketAddr>,
}

/// The most slots: a receiver index keeps 8 low bits for the tunnel's own use.
const MAX_PEERS: usize = 1 << 23;

fn in_prefix(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
        let whole = usize::from(prefix / 8);
        let rest = prefix % 8;
        a[..whole] == b[..whole] && (rest == 0 || (a[whole] ^ b[whole]) >> (8 - rest) == 0)
    }
    match (network, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            prefix <= 32 && bits_match(&n.octets(), &i.octets(), prefix)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            prefix <= 128 && bits_match(&n.octets(), &i.octets(), prefix)
        }
        _ => false,
    }
}

impl Peer {
    fn new(secret: &StaticSecret, spec: PeerSpec, slot: usize) -> Self {
        Peer {
            tunn: Tunn::new(
                secret.clone(),
                PublicKey::from(spec.public_key),
                spec.preshared_key,
                spec.keepalive,
                slot as u32,
                None,
            ),
            public_key: spec.public_key,
            preshared_key: spec.preshared_key,
            allowed: spec.allowed,
            endpoint: None,
        }
    }

    /// The longest prefix of this peer's list that holds `ip`, if any.
    fn prefix_for(&self, ip: IpAddr) -> Option<u8> {
        self.allowed
            .iter()
            .filter(|(network, prefix)| in_prefix(*network, *prefix, ip))
            .map(|(_, prefix)| *prefix)
            .max()
    }
}

struct Server {
    socket: Arc<UdpSocket>,
    secret: StaticSecret,
    public: PublicKey,
    /// Peers by slot; a free slot is `None`.
    peers: Vec<Option<Peer>>,
    buffer: Vec<u8>,
}

impl Server {
    /// Serve `specs` from now on (see the module's description).
    fn set_peers(&mut self, specs: Vec<PeerSpec>) {
        for slot in &mut self.peers {
            let staying = slot.as_ref().and_then(|peer| {
                specs.iter().find(|spec| {
                    spec.public_key == peer.public_key && spec.preshared_key == peer.preshared_key
                })
            });
            match (slot.as_mut(), staying) {
                (Some(peer), Some(spec)) => peer.allowed = spec.allowed.clone(),
                _ => *slot = None,
            }
        }
        for spec in specs {
            if self
                .peers
                .iter()
                .flatten()
                .any(|peer| peer.public_key == spec.public_key)
            {
                continue;
            }
            let slot = match self.peers.iter().position(Option::is_none) {
                Some(free) => free,
                None if self.peers.len() < MAX_PEERS => {
                    self.peers.push(None);
                    self.peers.len() - 1
                }
                None => return,
            };
            self.peers[slot] = Some(Peer::new(&self.secret, spec, slot));
        }
    }

    /// Datagrams to put on the wire and IP packets for the user, gathered
    /// while a tunnel's result is unwrapped so no borrow outlives it.
    fn unwrap_result(
        result: TunnResult<'_>,
        wire: &mut Vec<Vec<u8>>,
        packets: &mut Vec<(Vec<u8>, IpAddr)>,
    ) -> bool {
        match result {
            TunnResult::WriteToNetwork(datagram) => {
                wire.push(datagram.to_vec());
                true
            }
            TunnResult::WriteToTunnelV4(packet, source) => {
                packets.push((packet.to_vec(), IpAddr::V4(source)));
                false
            }
            TunnResult::WriteToTunnelV6(packet, source) => {
                packets.push((packet.to_vec(), IpAddr::V6(source)));
                false
            }
            TunnResult::Done | TunnResult::Err(_) => false,
        }
    }

    /// Which peer a datagram belongs to, or `None` for anything unknown.
    fn peer_of(&self, datagram: &[u8]) -> Option<usize> {
        let index = match Tunn::parse_incoming_packet(datagram).ok()? {
            Packet::HandshakeInit(init) => {
                let half = parse_handshake_anon(&self.secret, &self.public, &init).ok()?;
                return self.peers.iter().position(|peer| {
                    peer.as_ref()
                        .is_some_and(|peer| peer.public_key == half.peer_static_public)
                });
            }
            Packet::HandshakeResponse(response) => response.receiver_idx,
            Packet::PacketCookieReply(reply) => reply.receiver_idx,
            Packet::PacketData(data) => data.receiver_idx,
        };
        let peer = (index >> 8) as usize;
        self.peers
            .get(peer)
            .is_some_and(Option::is_some)
            .then_some(peer)
    }

    async fn on_datagram(
        &mut self,
        length: usize,
        from: SocketAddr,
        to_user: &mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) {
        let datagram = self.buffer[..length].to_vec();
        let Some(index) = self.peer_of(&datagram) else {
            return;
        };
        let mut wire = Vec::new();
        let mut packets = Vec::new();
        let mut scratch = vec![0u8; MAX_PACKET];
        let Some(peer) = self.peers[index].as_mut() else {
            return;
        };
        let mut again = Self::unwrap_result(
            peer.tunn
                .decapsulate(Some(from.ip()), &datagram, &mut scratch),
            &mut wire,
            &mut packets,
        );
        // After a reply is written, the tunnel may hold more to say (queued
        // packets, a keepalive): asking with no datagram drains it.
        while again {
            again = Self::unwrap_result(
                peer.tunn.decapsulate(None, &[], &mut scratch),
                &mut wire,
                &mut packets,
            );
        }
        // Anything that decrypted or answered came from the peer holding the
        // key, so this is where it is now (WireGuard roams the same way).
        if !wire.is_empty() || !packets.is_empty() {
            peer.endpoint = Some(from);
        }
        for (packet, source) in packets {
            if peer.prefix_for(source).is_some() {
                let _ = to_user.send((packet, from)).await;
            }
        }
        for datagram in wire {
            let _ = self.socket.send_to(&datagram, from).await;
        }
    }

    async fn on_packet(&mut self, packet: &[u8]) {
        let Some(destination) = Tunn::dst_address(packet) else {
            return;
        };
        let Some(index) = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| Some((index, peer.as_ref()?.prefix_for(destination)?)))
            .max_by_key(|(_, prefix)| *prefix)
            .map(|(index, _)| index)
        else {
            return;
        };
        let Some(peer) = self.peers[index].as_mut() else {
            return;
        };
        let Some(endpoint) = peer.endpoint else {
            return;
        };
        let mut wire = Vec::new();
        let mut packets = Vec::new();
        let mut scratch = vec![0u8; packet.len() + 256];
        Self::unwrap_result(
            peer.tunn.encapsulate(packet, &mut scratch),
            &mut wire,
            &mut packets,
        );
        for datagram in wire {
            let _ = self.socket.send_to(&datagram, endpoint).await;
        }
    }

    async fn on_tick(&mut self) {
        let mut scratch = vec![0u8; 256];
        for peer in self.peers.iter_mut().flatten() {
            let Some(endpoint) = peer.endpoint else {
                continue;
            };
            let mut wire = Vec::new();
            let mut packets = Vec::new();
            Self::unwrap_result(
                peer.tunn.update_timers(&mut scratch),
                &mut wire,
                &mut packets,
            );
            for datagram in wire {
                let _ = self.socket.send_to(&datagram, endpoint).await;
            }
        }
    }
}

/// Start serving on `socket` for `peers` (at most 2^23, far more than a
/// server will hold), answering with `secret_key`.
pub fn serve(socket: Arc<UdpSocket>, secret_key: [u8; 32], peers: Vec<PeerSpec>) -> WgLink {
    let secret = StaticSecret::from(secret_key);
    let public = PublicKey::from(&secret);
    let (to_user, from_peers) = mpsc::channel(QUEUE);
    let (to_peers, mut from_user) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (peer_lists, mut new_peers) = mpsc::unbounded_channel::<Vec<PeerSpec>>();
    let mut server = Server {
        socket,
        secret,
        public,
        peers: Vec::new(),
        buffer: vec![0u8; MAX_PACKET],
    };
    server.set_peers(peers);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK);
        let receiving = Arc::clone(&server.socket);
        loop {
            // The receive buffer is a field, so reading into it needs the
            // socket cloned out first: the borrow would otherwise span the
            // `&mut self` calls below.
            let mut buffer = std::mem::take(&mut server.buffer);
            tokio::select! {
                received = receiving.recv_from(&mut buffer) => {
                    server.buffer = buffer;
                    match received {
                        Ok((length, from)) => server.on_datagram(length, from, &to_user).await,
                        // A connection-reset notice for an earlier send: the
                        // socket is fine.
                        Err(error) if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                        ) => {}
                        Err(_) => return,
                    }
                }
                packet = from_user.recv() => {
                    server.buffer = buffer;
                    match packet {
                        Some(packet) => server.on_packet(&packet).await,
                        None => return,
                    }
                }
                _ = ticker.tick() => {
                    server.buffer = buffer;
                    server.on_tick().await;
                }
                Some(peers) = new_peers.recv() => {
                    server.buffer = buffer;
                    server.set_peers(peers);
                }
            }
        }
    });
    WgLink {
        from_peers,
        to_peers,
        peers: peer_lists,
        task,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_match_bit_by_bit() {
        let net: IpAddr = "10.8.0.0".parse().unwrap();
        assert!(in_prefix(net, 24, "10.8.0.77".parse().unwrap()));
        assert!(!in_prefix(net, 24, "10.8.1.77".parse().unwrap()));
        assert!(in_prefix(net, 13, "10.15.255.255".parse().unwrap()));
        assert!(!in_prefix(net, 13, "10.16.0.0".parse().unwrap()));
        assert!(in_prefix(net, 0, "203.0.113.1".parse().unwrap()));
        assert!(
            !in_prefix(net, 24, "::1".parse().unwrap()),
            "families differ"
        );
        assert!(in_prefix(
            "fd00::".parse().unwrap(),
            8,
            "fdff::1".parse().unwrap()
        ));
        assert!(
            !in_prefix(net, 40, "10.8.0.1".parse().unwrap()),
            "prefix past the family"
        );
    }

    #[test]
    fn the_longest_prefix_wins() {
        let spec = |allowed: &[(&str, u8)]| Peer {
            tunn: Tunn::new(
                StaticSecret::from([1u8; 32]),
                PublicKey::from([2u8; 32]),
                None,
                None,
                0,
                None,
            ),
            public_key: [2; 32],
            preshared_key: None,
            allowed: allowed
                .iter()
                .map(|(ip, prefix)| (ip.parse().unwrap(), *prefix))
                .collect(),
            endpoint: None,
        };
        let peer = spec(&[("0.0.0.0", 0), ("10.8.0.0", 24)]);
        assert_eq!(peer.prefix_for("10.8.0.9".parse().unwrap()), Some(24));
        assert_eq!(peer.prefix_for("8.8.8.8".parse().unwrap()), Some(0));
        assert_eq!(peer.prefix_for("::1".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn a_peer_that_stays_keeps_its_slot_and_a_new_one_takes_a_free_slot() {
        let spec = |key: u8| PeerSpec {
            public_key: *PublicKey::from(&StaticSecret::from([key; 32])).as_bytes(),
            preshared_key: None,
            allowed: vec![("10.0.0.0".parse().unwrap(), 8)],
            keepalive: None,
        };
        let secret = StaticSecret::from([9u8; 32]);
        let mut server = Server {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            public: PublicKey::from(&secret),
            secret,
            peers: Vec::new(),
            buffer: Vec::new(),
        };
        server.set_peers(vec![spec(1), spec(2)]);
        server.peers[1].as_mut().unwrap().endpoint = Some("127.0.0.1:9".parse().unwrap());
        server.set_peers(vec![spec(2), spec(3)]);
        let keys: Vec<Option<[u8; 32]>> = server
            .peers
            .iter()
            .map(|peer| peer.as_ref().map(|peer| peer.public_key))
            .collect();
        assert_eq!(
            keys,
            vec![Some(spec(3).public_key), Some(spec(2).public_key)]
        );
        assert!(
            server.peers[1].as_ref().unwrap().endpoint.is_some(),
            "the peer that stayed kept its tunnel and endpoint"
        );
        server.set_peers(Vec::new());
        assert!(server.peers.iter().all(Option::is_none));
    }
}
