//! A running server whose configuration can change in any way, inbounds
//! included, without the host restarting the process.
//!
//! How this works. [`Server::reload`] swaps everything a connection reads
//! when it starts (accounts, routing, DNS, outbounds, TLS material of TCP
//! inbounds) but keeps the listeners, which are bound once and known by
//! their place in the configuration. When a new configuration only changes
//! what a reload can, [`Host::apply`] reloads. When it adds, removes or
//! re-binds an inbound, or changes something a listener took when it started
//! (a QUIC certificate, a WireGuard peer, a socket option), the host hands
//! over instead: the listeners of the running server close, a successor
//! server built on the new configuration binds them, and it carries on the
//! same [`Stats`] (figures, accounts, speed limits, event subscribers), so
//! nothing a panel reads resets.
//!
//! The rules it keeps:
//!  * TCP sessions already open stay on the server that accepted them and
//!    run until they end; only accounts the new configuration drops on an
//!    inbound have their sessions ended, as a reload does;
//!  * a QUIC inbound's connections close with its listener: the socket they
//!    share must be released for the successor to bind it;
//!  * if the successor cannot bind, the previous configuration is put back
//!    and the error returned, so a bad change never leaves the server down.
//!
//! What it cannot do: between the old listeners closing and the new ones
//! binding (milliseconds, longer when a QUIC socket is slow to release) a
//! new connection is refused.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use zero_config::{Inbound, InboundProtocol, RuntimeConfig};
use zero_core::GenerationId;

use crate::server::{Server, ServerConfig, Stats};

/// How long a successor keeps trying to bind ports its predecessor's QUIC
/// sockets may still hold.
const BIND_PATIENCE: Duration = Duration::from_secs(5);
const BIND_RETRY: Duration = Duration::from_millis(100);

/// What [`Host::apply`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// A reload: the listeners stayed.
    Reloaded,
    /// A handover to a successor server with new listeners.
    Restarted,
}

struct Running {
    server: Arc<Server>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// A server and the configuration changes it goes through.
pub struct Host {
    stats: Arc<Stats>,
    current: arc_swap::ArcSwap<Server>,
    running: tokio::sync::Mutex<Option<Running>>,
    generation: AtomicU64,
    /// Set when the serving server stops by itself (not by a handover or
    /// [`Host::stop`]), with why.
    ended: Arc<tokio::sync::watch::Sender<Option<String>>>,
}

impl Host {
    /// Start serving `config`. Returns once every listener is bound.
    pub async fn start(config: Arc<RuntimeConfig>) -> std::io::Result<Self> {
        Self::start_with(config, Arc::new(Stats::default())).await
    }

    /// [`Host::start`] on `stats` set up beforehand (address tracking on, say).
    pub async fn start_with(
        config: Arc<RuntimeConfig>,
        stats: Arc<Stats>,
    ) -> std::io::Result<Self> {
        let ended = Arc::new(tokio::sync::watch::channel(None).0);
        let running = launch(config, GenerationId(1), &stats, Duration::ZERO, &ended).await?;
        Ok(Self {
            stats,
            current: arc_swap::ArcSwap::new(Arc::clone(&running.server)),
            running: tokio::sync::Mutex::new(Some(running)),
            generation: AtomicU64::new(1),
            ended,
        })
    }

    /// Resolve when the serving server stops by itself: every listener it
    /// had ended (a TUN device lost, say), or it failed. A handover or
    /// [`Host::stop`] does not count.
    pub async fn finished(&self) -> std::io::Result<()> {
        let mut ended = self.ended.subscribe();
        let why = loop {
            if let Some(why) = ended.borrow_and_update().clone() {
                break why;
            }
            if ended.changed().await.is_err() {
                return Ok(());
            }
        };
        if why.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(why))
        }
    }

    /// The server now serving. A handover replaces it, so hold it only for
    /// as long as one call needs it.
    pub fn server(&self) -> Arc<Server> {
        self.current.load_full()
    }

    /// The figures, accounts and events, which outlive any one server.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// Serve `config` from now on, by a reload when the listeners can stay
    /// and by a handover when they cannot.
    pub async fn apply(&self, config: Arc<RuntimeConfig>) -> Result<Applied, String> {
        let mut running = self.running.lock().await;
        let Some(current) = running.take() else {
            return Err("the host has stopped".into());
        };
        let generation = GenerationId(self.generation.fetch_add(1, Ordering::Relaxed) + 1);
        let previous = current.server.config_snapshot();
        if !needs_new_listeners(&previous, &config) {
            let result = current
                .server
                .reload(Arc::clone(&config), generation)
                .map(|()| Applied::Reloaded);
            *running = Some(current);
            return result;
        }
        config.validate()?;
        // A port the change newly asks for that something else holds would
        // only be found after the old listeners closed: look first, and keep
        // serving if it is taken.
        if let Err(error) = new_ports_free(&previous, &config) {
            *running = Some(current);
            return Err(error);
        }
        // Close the listeners; the sessions they accepted are their own tasks
        // and keep running on the old server.
        current.task.abort();
        let _ = current.task.await;
        match launch(
            Arc::clone(&config),
            generation,
            &self.stats,
            BIND_PATIENCE,
            &self.ended,
        )
        .await
        {
            Ok(successor) => {
                let accounts = crate::server::metered_accounts(&config);
                self.stats.accounts.end_where(|email, inbound| {
                    !accounts.contains(&(Arc::<str>::from(inbound), Arc::<str>::from(email)))
                });
                let (added, removed) = inbound_changes(&previous, &config);
                self.stats
                    .events()
                    .emit(|| crate::events::Event::InboundsChanged { added, removed });
                self.current.store(Arc::clone(&successor.server));
                *running = Some(successor);
                Ok(Applied::Restarted)
            }
            Err(error) => {
                // Put the previous configuration back rather than stay down.
                let restored = launch(
                    previous,
                    generation,
                    &self.stats,
                    BIND_PATIENCE,
                    &self.ended,
                )
                .await;
                match restored {
                    Ok(restored) => {
                        self.current.store(Arc::clone(&restored.server));
                        *running = Some(restored);
                        Err(format!("the new configuration could not start: {error}"))
                    }
                    Err(again) => Err(format!(
                        "the new configuration could not start ({error}), \
                         nor could the previous one ({again}); the host is stopped"
                    )),
                }
            }
        }
    }

    /// Close every listener, then wait up to `drain` for open sessions to
    /// finish. Returns how many were still open.
    pub async fn stop(&self, drain: Duration) -> u64 {
        let Some(current) = self.running.lock().await.take() else {
            return 0;
        };
        current.task.abort();
        let _ = current.task.await;
        current.server.drain(drain).await
    }
}

/// Build a server for `config` on `stats` and run it until its listeners are
/// bound, retrying for up to `patience` while a port is still taken.
async fn launch(
    config: Arc<RuntimeConfig>,
    generation: GenerationId,
    stats: &Arc<Stats>,
    patience: Duration,
    ended: &Arc<tokio::sync::watch::Sender<Option<String>>>,
) -> std::io::Result<Running> {
    let deadline = tokio::time::Instant::now() + patience;
    loop {
        let server = Arc::new(Server::with_stats(
            ServerConfig {
                config: Arc::clone(&config),
                generation,
            },
            Arc::clone(stats),
        ));
        let (running, ended) = (Arc::clone(&server), Arc::clone(ended));
        let mut task = tokio::spawn(async move {
            let result = Arc::clone(&running).run().await;
            // Reached only when the server stopped by itself: an aborted task
            // never gets here. A failure before the listeners were up is the
            // caller's to report, not an end of service.
            if running.is_listening() {
                let why = result
                    .as_ref()
                    .err()
                    .map_or(String::new(), |e| e.to_string());
                ended.send_replace(Some(why));
            }
            result
        });
        let outcome = tokio::select! {
            () = server.wait_until_listening() => Ok(()),
            ended = &mut task => Err(match ended {
                Ok(Ok(())) => std::io::Error::other("the server stopped as it started"),
                Ok(Err(error)) => error,
                Err(error) => std::io::Error::other(error.to_string()),
            }),
        };
        match outcome {
            Ok(()) => return Ok(Running { server, task }),
            Err(error) if port_taken(&error) && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(BIND_RETRY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Check that the addresses `new` listens on and `old` did not are free,
/// binding each for an instant (TCP, and UDP for the inbounds that use it).
fn new_ports_free(old: &RuntimeConfig, new: &RuntimeConfig) -> Result<(), String> {
    let bound = |inbound: &Inbound| (inbound.listen.clone(), inbound.port);
    let before: std::collections::HashSet<_> = old.inbounds.iter().map(bound).collect();
    for inbound in new.inbounds.iter().filter(|i| !before.contains(&bound(i))) {
        let ip = inbound
            .listen
            .as_ip()
            .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));
        let address = std::net::SocketAddr::new(ip, inbound.port);
        let udp = matches!(
            inbound.protocol,
            InboundProtocol::Hysteria2(_)
                | InboundProtocol::Tuic(_)
                | InboundProtocol::WireGuard(_)
        );
        let free = if udp {
            std::net::UdpSocket::bind(address).map(drop)
        } else {
            std::net::TcpListener::bind(address).map(drop)
        };
        if let Err(error) = free {
            return Err(format!(
                "inbound {:?} cannot listen on {address}: {error}",
                inbound.tag
            ));
        }
    }
    Ok(())
}

/// Whether `error` is a port still held, by a closing predecessor or by
/// something else. QUIC endpoints report it as text, not as the error kind.
fn port_taken(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AddrInUse
        || error.to_string().to_ascii_lowercase().contains("in use")
}

/// Whether serving `new` after `old` needs listeners a reload cannot give.
fn needs_new_listeners(old: &RuntimeConfig, new: &RuntimeConfig) -> bool {
    old.inbounds.len() != new.inbounds.len()
        || old
            .inbounds
            .iter()
            .zip(new.inbounds.iter())
            .any(|(old, new)| listener_differs(old, new))
}

/// What a listener took when it started, and a reload therefore cannot
/// change: where and how it is bound, and for the inbounds served by their
/// own loop, the settings that loop was given.
fn listener_differs(old: &Inbound, new: &Inbound) -> bool {
    if old.listen != new.listen
        || old.port != new.port
        || std::mem::discriminant(&old.protocol) != std::mem::discriminant(&new.protocol)
        || old.sockopt != new.sockopt
    {
        return true;
    }
    let quic = matches!(
        old.protocol,
        InboundProtocol::Hysteria2(_) | InboundProtocol::Tuic(_)
    ) || matches!(
        &old.transport,
        zero_config::Transport::Xhttp(settings)
            if settings.xhttp_http_version == zero_config::XhttpHttpVersion::Http3
    );
    // An mKCP inbound binds a UDP socket with its own session table and
    // tunables; none of that can be swapped under a running listener, and an
    // inbound that switches between mKCP and a TCP carrier must rebind.
    let old_kcp = match &old.transport {
        zero_config::Transport::Kcp(settings) => Some(settings.clone()),
        _ => None,
    };
    let new_kcp = match &new.transport {
        zero_config::Transport::Kcp(settings) => Some(settings.clone()),
        _ => None,
    };
    if old_kcp != new_kcp {
        return true;
    }
    // A QUIC endpoint holds its certificate from when it was made. Compared
    // in memory only: the text holds key material and is never printed.
    if quic
        && (format!("{:?}", old.security) != format!("{:?}", new.security)
            || format!("{:?}", old.transport) != format!("{:?}", new.transport))
    {
        return true;
    }
    match (&old.protocol, &new.protocol) {
        (InboundProtocol::Hysteria2(a), InboundProtocol::Hysteria2(b)) => {
            a.obfs_password != b.obfs_password || a.masquerade != b.masquerade
        }
        (InboundProtocol::WireGuard(a), InboundProtocol::WireGuard(b)) => a != b,
        (InboundProtocol::Tun(a), InboundProtocol::Tun(b)) => a != b,
        (InboundProtocol::Tide(a), InboundProtocol::Tide(b)) => a != b,
        (InboundProtocol::TideRelay(_), InboundProtocol::TideRelay(_))
        | (InboundProtocol::Dokodemo { .. }, InboundProtocol::Dokodemo { .. }) => {
            old.protocol != new.protocol
        }
        _ => false,
    }
}

/// The tags of the inbounds `new` adds to `old`, and of those it drops.
fn inbound_changes(old: &RuntimeConfig, new: &RuntimeConfig) -> (Vec<String>, Vec<String>) {
    let tags = |config: &RuntimeConfig| -> std::collections::BTreeSet<String> {
        config.inbounds.iter().map(|i| i.tag.to_string()).collect()
    };
    let (before, after) = (tags(old), tags(new));
    (
        after.difference(&before).cloned().collect(),
        before.difference(&after).cloned().collect(),
    )
}
