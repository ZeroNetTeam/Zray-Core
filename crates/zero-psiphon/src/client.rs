//! Server selection, the dial loop, and the streams a caller gets.
//!
//! A [`Client`] owns a pool of established Psiphon tunnels and hands out
//! streams to destinations the way a SOCKS proxy does. Establishing a tunnel
//! is the Psiphon client's core loop: take the (server entry, transport) pairs
//! in preference order, dial several at once — a blocked or slow address must
//! not hold the others up — and keep the first that completes both the SSH
//! session and the tunnel handshake. A tunnel that dies is replaced on the
//! next dial.
//!
//! What this port deliberately does not do: it does not run Psiphon's large
//! tunnel pool, and it has no local SOCKS/HTTP listener — Zray's router is the
//! proxy that uses these streams.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use crate::config::{ClientConfig, TunnelDialOptions};
use crate::error::{Error, Result};
use crate::obfuscator::OsshClient;
use crate::protocol::TunnelProtocol;
use crate::server_entry::ServerEntry;
use crate::tunnel::{HandshakeParams, SshTunnel, TunnelOptions, TunnelStream};
use zero_core::stream::{boxed, BoxStream};

/// TCP connect budget for one server address.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// A connected Psiphon client.
pub struct Client {
    config: ClientConfig,
    session_id: String,
    /// Established tunnels, at most `tunnel_pool_size` of them.
    tunnels: Mutex<Vec<Arc<SshTunnel>>>,
    /// Which tunnel the next dial uses.
    next_tunnel: AtomicUsize,
    /// Channels currently open, against `max_channels`. Shared with the
    /// streams that are handed out, so a dropped stream frees its slot.
    open_channels: Arc<AtomicUsize>,
}

impl Client {
    /// Establish a tunnel, trying the configured server entries in order.
    pub async fn connect(config: ClientConfig) -> Result<Client> {
        Self::connect_with_tactics(config, None).await
    }

    /// Establish a tunnel, fetching Psiphon's tactics first when the
    /// configuration asks for them.
    ///
    /// The tactics fetch needs an HTTP carrier, which this crate does not
    /// have: the caller supplies one, and a client that does not want tactics
    /// passes `None`. The tactics that come back adjust the dial — how long a
    /// tunnel may take, how much padding the obfuscated layer adds — and are
    /// then applied to the configuration the tunnel is built from.
    pub async fn connect_with_tactics(
        mut config: ClientConfig,
        transport: Option<&mut dyn crate::tactics::TacticsTransport>,
    ) -> Result<Client> {
        config.validate()?;

        if let Some(proxy) = &config.upstream_proxy {
            // Refusing beats silently ignoring a proxy the operator asked for:
            // dialling directly would leak the traffic the proxy exists to
            // hide, and would fail closed on the wrong network.
            return Err(Error::Config(format!(
                "the {:?} upstream proxy {}:{} is not supported in this build",
                proxy.kind, proxy.host, proxy.port
            )));
        }

        let session_id = match config.session_id.clone() {
            Some(session_id) => session_id,
            None => crate::tunnel::new_session_id(),
        };

        // Tactics first: they say how long a tunnel may take and how much
        // padding to add, and both are needed before the first dial.
        if config.tactics {
            if let Some(transport) = transport {
                let mut rng = rand::thread_rng();
                let mut record = crate::tactics::TacticsRecord::empty();
                let now = std::time::SystemTime::now();
                let entry = config.server_entries.first().cloned().ok_or_else(|| {
                    Error::Config("the psiphon outbound has no server entries".into())
                })?;
                let parameters = serde_json::json!({});
                match crate::tactics::fetch_tactics(
                    &mut record,
                    &entry,
                    &parameters,
                    &mut *transport,
                    &mut rng,
                    now,
                ) {
                    Ok(true) => apply_tactics(&mut config, &record),
                    Ok(false) => tracing::debug!(
                        target: "zero_psiphon",
                        "the server offered no new tactics",
                    ),
                    Err(error) => {
                        // Tactics are an optimisation, not a requirement: a
                        // server that will not answer must not stop the
                        // client from dialling.
                        tracing::debug!(
                            target: "zero_psiphon",
                            error = %error,
                            "the tactics fetch failed; dialling with the configured parameters",
                        );
                    }
                }
            } else {
                tracing::debug!(
                    target: "zero_psiphon",
                    "tactics are enabled but no transport was supplied; dialling with the configured parameters",
                );
            }
        }

        // One tunnel before returning, so `connect` means "ready to dial".
        // Boxed: the dial loop's future is large, and it is nested inside
        // this one, which is nested inside the caller's. Each level of that
        // nesting is a stack frame on the thread that polls it, and the
        // session handling this ends up inside has little stack to spare.
        let first = Box::pin(establish(&config, &session_id)).await?;
        let client = Client {
            config,
            session_id,
            tunnels: Mutex::new(vec![Arc::new(first)]),
            next_tunnel: AtomicUsize::new(0),
            open_channels: Arc::new(AtomicUsize::new(0)),
        };

        // The rest of the pool, if one was asked for: a second tunnel means a
        // dead one costs a dial rather than an outage.
        while client.tunnel_count().await < client.config.tunnel_pool_size {
            match establish(&client.config, &client.session_id).await {
                Ok(tunnel) => client.tunnels.lock().await.push(Arc::new(tunnel)),
                Err(error) => {
                    tracing::debug!(
                        target: "zero_psiphon",
                        error = %error,
                        "could not grow the psiphon tunnel pool"
                    );
                    break;
                }
            }
        }

        Ok(client)
    }

    /// Open one stream to `host:port` through the tunnel pool.
    ///
    /// The host is passed through unresolved, exactly as Psiphon does: the
    /// server resolves it, so the local resolver never learns the destination.
    pub async fn dial(&self, host: &str, port: u16) -> Result<BoxStream> {
        if self.open_channels.fetch_add(1, Ordering::Relaxed) as u32 >= self.config.max_channels {
            self.open_channels.fetch_sub(1, Ordering::Relaxed);
            return Err(Error::Config(format!(
                "the psiphon outbound already has {} channels open, its configured maximum",
                self.config.max_channels
            )));
        }

        match self.dial_inner(host, port).await {
            Ok(stream) => Ok(boxed(stream)),
            Err(error) => {
                self.open_channels.fetch_sub(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    /// The dial itself. The channel count is taken by [`Client::dial`] and
    /// released by the returned stream's drop, so every path that opens a
    /// channel frees its slot exactly once.
    async fn dial_inner(&self, host: &str, port: u16) -> Result<CountedStream> {
        let mut last_error = None;

        // Two passes: the first over the tunnels already established, the
        // second after re-establishing, which is what a tunnel the server has
        // torn down between dials needs.
        for _attempt in 0..2 {
            let tunnels: Vec<Arc<SshTunnel>> = self.tunnels.lock().await.clone();
            if !tunnels.is_empty() {
                // Round-robin so the pool is used evenly, and so a busy tunnel
                // does not take every new channel.
                let start = self.next_tunnel.fetch_add(1, Ordering::Relaxed);
                for offset in 0..tunnels.len() {
                    let tunnel = &tunnels[(start + offset) % tunnels.len()];
                    match tunnel.open(host, port).await {
                        Ok(inner) => {
                            return Ok(CountedStream {
                                inner,
                                open_channels: Arc::clone(&self.open_channels),
                                counted: true,
                            })
                        }
                        Err(error) => {
                            tracing::debug!(
                                target: "zero_psiphon",
                                host = %host,
                                port,
                                error = %error,
                                "psiphon channel open failed"
                            );
                            last_error = Some(error);
                        }
                    }
                }
                // Every established tunnel refused the channel: the tunnels
                // are stale, not the destination.
                *self.tunnels.lock().await = Vec::new();
            }

            match establish(&self.config, &self.session_id).await {
                Ok(tunnel) => self.tunnels.lock().await.push(Arc::new(tunnel)),
                Err(error) => {
                    return Err(Error::Connect(format!(
                        "no psiphon tunnel could be established after a channel failure: {error}"
                    )))
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::Channel(format!("no tunnel could open a channel to {host}:{port}"))
        }))
    }

    /// The configuration this client was built from.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// True when at least one tunnel is established.
    pub async fn is_alive(&self) -> bool {
        !self.tunnels.lock().await.is_empty()
    }

    /// How many tunnels are established.
    pub async fn tunnel_count(&self) -> usize {
        self.tunnels.lock().await.len()
    }

    /// The server entry of the first tunnel, when one is up.
    pub async fn server_entry(&self) -> Option<ServerEntry> {
        self.tunnels
            .lock()
            .await
            .first()
            .map(|tunnel| tunnel.server_entry().clone())
    }

    /// The transport of the first tunnel, when one is up.
    pub async fn protocol(&self) -> Option<TunnelProtocol> {
        self.tunnels
            .lock()
            .await
            .first()
            .map(|tunnel| tunnel.protocol())
    }

    /// Close every tunnel. The client can dial again afterwards.
    pub async fn close(&self) {
        let tunnels = std::mem::take(&mut *self.tunnels.lock().await);
        for tunnel in tunnels {
            if let Ok(tunnel) = Arc::try_unwrap(tunnel) {
                tunnel.close().await;
            }
        }
    }
}

/// A channel stream that releases the client's channel slot when it is
/// dropped, whether the caller read it to the end or abandoned it.
pub struct CountedStream {
    inner: TunnelStream,
    open_channels: Arc<AtomicUsize>,
    counted: bool,
}

impl Drop for CountedStream {
    fn drop(&mut self) {
        if self.counted {
            self.open_channels.fetch_sub(1, Ordering::Relaxed);
            self.counted = false;
        }
    }
}

impl AsyncRead for CountedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Apply the tactics the server sent to the configuration.
///
/// Only the parameters this client uses are applied: the establishment
/// timeout and the obfuscated layer's padding range. Everything else in a
/// tactics record concerns traffic shaping this port does not implement, and
/// is left for a future version rather than half-applied.
fn apply_tactics(config: &mut ClientConfig, record: &crate::tactics::TacticsRecord) {
    let parameters = &record.tactics.parameters;

    if let Some(timeout) = parameters.establish_tunnel_timeout {
        config.establish_timeout = timeout;
    }
    if let Some(timeout) = parameters.tunnel_connect_timeout {
        // The per-stage budget may not exceed the whole-establishment one.
        config.establish_timeout = config
            .establish_timeout
            .min(timeout.max(Duration::from_secs(1)));
    }
    if let (Some(minimum), Some(maximum)) =
        (parameters.ossh_min_padding, parameters.ossh_max_padding)
    {
        if minimum <= maximum {
            config.ossh_padding = Some((minimum, maximum));
        }
    }
}

/// Establish one tunnel, racing up to `establish_concurrency` candidates.
///
/// Racing rather than trying in strict order is what makes a dial fast when
/// the first candidate is a black hole: a filtered address accepts the TCP
/// connection and then says nothing, so a sequential client waits out the
/// whole budget before trying the next entry.
async fn establish(config: &ClientConfig, session_id: &str) -> Result<SshTunnel> {
    let candidates = candidate_list(config)?;
    let concurrency = config.establish_concurrency.max(1).min(candidates.len());

    if concurrency <= 1 {
        let mut failures = Vec::new();
        for (entry, protocol) in candidates {
            match attempt(config, &entry, protocol, session_id).await {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) => failures.push(format!(
                    "{} over {protocol}: {error}",
                    entry.diagnostic_id()
                )),
            }
        }
        return Err(Error::Connect(format!(
            "no psiphon tunnel could be established ({})",
            failures.join("; ")
        )));
    }

    // The candidates are borrowed by the futures, so they outlive the loop.
    let candidates: Vec<(ServerEntry, TunnelProtocol)> = candidates;
    let mut failures: Vec<String> = Vec::new();
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;

    // Fill the first window, then keep it full as results come in.
    while next < candidates.len() && pending.len() < concurrency {
        let (entry, protocol) = &candidates[next];
        pending.push(Box::pin(attempt(config, entry, *protocol, session_id)));
        next += 1;
    }

    while let Some(result) = pending.next().await {
        match result {
            Ok(tunnel) => {
                // The race is over: drop the other in-flight dials.
                return Ok(tunnel);
            }
            Err(error) => {
                failures.push(error);
                if next < candidates.len() {
                    let (entry, protocol) = &candidates[next];
                    pending.push(Box::pin(attempt(config, entry, *protocol, session_id)));
                    next += 1;
                }
            }
        }
    }

    Err(Error::Connect(format!(
        "no psiphon tunnel could be established ({})",
        failures.join("; ")
    )))
}

/// The (server entry, transport) pairs to try, in preference order.
///
/// The client's `protocols` narrows the list when set; the egress region
/// narrows it to entries in that region, keeping entries whose region is
/// unknown (embedded entries can omit it) as a last resort.
fn candidate_list(config: &ClientConfig) -> Result<Vec<(ServerEntry, TunnelProtocol)>> {
    let mut candidates = Vec::new();

    for entry in &config.server_entries {
        if !config.egress_region.is_empty()
            && !entry.region().is_empty()
            && entry.region() != config.egress_region
        {
            continue;
        }

        for protocol in entry.supported_protocols() {
            if !config.protocols.is_empty() && !config.protocols.contains(&protocol) {
                continue;
            }
            candidates.push((entry.clone(), protocol));
        }
    }

    if candidates.is_empty() {
        return Err(Error::Config(
            "no configured psiphon server entry offers a supported transport".into(),
        ));
    }
    Ok(candidates)
}

/// Build one carrier, run SSH over it, and complete the tunnel handshake.
///
/// The error carries the entry and transport, because a race reports several
/// and the caller needs to know which one failed.
async fn attempt(
    config: &ClientConfig,
    entry: &ServerEntry,
    protocol: TunnelProtocol,
    session_id: &str,
) -> std::result::Result<SshTunnel, String> {
    let describe = |error: Error| format!("{} over {protocol}: {error}", entry.diagnostic_id());

    let host = entry.host_for(protocol).map_err(describe)?;
    let port = entry.port_for(protocol).map_err(describe)?;

    let options = TunnelOptions {
        // The identification line is the SSH one; the Psiphon client version is
        // a separate, numeric field of the handshake (the server validates it
        // as an integer string).
        client_version: crate::tunnel::DEFAULT_CLIENT_VERSION.to_string(),
        keepalive_interval: config.keepalive_interval,
        window_size: config.channel_window_bytes,
        session_id: Some(session_id.to_string()),
        sponsor_id: config.handshake.sponsor_id.clone(),
        ..Default::default()
    };

    let budget = config.establish_timeout;
    let stream = Box::pin(carrier(
        config,
        entry,
        protocol,
        &host,
        port,
        &config.dial_options,
    ))
    .await
    .map_err(describe)?;

    // The SSH handshake's future is large, and it is nested inside the dial
    // loop's future, which is nested inside the client's. Boxing each step
    // keeps the whole chain off the worker thread's stack: a chain of inline
    // frames is a chain of stack frames, and this one overflowed it.
    let tunnel = Box::pin(SshTunnel::establish(stream, entry, &options, budget))
        .await
        .map_err(describe)?
        .with_protocol(protocol);

    let handshake = HandshakeParams::new(protocol)
        .with_propagation_channel_id(config.handshake.propagation_channel_id.clone())
        .with_sponsor_id(config.handshake.sponsor_id.clone())
        .with_client_version(config.handshake.client_version.clone())
        .with_client_platform(config.handshake.client_platform.clone());
    tunnel.handshake(&handshake).await.map_err(describe)?;

    Ok(tunnel)
}

/// Pick the fronting address to dial: one of the entry's edges, at random,
/// so that a block of one edge does not block the server.
fn pick_fronting_address(entry: &ServerEntry) -> Option<String> {
    let addresses = entry.meek_fronting_addresses();
    if addresses.is_empty() {
        // Older entries name a single fronting domain instead of a list.
        let domain = entry.host_for(TunnelProtocol::FrontedMeek).ok()?;
        return Some(domain);
    }
    let mut rng = rand::thread_rng();
    let index = rand::Rng::gen_range(&mut rng, 0..addresses.len());
    Some(addresses[index].clone())
}

/// Pick the fronting host to ask for. It is chosen independently of the
/// address, which is what lets a client reach an edge by address while asking
/// for a name that edge is configured to serve.
fn pick_fronting_host(entry: &ServerEntry) -> Option<String> {
    let hosts = entry.meek_fronting_hosts();
    if !hosts.is_empty() {
        let mut rng = rand::thread_rng();
        let index = rand::Rng::gen_range(&mut rng, 0..hosts.len());
        return Some(hosts[index].clone());
    }
    let single = entry.meek_fronting_host();
    if !single.is_empty() {
        return Some(single.to_string());
    }
    let domain = entry.host_for(TunnelProtocol::FrontedMeek).ok()?;
    Some(domain)
}

/// The byte stream the SSH handshake rides on, per transport.
async fn carrier(
    config: &ClientConfig,
    entry: &ServerEntry,
    protocol: TunnelProtocol,
    host: &str,
    port: u16,
    options: &TunnelDialOptions,
) -> Result<BoxedCarrier> {
    match protocol {
        TunnelProtocol::Ssh => {
            let stream = tcp(host, port).await?;
            Ok(Box::new(stream) as BoxedCarrier)
        }
        TunnelProtocol::Ossh => {
            let stream = tcp(host, port).await?;
            Ok(Box::new(OsshClient::with_padding_range(
                stream,
                entry.ssh_obfuscated_key().as_bytes(),
                config.ossh_padding,
            )) as BoxedCarrier)
        }
        TunnelProtocol::TlsOssh => {
            let stream = tcp(host, port).await?;
            // No SNI: the Go client only sends a name when tactics provide
            // one, and it dials the server's address rather than a domain.
            let options = crate::tls_ossh::TlsOsshOptions::default();
            Ok(
                Box::new(crate::tls_ossh::wrap(stream, entry.ssh_obfuscated_key(), &options).await?)
                    as BoxedCarrier,
            )
        }
        TunnelProtocol::UnfrontedMeek
        | TunnelProtocol::UnfrontedMeekHttps
        | TunnelProtocol::UnfrontedMeekSessionTicket => {
            // Unfronted meek: the server is reached directly, over TLS for
            // the HTTPS variants.
            let port = entry.meek_server_port().ok_or_else(|| {
                Error::Config(format!(
                    "server entry {} offers no meek port",
                    entry.diagnostic_id()
                ))
            })?;
            let host = entry.ip_address().to_string();
            let host_header = format!("{host}:{port}");

            let stream = if matches!(
                protocol,
                TunnelProtocol::UnfrontedMeekHttps | TunnelProtocol::UnfrontedMeekSessionTicket
            ) {
                // The meek server's certificate is self-signed and
                // regenerated at every restart, so it cannot be verified;
                // the SSH host key inside is what proves the server's
                // identity.
                let tcp = tcp(&host, port).await?;
                let config = crate::tls_ossh::tls_config(
                    entry.meek_obfuscated_key(),
                    &crate::tls_ossh::TlsOsshOptions {
                        passthrough: false,
                        ..Default::default()
                    },
                );
                let connector = tokio_rustls::TlsConnector::from(config);
                let name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|error| Error::Connect(format!("meek server name: {error}")))?;
                let tls = connector
                    .connect(name, tcp)
                    .await
                    .map_err(|error| Error::Connect(format!("meek TLS handshake: {error}")))?;
                Box::new(tls) as BoxedCarrier
            } else {
                Box::new(tcp(&host, port).await?) as BoxedCarrier
            };

            let options = crate::meek::MeekOptions::unfronted(
                protocol,
                entry.meek_obfuscated_key(),
                entry.meek_cookie_encryption_public_key(),
                host_header,
            );
            let mut rng = rand::thread_rng();
            let meek = crate::meek::MeekStream::new(stream, options, &mut rng)?;

            // The SSH session rides on the meek connection, under the same
            // obfuscation layer as the plain transports.
            Ok(
                Box::new(OsshClient::new(meek, entry.ssh_obfuscated_key().as_bytes()))
                    as BoxedCarrier,
            )
        }
        TunnelProtocol::FrontedMeek | TunnelProtocol::FrontedMeekHttp => {
            // Fronted meek puts a CDN between the client and the server: the
            // connection goes to a fronting address, the `Host` header (and,
            // for TLS, the server name) names a fronting host, and the CDN
            // forwards to a server it has been told to serve. What travels is
            // the same HTTP carrier — and the same obfuscated cookie — as the
            // unfronted transports.
            let dial_host = pick_fronting_address(entry).ok_or_else(|| {
                Error::Config(format!(
                    "server entry {} is fronted but names no fronting address",
                    entry.diagnostic_id()
                ))
            })?;
            let host_header = pick_fronting_host(entry).ok_or_else(|| {
                Error::Config(format!(
                    "server entry {} is fronted but names no fronting host",
                    entry.diagnostic_id()
                ))
            })?;

            // Plain HTTP for FRONTED-MEEK-HTTP-OSSH, HTTPS for the rest: the
            // scheme is the difference between the two fronted transports.
            let http_only = protocol == TunnelProtocol::FrontedMeekHttp;
            let dial_port = options
                .fronted_dial_port
                .unwrap_or(if http_only { 80 } else { 443 });

            let stream = tcp(&dial_host, dial_port).await?;
            let stream = if http_only {
                Box::new(stream) as BoxedCarrier
            } else {
                let sni = if entry.meek_fronting_disable_sni() {
                    None
                } else {
                    Some(dial_host.clone())
                };
                let tls_options = crate::tls_ossh::TlsOsshOptions {
                    server_name: sni,
                    passthrough: false,
                    ..Default::default()
                };
                let config = crate::tls_ossh::tls_config(entry.meek_obfuscated_key(), &tls_options);
                let connector = tokio_rustls::TlsConnector::from(config);
                let name = rustls::pki_types::ServerName::try_from(dial_host.clone())
                    .map_err(|error| Error::Meek(format!("fronting server name: {error}")))?;
                let tls = Box::pin(connector.connect(name, stream))
                    .await
                    .map_err(|error| Error::Connect(format!("fronting TLS handshake: {error}")))?;
                Box::new(tls) as BoxedCarrier
            };

            let meek_options = crate::meek::MeekOptions::fronted(
                protocol,
                entry.meek_obfuscated_key(),
                entry.meek_cookie_encryption_public_key(),
                host_header,
            );
            let mut rng = rand::thread_rng();
            let meek = crate::meek::MeekStream::new(stream, meek_options, &mut rng)?;
            Ok(
                Box::new(OsshClient::new(meek, entry.ssh_obfuscated_key().as_bytes()))
                    as BoxedCarrier,
            )
        }
        TunnelProtocol::ShadowsocksOssh
        | TunnelProtocol::QuicOssh
        | TunnelProtocol::FrontedMeekQuicOssh
        | TunnelProtocol::TapdanceOssh
        | TunnelProtocol::ConjureOssh => Err(Error::Protocol(format!(
            "the {protocol} transport is not implemented in this build"
        ))),
    }
}

/// A boxed carrier stream. `russh::client::connect_stream` is generic, so a
/// carrier is boxed only at this setup boundary, never per packet.
type BoxedCarrier = Box<dyn CarrierStream>;

/// The stream requirements the SSH handshake places on a carrier.
pub trait CarrierStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> CarrierStream for T {}

async fn tcp(host: &str, port: u16) -> Result<tokio::net::TcpStream> {
    let mut addresses: Vec<std::net::SocketAddr> = Vec::new();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        addresses.push(std::net::SocketAddr::new(ip, port));
    } else {
        let resolved = tokio::time::timeout(TCP_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| Error::Timeout { stage: "resolve" })?
            .map_err(|error| Error::Connect(format!("resolving {host}: {error}")))?;
        addresses.extend(resolved);
    }
    if addresses.is_empty() {
        return Err(Error::Connect(format!("{host} has no address")));
    }

    let mut last = None;
    for address in addresses {
        match tokio::time::timeout(TCP_TIMEOUT, zero_core::connect_protected(address)).await {
            Ok(Ok(stream)) => {
                // Proxy traffic is request/response: the latency of a small
                // request matters more than the cost of a small packet.
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(error)) => last = Some(error),
            Err(_) => {
                last = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timed out",
                ))
            }
        }
    }
    Err(Error::Connect(format!(
        "connecting to {host}:{port}: {}",
        last.map(|error| error.to_string())
            .unwrap_or_else(|| "no address".into())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn entry(region: &str, capabilities: &[&str]) -> ServerEntry {
        ServerEntry::from_value(serde_json::json!({
            "ipAddress": "127.0.0.1",
            "region": region,
            "sshPort": 1,
            "sshObfuscatedPort": 2,
            "tlsOSSHPort": 3,
            "sshHostKey": "AAAA",
            "sshPassword": "password",
            "capabilities": capabilities,
        }))
        .unwrap()
    }

    fn config(entries: Vec<ServerEntry>) -> ClientConfig {
        ClientConfig {
            server_entries: entries,
            establish_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    #[test]
    fn candidates_are_offered_per_entry_and_capability() {
        let config = config(vec![entry("US", &["SSH", "OSSH"])]);
        let list = candidate_list(&config).unwrap();
        assert_eq!(
            list.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            vec![TunnelProtocol::Ssh, TunnelProtocol::Ossh]
        );
    }

    #[test]
    fn the_transport_limit_narrows_the_candidates() {
        let mut config = config(vec![entry("US", &["SSH", "OSSH"])]);
        config.protocols = vec![TunnelProtocol::Ossh];
        let list = candidate_list(&config).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1, TunnelProtocol::Ossh);
    }

    #[test]
    fn the_egress_region_filters_entries() {
        let mut config = config(vec![
            entry("US", &["SSH"]),
            entry("GB", &["SSH"]),
            entry("", &["SSH"]),
        ]);
        config.egress_region = "GB".into();
        let list = candidate_list(&config).unwrap();
        // The GB entry and the region-less one (a last resort) remain.
        assert_eq!(list.len(), 2);
    }

    /// Read an HTTP request head from `stream` and return it as text.
    async fn read_request_head<S>(stream: &mut S) -> String
    where
        S: AsyncRead + Unpin,
    {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte).await {
                Ok(0) => panic!("the carrier closed before sending a request"),
                Ok(_) => head.push(byte[0]),
                Err(error) => panic!("reading the request head: {error}"),
            }
            assert!(head.len() < 8192, "the request head is not that long");
        }
        String::from_utf8(head).expect("the request head is text")
    }

    /// The plain-HTTP fronted carrier: the request goes to the fronting
    /// address, and it asks for the fronting host.
    #[tokio::test]
    async fn the_fronted_http_carrier_asks_for_the_fronting_host() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        use base64::Engine as _;
        let cookie_key = base64::engine::general_purpose::STANDARD
            .encode(crate::nacl_box::public_key(&[0x11u8; 32]));
        let entry = ServerEntry::from_value(serde_json::json!({
            "ipAddress": "192.0.2.10",
            "meekServerPort": 20087,
            "meekFrontingAddresses": ["127.0.0.1"],
            "meekFrontingHosts": ["front.example"],
            "meekObfuscatedKey": "obfuscation-key",
            "meekCookieEncryptionPublicKey": cookie_key,
            "sshObfuscatedKey": "obfuscation-key",
            "sshHostKey": "AAAA",
            "sshPassword": "password",
            "capabilities": ["FRONTED-MEEK-HTTP-OSSH"],
        }))
        .unwrap();

        let mut config = ClientConfig::default();
        config.dial_options.fronted_dial_port = Some(port);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request_head(&mut stream).await
        });

        // The carrier itself does no I/O; the request goes out when the SSH
        // layer writes its version line and flushes.
        let mut carrier = carrier(
            &config,
            &entry,
            TunnelProtocol::FrontedMeekHttp,
            "127.0.0.1",
            port,
            &config.dial_options,
        )
        .await
        .expect("the fronted carrier is built");
        assert!(carrier.write_all(b"SSH-2.0-test\r\n").await.is_ok());
        let _ = carrier.flush().await;

        let head = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("the request head arrives")
            .unwrap();
        assert!(head.starts_with("POST / HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains("Host: front.example\r\n"),
            "the Host header names the fronting host: {head}"
        );
        assert!(head.contains("Cookie: "), "{head}");
        assert!(head.contains("Content-Length: "), "{head}");
        assert!(
            !head.contains("192.0.2.10"),
            "the server's own address is not on the wire: {head}"
        );
    }

    /// The TLS fronted carrier: the same request, inside a TLS session whose
    /// server name is the *fronting address*, not the host it asks for.
    #[tokio::test]
    async fn the_fronted_https_carrier_uses_the_fronting_address_as_its_name() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        use base64::Engine as _;
        let cookie_key = base64::engine::general_purpose::STANDARD
            .encode(crate::nacl_box::public_key(&[0x11u8; 32]));
        let entry = ServerEntry::from_value(serde_json::json!({
            "ipAddress": "192.0.2.10",
            "meekServerPort": 20087,
            "meekFrontingAddresses": ["127.0.0.1"],
            "meekFrontingHosts": ["front.example"],
            "meekObfuscatedKey": "obfuscation-key",
            "meekCookieEncryptionPublicKey": cookie_key,
            "sshObfuscatedKey": "obfuscation-key",
            "sshHostKey": "AAAA",
            "sshPassword": "password",
            "capabilities": ["FRONTED-MEEK-OSSH"],
        }))
        .unwrap();

        let config = {
            let mut config = ClientConfig::default();
            config.dial_options.fronted_dial_port = Some(port);
            config
        };

        let server = tokio::spawn(async move {
            let acceptor =
                tokio_rustls::TlsAcceptor::from(crate::test_certificate::tls_server_config());
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor
                .accept(stream)
                .await
                .expect("the client completes the TLS handshake");
            read_request_head(&mut tls).await
        });

        let mut carrier = carrier(
            &config,
            &entry,
            TunnelProtocol::FrontedMeek,
            "127.0.0.1",
            port,
            &config.dial_options,
        )
        .await
        .expect("the fronted TLS carrier is built");
        assert!(carrier.write_all(b"SSH-2.0-test\r\n").await.is_ok());
        let _ = carrier.flush().await;

        let head = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("the TLS handshake and the request arrive")
            .unwrap();
        assert!(head.starts_with("POST / HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("Host: front.example\r\n"), "{head}");
        assert!(!head.contains("192.0.2.10"), "{head}");
    }

    #[test]
    fn a_fronted_entry_offers_the_fronting_address_and_host() {
        // The two choices are independent, which is what lets a client reach
        // an edge by address while asking for a name that edge serves.
        let entry = ServerEntry::from_value(serde_json::json!({
            "ipAddress": "192.0.2.10",
            "region": "US",
            "meekServerPort": 20087,
            "sshObfuscatedPort": 20082,
            "meekFrontingAddresses": ["192.0.2.50", "192.0.2.51"],
            "meekFrontingHosts": ["front-a.example", "front-b.example"],
            "sshHostKey": "AAAA",
            "sshPassword": "password",
            "capabilities": ["FRONTED-MEEK-OSSH"],
        }))
        .unwrap();

        let address = pick_fronting_address(&entry).expect("an address");
        assert!(
            ["192.0.2.50", "192.0.2.51"].contains(&address.as_str()),
            "{address}"
        );
        let host = pick_fronting_host(&entry).expect("a host");
        assert!(
            ["front-a.example", "front-b.example"].contains(&host.as_str()),
            "{host}"
        );

        // Both picks vary: one edge being blocked must not block the server.
        let addresses: std::collections::HashSet<String> = (0..64)
            .filter_map(|_| pick_fronting_address(&entry))
            .collect();
        assert!(addresses.len() > 1, "the address is chosen per connection");
    }

    #[test]
    fn the_older_single_fronting_fields_still_work() {
        let entry = ServerEntry::from_value(serde_json::json!({
            "ipAddress": "192.0.2.10",
            "meekServerPort": 20087,
            "meekFrontingDomain": "front.example",
            "meekFrontingHost": "host.example",
            "sshHostKey": "AAAA",
            "sshPassword": "password",
            "capabilities": ["FRONTED-MEEK-OSSH"],
        }))
        .unwrap();
        assert_eq!(
            pick_fronting_address(&entry).as_deref(),
            Some("front.example")
        );
        assert_eq!(pick_fronting_host(&entry).as_deref(), Some("host.example"));
    }

    #[test]
    fn an_entry_with_no_fronting_fields_is_refused_as_a_configuration_error() {
        let entry = entry("US", &["FRONTED-MEEK-OSSH"]);
        assert!(pick_fronting_address(&entry).is_none());
        assert!(pick_fronting_host(&entry).is_none());
    }

    #[test]
    fn no_supported_transport_is_a_configuration_error() {
        let config = config(vec![entry("US", &["QUIC"])]);
        assert!(matches!(
            candidate_list(&config).unwrap_err(),
            Error::Config(_)
        ));
    }

    #[tokio::test]
    async fn a_configuration_without_entries_is_rejected() {
        let result = Client::connect(config(Vec::new())).await;
        assert!(matches!(result, Err(Error::Config(_))));
    }

    #[tokio::test]
    async fn an_upstream_proxy_is_refused_rather_than_ignored() {
        let mut config = config(vec![entry("US", &["SSH"])]);
        config.upstream_proxy =
            Some(crate::config::UpstreamProxy::parse("socks5://127.0.0.1:1").unwrap());
        match Client::connect(config).await {
            Err(Error::Config(message)) => assert!(message.contains("upstream proxy"), "{message}"),
            Err(other) => panic!("expected a configuration error, got {other}"),
            Ok(_) => panic!("an unsupported proxy must not be ignored"),
        }
    }

    #[tokio::test]
    async fn an_unreachable_entry_fails_as_a_connect_error() {
        let mut config = config(vec![entry("US", &["SSH"])]);
        config.establish_timeout = Duration::from_millis(300);
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(20), Client::connect(config)).await;
        // Port 1 on loopback refuses immediately; the SSH attempt then fails.
        match result.expect("the dial loop is bounded") {
            Err(Error::Connect(message)) => assert!(
                message.contains("no psiphon tunnel could be established"),
                "unexpected message: {message}"
            ),
            Err(other) => panic!("expected a connect error, got {other}"),
            Ok(_) => panic!("an unreachable server entry must not produce a client"),
        }
        assert!(started.elapsed() < Duration::from_secs(15));
    }

    #[tokio::test]
    async fn a_race_reports_every_candidate_that_failed() {
        // Two entries and a concurrency of two: both are dialled, and both
        // failures are reported rather than only the first.
        let mut config = config(vec![entry("US", &["SSH"]), entry("US", &["OSSH"])]);
        config.establish_concurrency = 2;
        config.establish_timeout = Duration::from_millis(300);

        let result = tokio::time::timeout(Duration::from_secs(20), Client::connect(config))
            .await
            .expect("the race terminates");
        match result {
            Err(Error::Connect(message)) => {
                assert!(message.contains("SSH"), "{message}");
                assert!(message.contains("OSSH"), "{message}");
            }
            Err(other) => panic!("expected a connect error, got {other}"),
            Ok(_) => panic!("unreachable entries must not produce a client"),
        }
    }
}
