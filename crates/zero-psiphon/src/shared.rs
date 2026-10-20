//! One client per configuration, shared by every connection that uses it.
//!
//! A Psiphon tunnel is expensive to build — a TCP connection, an SSH key
//! exchange, an authentication and a tunnel handshake, several round trips —
//! and cheap to multiplex: one SSH session carries many `direct-tcpip`
//! channels. So a process keeps one [`Client`] per configuration and hands out
//! channels from it.
//!
//! The registry is keyed by [`ClientConfig::key`], a hash over everything that
//! changes the tunnel, so two outbounds that differ only in their destination
//! routing share a client while two that dial through different regions,
//! proxies or server entries do not.
//!
//! Nothing runs in the background. A client that has seen no new dial for
//! [`IDLE_AFTER`] is dropped by the next dial — which, since the last stream's
//! drop releases its lease, closes the tunnel and gives the memory back. A
//! proxy that goes quiet therefore costs nothing after a few minutes, and a
//! process that never uses Psiphon never starts a task, allocates a socket or
//! touches the network for it.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::client::Client;
use crate::config::ClientConfig;
use crate::error::Result;
use zero_core::stream::BoxStream;

/// No new dial for this long closes the client and its tunnel.
const IDLE_AFTER: Duration = Duration::from_secs(300);

/// The process's clients, keyed by the configuration hash.
///
/// Weak, so an instance that only the map refers to can go away: the map is a
/// cache, not an owner. Every dial and every live stream holds a strong
/// reference.
fn instances() -> &'static Mutex<HashMap<[u8; 32], Weak<Instance>>> {
    static INSTANCES: OnceLock<Mutex<HashMap<[u8; 32], Weak<Instance>>>> = OnceLock::new();
    INSTANCES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// When the process started, so "last used" needs only an atomic counter.
fn start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

struct Instance {
    client: Client,
    /// Milliseconds since [`start`] at the last dial.
    last_used: AtomicU64,
}

impl Instance {
    fn touch(&self) {
        self.last_used
            .store(start().elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let then = Duration::from_millis(self.last_used.load(Ordering::Relaxed));
        start().elapsed().saturating_sub(then)
    }
}

/// Open one stream to `host:port` through the client for `config`,
/// establishing the tunnel if this is the first connection.
///
/// The host is passed through unresolved: the Psiphon server resolves it, so
/// the local resolver never learns the destination.
pub async fn dial(config: &ClientConfig, host: &str, port: u16) -> Result<BoxStream> {
    let key = config.key();

    // Reap on the way in. No timer, no task: a process that stops using
    // Psiphon gives the memory back the next time it dials, and one that never
    // dials again gives it back when it exits.
    reap_idle();

    if let Some(instance) = live_instance(&key) {
        instance.touch();
        // A live client can still have lost its tunnel; `Client::dial`
        // re-establishes it, so there is nothing to check first.
        return instance
            .client
            .dial(host, port)
            .await
            .map(|stream| lease(stream, Arc::clone(&instance)))
            .inspect_err(|error| {
                // A tunnel the server has closed for good is worth replacing
                // rather than retrying: the next dial builds a fresh client.
                if !error.is_retryable() {
                    forget_key(&key);
                }
            });
    }

    // Boxed for the same reason the client's own steps are: the dial
    // future is large, and it is nested inside this one.
    let instance = Arc::new(Instance {
        client: Box::pin(Client::connect(config.clone())).await?,
        last_used: AtomicU64::new(start().elapsed().as_millis() as u64),
    });

    let stream = match instance.client.dial(host, port).await {
        Ok(stream) => stream,
        Err(error) => {
            // The tunnel came up but the destination could not be opened;
            // keep the client, because the tunnel itself is fine.
            if error.is_retryable() {
                publish(key, &instance);
            }
            return Err(error);
        }
    };

    publish(key, &instance);
    Ok(lease(stream, instance))
}

/// Drop the client for `config`, if one is running.
///
/// Called when an outbound is removed or replaced: the tunnel closes as soon
/// as the last stream through it is dropped.
pub fn forget(config: &ClientConfig) {
    forget_key(&config.key());
}

/// Drop every client. The process is about to exit, or configuration was
/// reloaded wholesale.
pub fn shutdown_all() {
    let mut map = instances()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    // `Instance::drop` closes the tunnel through `Client`'s own drop, and any
    // live stream keeps working on the clone it already holds.
    map.clear();
}

/// How many clients are alive. Diagnostics and tests only.
pub fn instance_count() -> usize {
    let map = instances()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    map.values().filter(|weak| weak.strong_count() > 0).count()
}

fn live_instance(key: &[u8; 32]) -> Option<Arc<Instance>> {
    let map = instances()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    map.get(key).and_then(Weak::upgrade)
}

fn publish(key: [u8; 32], instance: &Arc<Instance>) {
    let mut map = instances()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    map.retain(|_, weak| weak.strong_count() > 0);
    map.insert(key, Arc::downgrade(instance));
}

fn forget_key(key: &[u8; 32]) {
    let mut map = instances()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    map.remove(key);
}

/// Drop clients that have gone quiet. Cheap: a handful of entries at most.
fn reap_idle() {
    let mut map = instances()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    map.retain(|_, weak| match weak.upgrade() {
        Some(instance) => instance.idle_for() < IDLE_AFTER,
        None => false,
    });
}

/// Hold a strong reference to the client for as long as the stream is open.
///
/// The field is never read: dropping the stream is what matters, and dropping
/// it releases the client, which releases the tunnel once the last stream is
/// gone.
fn lease(stream: BoxStream, instance: Arc<Instance>) -> BoxStream {
    Box::pin(LeasedStream {
        inner: stream,
        _instance: instance,
    })
}

struct LeasedStream {
    inner: BoxStream,
    _instance: Arc<Instance>,
}

impl AsyncRead for LeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for LeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::server_entry::ServerEntry;

    fn config(region: &str) -> ClientConfig {
        ClientConfig {
            server_entries: vec![ServerEntry::from_value(serde_json::json!({
                "ipAddress": "127.0.0.1",
                "region": region,
                "sshPort": 1,
                "sshHostKey": "AAAA",
                "sshPassword": "password",
                "capabilities": ["SSH"],
            }))
            .unwrap()],
            establish_timeout: Duration::from_millis(200),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_failed_dial_leaves_no_client_behind() {
        // The configuration is valid but nothing is listening on port 1, so
        // the tunnel cannot come up and the registry must stay empty.
        match dial(&config("US"), "example.com", 80).await {
            Err(Error::Connect(message)) => {
                assert!(message.contains("no psiphon tunnel"), "{message}")
            }
            Err(other) => panic!("expected a connect error, got {other}"),
            Ok(_) => panic!("nothing is listening, so no tunnel can come up"),
        }
        assert_eq!(instance_count(), 0);
    }

    #[test]
    fn forgetting_a_configuration_is_idempotent() {
        let config = config("US");
        forget(&config);
        forget(&config);
        assert_eq!(instance_count(), 0);
        shutdown_all();
        assert_eq!(instance_count(), 0);
    }
}
