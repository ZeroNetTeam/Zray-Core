//! Small loopback management API.
//!
//! The API is intentionally separate from proxy listeners. It exposes only
//! bounded statistics and an authenticated whole-generation reload endpoint;
//! it never accepts arbitrary outbound destinations or executes config JSON
//! incrementally.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Server;

const MAX_REQUEST: usize = 2 * 1024 * 1024;
/// How long a client may take to deliver its request. Only reading is
/// bounded: handling (a forced asset refresh downloads rule sets) must not be
/// cancelled half-way by a deadline meant for slow senders.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How often an idle `GET /events` stream gets a comment line.
const EVENTS_KEEPALIVE: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct ManagementConfig {
    pub listen: SocketAddr,
    pub bearer_token: Option<Arc<str>>,
}

impl ManagementConfig {
    pub fn validate(&self) -> Result<(), String> {
        let loopback = self.listen.ip().is_loopback();
        if !loopback && self.bearer_token.as_deref().is_none_or(str::is_empty) {
            return Err("management API requires a bearer token off loopback".into());
        }
        Ok(())
    }
}

pub struct ManagementServer {
    config: ManagementConfig,
}

impl ManagementServer {
    pub fn new(config: ManagementConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self { config })
    }

    pub async fn run(self, server: Arc<Server>) -> std::io::Result<()> {
        self.serve(Target::Server(server)).await
    }

    /// [`ManagementServer::run`] for a [`crate::host::Host`]: every request
    /// goes to the server serving at the time, and `POST /reload` may then
    /// change inbounds too.
    pub async fn run_host(self, host: Arc<crate::host::Host>) -> std::io::Result<()> {
        self.serve(Target::Host(host)).await
    }

    async fn serve(self, target: Target) -> std::io::Result<()> {
        let addr = self.config.listen;
        let listener = zero_net::prepare_listener(addr)?;
        let mut backoff_ms = 10u64;
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => {
                    backoff_ms = 10;
                    accepted
                }
                // Descriptor exhaustion and aborted handshakes are transient;
                // returning here would take the management API down for good.
                Err(error) => {
                    tracing::warn!(%error, backoff_ms, "management accept failed");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(1000);
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let config = self.config.clone();
            let target = target.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_target(stream, peer, config, target).await {
                    tracing::debug!(%peer, %error, "management request failed");
                }
            });
        }
    }
}

/// What the API drives: one server, or a host whose server may be replaced.
#[derive(Clone)]
enum Target {
    Server(Arc<Server>),
    Host(Arc<crate::host::Host>),
}

#[cfg(test)]
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: ManagementConfig,
    server: Arc<Server>,
) -> Result<(), String> {
    handle_target(stream, peer, config, Target::Server(server)).await
}

async fn handle_target(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: ManagementConfig,
    target: Target,
) -> Result<(), String> {
    let (server, host) = match target {
        Target::Server(server) => (server, None),
        Target::Host(host) => (host.server(), Some(host)),
    };
    let deadline = tokio::time::Instant::now() + REQUEST_READ_TIMEOUT;
    let mut data = Vec::with_capacity(1024);
    let head_end;
    // Only the bytes that arrived since the last pass (plus three, for a
    // terminator split across reads) need scanning; rescanning the whole
    // buffer per read is quadratic in a trickled request.
    let mut scanned = 0usize;
    loop {
        let from = scanned.saturating_sub(3);
        if let Some(end) = data[from..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            head_end = from + end + 4;
            break;
        }
        scanned = data.len();
        if data.len() >= MAX_REQUEST {
            return write_response(&mut stream, 413, "request too large", b"").await;
        }
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| "request head timed out".to_string())?
            .map_err(|error| format!("reading request: {error}"))?;
        if n == 0 {
            return Ok(());
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut request = httparse::Request::new(&mut headers);
    request
        .parse(&data[..head_end])
        .map_err(|error| format!("malformed request: {error}"))?;
    let method = request.method.unwrap_or("").to_string();
    let path = request.path.unwrap_or("").to_string();
    let authorization = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::to_owned);
    // Copied out of the borrow of `data` below, which the rest of the handler
    // needs mutably while it reads the body.
    let origin = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("origin"))
        .map(|header| header.value.len());
    let content_length = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| {
            std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if content_length > MAX_REQUEST - head_end {
        return write_response(&mut stream, 413, "request too large", b"").await;
    }
    while data.len() < head_end + content_length {
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| "request body timed out".to_string())?
            .map_err(|error| format!("reading request body: {error}"))?;
        if n == 0 {
            return write_response(&mut stream, 400, "truncated body", b"").await;
        }
    }

    if let Some(expected) = config.bearer_token.as_deref() {
        let actual = authorization
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "));
        if actual != Some(expected) {
            return write_response(&mut stream, 401, "unauthorized", b"").await;
        }
    } else if !peer.ip().is_loopback() {
        return write_response(&mut stream, 403, "forbidden", b"").await;
    }

    // Cross-site requests. `POST /reload` installs a whole replacement
    // configuration, so a page open in the user's browser must not be able to
    // trigger it: without this, any site could send a form post to
    // `127.0.0.1` and rewrite the proxy. Every state-changing verb is checked
    // rather than just `/reload`, so the rule cannot be forgotten when an
    // endpoint is added.
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") && origin.is_some() {
        return write_response(&mut stream, 403, "cross-origin request refused", b"").await;
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/stats") => {
            let body = serde_json::to_vec(&server.stats.snapshot())
                .map_err(|error| format!("encoding stats: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", path) if path == "/stats/traffic" || path.starts_with("/stats/traffic?") => {
            // Xray-compatible per-tag counters. `?reset=true` zeroes each
            // counter as it is read, matching Xray's QueryStats reset.
            let reset = path
                .split_once('?')
                .map(|(_, query)| {
                    query
                        .split('&')
                        .any(|pair| matches!(pair, "reset=true" | "reset=1" | "reset"))
                })
                .unwrap_or(false);
            let stat = server
                .stats
                .traffic_counters(reset)
                .into_iter()
                .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
                .collect::<Vec<_>>();
            let body = serde_json::to_vec(&serde_json::json!({ "stat": stat }))
                .map_err(|error| format!("encoding traffic stats: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/usage") => {
            // Counts only: sessions and devices per inbound, plus its byte
            // totals. See `crate::usage` for why nothing here can name a user.
            let snapshot = server.stats.usage.snapshot();
            let traffic: std::collections::HashMap<String, u64> =
                server.stats.traffic_counters(false).into_iter().collect();
            let bytes = |tag: &str, way: &str| {
                traffic
                    .get(&format!("inbound>>>{tag}>>>traffic>>>{way}"))
                    .copied()
                    .unwrap_or(0)
            };
            let inbounds: Vec<_> = snapshot
                .inbounds
                .iter()
                .map(|usage| {
                    serde_json::json!({
                        "tag": usage.tag,
                        "sessions": usage.sessions,
                        "devices_now": usage.devices_now,
                        "devices_recent": usage.devices_recent,
                        "uplink": bytes(&usage.tag, "uplink"),
                        "downlink": bytes(&usage.tag, "downlink"),
                    })
                })
                .collect();
            let body = serde_json::to_vec(&serde_json::json!({
                "window_secs": snapshot.window_secs,
                "inbounds": inbounds,
            }))
            .map_err(|error| format!("encoding usage: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/health") => {
            let body = serde_json::to_vec(&server.health_snapshot())
                .map_err(|error| format!("encoding health: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/clean-ip") => {
            let body = serde_json::to_vec(&server.clean_ip_snapshot())
                .map_err(|error| format!("encoding clean-ip results: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/assets") => {
            let body = serde_json::to_vec(&server.asset_snapshot())
                .map_err(|error| format!("encoding asset status: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/assets/refresh") => {
            // Forced because an operator asking for a refresh is doing so
            // precisely when the TTL says nothing needs doing.
            let report = server.refresh_assets_now().await;
            let body = serde_json::to_vec(&report)
                .map_err(|error| format!("encoding refresh report: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/accounts/online") => {
            // Addresses are present only when the host has turned address
            // tracking on (see `crate::accounts`).
            let body = serde_json::json!({ "accounts": server.stats.accounts.online() });
            let body = serde_json::to_vec(&body)
                .map_err(|error| format!("encoding online accounts: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/accounts/end") => {
            // `{"email": "..."}`: end every open session of that account, for
            // a panel whose account just ran out of quota or time.
            let body = &data[head_end..head_end + content_length];
            let email = serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|value| value.get("email")?.as_str().map(str::to_owned))
                .filter(|email| !email.is_empty());
            let Some(email) = email else {
                return write_response(&mut stream, 400, "body must be {\"email\": ...}", b"")
                    .await;
            };
            let ended = server.stats.accounts.end_sessions(&email);
            let body = serde_json::to_vec(&serde_json::json!({ "ended": ended }))
                .map_err(|error| error.to_string())?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/events") => {
            // Server-sent events: one `data:` line of JSON per event
            // (`crate::events`), until the client goes away. A comment line
            // every few seconds keeps proxies from closing an idle stream and
            // lets a vanished client be noticed.
            use tokio::sync::broadcast::error::RecvError;
            let mut events = server.stats.events().subscribe();
            stream
                .write_all(
                    b"HTTP/1.1 200 ok\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                )
                .await
                .map_err(|error| format!("writing response: {error}"))?;
            let mut keepalive = tokio::time::interval(EVENTS_KEEPALIVE);
            keepalive.tick().await;
            loop {
                let chunk = tokio::select! {
                    received = events.recv() => match received {
                        Ok(record) => format!(
                            "data: {}\n\n",
                            serde_json::to_string(&record).map_err(|error| error.to_string())?
                        ),
                        Err(RecvError::Lagged(missed)) => {
                            format!("data: {{\"event\":\"lagged\",\"missed\":{missed}}}\n\n")
                        }
                        Err(RecvError::Closed) => return Ok(()),
                    },
                    _ = keepalive.tick() => ": keepalive\n\n".to_string(),
                };
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
        }
        ("GET", "/accounts/limits") => {
            let body = serde_json::json!({ "limits": server.stats.accounts.limits() });
            let body =
                serde_json::to_vec(&body).map_err(|error| format!("encoding limits: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/accounts/limit") => {
            // `{"email": ..., "uplink": B/s, "downlink": B/s}`, shared by all
            // the account's sessions; 0 or absent lifts that direction.
            let body = &data[head_end..head_end + content_length];
            let result = serde_json::from_slice::<serde_json::Value>(body)
                .map_err(|_| "body is not JSON".to_string())
                .and_then(|request| {
                    let email = request["email"]
                        .as_str()
                        .filter(|email| !email.is_empty())
                        .ok_or("body must name the \"email\"")?;
                    let rate = |key: &str| match &request[key] {
                        serde_json::Value::Null => Ok(0),
                        value => value
                            .as_u64()
                            .ok_or(format!("\"{key}\" must be bytes per second")),
                    };
                    let (uplink, downlink) = (rate("uplink")?, rate("downlink")?);
                    server.stats.accounts.set_limit(email, uplink, downlink);
                    Ok(serde_json::json!({ "uplink": uplink, "downlink": downlink }))
                });
            account_reply(&mut stream, result).await
        }
        ("POST", "/accounts/add") => {
            // `{"inbound": tag, "clients": [...]}`, each client in the shape
            // of the inbound's `settings.clients`. Applied without a reload.
            let body = &data[head_end..head_end + content_length];
            let request: serde_json::Value = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(_) => return write_response(&mut stream, 400, "body is not JSON", b"").await,
            };
            let result = (|| {
                let tag = request["inbound"]
                    .as_str()
                    .ok_or("body must name the \"inbound\"")?;
                let clients = request["clients"]
                    .as_array()
                    .ok_or("body must carry a \"clients\" array")?
                    .iter()
                    .map(|client| server.parse_account(tag, client))
                    .collect::<Result<Vec<_>, String>>()?;
                server.add_accounts(tag, &clients)?;
                Ok::<usize, String>(clients.len())
            })();
            account_reply(
                &mut stream,
                result.map(|added| serde_json::json!({ "added": added })),
            )
            .await
        }
        ("POST", "/accounts/remove") => {
            // `{"inbound": tag, "emails": [...]}`. Their sessions there end.
            let body = &data[head_end..head_end + content_length];
            let request: serde_json::Value = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(_) => return write_response(&mut stream, 400, "body is not JSON", b"").await,
            };
            let result = (|| {
                let tag = request["inbound"]
                    .as_str()
                    .ok_or("body must name the \"inbound\"")?;
                let emails: Vec<&str> = request["emails"]
                    .as_array()
                    .ok_or("body must carry an \"emails\" array")?
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect();
                server.remove_accounts(tag, &emails)
            })();
            account_reply(
                &mut stream,
                result.map(|removed| serde_json::json!({ "removed": removed })),
            )
            .await
        }
        ("POST", "/reload") => {
            let body = &data[head_end..head_end + content_length];
            let value: serde_json::Value = serde_json::from_slice(body)
                .map_err(|error| format!("reload body is not JSON: {error}"))?;
            let next = server.current_generation().0.saturating_add(1);
            let (generation, diagnostics) =
                zero_config::compile_config(&value, zero_core::GenerationId(next))
                    .map_err(|error| format!("reload config rejected: {error}"))?;
            let applied = match &host {
                // A host can also add, remove and re-bind inbounds.
                Some(host) => match host.apply(Arc::clone(&generation.config)).await {
                    Ok(crate::host::Applied::Reloaded) => "reloaded",
                    Ok(crate::host::Applied::Restarted) => "restarted",
                    Err(error) => {
                        let body = serde_json::to_vec(&serde_json::json!({ "error": error }))
                            .map_err(|error| error.to_string())?;
                        return write_response(&mut stream, 400, "reload rejected", &body).await;
                    }
                },
                None => {
                    server
                        .reload(Arc::clone(&generation.config), generation.id)
                        .map_err(|error| format!("reload rejected: {error}"))?;
                    "reloaded"
                }
            };
            let body = serde_json::json!({
                "generation": next,
                "diagnostics": diagnostics.diagnostics.len(),
                "applied": applied,
            });
            let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        _ => write_response(&mut stream, 404, "not found", b"").await,
    }
}

/// The reply to an account change: the outcome as JSON, or a 400 whose body
/// says why the change was refused, so a panel can show it.
async fn account_reply(
    stream: &mut TcpStream,
    result: Result<serde_json::Value, String>,
) -> Result<(), String> {
    match result {
        Ok(body) => {
            let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
            write_response(stream, 200, "ok", &body).await
        }
        Err(error) => {
            let body = serde_json::to_vec(&serde_json::json!({ "error": error }))
                .map_err(|error| error.to_string())?;
            write_response(stream, 400, "account change refused", &body).await
        }
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| format!("writing response: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("writing response body: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_management_listeners_require_authentication() {
        let config = ManagementConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            bearer_token: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn loopback_management_listener_can_be_private() {
        let config = ManagementConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            bearer_token: None,
        };
        assert!(config.validate().is_ok());
    }

    /// A page in the user's browser must not be able to drive the API.
    ///
    /// `POST /reload` installs a whole replacement configuration, and with
    /// only a loopback check a form post from any site reached it: a JSON
    /// body sent as `text/plain` is not preflighted, so the browser issued
    /// the request and the API parsed it happily.
    #[tokio::test]
    async fn a_cross_origin_post_is_refused() {
        use tokio::io::AsyncWriteExt;

        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let config = ManagementConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            bearer_token: None,
        };

        // One request per call, served by the real handler, so the check is
        // exercised where a browser's request would land.
        let post = |origin: Option<&str>| {
            let mut request = String::from(
                "POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\
Content-Length: 2\r\n",
            );
            if let Some(origin) = origin {
                request.push_str(&format!("Origin: {origin}\r\n"));
            }
            request.push_str("\r\n{}");
            let server = std::sync::Arc::clone(&server);
            let config = config.clone();
            async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let serving = {
                    let server = std::sync::Arc::clone(&server);
                    let config = config.clone();
                    async move {
                        let (accepted, peer) = listener.accept().await.unwrap();
                        handle_connection(accepted, peer, config, server).await
                    }
                };
                let client = async {
                    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
                    stream.write_all(request.as_bytes()).await.unwrap();
                    let mut reply = Vec::new();
                    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut reply)
                        .await
                        .unwrap();
                    String::from_utf8_lossy(&reply).into_owned()
                };
                let (reply, served) = tokio::join!(client, serving);
                // The handler reports a refusal as an error after it has
                // answered, so that is not a failure of the test.
                let _ = served;
                reply
            }
        };

        let crossed = post(Some("https://evil.example")).await;
        assert!(
            crossed.starts_with("HTTP/1.1 403"),
            "a browser could still rewrite the config: {crossed}"
        );

        // Same request without the header — a local tool, not a page — is
        // untouched, so nothing that legitimately drives the API breaks.
        let direct = post(None).await;
        assert!(
            !direct.starts_with("HTTP/1.1 403"),
            "a local client was refused: {direct}"
        );
    }

    /// `/usage` reports counts and byte totals per inbound and nothing that
    /// could name a client: not the address a session came from, not the key
    /// the tracker made from it.
    #[tokio::test]
    async fn usage_reports_counts_and_no_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let tag: std::sync::Arc<str> = std::sync::Arc::from("reality-in");
        let address: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let _a = server.stats.usage.open(&tag, address);
        let _b = server.stats.usage.open(&tag, address);
        let _c = server
            .stats
            .usage
            .open(&tag, "198.51.100.4".parse().unwrap());
        server.stats.record_tag_traffic(
            "reality-in",
            None,
            &crate::relay::Transferred {
                uploaded: 11,
                downloaded: 22,
            },
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let config = ManagementConfig {
            listen,
            bearer_token: Some("t0ken".into()),
        };
        let serving = {
            let server = std::sync::Arc::clone(&server);
            async move {
                let (accepted, peer) = listener.accept().await.unwrap();
                handle_connection(accepted, peer, config, server).await
            }
        };
        let client = async {
            let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
            stream
                .write_all(b"GET /usage HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0ken\r\n\r\n")
                .await
                .unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            String::from_utf8_lossy(&reply).into_owned()
        };
        let (reply, _) = tokio::join!(client, serving);
        let body = reply.split("\r\n\r\n").nth(1).expect("a body");
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON");
        let usage = &json["inbounds"][0];
        assert_eq!(usage["tag"], "reality-in");
        assert_eq!(usage["sessions"], 3);
        assert_eq!(usage["devices_now"], 2);
        assert_eq!(usage["devices_recent"], 2);
        assert_eq!(usage["uplink"], 11);
        assert_eq!(usage["downlink"], 22);
        assert!(!reply.contains("203.0.113.9") && !reply.contains("198.51.100.4"));
    }

    #[test]
    fn traffic_counters_accumulate_per_tag_and_reset_on_demand() {
        use crate::relay::Transferred;
        use crate::server::Stats;

        let stats = Stats::default();
        stats.record_tag_traffic(
            "socks-in",
            Some("proxy"),
            &Transferred {
                uploaded: 100,
                downloaded: 250,
            },
        );
        stats.record_tag_traffic(
            "socks-in",
            Some("proxy"),
            &Transferred {
                uploaded: 5,
                downloaded: 7,
            },
        );

        let counters = stats.traffic_counters(false);
        let find = |name: &str| {
            counters
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, value)| *value)
        };
        assert_eq!(find("inbound>>>socks-in>>>traffic>>>uplink"), Some(105));
        assert_eq!(find("inbound>>>socks-in>>>traffic>>>downlink"), Some(257));
        assert_eq!(find("outbound>>>proxy>>>traffic>>>uplink"), Some(105));
        assert_eq!(find("outbound>>>proxy>>>traffic>>>downlink"), Some(257));

        // A read with reset returns the accumulated values, then zeroes them.
        let reset = stats.traffic_counters(true);
        assert_eq!(
            reset
                .iter()
                .find(|(n, _)| n == "inbound>>>socks-in>>>traffic>>>uplink")
                .map(|(_, v)| *v),
            Some(105)
        );
        let after = stats.traffic_counters(false);
        assert!(
            after.iter().all(|(_, value)| *value == 0),
            "reset should have zeroed every counter: {after:?}"
        );
    }

    #[test]
    fn a_zero_byte_session_records_no_counter() {
        use crate::relay::Transferred;
        use crate::server::Stats;

        let stats = Stats::default();
        stats.record_tag_traffic(
            "socks-in",
            None,
            &Transferred {
                uploaded: 0,
                downloaded: 0,
            },
        );
        assert!(stats.traffic_counters(false).is_empty());
    }

    /// Serve one request on a fresh management listener and return the reply.
    async fn ask(server: std::sync::Arc<crate::Server>, request: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let config = ManagementConfig {
            listen,
            bearer_token: None,
        };
        let serving = async move {
            let (accepted, peer) = listener.accept().await.unwrap();
            handle_connection(accepted, peer, config, server).await
        };
        let client = async {
            let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            String::from_utf8_lossy(&reply).into_owned()
        };
        tokio::join!(client, serving).0
    }

    fn body_json(reply: &str) -> serde_json::Value {
        serde_json::from_str(reply.split("\r\n\r\n").nth(1).expect("a body")).expect("JSON")
    }

    /// A panel reads who is online and per-account bytes, and can end an
    /// account's sessions, which then fail on their next use.
    #[tokio::test]
    async fn accounts_are_reported_and_their_sessions_ended() {
        use tokio::io::AsyncWriteExt;

        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let email: std::sync::Arc<str> = std::sync::Arc::from("alice@panel");
        let tag: std::sync::Arc<str> = std::sync::Arc::from("vless-in");
        let address: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let (client, _far) = tokio::io::duplex(1024);
        let mut session = server.stats.accounts.meter(&email, &tag, address, client);
        session.write_all(b"twelve bytes").await.unwrap();

        let online = body_json(
            &ask(
                Arc::clone(&server),
                "GET /accounts/online HTTP/1.1\r\nHost: x\r\n\r\n".into(),
            )
            .await,
        );
        assert_eq!(online["accounts"][0]["email"], "alice@panel");
        assert_eq!(online["accounts"][0]["sessions"], 1);
        assert_eq!(online["accounts"][0]["addresses"], serde_json::json!([]));

        let traffic = body_json(
            &ask(
                Arc::clone(&server),
                "GET /stats/traffic HTTP/1.1\r\nHost: x\r\n\r\n".into(),
            )
            .await,
        );
        let downlink = traffic["stat"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stat| stat["name"] == "user>>>alice@panel>>>traffic>>>downlink")
            .map(|stat| stat["value"].clone());
        assert_eq!(downlink, Some(serde_json::json!(12)));

        let body = r#"{"email": "alice@panel"}"#;
        let request = format!(
            "POST /accounts/end HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let ended = body_json(&ask(Arc::clone(&server), request).await);
        assert_eq!(ended["ended"], 1);
        assert!(session.write_all(b"more").await.is_err());

        let body = r#"{"email": "alice@panel", "downlink": 1000000}"#;
        let request = format!(
            "POST /accounts/limit HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            body_json(&ask(Arc::clone(&server), request).await)["downlink"],
            1_000_000
        );
        let limits = body_json(
            &ask(
                Arc::clone(&server),
                "GET /accounts/limits HTTP/1.1\r\nHost: x\r\n\r\n".into(),
            )
            .await,
        );
        assert_eq!(limits["limits"][0]["email"], "alice@panel");
        assert_eq!(limits["limits"][0]["uplink"], 0);
        let body = r#"{"email": "alice@panel", "uplink": "fast"}"#;
        let request = format!(
            "POST /accounts/limit HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert!(ask(Arc::clone(&server), request)
            .await
            .starts_with("HTTP/1.1 400"));

        let refused = ask(
            server,
            "POST /accounts/end HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}".into(),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
    }

    /// Accounts are added and removed over the API in the same JSON shape as
    /// `settings.clients`, and a refused change says why.
    #[tokio::test]
    async fn accounts_are_added_and_removed_over_the_api() {
        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{
                    "inbounds": [{
                        "tag": "vless-in", "listen": "127.0.0.1", "port": 1, "protocol": "vless",
                        "settings": {"clients": [{"id": "5783a3e7-e373-51cd-8642-c83782b807c5", "email": "a@p"}], "decryption": "none"}
                    }],
                    "outbounds": [{"tag": "direct", "protocol": "freedom"}]
                }"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let post = |path: &str, body: serde_json::Value| {
            let body = body.to_string();
            format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let users = |server: &crate::Server| match &server.config_for_tests().inbounds[0].protocol {
            zero_config::InboundProtocol::Vless(vless) => vless
                .users
                .iter()
                .map(|user| user.email.as_deref().unwrap_or("").to_string())
                .collect::<Vec<_>>(),
            other => panic!("not vless: {other:?}"),
        };

        let added = ask(
            Arc::clone(&server),
            post(
                "/accounts/add",
                serde_json::json!({"inbound": "vless-in", "clients": [
                    {"id": "0f3c2a10-8b5e-4d7a-9c21-6e4b8f0a1d33", "email": "b@p", "flow": "xtls-rprx-vision"}
                ]}),
            ),
        )
        .await;
        assert_eq!(body_json(&added)["added"], 1, "{added}");
        assert_eq!(users(&server), ["a@p", "b@p"]);

        let refused = ask(
            Arc::clone(&server),
            post(
                "/accounts/add",
                serde_json::json!({"inbound": "vless-in", "clients": [{"id": "1b1d3a6e-5d0f-4c8e-9f6a-2a7c3e9b8d41", "email": "c@p", "flow": "no-such-flow"}]}),
            ),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
        assert!(body_json(&refused)["error"]
            .as_str()
            .unwrap()
            .contains("client"));

        let removed = ask(
            Arc::clone(&server),
            post(
                "/accounts/remove",
                serde_json::json!({"inbound": "vless-in", "emails": ["a@p", "nobody@p"]}),
            ),
        )
        .await;
        assert_eq!(body_json(&removed)["removed"], 1, "{removed}");
        assert_eq!(users(&server), ["b@p"]);

        let unknown = ask(
            server,
            post(
                "/accounts/remove",
                serde_json::json!({"inbound": "nope", "emails": []}),
            ),
        )
        .await;
        assert!(unknown.starts_with("HTTP/1.1 400"), "{unknown}");
    }

    /// `GET /events` streams what happens as server-sent events.
    #[tokio::test]
    async fn events_are_streamed_as_they_happen() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let generation = zero_config::RuntimeGeneration::compile(
            zero_config::parse_config_array(
                r#"{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}"#,
            )
            .expect("a config the engine accepts")
            .remove(0)
            .1,
            zero_core::GenerationId(1),
        )
        .expect("compiles");
        let server = std::sync::Arc::new(crate::Server::new(crate::ServerConfig {
            config: std::sync::Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let config = ManagementConfig {
            listen,
            bearer_token: None,
        };
        let serving = Arc::clone(&server);
        tokio::spawn(async move {
            let (accepted, peer) = listener.accept().await.unwrap();
            let _ = handle_connection(accepted, peer, config, serving).await;
        });
        let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
        stream
            .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut lines = tokio::io::BufReader::new(stream).lines();
        let status = lines.next_line().await.unwrap().unwrap();
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        while !lines.next_line().await.unwrap().unwrap().is_empty() {}

        // Subscribed once the head is out; now something happens.
        server.stats.accounts.set_limit("g@p", 5, 6);
        let data = tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line())
            .await
            .expect("an event in time")
            .unwrap()
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_str(data.strip_prefix("data: ").expect("an SSE data line")).unwrap();
        assert_eq!(json["event"], "limit_changed");
        assert_eq!(json["email"], "g@p");
        assert_eq!(json["downlink"], 6);
    }
}
