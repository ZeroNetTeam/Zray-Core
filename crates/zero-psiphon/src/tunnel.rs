//! The SSH client at the end of every Psiphon tunnel.
//!
//! Once the carrier is up (plain TCP, OSSH, TLS-OSSH or meek), Psiphon speaks
//! ordinary SSH/2 with three Psiphon-specific twists:
//!
//! * the password is not a password but a JSON credential payload carrying
//!   the server's password, this client's session ID and its capabilities;
//! * the server's host key is pinned by value: `sshHostKey` in the server
//!   entry is the base64 SSH wire encoding of the key, and the key exchange
//!   must present exactly those bytes;
//! * destinations are forwarded as `direct-tcpip` channels (or Psiphon's
//!   `direct-tcpip-no-split-tunnel@psiphon.ca` variant on servers with split
//!   tunnel enabled).
//!
//! The SSH implementation itself is `russh`; this module is the Psiphon
//! semantics around it and nothing else.
//!
//! Not yet implemented: Psiphon's custom `direct-tcpip-no-split-tunnel` channel
//! type (russh carries the type in the message, so this needs a small patch in
//! `russh` or a hand-rolled channel-open message; `direct-tcpip` works against
//! every server with split tunnel off, which is the default).

use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::server_entry::ServerEntry;

/// Psiphon's session ID length in bytes, hex-encoded in the credential.
pub const SESSION_ID_BYTES: usize = 16;

/// The client capability that tells the server this client understands
/// server-initiated SSH requests (`CLIENT_CAPABILITY_SERVER_REQUESTS`).
pub const CAPABILITY_SERVER_REQUESTS: &str = "server-requests";

/// The SSH client identification Psiphon sends when tactics name none.
pub const DEFAULT_CLIENT_VERSION: &str = "SSH-2.0-OpenSSH_9.6";

/// How long a single destination's channel may take to open.
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

/// Settings for one tunnel's SSH session.
#[derive(Debug, Clone)]
pub struct TunnelOptions {
    /// The SSH identification line (`SSH-2.0-...`).
    pub client_version: String,
    /// `keepalive@openssh.com` interval.
    pub keepalive_interval: Option<Duration>,
    /// Channel window size. Larger windows cost memory per channel but stop
    /// throughput from being window-limited on high-latency paths.
    pub window_size: u32,
    /// Largest SSH packet this client will accept.
    pub maximum_packet_size: u32,
    /// Buffered channel messages before backpressure.
    pub channel_buffer_size: usize,
    /// The session ID to send; a fresh random one when absent.
    pub session_id: Option<String>,
    /// Sponsor identifier, empty when none.
    pub sponsor_id: String,
    /// SSH capabilities to advertise in the credential payload.
    pub capabilities: Vec<String>,
}

impl Default for TunnelOptions {
    fn default() -> Self {
        TunnelOptions {
            client_version: DEFAULT_CLIENT_VERSION.to_string(),
            keepalive_interval: Some(Duration::from_secs(25)),
            // Psiphon raises its window above OpenSSH's 2 MiB default for
            // long-fat paths; 4 MiB is the Go client's ceiling.
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: 32 * 1024,
            channel_buffer_size: 64,
            session_id: None,
            sponsor_id: String::new(),
            capabilities: Vec::new(),
        }
    }
}

/// The credential payload Psiphon sends as the SSH password.
#[derive(Debug, Clone, serde::Serialize)]
struct CredentialPayload {
    #[serde(rename = "SessionId", skip_serializing_if = "String::is_empty")]
    session_id: String,
    #[serde(rename = "SshPassword", skip_serializing_if = "String::is_empty")]
    ssh_password: String,
    #[serde(rename = "ClientCapabilities", skip_serializing_if = "Vec::is_empty")]
    client_capabilities: Vec<String>,
    #[serde(rename = "SponsorId", skip_serializing_if = "String::is_empty")]
    sponsor_id: String,
}

/// A fresh session ID: `SESSION_ID_BYTES` random bytes, lowercase hex.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; SESSION_ID_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Build the JSON credential payload that stands in for an SSH password.
///
/// `capabilities` is empty by default: advertising
/// [`CAPABILITY_SERVER_REQUESTS`] makes the server send its own SSH requests
/// (OSL, alerts), which this client does not handle yet.
pub fn credential_payload(
    ssh_password: &str,
    session_id: &str,
    sponsor_id: &str,
    capabilities: &[&str],
) -> String {
    serde_json::to_string(&CredentialPayload {
        session_id: session_id.to_string(),
        ssh_password: ssh_password.to_string(),
        client_capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        sponsor_id: sponsor_id.to_string(),
    })
    .expect("serializing the credential payload cannot fail")
}

/// The parameters of the `psiphon-handshake` request the server requires
/// before it will forward any port.
///
/// The server validates every field: `propagation_channel_id` must be hex,
/// `sponsor_id` exactly 16 hex characters, `client_version` an integer
/// string, `client_platform` non-empty without whitespace, and
/// `relay_protocol` one of the tunnel protocols. Optional values (pad sizes,
/// dial metrics) are omitted: the server logs them and does not require them.
#[derive(Debug, Clone)]
pub struct HandshakeParams {
    /// 16 hex characters; all zeros when the client has no channel.
    pub propagation_channel_id: String,
    /// 16 hex characters.
    pub sponsor_id: String,
    /// An integer string, e.g. `"1"`.
    pub client_version: String,
    /// `"Windows"`, `"Android"`, `"iOS"`, `"iPadOS"` or `"Other"`.
    pub client_platform: String,
    /// The tunnel protocol actually dialed, e.g. `"SSH"` or `"OSSH"`.
    pub relay_protocol: String,
}

impl HandshakeParams {
    /// Handshake parameters for `protocol`, with the defaults Psiphon's own
    /// client uses for an unaffiliated client.
    pub fn new(protocol: crate::protocol::TunnelProtocol) -> Self {
        HandshakeParams {
            propagation_channel_id: "0000000000000000".into(),
            sponsor_id: "0000000000000000".into(),
            client_version: "1".into(),
            client_platform: "Other".into(),
            relay_protocol: protocol.as_str().into(),
        }
    }

    /// Announce this propagation channel (`PropagationChannelId`).
    pub fn with_propagation_channel_id(mut self, value: String) -> Self {
        if !value.is_empty() {
            self.propagation_channel_id = value;
        }
        self
    }

    /// Announce this sponsor (`SponsorId`). An empty value keeps the default,
    /// because Psiphon's server rejects an empty `sponsor_id` field outright.
    pub fn with_sponsor_id(mut self, value: String) -> Self {
        if !value.is_empty() {
            self.sponsor_id = value;
        }
        self
    }

    /// Announce this client version.
    pub fn with_client_version(mut self, value: String) -> Self {
        if !value.is_empty() {
            self.client_version = value;
        }
        self
    }

    /// Announce this client platform (`Windows`, `Android`, `Linux`, `Other`).
    pub fn with_client_platform(mut self, value: String) -> Self {
        if !value.is_empty() {
            self.client_platform = value;
        }
        self
    }

    /// The request payload: a JSON object with Psiphon's snake_case names.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&serde_json::json!({
            "propagation_channel_id": self.propagation_channel_id,
            "sponsor_id": self.sponsor_id,
            "client_version": self.client_version,
            "client_platform": self.client_platform,
            "relay_protocol": self.relay_protocol,
        }))
        .map_err(|error| Error::Protocol(format!("handshake payload: {error}")))
    }
}

/// Pins the server's SSH host key to the bytes in the server entry.
struct Pinned {
    expected: Vec<u8>,
}

impl russh::client::Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let presented = key.public_key().to_bytes()?;
        Ok(presented == self.expected)
    }
}

/// An established, authenticated SSH session to a Psiphon server.
pub struct SshTunnel {
    handle: russh::client::Handle<Pinned>,
    session_id: String,
    /// The entry this tunnel was built from, for diagnostics and for a caller
    /// that needs to know which server it is talking to.
    entry: ServerEntry,
    protocol: crate::protocol::TunnelProtocol,
}

impl SshTunnel {
    /// The session ID this tunnel authenticated with.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The server entry this tunnel was established from.
    pub fn server_entry(&self) -> &ServerEntry {
        &self.entry
    }

    /// The transport this tunnel runs over.
    pub fn protocol(&self) -> crate::protocol::TunnelProtocol {
        self.protocol
    }

    /// Record which transport the carrier was, so diagnostics name the
    /// transport the entry actually used rather than the default.
    pub fn with_protocol(mut self, protocol: crate::protocol::TunnelProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Run the SSH client handshake over an already-connected carrier.
    ///
    /// `stream` is the carrier: a plain TCP socket, an OSSH-wrapped stream, or
    /// (later) a meek stream. The handshake is bounded by `timeout`.
    pub async fn establish<S>(
        stream: S,
        entry: &ServerEntry,
        options: &TunnelOptions,
        timeout: Duration,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let expected = entry.ssh_host_key_bytes()?;
        let session_id = match &options.session_id {
            Some(id) => id.clone(),
            None => new_session_id(),
        };

        let config = Arc::new(russh::client::Config {
            client_id: russh::SshId::Standard(Cow::Owned(options.client_version.clone())),
            window_size: options.window_size,
            maximum_packet_size: options.maximum_packet_size,
            channel_buffer_size: options.channel_buffer_size,
            keepalive_interval: options.keepalive_interval,
            keepalive_max: 3,
            // A dead peer must be noticed; an idle tunnel is not a dead one,
            // so there is no inactivity timeout.
            inactivity_timeout: None,
            ..Default::default()
        });

        let mut handle = tokio::time::timeout(
            timeout,
            russh::client::connect_stream(config, stream, Pinned { expected }),
        )
        .await
        .map_err(|_| Error::Timeout {
            stage: "ssh key exchange",
        })?
        .map_err(|error| Error::Ssh(format!("key exchange: {error}")))?;

        let payload = credential_payload(
            entry.ssh_password(),
            &session_id,
            &options.sponsor_id,
            &options
                .capabilities
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );

        let auth = tokio::time::timeout(
            timeout,
            handle.authenticate_password(entry.ssh_username(), payload),
        )
        .await
        .map_err(|_| Error::Timeout {
            stage: "ssh authentication",
        })?
        .map_err(|error| Error::Ssh(format!("authentication: {error}")))?;

        if !auth.success() {
            return Err(Error::Ssh(
                "the server rejected the tunnel credentials".into(),
            ));
        }

        Ok(SshTunnel {
            handle,
            session_id,
            entry: entry.clone(),
            // The transport is not a parameter of `establish`, so it is
            // recovered from the entry and the caller's intent later; a
            // carrier that is not in the entry's list defaults to plain SSH,
            // which is what the tests drive.
            protocol: crate::protocol::TunnelProtocol::Ssh,
        })
    }

    /// Perform Psiphon's tunnel handshake: an SSH global request named
    /// `psiphon-handshake` carrying the API parameters.
    ///
    /// The server refuses every port forward until this has succeeded, so it
    /// is part of bringing the tunnel up, not an optional extra. The payload
    /// is legacy JSON, which the server accepts alongside its packed CBOR
    /// form; the response is the server's JSON `HandshakeResponse`.
    pub async fn handshake(&self, params: &HandshakeParams) -> Result<Vec<u8>> {
        let payload = params.to_json()?;

        // The server's confirmation is wanted, because Psiphon's server sends
        // its configuration back in it.
        match self
            .handle
            .send_global_request("psiphon-handshake", payload.as_bytes(), true)
            .await
        {
            Ok(response) => Ok(response.map(|data| data.to_vec()).unwrap_or_default()),
            Err(russh::Error::RequestDenied) => {
                // A server that does not implement arbitrary global requests
                // answers with a failure. The request itself was still
                // delivered and processed — the failure is about the reply,
                // not about the handshake — so it is sent once more without
                // asking for one. Psiphon's server, which does implement the
                // request, never takes this path.
                self.handle
                    .send_global_request("psiphon-handshake", payload.as_bytes(), false)
                    .await
                    .map_err(|error| Error::Ssh(format!("handshake request: {error}")))?;
                Ok(Vec::new())
            }
            Err(other) => Err(Error::Ssh(format!("handshake request: {other}"))),
        }
    }

    /// Open a stream to `host:port` through the tunnel.
    pub async fn open(&self, host: &str, port: u16) -> Result<TunnelStream> {
        let channel = tokio::time::timeout(
            CHANNEL_TIMEOUT,
            self.handle
                .channel_open_direct_tcpip(host, u32::from(port), "0.0.0.0", 0),
        )
        .await
        .map_err(|_| Error::Timeout {
            stage: "tunnel channel",
        })?
        .map_err(|error| Error::Channel(error.to_string()))?;

        Ok(TunnelStream {
            inner: channel.into_stream(),
        })
    }

    /// Disconnect cleanly.
    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
    }
}

/// A stream through a `direct-tcpip` channel.
pub struct TunnelStream {
    inner: russh::ChannelStream<russh::client::Msg>,
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
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
    use base64::Engine as _;
    use russh::server::Auth;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The password this fake server accepts, as its credential payload says.
    const PASSWORD: &str = "tunnel-password";

    /// A server that pins itself to one host key, checks the Psiphon
    /// credential payload, and echoes every tunneled stream.
    struct EchoServer {
        expected_session_prefix: String,
    }

    struct EchoHandler {
        expected_session_prefix: String,
    }

    impl russh::server::Handler for EchoHandler {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> std::result::Result<Auth, Self::Error> {
            // The whole Psiphon compatibility of authentication is here: the
            // password must be JSON with the server password inside.
            let Ok(payload) = serde_json::from_str::<serde_json::Value>(password) else {
                return Ok(Auth::reject());
            };
            let password_ok = payload["SshPassword"].as_str() == Some(PASSWORD);
            let session_ok = payload["SessionId"]
                .as_str()
                .is_some_and(|id| id.starts_with(&self.expected_session_prefix) && id.len() == 32);
            // The client does not advertise server-requests yet, so the
            // capabilities field must be absent rather than wrong.
            let capability_ok = match payload.get("ClientCapabilities") {
                None => true,
                Some(list) => list
                    .as_array()
                    .is_some_and(|list| list.iter().any(|c| c == CAPABILITY_SERVER_REQUESTS)),
            };
            if user == "psiphon" && password_ok && session_ok && capability_ok {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            _host: &str,
            _port: u32,
            _origin: &str,
            _origin_port: u32,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> std::result::Result<(), Self::Error> {
            reply.accept().await;
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            Ok(())
        }
    }

    impl russh::server::Server for EchoServer {
        type Handler = EchoHandler;

        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> EchoHandler {
            EchoHandler {
                expected_session_prefix: self.expected_session_prefix.clone(),
            }
        }
    }

    fn host_key() -> russh::keys::PrivateKey {
        use russh::keys::ssh_key::private::Ed25519Keypair;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(&seed))
    }

    fn entry_for(port: u16, host_key: &russh::keys::PrivateKey) -> ServerEntry {
        let public = host_key.public_key().to_bytes().unwrap();
        ServerEntry::from_value(json!({
            "ipAddress": "127.0.0.1",
            "region": "TEST",
            "sshPort": port,
            "sshUsername": "psiphon",
            "sshPassword": PASSWORD,
            "sshHostKey": base64::engine::general_purpose::STANDARD.encode(&public),
            "capabilities": ["SSH"],
        }))
        .unwrap()
    }

    /// Start the echo server; returns its port, host key and the server
    /// entry that points at it.
    async fn serve(session_prefix: &str) -> (u16, ServerEntry, russh::keys::PrivateKey) {
        let key = host_key();
        let config = Arc::new(russh::server::Config {
            keys: vec![key.clone()],
            ..Default::default()
        });
        let mut server = EchoServer {
            expected_session_prefix: session_prefix.to_string(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use russh::server::Server;
            let _ = server.run_on_socket(config, &listener).await;
        });
        let entry = entry_for(port, &key);
        (port, entry, key)
    }

    async fn dial(entry: &ServerEntry) -> Result<SshTunnel> {
        let port = entry
            .port_for(crate::protocol::TunnelProtocol::Ssh)
            .unwrap();
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let options = TunnelOptions {
            session_id: Some("ab".repeat(16)),
            ..Default::default()
        };
        SshTunnel::establish(stream, entry, &options, Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn a_tunnel_authenticates_and_carries_a_stream() {
        let (_port, entry, _key) = serve("ab").await;
        let tunnel = tokio::time::timeout(Duration::from_secs(10), dial(&entry))
            .await
            .expect("the handshake finished")
            .expect("the tunnel came up");
        assert_eq!(tunnel.session_id().len(), 32);

        let mut stream = tunnel.open("192.0.2.55", 80).await.expect("channel");
        stream.write_all(b"hello psiphon").await.unwrap();
        let mut echoed = vec![0u8; 13];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello psiphon");
        tunnel.close().await;
    }

    #[tokio::test]
    async fn a_wrong_host_key_is_refused() {
        let (_port, entry, _key) = serve("ab").await;
        // Point the entry at another valid key.
        let other = host_key();
        let port = entry
            .port_for(crate::protocol::TunnelProtocol::Ssh)
            .unwrap();
        let value = json!({
            "ipAddress": "127.0.0.1",
            "sshPort": port,
            "sshUsername": "psiphon",
            "sshPassword": PASSWORD,
            "sshHostKey": base64::engine::general_purpose::STANDARD
                .encode(other.public_key().to_bytes().unwrap()),
            "capabilities": ["SSH"],
        });
        let entry = ServerEntry::from_value(value).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(10), dial(&entry))
            .await
            .expect("the handshake finished");
        assert!(result.is_err(), "a mismatched host key must fail");
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused() {
        let (_port, entry, _key) = serve("ab").await;
        let port = entry
            .port_for(crate::protocol::TunnelProtocol::Ssh)
            .unwrap();
        let value = json!({
            "ipAddress": "127.0.0.1",
            "sshPort": port,
            "sshUsername": "psiphon",
            "sshPassword": "not-the-password",
            "sshHostKey": base64::engine::general_purpose::STANDARD
                .encode(entry.ssh_host_key_bytes().unwrap()),
            "capabilities": ["SSH"],
        });
        let entry = ServerEntry::from_value(value).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(10), dial(&entry))
            .await
            .expect("the handshake finished");
        assert!(
            matches!(result, Err(Error::Ssh(_))),
            "a rejected credential is an authentication error: {:?}",
            result.err()
        );
    }

    #[test]
    fn the_credential_payload_has_psiphons_field_names() {
        let payload = credential_payload("pw", "00112233445566778899aabbccddeeff", "", &[]);
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["SshPassword"], "pw");
        assert_eq!(value["SessionId"], "00112233445566778899aabbccddeeff");
        // Capabilities are not advertised by default, and an empty sponsor is
        // omitted, as Go's `omitempty` does.
        assert!(value.get("ClientCapabilities").is_none());
        assert!(value.get("SponsorId").is_none());
        let payload = credential_payload(
            "pw",
            "00112233445566778899aabbccddeeff",
            "",
            &[CAPABILITY_SERVER_REQUESTS],
        );
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["ClientCapabilities"][0], CAPABILITY_SERVER_REQUESTS);
    }

    #[test]
    fn session_ids_are_lowercase_hex() {
        let id = new_session_id();
        assert_eq!(id.len(), SESSION_ID_BYTES * 2);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(id, new_session_id());
    }
}
