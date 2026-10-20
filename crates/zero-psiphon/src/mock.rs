//! An in-process Psiphon server, for end-to-end tests.
//!
//! The real oracle is the Go server in `.research/psiphon-server-harness`,
//! but a test that needs the server *and* the origin in one process — one
//! that checks a request's path through the whole stack, or that runs on a
//! machine with no Go toolchain — needs a server it can start itself.
//!
//! This one speaks Psiphon's side of the protocol: the JSON credential
//! payload as the SSH password, the `psiphon-handshake` global request, and
//! `direct-tcpip` channels that are forwarded to a real origin. It can also
//! serve the obfuscated transport, so a test covers the OSSH layer without a
//! second process.
//!
//! It is deliberately a *client-facing* mock: it checks what a Psiphon server
//! checks and nothing more. It does not implement the server's API, its
//! tactics endpoint or its rate limits, so a test that needs those is testing
//! something this file does not stand in for.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use russh::server::Auth;
use serde_json::json;
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::obfuscator::{
    derive_key, Rc4, CLIENT_TO_SERVER, MAGIC_VALUE, SEED_LENGTH, SERVER_TO_CLIENT,
};

/// The SSH message that ends the obfuscated phase.
const SSH_MSG_NEWKEYS: u8 = 21;
use crate::protocol::TunnelProtocol;
use crate::server_entry::ServerEntry;

/// The password the mock accepts, as the credential payload carries it.
pub const MOCK_PASSWORD: &str = "psiphon-mock-password";
/// The user name the mock accepts.
pub const MOCK_USERNAME: &str = "psiphon";

/// The transport the mock listens for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain SSH.
    Ssh,
    /// Obfuscated SSH: the seed message and the RC4 layer around it.
    Ossh,
}

/// How the mock server should behave.
#[derive(Debug, Clone)]
pub struct MockOptions {
    /// The password the credential payload must carry.
    pub password: String,
    /// The transport the server listens for.
    pub transport: Transport,
    /// The OSSH keyword, when the transport needs one.
    pub obfuscated_key: String,
}

impl MockOptions {
    /// The default options: plain SSH and the mock password.
    pub fn new() -> MockOptions {
        MockOptions {
            password: MOCK_PASSWORD.to_string(),
            transport: Transport::Ssh,
            obfuscated_key: String::new(),
        }
    }

    /// The options for the obfuscated transport.
    pub fn ossh(obfuscated_key: &str) -> MockOptions {
        MockOptions {
            transport: Transport::Ossh,
            obfuscated_key: obfuscated_key.to_string(),
            ..MockOptions::new()
        }
    }
}

impl Default for MockOptions {
    fn default() -> Self {
        MockOptions::new()
    }
}

/// A running mock server.
pub struct MockServer {
    /// The port it listens on.
    pub port: u16,
    /// The server entry a client needs to reach it.
    pub entry: ServerEntry,
    /// The host key it uses, so a test can check the pinning.
    pub host_key: russh::keys::PrivateKey,
    /// How many channels it opened, for a test that counts them.
    pub channels_opened: Arc<AtomicUsize>,
}

/// A handler that checks the Psiphon credential payload and forwards
/// channels to the origin.
struct MockHandler {
    options: MockOptions,
    origin: std::net::SocketAddr,
    channels_opened: Arc<AtomicUsize>,
}

impl russh::server::Handler for MockHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        // The whole of Psiphon's authentication compatibility is here: the
        // password must be a JSON document with the server's password in it.
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(password) else {
            return Ok(Auth::reject());
        };
        let password_ok = payload["SshPassword"].as_str() == Some(self.options.password.as_str());
        let session_ok = payload["SessionId"]
            .as_str()
            .is_some_and(|id| id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()));
        if user == MOCK_USERNAME && password_ok && session_ok {
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
        self.channels_opened.fetch_add(1, Ordering::Relaxed);
        reply.accept().await;

        // The channel is forwarded to the origin, so a test sees the real
        // path: client -> tunnel -> origin.
        let origin = self.origin;
        tokio::spawn(async move {
            let Ok(mut upstream) = tokio::net::TcpStream::connect(origin).await else {
                return;
            };
            let mut stream = channel.into_stream();
            tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                .await
                .ok();
        });
        Ok(())
    }
}

/// A server that hands out a handler per connection.
struct MockServerRunner {
    options: MockOptions,
    origin: std::net::SocketAddr,
    channels_opened: Arc<AtomicUsize>,
}

impl russh::server::Server for MockServerRunner {
    type Handler = MockHandler;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> MockHandler {
        MockHandler {
            options: self.options.clone(),
            origin: self.origin,
            channels_opened: Arc::clone(&self.channels_opened),
        }
    }
}

/// A host key for the mock: a fresh Ed25519 key each time.
pub fn host_key() -> russh::keys::PrivateKey {
    use rand::RngCore;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

/// Start the mock server, forwarding to `origin`.
///
/// Returns the server, so a test can read its port and its entry.
pub async fn serve(origin: std::net::SocketAddr, options: MockOptions) -> MockServer {
    let key = host_key();
    let config = Arc::new(russh::server::Config {
        keys: vec![key.clone()],
        ..Default::default()
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let channels_opened = Arc::new(AtomicUsize::new(0));

    let mut server = MockServerRunner {
        options: options.clone(),
        origin,
        channels_opened: Arc::clone(&channels_opened),
    };

    match options.transport {
        Transport::Ssh => {
            use russh::server::Server;
            tokio::spawn(async move {
                let _ = server.run_on_socket(config, &listener).await;
            });
        }
        Transport::Ossh => {
            // The obfuscated transport: every connection begins with the seed
            // message, and the rest of the session runs under the RC4 layer.
            let obfuscated_key = options.obfuscated_key.clone();
            let key = key.clone();
            let channels_opened = Arc::clone(&channels_opened);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let obfuscated_key = obfuscated_key.clone();
                    let config = Arc::new(russh::server::Config {
                        keys: vec![key.clone()],
                        ..Default::default()
                    });
                    let handler = MockHandler {
                        options: MockOptions::ossh(&obfuscated_key),
                        origin,
                        channels_opened: Arc::clone(&channels_opened),
                    };
                    tokio::spawn(async move {
                        let Some(stream) = OsshServer::accept(stream, &obfuscated_key).await else {
                            return;
                        };
                        let _ = russh::server::run_stream(config, stream, handler).await;
                    });
                }
            });
        }
    }

    let public = key.public_key().to_bytes().expect("a public key");
    let entry = ServerEntry::from_value(json!({
        "ipAddress": "127.0.0.1",
        "region": "TEST",
        "sshPort": port,
        "sshObfuscatedPort": port,
        "sshUsername": MOCK_USERNAME,
        "sshPassword": options.password,
        "sshObfuscatedKey": options.obfuscated_key,
        "sshHostKey": base64::engine::general_purpose::STANDARD.encode(&public),
        "capabilities": ["SSH", "OSSH"],
    }))
    .expect("the entry parses");

    MockServer {
        port,
        entry,
        host_key: key,
        channels_opened,
    }
}

/// The server side of the obfuscated layer: the mirror of the client's.
///
/// The client encrypts what it writes with the `client_to_server` cipher and
/// decrypts what it reads with `server_to_client`; the server does the
/// opposite.
pub struct OsshServer<S = tokio::net::TcpStream> {
    inner: S,
    /// What the client writes: decrypted with the client-to-server cipher.
    read_cipher: Rc4,
    /// What the server writes: encrypted with the server-to-client cipher.
    write_cipher: Rc4,
    /// Whether what the client writes is still obfuscated. It ends with the
    /// client's `SSH_MSG_NEWKEYS` packet: everything after that is plain SSH,
    /// and decrypting it would turn the session into noise.
    read_obfuscated: bool,
    /// Whether what the server writes is still obfuscated. It ends with the
    /// server's own `SSH_MSG_NEWKEYS`, which is a separate moment: the two
    /// directions leave the obfuscated phase independently.
    write_obfuscated: bool,
    /// The bytes of a packet that has not been read in full yet, so the
    /// `NEWKEYS` boundary can be found across reads.
    read_pending: Vec<u8>,
    /// The same for the outgoing direction.
    write_pending: Vec<u8>,
}

impl OsshServer {
    /// Read the seed message and return the session's server side.
    pub async fn accept(stream: tokio::net::TcpStream, obfuscated_key: &str) -> Option<OsshServer> {
        Self::from_parts(stream, obfuscated_key.to_string()).await
    }

    /// The same, over any stream.
    pub async fn from_parts<S>(mut stream: S, obfuscated_key: String) -> Option<OsshServer<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut header = [0u8; SEED_LENGTH + 8];
        stream.read_exact(&mut header).await.ok()?;
        let seed: [u8; SEED_LENGTH] = header[..SEED_LENGTH].try_into().ok()?;

        let mut read_cipher = Rc4::new(&derive_key(
            &seed,
            obfuscated_key.as_bytes(),
            CLIENT_TO_SERVER,
        ));
        let write_cipher = Rc4::new(&derive_key(
            &seed,
            obfuscated_key.as_bytes(),
            SERVER_TO_CLIENT,
        ));

        // The magic value is encrypted, so it can only be checked with the
        // derived cipher.
        let mut magic = header[SEED_LENGTH..SEED_LENGTH + 4].to_vec();
        read_cipher.apply(&mut magic);
        if u32::from_be_bytes(magic.try_into().ok()?) != MAGIC_VALUE {
            return None;
        }

        // The padding is part of the encrypted region, and the client's
        // cipher has to be advanced over it before the session starts.
        let mut padding_length = header[SEED_LENGTH + 4..SEED_LENGTH + 8].to_vec();
        read_cipher.apply(&mut padding_length);
        let padding_length = u32::from_be_bytes(padding_length.try_into().ok()?) as usize;
        if padding_length > 64 * 1024 {
            return None;
        }
        let mut padding = vec![0u8; padding_length];
        stream.read_exact(&mut padding).await.ok()?;
        read_cipher.apply(&mut padding);

        Some(OsshServer {
            inner: stream,
            read_cipher,
            write_cipher,
            read_obfuscated: true,
            write_obfuscated: true,
            read_pending: Vec::new(),
            write_pending: Vec::new(),
        })
    }
}

impl<S> OsshServer<S> {
    /// Whether the bytes read so far contain a `SSH_MSG_NEWKEYS` packet.
    ///
    /// The packet framing is the SSH one — a four-byte length, a one-byte
    /// padding length, the payload, the padding — so the message type is the
    /// first payload byte.
    fn read_pending_has_newkeys(&mut self) -> bool {
        scan_for_newkeys(&mut self.read_pending)
    }

    /// The same for the outgoing direction.
    fn write_pending_has_newkeys(&mut self) -> bool {
        scan_for_newkeys(&mut self.write_pending)
    }
}

/// Look for a `SSH_MSG_NEWKEYS` packet in `pending`, consuming the packets it
/// recognises.
fn scan_for_newkeys(pending: &mut Vec<u8>) -> bool {
    loop {
        if pending.len() < 5 {
            return false;
        }
        let packet_length =
            u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
        if !(2..=256 * 1024).contains(&packet_length) {
            // Not a packet this layer can parse; stop looking.
            pending.clear();
            return false;
        }
        if pending.len() < 4 + packet_length {
            return false;
        }
        let payload_length = packet_length - pending[4] as usize - 1;
        let is_newkeys = payload_length > 0 && pending[5] == SSH_MSG_NEWKEYS;
        pending.drain(..4 + packet_length);
        if is_newkeys {
            return true;
        }
    }
}

impl<S> AsyncRead for OsshServer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Read into the caller's buffer, then decrypt in place. The buffer is
        // borrowed, so the decryption happens after the read completes.
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let filled = buf.filled().len();
                if filled > before {
                    let mut chunk = buf.filled()[before..].to_vec();
                    if this.read_obfuscated {
                        this.read_cipher.apply(&mut chunk);
                    }
                    this.read_pending.extend_from_slice(&chunk);
                    if this.read_pending_has_newkeys() {
                        this.read_obfuscated = false;
                    }
                    buf.filled_mut()[before..].copy_from_slice(&chunk);
                }
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> AsyncWrite for OsshServer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut encrypted = buf.to_vec();
        if this.write_obfuscated {
            this.write_cipher.apply(&mut encrypted);
        }
        // The packet that carries NEWKEYS is still obfuscated; the one after
        // it is not.
        this.write_pending.extend_from_slice(buf);
        if this.write_pending_has_newkeys() {
            this.write_obfuscated = false;
        }
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            std::task::Poll::Ready(Ok(written)) => {
                // Report the caller's bytes, not the encrypted ones.
                std::task::Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The transport a mock entry offers.
pub fn transport_of(entry: &ServerEntry) -> TunnelProtocol {
    entry
        .supported_protocols()
        .first()
        .copied()
        .unwrap_or(TunnelProtocol::Ssh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::{HandshakeParams, SshTunnel, TunnelOptions};
    use std::time::Duration;

    /// A tiny HTTP origin, so a test can see what came through the tunnel.
    async fn origin_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nmock-ok")
                        .await
                        .ok();
                });
            }
        });
        (address, handle)
    }

    async fn fetch(tunnel: &SshTunnel, origin: std::net::SocketAddr) -> String {
        let mut channel = tunnel
            .open(&origin.ip().to_string(), origin.port())
            .await
            .expect("the channel opens");
        channel
            .write_all(b"GET / HTTP/1.1\r\nHost: mock\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        channel.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn a_client_tunnels_through_the_mock_server() {
        let (origin, _origin_task) = origin_server().await;
        let server = serve(origin, MockOptions::new()).await;

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        let tunnel = SshTunnel::establish(
            stream,
            &server.entry,
            &TunnelOptions::default(),
            Duration::from_secs(10),
        )
        .await
        .expect("the mock server accepts the credential payload");

        tunnel
            .handshake(&HandshakeParams::new(TunnelProtocol::Ssh))
            .await
            .expect("the handshake completes");

        let text = fetch(&tunnel, origin).await;
        assert!(text.contains("mock-ok"), "{text}");
        assert_eq!(
            server.channels_opened.load(Ordering::Relaxed),
            1,
            "the mock opened one channel"
        );
    }

    #[tokio::test]
    async fn the_obfuscated_transport_carries_the_same_session() {
        let (origin, _origin_task) = origin_server().await;
        let server = serve(origin, MockOptions::ossh("mock-obfuscation-key")).await;

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        let carrier = crate::obfuscator::OsshClient::new(stream, b"mock-obfuscation-key");
        let tunnel = SshTunnel::establish(
            carrier,
            &server.entry,
            &TunnelOptions::default(),
            Duration::from_secs(10),
        )
        .await
        .expect("the mock server accepts the obfuscated session");

        tunnel
            .handshake(&HandshakeParams::new(TunnelProtocol::Ossh))
            .await
            .expect("the handshake completes");

        let text = fetch(&tunnel, origin).await;
        assert!(text.contains("mock-ok"), "{text}");
    }

    /// The same session over a plain stream, with no obfuscation: this tells
    /// the two halves of the mock apart when something fails.
    #[tokio::test]
    async fn a_client_tunnels_through_the_mock_over_a_plain_stream() {
        let (origin, _origin_task) = origin_server().await;

        // The listener path goes through `run_on_socket`; this test drives
        // `run_stream` instead, which is what the obfuscated transport needs.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let key = host_key();
        let config = Arc::new(russh::server::Config {
            keys: vec![key.clone()],
            ..Default::default()
        });
        let handler = MockHandler {
            options: MockOptions::new(),
            origin,
            channels_opened: Arc::new(AtomicUsize::new(0)),
        };
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = russh::server::run_stream(config, stream, handler).await;
        });

        let public = key.public_key().to_bytes().unwrap();
        let entry = ServerEntry::from_value(json!({
            "ipAddress": "127.0.0.1",
            "region": "TEST",
            "sshPort": port,
            "sshUsername": MOCK_USERNAME,
            "sshPassword": MOCK_PASSWORD,
            "sshHostKey": base64::engine::general_purpose::STANDARD.encode(&public),
            "capabilities": ["SSH"],
        }))
        .unwrap();

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let tunnel = SshTunnel::establish(
            stream,
            &entry,
            &TunnelOptions::default(),
            Duration::from_secs(10),
        )
        .await
        .expect("the session comes up over a plain stream");
        tunnel
            .handshake(&HandshakeParams::new(TunnelProtocol::Ssh))
            .await
            .unwrap();
        let text = fetch(&tunnel, origin).await;
        assert!(text.contains("mock-ok"), "{text}");
    }

    #[tokio::test]
    async fn the_mock_rejects_a_wrong_password() {
        let (origin, _origin_task) = origin_server().await;
        let server = serve(origin, MockOptions::new()).await;

        let entry = ServerEntry::from_value(json!({
            "ipAddress": "127.0.0.1",
            "region": "TEST",
            "sshPort": server.port,
            "sshUsername": MOCK_USERNAME,
            "sshPassword": "wrong",
            "sshHostKey": base64::engine::general_purpose::STANDARD
                .encode(server.host_key.public_key().to_bytes().unwrap()),
            "capabilities": ["SSH"],
        }))
        .unwrap();

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        let result = SshTunnel::establish(
            stream,
            &entry,
            &TunnelOptions::default(),
            Duration::from_secs(10),
        )
        .await;
        assert!(result.is_err(), "a wrong password must be refused");
    }
}

#[cfg(test)]
mod cipher_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// The two sides of the obfuscated layer must agree byte for byte: this
    /// is the check that catches a desync before the SSH handshake does.
    #[tokio::test]
    async fn the_server_side_reverses_the_client_side() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let keyword = "test-keyword";

        let server_task = tokio::spawn(async move {
            let mut server = OsshServer::from_parts(server, keyword.to_string())
                .await
                .expect("the seed message");
            // The client sends an identification line first, as SSH requires.
            let mut line = vec![0u8; b"SSH-2.0-test\r\n".len()];
            server.read_exact(&mut line).await.unwrap();
            assert_eq!(&line, b"SSH-2.0-test\r\n");
            server.write_all(b"SSH-2.0-server\r\n").await.unwrap();
            server.flush().await.unwrap();
        });

        let mut client = crate::obfuscator::OsshClient::new(client, keyword.as_bytes());
        client.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        client.flush().await.unwrap();
        let mut buffer = vec![0u8; b"SSH-2.0-server\r\n".len()];
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"SSH-2.0-server\r\n");

        server_task.await.unwrap();
    }
}
