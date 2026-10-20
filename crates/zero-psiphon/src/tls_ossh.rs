//! The TLS-obfuscated SSH (TLS-OSSH) carrier.
//!
//! TLS-OSSH is the OSSH layer of [`crate::obfuscator`] carried inside a TLS
//! session, so the connection on the wire looks like an ordinary HTTPS
//! connection to a server whose certificate nobody can verify. Psiphon's
//! server issues a self-signed certificate with a random common name that is
//! regenerated at every restart, so the client cannot and does not
//! authenticate it: TLS here is camouflage, and every real guarantee comes
//! from the SSH session inside.
//!
//! Two details make the camouflage hold:
//!
//! * The TLS client offers only TLS 1.3, so the server's certificate — which
//!   is what a filter would use to single the connection out — never appears
//!   in the clear.
//! * The 32 random bytes a TLS client normally puts in its `ClientHello` are
//!   replaced by a *passthrough message*: a nonce and an HMAC over it, keyed
//!   by a value derived from the server entry's obfuscated key. The server
//!   checks it (under a rounded time period, so a message is valid for about
//!   an hour) and otherwise relays the connection to an innocent web server.
//!   An observer sees a plausible TLS handshake either way; only someone who
//!   knows the obfuscated key can tell a Psiphon client from a plain client.
//!
//! The OSSH layer then runs unchanged over the TLS session — the keyword is
//! the entry's `sshObfuscatedKey`, and from OSSH's point of view TLS is just a
//! byte pipe.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};
use crate::obfuscator::OsshClient;

/// Length of the passthrough message's random nonce.
pub const PASSTHROUGH_NONCE_LENGTH: usize = 16;
/// Length of the derived passthrough key.
pub const PASSTHROUGH_KEY_LENGTH: usize = 32;
/// Length of the whole passthrough message, which is exactly the size of a
/// TLS `ClientHello.random`.
pub const PASSTHROUGH_MESSAGE_LENGTH: usize = 32;
/// The message's validity period, in seconds.
pub const PASSTHROUGH_TIME_PERIOD: i64 = 20 * 60;
/// The context string that separates the passthrough key from every other key
/// derived from the same obfuscated key.
const PASSTHROUGH_SALT: &[u8] = b"passthrough-obfuscation-key";

/// Derive the passthrough key for one rounded time period.
///
/// `hkdf.New(sha256.New, obfuscatedKey, "passthrough-obfuscation-key" ||
/// LE64(period), nil)` in the Go client.
fn derive_passthrough_key(obfuscated_key: &str, rounded_period: Option<i64>) -> [u8; 32] {
    let mut salt = PASSTHROUGH_SALT.to_vec();
    if let Some(period) = rounded_period {
        salt.extend_from_slice(&(period as u64).to_le_bytes());
    }

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), obfuscated_key.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(&[], &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// The time period a timestamp falls in: the clock is rounded to
/// `PASSTHROUGH_TIME_PERIOD` boundaries with a half-period of slack, so a
/// client whose clock is slightly off still lands in a period the server
/// accepts.
fn rounded_time_period(unix_time: i64) -> i64 {
    let shift = 0;
    (unix_time + (PASSTHROUGH_TIME_PERIOD / 2) + PASSTHROUGH_TIME_PERIOD * shift)
        / PASSTHROUGH_TIME_PERIOD
}

/// Build the passthrough message for `unix_time` with a caller-supplied nonce,
/// so tests can pin every input.
pub fn passthrough_message_with_nonce(
    obfuscated_key: &str,
    unix_time: i64,
    nonce: [u8; PASSTHROUGH_NONCE_LENGTH],
) -> [u8; PASSTHROUGH_MESSAGE_LENGTH] {
    let key = derive_passthrough_key(obfuscated_key, Some(rounded_time_period(unix_time)));

    let mut message = [0u8; PASSTHROUGH_MESSAGE_LENGTH];
    message[..PASSTHROUGH_NONCE_LENGTH].copy_from_slice(&nonce);

    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&message[..PASSTHROUGH_NONCE_LENGTH]);
    let tag = mac.finalize().into_bytes();
    message[PASSTHROUGH_NONCE_LENGTH..]
        .copy_from_slice(&tag[..PASSTHROUGH_MESSAGE_LENGTH - PASSTHROUGH_NONCE_LENGTH]);

    message
}

/// Build a fresh passthrough message from a random nonce and the current time.
pub fn passthrough_message(obfuscated_key: &str) -> [u8; PASSTHROUGH_MESSAGE_LENGTH] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let mut nonce = [0u8; PASSTHROUGH_NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce);
    passthrough_message_with_nonce(obfuscated_key, now, nonce)
}

/// Check a passthrough message the way the server does: against the current,
/// previous and future time periods, comparing in constant time.
pub fn verify_passthrough_message(obfuscated_key: &str, message: &[u8], unix_time: i64) -> bool {
    if message.len() != PASSTHROUGH_MESSAGE_LENGTH {
        return false;
    }
    let nonce = &message[..PASSTHROUGH_NONCE_LENGTH];
    let tag = &message[PASSTHROUGH_NONCE_LENGTH..];

    (-1..=1).any(|shift| {
        let period = (unix_time + (PASSTHROUGH_TIME_PERIOD / 2) + PASSTHROUGH_TIME_PERIOD * shift)
            / PASSTHROUGH_TIME_PERIOD;
        let key = derive_passthrough_key(obfuscated_key, Some(period));
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(nonce);
        mac.verify_truncated_left(tag).is_ok()
    })
}

/// The ClientHello hook: it puts the passthrough message in the
/// `ClientHello.random` field and, when asked for, the RFC 7685 padding
/// extension in the extension list.
#[derive(Debug)]
struct ClientHelloShaper {
    /// The entry's obfuscated key, absent when no passthrough message is
    /// wanted.
    obfuscated_key: Option<String>,
    padding_length: Option<usize>,
}

impl rustls::client::ClientHelloCustomizer for ClientHelloShaper {
    fn build_client_hello_plan(
        &self,
        _context: rustls::client::ClientHelloContext<'_>,
    ) -> std::result::Result<Option<rustls::client::ClientHelloPlan>, rustls::Error> {
        let mut plan = rustls::client::ClientHelloPlan::new();

        if let Some(obfuscated_key) = self.obfuscated_key.as_deref() {
            // A fresh message per connection: the server keeps a history of
            // recent messages and treats a repeat as a replay.
            plan = plan.with_random(passthrough_message(obfuscated_key));
        }

        if let Some(length) = self.padding_length {
            plan = plan.with_padding(rustls::client::ClientHelloPaddingPlan::fixed(length)?);
        }

        Ok(Some(plan))
    }
}

/// The certificate verifier TLS-OSSH needs: everything is accepted.
///
/// The server's certificate is self-signed with a name generated at each
/// restart, so there is nothing to verify against. This is safe here only
/// because TLS-OSSH does not rely on TLS for authentication — the pinned RSA
/// host key in the SSH handshake inside is what proves the server's identity.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // The server's certificate is not checked against these, but they
        // still have to cover whatever it signs its handshake with.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// How the TLS-OSSH carrier presents itself.
#[derive(Debug, Clone)]
pub struct TlsOsshOptions {
    /// The TLS server name: the `ClientHello` SNI and the name the certificate
    /// would be checked against, if it were checked. `None` sends no SNI at
    /// all, which is what the Go client does when it dials an IP literal and
    /// has no tactics-provided name.
    pub server_name: Option<String>,
    /// Replace `ClientHello.random` with a passthrough message. The Go client
    /// always does this, whether or not the server is configured to check it:
    /// a client that sometimes omitted it would be telling a filter which
    /// servers care.
    pub passthrough: bool,
    /// Bearer padding to advertise with the RFC 7685 TLS padding extension
    /// (type 21). `None` sends no such extension; the Go client only adds it
    /// when tactics say so, with a default length of zero.
    pub padding_length: Option<usize>,
}

impl Default for TlsOsshOptions {
    fn default() -> Self {
        TlsOsshOptions {
            server_name: None,
            passthrough: true,
            padding_length: None,
        }
    }
}

/// Build the TLS client configuration for a TLS-OSSH connection.
pub fn tls_config(obfuscated_key: &str, options: &TlsOsshOptions) -> Arc<rustls::ClientConfig> {
    // The workspace builds against a rustls fork that can shape a ClientHello,
    // which is what lets the passthrough message take the place of the client
    // random. Both TLS versions are enabled in the provider; TLS-OSSH offers
    // TLS 1.3 only.
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is a supported protocol version");

    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();

    config.client_hello_customizer = Some(Arc::new(ClientHelloShaper {
        obfuscated_key: options.passthrough.then(|| obfuscated_key.to_owned()),
        padding_length: options.padding_length,
    }));

    Arc::new(config)
}

/// Run a TLS session over `stream` and wrap it in the OSSH layer.
pub async fn wrap<S>(
    stream: S,
    obfuscated_key: &str,
    options: &TlsOsshOptions,
) -> Result<OsshClient<TlsStream<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut config = (*tls_config(obfuscated_key, options)).clone();
    // SNI is omitted when the caller has no name to offer, which is what the
    // Go client does for an IP-literal destination.
    config.enable_sni = options.server_name.is_some();
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = match options.server_name.as_deref() {
        Some(name) => {
            rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|error| {
                Error::Protocol(format!("invalid TLS server name {name:?}: {error}"))
            })?
        }
        // No SNI wanted: an IP address is a valid `ServerName` that rustls
        // omits from the ClientHello when SNI is disabled, and verification is
        // disabled anyway.
        None => {
            rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::from([0, 0, 0, 0]).into())
        }
    };

    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| Error::Connect(format!("TLS handshake: {error}")))?;

    Ok(OsshClient::new(tls, obfuscated_key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    /// The obfuscated key and rounded period the wire spec's fixture uses.
    const FIXTURE_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FIXTURE_TIME: i64 = 1_700_000_000;
    const FIXTURE_PERIOD: i64 = 1_416_667;
    const FIXTURE_NONCE: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    #[test]
    fn the_rounded_time_period_matches_the_reference() {
        assert_eq!(rounded_time_period(FIXTURE_TIME), FIXTURE_PERIOD);
    }

    #[test]
    fn the_passthrough_key_matches_the_reference() {
        let key = derive_passthrough_key(FIXTURE_KEY, Some(FIXTURE_PERIOD));
        assert_eq!(
            hex::encode(key),
            "ec4287d22cfceecccfa8a20b898be2212b0a5e770a2410f9d9075e3b1cc9b87b"
        );
        // The legacy form, without the time factor, is a different key.
        let key = derive_passthrough_key(FIXTURE_KEY, None);
        assert_eq!(
            hex::encode(key),
            "43757723b9deba4bb00c8ccf3745da0121e1d8a70e0883f47f29bd64d7459fc0"
        );
    }

    #[test]
    fn the_passthrough_message_matches_the_reference() {
        let message = passthrough_message_with_nonce(FIXTURE_KEY, FIXTURE_TIME, FIXTURE_NONCE);
        assert_eq!(
            hex::encode(message),
            "00112233445566778899aabbccddeeffc87c181f1a4dd2a624e01a5876c1a216"
        );
    }

    #[test]
    fn the_server_accepts_a_fresh_message_and_rejects_edits() {
        let message = passthrough_message_with_nonce(FIXTURE_KEY, FIXTURE_TIME, FIXTURE_NONCE);
        assert!(verify_passthrough_message(
            FIXTURE_KEY,
            &message,
            FIXTURE_TIME
        ));
        // The server also accepts the neighbouring periods, so a client whose
        // clock is off by up to one period is not locked out.
        assert!(verify_passthrough_message(
            FIXTURE_KEY,
            &message,
            FIXTURE_TIME + PASSTHROUGH_TIME_PERIOD
        ));
        // Too far away, and it is no longer valid.
        assert!(!verify_passthrough_message(
            FIXTURE_KEY,
            &message,
            FIXTURE_TIME + 3 * PASSTHROUGH_TIME_PERIOD
        ));

        // A different key does not verify it, and neither does a changed byte.
        assert!(!verify_passthrough_message(
            "aabbccdd",
            &message,
            FIXTURE_TIME
        ));
        let mut edited = message;
        edited[31] ^= 1;
        assert!(!verify_passthrough_message(
            FIXTURE_KEY,
            &edited,
            FIXTURE_TIME
        ));
        assert!(!verify_passthrough_message(
            FIXTURE_KEY,
            &message[..31],
            FIXTURE_TIME
        ));
    }

    #[test]
    fn a_fresh_message_verifies_against_the_current_time() {
        let message = passthrough_message(FIXTURE_KEY);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(verify_passthrough_message(FIXTURE_KEY, &message, now));
        // The nonce is random, so two messages never repeat: the server
        // rejects a repeat as a replay.
        assert_ne!(message, passthrough_message(FIXTURE_KEY));
    }

    /// A stream that records the first bytes the client writes, so a test can
    /// inspect the ClientHello the way a network observer would.
    struct RecordsFirstBytes<S> {
        inner: S,
        recorded: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        limit: usize,
    }

    impl<S> AsyncWrite for RecordsFirstBytes<S>
    where
        S: AsyncWrite + Unpin,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            {
                let mut recorded = this.recorded.lock().unwrap();
                if recorded.len() < this.limit {
                    let room = this.limit - recorded.len();
                    recorded.extend_from_slice(&buf[..room.min(buf.len())]);
                }
            }
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl<S> AsyncRead for RecordsFirstBytes<S>
    where
        S: AsyncRead + Unpin,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    /// The self-signed certificate the test TLS server presents. Generated
    /// once for these tests; TLS-OSSH never verifies it, which is the point.
    const TEST_CERTIFICATE_DER: &str = crate::test_certificate::CERTIFICATE_DER;

    /// The PKCS#8 key for [`TEST_CERTIFICATE_DER`].
    const TEST_PRIVATE_KEY_DER: &str = crate::test_certificate::PRIVATE_KEY_DER;

    fn test_tls_server_config() -> Arc<rustls::ServerConfig> {
        let certificate = rustls::pki_types::CertificateDer::from(
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                TEST_CERTIFICATE_DER,
            )
            .unwrap(),
        );
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    TEST_PRIVATE_KEY_DER,
                )
                .unwrap(),
            ));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn the_client_hello_carries_the_passthrough_message_and_no_certificate_name() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let server_task = tokio::spawn({
            let config = test_tls_server_config();
            async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                let mut tls = acceptor.accept(server).await.expect("TLS handshake");
                // Read the OSSH seed message the client sends over TLS.
                let mut header = [0u8; 24];
                tls.read_exact(&mut header).await.unwrap();
                tls
            }
        });

        let stream = RecordsFirstBytes {
            inner: client,
            recorded: std::sync::Arc::clone(&recorded),
            limit: 64,
        };
        let mut session = wrap(stream, FIXTURE_KEY, &TlsOsshOptions::default())
            .await
            .expect("the TLS handshake completes against a self-signed server");

        // The OSSH layer is intact on top of TLS: the client's first bytes are
        // the seed, and the magic value follows.
        session.write_all(b"SSH-2.0-rust\r\n").await.unwrap();

        let _ = server_task.await.unwrap();

        // TLS record header (5) + handshake header (4) + legacy version (2)
        // then exactly the ClientHello random.
        let hello = recorded.lock().unwrap().clone();
        assert!(hello.len() >= 43, "recorded {} bytes", hello.len());
        assert_eq!(hello[0], 0x16, "the first record is a handshake");
        assert_eq!(
            hello[5], 0x01,
            "the first handshake message is a ClientHello"
        );

        let random: [u8; 32] = hello[11..43].try_into().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            verify_passthrough_message(FIXTURE_KEY, &random, now),
            "ClientHello.random is a passthrough message"
        );
    }

    #[tokio::test]
    async fn the_ossh_layer_runs_inside_the_tls_session() {
        // The full nesting the real server sees: TLS, then the OSSH seed
        // message and obfuscated SSH, ending at NEWKEYS. The server side here
        // derives the same keys from the seed the client sent, so this also
        // proves the two ends of the TLS carrier agree on the OSSH state
        // machine.
        use crate::obfuscator::{derive_key, Rc4, CLIENT_TO_SERVER, SERVER_TO_CLIENT};

        let (client, server) = tokio::io::duplex(64 * 1024);
        let client_line = b"SSH-2.0-rust\r\n";
        let expected_line = b"SSH-2.0-test-server\r\n";
        let after_newkeys = b"PLAINTEXT-AFTER-NEWKEYS";

        let server_task = tokio::spawn({
            let config = test_tls_server_config();
            async move {
                use tokio::io::AsyncReadExt;
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                let mut tls = acceptor.accept(server).await.expect("TLS handshake");

                // The seed message: the seed is clear, the rest is encrypted.
                let mut header = [0u8; 24];
                tls.read_exact(&mut header).await.unwrap();
                let seed: [u8; 16] = header[..16].try_into().unwrap();
                let mut c2s =
                    Rc4::new(&derive_key(&seed, FIXTURE_KEY.as_bytes(), CLIENT_TO_SERVER));
                let mut s2c =
                    Rc4::new(&derive_key(&seed, FIXTURE_KEY.as_bytes(), SERVER_TO_CLIENT));
                c2s.apply(&mut header[16..]);
                assert_eq!(
                    u32::from_be_bytes(header[16..20].try_into().unwrap()),
                    crate::obfuscator::MAGIC_VALUE
                );

                // The seed message's own padding: random bytes that are part
                // of the obfuscated region, so the server has to consume them
                // to stay in step with the client's cipher.
                let padding_length =
                    u32::from_be_bytes(header[20..24].try_into().unwrap()) as usize;
                assert!((32..=8192).contains(&padding_length));
                let mut padding = vec![0u8; padding_length];
                tls.read_exact(&mut padding).await.unwrap();
                c2s.apply(&mut padding);

                // Version line, one byte at a time, as the Go client reads it.
                let mut line = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    tls.read_exact(&mut byte).await.unwrap();
                    c2s.apply(&mut byte);
                    line.push(byte[0]);
                    if line.ends_with(b"\r\n") {
                        break;
                    }
                }
                assert_eq!(line, client_line);

                // The server's own version line, obfuscated, then a NEWKEYS
                // packet, then bytes that are not obfuscated because NEWKEYS
                // has passed.
                let mut reply = expected_line.to_vec();
                s2c.apply(&mut reply);
                tls.write_all(&reply).await.unwrap();

                let mut newkeys = [0u8; 7];
                newkeys[..4].copy_from_slice(&3u32.to_be_bytes());
                newkeys[4] = 1;
                newkeys[5] = 21;
                s2c.apply(&mut newkeys);
                tls.write_all(&newkeys).await.unwrap();
                tls.write_all(after_newkeys).await.unwrap();
                tls.flush().await.unwrap();

                // The client's own NEWKEYS ends its obfuscated phase; the
                // packet-length rewrite applies to it like any other packet.
                let mut prefix = [0u8; 5];
                tls.read_exact(&mut prefix).await.unwrap();
                c2s.apply(&mut prefix);
                let packet_length = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
                let padding_length = prefix[4] as usize;
                let mut rest = vec![0u8; 4 + packet_length - 5];
                tls.read_exact(&mut rest).await.unwrap();
                c2s.apply(&mut rest);
                assert_eq!(rest[..packet_length - padding_length - 1], [21u8]);

                // Everything the client sends after its NEWKEYS is plaintext.
                let mut tail = vec![0u8; client_line.len()];
                tls.read_exact(&mut tail).await.unwrap();
                assert_eq!(tail, client_line);
            }
        });

        let mut session = wrap(client, FIXTURE_KEY, &TlsOsshOptions::default())
            .await
            .expect("the TLS handshake completes");
        session.write_all(client_line).await.unwrap();

        use tokio::io::AsyncReadExt;
        let mut line = vec![0u8; expected_line.len()];
        session.read_exact(&mut line).await.unwrap();
        assert_eq!(line, expected_line);

        let mut packet = [0u8; 7];
        session.read_exact(&mut packet).await.unwrap();
        assert_eq!(packet[5], 21, "the packet is SSH_MSG_NEWKEYS");

        let mut tail = vec![0u8; after_newkeys.len()];
        session.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, after_newkeys);

        // The client's NEWKEYS: from here its own writes are plaintext too.
        session.write_all(&ssh_packet(&[21])).await.unwrap();
        // Post-NEWKEYS writes go out unobfuscated, as the server expects.
        session.write_all(client_line).await.unwrap();
        session.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("the server task finishes")
            .unwrap();
    }

    /// A minimal SSH packet: length, padding length, payload, padding. The
    /// OSSH layer rewrites the padding but not the payload.
    fn ssh_packet(payload: &[u8]) -> Vec<u8> {
        let padding = 4;
        let packet_length = payload.len() + padding + 1;
        let mut packet = Vec::new();
        packet.extend_from_slice(&(packet_length as u32).to_be_bytes());
        packet.push(padding as u8);
        packet.extend_from_slice(payload);
        packet.extend_from_slice(&[0u8; 4]);
        packet
    }

    /// Record the ClientHello of one handshake against the test server.
    async fn recorded_client_hello(options: TlsOsshOptions) -> Vec<u8> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let server_task = tokio::spawn({
            let config = test_tls_server_config();
            async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                let _ = acceptor.accept(server).await;
            }
        });

        let stream = RecordsFirstBytes {
            inner: client,
            recorded: std::sync::Arc::clone(&recorded),
            limit: 1024,
        };
        let session = wrap(stream, FIXTURE_KEY, &options).await;
        drop(session);
        let _ = server_task.await;
        let hello = recorded.lock().unwrap().clone();
        hello
    }

    /// The length of the ClientHello body, from its handshake header.
    fn hello_body_length(hello: &[u8]) -> usize {
        u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize
    }

    #[tokio::test]
    async fn padding_lengthens_the_client_hello_only_when_asked_for() {
        let plain = recorded_client_hello(TlsOsshOptions::default()).await;
        let padded = recorded_client_hello(TlsOsshOptions {
            padding_length: Some(64),
            ..Default::default()
        })
        .await;

        assert!(!plain.is_empty() && !padded.is_empty());
        // The extension costs its four-byte header on top of the padding.
        assert_eq!(
            hello_body_length(&padded) - hello_body_length(&plain),
            64 + 4
        );
    }
}
