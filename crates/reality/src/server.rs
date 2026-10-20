//! Minimal TLS 1.3 server handshake used by REALITY.
//!
//! This is deliberately the mirror image of `client.rs`, not a general
//! certificate TLS implementation. It accepts a byte-controlled ClientHello,
//! validates the REALITY session seal, and then exposes the same record stream
//! type used by the client implementation.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use ml_kem::{Encapsulate, EncapsulationKey768};
use rand::RngCore;
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use zero_core::{Confidence, Failure, FailureKind, Stage};
use zero_security::tls13::kdf::{
    establish_application_secrets, establish_handshake_secrets, finished_verify_data, Transcript,
};
use zero_security::tls13::record::{
    check_cleartext_body, parse_header, record_header, RecordCrypter, CONTENT_APPDATA, CONTENT_CCS,
    CONTENT_HANDSHAKE, DUMMY_CCS,
};
use zero_security::tls13::{CipherSuite, Tls13Stream};

#[derive(Clone)]
pub struct RealityServerParams {
    pub private_key: [u8; 32],
    pub server_names: Box<[Box<str>]>,
    pub short_ids: Box<[Box<[u8]>]>,
    /// Seed of the ML-DSA-65 key that signs each handshake's binding to the
    /// client's hello and the server's (Xray's `mldsa65Seed`); `None` leaves
    /// the certificate as it has always been.
    pub mldsa65_seed: Option<[u8; 32]>,
    /// Refuse (as not REALITY) a hello whose clock is further than this from
    /// ours; zero for no check.
    pub max_time_diff: std::time::Duration,
    /// Refuse a client older or newer than these, as `[major, minor, patch]`.
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    /// What each server name's real site sends after a handshake, filled in
    /// by whoever can reach that site. Empty until then, and the server sends
    /// nothing extra for a name it has no entry for.
    pub post_handshake: Arc<PostHandshakeShapes>,
}

impl std::fmt::Debug for RealityServerParams {
    // Neither key is ever printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityServerParams")
            .field("server_names", &self.server_names)
            .field("short_ids", &self.short_ids.len())
            .field("mldsa65", &self.mldsa65_seed.is_some())
            .finish_non_exhaustive()
    }
}

/// The sizes of the records a camouflage site sends straight after a
/// handshake, per server name (see [`zero_security::tls13::post_handshake`]).
///
/// After each handshake it accepts, the server sends empty records of the
/// sizes stored for the name the client asked for, so the first thing on the
/// wire after the handshake matches the real site's.
#[derive(Debug, Default)]
pub struct PostHandshakeShapes(Mutex<Vec<Shape>>);

/// A server name and the record sizes its site sends.
type Shape = (Box<str>, Arc<[u16]>);

impl PostHandshakeShapes {
    /// Remember `wire_lens` for `server_name`, replacing what was there.
    pub fn set(&self, server_name: &str, wire_lens: &[u16]) {
        let mut shapes = self.0.lock().unwrap_or_else(|p| p.into_inner());
        shapes.retain(|(name, _)| &**name != server_name);
        shapes.push((server_name.into(), wire_lens.into()));
    }

    fn get(&self, server_name: &str) -> Option<Arc<[u16]>> {
        let shapes = self.0.lock().unwrap_or_else(|p| p.into_inner());
        shapes
            .iter()
            .find(|(name, _)| &**name == server_name)
            .map(|(_, lens)| Arc::clone(lens))
    }
}

struct ClientHelloInfo {
    message: Vec<u8>,
    random: [u8; 32],
    session_id: [u8; 32],
    /// The X25519 public key the REALITY *tag* is authenticated against.
    ///
    /// The standalone `x25519` share when the hello carries one, otherwise the
    /// X25519 half of the hybrid share — the order REALITY's own server scan
    /// uses ("secondary choice: X25519 in X25519MLKEM768").
    auth_key_share: [u8; 32],
    /// The hybrid share, split into its two halves.
    ///
    /// These are kept apart from `auth_key_share` because they are genuinely
    /// different keys. Go's TLS client generates an independent ECDHE key for
    /// every group it offers, so the X25519 inside `X25519MLKEM768` is *not*
    /// the standalone `x25519` share. Deriving the TLS handshake secret from
    /// the wrong one produces a valid-looking hello, a completed ServerHello,
    /// and then a peer that cannot open a single record.
    hybrid: Option<HybridShare>,
    sni: String,
    suite: CipherSuite,
}

/// A client `X25519MLKEM768` key share.
struct HybridShare {
    /// ML-KEM-768 encapsulation key (1184 bytes).
    mlkem_key: Vec<u8>,
    /// The X25519 public key that follows it, used for this group's ECDH.
    x25519: [u8; 32],
}

/// Result of the first REALITY inspection. The fallback arm preserves the
/// socket and the exact record bytes already consumed from it.
///
/// `Accepted` is deliberately unboxed even though it dwarfs the other arms:
/// the outcome is produced once per connection and destructured immediately,
/// so the size costs one move, while boxing would add a heap allocation to
/// every accepted connection and change the type callers match on.
#[allow(clippy::large_enum_variant)]
pub enum HandshakeOutcome<S> {
    Accepted(Tls13Stream<S>),
    Fallback {
        stream: S,
        client_hello: Vec<u8>,
        failure: Failure,
    },
    Rejected(Failure),
}

pub async fn handshake<S>(io: S, params: &RealityServerParams) -> Result<Tls13Stream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match handshake_or_fallback(io, params).await {
        HandshakeOutcome::Accepted(stream) => Ok(stream),
        HandshakeOutcome::Fallback { failure, .. } | HandshakeOutcome::Rejected(failure) => {
            Err(failure)
        }
    }
}

/// Perform the REALITY handshake while preserving a valid first record for a
/// fallback site when the connection is ordinary TLS or has the wrong REALITY
/// credentials.
pub async fn handshake_or_fallback<S>(
    mut io: S,
    params: &RealityServerParams,
) -> HandshakeOutcome<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (client_hello, message) = match read_client_hello_record(&mut io).await {
        Ok(ClientHelloRead::Complete { record, message }) => (record, message),
        Ok(ClientHelloRead::NotTls { consumed, failure }) => {
            // Not a ClientHello at all: exactly what REALITY forwards to the
            // target untouched. Dropping it instead would answer an active
            // probe differently from the decoy site.
            return HandshakeOutcome::Fallback {
                stream: io,
                client_hello: consumed,
                failure,
            };
        }
        Err(failure) => return HandshakeOutcome::Rejected(failure),
    };
    let hello = match parse_client_hello(message) {
        Ok(hello) => hello,
        Err(failure) => {
            return HandshakeOutcome::Fallback {
                stream: io,
                client_hello,
                failure,
            }
        }
    };
    // The server name is compared exactly, as sent: Go's gate is a plain
    // `config.ServerNames[hs.clientHello.serverName]` map lookup
    // (`RL/tls.go:211`), so a hello naming `Example.com` does not match a
    // configured `example.com` and is answered by the camouflage site. A server
    // that accepts a spelling it does not advertise is a fingerprint, and
    // widening the accepted set is exactly the direction a prober can measure.
    if !params
        .server_names
        .iter()
        .any(|name| name.as_ref() == hello.sni.as_str())
    {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("ClientHello SNI is not allowed"),
        };
    }

    let shared = x25519_dalek::x25519(params.private_key, hello.auth_key_share);
    if shared.iter().all(|byte| *byte == 0) {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("REALITY X25519 shared secret is degenerate"),
        };
    }
    let auth_key = derive_auth_key(&shared, &hello.random[..20]);
    let aad = match zero_session_id(&hello.message) {
        Ok(aad) => aad,
        Err(failure) => {
            return HandshakeOutcome::Fallback {
                stream: io,
                client_hello,
                failure,
            }
        }
    };
    let plaintext =
        match decrypt_session_id(&auth_key, &hello.random[20..], &hello.session_id, &aad) {
            Ok(plaintext) => plaintext,
            Err(failure) => {
                return HandshakeOutcome::Fallback {
                    stream: io,
                    client_hello,
                    failure,
                }
            }
        };
    // The gates are asked in Go's order (`RL/tls.go:257-262`): the seal above,
    // then `MinClientVer` / `MaxClientVer`, then `MaxTimeDiff`, then the
    // shortId. Every one of them fails into the same silent fallback, so the
    // order is only visible in which refusal a probe that fails several earns
    // — and a server that named the selector before the version would be
    // answering about a hello Go had already sent to the site.
    if let Err(failure) = check_client_limits(params, &plaintext) {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure,
        };
    }
    // Fold over every configured id without short-circuiting: the shortId is
    // the actual secret gate (anyone with the public key can produce a valid
    // seal), so its comparison must not leak through timing.
    let authorised = params.short_ids.iter().fold(Choice::from(0), |acc, short| {
        acc | short_id_matches(&plaintext[8..16], short)
    });
    if !bool::from(authorised) {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("REALITY shortId is not authorised"),
        };
    }

    let post_handshake = params.post_handshake.get(&hello.sni);
    match complete_handshake(io, hello, auth_key, post_handshake, params.mldsa65_seed).await {
        Ok(stream) => HandshakeOutcome::Accepted(stream),
        Err(failure) => HandshakeOutcome::Rejected(failure),
    }
}

/// The client's version and clock, from the session id's plaintext, held to
/// the limits the server was given. A client that fails them is answered as
/// any non-REALITY visitor is, so the limits are not an oracle either.
fn check_client_limits(params: &RealityServerParams, plaintext: &[u8]) -> Result<(), Failure> {
    let version = [plaintext[0], plaintext[1], plaintext[2]];
    if params.min_client_ver.is_some_and(|min| version < min)
        || params.max_client_ver.is_some_and(|max| version > max)
    {
        return Err(reality_error(
            "REALITY client version is outside the accepted range",
        ));
    }
    if !params.max_time_diff.is_zero() {
        let sent = u64::from(u32::from_be_bytes([
            plaintext[4],
            plaintext[5],
            plaintext[6],
            plaintext[7],
        ]));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let difference = Duration::from_secs(now.abs_diff(sent));
        if difference > params.max_time_diff {
            return Err(reality_error(
                "REALITY client clock is too far from this server's",
            ));
        }
    }
    Ok(())
}

async fn complete_handshake<S>(
    mut io: S,
    hello: ClientHelloInfo,
    auth_key: [u8; 32],
    post_handshake: Option<Arc<[u16]>>,
    mldsa65_seed: Option<[u8; 32]>,
) -> Result<Tls13Stream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut server_seed);
    let server_seed = zeroize::Zeroizing::new(server_seed);
    let server_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*server_seed)).to_bytes();
    let (server_share, mut handshake_shared) = if let Some(hybrid) = hello.hybrid {
        // The hybrid group's ECDH uses the X25519 key carried *inside* that
        // share, not the standalone one the REALITY tag was checked against.
        let x25519_shared = x25519_dalek::x25519(*server_seed, hybrid.x25519);
        let key_bytes = hybrid
            .mlkem_key
            .as_slice()
            .try_into()
            .map_err(|_| reality_error("ML-KEM-768 public key has the wrong length"))?;
        let key = EncapsulationKey768::new(&key_bytes)
            .map_err(|_| reality_error("ML-KEM-768 public key is invalid"))?;
        let (ciphertext, mlkem_shared) = key.encapsulate();
        let ciphertext_bytes: &[u8] = ciphertext.as_ref();
        let mlkem_shared_bytes: &[u8] = mlkem_shared.as_ref();
        let mut share = Vec::with_capacity(ciphertext_bytes.len() + server_public.len());
        share.extend_from_slice(ciphertext_bytes);
        share.extend_from_slice(&server_public);
        let mut shared = Vec::with_capacity(mlkem_shared_bytes.len() + x25519_shared.len());
        shared.extend_from_slice(mlkem_shared_bytes);
        shared.extend_from_slice(&x25519_shared);
        (share, shared)
    } else {
        let x25519_shared = x25519_dalek::x25519(*server_seed, hello.auth_key_share);
        (server_public.to_vec(), x25519_shared.to_vec())
    };

    let group = if server_share.len() == 1088 + 32 {
        0x11ec
    } else {
        0x001d
    };
    let server_hello = build_server_hello(&hello.session_id, hello.suite, group, &server_share);
    write_clear_record(&mut io, &server_hello).await?;

    let mut transcript = Transcript::new(hello.suite.hash);
    transcript.update(&hello.message);
    transcript.update(&server_hello);
    let schedule =
        establish_handshake_secrets(hello.suite, &handshake_shared, &transcript.snapshot());
    handshake_shared.zeroize();

    let mut signing_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut signing_seed);
    let signing = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    let certificate = reality_certificate(
        &signing,
        &auth_key,
        &hello.sni,
        mldsa65_seed
            .as_ref()
            .map(|seed| (seed, hello.message.as_slice(), server_hello.as_slice())),
    );
    let encrypted_flight = build_encrypted_flight(
        hello.suite,
        &schedule.server_hs_traffic,
        &mut transcript,
        &certificate,
        &signing,
    )?;
    // The dummy CCS a real server sends after its ServerHello, in the same
    // write as the encrypted flight it precedes.
    let mut flight = Vec::with_capacity(DUMMY_CCS.len() + encrypted_flight.len());
    flight.extend_from_slice(&DUMMY_CCS);
    flight.extend_from_slice(&encrypted_flight);
    io.write_all(&flight)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    io.flush()
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;

    let client_finished =
        read_encrypted_handshake(&mut io, hello.suite, &schedule.client_hs_traffic).await?;
    let expected = finished_verify_data(
        hello.suite.hash,
        &schedule.client_hs_traffic,
        &transcript.snapshot(),
    );
    if !bool::from(client_finished.ct_eq(expected.as_slice())) {
        return Err(reality_error("client Finished verification failed"));
    }
    // Application traffic secrets are derived from the transcript through
    // the server Finished.  The client Finished is sent under the handshake
    // traffic secret but is not part of the transcript input to the
    // application traffic key schedule (RFC 8446 §7.1).
    let (client_app, server_app) = establish_application_secrets(&schedule, &transcript.snapshot());
    let mut stream = Tls13Stream::new(io, hello.suite, client_app, server_app);
    if let Some(wire_lens) = post_handshake {
        // Where the real site would be sending its session tickets.
        stream.queue_empty_records(&wire_lens)?;
        stream
            .flush()
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    }
    Ok(stream)
}

fn derive_auth_key(shared: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), shared);
    let mut key = [0u8; 32];
    hk.expand(b"REALITY", &mut key).expect("fixed HKDF output");
    key
}

fn decrypt_session_id(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8; 32],
    aad: &[u8],
) -> Result<[u8; 16], Failure> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("fixed AES key");
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| reality_error("REALITY session seal did not verify"))?;
    plain
        .try_into()
        .map_err(|_| reality_error("REALITY session plaintext has the wrong length"))
}

/// Constant-time check that `sealed` equals `configured` left-aligned and
/// zero-padded to eight bytes.
fn short_id_matches(sealed: &[u8], configured: &[u8]) -> Choice {
    if sealed.len() != 8 || configured.len() > 8 {
        // Lengths are public configuration, not secrets.
        return Choice::from(0);
    }
    let mut padded = [0u8; 8];
    padded[..configured.len()].copy_from_slice(configured);
    sealed.ct_eq(&padded)
}

fn zero_session_id(message: &[u8]) -> Result<Vec<u8>, Failure> {
    if message.len() < 71 || message[0] != 1 || message[38] != 32 {
        return Err(reality_error("malformed REALITY ClientHello session id"));
    }
    let mut zeroed = message.to_vec();
    zeroed[39..71].fill(0);
    Ok(zeroed)
}

/// Go's limit on one handshake message (crypto/tls `maxHandshake`).
const MAX_CLIENT_HELLO: usize = 65536;

enum ClientHelloRead {
    /// The complete ClientHello message and every record byte consumed.
    Complete { record: Vec<u8>, message: Vec<u8> },
    /// The peer is not speaking TLS; `consumed` must be replayed verbatim.
    NotTls { consumed: Vec<u8>, failure: Failure },
}

/// Read one ClientHello handshake message, reassembling it if the client
/// fragmented it across several records — which a client using TLS-hello
/// fragmentation against DPI does, and which Go's REALITY server accepts.
async fn read_client_hello_record<S>(io: &mut S) -> Result<ClientHelloRead, Failure>
where
    S: AsyncRead + Unpin,
{
    let mut record = Vec::new();
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 5];
        io.read_exact(&mut header)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        record.extend_from_slice(&header);
        let length = match parse_header(&header) {
            Ok((CONTENT_HANDSHAKE, length)) => length,
            Ok(_) => {
                return Ok(ClientHelloRead::NotTls {
                    consumed: record,
                    failure: reality_error("REALITY expected a cleartext ClientHello"),
                })
            }
            Err(failure) => {
                return Ok(ClientHelloRead::NotTls {
                    consumed: record,
                    failure,
                })
            }
        };
        // The record is cleartext, so its body is the plaintext, and Go reads
        // it before failing a body longer than one plaintext
        // (`len(data) > maxPlaintext`, `RL/conn.go:725-727`) — by which time
        // the record has already been mirrored to the target. REALITY's answer
        // to that error is the fallback, so the whole record is handed back
        // for replay here rather than refused at the header. The wider
        // `parse_header` bound covers what a pre-1.3 *ciphertext* may be; it
        // is not what a ClientHello record may be.
        let body_at = record.len();
        record.resize(body_at + length, 0);
        io.read_exact(&mut record[body_at..])
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        message.extend_from_slice(&record[body_at..]);
        if let Err(failure) = check_cleartext_body(length) {
            return Ok(ClientHelloRead::NotTls {
                consumed: record,
                failure,
            });
        }
        if length == 0 {
            // RFC 8446 §5.1 forbids empty handshake fragments.
            return Ok(ClientHelloRead::NotTls {
                consumed: record,
                failure: reality_error("empty handshake record"),
            });
        }
        if message.len() < 4 {
            continue;
        }
        let need = 4
            + (((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize);
        if need > MAX_CLIENT_HELLO {
            return Ok(ClientHelloRead::NotTls {
                consumed: record,
                failure: reality_error("ClientHello exceeds the handshake size limit"),
            });
        }
        if message.len() >= need {
            // Anything past `need` is caught by `parse_client_hello`'s
            // length-consistency check and falls back.
            return Ok(ClientHelloRead::Complete { record, message });
        }
    }
}

fn parse_client_hello(message: Vec<u8>) -> Result<ClientHelloInfo, Failure> {
    if message.len() < 4 || message[0] != 1 {
        return Err(reality_error("first handshake message is not ClientHello"));
    }
    let body_len =
        ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize;
    if body_len + 4 != message.len() {
        return Err(reality_error("ClientHello length is inconsistent"));
    }
    let mut at = 4 + 2;
    let random: [u8; 32] = message
        .get(at..at + 32)
        .ok_or_else(|| reality_error("ClientHello random is truncated"))?
        .try_into()
        .unwrap();
    at += 32;
    let sid_len = *message
        .get(at)
        .ok_or_else(|| reality_error("ClientHello session id is truncated"))?
        as usize;
    at += 1;
    if sid_len != 32 || at + sid_len > message.len() {
        return Err(reality_error("REALITY requires a 32-byte session id"));
    }
    let session_id = message[at..at + 32].try_into().unwrap();
    at += 32;
    let suites_len = u16::from_be_bytes(take2(&message, at, "cipher suites")?) as usize;
    at += 2;
    let suites_end = at + suites_len;
    if suites_end > message.len() || !suites_len.is_multiple_of(2) {
        return Err(reality_error("ClientHello cipher suites are truncated"));
    }
    let mut suite = None;
    let (pairs, remainder) = message[at..suites_end].as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        if let Some(candidate) = CipherSuite::by_id(u16::from_be_bytes([pair[0], pair[1]])) {
            suite.get_or_insert(candidate);
        }
    }
    let suite = suite.ok_or_else(|| reality_error("ClientHello has no supported TLS 1.3 suite"))?;
    at = suites_end;
    let compression_len = *message
        .get(at)
        .ok_or_else(|| reality_error("ClientHello compression is truncated"))?
        as usize;
    at += 1 + compression_len;
    let ext_len = u16::from_be_bytes(take2(&message, at, "extensions")?) as usize;
    at += 2;
    let end = at + ext_len;
    if end > message.len() {
        return Err(reality_error("ClientHello extensions are truncated"));
    }
    let mut sni = None;
    let mut standalone_x25519 = None;
    let mut hybrid = None;
    let mut tls13_offered = false;
    while at + 4 <= end {
        let typ = u16::from_be_bytes([message[at], message[at + 1]]);
        let len = u16::from_be_bytes([message[at + 2], message[at + 3]]) as usize;
        at += 4;
        let body = message
            .get(at..at + len)
            .ok_or_else(|| reality_error("ClientHello extension body is truncated"))?;
        at += len;
        if typ == 0 {
            sni = parse_sni(body);
        } else if typ == 43 {
            tls13_offered |= offers_tls13(body);
        } else if typ == 51 {
            let (x25519, parsed_hybrid) = parse_key_shares(body);
            // Every `key_share` extension is read, and the *first* acceptable
            // share of each group is the one that counts (Go appends the
            // shares of all of them and then breaks on the first match,
            // `RL/tls.go:214-228`). Letting a later extension displace an
            // earlier one would authenticate against a different point than
            // Go does — and only one of the two would accept the seal.
            standalone_x25519 = standalone_x25519.or(x25519);
            hybrid = hybrid.or(parsed_hybrid);
        }
    }
    // Go derives nothing until the hello has negotiated TLS 1.3: REALITY's own
    // gate is `hs.c.vers != VersionTLS13` (`RL/tls.go:211`), and that version
    // comes from `mutualVersion` over `supported_versions`
    // (`RL/handshake_server.go:180-196`). A hello offering a TLS 1.3 suite but
    // no `supported_versions: 0x0304` is not TLS 1.3 to Go and is answered by
    // the camouflage site, never by a wire error.
    if !tls13_offered {
        return Err(reality_error(
            "ClientHello does not offer TLS 1.3 in supported_versions",
        ));
    }
    // "Secondary choice: X25519 in X25519MLKEM768" (`RL/tls.go:221-228`): a
    // hello that offers only the hybrid still authenticates, against the key
    // inside it. Go's two loops run over every share it collected, so a
    // standalone share anywhere wins over any hybrid's half.
    let auth_key_share = standalone_x25519
        .or_else(|| hybrid.as_ref().map(|share| share.x25519))
        .ok_or_else(|| reality_error("ClientHello has no X25519 key share"))?;
    Ok(ClientHelloInfo {
        message,
        random,
        session_id,
        auth_key_share,
        hybrid,
        sni: sni.ok_or_else(|| reality_error("ClientHello has no SNI"))?,
        suite,
    })
}

/// Does this `supported_versions` body offer TLS 1.3?
///
/// RFC 8446 §4.2.1: in a ClientHello the body is a one-byte list length and
/// then that many two-byte versions. Anything malformed simply does not offer
/// it, which is Go's outcome too — no mutual version, no REALITY.
fn offers_tls13(body: &[u8]) -> bool {
    let Some(&list_len) = body.first() else {
        return false;
    };
    let list = &body[1..];
    let list_len = usize::from(list_len);
    if list.len() < list_len {
        return false;
    }
    let (versions, _) = list[..list_len].as_chunks::<2>();
    versions
        .iter()
        .any(|version| u16::from_be_bytes(*version) == 0x0304)
}

fn take2(buf: &[u8], at: usize, what: &'static str) -> Result<[u8; 2], Failure> {
    buf.get(at..at + 2)
        .ok_or_else(|| reality_error(format!("{what} are truncated")))
        .map(|v| [v[0], v[1]])
}

fn parse_sni(body: &[u8]) -> Option<String> {
    if body.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if list_len + 2 > body.len() || body[2] != 0 {
        return None;
    }
    let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
    std::str::from_utf8(body.get(5..5 + name_len)?)
        .ok()
        .map(str::to_string)
}

/// Split a `key_share` extension into the standalone X25519 share and the
/// hybrid share.
///
/// Both are returned because REALITY uses them for different things: the tag
/// is authenticated against the standalone share when there is one, while the
/// TLS handshake secret comes from whichever group the server selects.
///
/// A group offered twice keeps its **first** share, like Go: both of its
/// scans `break` on the first acceptable entry (`RL/tls.go:214-228`), so the
/// last duplicate is never looked at. RFC 8446 §4.2.8 forbids the duplicate,
/// so no honest client reaches the difference — a probe can, and the two
/// implementations would otherwise derive different auth keys from the same
/// hello and only one would accept.
fn parse_key_shares(body: &[u8]) -> (Option<[u8; 32]>, Option<HybridShare>) {
    if body.len() < 2 {
        return (None, None);
    }
    let total = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut at = 2;
    let mut x25519 = None;
    let mut hybrid = None;
    while at + 4 <= body.len() && at - 2 < total {
        let group = u16::from_be_bytes([body[at], body[at + 1]]);
        let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        at += 4;
        let share = match body.get(at..at + len) {
            Some(share) => share,
            None => break,
        };
        if group == 0x001d && len == 32 && x25519.is_none() {
            x25519 = share.try_into().ok();
        } else if group == 0x11ec && len == 1216 && hybrid.is_none() {
            if let Ok(tail) = share[1184..].try_into() {
                hybrid = Some(HybridShare {
                    mlkem_key: share[..1184].to_vec(),
                    x25519: tail,
                });
            }
        }
        at += len;
    }
    (x25519, hybrid)
}

fn build_server_hello(
    session_id: &[u8; 32],
    suite: CipherSuite,
    group: u16,
    key: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.id.to_be_bytes());
    body.push(0);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
    extensions.extend_from_slice(&[0, 51]);
    extensions.extend_from_slice(&((4 + key.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(key.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    handshake_message(2, &body)
}

async fn write_clear_record<S>(io: &mut S, message: &[u8]) -> Result<(), Failure>
where
    S: AsyncWrite + Unpin,
{
    let header = record_header(CONTENT_HANDSHAKE, message.len());
    io.write_all(&header)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    io.write_all(message)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    Ok(())
}

fn build_encrypted_flight(
    suite: CipherSuite,
    secret: &[u8],
    transcript: &mut Transcript,
    certificate: &[u8],
    signing: &SigningKey,
) -> Result<Vec<u8>, Failure> {
    // EncryptedExtensions is a vector, even when no extensions are selected.
    // The two-byte zero length is required by RFC 8446 §4.4.2 and by Go's
    // TLS parser; an empty handshake body is not a valid message.
    let ee = handshake_message(8, &[0, 0]);
    let cert = certificate_message(certificate);
    let mut out = Vec::new();
    let mut crypter = RecordCrypter::new(suite, secret);
    transcript.update(&ee);
    out.extend_from_slice(&crypter.seal(&ee, CONTENT_HANDSHAKE)?.bytes);
    transcript.update(&cert);
    out.extend_from_slice(&crypter.seal(&cert, CONTENT_HANDSHAKE)?.bytes);
    let signed = certificate_verify_input(transcript.snapshot());
    let signature = signing.sign(&signed);
    let mut cv_body = Vec::with_capacity(68);
    cv_body.extend_from_slice(&0x0807u16.to_be_bytes());
    cv_body.extend_from_slice(&64u16.to_be_bytes());
    cv_body.extend_from_slice(&signature.to_bytes());
    let cv = handshake_message(15, &cv_body);
    transcript.update(&cv);
    out.extend_from_slice(&crypter.seal(&cv, CONTENT_HANDSHAKE)?.bytes);
    let verify = finished_verify_data(suite.hash, secret, &transcript.snapshot());
    let finished = handshake_message(20, &verify);
    transcript.update(&finished);
    out.extend_from_slice(&crypter.seal(&finished, CONTENT_HANDSHAKE)?.bytes);
    Ok(out)
}

async fn read_encrypted_handshake<S>(
    io: &mut S,
    suite: CipherSuite,
    secret: &[u8],
) -> Result<Vec<u8>, Failure>
where
    S: AsyncRead + Unpin,
{
    let mut crypter = RecordCrypter::new(suite, secret);
    // One record buffer for the whole loop: the peer chooses the length in
    // the header, so allocating a fresh `vec![0u8; len]` per record hands it
    // an allocation of its own choosing on every iteration.
    let mut body: Vec<u8> = Vec::new();
    loop {
        let mut header = [0u8; 5];
        io.read_exact(&mut header)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        let (kind, len) = parse_header(&header)?;
        if kind != CONTENT_APPDATA {
            // A change_cipher_spec or alert here is cleartext, and Go fails a
            // cleartext record longer than a plaintext (`RL/conn.go:725-727`).
            // A protected record is bounded inside `open_in_place`.
            check_cleartext_body(len)?;
        }
        body.resize(len, 0);
        io.read_exact(&mut body)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        if kind == CONTENT_CCS {
            // RFC 8446 §5.1 middlebox compatibility: a client may send a
            // cleartext 0x14/0x03.03/0x0001 record between ServerHello and
            // its encrypted Finished. It carries no transcript bytes.
            continue;
        }
        if kind != CONTENT_APPDATA {
            return Err(reality_error("client Finished is not encrypted"));
        }
        let (inner_type, plaintext_len) = crypter.open_in_place(&header, &mut body)?;
        let plaintext = &body[..plaintext_len];
        if inner_type != CONTENT_HANDSHAKE || plaintext.len() < 4 || plaintext[0] != 20 {
            return Err(reality_error(format!(
                "client did not send Finished (inner={inner_type:#04x}, plaintext_len={}, first={:02x?})",
                plaintext.len(),
                &plaintext[..plaintext.len().min(8)]
            )));
        }
        let len = ((plaintext[1] as usize) << 16)
            | ((plaintext[2] as usize) << 8)
            | plaintext[3] as usize;
        if len + 4 != plaintext.len() {
            return Err(reality_error("client Finished length is invalid"));
        }
        return Ok(plaintext[4..].to_vec());
    }
}

/// The certificate REALITY presents. With `binding` (the ML-DSA-65 seed and
/// the two hello messages) it carries one extension: the signature, by the
/// ML-DSA key, of an HMAC over the certificate's key and both hellos, which
/// ties this handshake to this server for a client that knows the verify key.
fn reality_certificate(
    signing: &SigningKey,
    auth_key: &[u8; 32],
    hostname: &str,
    binding: Option<(&[u8; 32], &[u8], &[u8])>,
) -> Vec<u8> {
    let public = signing.verifying_key().to_bytes();
    let algorithm = der_sequence(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let spki = der_sequence(&[algorithm.as_slice(), &der_bit_string(&public)].concat());
    let version = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let serial = der_tlv(0x02, &[0x01]);
    let name = der_name(hostname);
    let signature_algorithm = algorithm.clone();
    let validity = der_sequence(
        &[
            der_tlv(0x17, b"250101000000Z"),
            der_tlv(0x17, b"500101000000Z"),
        ]
        .concat(),
    );
    // Keep all mandatory RFC 5280 fields present. REALITY replaces ordinary
    // certificate-chain verification with the HMAC below, but Xray's Go
    // parser still requires a structurally valid certificate.
    let extensions = binding.map_or_else(Vec::new, |(seed, client_hello, server_hello)| {
        use ml_dsa::{MlDsa65, Signer, SigningKey as MlDsaKey};
        let mut signed = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("fixed HMAC key");
        signed.update(&public);
        signed.update(client_hello);
        signed.update(server_hello);
        let key = MlDsaKey::<MlDsa65>::from_seed(&(*seed).into());
        let signature = key.sign(signed.finalize().into_bytes().as_slice());
        let extension = der_sequence(
            &[
                &[0x06, 0x01, 0x2b][..],
                der_tlv(0x04, signature.encode().as_slice()).as_slice(),
            ]
            .concat(),
        );
        der_tlv(0xa3, &der_sequence(&extension))
    });
    let tbs = der_sequence(
        &[
            version.as_slice(),
            serial.as_slice(),
            signature_algorithm.as_slice(),
            name.as_slice(),
            validity.as_slice(),
            name.as_slice(),
            spki.as_slice(),
            extensions.as_slice(),
        ]
        .concat(),
    );
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("fixed HMAC key");
    mac.update(&public);
    let signature = mac.finalize().into_bytes();
    let signature = der_bit_string(&signature);
    der_sequence(&[tbs.as_slice(), algorithm.as_slice(), signature.as_slice()].concat())
}

fn der_name(hostname: &str) -> Vec<u8> {
    let common_name = der_sequence(
        &[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            der_tlv(0x0c, hostname.as_bytes()).as_slice(),
        ]
        .concat(),
    );
    let set = der_tlv(0x31, &common_name);
    der_sequence(&set)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn certificate_message(certificate: &[u8]) -> Vec<u8> {
    let mut body = vec![0];
    let mut list = Vec::with_capacity(3 + certificate.len() + 2);
    put_u24(&mut list, certificate.len());
    list.extend_from_slice(certificate);
    list.extend_from_slice(&[0, 0]);
    put_u24_at(&mut body, list.len());
    body.extend_from_slice(&list);
    handshake_message(11, &body)
}

fn certificate_verify_input(transcript_hash: Vec<u8>) -> Vec<u8> {
    let mut signed = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed.extend_from_slice(&[0x20; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0);
    signed.extend_from_slice(&transcript_hash);
    signed
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    put_u24(&mut message, body.len());
    message.extend_from_slice(body);
    message
}

fn put_u24(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
}

fn put_u24_at(out: &mut Vec<u8>, value: usize) {
    put_u24(out, value);
}

fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend_from_slice(&der_len(data.len() + 1));
    out.push(0);
    out.extend_from_slice(data);
    out
}

fn der_len(length: usize) -> Vec<u8> {
    if length < 128 {
        vec![length as u8]
    } else {
        let bytes = (length as u32).to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
        let body = &bytes[first..];
        let mut out = vec![0x80 | body.len() as u8];
        out.extend_from_slice(body);
        out
    }
}

fn reality_error(detail: impl Into<String>) -> Failure {
    Failure::new(FailureKind::RealityFallback, Stage::TlsStarted)
        .with_confidence(Confidence::Confirmed)
        .with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zero_security::tls13::record::MAX_CIPHERTEXT_BEFORE_TLS13;
    use zero_security::tls13::{HelloParams, PendingHello};

    #[tokio::test]
    async fn reality_server_round_trips_application_data() {
        let private_key = [7u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key))
                .to_bytes();
        let server_params = RealityServerParams {
            private_key,
            server_names: vec![Box::from("example.test")].into_boxed_slice(),
            short_ids: vec![vec![0xaa, 0xbb, 0xcc, 0xdd].into_boxed_slice()].into_boxed_slice(),
            mldsa65_seed: None,
            max_time_diff: Duration::ZERO,
            min_client_ver: None,
            max_client_ver: None,
            post_handshake: Default::default(),
        };
        let client_params = zero_security::RealityParams::from_config(
            std::sync::Arc::from("example.test"),
            public_key,
            &[0xaa, 0xbb, 0xcc, 0xdd],
        )
        .with_hybrid_kem(true);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = handshake(server_io, &server_params).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut client = zero_security::reality_connect(client_io, &client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    /// The ML-DSA-65 verify key for `seed`, as a client is configured with it.
    fn mldsa65_verify_key(seed: [u8; 32]) -> Box<[u8]> {
        use ml_dsa::{Keypair, MlDsa65, SigningKey as MlDsaKey};
        MlDsaKey::<MlDsa65>::from_seed(&seed.into())
            .verifying_key()
            .encode()
            .as_slice()
            .into()
    }

    /// Run one handshake between a server holding `server_seed` and a client
    /// holding `verify`; true when the client got through and exchanged data.
    async fn handshake_with_mldsa65(
        server_seed: Option<[u8; 32]>,
        verify: Option<Box<[u8]>>,
    ) -> bool {
        let (mut server_params, _) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        server_params.mldsa65_seed = server_seed;
        let client_params = zero_security::RealityParams::from_config_with_fingerprint_and_mldsa(
            std::sync::Arc::from("example.test"),
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([7u8; 32])).to_bytes(),
            &[0xaa, 0xbb, 0xcc, 0xdd],
            zero_security::FingerprintProfile::Chrome,
            verify,
        )
        .with_hybrid_kem(false);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let Ok(mut stream) = handshake(server_io, &server_params).await else {
                return;
            };
            let mut request = [0u8; 4];
            if stream.read_exact(&mut request).await.is_ok() {
                let _ = stream.write_all(b"pong").await;
                let _ = stream.flush().await;
            }
        });
        let outcome = async {
            let mut client = zero_security::reality_connect(client_io, &client_params)
                .await
                .ok()?;
            client.write_all(b"ping").await.ok()?;
            client.flush().await.ok()?;
            let mut response = [0u8; 4];
            client.read_exact(&mut response).await.ok()?;
            (&response == b"pong").then_some(())
        }
        .await
        .is_some();
        let _ = server.await;
        outcome
    }

    #[tokio::test]
    async fn a_client_with_the_verify_key_accepts_the_server_that_holds_the_seed() {
        let seed = [9u8; 32];
        assert!(handshake_with_mldsa65(Some(seed), Some(mldsa65_verify_key(seed))).await);
        // Neither side uses it: the handshake is what it always was.
        assert!(handshake_with_mldsa65(None, None).await);
        // A server that signs is fine with a client that does not check.
        assert!(handshake_with_mldsa65(Some(seed), None).await);
    }

    #[tokio::test]
    async fn a_client_that_wants_the_signature_refuses_a_server_without_it_or_with_another() {
        let seed = [9u8; 32];
        let verify = mldsa65_verify_key(seed);
        assert!(!handshake_with_mldsa65(None, Some(verify.clone())).await);
        assert!(!handshake_with_mldsa65(Some([10u8; 32]), Some(verify)).await);
    }

    fn reality_pair(client_short_id: &[u8]) -> (RealityServerParams, zero_security::RealityParams) {
        let private_key = [7u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key))
                .to_bytes();
        let server_params = RealityServerParams {
            mldsa65_seed: None,
            max_time_diff: Duration::ZERO,
            min_client_ver: None,
            max_client_ver: None,
            private_key,
            server_names: vec![Box::from("example.test")].into_boxed_slice(),
            short_ids: vec![
                vec![0x01].into_boxed_slice(),
                vec![0xaa, 0xbb, 0xcc, 0xdd].into_boxed_slice(),
            ]
            .into_boxed_slice(),
            post_handshake: Default::default(),
        };
        let client_params = zero_security::RealityParams::from_config(
            std::sync::Arc::from("example.test"),
            public_key,
            client_short_id,
        );
        (server_params, client_params)
    }

    /// The record types of everything one side wrote, in order.
    fn record_types(mut wire: &[u8]) -> Vec<u8> {
        let mut types = Vec::new();
        while wire.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            types.push(wire[0]);
            wire = &wire[(5 + len).min(wire.len())..];
        }
        types
    }

    /// Copy `from` to `to`, keeping a record of every byte that passed.
    async fn tap(
        mut from: impl AsyncRead + Unpin,
        mut to: impl AsyncWrite + Unpin,
        record: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    ) {
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = from.read(&mut chunk).await {
            record.lock().unwrap().extend_from_slice(&chunk[..n]);
            if to.write_all(&chunk[..n]).await.is_err() {
                break;
            }
        }
    }

    /// A real server follows its ServerHello with a dummy ChangeCipherSpec and
    /// a browser sends one before its Finished; both ends here do the same, or
    /// the wire would carry a pattern no real peer produces.
    #[tokio::test]
    async fn both_ends_send_the_dummy_change_cipher_spec_a_real_peer_sends() {
        use std::sync::{Arc, Mutex};
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        // client <-> tap <-> server, recording what each side wrote.
        let (client_io, tap_client) = tokio::io::duplex(64 * 1024);
        let (tap_server, server_io) = tokio::io::duplex(64 * 1024);
        let from_client = Arc::new(Mutex::new(Vec::new()));
        let from_server = Arc::new(Mutex::new(Vec::new()));
        let (cr, cw) = tokio::io::split(tap_client);
        let (sr, sw) = tokio::io::split(tap_server);
        tokio::spawn(tap(cr, sw, Arc::clone(&from_client)));
        tokio::spawn(tap(sr, cw, Arc::clone(&from_server)));
        let server = tokio::spawn(async move { handshake(server_io, &server_params).await });
        let mut client = zero_security::reality_connect(client_io, &client_params)
            .await
            .unwrap();
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        let _ = server.await;
        let to_server = record_types(&from_client.lock().unwrap());
        let to_client = record_types(&from_server.lock().unwrap());
        // ClientHello, dummy CCS, encrypted Finished (then application data).
        assert_eq!(
            &to_server[..3],
            &[CONTENT_HANDSHAKE, CONTENT_CCS, CONTENT_APPDATA]
        );
        // ServerHello, dummy CCS, then the encrypted flight.
        assert_eq!(
            &to_client[..3],
            &[CONTENT_HANDSHAKE, CONTENT_CCS, CONTENT_APPDATA]
        );
    }

    /// A client fragmenting its ClientHello into several TLS records (the
    /// `tlshello` fragment strategy) must still authenticate: Go's REALITY
    /// server reassembles the handshake message, and so must this one.
    #[tokio::test]
    async fn fragmented_client_hello_is_reassembled_and_accepted() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = match handshake_or_fallback(server_io, &server_params).await {
                HandshakeOutcome::Accepted(stream) => stream,
                HandshakeOutcome::Fallback { failure, .. }
                | HandshakeOutcome::Rejected(failure) => {
                    panic!("fragmented hello was not accepted: {failure}")
                }
            };
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
        });
        let fragmented = zero_evasion::FragmentStream::new(
            client_io,
            zero_evasion::FragmentPolicy {
                interval_min_ms: 0,
                interval_max_ms: 0,
                ..Default::default()
            },
        );
        let mut client = zero_security::reality_connect(fragmented, &client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap();
    }

    /// With a site's record sizes on file, the first things the server sends
    /// after the handshake are empty records of exactly those sizes, and the
    /// session behind them is undisturbed.
    #[tokio::test]
    async fn the_sites_post_handshake_records_are_replayed_by_size() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        server_params.post_handshake.set("example.test", &[255, 69]);
        // A different name's sizes are not this name's.
        server_params.post_handshake.set("other.test", &[1000]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = handshake(server_io, &server_params).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
        });
        let (tapped, sizes) = zero_security::tls13::post_handshake::tap(client_io);
        let mut client = zero_security::reality_connect(tapped, &client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        server.await.unwrap();
        // The two replayed records, then the 4-byte reply in a record of its
        // own: header, payload, type byte, tag.
        assert_eq!(*sizes.lock().unwrap(), [255, 69, 5 + 4 + 1 + 16]);
    }

    #[tokio::test]
    async fn unknown_short_id_falls_back() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let _ = zero_security::reality_connect(client_io, &client_params).await;
        });
        match handshake_or_fallback(server_io, &server_params).await {
            HandshakeOutcome::Fallback { failure, .. } => {
                assert!(failure.to_string().contains("shortId"), "{failure}")
            }
            HandshakeOutcome::Accepted(_) => panic!("a prefix of a short id must not authorise"),
            HandshakeOutcome::Rejected(error) => panic!("expected fallback: {error}"),
        }
        client.abort();
    }

    #[test]
    fn short_id_matching_is_exact_and_zero_padded() {
        let sealed = [0xaa, 0xbb, 0, 0, 0, 0, 0, 0];
        assert!(bool::from(short_id_matches(&sealed, &[0xaa, 0xbb])));
        assert!(bool::from(short_id_matches(&sealed, &[0xaa, 0xbb, 0])));
        assert!(!bool::from(short_id_matches(&sealed, &[0xaa])));
        assert!(!bool::from(short_id_matches(&sealed, &[0xaa, 0xbc])));
        assert!(!bool::from(short_id_matches(&sealed, &[0; 9])));
        assert!(bool::from(short_id_matches(&[0; 8], &[])));
    }

    /// Non-TLS first bytes are REALITY's "forward to target" case, not a
    /// drop: the consumed bytes come back for replay.
    #[tokio::test]
    async fn non_tls_first_record_falls_back_with_the_consumed_bytes() {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let (params, _) = reality_pair(&[0xaa]);
        match handshake_or_fallback(server, &params).await {
            HandshakeOutcome::Fallback { client_hello, .. } => assert_eq!(client_hello, b"GET /"),
            HandshakeOutcome::Accepted(_) => panic!("HTTP must not authenticate"),
            HandshakeOutcome::Rejected(error) => panic!("expected fallback: {error}"),
        }
    }

    #[tokio::test]
    async fn fallback_preserves_the_exact_client_hello_record() {
        let hello = PendingHello::new(&HelloParams::new("ordinary.example"));
        let mut record = record_header(CONTENT_HANDSHAKE, hello.msg.len()).to_vec();
        record[2] = 0x01;
        record.extend_from_slice(&hello.msg);
        let expected = record.clone();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        client.write_all(&record).await.unwrap();
        client.flush().await.unwrap();

        let params = RealityServerParams {
            mldsa65_seed: None,
            max_time_diff: Duration::ZERO,
            min_client_ver: None,
            max_client_ver: None,
            private_key: [7u8; 32],
            server_names: vec![Box::from("reality.example")].into_boxed_slice(),
            short_ids: vec![vec![1, 2, 3, 4].into_boxed_slice()].into_boxed_slice(),
            post_handshake: Default::default(),
        };
        match handshake_or_fallback(server, &params).await {
            HandshakeOutcome::Fallback { client_hello, .. } => assert_eq!(client_hello, expected),
            HandshakeOutcome::Accepted(_) => panic!("ordinary hello must not authenticate"),
            HandshakeOutcome::Rejected(error) => panic!("hello should be replayable: {error}"),
        }
    }

    /// A ClientHello a test builds byte by byte and seals the way a REALITY
    /// client seals one: ECDH against the server's static key, HKDF-SHA256
    /// with the first 20 bytes of `random` as the salt, and AES-256-GCM over
    /// the 16-byte version/clock/shortId block with the hello's session id
    /// zeroed as the AAD.
    ///
    /// Every gate in the accept path ends the same way — the connection is
    /// relayed to the camouflage site — so a test that only observes "it did
    /// not get through" cannot tell one gate from a malformed hello. Building
    /// the hello here, with a genuine seal, is what makes the gates themselves
    /// observable.
    struct CraftedHello {
        sni: Option<String>,
        /// Versions offered in `supported_versions`; `None` omits the
        /// extension, as a pre-TLS-1.3 client would.
        versions: Option<Vec<u16>>,
        /// One `key_share` extension per entry, each a list of (group, share).
        key_shares: Vec<Vec<(u16, Vec<u8>)>>,
        suites: Vec<u16>,
        /// The X25519 secret the seal is derived from. A share only
        /// authenticates the hello if it is this key's public half.
        secret: [u8; 32],
        version: [u8; 3],
        time: u32,
        short_id: [u8; 8],
    }

    fn unix_now() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as u32)
    }

    fn x25519_public(secret: [u8; 32]) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes()
    }

    impl CraftedHello {
        /// A hello the server accepts as it stands: the configured name, TLS
        /// 1.3 offered, one X25519 share, a fresh clock and the configured
        /// shortId. Tests change one thing at a time from here.
        fn new() -> Self {
            let secret = [3u8; 32];
            Self {
                sni: Some("example.test".into()),
                versions: Some(vec![0x0304]),
                key_shares: vec![vec![(0x001d, x25519_public(secret).to_vec())]],
                suites: vec![0x1301],
                secret,
                version: [1, 0, 0],
                time: unix_now(),
                short_id: [0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0],
            }
        }

        /// One `x25519` share per secret, in the order given, all in a single
        /// `key_share` extension — a hello no honest client sends, because
        /// RFC 8446 §4.2.8 forbids offering a group twice.
        fn with_shares(mut self, secrets: &[[u8; 32]]) -> Self {
            self.secret = secrets[0];
            let shares: Vec<(u16, Vec<u8>)> = secrets
                .iter()
                .map(|secret| (0x001d, x25519_public(*secret).to_vec()))
                .collect();
            self.key_shares = vec![shares];
            self
        }

        fn extensions(&self) -> Vec<(u16, Vec<u8>)> {
            let mut extensions = Vec::new();
            if let Some(sni) = &self.sni {
                let mut body = Vec::new();
                body.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
                body.push(0);
                body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
                body.extend_from_slice(sni.as_bytes());
                extensions.push((0, body));
            }
            if let Some(versions) = &self.versions {
                let mut body = vec![(versions.len() * 2) as u8];
                for version in versions {
                    body.extend_from_slice(&version.to_be_bytes());
                }
                extensions.push((43, body));
            }
            for shares in &self.key_shares {
                let total: usize = shares.iter().map(|(_, share)| 4 + share.len()).sum();
                let mut body = (total as u16).to_be_bytes().to_vec();
                for (group, share) in shares {
                    body.extend_from_slice(&group.to_be_bytes());
                    body.extend_from_slice(&(share.len() as u16).to_be_bytes());
                    body.extend_from_slice(share);
                }
                extensions.push((51, body));
            }
            extensions
        }

        fn message(&self) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[0x11; 32]);
            body.push(32);
            body.extend_from_slice(&[0u8; 32]); // the seal goes here
            body.extend_from_slice(&((self.suites.len() * 2) as u16).to_be_bytes());
            for suite in &self.suites {
                body.extend_from_slice(&suite.to_be_bytes());
            }
            body.extend_from_slice(&[1, 0]); // one compression method: null
            let mut extensions = Vec::new();
            for (typ, extension) in self.extensions() {
                extensions.extend_from_slice(&typ.to_be_bytes());
                extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&extension);
            }
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
            handshake_message(1, &body)
        }

        /// The sealed ClientHello message.
        fn sealed(&self, server_public: [u8; 32]) -> Vec<u8> {
            let mut message = self.message();
            let random: [u8; 32] = message[6..38].try_into().unwrap();
            let shared = x25519_dalek::x25519(self.secret, server_public);
            let auth_key = derive_auth_key(&shared, &random[..20]);
            let aad = zero_session_id(&message).unwrap();
            let mut plaintext = [0u8; 16];
            plaintext[..3].copy_from_slice(&self.version);
            plaintext[4..8].copy_from_slice(&self.time.to_be_bytes());
            plaintext[8..].copy_from_slice(&self.short_id);
            let cipher = Aes256Gcm::new_from_slice(&auth_key).unwrap();
            let sealed = cipher
                .encrypt(
                    Nonce::from_slice(&random[20..]),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .unwrap();
            message[39..71].copy_from_slice(&sealed);
            message
        }

        /// The sealed message as the one handshake record the intake reads.
        fn record(&self, server_public: [u8; 32]) -> Vec<u8> {
            let message = self.sealed(server_public);
            let mut record = record_header(CONTENT_HANDSHAKE, message.len()).to_vec();
            record.extend_from_slice(&message);
            record
        }
    }

    /// What the server did with one crafted hello.
    #[derive(Debug, PartialEq, Eq)]
    enum Intake {
        /// The hello was left for the fallback target, refused by the gate
        /// named here.
        Fallback(String),
        /// The seal opened and no gate refused it: the server answered with a
        /// ServerHello of its own instead of relaying the connection.
        Accepted,
    }

    /// The parameters these tests use, and the public key a client configured
    /// for them holds.
    fn crafted_params() -> (RealityServerParams, [u8; 32]) {
        let (params, _) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let public = x25519_public(params.private_key);
        (params, public)
    }

    /// Feed one hello to the accept path and report which way it went.
    ///
    /// No timeout is needed to tell the outcomes apart: a refused hello
    /// returns the fallback outcome and writes nothing, while an accepted one
    /// makes the server write its ServerHello before it waits for the client's
    /// Finished.
    async fn intake(params: &RealityServerParams, record: Vec<u8>) -> Intake {
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let params = params.clone();
        let mut server =
            tokio::spawn(async move { handshake_or_fallback(server_io, &params).await });
        client.write_all(&record).await.unwrap();
        client.flush().await.unwrap();
        let mut header = [0u8; 5];
        tokio::select! {
            outcome = &mut server => match outcome.unwrap() {
                HandshakeOutcome::Fallback { failure, .. } => Intake::Fallback(failure.to_string()),
                HandshakeOutcome::Rejected(failure) => {
                    panic!("the hello was rejected rather than relayed: {failure}")
                }
                HandshakeOutcome::Accepted(_) => panic!("a relayed hello has no handshake"),
            },
            read = client.read_exact(&mut header) => {
                read.expect("the server closed instead of answering");
                assert_eq!(
                    header[0], CONTENT_HANDSHAKE,
                    "an accepted hello is answered with a ServerHello record",
                );
                server.abort();
                Intake::Accepted
            }
        }
    }

    /// Go's SNI gate is a plain map lookup of the name as it arrived
    /// (`RL/tls.go:211`), so case matters. The port folded it, and a server
    /// that accepts a spelling it does not advertise is a fingerprint: a
    /// prober that gets a REALITY ServerHello for `Example.test` against a
    /// configured `example.test` has found the server, and the accepted set is
    /// exactly what such a probe enumerates.
    #[tokio::test]
    async fn a_server_name_in_another_case_is_not_the_advertised_one() {
        let (params, public) = crafted_params();
        // The positive control: the exact name authenticates.
        assert_eq!(
            intake(&params, CraftedHello::new().record(public)).await,
            Intake::Accepted
        );

        let mut hello = CraftedHello::new();
        hello.sni = Some("Example.test".into());
        match intake(&params, hello.record(public)).await {
            Intake::Fallback(reason) => assert!(reason.contains("SNI"), "{reason}"),
            Intake::Accepted => panic!("the server name is matched exactly, as Go matches it"),
        }
    }

    /// Go settles the version before it derives anything: `mutualVersion` over
    /// `supported_versions` (`RL/handshake_server.go:180-196`) feeds the
    /// `hs.c.vers != VersionTLS13` gate (`RL/tls.go:211`). The port inferred
    /// TLS 1.3 from a TLS 1.3 cipher suite being in the list, so a hello
    /// offering `0x1301` with no `supported_versions` at all — or with one
    /// that never names `0x0304` — authenticated here and was handed to the
    /// camouflage site by Go.
    #[tokio::test]
    async fn a_hello_without_supported_versions_is_not_tls13_enough() {
        let (params, public) = crafted_params();

        let mut hello = CraftedHello::new();
        hello.versions = None;
        match intake(&params, hello.record(public)).await {
            Intake::Fallback(reason) => {
                assert!(reason.contains("supported_versions"), "{reason}")
            }
            Intake::Accepted => panic!("TLS 1.3 has to be offered, not assumed"),
        }

        // An extension that offers only older versions is the same refusal.
        let mut hello = CraftedHello::new();
        hello.versions = Some(vec![0x0303, 0x0302]);
        assert!(matches!(
            intake(&params, hello.record(public)).await,
            Intake::Fallback(_)
        ));

        // Offering 1.3 among older versions is still TLS 1.3: Go's
        // `mutualVersion` picks the highest version both ends have.
        let mut hello = CraftedHello::new();
        hello.versions = Some(vec![0x0303, 0x0304]);
        assert_eq!(
            intake(&params, hello.record(public)).await,
            Intake::Accepted
        );
    }

    /// Go keeps the **first** share of a group: both of its scans `break` on
    /// the first acceptable entry (`RL/tls.go:214-228`). The port kept the
    /// last, so a hello carrying two X25519 shares was authenticated against a
    /// different point than Go uses, and a client that seals against its first
    /// share was accepted by Go and refused here.
    #[tokio::test]
    async fn the_first_share_of_a_duplicated_group_is_the_one_that_counts() {
        let (params, public) = crafted_params();
        let (first, second) = ([4u8; 32], [5u8; 32]);

        // Sealed against the first share: what Go uses, so this authenticates.
        let hello = CraftedHello::new().with_shares(&[first, second]);
        assert_eq!(
            intake(&params, hello.record(public)).await,
            Intake::Accepted
        );

        // Sealed against the second: Go never looks at it, so the seal cannot
        // open — and the "last wins" port accepted exactly this hello.
        let mut hello = CraftedHello::new().with_shares(&[first, second]);
        hello.secret = second;
        assert!(matches!(
            intake(&params, hello.record(public)).await,
            Intake::Fallback(_)
        ));
    }

    /// The gates are asked in Go's order (`RL/tls.go:257-262`): the seal, then
    /// `MinClientVer` / `MaxClientVer`, then `MaxTimeDiff`, then the shortId.
    /// Each one fails into the same silent fallback, so a probe that fails
    /// several learns the order from *which* refusal comes back. The port
    /// asked the selector first and named it, telling a prober about a hello
    /// the version gate had already rejected.
    #[tokio::test]
    async fn a_hello_that_fails_several_gates_is_refused_for_go_s_first_one() {
        let (mut params, public) = crafted_params();
        params.min_client_ver = Some([1, 0, 0]);
        params.max_client_ver = Some([3, 0, 0]);
        params.max_time_diff = Duration::from_secs(60);

        // Too old a client, a stale clock and an unknown selector at once.
        let mut hello = CraftedHello::new();
        hello.version = [0, 9, 0];
        hello.time = unix_now() - 3600;
        hello.short_id = [0x99; 8];
        match intake(&params, hello.record(public)).await {
            Intake::Fallback(reason) => assert!(reason.contains("version"), "{reason}"),
            Intake::Accepted => panic!("three failing gates cannot be accepted"),
        }

        // A version inside the range leaves the clock, not the selector.
        let mut hello = CraftedHello::new();
        hello.time = unix_now() - 3600;
        hello.short_id = [0x99; 8];
        match intake(&params, hello.record(public)).await {
            Intake::Fallback(reason) => assert!(reason.contains("clock"), "{reason}"),
            Intake::Accepted => panic!("a stale clock and a wrong selector cannot be accepted"),
        }

        // Only the selector is wrong.
        let mut hello = CraftedHello::new();
        hello.short_id = [0x99; 8];
        match intake(&params, hello.record(public)).await {
            Intake::Fallback(reason) => assert!(reason.contains("shortId"), "{reason}"),
            Intake::Accepted => panic!("an unknown selector cannot be accepted"),
        }

        // The control: everything inside the limits authenticates.
        assert_eq!(
            intake(&params, CraftedHello::new().record(public)).await,
            Intake::Accepted
        );
    }

    /// Go reads the first record of a connection under its *pre-negotiation*
    /// bound, `maxCiphertext = 16384 + 2048` (`RL/conn.go:707-711`), and only
    /// then fails a **cleartext** body longer than one plaintext (`:725-727`)
    /// — by which time the record is already on its way to the target. The
    /// substrate refused anything over 16640 at the header, turning a peer at
    /// Go's limit away before its bytes were handed back for replay.
    #[tokio::test]
    async fn a_record_at_go_s_pre_negotiation_bound_is_read_then_relayed() {
        let (params, _) = crafted_params();
        let mut record =
            record_header(CONTENT_HANDSHAKE, MAX_CIPHERTEXT_BEFORE_TLS13).to_vec();
        record.resize(5 + MAX_CIPHERTEXT_BEFORE_TLS13, 0);

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(&record).await.unwrap();
        client.flush().await.unwrap();
        match handshake_or_fallback(server, &params).await {
            HandshakeOutcome::Fallback {
                client_hello,
                failure,
                ..
            } => {
                assert_eq!(
                    client_hello.len(),
                    record.len(),
                    "every consumed byte is replayed to the target"
                );
                assert!(failure.to_string().contains("cleartext"), "{failure}");
            }
            HandshakeOutcome::Accepted(_) => {
                panic!("a cleartext record past the plaintext bound cannot authenticate")
            }
            HandshakeOutcome::Rejected(error) => panic!("expected fallback: {error}"),
        }
    }
}
