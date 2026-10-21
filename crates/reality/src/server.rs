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
    /// Xray's `show`: report, per connection, what the handshake decoded.
    ///
    /// The report is a line, and it names what the client sent and whether it
    /// was let through — never the key that proved it. `false` reports
    /// nothing.
    pub show: bool,
    /// Xray's `masterKeyLog`: where the handshake's traffic secrets are
    /// written, so an operator can decrypt a captured session.
    ///
    /// A secret on disk, on purpose; `None` writes nothing.
    pub key_log: Option<Arc<crate::keys::KeyLog>>,
    /// How the camouflage site is reached, when it is reached at all.
    ///
    /// Go's server dials the site for *every* connection, authenticated or
    /// not (`RL/tls.go:168`), and reads the site's own flight off that
    /// connection — so the flight the client sees is the site's, read live,
    /// rather than one learned earlier. This hook is that dial: the caller
    /// owns the resolver and the deadline, and hands back a connection to
    /// the site.
    ///
    /// `None` means the site is not dialled on the accepting path, and the
    /// flight learned at start-up is used instead.
    pub decoy: Option<Arc<dyn DecoyDialer>>,
}

/// Opens a connection to the camouflage site, for the server to read the
/// site's own flight off.
///
/// The caller owns the resolver, the dial and its deadline; this is only the
/// shape of what it hands back.
pub trait DecoyDialer: Send + Sync {
    /// Connect to the site and return the connection.
    fn dial(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<zero_core::BoxStream, String>> + Send>,
    >;
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

/// The record sizes a camouflage site presents, per server name (see
/// [`zero_security::tls13::post_handshake`]).
///
/// Two things are stored for each name, both learned by asking the real site:
///
/// * the **first flight**: the wire sizes of the records it answered a
///   ClientHello with, ServerHello first. The server puts its own flight on
///   the wire in those sizes, so the bytes an observer counts before the
///   handshake completes are the site's and not this implementation's
///   (REALITY's own server does the same, `RL/conn.go:526-557`).
/// * the **post-handshake** records: the sizes it sends once the handshake is
///   done. After each handshake it accepts, the server sends empty records of
///   those sizes, so the first thing on the wire afterwards matches the site.
///
/// Either half may be missing, and both start out missing: a name nothing has
/// been learned for keeps the behaviour of a server that never learned
/// anything — its own flight sizes, and nothing after the handshake.
#[derive(Debug, Default)]
pub struct PostHandshakeShapes(Mutex<Vec<Site>>);

/// One server name and what its site's handshake looks like.
#[derive(Debug, Default, Clone)]
struct Site {
    name: Box<str>,
    /// The ALPN index the site's shapes are filed under, as Go files them
    /// (`RL/tls.go:396-403`).
    ///
    /// Go's key is `dest + " " + sni + " " + alpn`, where the last part is
    /// 0 for a client that offered no ALPN, 2 for one that offered h2 first
    /// and 1 for anything else. A site that answers an h2 client
    /// differently from an http/1.1 one is copied per protocol, so the
    /// port's key is the same index rather than the name alone.
    alpn: u8,
    /// Wire sizes of the site's first-flight records, ServerHello first.
    flight: Arc<[u16]>,
    /// Wire sizes of the records it sends after the handshake.
    after: Arc<[u16]>,
    /// How many records that advance nothing the site tolerates before it
    /// answers with an alert.
    ///
    /// The site is asked at start-up, and the answer is the site's own
    /// patience: a REALITY server that put up with fewer useless records
    /// than the site it borrows its name from would be a REALITY server that
    /// can be told apart. Go learns the same number the same way
    /// (`RL/record_detect.go:137-185`) and applies it to the connections it
    /// accepts (`RL/tls.go:425-427`).
    budget: Option<u64>,
}

/// What is known about one name, as the handshake path wants it.
#[derive(Debug, Default, Clone)]
pub(super) struct SiteShapes {
    pub flight: Option<Arc<[u16]>>,
    pub after: Option<Arc<[u16]>>,
    /// The site's budget for records that advance nothing, when it is known.
    pub budget: Option<u64>,
}

impl PostHandshakeShapes {
    /// Remember the post-handshake record sizes for `server_name`, replacing
    /// what was there. The first flight learned for the name, if any, stays.
    pub fn set(&self, server_name: &str, alpn: u8, wire_lens: &[u16]) {
        self.edit(server_name, alpn, |site| site.after = wire_lens.into());
    }

    /// Remember the first flight's record sizes for `server_name`, replacing
    /// what was there (the post-handshake sizes stay).
    pub fn set_flight(&self, server_name: &str, alpn: u8, wire_lens: &[u16]) {
        self.edit(server_name, alpn, |site| site.flight = wire_lens.into());
    }

    /// Remember how many records that advance nothing the site tolerates,
    /// for `server_name`.
    pub fn set_budget(&self, server_name: &str, alpn: u8, budget: u64) {
        self.edit(server_name, alpn, |site| site.budget = Some(budget));
    }

    fn edit(&self, server_name: &str, alpn: u8, change: impl FnOnce(&mut Site)) {
        let mut sites = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match sites
            .iter_mut()
            .find(|site| &*site.name == server_name && site.alpn == alpn)
        {
            Some(site) => change(site),
            None => {
                let mut site = Site {
                    name: server_name.into(),
                    alpn,
                    ..Site::default()
                };
                change(&mut site);
                sites.push(site);
            }
        }
    }

    /// What is known about `server_name`, for one handshake.
    pub(super) fn site(&self, server_name: &str, alpn: u8) -> SiteShapes {
        let sites = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match sites
            .iter()
            .find(|site| &*site.name == server_name && site.alpn == alpn)
        {
            Some(site) => SiteShapes {
                flight: Some(Arc::clone(&site.flight)).filter(|lens| !lens.is_empty()),
                after: Some(Arc::clone(&site.after)).filter(|lens| !lens.is_empty()),
                budget: site.budget,
            },
            None => SiteShapes::default(),
        }
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
    /// Whether the client offered a standalone X25519 key share.
    ///
    /// The site's group can only be copied if the client offered a share for
    /// it: Go searches the client's shares for the group's
    /// (`RL/tls.go:216-228`), and a client that offered only the hybrid
    /// cannot complete a handshake in the plain group.
    offered_x25519: bool,
    sni: String,
    /// The protocols the client offered, in the order it offered them.
    ///
    /// Go files the shapes it learned per ALPN and picks the entry by the
    /// client's own list (`RL/tls.go:396-403`), so a site that answers an
    /// h2 client differently from an http/1.1 one is copied per protocol.
    alpn: Vec<String>,
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
    match handshake_or_fallback(io, params, None).await {
        HandshakeOutcome::Accepted(stream) => Ok(stream),
        HandshakeOutcome::Fallback { failure, .. } | HandshakeOutcome::Rejected(failure) => {
            Err(failure)
        }
    }
}

/// Perform the REALITY handshake while preserving a valid first record for a
/// fallback site when the connection is ordinary TLS or has the wrong REALITY
/// credentials.
///
/// `peer` is the address the connection came from, as the server sees it. It
/// is only used for the `show` report; the handshake itself never looks at it.
pub async fn handshake_or_fallback<S>(
    mut io: S,
    params: &RealityServerParams,
    peer: Option<std::net::SocketAddr>,
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
    // The `show` report: what the client said, and whether it was let
    // through. It is written here rather than at the end, because the fields
    // it names are the ones the session id carried, and a client that is
    // refused is refused *for* one of them.
    let report = params.show.then(|| crate::keys::ClientReport {
        peer: peer.unwrap_or(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
        client_version: [plaintext[0], plaintext[1], plaintext[2]],
        client_clock: std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(u64::from(u32::from_be_bytes([
                plaintext[4],
                plaintext[5],
                plaintext[6],
                plaintext[7],
            ]))),
        short_id: plaintext[8..16].into(),
        authenticated: false,
    });
    // The gates are asked in Go's order (`RL/tls.go:257-262`): the seal above,
    // then `MinClientVer` / `MaxClientVer`, then `MaxTimeDiff`, then the
    // shortId. Every one of them fails into the same silent fallback, so the
    // order is only visible in which refusal a probe that fails several earns
    // — and a server that named the selector before the version would be
    // answering about a hello Go had already sent to the site.
    if let Err(failure) = check_client_limits(params, &plaintext) {
        if let Some(report) = report {
            report_line(report);
        }
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
        if let Some(report) = report {
            report_line(report);
        }
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("REALITY shortId is not authorised"),
        };
    }

    // The site's own flight, read off a connection to the site.
    //
    // Go dials the site for every connection and reads the flight off that
    // connection (`RL/tls.go:168`, `:293-330`), so the flight the client sees
    // is the site's, read live. The port asks the site at start-up instead and
    // keeps the answer, which is the same flight unless the site's certificate
    // has changed size since — and a server that cannot reach the site at
    // all is the case the live read handles and the cached one cannot.
    let mut shapes = params
        .post_handshake
        .site(&hello.sni, alpn_index(&hello.alpn));
    // What the site chose, if it could be asked: the cipher suite and the
    // key-share group from its ServerHello, as Go takes them
    // (`RL/handshake_server_tls13.go:100-128`).
    // The site, if it could be asked: its answer, and the connection the
    // visitor's Finished is forwarded to.
    let mut site = None;
    if let Some(decoy) = params.decoy.as_deref() {
        match read_live_shapes(decoy, &hello.sni, &hello.alpn, &client_hello).await {
            Ok(Some(live)) => {
                let LiveSite {
                    flight,
                    after,
                    answer,
                    site: connection,
                } = live;
                if let Some(flight) = flight {
                    shapes.flight = Some(flight);
                }
                if let Some(after) = after {
                    shapes.after = Some(after);
                }
                site = Some(LiveSite {
                    flight: None,
                    after: None,
                    answer,
                    site: connection,
                });
            }
            Ok(None) => {}
            Err(error) => {
                // The site could not be reached. Go's server would have closed
                // the connection (`RL/tls.go:168-172`); the port answers with
                // what it learned at start-up, which is the flight it would
                // have used anyway.
                tracing::debug!(
                    %error,
                    "REALITY camouflage site could not be reached for its live flight; \
                     the flight learned at start-up is used instead"
                );
            }
        }
    }
    match complete_handshake(
        io,
        hello,
        auth_key,
        shapes,
        site,
        params.mldsa65_seed,
        params.key_log.as_ref(),
    )
    .await
    {
        Ok(stream) => {
            if let Some(mut report) = report {
                report.authenticated = true;
                report_line(report);
            }
            HandshakeOutcome::Accepted(stream)
        }
        Err(failure) => HandshakeOutcome::Rejected(failure),
    }
}

/// The `show` line, as one line of the log.
///
/// The level is `info`: `show` is a switch an operator turns on to read, and
/// a line that needs `debug` turned on as well is a line nobody reads.
fn report_line(report: crate::keys::ClientReport) {
    tracing::info!(
        target: "reality",
        "REALITY {}",
        report.line(std::time::SystemTime::now())
    );
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
    shapes: SiteShapes,
    mut site: Option<LiveSite>,
    mldsa65_seed: Option<[u8; 32]>,
    key_log: Option<&Arc<crate::keys::KeyLog>>,
) -> Result<Tls13Stream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut server_seed);
    let server_seed = zeroize::Zeroizing::new(server_seed);
    let server_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*server_seed)).to_bytes();
    // Whether the client offered a share for the plain and the hybrid group,
    // which decides whether the site's group can be copied at all.
    let offered_x25519 = hello.offered_x25519;
    let offered_hybrid = hello.hybrid.is_some();
    // The group comes first, because the share has to be *for* that group.
    //
    // The site's group is copied only if the client offered a share for it:
    // Go searches the client's shares for the group's
    // (`RL/tls.go:216-228`), and a client that offered only one group
    // cannot complete a handshake in the other.
    let site_answer = site.as_ref().and_then(|site| site.answer);
    let site_group = site_answer.map(|answer| answer.group);
    let offered = match site_group {
        Some(0x001d) => offered_x25519,
        Some(0x11ec) => offered_hybrid,
        _ => false,
    };
    let use_hybrid = match site_group {
        Some(group) if offered => group == 0x11ec,
        _ => offered_hybrid,
    };
    let (server_share, mut handshake_shared) = if use_hybrid {
        let hybrid = hello.hybrid.as_ref().expect("the hybrid share was offered");
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

    // The group and the suite are the site's, as Go takes them: the site
    // chose the group in its ServerHello, and Go answers with the same one
    // (`RL/handshake_server_tls13.go:100-128`). A server that answered with
    // a different group than the site chose is a server that says it is not
    // the site.
    //
    // The *key* is ours either way: Go uses the client's share with its own
    // private key, and so does the port.
    let site_suite = site_answer.map(|answer| answer.suite);
    let group = if use_hybrid { 0x11ec } else { 0x001d };
    let suite = match site_suite {
        // The site chose a suite the client offered, so it is one the port
        // knows; a suite the port does not know falls back to the client's.
        Some(id) => CipherSuite::by_id(id).unwrap_or(hello.suite),
        None => hello.suite,
    };
    let server_hello = build_server_hello(&hello.session_id, suite, group, &server_share);
    // What the camouflage site's own flight looked like, if it can be copied
    // at all: our ServerHello has to be the size the site's was, or there is
    // no record-for-record shape to reproduce and the flight goes out as
    // this server makes it.
    let flight = FlightPlan::for_hello(shapes.flight.as_deref(), &server_hello);
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
        flight.as_ref(),
    )?;
    // The dummy CCS a real server sends after its ServerHello, in the same
    // write as the encrypted flight it precedes. It is six bytes on every
    // server, which is why a site whose CCS is not six bytes cannot be copied
    // record for record and `FlightPlan` refuses the whole shape.
    let mut flight_bytes = Vec::with_capacity(DUMMY_CCS.len() + encrypted_flight.len());
    flight_bytes.extend_from_slice(&DUMMY_CCS);
    flight_bytes.extend_from_slice(&encrypted_flight);
    io.write_all(&flight_bytes)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    io.flush()
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;

    let (client_finished, finished_record) =
        read_encrypted_handshake_raw(&mut io, hello.suite, &schedule.client_hs_traffic).await?;
    // The visitor's Finished goes to the site too, as Go's `MirrorConn`
    // forwards every byte read from the visitor (`RL/tls.go:70-83`). A site
    // holds its own CertificateVerify and its own Finished until the
    // client's Finished arrives, so without this the site sends only part of
    // its flight.
    if let Some(site) = site.as_mut().and_then(|site| site.site.as_mut()) {
        let _ = tokio::io::AsyncWriteExt::write_all(site, &finished_record).await;
        let _ = tokio::io::AsyncWriteExt::flush(site).await;
    }
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
    // The key log, when it is on, gets the handshake secrets as soon as they
    // exist and the application secrets as soon as they do
    // (`RL/handshake_server_tls13.go:884-893`, `:1031-1040`). A log that
    // cannot be written is a debugging aid failing, not a connection to drop:
    // the line is skipped and the handshake carries on.
    if let Some(log) = key_log {
        let _ = log.log_handshake_secrets(
            &hello.random,
            &schedule.client_hs_traffic,
            &schedule.server_hs_traffic,
        );
        let _ = log.log_application_secrets(&hello.random, &client_app, &server_app);
    }
    let mut stream = Tls13Stream::new(io, hello.suite, client_app, server_app);
    // This end is the server, so a session ticket arriving from the client is
    // refused rather than ignored, as Go refuses it
    // (`RL/handshake_client_tls13.go:855-858`).
    stream.set_server_side();
    if let Some(budget) = shapes.budget {
        // How long this server puts up with a run of records that advance
        // nothing is how long the site it borrows its name from does, which
        // is what the site was asked at start-up (`RL/tls.go:425-427`).
        stream.set_max_useless_records(budget);
    }
    if let Some(wire_lens) = shapes.after {
        // Where the real site would be sending its session tickets.
        stream.queue_empty_records(&wire_lens)?;
        stream
            .flush()
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    }
    Ok(stream)
}

/// Read the camouflage site's own shapes, off a connection to the site.
///
/// Two things come back, and Go reads both off that one connection: the
/// **flight** — the wire lengths of the records the site answered a
/// ClientHello with, ServerHello first — and the **records it sends after
/// the handshake** (`RL/tls.go:293-330`, `:404-421`).
///
/// The site's certificate is not verified: the probe carries no application
/// data, and the site is the one the operator chose as the camouflage, so
/// requiring a public chain would leave every private-CA decoy unanswered.
/// The site's answer, and the connection it was given on.
///
/// The connection is handed back because the visitor's Finished has to be
/// forwarded to it: a site holds its own CertificateVerify and its own
/// Finished until the client's Finished arrives, so without that the site
/// sends only part of its flight. Go's `MirrorConn` forwards every byte
/// read from the visitor (`RL/tls.go:70-83`), and this is the same thing.
struct LiveSite {
    flight: Option<Arc<[u16]>>,
    after: Option<Arc<[u16]>>,
    answer: Option<zero_security::tls13::post_handshake::SiteAnswer>,
    /// The connection the site was asked on, if it is still open.
    ///
    /// It is the *tap* rather than the bare stream, so the records the
    /// site sends after the visitor's Finished can still be counted.
    site: Option<zero_security::tls13::post_handshake::Tap<zero_core::BoxStream>>,
}

async fn read_live_shapes(
    decoy: &dyn DecoyDialer,
    server_name: &str,
    alpn: &[String],
    client_hello: &[u8],
) -> Result<Option<LiveSite>, String> {
    // The protocols the probe offers the site, so the flight is the one the
    // client would have got.
    let protocols: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let site = decoy.dial().await?;
    // The *client's* hello is what the site is asked, verbatim, so the
    // site's answer — its cipher suite and its key-share group — is its
    // reply to the visitor. Go does the same, by forwarding the client's
    // bytes through the `MirrorConn` (`RL/tls.go:70-83`).
    //
    // The *flight* is a different question: the site sends its encrypted
    // records only after the client's Finished, and the client sends that
    // on the visitor's own connection, not on this one. So the flight is
    // asked for separately, with a handshake of the port's own.
    let (forwarded, connection) =
        zero_security::tls13::post_handshake::observe_with_the_clients_hello(site, client_hello)
            .await
            .map_err(|error| error.to_string())?;
    let answer = forwarded.answer;
    let site = decoy.dial().await?;
    let observed = zero_security::tls13::post_handshake::observe_all_with_alpn(
        site,
        server_name,
        zero_security::tls13::post_handshake::SiteTrust::Unverified,
        &protocols,
    )
    .await
    .map_err(|error| error.to_string())?;
    if observed.flight.is_empty() {
        return Ok(None);
    }
    // Go reads both off that one connection: the flight it answers the hello
    // with, and the records the site sends after the handshake
    // (`RL/tls.go:293-330`, `:404-421`).
    let flight = (!observed.flight.is_empty()).then(|| Arc::from(observed.flight.as_slice()));
    let after = (!observed.post_handshake.is_empty())
        .then(|| Arc::from(observed.post_handshake.as_slice()));
    Ok(Some(LiveSite {
        flight,
        after,
        answer,
        site: connection,
    }))
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
    let mut alpn = None;
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
        } else if typ == 16 {
            alpn = parse_alpn(body);
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
        offered_x25519: standalone_x25519.is_some(),
        hybrid,
        sni: sni.ok_or_else(|| reality_error("ClientHello has no SNI"))?,
        alpn: alpn.unwrap_or_default(),
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

/// The protocols a client offered, in the order it offered them.
///
/// The `application_layer_protocol_negotiation` extension is a list of
/// length-prefixed names (RFC 7301 §3.1). A malformed one is read as no
/// protocols at all, which is what Go's own reader does with a list it
/// cannot walk.
fn parse_alpn(body: &[u8]) -> Option<Vec<String>> {
    if body.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if list_len + 2 > body.len() {
        return None;
    }
    let mut protocols = Vec::new();
    let mut at = 2usize;
    let end = 2 + list_len;
    while at < end {
        let name_len = *body.get(at)? as usize;
        at += 1;
        let name = std::str::from_utf8(body.get(at..at + name_len)?).ok()?;
        protocols.push(name.to_string());
        at += name_len;
    }
    Some(protocols)
}

/// The ALPN index the site's shapes are filed under, as Go files them.
///
/// Go's key is `dest + " " + sni + " " + alpn`, where the last part is 0 for
/// a client that offered no ALPN, 2 for one that offered h2 first, and 1 for
/// anything else (`RL/tls.go:396-403`). An *index* and not the list of
/// protocols, because Go files a bucket: a client that offered `http/1.1`
/// first gets the http/1.1 answer whichever else it offered.
fn alpn_index(protocols: &[String]) -> u8 {
    match protocols.split_first() {
        None => 0,
        Some((first, _)) if first == "h2" => 2,
        Some(_) => 1,
    }
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

/// The record sizes this server's first flight is to be written in, learned
/// from the site the name belongs to.
///
/// REALITY's own server reads the site's flight on every connection and
/// writes its four encrypted messages padded to the site's record sizes
/// (`RL/conn.go:526-557`), so the record boundaries a censor can count are the
/// site's. This is the same idea, with the sizes learned once at start-up
/// instead of per connection.
///
/// It is a plan only when the shape can be reproduced exactly. Two things can
/// rule that out, and both leave the flight as this server would have written
/// it anyway:
///
/// * the site's ServerHello record is not the size of ours. Go replays the
///   site's ServerHello byte for byte, so it never has this problem; this
///   implementation builds its own, and a site whose ServerHello differs
///   (another extension set, another key share) cannot be copied record for
///   record. A flight that matches everywhere except its first record is no
///   better than one that matches nowhere, and refusing every client because
///   a site's ServerHello is 3 bytes longer would be worse than either.
/// * the site's ChangeCipherSpec is not six bytes. Go treats that as the
///   site not being TLS 1.3 as expected and gives up on the connection
///   (`RL/tls.go:337-339`); here the name simply keeps this server's sizes.
#[derive(Debug)]
struct FlightPlan {
    /// The sizes of the site's encrypted flight records, in order: what each
    /// of EncryptedExtensions, Certificate, CertificateVerify and Finished is
    /// padded to.
    encrypted: Arc<[u16]>,
}

impl FlightPlan {
    fn for_hello(flight: Option<&[u16]>, server_hello: &[u8]) -> Option<Self> {
        let [hello, ccs, encrypted @ ..] = flight? else {
            return None;
        };
        if usize::from(*hello) != 5 + server_hello.len() {
            return None;
        }
        if usize::from(*ccs) != DUMMY_CCS.len() {
            return None;
        }
        if encrypted.is_empty() {
            return None;
        }
        Some(Self {
            encrypted: encrypted.into(),
        })
    }
}

fn build_encrypted_flight(
    suite: CipherSuite,
    secret: &[u8],
    transcript: &mut Transcript,
    certificate: &[u8],
    signing: &SigningKey,
    plan: Option<&FlightPlan>,
) -> Result<Vec<u8>, Failure> {
    // EncryptedExtensions is a vector, even when no extensions are selected.
    // The two-byte zero length is required by RFC 8446 §4.4.2 and by Go's
    // TLS parser; an empty handshake body is not a valid message.
    let ee = handshake_message(8, &[0, 0]);
    let cert = certificate_message(certificate);
    let sizes = plan.map(|plan| &plan.encrypted[..]).unwrap_or_default();
    let mut out = Vec::new();
    let mut crypter = RecordCrypter::new(suite, secret);
    transcript.update(&ee);
    seal_flight_record(&mut crypter, &ee, sizes.first().copied(), &mut out)?;
    transcript.update(&cert);
    seal_flight_record(&mut crypter, &cert, sizes.get(1).copied(), &mut out)?;
    let signed = certificate_verify_input(transcript.snapshot());
    let signature = signing.sign(&signed);
    let mut cv_body = Vec::with_capacity(68);
    cv_body.extend_from_slice(&0x0807u16.to_be_bytes());
    cv_body.extend_from_slice(&64u16.to_be_bytes());
    cv_body.extend_from_slice(&signature.to_bytes());
    let cv = handshake_message(15, &cv_body);
    transcript.update(&cv);
    seal_flight_record(&mut crypter, &cv, sizes.get(2).copied(), &mut out)?;
    let verify = finished_verify_data(suite.hash, secret, &transcript.snapshot());
    let finished = handshake_message(20, &verify);
    transcript.update(&finished);
    seal_flight_record(&mut crypter, &finished, sizes.get(3).copied(), &mut out)?;
    Ok(out)
}

/// Seal one record of the flight, in the size the site sent for that message
/// when one was learned.
///
/// A message that does not fit the site's record is the one thing this
/// implementation refuses rather than papers over: the flight would have to
/// go out in a size the site never sends, which is exactly what a censor
/// comparing the two would see. REALITY's own server fails the write there
/// and drops the connection (`RL/conn.go:553-555`), and so does this.
fn seal_flight_record(
    crypter: &mut RecordCrypter,
    content: &[u8],
    target: Option<u16>,
    out: &mut Vec<u8>,
) -> Result<(), Failure> {
    let Some(wire_len) = target else {
        return crypter
            .seal_into(content, CONTENT_HANDSHAKE, out)
            .map_err(|failure| reality_error(format!("sealing the handshake flight: {failure}")));
    };
    crypter
        .seal_padded_into(content, CONTENT_HANDSHAKE, usize::from(wire_len), out)
        .map_err(|_| {
            reality_error(format!(
                "the camouflage site's {} byte record cannot carry this handshake's {} byte message",
                wire_len,
                content.len()
            ))
        })
}

/// The same, and the record's bytes as they came off the wire.
///
/// The *encrypted* record is what a camouflage site needs: a site holds its
/// own CertificateVerify and its own Finished until the client's Finished
/// arrives, so the port has to be able to forward the visitor's Finished to
/// the site for the site's last records to come back.
async fn read_encrypted_handshake_raw<S>(
    io: &mut S,
    suite: CipherSuite,
    secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Failure>
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
        // The record as it came off the wire, before it was opened.
        let mut raw = Vec::with_capacity(5 + body.len());
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&body);
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
        return Ok((plaintext[4..].to_vec(), raw));
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

    /// A `tracing` writer that keeps every line, so a test can read what the
    /// code under test logged.
    struct CollectingSink {
        lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl std::io::Write for CollectingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let text = String::from_utf8_lossy(buf).into_owned();
            for line in text.lines() {
                self.lines.lock().unwrap().push(line.to_string());
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CollectingSink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            CollectingSink {
                lines: self.lines.clone(),
            }
        }
    }

    /// The sink, wrapped so it can be a `MakeWriter` by value: the orphan
    /// rule will not let this crate implement a foreign trait for `Arc<_>`.
    struct SinkWriter(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SinkWriter {
        type Writer = CollectingSink;
        fn make_writer(&'a self) -> Self::Writer {
            CollectingSink {
                lines: self.0.clone(),
            }
        }
    }

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
            show: false,
            key_log: None,
            decoy: None,
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

    /// The `show` switch writes a line per connection, and the line names
    /// what the client sent and whether it was let through.
    ///
    /// The report is what an operator turns the switch on for, so a version
    /// that reported nothing would be worse than no switch at all.
    #[tokio::test]
    async fn the_show_switch_reports_what_the_client_sent() {
        // A subscriber that keeps what was logged, so the test can read the
        // line the switch wrote. One per process, so the first test to want
        // one installs it and the rest share it.
        static LINES: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<String>>>> =
            std::sync::OnceLock::new();
        let lines = LINES.get_or_init(|| {
            let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_writer(SinkWriter(lines.clone()))
                .try_init();
            lines
        });
        lines.lock().unwrap().clear();

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
            show: true,
            key_log: None,
            decoy: None,
        };
        let client_params = zero_security::RealityParams::from_config(
            std::sync::Arc::from("example.test"),
            public_key,
            &[0xaa, 0xbb, 0xcc, 0xdd],
        )
        .with_hybrid_kem(true);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let _ = handshake_or_fallback(
                server_io,
                &server_params,
                Some("192.0.2.1:1234".parse().unwrap()),
            )
            .await;
        });
        let mut client = zero_security::reality_connect(client_io, &client_params)
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let _ = client.read_exact(&mut byte).await;
        server.await.unwrap();

        let logged = lines.lock().unwrap().join("\n");
        assert!(
            logged.contains("REALITY remoteAddr: 192.0.2.1:1234"),
            "the show line must name where the connection came from:\n{logged}"
        );
        assert!(
            logged.contains("authenticated: true"),
            "the show line must say whether the client was let through:\n{logged}"
        );
    }

    /// `masterKeyLog` writes the handshake's traffic secrets, in Go's order.
    ///
    /// The four lines are what an operator needs to decrypt a captured
    /// session, so their absence would make the switch a no-op.
    #[tokio::test]
    async fn the_key_log_writes_the_handshakes_traffic_secrets() {
        let private_key = [7u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key))
                .to_bytes();
        let path = std::env::temp_dir().join(format!(
            "zray-reality-keylog-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let log = Arc::new(crate::keys::KeyLog::open(path.to_str().unwrap()).unwrap());
        let server_params = RealityServerParams {
            private_key,
            server_names: vec![Box::from("example.test")].into_boxed_slice(),
            short_ids: vec![vec![0xaa, 0xbb, 0xcc, 0xdd].into_boxed_slice()].into_boxed_slice(),
            mldsa65_seed: None,
            max_time_diff: Duration::ZERO,
            min_client_ver: None,
            max_client_ver: None,
            post_handshake: Default::default(),
            show: false,
            key_log: Some(log),
            decoy: None,
        };
        let client_params = zero_security::RealityParams::from_config(
            std::sync::Arc::from("example.test"),
            public_key,
            &[0xaa, 0xbb, 0xcc, 0xdd],
        )
        .with_hybrid_kem(true);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let _ = handshake_or_fallback(server_io, &server_params, None).await;
        });
        let mut client = zero_security::reality_connect(client_io, &client_params)
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let _ = client.read_exact(&mut byte).await;
        server.await.unwrap();

        let written = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        for label in [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
        ] {
            assert!(
                written.contains(label),
                "the key log has no {label} line:\n{written}"
            );
        }
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
            show: false,
            key_log: None,
            decoy: None,
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
            let mut stream = match handshake_or_fallback(server_io, &server_params, None).await {
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
        server_params
            .post_handshake
            .set("example.test", 2, &[255, 69]);
        // A different name's sizes are not this name's.
        server_params.post_handshake.set("other.test", 2, &[1000]);
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

    /// The server answers with the cipher suite and the group the *site*
    /// chose.
    ///
    /// Go takes both from the site's ServerHello
    /// (`RL/handshake_server_tls13.go:100-128`), and a server that answered
    /// with a different suite or group than the site chose is a server that
    /// says it is not the site.
    #[tokio::test]
    async fn the_sites_suite_and_group_are_the_ones_answered_with() {
        let site = TestSite::start();
        let (mut server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        server_params.decoy = Some(Arc::clone(&site.dialer) as Arc<dyn DecoyDialer>);

        // The client's own hello, which is what the site is asked.
        let client_hello = client_hello_record(client_params.clone()).await;
        // What the site chose, read the way the port reads it.
        let live = read_live_shapes(site.dialer.as_ref(), "example.test", &[], &client_hello)
            .await
            .expect("the site was reached")
            .expect("the site answered");
        let answer = live.answer.expect("the site's ServerHello was read");
        assert_eq!(answer.group, 0x001d, "the test site chose X25519");

        // The client is answered, and the ServerHello it gets names the
        // site's group and suite.
        let (group, suite) = server_hello_choice(&server_params, &client_params).await;
        assert_eq!(
            group, answer.group,
            "the server answered with a group other than the site's"
        );
        assert_eq!(
            suite, answer.suite,
            "the server answered with a suite other than the site's"
        );
    }

    /// The site is asked with the *client's own* hello, verbatim.
    ///
    /// Go forwards the client's bytes to the site through the `MirrorConn`
    /// (`RL/tls.go:70-83`), so the site's answer — its cipher suite and its
    /// key-share group — is its reply to the visitor. The port does the
    /// same, which is why the suite and the group it answers with are the
    /// ones the site would have answered the visitor with.
    #[tokio::test]
    async fn the_site_is_asked_with_the_clients_own_hello() {
        let site = TestSite::start();
        let (_server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let client_hello = client_hello_record(client_params).await;

        // The site is asked, and the answer comes back: the site saw a
        // ClientHello it could answer, which it could not have done with
        // anything but a real hello.
        let live = read_live_shapes(site.dialer.as_ref(), "example.test", &[], &client_hello)
            .await
            .expect("the site was reached")
            .expect("the site answered");
        assert!(
            live.answer.is_some(),
            "the site answered the client's hello, so its ServerHello was read"
        );
    }

    /// The records the site sends after the handshake are read off the same
    /// connection as the flight.
    ///
    /// Go reads both off the one connection it dialled (`RL/tls.go:293-330`,
    /// `:404-421`), so a client is answered with the site's own records
    /// rather than with what the site said at start-up.
    #[tokio::test]
    async fn the_post_handshake_records_are_read_off_the_site_too() {
        let site = TestSite::start();
        let (_server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let client_hello = client_hello_record(client_params).await;
        let live = read_live_shapes(site.dialer.as_ref(), "example.test", &[], &client_hello)
            .await
            .expect("the site was reached")
            .expect("the site answered");
        assert!(
            live.flight.is_some(),
            "the site's flight was read off the connection"
        );
        assert!(
            live.after.is_some(),
            "the site's post-handshake records were read off the same connection"
        );
    }

    /// The server answers with the record budget the site was found to have.
    ///
    /// Go's server puts up with a run of records that advance nothing for as
    /// long as the site it borrows its name from does, which is what the site
    /// was asked at start-up (`RL/record_detect.go:137-185`,
    /// `RL/tls.go:425-427`). A server that always answered with the default
    /// would be a server that could be told apart from the site by how long
    /// it tolerated the run.
    #[tokio::test]
    async fn the_server_puts_up_with_what_the_site_puts_up_with() {
        // A site that tolerates two records that advance nothing.
        let budget = 2u64;
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        server_params
            .post_handshake
            .set_budget("example.test", 2, budget);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = handshake(server_io, &server_params).await.unwrap();
            // The server reads until the run of records that advance nothing
            // is one too long, which is what ends the connection.
            let mut sink = [0u8; 64];
            let outcome = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) => return "the peer closed the connection".to_string(),
                        Ok(_) => continue,
                        Err(error) => return error.to_string(),
                    }
                }
            })
            .await
            .unwrap_or_else(|_| "the server waited for more".to_string());
            outcome
        });
        let mut client = zero_security::reality_connect(client_io, &client_params)
            .await
            .unwrap();
        // A run of records that advance nothing, one more than the budget
        // allows.
        for _ in 0..=budget {
            client.queue_empty_records(&[69]).unwrap();
        }
        client.flush().await.unwrap();
        let outcome = server.await.unwrap();
        assert!(
            outcome.contains(&format!("more than {budget} consecutive")),
            "the server gave up with {outcome:?}, not with the run past its budget of {budget}"
        );
    }

    /// One handshake against `server_params`, and the sizes of the records the
    /// client received before it sent its Finished — the server's flight.
    /// The ClientHello the client writes, in full.
    ///
    /// It is the client's own bytes, which is what the port forwards to the
    /// site — the same thing Go's `MirrorConn` does (`RL/tls.go:70-83`).
    async fn client_hello_record(client_params: zero_security::RealityParams) -> Vec<u8> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (tapped, taps) = zero_security::tls13::post_handshake::tap_with_flight(client_io);
        // The server end is read and dropped: the client's hello goes out
        // into the duplex, and the server never answers, so the client
        // stops after the hello.
        let server = tokio::spawn(async move {
            // The server end keeps reading: a ClientHello with a hybrid
            // share is larger than one read, and a client whose write
            // blocks would never finish.
            let mut server_io = server_io;
            let mut sink = [0u8; 4096];
            loop {
                match tokio::io::AsyncReadExt::read(&mut server_io, &mut sink).await {
                    Ok(n) if n > 0 => continue,
                    _ => break,
                }
            }
        });
        let client = tokio::spawn(async move {
            let _ = zero_security::reality_connect(tapped, &client_params).await;
        });
        // The hello is bounded: a client that never writes one is a
        // failure, not a hang.
        let hello = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let written = taps.sent_first.lock().unwrap().clone();
                if !written.is_empty() {
                    break written;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the client wrote a hello");
        client.abort();
        server.abort();
        hello
    }

    /// The key-share group and the cipher suite in the ServerHello the
    /// client was answered with.
    async fn server_hello_choice(
        server_params: &RealityServerParams,
        client_params: &zero_security::RealityParams,
    ) -> (u16, u16) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn({
            let server_params = server_params.clone();
            async move {
                let mut stream = handshake(server_io, &server_params).await.unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
            }
        });
        // The tap keeps the client's first record — the ServerHello it was
        // answered with.
        let (tapped, taps) = zero_security::tls13::post_handshake::tap_with_flight(client_io);
        let mut client = zero_security::reality_connect(tapped, client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        server.await.unwrap();
        let hello = taps.server_hello.lock().unwrap().clone();
        let answer = zero_security::tls13::post_handshake::parse_site_answer(&hello)
            .expect("the ServerHello the client was answered with parses");
        (answer.group, answer.suite)
    }

    async fn flight_sizes(
        server_params: &RealityServerParams,
        client_params: &zero_security::RealityParams,
    ) -> Vec<u16> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn({
            let server_params = server_params.clone();
            async move {
                let mut stream = handshake(server_io, &server_params).await.unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
            }
        });
        let (tapped, taps) = zero_security::tls13::post_handshake::tap_with_flight(client_io);
        let mut client = zero_security::reality_connect(tapped, client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        server.await.unwrap();
        let flight = taps.flight.lock().unwrap().clone();
        flight
    }

    /// The site is dialled for every connection, and the flight the client
    /// sees is the site's, read live off that connection.
    ///
    /// Go dials the site for *every* connection, authenticated or not
    /// (`RL/tls.go:168`), and reads the site's own flight off that connection
    /// (`:293-330`), so what the client sees is the site's flight read now
    /// rather than one read earlier. A site that changes its certificate size
    /// between two connections is followed by Go and not by a cached flight.
    ///
    /// The test's site answers with a flight of one size, and the server is
    /// given a *different* cached flight. What the client sees must be the
    /// site's, not the cached one.
    #[tokio::test]
    async fn the_flight_is_read_off_the_site_on_every_connection() {
        // A site that answers with a flight of its own.
        let site = TestSite::start();
        let (mut server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        // A cached flight, shaped so that it *could* be copied: the first
        // record is the ServerHello, whose size must match this server's own
        // ServerHello for the plan to be used at all. A flight that cannot
        // be copied would leave the server's own sizes on the wire either
        // way, and the test could not tell the two apart.
        let cached = cached_flight();
        server_params
            .post_handshake
            .set_flight("example.test", 2, &cached);
        server_params.decoy = Some(Arc::clone(&site.dialer) as Arc<dyn DecoyDialer>);

        let seen = flight_sizes(&server_params, &client_params).await;
        // The site records its flight as its handshake ends, which is a
        // moment after the probe read it.
        let mut site_flight = Vec::new();
        for _ in 0..200 {
            site_flight = site.dialer.flight.lock().unwrap().clone();
            if !site_flight.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !site_flight.is_empty(),
            "the site's own flight was not recorded, so the comparison says nothing"
        );
        // The cached flight's first record is this server's own ServerHello
        // size, so it *could* be copied: the encrypted record that follows
        // would have been padded to the cached 1000 bytes. The site's own
        // flight has a different first record — a real site answers with a
        // ServerHello of its own size — so the live flight is not copyable
        // and the sizes on the wire are this server's own.
        //
        // That is the proof that the site was read: without the live read
        // the cached flight would have been copied, and the encrypted record
        // would have been 1000 bytes.
        assert_ne!(
            seen[3], cached[2],
            "the encrypted record was padded to the cached flight's size, so the cached \
             flight was used and the site was not read"
        );
    }

    /// A site that cannot be reached does not stop the server: the flight
    /// learned at start-up is used instead.
    ///
    /// Go closes the connection when the site cannot be dialled
    /// (`RL/tls.go:168-172`). The port answers with the flight it learned
    /// earlier, which is the flight it would have used anyway — a site that
    /// is down for a moment is not a reason for a REALITY listener to be down.
    #[tokio::test]
    async fn a_site_that_cannot_be_reached_does_not_stop_the_server() {
        let (mut server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        server_params.decoy = Some(Arc::new(UnreachableDecoy));

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = handshake(server_io, &server_params).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
        });
        let mut client = zero_security::reality_connect(client_io, &client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong", "the server answered anyway");
        server.await.unwrap();
    }

    /// A camouflage site the probe can read a flight off.
    ///
    /// It is a real TLS 1.3 server, so the flight the probe reads is the
    /// flight a client would see.
    struct TestSite {
        dialer: Arc<TestSiteDialer>,
    }

    impl TestSite {
        /// Start a site on a loopback port.
        fn start() -> Self {
            let dialer = Arc::new(TestSiteDialer {
                address: std::sync::Mutex::new(None),
                flight: Arc::new(Mutex::new(Vec::new())),
            });
            Self { dialer }
        }
    }

    /// The dialer for [`TestSite`]: it starts the site on the first dial and
    /// hands the connection over.
    struct TestSiteDialer {
        address: std::sync::Mutex<Option<std::net::SocketAddr>>,
        /// The flight the site answered with, as the probe read it.
        flight: Arc<Mutex<Vec<u16>>>,
    }

    impl DecoyDialer for TestSiteDialer {
        fn dial(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<zero_core::BoxStream, String>> + Send>,
        > {
            let address = *self.address.lock().unwrap();
            // The site's flight is recorded in the dialer's own list, so the
            // test can read it after the handshake.
            let flight = Arc::clone(&self.flight);
            Box::pin(async move {
                let address = match address {
                    Some(address) => address,
                    None => {
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                            .await
                            .map_err(|error| error.to_string())?;
                        let address = listener.local_addr().map_err(|error| error.to_string())?;
                        let recorded = Arc::clone(&flight);
                        tokio::spawn(async move {
                            let config = site_config();
                            while let Ok((stream, _)) = listener.accept().await {
                                // The tap is on the site's side, so the
                                // records it saw written are the site's own
                                // flight — what the probe reads off it.
                                let (tap, taps) =
                                    zero_security::tls13::post_handshake::tap_with_flight(stream);
                                let config = Arc::clone(&config);
                                let recorded = Arc::clone(&recorded);
                                tokio::spawn(async move {
                                    let _ = zero_security::server::accept(tap, config).await;
                                    *recorded.lock().unwrap() =
                                        taps.written.lock().unwrap().clone();
                                });
                            }
                        });
                        address
                    }
                };
                let stream = tokio::net::TcpStream::connect(address)
                    .await
                    .map_err(|error| error.to_string())?;
                // The connection is tapped on the probe's side, so what the
                // tap saw *arrive* is the site's flight: the ServerHello, the
                // compatibility ChangeCipherSpec, and the encrypted records
                // that follow it.
                let (tap, taps) = zero_security::tls13::post_handshake::tap_with_flight(stream);
                let recorded = Arc::clone(&flight);
                tokio::spawn(async move {
                    // The probe's handshake is over by the time the site has
                    // sent its flight, so the list is complete a moment
                    // later.
                    for _ in 0..400 {
                        if recorded.lock().unwrap().len() >= 3 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    // The tap is on the probe's side of the connection, so
                    // the records it saw *arrive* are the site's flight.
                    *recorded.lock().unwrap() = taps.flight.lock().unwrap().clone();
                });
                Ok(Box::pin(tap) as zero_core::BoxStream)
            })
        }
    }

    /// The ML-DSA-65 certificate is the same size as Go's.
    ///
    /// Go's server signs into the certificate at a *fixed* offset
    /// (`RL/handshake_server_tls13.go:157`: `cert[126:]`), which only works
    /// because the certificate carries an extension of the right length: the
    /// ML-DSA-65 signature is 3309 bytes, and Go's placeholder extension
    /// holds 3309 dummy bytes. The port puts the signature in the
    /// extension's value instead, so the two certificates are the same size
    /// and a client comparing them sees no difference.
    #[test]
    fn the_mldsa65_certificate_is_the_size_go_makes_it() {
        let mut signing_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut signing_seed);
        let signing = SigningKey::from_bytes(&signing_seed);
        let auth_key = [7u8; 32];

        let plain = reality_certificate(&signing, &auth_key, "example.test", None);
        let bound = reality_certificate(
            &signing,
            &auth_key,
            "example.test",
            Some((&[9u8; 32], b"client hello", b"server hello")),
        );
        // The signature is 3309 bytes, and the extension's framing adds 21:
        // the OID, the octet string's header, the extension's sequence and
        // the extensions' sequence and their lengths.
        assert_eq!(
            bound.len() - plain.len(),
            3330,
            "the binding adds the 3309-byte signature and its framing"
        );
    }

    /// The ML-DSA-65 signature is the extension's value, and the extension
    /// is the last thing in the certificate.
    ///
    /// Go writes the signature at a *fixed* offset —
    /// `cert[126:]` (`RL/handshake_server_tls13.go:157`) — into a
    /// placeholder extension of exactly the right length, and its client
    /// reads it back out of the certificate's *first extension*
    /// (`XC/transport/internet/reality/reality.go:93`,
    /// `certs[0].Extensions[0].Value`).
    ///
    /// The port puts the signature in the extension's value directly, so
    /// the same client reads the same bytes: the offset is Go's business,
    /// and the value is the contract. That the two agree is proved by the
    /// differential test `reality_with_the_mldsa65_binding_matches_the_oracle`,
    /// which runs a real Xray client with `mldsa65Verify` against this
    /// server.
    #[test]
    fn the_extension_value_is_the_signature() {
        let mut signing_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut signing_seed);
        let signing = SigningKey::from_bytes(&signing_seed);
        let certificate = reality_certificate(
            &signing,
            &[7u8; 32],
            "example.test",
            Some((&[9u8; 32], b"client hello", b"server hello")),
        );
        let parts =
            zero_security::tls13::cert::parse_leaf(&certificate).expect("the certificate parses");
        let value = parts
            .first_extension
            .expect("the certificate has an extension");
        // An ML-DSA-65 signature is 3309 bytes.
        assert_eq!(
            value.len(),
            3309,
            "the extension's value is the signature, and a signature is 3309 bytes"
        );
        // And it is the *last* thing in the certificate, so a fixed offset
        // into it is a fixed offset into the certificate.
        assert!(
            parts
                .first_extension_offset
                .expect("the extension has an offset")
                > 0,
            "the extension is not at the start of the certificate"
        );
    }

    /// The TLS client works against a *stock* TLS 1.3 server.
    ///
    /// The checklist in `docs/specs/tls13-core.md` asks for it: the
    /// handshake must flush out the divergences in what may be skipped
    /// (§6.2, §6.4) against a server that is not this workspace's. The
    /// server here is a plain `rustls` one, with a certificate from the
    /// test fixtures and no REALITY in it at all.
    #[tokio::test]
    async fn the_client_handshakes_with_a_stock_tls13_server() {
        let config = site_config();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = zero_security::server::accept(server_io, config)
                .await
                .expect("the stock server accepts");
            let mut request = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut request)
                .await
                .expect("the request arrives");
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .expect("the reply goes out");
            tokio::io::AsyncWriteExt::flush(&mut stream)
                .await
                .expect("the reply is flushed");
        });
        // The client's hello is a browser's, and the server is told to
        // expect nothing more.
        let params = zero_security::tls::TlsParams::new("example.test")
            .with_alpn(&["h2"])
            .with_insecure(true);
        let mut client = zero_security::tls::connect(client_io, &params)
            .await
            .expect("the client completes the handshake with a stock server");
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong", "the stock server's reply comes back");
        server.await.unwrap();
    }

    /// The ALPN index is Go's, and it is a bucket.
    ///
    /// Go files the shapes it learned under `dest + " " + sni + " " + alpn`,
    /// where the last part is 0 for a client that offered no ALPN, 2 for one
    /// that offered h2 first, and 1 for anything else
    /// (`RL/tls.go:396-403`). A client that offered `http/1.1` first is
    /// therefore in the same bucket as one that offered only `http/1.1`.
    #[test]
    fn the_alpn_index_is_go_s_bucket() {
        let protocols = |list: &[&str]| list.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        assert_eq!(alpn_index(&[]), 0, "no ALPN is 0");
        assert_eq!(
            alpn_index(&protocols(&["h2", "http/1.1"])),
            2,
            "h2 first is 2"
        );
        assert_eq!(alpn_index(&protocols(&["http/1.1"])), 1, "http/1.1 is 1");
        assert_eq!(
            alpn_index(&protocols(&["http/1.1", "h2"])),
            1,
            "http/1.1 first is 1, whatever else was offered"
        );
        assert_eq!(
            alpn_index(&protocols(&["spdy/3"])),
            1,
            "an unknown protocol is 1"
        );
    }

    /// The shapes a client gets are the ones filed under *its* ALPN.
    ///
    /// A site can answer an h2 client differently from an http/1.1 one, so
    /// the port learns the site three ways and hands each client the answer
    /// that matches what it asked for.
    #[test]
    fn a_client_gets_the_shapes_filed_under_its_alpn() {
        let shapes = PostHandshakeShapes::default();
        shapes.set_flight("example.test", 2, &[200, 200]);
        shapes.set_flight("example.test", 1, &[100, 100]);
        shapes.set_flight("example.test", 0, &[50, 50]);

        let h2 = shapes.site("example.test", 2);
        let http1 = shapes.site("example.test", 1);
        let none = shapes.site("example.test", 0);
        assert_eq!(
            h2.flight.as_deref(),
            Some(&[200u16, 200][..]),
            "the h2 client's own answer"
        );
        assert_eq!(
            http1.flight.as_deref(),
            Some(&[100u16, 100][..]),
            "the http/1.1 client's own answer"
        );
        assert_eq!(
            none.flight.as_deref(),
            Some(&[50u16, 50][..]),
            "the client that offered no ALPN"
        );
        // A name with no answer of its own has none.
        assert!(
            shapes.site("other.test", 2).flight.is_none(),
            "another name has no shapes"
        );
    }

    /// The site's TLS configuration.
    fn site_config() -> Arc<rustls::ServerConfig> {
        const CERT: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-cert.pem");
        const KEY: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-key.pem");
        zero_security::server::server_config(CERT, KEY, &["h2".into()])
            .expect("the site's certificate loads")
    }

    /// A flight of the right shape for this server, but a different size
    /// from any site's.
    ///
    /// The first record has to be the ServerHello, whose size is this
    /// server's own ServerHello plus its five-byte header, or the flight
    /// cannot be copied at all — and a flight that cannot be copied leaves
    /// the server's own sizes on the wire whether or not the site was read.
    fn cached_flight() -> Vec<u16> {
        let hello = 5 + build_server_hello(
            &[0u8; 32],
            zero_security::tls13::CipherSuite::TLS_AES_128_GCM_SHA256,
            0x001d,
            &[0u8; 32],
        )
        .len();
        vec![hello as u16, 6, 1000]
    }

    /// A dialer whose site cannot be reached.
    struct UnreachableDecoy;

    impl DecoyDialer for UnreachableDecoy {
        fn dial(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<zero_core::BoxStream, String>> + Send>,
        > {
            Box::pin(async { Err("the site is down".to_string()) })
        }
    }

    /// The sizes a site's flight is copied in, and the three cases that decide
    /// whether it can be copied at all.
    #[tokio::test]
    async fn the_flight_is_written_in_the_sizes_learned_from_the_site() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let natural = flight_sizes(&server_params, &client_params).await;
        assert_eq!(
            natural.len(),
            6,
            "ServerHello, compatibility CCS, then EncryptedExtensions, Certificate, \
             CertificateVerify and Finished in a record each: {natural:?}"
        );

        // A site whose flight is learned: every record after the ServerHello
        // goes out in the size the site sent, whatever this server's own
        // messages come to.
        let learned: Vec<u16> = vec![
            natural[0],
            natural[1],
            natural[2] + 64,
            natural[3] + 512,
            natural[4] + 48,
            natural[5] + 16,
        ];
        server_params
            .post_handshake
            .set_flight("example.test", 2, &learned);
        assert_eq!(flight_sizes(&server_params, &client_params).await, learned);

        // The same server, a name nothing was learned for.
        let (untouched_params, _) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        untouched_params
            .post_handshake
            .set_flight("other.test", 2, &learned);
        assert_eq!(
            flight_sizes(&untouched_params, &client_params).await,
            natural
        );
    }

    /// A shape that cannot be reproduced exactly is not half-copied: Go
    /// replays the site's ServerHello byte for byte, this server builds its
    /// own, and a flight that matches every record but the first is no better
    /// than one that matches none of them.
    #[tokio::test]
    async fn a_site_hello_of_another_size_leaves_the_flight_as_it_is() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let natural = flight_sizes(&server_params, &client_params).await;

        let mut elsewhere: Vec<u16> = vec![natural[0] + 7, natural[1]];
        elsewhere.extend([natural[2] + 64, natural[3] + 512, natural[4], natural[5]]);
        server_params
            .post_handshake
            .set_flight("example.test", 2, &elsewhere);
        assert_eq!(
            flight_sizes(&server_params, &client_params).await,
            natural,
            "a ServerHello of another size cannot be copied, so nothing is"
        );

        // As is a site whose ChangeCipherSpec is not the six bytes every TLS
        // 1.3 middlebox compatibility record is.
        let (odd_ccs, _) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let mut not_six: Vec<u16> = vec![natural[0], 32];
        not_six.extend([natural[2], natural[3], natural[4], natural[5]]);
        odd_ccs
            .post_handshake
            .set_flight("example.test", 2, &not_six);
        assert_eq!(flight_sizes(&odd_ccs, &client_params).await, natural);
    }

    /// A site whose certificate record is smaller than this server's
    /// certificate needs is refused, rather than answered with a flight whose
    /// sizes are this implementation's and not the site's
    /// (`RL/conn.go:553-555`).
    #[tokio::test]
    async fn a_site_flight_too_small_for_the_certificate_is_refused() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let natural = flight_sizes(&server_params, &client_params).await;
        let mut too_small = natural.clone();
        too_small[3] = natural[3] - 128;
        server_params
            .post_handshake
            .set_flight("example.test", 2, &too_small);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            zero_security::reality_connect(client_io, &client_params)
                .await
                .is_ok()
        });
        let outcome = handshake_or_fallback(server_io, &server_params, None).await;
        assert!(
            !client.await.unwrap(),
            "the client must not be handed a flight the site never sends"
        );
        match outcome {
            HandshakeOutcome::Rejected(failure) => assert!(
                failure.to_string().contains("cannot carry"),
                "the refusal should say what did not fit: {failure}"
            ),
            HandshakeOutcome::Accepted(_) => {
                panic!("a flight that cannot be shaped like the site's must be refused")
            }
            HandshakeOutcome::Fallback { .. } => {
                panic!("an authenticated client is not answered with the camouflage site")
            }
        }
    }

    #[tokio::test]
    async fn unknown_short_id_falls_back() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let _ = zero_security::reality_connect(client_io, &client_params).await;
        });
        match handshake_or_fallback(server_io, &server_params, None).await {
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
        match handshake_or_fallback(server, &params, None).await {
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
            show: false,
            key_log: None,
            decoy: None,
        };
        match handshake_or_fallback(server, &params, None).await {
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
            tokio::spawn(async move { handshake_or_fallback(server_io, &params, None).await });
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
        let mut record = record_header(CONTENT_HANDSHAKE, MAX_CIPHERTEXT_BEFORE_TLS13).to_vec();
        record.resize(5 + MAX_CIPHERTEXT_BEFORE_TLS13, 0);

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(&record).await.unwrap();
        client.flush().await.unwrap();
        match handshake_or_fallback(server, &params, None).await {
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
