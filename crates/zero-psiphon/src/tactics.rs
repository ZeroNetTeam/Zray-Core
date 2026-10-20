//! Remote tactics: Psiphon's periodically refreshed parameter set.
//!
//! A Psiphon server hands out *tactics*: a small set of parameters — dial
//! timeouts, padding ranges, which tunnel protocols to try — that the client
//! applies until they expire. The server chooses them per client: a client
//! on a slow link gets longer timeouts, a client whose protocol is blocked
//! gets a protocol limit. That is why the client asks for them instead of
//! hard-coding them (`psiphon/common/tactics/tactics.go:20-27`).
//!
//! The exchange happens *before* any tunnel exists: it is an untunnelled
//! HTTP round trip to the server's meek endpoint, so it has to be
//! self-protecting. Two layers do that:
//!
//! * The request and the response are sealed with NaCl's `box`, to a key
//!   pair the server publishes in its entry, each with its own nonce, so a
//!   response cannot be replayed as a request
//!   (`tactics.go:202-203`, `tactics.go:1737-1744`).
//! * The sealed bytes are wrapped in an obfuscator seed message, so the
//!   request does not look like a protocol the server does not speak
//!   (`tactics.go:2061-2084`). This is the same wrapper the meek cookie
//!   uses; see [`crate::meek`].
//!
//! This module owns the framing, the parameter model and the fetch. It does
//! not own the transport: the caller supplies one, because this crate has
//! no HTTP client of its own and the transport Psiphon uses (meek) is built
//! by the caller on top of [`crate::meek`].
//!
//! What is verified here, and what is not: the framing is reproduced from
//! the Go source and checked by round-trip tests against this module's own
//! decoder, which is the same decoder a Psiphon server's half of the
//! exchange needs. No live Psiphon tactics endpoint was available while this
//! was written, so the bytes have not been compared against a real server's
//! answer; the Go reference (`tactics.go:2022-2151`) is the authority the
//! implementation follows.

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use rand::Rng;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::nacl_box;
use crate::obfuscator::{
    derive_key, Rc4, CLIENT_TO_SERVER, MAGIC_VALUE, MAX_PADDING, MIN_PADDING, SEED_LENGTH,
};
use crate::protocol::TunnelProtocol;
use crate::server_entry::ServerEntry;

/// The nonce a tactics request is sealed with.
///
/// Go's `TACTICS_REQUEST_NONCE` is the single byte `1`, copied into the left
/// of a 24-byte nonce array (`tactics.go:202`, `tactics.go:2045-2046`).
pub const TACTICS_REQUEST_NONCE: [u8; 24] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The nonce a tactics response is sealed with: the single byte `2`
/// (`tactics.go:203`).
pub const TACTICS_RESPONSE_NONCE: [u8; 24] = [
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The endpoint a tactics request goes to (`TACTICS_END_POINT`,
/// `tactics.go:183`).
pub const TACTICS_END_POINT: &str = "tactics";

/// The endpoint a speed test goes to (`SPEED_TEST_END_POINT`,
/// `tactics.go:182`).
pub const SPEED_TEST_END_POINT: &str = "speedtest";

/// The largest padding the seed message of a tactics payload may carry
/// (`TACTICS_PADDING_MAX_SIZE`, `tactics.go:187`).
pub const TACTICS_PADDING_MAX_SIZE: usize = 256;

/// The largest body the server accepts for a tactics request
/// (`MAX_REQUEST_BODY_SIZE`, `tactics.go:184`).
pub const MAX_REQUEST_BODY_SIZE: usize = 65536;

/// The parameters a tactics record may override.
///
/// Only the parameters this client acts on are modelled. The server sends
/// the whole Psiphon parameter set, and most of it names behaviour this
/// port does not implement (QUIC transforms, in-proxy announcements, the
/// API request shape). Unknown parameters are ignored rather than rejected:
/// a server that adds a parameter must not be able to break a client that
/// has never heard of it.
///
/// The field names are Psiphon's own, because that is what is on the wire:
/// the server writes the parameters into a map keyed by the names in
/// `psiphon/common/parameters/parameters.go`, and the client looks them up
/// by the same names. Every field is optional: a tactics record only
/// carries the parameters the server wants changed.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
pub struct TacticsParameters {
    // Dial timeouts.
    /// How long a tunnel may take to connect (`TunnelConnectTimeout`).
    #[serde(
        rename = "TunnelConnectTimeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub tunnel_connect_timeout: Option<Duration>,

    /// How long the whole establishment sequence may take
    /// (`EstablishTunnelTimeout`).
    #[serde(
        rename = "EstablishTunnelTimeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub establish_tunnel_timeout: Option<Duration>,

    /// How long a forwarded connection may take to dial
    /// (`TunnelPortForwardDialTimeout`).
    #[serde(
        rename = "TunnelPortForwardDialTimeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub tunnel_port_forward_dial_timeout: Option<Duration>,

    /// How long a read from a tunnel may block (`PacketTunnelReadTimeout`).
    #[serde(
        rename = "PacketTunnelReadTimeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub packet_tunnel_read_timeout: Option<Duration>,

    // Padding ranges and probabilities.
    /// The smallest padding the obfuscated-SSH seed message may carry
    /// (`ObfuscatedSSHMinPadding`).
    #[serde(rename = "ObfuscatedSSHMinPadding")]
    pub ossh_min_padding: Option<usize>,

    /// The largest padding the obfuscated-SSH seed message may carry
    /// (`ObfuscatedSSHMaxPadding`).
    #[serde(rename = "ObfuscatedSSHMaxPadding")]
    pub ossh_max_padding: Option<usize>,

    /// How likely the client is to pad its meek payloads
    /// (`MeekPayloadPaddingProbability`).
    #[serde(rename = "MeekPayloadPaddingProbability")]
    pub meek_payload_padding_probability: Option<f64>,

    /// The smallest padding the client adds to a meek payload
    /// (`MeekPayloadPaddingClientMinSize`).
    #[serde(rename = "MeekPayloadPaddingClientMinSize")]
    pub meek_payload_padding_client_min_size: Option<usize>,

    /// The largest padding the client adds to a meek payload
    /// (`MeekPayloadPaddingClientMaxSize`).
    #[serde(rename = "MeekPayloadPaddingClientMaxSize")]
    pub meek_payload_padding_client_max_size: Option<usize>,

    /// The smallest padding the server adds to a meek payload
    /// (`MeekPayloadPaddingServerMinSize`).
    #[serde(rename = "MeekPayloadPaddingServerMinSize")]
    pub meek_payload_padding_server_min_size: Option<usize>,

    /// The largest padding the server adds to a meek payload
    /// (`MeekPayloadPaddingServerMaxSize`).
    #[serde(rename = "MeekPayloadPaddingServerMaxSize")]
    pub meek_payload_padding_server_max_size: Option<usize>,

    /// The smallest padding a speed test request may carry
    /// (`SpeedTestPaddingMinBytes`).
    #[serde(rename = "SpeedTestPaddingMinBytes")]
    pub speed_test_padding_min_bytes: Option<usize>,

    /// The largest padding a speed test request may carry
    /// (`SpeedTestPaddingMaxBytes`).
    #[serde(rename = "SpeedTestPaddingMaxBytes")]
    pub speed_test_padding_max_bytes: Option<usize>,

    // Limit tunnel protocols.
    /// The tunnel protocols the client may use, when the server limits them
    /// (`LimitTunnelProtocols`).
    ///
    /// Names this client does not know are dropped: a protocol the client
    /// cannot speak is not a candidate anyway, and a server that adds one
    /// must not break the client.
    #[serde(
        rename = "LimitTunnelProtocols",
        deserialize_with = "deserialize_tunnel_protocols"
    )]
    pub limit_tunnel_protocols: Option<Vec<TunnelProtocol>>,

    /// How likely the protocol limit is to be applied
    /// (`LimitTunnelProtocolsProbability`).
    #[serde(rename = "LimitTunnelProtocolsProbability")]
    pub limit_tunnel_protocols_probability: Option<f64>,

    /// The tunnel protocols the client may use for its first attempts
    /// (`InitialLimitTunnelProtocols`).
    #[serde(
        rename = "InitialLimitTunnelProtocols",
        deserialize_with = "deserialize_tunnel_protocols"
    )]
    pub initial_limit_tunnel_protocols: Option<Vec<TunnelProtocol>>,

    /// How likely the initial protocol limit is to be applied
    /// (`InitialLimitTunnelProtocolsProbability`).
    #[serde(rename = "InitialLimitTunnelProtocolsProbability")]
    pub initial_limit_tunnel_protocols_probability: Option<f64>,

    /// How many candidates the initial protocol limit draws
    /// (`InitialLimitTunnelProtocolsCandidateCount`).
    #[serde(rename = "InitialLimitTunnelProtocolsCandidateCount")]
    pub initial_limit_tunnel_protocols_candidate_count: Option<usize>,

    // Meek limits.
    /// The buffer sizes the meek carrier may use (`MeekLimitBufferSizes`).
    #[serde(rename = "MeekLimitBufferSizes")]
    pub meek_limit_buffer_sizes: Option<Vec<usize>>,

    /// The largest padding the meek cookie's seed message may carry
    /// (`MeekCookieMaxPadding`).
    #[serde(rename = "MeekCookieMaxPadding")]
    pub meek_cookie_max_padding: Option<usize>,

    /// The smallest request body the meek carrier may send
    /// (`MeekMinLimitRequestPayloadLength`).
    #[serde(rename = "MeekMinLimitRequestPayloadLength")]
    pub meek_min_limit_request_payload_length: Option<usize>,

    /// The largest request body the meek carrier may send
    /// (`MeekMaxLimitRequestPayloadLength`).
    #[serde(rename = "MeekMaxLimitRequestPayloadLength")]
    pub meek_max_limit_request_payload_length: Option<usize>,

    /// The shortest interval between polls of an idle meek session
    /// (`MeekMinPollInterval`).
    #[serde(
        rename = "MeekMinPollInterval",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub meek_min_poll_interval: Option<Duration>,

    /// The longest interval between polls of an idle meek session
    /// (`MeekMaxPollInterval`).
    #[serde(
        rename = "MeekMaxPollInterval",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub meek_max_poll_interval: Option<Duration>,

    /// How long a meek round trip may take (`MeekRoundTripTimeout`).
    #[serde(
        rename = "MeekRoundTripTimeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub meek_round_trip_timeout: Option<Duration>,

    /// How likely the meek carrier is to reshape its traffic
    /// (`MeekTrafficShapingProbability`).
    #[serde(rename = "MeekTrafficShapingProbability")]
    pub meek_traffic_shaping_probability: Option<f64>,

    /// The smallest TLS padding the meek carrier may add
    /// (`MeekMinTLSPadding`).
    #[serde(rename = "MeekMinTLSPadding")]
    pub meek_min_tls_padding: Option<usize>,

    /// The largest TLS padding the meek carrier may add
    /// (`MeekMaxTLSPadding`).
    #[serde(rename = "MeekMaxTLSPadding")]
    pub meek_max_tls_padding: Option<usize>,
}

/// The tactics themselves: how long they may be used, and the parameters
/// they carry.
///
/// This is Go's `tactics.Tactics` (`tactics.go:372-393`). The field names
/// are Go's, because the struct carries no JSON tags.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct Tactics {
    /// How long the client may use these tactics, as a Go duration string
    /// ("24h"). The client turns it into an expiry when it stores them
    /// (`tactics.go:381`, `tactics.go:1988-1999`).
    ///
    /// The string is parsed when the payload is read, so a TTL the client
    /// cannot read makes the whole payload unreadable. That is deliberate:
    /// Go's client applies a tactics record as a whole or not at all, and
    /// leaves the previous values in place when it cannot
    /// (`psiphon/tactics.go:190-205`).
    #[serde(
        rename = "TTL",
        default,
        deserialize_with = "deserialize_optional_duration"
    )]
    pub ttl: Option<Duration>,

    /// The probability the server attached to the tactics.
    ///
    /// The server always sends 1.0: tactics are applied unconditionally now,
    /// and the field survives only for older clients (`tactics.go:383-387`,
    /// `tactics.go:1100`).
    #[serde(rename = "Probability", default)]
    pub probability: Option<f64>,

    /// The parameters the tactics override.
    #[serde(
        rename = "Parameters",
        default,
        deserialize_with = "deserialize_optional_parameters"
    )]
    pub parameters: TacticsParameters,
}

/// The server's answer to a tactics request.
///
/// Go's `tactics.Payload` (`tactics.go:337-350`). The tag identifies the
/// tactics: the client sends the tag of the tactics it already has, and the
/// server leaves the tactics out when the tag is unchanged
/// (`tactics.go:832-840`).
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct TacticsPayload {
    /// The hash tag of the tactics.
    #[serde(rename = "Tag", default)]
    pub tag: String,

    /// The tactics, when they changed. Absent when the tag is unchanged.
    #[serde(rename = "Tactics", default)]
    pub tactics: Option<Tactics>,

    /// How the tactics were compressed: 0 is none, 1 is zlib
    /// (`tactics.go:348-349`).
    ///
    /// The client never asks for compressed tactics — the parameter that
    /// would do so is off by default — so this is only ever 0 here. A
    /// non-zero value is refused rather than silently misread.
    #[serde(rename = "TacticsCompression", default)]
    pub tactics_compression: i32,
}

/// A tactics record: what the client keeps between runs.
///
/// Go's `tactics.Record` (`tactics.go:352-367`). There is one record per
/// network context, because the server's advice depends on the network the
/// client is on.
#[derive(Debug, Clone, PartialEq)]
pub struct TacticsRecord {
    /// The tag of the tactics in the record.
    pub tag: String,
    /// When the tactics expire.
    pub expiry: SystemTime,
    /// The tactics themselves.
    pub tactics: Tactics,
}

impl Default for TacticsRecord {
    /// A record with no tactics, expiring at the epoch: it is already
    /// expired, and so never usable.
    fn default() -> Self {
        TacticsRecord {
            tag: String::new(),
            expiry: SystemTime::UNIX_EPOCH,
            tactics: Tactics::default(),
        }
    }
}

impl TacticsRecord {
    /// A record with no tactics: nothing to apply, and already expired.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether the record's tactics have expired at `now`.
    ///
    /// Go compares the expiry against the clock the same way
    /// (`tactics.go:1611`).
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expiry <= now
    }

    /// Whether the record holds tactics the client may use at `now`.
    ///
    /// A record with no tag holds no tactics, whatever its expiry says
    /// (`tactics.go:1611`).
    pub fn is_usable(&self, now: SystemTime) -> bool {
        !self.tag.is_empty() && !self.is_expired(now)
    }

    /// Apply a payload to the record, and report whether the tactics
    /// changed.
    ///
    /// When the payload's tag differs from the record's, the tactics are
    /// replaced; when it is the same, the record keeps the tactics it has and
    /// only the expiry is extended. The expiry always comes from the
    /// tactics in the record, so an unchanged tag extends the record by the
    /// TTL it was stored with (`tactics.go:1933-2002`).
    pub fn apply(&mut self, payload: &TacticsPayload, now: SystemTime) -> Result<bool> {
        if payload.tag.is_empty() {
            return Err(Error::Protocol("the tactics response has no tag".into()));
        }

        let mut changed = false;
        if payload.tag != self.tag {
            let Some(tactics) = payload.tactics.as_ref() else {
                return Err(Error::Protocol(
                    "the tactics response has a new tag but no tactics".into(),
                ));
            };
            self.tag = payload.tag.clone();
            self.tactics = tactics.clone();
            changed = true;
        }

        let ttl = self
            .tactics
            .ttl
            .ok_or_else(|| Error::Protocol("the tactics have no TTL".into()))?;
        if ttl.is_zero() {
            return Err(Error::Protocol("the tactics have a zero TTL".into()));
        }

        // A TTL large enough to overflow the clock is not a value a server
        // sends; treating the record as expiring at once is safer than
        // panicking on the addition.
        self.expiry = now.checked_add(ttl).unwrap_or(now);
        Ok(changed)
    }
}

/// Whether the client should fetch tactics now.
///
/// Go's client asks for tactics only when it has no usable record
/// (`tactics.go:1603-1616`): an expired record is fetched again, an
/// unexpired one is not.
pub fn should_fetch(record: &TacticsRecord, now: SystemTime) -> bool {
    !record.is_usable(now)
}

/// One speed test sample, as the client reports it to the server.
///
/// Go's `tactics.SpeedTestSample` (`tactics.go:401-432`). The field names
/// are the short ones Go uses, to keep the marshaled size down.
///
/// This module models the format only. Collecting the samples is the
/// caller's job: the client measures a round trip to the server before its
/// first tactics request, so the server can pick tactics for the link the
/// client is on (`tactics.go:1671-1706`), and that round trip is the
/// transport's business.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpeedTestSample {
    /// The server's timestamp, in RFC 3339, truncated to the hour.
    #[serde(rename = "s", default, skip_serializing_if = "String::is_empty")]
    pub timestamp: String,
    /// The region of the server that answered.
    #[serde(rename = "r", default, skip_serializing_if = "String::is_empty")]
    pub end_point_region: String,
    /// The protocol the round trip used.
    #[serde(rename = "p", default, skip_serializing_if = "String::is_empty")]
    pub end_point_protocol: String,
    /// The round trip time, in milliseconds.
    #[serde(rename = "t", default)]
    pub rtt_milliseconds: u64,
    /// The bytes sent.
    #[serde(rename = "u", default)]
    pub bytes_up: u64,
    /// The bytes received.
    #[serde(rename = "d", default)]
    pub bytes_down: u64,
}

/// The API parameters a tactics request carries.
///
/// These are the parameters the tactics exchange itself needs; the caller
/// adds whatever else the server expects in the same map
/// (`tactics.go:1710-1711`).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct TacticsRequestParameters {
    /// The tag of the tactics the client already has, empty when it has
    /// none (`STORED_TACTICS_TAG_PARAMETER_NAME`, `tactics.go:1533`).
    #[serde(rename = "stored_tactics_tag")]
    pub stored_tactics_tag: String,

    /// The speed test samples the client has collected
    /// (`SPEED_TEST_SAMPLES_PARAMETER_NAME`, `tactics.go:1534`).
    #[serde(rename = "speed_test_samples", skip_serializing_if = "Vec::is_empty")]
    pub speed_test_samples: Vec<SpeedTestSample>,
}

impl TacticsRequestParameters {
    /// The parameters as a JSON value, ready to be framed.
    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|error| Error::Protocol(format!("tactics request: {error}")))
    }
}

/// How a tactics request reaches the server.
///
/// Go's equivalent is `tactics.ObfuscatedRoundTripper`
/// (`tactics.go:1500-1503`): a function that takes an endpoint name and a
/// request body and returns the response body. The transport belongs to the
/// caller, because this crate has no HTTP client of its own and the
/// transport Psiphon uses (meek) is built by the caller on top of
/// [`crate::meek`].
pub trait TacticsTransport: Send {
    /// Send `body` to `endpoint` and return the response body.
    ///
    /// `endpoint` is [`TACTICS_END_POINT`] for a tactics request and
    /// [`SPEED_TEST_END_POINT`] for a speed test (`tactics.go:182-183`).
    fn round_trip(&mut self, endpoint: &str, body: &[u8]) -> Result<Vec<u8>>;
}

impl<F> TacticsTransport for F
where
    F: FnMut(&str, &[u8]) -> Result<Vec<u8>> + Send,
{
    fn round_trip(&mut self, endpoint: &str, body: &[u8]) -> Result<Vec<u8>> {
        (self)(endpoint, body)
    }
}

/// A tactics request in flight.
///
/// The request is sealed to the server's tactics public key with an
/// ephemeral key pair, so the request has to outlive the encoding: the
/// answer is sealed to the ephemeral public key, and only the ephemeral
/// private key can open it (`tactics.go:1732-1744`, `tactics.go:1761-1768`).
pub struct TacticsRequest {
    /// The ephemeral private key the request is sealed with.
    ephemeral_secret: [u8; 32],
    /// The ephemeral public key the server seals its answer to.
    ephemeral_public: [u8; 32],
    /// The server's tactics public key, which the request is sealed to.
    server_public_key: [u8; 32],
    /// The obfuscation key the seed message is keyed by.
    obfuscated_key: Vec<u8>,
}

impl TacticsRequest {
    /// Start a request against a server entry.
    ///
    /// The entry must carry the server's tactics public key
    /// (`tacticsRequestPublicKey`) and the obfuscation key
    /// (`tacticsRequestObfuscatedKey`), both base64; a server without them
    /// does not answer tactics requests (`tactics.go:1722-1730`).
    pub fn new(entry: &ServerEntry, rng: &mut impl Rng) -> Result<Self> {
        let server_public_key = decode_public_key(
            entry.tactics_request_public_key(),
            "tacticsRequestPublicKey",
        )?;
        let obfuscated_key = decode_obfuscated_key(entry.tactics_request_obfuscated_key())?;
        Ok(Self::from_keys(&server_public_key, &obfuscated_key, rng))
    }

    /// Start a request with the keys already decoded.
    pub fn from_keys(
        server_public_key: &[u8; 32],
        obfuscated_key: &[u8],
        rng: &mut impl Rng,
    ) -> Self {
        let mut ephemeral_secret = [0u8; 32];
        rng.fill(&mut ephemeral_secret);
        let ephemeral_public = nacl_box::public_key(&ephemeral_secret);
        TacticsRequest {
            ephemeral_secret,
            ephemeral_public,
            server_public_key: *server_public_key,
            obfuscated_key: obfuscated_key.to_vec(),
        }
    }

    /// The ephemeral public key the server seals its answer to.
    pub fn ephemeral_public_key(&self) -> [u8; 32] {
        self.ephemeral_public
    }

    /// Frame the request body for `api_parameters`.
    ///
    /// The bytes are the API parameters, encoded the way Go encodes them,
    /// sealed to the server's public key with the request nonce, prefixed
    /// with the ephemeral public key, and wrapped in an obfuscator seed
    /// message (`tactics.go:2022-2085`).
    pub fn encode(&self, api_parameters: &Value, rng: &mut impl Rng) -> Result<Vec<u8>> {
        let payload = crate::json::encode(api_parameters)
            .map_err(|error| Error::Protocol(format!("tactics request: {error}")))?;
        let sealed = nacl_box::seal(
            &TACTICS_REQUEST_NONCE,
            &payload,
            &self.server_public_key,
            &self.ephemeral_secret,
        );

        // The server learns the ephemeral public key from the request
        // itself, so it travels in front of the sealed bytes
        // (`tactics.go:2054-2059`).
        let mut boxed = Vec::with_capacity(32 + sealed.len());
        boxed.extend_from_slice(&self.ephemeral_public);
        boxed.extend_from_slice(&sealed);

        Ok(wrap_seed_message(&self.obfuscated_key, &boxed, rng))
    }

    /// Decode the server's answer.
    ///
    /// The mirror of [`TacticsRequest::encode`]: the seed message is read,
    /// the box is opened with the response nonce, and the payload is
    /// decoded (`tactics.go:1761-1768`).
    pub fn decode_response(&self, framed: &[u8]) -> Result<TacticsPayload> {
        let boxed = unwrap_seed_message(&self.obfuscated_key, framed)?;
        let opened = nacl_box::open(
            &TACTICS_RESPONSE_NONCE,
            &boxed,
            &self.server_public_key,
            &self.ephemeral_secret,
        )
        .ok_or_else(|| Error::Protocol("the tactics response did not open".into()))?;
        parse_payload(&opened)
    }

    /// Frame the request, send it, and decode the answer.
    pub fn fetch(
        &self,
        api_parameters: &Value,
        transport: &mut dyn TacticsTransport,
        rng: &mut impl Rng,
    ) -> Result<TacticsPayload> {
        let body = self.encode(api_parameters, rng)?;
        let response = transport.round_trip(TACTICS_END_POINT, &body)?;
        self.decode_response(&response)
    }
}

/// Fetch tactics for a server entry and apply them to `record`.
///
/// Returns whether the tactics changed. The record's expiry is set from the
/// tactics' TTL, whether they changed or not (`tactics.go:1933-2002`).
pub fn fetch_tactics(
    record: &mut TacticsRecord,
    entry: &ServerEntry,
    api_parameters: &Value,
    transport: &mut dyn TacticsTransport,
    rng: &mut impl Rng,
    now: SystemTime,
) -> Result<bool> {
    let request = TacticsRequest::new(entry, rng)?;
    let payload = request.fetch(api_parameters, transport, rng)?;
    record.apply(&payload, now)
}

/// What a server reads from a tactics request.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenedTacticsRequest {
    /// The client's ephemeral public key: the server seals its answer to it.
    pub peer_public_key: [u8; 32],
    /// The API parameters the client sent.
    pub api_parameters: Value,
}

/// Open a tactics request the way the server does.
///
/// This is the server's half of the exchange: it reads the seed message,
/// opens the box with the server's private key, and returns the client's
/// ephemeral public key so the answer can be sealed to it
/// (`tactics.go:1414-1421`, `tactics.go:2088-2150`).
///
/// It exists so the mock server and the tests can read what a client
/// produced.
pub fn open_tactics_request(
    framed: &[u8],
    server_secret: &[u8; 32],
    obfuscated_key: &[u8],
) -> Result<OpenedTacticsRequest> {
    let boxed = unwrap_seed_message(obfuscated_key, framed)?;
    if boxed.len() < 32 {
        return Err(Error::Protocol("the tactics request is too short".into()));
    }

    let mut peer_public_key = [0u8; 32];
    peer_public_key.copy_from_slice(&boxed[..32]);
    let opened = nacl_box::open(
        &TACTICS_REQUEST_NONCE,
        &boxed[32..],
        &peer_public_key,
        server_secret,
    )
    .ok_or_else(|| Error::Protocol("the tactics request did not open".into()))?;

    let api_parameters: Value = serde_json::from_slice(&opened)
        .map_err(|error| Error::Protocol(format!("tactics request: {error}")))?;

    Ok(OpenedTacticsRequest {
        peer_public_key,
        api_parameters,
    })
}

/// Seal a tactics response the way the server does.
///
/// The response is sealed to the client's ephemeral public key with the
/// server's private key and the response nonce, and is then wrapped in a
/// seed message of its own (`tactics.go:1459-1466`, `tactics.go:2022-2085`).
pub fn seal_tactics_response(
    payload: &Value,
    peer_public_key: &[u8; 32],
    server_secret: &[u8; 32],
    obfuscated_key: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>> {
    let marshaled = crate::json::encode(payload)
        .map_err(|error| Error::Protocol(format!("tactics response: {error}")))?;
    let sealed = nacl_box::seal(
        &TACTICS_RESPONSE_NONCE,
        &marshaled,
        peer_public_key,
        server_secret,
    );
    Ok(wrap_seed_message(obfuscated_key, &sealed, rng))
}

/// Wrap `payload` in an obfuscator seed message and encrypt it.
///
/// The wrapper is the one the meek cookie uses: a random 16-byte seed in
/// the clear, then the magic value, the padding length and the padding,
/// all encrypted with the client-to-server RC4 stream, and the payload
/// encrypted with the same stream (`meek.rs:150-172`, `tactics.go:2061-2084`).
/// The server reads the seed, derives the same key and continues the stream
/// over the payload (`tactics.go:2099-2115`).
fn wrap_seed_message(obfuscated_key: &[u8], payload: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let padding_length = rng.gen_range(MIN_PADDING..=TACTICS_PADDING_MAX_SIZE);
    let mut padding = vec![0u8; padding_length];
    rng.fill(&mut padding[..]);
    let mut seed = [0u8; SEED_LENGTH];
    rng.fill(&mut seed);

    let mut cipher = Rc4::new(&derive_key(&seed, obfuscated_key, CLIENT_TO_SERVER));

    let mut out = Vec::with_capacity(SEED_LENGTH + 8 + padding.len() + payload.len());
    out.extend_from_slice(&seed);
    out.extend_from_slice(&MAGIC_VALUE.to_be_bytes());
    out.extend_from_slice(&(padding.len() as u32).to_be_bytes());
    out.extend_from_slice(&padding);
    cipher.apply(&mut out[SEED_LENGTH..]);

    let mut body = payload.to_vec();
    cipher.apply(&mut body);
    out.extend_from_slice(&body);
    out
}

/// Read a seed message and decrypt what follows it.
///
/// The mirror of [`wrap_seed_message`]. The padding is part of the same
/// RC4 stream, so the cipher has to advance over it before the payload is
/// decrypted.
fn unwrap_seed_message(obfuscated_key: &[u8], framed: &[u8]) -> Result<Vec<u8>> {
    if framed.len() < SEED_LENGTH + 8 {
        return Err(Error::Protocol(
            "the tactics message is shorter than a seed message".into(),
        ));
    }

    let mut seed = [0u8; SEED_LENGTH];
    seed.copy_from_slice(&framed[..SEED_LENGTH]);
    let mut cipher = Rc4::new(&derive_key(&seed, obfuscated_key, CLIENT_TO_SERVER));

    let mut header = framed[SEED_LENGTH..SEED_LENGTH + 8].to_vec();
    cipher.apply(&mut header);
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != MAGIC_VALUE {
        return Err(Error::Protocol(
            "the tactics message has no obfuscator magic value".into(),
        ));
    }

    let padding_length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if padding_length > MAX_PADDING {
        return Err(Error::Protocol(
            "the tactics message has an invalid padding length".into(),
        ));
    }

    let body_start = SEED_LENGTH + 8 + padding_length;
    if framed.len() < body_start {
        return Err(Error::Protocol(
            "the tactics message is shorter than its padding".into(),
        ));
    }

    let mut padding = framed[SEED_LENGTH + 8..body_start].to_vec();
    cipher.apply(&mut padding);

    let mut body = framed[body_start..].to_vec();
    cipher.apply(&mut body);
    Ok(body)
}

/// Decode the JSON body of a tactics response.
fn parse_payload(bytes: &[u8]) -> Result<TacticsPayload> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| Error::Protocol(format!("tactics response: {error}")))?;

    // The tactics are compressed when the client asked for compressed
    // tactics, which this client never does; refuse rather than misread the
    // compressed bytes as JSON.
    let compression = value
        .get("TacticsCompression")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if compression != 0 {
        return Err(Error::Protocol(format!(
            "the server sent compressed tactics (compression {compression}), which this client does not read"
        )));
    }

    serde_json::from_value(value)
        .map_err(|error| Error::Protocol(format!("tactics response: {error}")))
}

/// Decode a base64 public key from a server entry.
fn decode_public_key(text: &str, field: &str) -> Result<[u8; 32]> {
    if text.trim().is_empty() {
        return Err(Error::Config(format!("the server entry has no {field}")));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|error| Error::Config(format!("{field} is not base64: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| Error::Config(format!("{field} is not 32 bytes")))
}

/// Decode the obfuscation key from a server entry.
///
/// The key's length is not checked against the server's 32 bytes: the key is
/// only ever used as the obfuscator's keyword, and the server's own value is
/// what both ends must agree on.
fn decode_obfuscated_key(text: &str) -> Result<Vec<u8>> {
    if text.trim().is_empty() {
        return Err(Error::Config(
            "the server entry has no tacticsRequestObfuscatedKey".into(),
        ));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|error| {
            Error::Config(format!(
                "tacticsRequestObfuscatedKey is not base64: {error}"
            ))
        })?;
    if decoded.is_empty() {
        return Err(Error::Config(
            "the server entry has an empty tacticsRequestObfuscatedKey".into(),
        ));
    }
    Ok(decoded)
}

/// Parse a remote server list.
///
/// Psiphon's remote server list is a JSON array of server entry objects
/// (`psiphon/common/protocol/serverEntry.go:81-120`). Operators publish it
/// in several encodings and the client has to accept whichever one the URL
/// served: the array itself, the array base64-encoded, or the array
/// hex-encoded. Psiphon's own packed list — one hex-encoded entry per line
/// — is accepted as well (`serverEntry.go:1207-1236`).
///
/// The entries are not trusted by this function: [`verify_server_list`]
/// checks each entry's own signature before the entries are used.
///
/// One thing this does not do: Psiphon's own distribution wraps the list in
/// an RSA-signed "authenticated data package"
/// (`psiphon/common/authPackage.go:44-49`), and that package's signature is
/// not checked here, because this crate has no RSA implementation. The
/// per-entry Ed25519 signature is the check that matters for the entries
/// themselves, and it is the one Psiphon's embedded list relies on as well.
pub fn decode_server_list(data: &[u8]) -> Result<Vec<ServerEntry>> {
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Config("the server list is not UTF-8".into()))?;
    let text = text.trim();

    if let Some(entries) = parse_json_entries(text.as_bytes())? {
        return Ok(entries);
    }

    // Base64 and hex are both tried, and the *decoded* bytes must be the
    // JSON: a hex string is also a valid base64 string, so the encoding
    // cannot be told apart by the decode alone.
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(text) {
            if let Some(entries) = parse_json_entries(&decoded)? {
                return Ok(entries);
            }
        }
    }

    if let Ok(decoded) = hex::decode(text) {
        if let Some(entries) = parse_json_entries(&decoded)? {
            return Ok(entries);
        }
    }

    if let Some(entries) = parse_packed_entries(text)? {
        return Ok(entries);
    }

    Err(Error::Config(
        "the server list is not a JSON array, nor a base64 or hex encoding of one".into(),
    ))
}

/// Check every entry of a server list against the configured signing key.
///
/// The remote server list arrives from the network, so it is only usable
/// once every entry's signature verifies. One entry that does not verify
/// rejects the whole list: a list is published as a unit, and a list with a
/// forged entry in it is not a list the operator published.
pub fn verify_server_list(entries: &[ServerEntry], public_key: &str) -> Result<()> {
    for entry in entries {
        entry.verify_signature(public_key)?;
    }
    Ok(())
}

/// Parse a JSON array of server entries, or a single entry.
///
/// Returns `None` when the bytes are not JSON at all, which is how the
/// caller tells the encodings apart: a hex string is also a valid base64
/// string, so the encoding can only be recognized by what the decoded bytes
/// turn out to be.
fn parse_json_entries(data: &[u8]) -> Result<Option<Vec<ServerEntry>>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Ok(None);
    };
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }

    if text.starts_with('[') {
        let entries = ServerEntry::from_json_array(text)?;
        return Ok(Some(entries));
    }

    if text.starts_with('{') {
        let entry = ServerEntry::from_json(text)?;
        return Ok(Some(vec![entry]));
    }

    Ok(None)
}

/// Parse Psiphon's packed list: one hex-encoded entry per line.
fn parse_packed_entries(text: &str) -> Result<Option<Vec<ServerEntry>>> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let decoded = hex::decode(line)
            .map_err(|error| Error::Config(format!("the server list entry is not hex: {error}")))?;
        let entry = ServerEntry::from_json(&String::from_utf8_lossy(&decoded))?;
        entries.push(entry);
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(entries))
    }
}

/// A duration as Psiphon sends it.
///
/// A duration parameter arrives either as a count of nanoseconds — what Go
/// marshals a `time.Duration` to — or as a duration string, which the
/// client accepts for the same parameter (`parameters.go:625-632`).
#[derive(Deserialize)]
#[serde(untagged)]
enum DurationValue {
    Text(String),
    Nanos(i64),
}

impl DurationValue {
    /// The duration this value names.
    fn into_duration(self) -> Result<Duration> {
        match self {
            DurationValue::Text(text) => parse_go_duration(&text),
            DurationValue::Nanos(nanos) => Ok(Duration::from_nanos(nanos.max(0) as u64)),
        }
    }
}

/// Read an optional duration.
fn deserialize_optional_duration<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<DurationValue>::deserialize(deserializer)? {
        None => Ok(None),
        Some(value) => value
            .into_duration()
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

/// Read the parameters, tolerating the server sending none.
fn deserialize_optional_parameters<'de, D>(
    deserializer: D,
) -> std::result::Result<TacticsParameters, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<TacticsParameters>::deserialize(deserializer)?.unwrap_or_default())
}

/// Read a list of tunnel protocols, dropping the names this client does not
/// know.
fn deserialize_tunnel_protocols<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<TunnelProtocol>>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Option::<Vec<String>>::deserialize(deserializer)?;
    Ok(names.map(|names| {
        names
            .iter()
            .filter_map(|name| TunnelProtocol::parse(name))
            .collect()
    }))
}

/// Parse a Go duration string, the syntax `time.ParseDuration` accepts
/// ("24h", "1h30m", "300ms", "0").
///
/// The server writes the tactics TTL this way (`tactics.go:381`), and a
/// duration parameter may arrive as a string too (`parameters.go:625-632`).
fn parse_go_duration(text: &str) -> Result<Duration> {
    let original = text;
    let mut rest = text;

    let negative = match rest.as_bytes().first() {
        Some(b'-') => {
            rest = &rest[1..];
            true
        }
        Some(b'+') => {
            rest = &rest[1..];
            false
        }
        _ => false,
    };

    // Go accepts a bare "0" and nothing else without a unit.
    if rest == "0" {
        return Ok(Duration::ZERO);
    }
    if rest.is_empty() {
        return Err(Error::Protocol(format!("invalid duration \"{original}\"")));
    }
    if negative {
        return Err(Error::Protocol(format!(
            "duration \"{original}\" is negative"
        )));
    }

    let mut total: u128 = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits_end == 0 {
            return Err(Error::Protocol(format!("invalid duration \"{original}\"")));
        }
        let integer: u128 = rest[..digits_end]
            .parse()
            .map_err(|_| Error::Protocol(format!("invalid duration \"{original}\"")))?;
        rest = &rest[digits_end..];

        // The fraction, if any, as a fraction of one unit. Only the first
        // nine digits matter: the unit is a nanosecond, and the rest cannot
        // change the result.
        let mut fraction_numerator: u128 = 0;
        let mut fraction_denominator: u128 = 1;
        if let Some(stripped) = rest.strip_prefix('.') {
            let fraction_end = stripped
                .find(|character: char| !character.is_ascii_digit())
                .unwrap_or(stripped.len());
            let digits: String = stripped[..fraction_end].chars().take(9).collect();
            if digits.is_empty() {
                return Err(Error::Protocol(format!("invalid duration \"{original}\"")));
            }
            fraction_numerator = digits
                .parse()
                .map_err(|_| Error::Protocol(format!("invalid duration \"{original}\"")))?;
            fraction_denominator = 10u128.pow(digits.len() as u32);
            rest = &stripped[fraction_end..];
        }

        // The unit. It runs until the next digit: "1h30m" is an hour and
        // thirty minutes, not an hour and a unit called "h30m".
        let unit_end = rest
            .find(|character: char| character.is_ascii_digit())
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];

        let scale: u128 = match unit {
            "ns" => 1,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(Error::Protocol(format!("unknown duration unit \"{unit}\""))),
        };

        let nanos = integer
            .checked_mul(scale)
            .and_then(|value| value.checked_add(fraction_numerator * scale / fraction_denominator))
            .ok_or_else(|| Error::Protocol(format!("duration \"{original}\" is too large")))?;
        total = total
            .checked_add(nanos)
            .ok_or_else(|| Error::Protocol(format!("duration \"{original}\" is too large")))?;
    }

    if total > u64::MAX as u128 {
        return Err(Error::Protocol(format!(
            "duration \"{original}\" is too large"
        )));
    }
    Ok(Duration::from_nanos(total as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use serde_json::json;

    /// A server key pair, made the way the server's own keys are.
    fn server_keys() -> ([u8; 32], [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        (secret, nacl_box::public_key(&secret))
    }

    /// A deterministic source of randomness, so a failure can be repeated.
    fn test_rng() -> StdRng {
        StdRng::from_seed([7u8; 32])
    }

    /// A server entry that answers tactics requests.
    fn entry(server_public: &[u8; 32], obfuscated_key: &[u8]) -> ServerEntry {
        ServerEntry::from_value(json!({
            "ipAddress": "192.0.2.10",
            "tacticsRequestPublicKey":
                base64::engine::general_purpose::STANDARD.encode(server_public),
            "tacticsRequestObfuscatedKey":
                base64::engine::general_purpose::STANDARD.encode(obfuscated_key)
        }))
        .unwrap()
    }

    #[test]
    fn a_fetch_goes_through_the_callers_transport() {
        let (server_secret, server_public) = server_keys();
        let obfuscated_key = b"tactics-obfuscated-key".to_vec();
        let mut rng = test_rng();
        let mut server_rng = test_rng();

        // The transport is the caller's: here it is the server's half of
        // the exchange, standing in for the HTTP round trip.
        let mut transport = |endpoint: &str, body: &[u8]| -> Result<Vec<u8>> {
            assert_eq!(endpoint, TACTICS_END_POINT);
            let opened = open_tactics_request(body, &server_secret, &obfuscated_key)?;
            seal_tactics_response(
                &json!({
                    "Tag": "tag",
                    "Tactics": {"TTL": "1h", "Probability": 1.0, "Parameters": {}}
                }),
                &opened.peer_public_key,
                &server_secret,
                &obfuscated_key,
                &mut server_rng,
            )
        };

        let request = TacticsRequest::from_keys(&server_public, &obfuscated_key, &mut rng);
        let payload = request
            .fetch(&json!({"stored_tactics_tag": ""}), &mut transport, &mut rng)
            .unwrap();
        assert_eq!(payload.tag, "tag");
        assert_eq!(
            payload.tactics.unwrap().ttl,
            Some(Duration::from_secs(3_600))
        );
    }

    #[test]
    fn a_fetch_against_an_entry_updates_the_record() {
        let (server_secret, server_public) = server_keys();
        let obfuscated_key = b"tactics-obfuscated-key".to_vec();
        let entry = entry(&server_public, &obfuscated_key);
        let mut rng = test_rng();
        let mut server_rng = test_rng();

        let mut transport = |_endpoint: &str, body: &[u8]| -> Result<Vec<u8>> {
            let opened = open_tactics_request(body, &server_secret, &obfuscated_key)?;
            seal_tactics_response(
                &json!({
                    "Tag": "tag",
                    "Tactics": {"TTL": "1h", "Probability": 1.0, "Parameters": {}}
                }),
                &opened.peer_public_key,
                &server_secret,
                &obfuscated_key,
                &mut server_rng,
            )
        };

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut record = TacticsRecord::empty();
        let changed = fetch_tactics(
            &mut record,
            &entry,
            &json!({"stored_tactics_tag": ""}),
            &mut transport,
            &mut rng,
            now,
        )
        .unwrap();

        assert!(changed);
        assert_eq!(record.tag, "tag");
        assert_eq!(record.expiry, now + Duration::from_secs(3_600));
        assert!(record.is_usable(now));
        assert!(!should_fetch(&record, now));
    }

    #[test]
    fn an_entry_without_tactics_keys_is_refused() {
        let entry = ServerEntry::from_value(json!({"ipAddress": "192.0.2.10"})).unwrap();
        let mut rng = test_rng();
        assert!(TacticsRequest::new(&entry, &mut rng).is_err());
    }

    #[test]
    fn a_request_round_trips_through_the_servers_decoder() {
        let (server_secret, server_public) = server_keys();
        let obfuscated_key = b"tactics-obfuscated-key".to_vec();
        let mut rng = test_rng();

        let request = TacticsRequest::from_keys(&server_public, &obfuscated_key, &mut rng);
        let parameters = json!({"stored_tactics_tag": "", "speed_test_samples": []});
        let body = request.encode(&parameters, &mut rng).unwrap();

        let opened = open_tactics_request(&body, &server_secret, &obfuscated_key).unwrap();
        assert_eq!(opened.api_parameters, parameters);
        assert_eq!(
            opened.peer_public_key,
            nacl_box::public_key(&request.ephemeral_secret)
        );
    }

    #[test]
    fn a_response_round_trips_through_the_clients_decoder() {
        let (server_secret, server_public) = server_keys();
        let obfuscated_key = b"tactics-obfuscated-key".to_vec();
        let mut rng = test_rng();

        let request = TacticsRequest::from_keys(&server_public, &obfuscated_key, &mut rng);
        let body = request
            .encode(&json!({"stored_tactics_tag": ""}), &mut rng)
            .unwrap();
        let opened = open_tactics_request(&body, &server_secret, &obfuscated_key).unwrap();

        let payload = json!({
            "Tag": "0123456789abcdef",
            "Tactics": {
                "TTL": "24h",
                "Probability": 1.0,
                "Parameters": {"TunnelConnectTimeout": 30_000_000_000i64}
            }
        });
        let response = seal_tactics_response(
            &payload,
            &opened.peer_public_key,
            &server_secret,
            &obfuscated_key,
            &mut rng,
        )
        .unwrap();

        let decoded = request.decode_response(&response).unwrap();
        assert_eq!(decoded.tag, "0123456789abcdef");
        let tactics = decoded.tactics.unwrap();
        assert_eq!(tactics.ttl, Some(Duration::from_secs(24 * 60 * 60)));
        assert_eq!(tactics.probability, Some(1.0));
        assert_eq!(
            tactics.parameters.tunnel_connect_timeout,
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn a_tampered_request_does_not_open() {
        let (server_secret, server_public) = server_keys();
        let obfuscated_key = b"tactics-obfuscated-key".to_vec();
        let mut rng = test_rng();

        let request = TacticsRequest::from_keys(&server_public, &obfuscated_key, &mut rng);
        let body = request.encode(&json!({}), &mut rng).unwrap();

        // The seed, the seed message's header and the last byte of the
        // sealed payload are all covered: a flipped bit anywhere in them
        // changes what the server reads.
        //
        // The padding between the header and the payload is not: it carries
        // no information, and Go's server does not authenticate it either
        // (`obfuscator.go:520-537`).
        for index in [0, SEED_LENGTH, body.len() - 1] {
            let mut edited = body.clone();
            edited[index] ^= 1;
            assert!(
                open_tactics_request(&edited, &server_secret, &obfuscated_key).is_err(),
                "a flipped bit at {index} must not open"
            );
        }

        // A truncated request does not open either.
        assert!(
            open_tactics_request(&body[..body.len() - 1], &server_secret, &obfuscated_key).is_err()
        );
    }

    #[test]
    fn a_response_does_not_open_as_a_request() {
        // The request and the response use different nonces, so a captured
        // response cannot be replayed as a request.
        let (server_secret, server_public) = server_keys();
        let obfuscated_key = b"tactics-obfuscated-key".to_vec();
        let mut rng = test_rng();

        let request = TacticsRequest::from_keys(&server_public, &obfuscated_key, &mut rng);
        let body = request.encode(&json!({}), &mut rng).unwrap();
        let opened = open_tactics_request(&body, &server_secret, &obfuscated_key).unwrap();

        let response = seal_tactics_response(
            &json!({"Tag": "tag"}),
            &opened.peer_public_key,
            &server_secret,
            &obfuscated_key,
            &mut rng,
        )
        .unwrap();

        assert!(open_tactics_request(&response, &server_secret, &obfuscated_key).is_err());
        assert!(request.decode_response(&body).is_err());
    }

    #[test]
    fn the_seed_message_wrapper_decodes_server_side() {
        let mut rng = test_rng();
        let obfuscated_key = b"the-keyword";
        let payload = b"the payload the server has to read";

        let framed = wrap_seed_message(obfuscated_key, payload, &mut rng);
        assert_eq!(
            unwrap_seed_message(obfuscated_key, &framed).unwrap(),
            payload.to_vec()
        );

        // A different keyword derives a different key, so the magic value
        // does not appear.
        assert!(unwrap_seed_message(b"another-keyword", &framed).is_err());

        // Neither does a truncated message.
        assert!(unwrap_seed_message(obfuscated_key, &framed[..10]).is_err());
    }

    #[test]
    fn an_expired_record_is_not_usable() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut record = TacticsRecord::empty();
        assert!(record.is_expired(now));
        assert!(!record.is_usable(now));
        assert!(should_fetch(&record, now));

        let payload = TacticsPayload {
            tag: "tag".into(),
            tactics: Some(Tactics {
                ttl: Some(Duration::from_secs(3_600)),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(record.apply(&payload, now).unwrap());
        assert!(!record.is_expired(now));
        assert!(record.is_usable(now));
        assert!(!should_fetch(&record, now));

        // The record expires one TTL after it was applied.
        let later = now + Duration::from_secs(3_600);
        assert!(record.is_expired(later));
        assert!(!record.is_usable(later));
        assert!(should_fetch(&record, later));
    }

    #[test]
    fn an_unchanged_tag_only_extends_the_expiry() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut record = TacticsRecord::empty();
        let payload = TacticsPayload {
            tag: "tag".into(),
            tactics: Some(Tactics {
                ttl: Some(Duration::from_secs(60)),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(record.apply(&payload, now).unwrap());
        let expiry = record.expiry;

        // The server sends the same tag with no tactics: the record keeps
        // what it has and only the expiry moves.
        let again = TacticsPayload {
            tag: "tag".into(),
            tactics: None,
            ..Default::default()
        };
        assert!(!record.apply(&again, now + Duration::from_secs(30)).unwrap());
        assert!(record.expiry > expiry);
        assert_eq!(record.tactics.ttl, Some(Duration::from_secs(60)));
    }

    #[test]
    fn a_payload_without_tactics_or_a_ttl_is_refused() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut record = TacticsRecord::empty();

        // No tag at all.
        assert!(record.apply(&TacticsPayload::default(), now).is_err());

        // A new tag but no tactics.
        assert!(record
            .apply(
                &TacticsPayload {
                    tag: "tag".into(),
                    ..Default::default()
                },
                now
            )
            .is_err());

        // Tactics without a TTL.
        assert!(record
            .apply(
                &TacticsPayload {
                    tag: "tag".into(),
                    tactics: Some(Tactics::default()),
                    ..Default::default()
                },
                now
            )
            .is_err());
    }

    #[test]
    fn unknown_fields_and_parameters_are_tolerated() {
        // A server that knows more than this client must not break it.
        let value = json!({
            "Tag": "tag",
            "Tactics": {
                "TTL": "24h",
                "Probability": 1.0,
                "SomeFutureField": {"nested": [1, 2, 3]},
                "Parameters": {
                    "TunnelConnectTimeout": 30_000_000_000i64,
                    "SomeFutureParameter": "whatever",
                    "LimitTunnelProtocols": ["OSSH", "SOME-FUTURE-PROTOCOL"]
                }
            },
            "SomeFuturePayloadField": 7
        });

        let payload: TacticsPayload = serde_json::from_value(value).unwrap();
        assert_eq!(payload.tag, "tag");
        let tactics = payload.tactics.unwrap();
        assert_eq!(tactics.ttl, Some(Duration::from_secs(86_400)));
        assert_eq!(
            tactics.parameters.tunnel_connect_timeout,
            Some(Duration::from_secs(30))
        );
        // The protocol the client does not know is dropped, the one it does
        // is kept.
        assert_eq!(
            tactics.parameters.limit_tunnel_protocols,
            Some(vec![TunnelProtocol::Ossh])
        );
    }

    #[test]
    fn a_duration_is_read_as_nanoseconds_or_as_a_string() {
        let parameters: TacticsParameters = serde_json::from_value(json!({
            "TunnelConnectTimeout": 30_000_000_000i64,
            "EstablishTunnelTimeout": "1h30m",
            "MeekMinPollInterval": "100ms"
        }))
        .unwrap();

        assert_eq!(
            parameters.tunnel_connect_timeout,
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parameters.establish_tunnel_timeout,
            Some(Duration::from_secs(5_400))
        );
        assert_eq!(
            parameters.meek_min_poll_interval,
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn go_durations_are_parsed() {
        assert_eq!(parse_go_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_go_duration("1ns").unwrap(), Duration::from_nanos(1));
        assert_eq!(
            parse_go_duration("300ms").unwrap(),
            Duration::from_millis(300)
        );
        assert_eq!(
            parse_go_duration("1.5h").unwrap(),
            Duration::from_secs(5_400)
        );
        assert_eq!(
            parse_go_duration("24h").unwrap(),
            Duration::from_secs(86_400)
        );
        assert!(parse_go_duration("24").is_err());
        assert!(parse_go_duration("24y").is_err());
        assert!(parse_go_duration("-1h").is_err());
    }

    #[test]
    fn a_server_list_decodes_from_every_encoding() {
        let array = serde_json::to_vec(&json!([{"ipAddress": "192.0.2.10"}])).unwrap();

        assert_eq!(decode_server_list(&array).unwrap().len(), 1);

        let base64 = base64::engine::general_purpose::STANDARD.encode(&array);
        assert_eq!(decode_server_list(base64.as_bytes()).unwrap().len(), 1);

        let hex = hex::encode(&array);
        assert_eq!(decode_server_list(hex.as_bytes()).unwrap().len(), 1);

        // Psiphon's packed list: one hex-encoded entry per line.
        let packed = format!(
            "{}\n{}\n",
            hex::encode(br#"{"ipAddress":"192.0.2.10"}"#),
            hex::encode(br#"{"ipAddress":"192.0.2.11"}"#)
        );
        assert_eq!(decode_server_list(packed.as_bytes()).unwrap().len(), 2);

        assert!(decode_server_list(b"not a list").is_err());
    }

    #[test]
    fn a_server_list_is_verified_against_the_signing_key() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        let private_key =
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_keypair_bytes());

        let mut entry = ServerEntry::from_value(json!({"ipAddress": "192.0.2.10"})).unwrap();
        entry.sign(&public_key, &private_key).unwrap();

        let list = vec![entry];
        verify_server_list(&list, &public_key).unwrap();

        // A different key does not verify.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let other_public =
            base64::engine::general_purpose::STANDARD.encode(other.verifying_key().to_bytes());
        assert!(verify_server_list(&list, &other_public).is_err());
    }
}
