//! The unauthenticated path, over real loopback sockets.
//!
//! What a censor's probe meets on this port is the thing REALITY is judged by,
//! and none of it is visible to a unit test with a `duplex` in the middle: the
//! PROXY header and the replayed hello have to be the *first bytes on a TCP
//! connection*, and the half-close has to be a real `shutdown(Write)` for the
//! target to see the request's end of stream while the response is still
//! coming back. So every test here stands up two loopback pairs — prober and
//! client socket, target socket and camouflage site — and drives the far ends
//! by hand.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use reality::fallback::{
    relay_with_idle_timeout, FallbackError, FallbackLimit, FallbackOutcome, FallbackPolicy,
    Transferred,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use zero_core::Stage;
use zero_security::tls13::record::{record_header, CONTENT_APPDATA, CONTENT_HANDSHAKE};
use zero_security::tls13::{HelloParams, PendingHello};

/// Nothing in this file should need this long. It is here so that a relay that
/// never closes its side fails the test loudly instead of hanging the run:
/// a missing half-close is one of the things these tests exist to catch.
const DEADLINE: Duration = Duration::from_secs(10);

/// A real ClientHello record, as the server would have consumed it before it
/// decided this connection is not REALITY.
///
/// Built through the same `PendingHello` the handshake uses, so the bytes a
/// target receives are the bytes a client put on the wire — including the
/// legacy version byte in the record header, which a hand-written fixture would
/// not have.
fn client_hello_record(server_name: &str) -> Vec<u8> {
    let hello = PendingHello::new(&HelloParams::new(server_name));
    let mut record = record_header(CONTENT_HANDSHAKE, hello.msg.len()).to_vec();
    record[2] = 0x01;
    record.extend_from_slice(&hello.msg);
    record
}

/// What a client sends after the hello the server consumed.
fn application_record(payload: &[u8]) -> Vec<u8> {
    let mut record = record_header(CONTENT_APPDATA, payload.len()).to_vec();
    record.extend_from_slice(payload);
    record
}

/// A connected pair of loopback sockets: the half the crate drives, and the
/// half standing in for the far end.
async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let far_end = TcpStream::connect(listener.local_addr().expect("its address"))
        .await
        .expect("connect to it");
    let (near_end, _) = listener.accept().await.expect("accept the connection");
    (near_end, far_end)
}

/// One fallback in flight.
struct Visit {
    /// The prober's end of the client socket.
    visitor: TcpStream,
    /// The camouflage target's end of the target socket.
    site: TcpStream,
    done: JoinHandle<Result<FallbackOutcome, FallbackError>>,
}

impl Visit {
    /// The bytes the target's side saw, up to end of stream.
    ///
    /// This returning at all is the half-close proof: the relay only closes
    /// the target's write side when the visitor's own stream ended.
    async fn hear_the_target(&mut self, what: &str) -> Vec<u8> {
        read_to_end(&mut self.site, what).await
    }

    /// End the visit the way a browser would — the visitor closes its write
    /// side, the site closes its socket — and hand back how the relay reports
    /// it.
    async fn close(self) -> FallbackOutcome {
        let Visit {
            mut visitor,
            site,
            done,
        } = self;
        let _ = visitor.shutdown().await;
        drop(site);
        waited(done).await
    }
}

/// The relay's outcome, or a failure that says the relay never returned.
async fn waited(done: JoinHandle<Result<FallbackOutcome, FallbackError>>) -> FallbackOutcome {
    timeout(DEADLINE, done)
        .await
        .expect("the relay must return once both sides have closed")
        .expect("the relay task must not panic")
        .expect("the relay must not fail once it has started")
}

/// Read until end of stream, failing loudly rather than hanging.
async fn read_to_end(stream: &mut TcpStream, what: &str) -> Vec<u8> {
    let mut got = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut got))
        .await
        .unwrap_or_else(|_| panic!("{what} never saw end of stream"))
        .unwrap_or_else(|error| panic!("{what} could not be read: {error}"));
    got
}

/// Read exactly `len` bytes, failing loudly rather than hanging.
async fn read_exact(stream: &mut TcpStream, len: usize, what: &str) -> Vec<u8> {
    let mut got = vec![0u8; len];
    timeout(DEADLINE, stream.read_exact(&mut got))
        .await
        .unwrap_or_else(|_| panic!("{what} never received {len} bytes"))
        .unwrap_or_else(|error| panic!("{what} could not be read: {error}"));
    got
}

/// Start one fallback between two loopback pairs.
async fn start(
    policy: FallbackPolicy,
    hello: Vec<u8>,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
) -> Visit {
    start_with_idle(
        policy,
        hello,
        peer,
        local,
        // Long enough that it is never what ends a test which closes both
        // sides itself.
        Some(Duration::from_secs(30)),
    )
    .await
}

async fn start_with_idle(
    policy: FallbackPolicy,
    hello: Vec<u8>,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    idle: Option<Duration>,
) -> Visit {
    let (client, visitor) = loopback_pair().await;
    let (target, site) = loopback_pair().await;
    let done = tokio::spawn(async move {
        relay_with_idle_timeout(client, target, &policy, &hello, peer, local, idle).await
    });
    Visit {
        visitor,
        site,
        done,
    }
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address literal")
}

/// A `xver: 1` server writes the specification's text line for the visitor's
/// real address, and then the hello it consumed, byte for byte.
#[tokio::test]
async fn a_prober_meets_the_version_one_proxy_header_then_its_own_hello() {
    let (peer, local) = (addr("192.0.2.1:56324"), addr("198.51.100.7:443"));
    let hello = client_hello_record("camouflage.example");
    let mut visit = start(
        FallbackPolicy::new(1, FallbackLimit::unlimited(), FallbackLimit::unlimited()),
        hello.clone(),
        Some(peer),
        Some(local),
    )
    .await;

    // The header the specification describes, and the header the workspace
    // encoder writes: a target has to read whichever a Zray proxy would send.
    let mut expected = b"PROXY TCP4 192.0.2.1 198.51.100.7 56324 443\r\n".to_vec();
    expected.extend_from_slice(&hello);
    let mut encoded = zero_protocol::proxy_protocol::encode(1, Some(peer), Some(local));
    encoded.extend_from_slice(&hello);
    assert_eq!(
        expected, encoded,
        "the encoder and the specification disagree"
    );

    let seen = read_exact(&mut visit.site, expected.len(), "the target").await;
    assert_eq!(
        seen, expected,
        "the target must read exactly the PROXY header and then the visitor's hello"
    );

    let outcome = visit.close().await;
    // The replayed hello is not relayed traffic, and the visitor sent nothing
    // else, so the relay moved nothing.
    assert_eq!(outcome.transferred, Transferred::default());
    assert_eq!(outcome.error, None);
}

/// The same for `xver: 2`, with the addresses of a real IPv6 visitor: the
/// twelve-byte signature, the version and command byte, the family and length,
/// then the two addresses and the two ports.
#[tokio::test]
async fn a_prober_meets_the_version_two_proxy_header_byte_for_byte() {
    let (peer, local) = (addr("[2001:db8::1]:56324"), addr("[2001:db8::2]:443"));
    let hello = client_hello_record("camouflage.example");
    let mut visit = start(
        FallbackPolicy::new(2, FallbackLimit::unlimited(), FallbackLimit::unlimited()),
        hello.clone(),
        Some(peer),
        Some(local),
    )
    .await;

    let mut literal = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    // Version 2, PROXY command; INET6, stream; 36 bytes of address.
    literal.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
    literal.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets());
    literal.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).octets());
    literal.extend_from_slice(&56324u16.to_be_bytes());
    literal.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(literal.len(), 52, "12 + 4 + 16 + 16 + 2 + 2");

    let mut expected = zero_protocol::proxy_protocol::encode(2, Some(peer), Some(local));
    assert_eq!(
        expected, literal,
        "the encoder and the specification disagree"
    );
    expected.extend_from_slice(&hello);

    let seen = read_exact(&mut visit.site, expected.len(), "the target").await;
    assert_eq!(seen, expected);

    let outcome = visit.close().await;
    assert_eq!(outcome.transferred, Transferred::default());
    assert_eq!(outcome.error, None);
}

/// With no address to name — behind a load balancer whose own header was never
/// read — a version 2 header says `LOCAL` rather than inventing one.
#[tokio::test]
async fn a_visitor_with_no_known_address_is_announced_as_local() {
    let hello = client_hello_record("camouflage.example");
    let mut visit = start(
        FallbackPolicy::new(2, FallbackLimit::unlimited(), FallbackLimit::unlimited()),
        hello.clone(),
        None,
        None,
    )
    .await;

    let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    expected.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&hello);
    assert_eq!(
        expected,
        {
            let mut encoded = zero_protocol::proxy_protocol::encode(2, None, None);
            encoded.extend_from_slice(&hello);
            encoded
        },
        "the encoder and the specification disagree"
    );

    let seen = read_exact(&mut visit.site, expected.len(), "the target").await;
    assert_eq!(seen, expected);
    visit.close().await;
}

/// Every byte the visitor sent after the consumed record reaches the target,
/// in order, and nothing else does: with `xver` 0 there is no header in front
/// of the hello, and the replayed record is not re-framed.
#[tokio::test]
async fn the_hello_and_every_byte_after_it_reach_the_target_in_order() {
    let hello = client_hello_record("camouflage.example");
    // A payload that includes the bytes a proxy protocol parser looks for, so
    // a header leaking into the stream would be caught by a byte comparison
    // rather than only by the first byte.
    let payload = [
        0x16u8, 0x03, 0x03, b'\r', b'\n', b'\r', b'\n', 0x00, b'Q', b'U', b'I', b'T', 0x0a, 0xff,
    ];
    let rest = application_record(&payload);
    let mut visit = start(FallbackPolicy::default(), hello.clone(), None, None).await;

    // Two writes, as a client sending a second flight would produce them.
    let (first, second) = rest.split_at(rest.len() / 2);
    visit.visitor.write_all(first).await.unwrap();
    visit.visitor.write_all(second).await.unwrap();
    visit.visitor.shutdown().await.unwrap();

    let mut expected = hello.clone();
    expected.extend_from_slice(&rest);
    assert_eq!(expected[0], 0x16, "a ClientHello record, not a header");
    let seen = visit.hear_the_target("the target").await;
    assert_eq!(seen, expected, "the target read something else entirely");

    let outcome = visit.close().await;
    assert_eq!(outcome.transferred.uploaded, rest.len() as u64);
    assert_eq!(outcome.error, None);
}

/// The visitor's half-close is a half-close: the target sees end of stream
/// *and* its answer still reaches the visitor.
///
/// Both halves of that are load-bearing. Without the first, a site waiting for
/// a request's end never answers at all; without the second, the answer is
/// thrown away, and the probe sees a connection that dies the moment it asks
/// for something.
#[tokio::test]
async fn the_relay_half_closes_the_target_and_keeps_the_response_flowing() {
    let hello = client_hello_record("camouflage.example");
    let rest = application_record(b"GET / HTTP/1.1\r\nHost: camouflage.example\r\n\r\n");
    let response = application_record(&vec![0x5au8; 4096]);
    let mut visit = start(FallbackPolicy::default(), hello.clone(), None, None).await;

    visit.visitor.write_all(&rest).await.unwrap();
    // Everything below happens after the visitor's FIN.
    visit.visitor.shutdown().await.unwrap();

    let mut request = hello.clone();
    request.extend_from_slice(&rest);
    assert_eq!(
        visit.hear_the_target("the target").await,
        request,
        "the target must see the request's end of stream"
    );

    visit.site.write_all(&response).await.unwrap();
    visit.site.shutdown().await.unwrap();
    let answered = read_to_end(&mut visit.visitor, "the visitor").await;
    assert_eq!(
        answered, response,
        "the answer must survive the visitor's FIN"
    );

    let outcome = visit.close().await;
    assert_eq!(outcome.transferred.uploaded, rest.len() as u64);
    assert_eq!(outcome.transferred.downloaded, response.len() as u64);
    assert_eq!(outcome.stage, Stage::BidirectionalConfirmed);
    assert_eq!(outcome.error, None, "a visitor leaving is not a failure");
    assert!(outcome.is_useful());
}

/// `limitFallbackUpload` holds what the visitor sends to the target.
///
/// Nothing here can pass without the limit: at the configured rate the second
/// half of this payload cannot arrive before the assertion's floor, and a
/// relay that ignored the limit delivers it in microseconds.
#[tokio::test]
async fn the_upload_limit_holds_the_visitor_to_the_configured_rate() {
    let hello = client_hello_record("camouflage.example");
    let payload = vec![0x33u8; 128 * 1024];
    let rest = application_record(&payload);
    let mut visit = start(
        FallbackPolicy::new(
            0,
            FallbackLimit::new(0, 64 * 1024, 64 * 1024),
            FallbackLimit::unlimited(),
        ),
        hello.clone(),
        None,
        None,
    )
    .await;

    let started = Instant::now();
    visit.visitor.write_all(&rest).await.unwrap();
    visit.visitor.shutdown().await.unwrap();
    let mut expected = hello.clone();
    expected.extend_from_slice(&rest);
    assert_eq!(visit.hear_the_target("the target").await, expected);
    let elapsed = started.elapsed();

    // 64 KiB of burst pass at once; the other 64 KiB cannot before one second
    // at 64 KiB a second.
    assert!(
        elapsed >= Duration::from_millis(700),
        "the upload limit did nothing: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "the upload limit held far longer than it should: {elapsed:?}"
    );

    let outcome = visit.close().await;
    assert_eq!(outcome.transferred.uploaded, rest.len() as u64);
}

/// `afterBytes` is what makes a fallback look like a real site: the first bytes
/// of an exchange pass untouched.
///
/// The rate after the free part is one byte per second, so a relay that ignored
/// `afterBytes` would not finish this test today.
#[tokio::test]
async fn the_bytes_before_after_bytes_pass_at_once() {
    let hello = client_hello_record("camouflage.example");
    let payload = vec![0x44u8; 128 * 1024];
    let rest = application_record(&payload);
    let mut visit = start(
        FallbackPolicy::new(
            0,
            FallbackLimit::new(128 * 1024, 1, 1),
            FallbackLimit::unlimited(),
        ),
        hello.clone(),
        None,
        None,
    )
    .await;

    let started = Instant::now();
    visit.visitor.write_all(&rest).await.unwrap();
    visit.visitor.shutdown().await.unwrap();
    let mut expected = hello.clone();
    expected.extend_from_slice(&rest);
    assert_eq!(visit.hear_the_target("the target").await, expected);

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "the free part was shaped anyway: {elapsed:?}"
    );
    let outcome = visit.close().await;
    assert_eq!(outcome.transferred.uploaded, rest.len() as u64);
}

/// The two limits belong to two directions, and this is the test that catches
/// them being installed the wrong way round: a large exchange each way, with
/// the upload free and the download held to a rate.
#[tokio::test]
async fn the_download_limit_shapes_the_target_and_leaves_the_visitor_alone() {
    let hello = client_hello_record("camouflage.example");
    let request = application_record(&vec![0x33u8; 128 * 1024]);
    let response = application_record(&vec![0x5au8; 128 * 1024]);
    let mut visit = start(
        FallbackPolicy::new(
            0,
            FallbackLimit::unlimited(),
            FallbackLimit::new(0, 64 * 1024, 64 * 1024),
        ),
        hello.clone(),
        None,
        None,
    )
    .await;

    let started = Instant::now();
    visit.visitor.write_all(&request).await.unwrap();
    visit.visitor.shutdown().await.unwrap();
    let mut expected = hello.clone();
    expected.extend_from_slice(&request);
    assert_eq!(visit.hear_the_target("the target").await, expected);
    let uploaded = started.elapsed();
    assert!(
        uploaded < Duration::from_millis(700),
        "the download limit shaped the visitor's uploads: {uploaded:?}"
    );

    let started = Instant::now();
    visit.site.write_all(&response).await.unwrap();
    visit.site.shutdown().await.unwrap();
    assert_eq!(
        read_to_end(&mut visit.visitor, "the visitor").await,
        response
    );
    let downloaded = started.elapsed();
    assert!(
        downloaded >= Duration::from_millis(700),
        "the download limit did nothing: {downloaded:?}"
    );

    let outcome = visit.close().await;
    assert_eq!(outcome.transferred.uploaded, request.len() as u64);
    assert_eq!(outcome.transferred.downloaded, response.len() as u64);
}

/// A visitor that sends its hello and then says nothing at all must not pin the
/// socket: a probe that gives up is a probe that is about to open another one.
#[tokio::test]
async fn a_visitor_that_says_nothing_is_closed_at_the_idle_limit() {
    let hello = client_hello_record("camouflage.example");
    let mut visit = start_with_idle(
        FallbackPolicy::default(),
        hello.clone(),
        None,
        None,
        Some(Duration::from_millis(300)),
    )
    .await;

    // The target still gets the hello — the fallback happened, it just went
    // nowhere.
    assert_eq!(
        read_exact(&mut visit.site, hello.len(), "the target").await,
        hello
    );

    let started = Instant::now();
    let outcome = timeout(DEADLINE, visit.done)
        .await
        .expect("a silent visit must be closed")
        .expect("the relay task must not panic")
        .expect("a silent visit is not a startup failure");
    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(5), "closed late: {waited:?}");

    assert_eq!(outcome.transferred, Transferred::default());
    assert_eq!(outcome.stage, Stage::RequestSent);
    assert!(!outcome.is_useful());
    // Nothing ever moved, so there is nothing to blame on the path.
    assert_eq!(outcome.error, None);
}

/// Once the site has finished, a visitor that never answers is closed within
/// the half-close limit rather than held for the whole idle period.
#[tokio::test]
async fn a_visit_the_site_has_finished_with_is_closed_soon_after() {
    let hello = client_hello_record("camouflage.example");
    let answer = b"hello from the site";
    let mut visit = start(FallbackPolicy::default(), hello.clone(), None, None).await;
    assert_eq!(
        read_exact(&mut visit.site, hello.len(), "the target").await,
        hello
    );

    visit.site.write_all(answer).await.unwrap();
    visit.site.shutdown().await.unwrap();
    assert_eq!(
        read_exact(&mut visit.visitor, answer.len(), "the visitor").await,
        answer
    );

    let started = Instant::now();
    let outcome = timeout(DEADLINE, visit.done)
        .await
        .expect("a finished visit must end")
        .expect("the relay task must not panic")
        .expect("a finished visit is not a startup failure");
    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(5), "held for {waited:?}");
    assert_eq!(outcome.transferred.downloaded, answer.len() as u64);
    assert_eq!(outcome.error, None, "a finished flow is not a failure");
}
