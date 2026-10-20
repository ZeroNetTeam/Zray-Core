//! The key material a REALITY server needs, in Xray's encodings.
//!
//! A server's `realitySettings` carries three secrets and one selector: an
//! X25519 private key (`privateKey`), an optional ML-DSA-65 seed
//! (`mldsa65Seed`), an optional allowlist of `shortIds`, and the allowlist of
//! `serverNames` it is willing to camouflage. Everything here is the same
//! arithmetic the client's share link carries, so the primitives live in
//! `zero-security::keys` — one implementation for both sides — and this module
//! is the server-facing name for them, so a server crate can depend on
//! `reality` alone.
//!
//! The encodings are Xray's, byte for byte:
//!
//! * `xray x25519` prints the private key as unpadded URL-safe base64 of the
//!   32-byte scalar, and the public key the same way. The private key is
//!   clamped before it is written, so the key in the config is the key that is
//!   used.
//! * `xray mldsa65` prints a seed and the verify key derived from it, both
//!   unpadded URL-safe base64. The seed is a secret and stays on the server;
//!   only the verify key goes to clients as `mldsa65Verify`.
//! * A `shortIds` entry is lowercase hex of up to 8 bytes, and Xray pads it on
//!   the right with zeros to the 8 bytes the session id carries, so `"ab"` and
//!   `"ab000000000000"` are the same selector and `""` selects the all-zero
//!   one. There is no wildcard: a server accepts exactly the selectors it
//!   lists, which is why a fresh deployment usually writes one of each.
//!
//! The module also carries the two `realitySettings` switches that decide what
//! a running server says about a handshake, because both are about this key
//! material and neither may put a key in a log:
//!
//! * [`KeyLog`] is `masterKeyLog`: the NSS file a capture of this server's own
//!   traffic can be decrypted with. It is the one place a secret is written out
//!   on purpose, and [`KeyLog`]'s documentation says plainly what that costs.
//! * [`ClientReport`] is `show`: the per-connection line of fields the handshake
//!   decoded. Xray's `show` also prints the first 16 bytes of the authentication
//!   key it derived (`RL/tls.go:238-240`), which the rule this workspace follows
//!   forbids (`crates/zero-runtime/tests/log_privacy.rs`); the report is a type
//!   a key cannot be put into, rather than a formatter that has to remember not
//!   to.

use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::path::Path;

pub use zero_security::keys::{
    mldsa65, mldsa65_from_seed, short_id, x25519, x25519_from_private, MlDsa65Pair, X25519Pair,
};

/// The NSS key-log labels a TLS 1.3 handshake writes, spelled as Go spells them
/// (`RL/common.go:1563-1567`) so the file opens in the tools operators already
/// use.
pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
pub const CLIENT_TRAFFIC_SECRET_0: &str = "CLIENT_TRAFFIC_SECRET_0";
pub const SERVER_TRAFFIC_SECRET_0: &str = "SERVER_TRAFFIC_SECRET_0";

/// The file `realitySettings.masterKeyLog` names: every handshake's TLS 1.3
/// traffic secrets, appended one per line in the NSS key log format, so that a
/// packet capture of this server can be decrypted in Wireshark.
///
/// **What writing this file exposes.** A key log is not a diagnostic trail, it
/// is a decryption key for the capture: anyone who can read the file — the
/// operator, but also a backup, a support bundle, a sync client, another user on
/// the host if the file's mode is relaxed — can decrypt every session recorded
/// while it was being written, for *every* user of the server, not only the one
/// being debugged. It is worth that only while chasing a handshake that fails on
/// the wire, which is why the default is off: an absent, empty or `"none"`
/// `masterKeyLog` writes nothing at all. Enable it for one investigation, on a
/// host whose disk and backups are yours, then disable it and delete the file.
///
/// Xray opens the file `O_CREATE|O_RDWR|O_APPEND` with mode 0644 and, when that
/// fails, logs the error and runs *without* a key log
/// (`XC/transport/internet/reality/config.go:61-72`). This port keeps the append
/// mode, and keeps the "the server still runs" decision in the caller's hands by
/// returning the open error instead of absorbing it — a REALITY listener should
/// not refuse to start because a debug file is unwritable — but creates the file
/// 0600, the mode the rustls key log in this workspace uses
/// (`zero-security/src/tls.rs`): world-readable session secrets are a worse
/// default than a file the operator has to loosen.
pub struct KeyLog {
    path: Box<str>,
    file: Mutex<File>,
}

impl std::fmt::Debug for KeyLog {
    /// The path, and never the handle or a line of what has been written to it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyLog").field("path", &self.path).finish()
    }
}

impl KeyLog {
    /// Open `path`, creating it if it is not there, and append to it. Several
    /// handshakes write through one `KeyLog`, so the caller opens it once per
    /// listener rather than once per connection.
    pub fn open(path: &str) -> Result<Self, String> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .map(|file| Self {
                path: Box::from(path),
                file: Mutex::new(file),
            })
            .map_err(|error| format!("masterKeyLog {path}: {error}"))
    }

    /// The file this log appends to.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// One NSS line: the label, the handshake's client random and the secret,
    /// all in lowercase hex, exactly as Go writes them (`RL/common.go:1570-1582`).
    ///
    /// The error is returned rather than swallowed or fatal: Go fails the whole
    /// handshake when the key log cannot be written, and the rustls key log in
    /// this workspace ignores it. A debugging aid that can drop live connections
    /// when a disk fills is the worse of the two, so the caller decides, and the
    /// handshake has no business consulting it at all.
    pub fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) -> std::io::Result<()> {
        let line = format!(
            "{label} {} {}\n",
            hex::encode(client_random),
            hex::encode(secret)
        );
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        file.write_all(line.as_bytes())
    }

    /// The two lines a REALITY handshake contributes as soon as its handshake
    /// keys exist (`RL/handshake_server_tls13.go:884-893`), in Go's order.
    pub fn log_handshake_secrets(
        &self,
        client_random: &[u8],
        client: &[u8],
        server: &[u8],
    ) -> std::io::Result<()> {
        self.log(CLIENT_HANDSHAKE_TRAFFIC_SECRET, client_random, client)?;
        self.log(SERVER_HANDSHAKE_TRAFFIC_SECRET, client_random, server)
    }

    /// The two lines it contributes once the handshake completes
    /// (`RL/handshake_server_tls13.go:1031-1040`), in Go's order.
    pub fn log_application_secrets(
        &self,
        client_random: &[u8],
        client: &[u8],
        server: &[u8],
    ) -> std::io::Result<()> {
        self.log(CLIENT_TRAFFIC_SECRET_0, client_random, client)?;
        self.log(SERVER_TRAFFIC_SECRET_0, client_random, server)
    }
}

/// One connection that got as far as opening a REALITY seal, as Xray's
/// `realitySettings.show` reports it.
///
/// Xray prints the peer's address when the connection arrives
/// (`RL/tls.go:164-166`), the first 16 bytes of the authentication key it
/// derived and the AEAD it built from it (`:238-240`), then the client version,
/// clock and short id it decoded from the session id (`:252-256`). The key line
/// is the one this port drops: what a client authenticates with is exactly what
/// a log must not hold, and a type with no field for a key cannot leak one by
/// accident later. The fields below answer the question an operator actually
/// has — *why did this client fall back?* — and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReport {
    /// Where the connection came from, as the server sees it (behind a load
    /// balancer, the address its own inbound PROXY header named).
    pub peer: SocketAddr,
    /// The client version the sealed session id carried, `major.minor.patch`.
    pub client_version: [u8; 3],
    /// The client's clock, as its hello claimed it. A REALITY client whose
    /// clock is outside `maxTimeDiff` is refused, so this and the skew against
    /// this server's own clock are the first thing to look at when a client
    /// that used to work stops working.
    pub client_clock: SystemTime,
    /// The short id the client selected, as it sent it: up to eight bytes, and
    /// empty for the all-zero selector. Printed as hex, in the same spelling
    /// `shortIds` is configured with, so the line can be compared with the
    /// config that produced it.
    pub short_id: Box<[u8]>,
    /// Whether the version, clock and short-id checks all passed — Xray's
    /// conjunction (`RL/tls.go:257-261`). False is not an error: it is the
    /// reason a client that "connects" is quietly handed to the camouflage
    /// site, and therefore the one field to read first.
    pub authenticated: bool,
}

impl ClientReport {
    /// The log line, as one line, with the client's clock skew measured against
    /// `now`.
    ///
    /// One line and not four: a log filter keeps a line or drops it, and Go's
    /// four `Printf`s (`RL/tls.go:164-166`, `:252-256`) interleave with every
    /// other connection's under load. The level belongs to the caller, and
    /// `show` is a switch an operator turns on and reads, so `info` is the
    /// level that keeps it visible without turning on everything else.
    pub fn line(&self, now: SystemTime) -> String {
        let seconds = self
            .client_clock
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0);
        // The hello carries a 32-bit seconds value, so the clock is always
        // after 1970; a clock that is not means nothing here, and the skew is
        // still worth printing.
        let skew = match now.duration_since(self.client_clock) {
            Ok(ahead) => ahead,
            Err(behind) => behind.duration(),
        };
        format!(
            "REALITY remoteAddr: {} clientVer: {}.{}.{} clientTime: {}s skew: {}s shortId: {} authenticated: {}",
            self.peer,
            self.client_version[0],
            self.client_version[1],
            self.client_version[2],
            seconds,
            skew.as_secs(),
            hex::encode(&self.short_id),
            self.authenticated,
        )
    }
}

impl std::fmt::Display for ClientReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.line(SystemTime::now()))
    }
}

/// A file under the workspace's `target/`, unique to the test that asks for it,
/// so that two runs in parallel cannot write over each other. Every test that
/// uses one deletes it before it returns; a test that fails leaves its file
/// behind, which is what its author wants to look at.
#[cfg(test)]
pub(crate) fn scratch_path(what: &str) -> std::path::PathBuf {
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&target).expect("the workspace target directory");
    target.join(format!("reality-{what}-{}.log", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_pair_reads_back_as_the_key_it_was_made_from() {
        let pair = x25519();
        let again = x25519_from_private(&pair.private_key).expect("the private key parses back");
        assert_eq!(again.public_key, pair.public_key);
    }

    #[test]
    fn a_generated_short_id_is_hex_and_fits_the_session_id() {
        for bytes in 1..=8 {
            let id = short_id(bytes).expect("1 to 8 bytes is a valid short id");
            assert_eq!(id.len(), bytes * 2);
            assert!(id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        // The generator will not make a selector that cannot be told apart
        // from an unwritten one; a config that wants the all-zero selector
        // writes `""` by hand, as Xray's own docs do.
        assert!(short_id(0).is_err());
        assert!(short_id(9).is_err(), "9 bytes cannot fit the session id");
    }

    #[test]
    fn mldsa65_material_round_trips_through_its_seed() {
        let pair = mldsa65();
        let again = mldsa65_from_seed(&pair.seed).expect("the seed parses back");
        assert_eq!(again.verify, pair.verify);
    }

    /// A file under the workspace's `target/`, unique to the test that asks for
    /// it, so two runs in parallel cannot write over each other. Every test that
    /// uses one deletes it before it returns.
    fn scratch_path(what: &str) -> std::path::PathBuf {
        let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        std::fs::create_dir_all(&target).expect("the workspace target directory");
        target.join(format!("reality-{what}-{}.log", std::process::id()))
    }

    #[test]
    fn the_key_log_file_holds_the_four_lines_a_capture_needs() {
        // The artefact itself, because a key log that is written in the wrong
        // shape is worse than none: an operator would chase a capture that
        // cannot open and blame the handshake. The labels, the order and the
        // hex are Go's (`RL/common.go:1563-1582`).
        let path = scratch_path("keys-keylog");
        let log = KeyLog::open(&path.to_string_lossy()).expect("the target directory is writable");
        assert_eq!(log.path(), path.to_string_lossy());

        let client_random = [0x11u8; 32];
        let (client_handshake, server_handshake) = ([0x22u8; 32], [0x33u8; 32]);
        let (client_application, server_application) = ([0x44u8; 32], [0x55u8; 32]);
        log.log_handshake_secrets(&client_random, &client_handshake, &server_handshake)
            .expect("the file was opened for appending");
        log.log_application_secrets(&client_random, &client_application, &server_application)
            .expect("the file was opened for appending");

        let written = std::fs::read_to_string(&path).expect("the key log was written");
        assert_eq!(
            written,
            format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {r} {c}\n\
                 SERVER_HANDSHAKE_TRAFFIC_SECRET {r} {s}\n\
                 CLIENT_TRAFFIC_SECRET_0 {r} {ca}\n\
                 SERVER_TRAFFIC_SECRET_0 {r} {sa}\n",
                r = hex::encode(client_random),
                c = hex::encode(client_handshake),
                s = hex::encode(server_handshake),
                ca = hex::encode(client_application),
                sa = hex::encode(server_application),
            )
        );
        // A second handshake appends rather than truncates: one file collects
        // many sessions, which is the point of it.
        log.log_handshake_secrets(&client_random, &client_handshake, &server_handshake)
            .expect("appending works");
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("the key log is still readable")
                .lines()
                .count(),
            6
        );
        // A key log holds secrets, so nothing that prints one may print them.
        let printed = format!("{log:?}");
        assert!(printed.contains("KeyLog"), "{printed}");
        assert!(
            !printed.contains(&hex::encode(server_application)),
            "a secret reached a Debug print: {printed}"
        );

        std::fs::remove_file(&path).expect("the test's own key log is removable");
    }

    #[test]
    fn the_show_line_carries_the_client_fields_and_cannot_carry_a_key() {
        // Xray's `show` prints `AuthKey[:16]` (`RL/tls.go:238-240`); this port
        // keeps the fields an operator needs to explain a fallback and drops
        // that one. The exact line is asserted so that a field added later
        // cannot quietly be a key: the test fails and its author has to justify
        // the new token.
        let peer: SocketAddr = "192.0.2.1:56324".parse().expect("an address");
        let report = ClientReport {
            peer,
            client_version: [26, 3, 27],
            client_clock: UNIX_EPOCH + std::time::Duration::from_secs(1_760_930_680),
            short_id: Box::from([0xab, 0xbc, 0xcc, 0xdd]),
            authenticated: true,
        };
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1_760_930_682);

        assert_eq!(
            report.line(now),
            "REALITY remoteAddr: 192.0.2.1:56324 clientVer: 26.3.27 \
             clientTime: 1760930680s skew: 2s shortId: abbcccdd authenticated: true"
        );
        // A clock ahead of this server's reads as a skew too, not as an error.
        let ahead = ClientReport {
            client_clock: UNIX_EPOCH + std::time::Duration::from_secs(1_760_930_700),
            ..report.clone()
        };
        assert!(ahead.line(now).contains("skew: 18s"), "{}", ahead.line(now));
        // The line is one line — a filter keeps it or drops it, and Go's four
        // `Printf`s interleave under load.
        assert_eq!(report.line(now).lines().count(), 1);
        assert!(!report.line(now).contains('\n'));

        // Nothing key-shaped: a secret is 32 bytes, so in this file's spelling
        // it is 64 hex characters, and the longest token the line may carry is
        // the eight-byte short id.
        let line = report.line(now);
        let key_shaped: Vec<&str> = line
            .split_whitespace()
            .filter(|token| token.len() > 16)
            .collect();
        assert!(
            key_shaped.is_empty(),
            "a token long enough to be a secret: {key_shaped:?}"
        );
        assert!(!line.contains(&hex::encode([0x5au8; 32])));
        // And the same through `Display`, which is what a caller logs.
        let displayed = report.to_string();
        assert!(
            displayed.starts_with("REALITY remoteAddr: 192.0.2.1:56324"),
            "{displayed}"
        );
        assert!(displayed.contains("authenticated: true"), "{displayed}");

        // A fallback is reported, not hidden: the client that fails the checks
        // is the one an operator is looking for.
        let refused = ClientReport {
            authenticated: false,
            ..report
        };
        assert!(
            refused.line(now).contains("authenticated: false"),
            "{}",
            refused.line(now)
        );
    }
}
