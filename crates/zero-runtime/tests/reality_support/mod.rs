//! Helpers for putting a *real* Xray REALITY server, and a camouflage site
//! behind it, in front of a test or a benchmark.
//!
//! These are the techniques `zero-runtime/tests/xray_oracle.rs` uses, lifted
//! out of that file unchanged in substance so a second caller does not have to
//! copy them. The oracle test keeps its own copies for now — it is the
//! differential test the REALITY server is proved against, and moving its
//! fixtures would put this module on the critical path of the one test that
//! must not change shape. New callers (the handshake benchmark does) should
//! use this module instead.
//!
//! Nothing here is a test target: it is a subdirectory without a `main.rs`, so
//! cargo never compiles it on its own. It is included with `#[path]` by the
//! caller, which means the caller's dependency set is what it must satisfy.
//!
//! What it deliberately does not do: decide whether a handshake is good
//! enough. Every helper either returns the raw thing (a port, a keypair, a
//! child process) or explains why it could not.

#![allow(dead_code)]

use std::collections::HashSet;
use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::net::TcpStream;

/// The one user both ends know, as Xray and Zray spell a VLESS id.
pub const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// The same id as the bytes VLESS puts on the wire, for a client that builds
/// its own request header instead of going through a config.
pub const UUID_BYTES: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
    0x11,
];
/// [`REALITY_SHORT_ID`] as the eight bytes the session id carries.
///
/// A `shortIds` entry is lowercase hex, and every reader of it — the config
/// compiler, Xray — decodes it to bytes before it reaches the client. A client
/// handed the ASCII text instead seals a selector no server authorises, and
/// the handshake fails by falling back to the decoy rather than by reporting
/// an error.
pub fn reality_short_id() -> [u8; 8] {
    let text = REALITY_SHORT_ID.as_bytes();
    let mut out = [0u8; 8];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = (text[index * 2] as char).to_digit(16).expect("hex short id");
        let low = (text[index * 2 + 1] as char)
            .to_digit(16)
            .expect("hex short id");
        *byte = ((high << 4) | low) as u8;
    }
    out
}

/// The decoy SNI both ends agree on.
pub const REALITY_SNI: &str = "www.googletagmanager.com";
/// Eight bytes, the maximum a REALITY shortId can carry.
pub const REALITY_SHORT_ID: &str = "0123456789abcdef";

/// The decoy's TLS material: a loopback certificate for [`REALITY_SNI`] and
/// its key, read from the fixtures the oracle test uses.
pub const DECOY_CERTIFICATE: &str = include_str!("../fixtures/loopback-cert.pem");
pub const DECOY_PRIVATE_KEY: &str = include_str!("../fixtures/loopback-key.pem");
/// A second decoy certificate, much larger than the one above, for the cases
/// where what the decoy sends has to be big enough to be copied — Xray's
/// REALITY server shapes its own flight to the sizes it reads from the decoy,
/// and an ML-DSA-65 certificate is ~3.5 KB, which a small decoy cannot hold.
pub const BIG_DECOY_CERTIFICATE: &str = include_str!("../fixtures/big-decoy-cert.pem");
pub const BIG_DECOY_PRIVATE_KEY: &str = include_str!("../fixtures/big-decoy-key.pem");

/// Locate the official Xray binary, or explain why the comparison cannot be
/// made.
pub fn oracle_binary() -> Result<String, String> {
    if let Some(path) = std::env::var_os("ZRAY_XRAY_BINARY") {
        let path = path.to_string_lossy().into_owned();
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
        return Err(format!(
            "ZRAY_XRAY_BINARY points at {path}, which does not exist"
        ));
    }
    let probe = Command::new("xray").arg("version").output();
    match probe {
        Ok(output) if output.status.success() => Ok("xray".into()),
        _ => Err("no `xray` on PATH and ZRAY_XRAY_BINARY is unset".into()),
    }
}

/// The oracle's first version line, which is what a result table has to quote.
pub fn oracle_version(binary: &str) -> String {
    Command::new(binary)
        .arg("version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.lines().next().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

/// A port that was free a moment ago and has not been handed out twice.
///
/// The listener is dropped immediately, so the port is only *probably* free:
/// it is the same race every test harness has, narrowed by remembering what
/// was already handed out.
pub fn free_port() -> u16 {
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|listener| listener.local_addr().ok())
            .map(|address| address.port())
            .unwrap_or_else(|| panic!("could not bind a loopback port"));
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free port");
}

/// A server process that is killed when it goes out of scope, however the
/// caller leaves, along with the directory its config was written to.
pub struct ServerProcess {
    child: Child,
    directory: PathBuf,
    name: String,
}

impl ServerProcess {
    /// Write `config` into a private directory and start `binary run -c` on
    /// it. Both Xray and Zray accept that invocation.
    ///
    /// The process's output goes to files in the same directory rather than
    /// to /dev/null, because the first question about a server that did not
    /// come up is what it said on the way.
    pub fn spawn(binary: &str, config: Value) -> Self {
        Self::spawn_named(binary, config, binary)
    }

    pub fn spawn_named(binary: &str, config: Value, name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "zray-reality-support-{}-{}-{}",
            std::process::id(),
            name.replace(['/', '.'], "-"),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("could not make {}: {error}", directory.display()));
        let path = directory.join("config.json");
        let mut file = std::fs::File::create(&path)
            .unwrap_or_else(|error| panic!("could not write {}: {error}", path.display()));
        file.write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
            .unwrap();
        file.sync_all().unwrap();

        let out = std::fs::File::create(directory.join("stdout.log")).unwrap();
        let err = std::fs::File::create(directory.join("stderr.log")).unwrap();
        let child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {binary}: {error}"));
        Self {
            child,
            directory,
            name: name.to_owned(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The last `lines` lines the process wrote anywhere, for the failure
    /// message of whatever it was supposed to be serving.
    pub fn tail(&mut self, lines: usize) -> String {
        let mut text = String::new();
        for name in ["stdout.log", "stderr.log"] {
            if let Ok(contents) = std::fs::read_to_string(self.directory.join(name)) {
                if !contents.trim().is_empty() {
                    text.push_str(&format!("--- {name} ---\n{contents}\n"));
                }
            }
        }
        let tail: Vec<&str> = text.lines().rev().take(lines).collect();
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
    }

    /// Whether the process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Whether the process's config file was accepted — the check `zray
    /// check` and `xray run` refuse a bad config with.
    pub fn config_path(&self) -> PathBuf {
        self.directory.join("config.json")
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Wait for something to answer on `address`, for up to ten seconds.
pub async fn wait_for(address: SocketAddr) -> bool {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// An X25519 keypair in the exact encoding Xray expects.
///
/// Generated by the pinned oracle itself rather than by Zray: if the two
/// disagreed about base64 variant, key clamping or byte order, a pair Zray
/// produced would hide the disagreement by being self-consistent.
pub fn oracle_x25519_keypair(binary: &str) -> (String, String) {
    let output = Command::new(binary)
        .arg("x25519")
        .output()
        .expect("the oracle binary should be able to generate an X25519 keypair");
    assert!(
        output.status.success(),
        "`{binary} x25519` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut private = None;
    let mut public = None;
    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        // The wording has changed across releases ("Private key" vs
        // "PrivateKey"), so match on the distinguishing word rather than on an
        // exact label that would silently stop matching.
        if label.contains("private") {
            private = Some(value);
        } else if label.contains("public") || label.contains("password") {
            public = Some(value);
        }
    }
    match (private, public) {
        (Some(private), Some(public)) => (private, public),
        _ => panic!("could not parse an X25519 keypair from `{binary} x25519`:\n{text}"),
    }
}

/// The REALITY server half, for an inbound.
pub fn reality_server_settings(private_key: &str, fallback: SocketAddr) -> Value {
    json!({
        "show": false,
        "dest": fallback.to_string(),
        "xver": 0,
        "serverNames": [REALITY_SNI],
        "privateKey": private_key,
        "shortIds": [REALITY_SHORT_ID],
    })
}

/// A loopback TLS 1.3 server to act as the REALITY decoy.
///
/// The decoy is not optional scenery and it is not only used on failure: the
/// REALITY server asks it what a real visitor sees, and shapes its own session
/// after it. Another Xray instance is the honest choice for it — a decoy built
/// out of Zray's own TLS stack could pass by being shaped the way Zray happens
/// to expect.
pub fn spawn_decoy(binary: &str, port: u16) -> ServerProcess {
    ServerProcess::spawn_named(binary, decoy_config(port), "decoy")
}

/// The same, with a chosen certificate — the larger one for the handshakes
/// whose flight is bigger than the small decoy's certificate.
pub fn spawn_decoy_with(
    binary: &str,
    port: u16,
    certificate: &str,
    key: &str,
) -> ServerProcess {
    ServerProcess::spawn_named(binary, decoy_config_with(port, certificate, key), "decoy")
}

/// The decoy's config: a TLS 1.3 server for [`REALITY_SNI`], with a VLESS
/// inbound so it is a believable site rather than a bare TLS listener.
pub fn decoy_config(port: u16) -> Value {
    decoy_config_with(port, DECOY_CERTIFICATE, DECOY_PRIVATE_KEY)
}

pub fn decoy_config_with(port: u16, certificate: &str, key: &str) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "decoy-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": REALITY_SNI,
                    "certificates": [{
                        "certificate": [certificate],
                        "key": [key],
                    }],
                },
            },
        }],
        "outbounds": [loopback_freedom()],
    })
}

/// Xray v26.7.28 protects proxy inbounds from SSRF by default and blackholes
/// private destinations reached through Freedom. Every target in a loopback
/// harness is a local echo server, so opt out *inside the disposable
/// configuration* just as Xray's own integration scenarios do. Zray accepts
/// the same block, which is what lets one config file serve both binaries.
pub fn loopback_freedom() -> Value {
    json!({
        "protocol": "freedom",
        "settings": {"finalRules": [{"action": "allow"}]},
    })
}

/// The server both binaries are asked to be: VLESS over TCP under REALITY,
/// with the camouflage site behind it.
///
/// One function for both, deliberately. If Xray and Zray were given configs
/// that differed anywhere, a difference in the numbers could be a difference
/// in the settings.
pub fn vless_reality_server_config(port: u16, private_key: &str, decoy: SocketAddr) -> Value {
    vless_reality_server_config_with(port, reality_server_settings(private_key, decoy))
}

/// The same, for a caller that has already built (or extended) the
/// `realitySettings` block and wants that exact block used.
pub fn vless_reality_server_config_with(port: u16, reality_settings: Value) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "reality-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": reality_settings,
            },
        }],
        "outbounds": [loopback_freedom()],
    })
}

/// A loopback service that sends back every byte it is given, so a client can
/// prove that what it sent arrived and came back.
pub async fn echo_service() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback echo listener");
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}
