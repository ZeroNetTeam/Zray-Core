//! The three servers in the table, each behind the same interface.
//!
//! Two of them are separate processes — the official Xray binary and Zray's
//! own binary — and one is the `reality` crate's handshake driven directly
//! over a loopback listener. The separate processes are the comparison that
//! can be accounted for: their CPU is read from `/proc` and belongs to the
//! server alone. The in-process row exists to isolate the handshake from
//! everything a runtime does around it, and it says so in the report.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reality::HandshakeOutcome;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::proc;
use crate::support::{self, ServerProcess};

/// Where a row's CPU time can be read from.
#[derive(Debug, Clone, Copy)]
pub enum Cpu {
    /// A process of its own, so `/proc/<pid>/stat` is the whole server.
    Process(u32),
    /// The server and the client are the same process, so no part of the
    /// process's CPU can be attributed to the server.
    SharedWithTheClient,
}

/// What the in-process server did with every connection it was given.
#[derive(Debug, Clone, Default)]
pub struct Outcomes {
    pub accepted: u64,
    pub fell_back: u64,
    pub rejected: u64,
    pub first_complaint: Option<String>,
}

/// What the camouflage site told the server about its handshake: the sizes of
/// its first flight's records, and of the records it sends afterwards.
pub enum Shapes {
    /// The site completed a handshake and these are the sizes of the records
    /// it sent, flight first.
    Learned {
        flight: Vec<u16>,
        post_handshake: Vec<u16>,
    },
    /// The probe did not get an answer that could be used, so the server sends
    /// its own flight sizes and nothing extra after its handshakes.
    ///
    /// Against a test camouflage site this is the ordinary outcome, and it is
    /// also Xray's: its own start-up probe verifies the site's certificate,
    /// fails against the harness's self-signed one, and files an empty list.
    /// Both implementations then send nothing extra, which is part of what
    /// makes the two rows comparable.
    NotLearned(String),
}

impl Shapes {
    /// The sizes, as the report prints them.
    pub fn note(&self) -> String {
        match self {
            Shapes::Learned {
                flight,
                post_handshake,
            } => format!("flight {flight:?}, then {post_handshake:?}"),
            Shapes::NotLearned(reason) => format!("nothing learned ({reason})"),
        }
    }
}

/// The `reality` crate's server half, accepting on a loopback port.
///
/// Each connection gets its own task, as the runtime gives it, and the
/// outcome of every handshake is counted: a run where the server fell back to
/// the camouflage site would otherwise look like a run of very fast
/// handshakes.
pub struct InProcessServer {
    pub address: SocketAddr,
    accepted: Arc<AtomicU64>,
    fell_back: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    complaints: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl InProcessServer {
    /// Bind a loopback port and start accepting REALITY handshakes.
    ///
    /// `decoy` is the camouflage site behind the server. When it is given, the
    /// server asks it what its handshake looks like — its first flight's
    /// record sizes and what it sends afterwards — and files the answer in
    /// `params.post_handshake`, which is what a deployed Zray inbound does
    /// once at start-up. Doing it here keeps this row's server shaped like the
    /// one that ships, so the row measures the same server the binary runs.
    pub async fn start(
        params: reality::RealityServerParams,
        decoy: Option<SocketAddr>,
        server_name: &str,
    ) -> Result<(Self, Shapes), String> {
        let shapes = match decoy {
            Some(decoy) => match tokio::net::TcpStream::connect(decoy).await {
                Ok(site) => match zero_security::tls13::post_handshake::observe_all_with(
                    site,
                    server_name,
                    zero_security::tls13::post_handshake::SiteTrust::Unverified,
                )
                .await
                {
                    Ok(learned) => {
                        params
                            .post_handshake
                            .set_flight(server_name, 0, &learned.flight);
                        params
                            .post_handshake
                            .set(server_name, 0, &learned.post_handshake);
                        Shapes::Learned {
                            flight: learned.flight,
                            post_handshake: learned.post_handshake,
                        }
                    }
                    Err(failure) => Shapes::NotLearned(failure.to_string()),
                },
                Err(error) => Shapes::NotLearned(format!("connecting to the site: {error}")),
            },
            None => Shapes::NotLearned("no camouflage site configured".into()),
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| format!("binding a loopback port: {error}"))?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;

        let accepted = Arc::new(AtomicU64::new(0));
        let fell_back = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));
        let complaints = Arc::new(Mutex::new(Vec::new()));

        let task = tokio::spawn({
            let params = params.clone();
            let accepted = Arc::clone(&accepted);
            let fell_back = Arc::clone(&fell_back);
            let rejected = Arc::clone(&rejected);
            let complaints = Arc::clone(&complaints);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let params = params.clone();
                    let accepted = Arc::clone(&accepted);
                    let fell_back = Arc::clone(&fell_back);
                    let rejected = Arc::clone(&rejected);
                    let complaints = Arc::clone(&complaints);
                    tokio::spawn(async move {
                        let complaint =
                            match reality::handshake_or_fallback(stream, &params, None).await {
                                HandshakeOutcome::Accepted(_stream) => {
                                    accepted.fetch_add(1, Ordering::Relaxed);
                                    None
                                }
                                HandshakeOutcome::Fallback { failure, .. } => {
                                    fell_back.fetch_add(1, Ordering::Relaxed);
                                    Some(format!("fell back to the camouflage site: {failure}"))
                                }
                                HandshakeOutcome::Rejected(failure) => {
                                    rejected.fetch_add(1, Ordering::Relaxed);
                                    Some(format!("rejected: {failure}"))
                                }
                            };
                        if let Some(complaint) = complaint {
                            let mut complaints = complaints
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if complaints.len() < 5 {
                                complaints.push(complaint);
                            }
                        }
                    });
                }
            }
        });

        Ok((
            Self {
                address,
                accepted,
                fell_back,
                rejected,
                complaints,
                task,
            },
            shapes,
        ))
    }

    pub fn outcomes(&self) -> Outcomes {
        Outcomes {
            accepted: self.accepted.load(Ordering::Relaxed),
            fell_back: self.fell_back.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            first_complaint: self
                .complaints
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .first()
                .cloned(),
        }
    }
}

impl Drop for InProcessServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One server as the harness drives it: where to connect, where its CPU comes
/// from, and what keeps it alive.
pub struct Row {
    pub name: &'static str,
    /// What the row is, in the words the report uses.
    pub note: String,
    pub version: String,
    pub address: SocketAddr,
    pub cpu: Cpu,
    /// Resident bytes of the server process, for context. Not a handshake
    /// claim: it is what each server costs to keep running.
    pub resident_bytes: Option<u64>,
    /// What the camouflage site said it sends after a handshake, for the row
    /// that has to ask it itself.
    pub shapes: Option<Shapes>,
    process: Option<ServerProcess>,
    inprocess: Option<InProcessServer>,
}

impl Row {
    /// The official Xray server, with the VLESS + REALITY inbound the Zray
    /// server is compared against.
    pub fn xray(
        binary: &str,
        port: u16,
        private_key: &str,
        decoy: SocketAddr,
        extras: Extras,
    ) -> Self {
        let mut settings = support::reality_server_settings(private_key, decoy);
        extras.apply(&mut settings);
        let config = support::vless_reality_server_config_with(port, settings.clone());
        let process = ServerProcess::spawn_named(binary, config, "xray");
        Self {
            name: "xray",
            note: "official Xray binary, VLESS + REALITY inbound".into(),
            version: support::oracle_version(binary),
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            cpu: Cpu::Process(process.pid()),
            resident_bytes: proc::resident_bytes(process.pid()),
            shapes: None,
            process: Some(process),
            inprocess: None,
        }
    }

    /// Zray's own binary, on the same config.
    pub fn zray_binary(
        binary: &str,
        port: u16,
        private_key: &str,
        decoy: SocketAddr,
        extras: Extras,
    ) -> Self {
        let mut settings = support::reality_server_settings(private_key, decoy);
        extras.apply(&mut settings);
        let config = support::vless_reality_server_config_with(port, settings.clone());
        let process = ServerProcess::spawn_named(binary, config, "zray");
        Self {
            name: "zray",
            note: "Zray's own binary, same config file as the Xray row".into(),
            version: zray_version(binary),
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            cpu: Cpu::Process(process.pid()),
            resident_bytes: proc::resident_bytes(process.pid()),
            shapes: None,
            process: Some(process),
            inprocess: None,
        }
    }

    /// The `reality` crate's handshake over a loopback listener, inside this
    /// process.
    pub fn zray_in_process(server: InProcessServer, shapes: Shapes) -> Self {
        Self {
            name: "zray-inproc",
            note: "reality::handshake_or_fallback on a loopback listener, in this process".into(),
            version: zray_version_crate(),
            address: server.address,
            cpu: Cpu::SharedWithTheClient,
            resident_bytes: None,
            shapes: Some(shapes),
            process: None,
            inprocess: Some(server),
        }
    }

    /// Whether this row is a separate process, which is what makes its CPU
    /// readable and its liveness checkable.
    pub fn is_external(&self) -> bool {
        self.process.is_some()
    }

    /// Whether this row has a VLESS layer to send a request through. The
    /// in-process row is the handshake alone.
    pub fn server_accepts_vless(&self) -> bool {
        self.inprocess.is_none()
    }

    /// The server's CPU right now, when it is a process of its own.
    pub fn cpu_now(&self) -> Option<Duration> {
        match self.cpu {
            Cpu::Process(pid) => proc::process_cpu(pid),
            Cpu::SharedWithTheClient => None,
        }
    }

    /// Whether the servers this row needs are still running. `None` for the
    /// in-process row, which cannot stop without the harness stopping.
    pub fn alive(&mut self) -> Option<bool> {
        self.process.as_mut().map(ServerProcess::is_running)
    }

    /// The last words of a server that died, for the failure message.
    pub fn log_tail(&mut self, lines: usize) -> String {
        match self.process.as_mut() {
            Some(process) => process.tail(lines),
            None => String::new(),
        }
    }

    /// The in-process server's tally, if this is that row.
    pub fn outcomes(&self) -> Option<Outcomes> {
        self.inprocess.as_ref().map(InProcessServer::outcomes)
    }
}

/// Optional pieces of the `realitySettings` block, so one harness can measure
/// more than one configuration without a second code path.
#[derive(Debug, Clone, Default)]
pub struct Extras {
    /// The ML-DSA-65 seed, when the run is measuring the binding Xray added
    /// for post-quantum clients.
    pub mldsa65_seed: Option<String>,
}

impl Extras {
    fn apply(&self, settings: &mut serde_json::Value) {
        if let Some(seed) = &self.mldsa65_seed {
            settings["mldsa65Seed"] = serde_json::json!(seed);
        }
    }
}

fn zray_version(binary: &str) -> String {
    std::process::Command::new(binary)
        .arg("version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| {
            text.lines()
                .find(|line| !line.trim().is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into())
}

fn zray_version_crate() -> String {
    format!(
        "reality {} (crate in this build)",
        env!("CARGO_PKG_VERSION")
    )
}
