//! The Psiphon outbound.
//!
//! Without the `psiphon` feature the outbound must still parse and then refuse
//! to connect with a sentence that says why. With the feature, the loopback
//! test (ignored by default: it needs the local `psiphond` harness) runs a
//! whole request through the outbound to a test origin, which is what proves
//! the wiring — configuration, client, carrier, tunnel, channel — rather than
//! any one piece of it.
//!
//! ```text
//! # one shell, because the harness server must live as long as the test:
//! .research/psiphon-server-harness/run.sh --origin
//! ZERO_PSIPHON_SERVER_ENTRY=$(pwd)/.research/psiphon-server-harness/config/server-entry.json \
//!   cargo test -p zero-runtime --features psiphon --test psiphon_outbound -- --ignored --nocapture
//! ```

use zero_core::{Address, Destination};

#[cfg(not(feature = "psiphon"))]
#[tokio::test]
async fn a_build_without_psiphon_support_says_so() {
    // The configuration parses in every build: only the connection needs the
    // feature, so a config file written for one build works in the other.
    let outbound = zero_config::parse_config(&serde_json::json!({
        "inbounds": [],
        "outbounds": [{
            "tag": "psiphon",
            "protocol": "psiphon",
            "settings": {
                "serverEntries": [{
                    "ipAddress": "192.0.2.10",
                    "sshPort": 22,
                    "sshUsername": "psiphon",
                    "sshPassword": "password",
                    "sshHostKey": "AAAA",
                    "capabilities": ["SSH"]
                }]
            }
        }]
    }))
    .expect("the configuration parses")
    .0;

    let destination = Destination::tcp(Address::domain("example.com"), 443);
    let error = zero_runtime::outbound::connect(&outbound.outbounds[0], &destination)
        .await
        .err()
        .expect("connecting through Psiphon cannot work in this build");
    let text = error.to_string();
    assert!(text.contains("without Psiphon support"), "{text}");
}

#[cfg(feature = "psiphon")]
#[tokio::test]
async fn psiphon_refuses_udp() {
    let outbound = zero_config::parse_config(&serde_json::json!({
        "inbounds": [],
        "outbounds": [{
            "tag": "psiphon",
            "protocol": "psiphon",
            "settings": {"serverEntries": [{
                "ipAddress": "192.0.2.10",
                "sshPort": 22,
                "sshUsername": "psiphon",
                "sshPassword": "password",
                "sshHostKey": "AAAA",
                "capabilities": ["SSH"]
            }]}
        }]
    }))
    .unwrap()
    .0;

    let destination = Destination::new(Address::domain("example.com"), 53, zero_core::Network::Udp);
    let error = zero_runtime::outbound::connect(&outbound.outbounds[0], &destination)
        .await
        .err()
        .expect("Psiphon carries TCP only");
    assert!(error.to_string().contains("TCP only"), "{error}");
}

#[cfg(feature = "psiphon")]
#[tokio::test]
async fn a_bad_server_entry_is_a_configuration_failure_not_a_hang() {
    let outbound = zero_config::parse_config(&serde_json::json!({
        "inbounds": [],
        "outbounds": [{
            "tag": "psiphon",
            "protocol": "psiphon",
            "settings": {
                // Entries that parse as configuration but cannot be dialled:
                // no address a server could be reached at.
                "serverEntries": [{
                    "ipAddress": "not-an-address",
                    "sshPort": 22,
                    "sshUsername": "psiphon",
                    "sshPassword": "password",
                    "sshHostKey": "AAAA",
                    "capabilities": ["SSH"]
                }],
                "establishTimeoutSeconds": 2,
            }
        }]
    }))
    .unwrap()
    .0;

    let destination = Destination::tcp(Address::domain("example.com"), 443);
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        zero_runtime::outbound::connect(&outbound.outbounds[0], &destination),
    )
    .await
    .expect("the dial is bounded")
    .err()
    .expect("an unusable entry cannot produce a stream");
    assert!(error.to_string().contains("psiphon"), "{error}");
}

/// `cargo test -p zero-runtime --features psiphon --test psiphon_outbound -- --ignored --nocapture`
#[cfg(feature = "psiphon")]
#[tokio::test]
#[ignore = "needs the local psiphon-server harness"]
async fn a_request_travels_through_the_outbound_to_the_origin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(entry_path) = std::env::var("ZERO_PSIPHON_SERVER_ENTRY").ok() else {
        eprintln!("ZERO_PSIPHON_SERVER_ENTRY is not set; nothing to test");
        return;
    };
    let entries: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&entry_path).expect("the harness server entry is readable"),
    )
    .expect("the harness server entry is JSON");

    // The origin the harness serves, and the marker it answers with.
    let target = std::env::var("ZERO_PSIPHON_TARGET").unwrap_or_else(|_| "127.0.0.1:20085".into());
    let (host, port) = target.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("a port");

    let outbound = zero_config::parse_config(&serde_json::json!({
        "inbounds": [],
        "outbounds": [{
            "tag": "psiphon",
            "protocol": "psiphon",
            "settings": {
                "serverEntries": entries,
                "protocols": ["TLS-OSSH"],
                "establishTimeoutSeconds": 20,
            }
        }]
    }))
    .expect("the configuration parses")
    .0;
    let outbound = outbound.outbounds[0].clone();

    let destination = Destination::tcp(Address::domain(host), port);
    let mut stream = zero_runtime::outbound::connect(&outbound, &destination)
        .await
        .expect("the Psiphon tunnel comes up and opens a channel");

    let request = format!("GET /marker.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("writing through the outbound");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("reading through the outbound");

    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1."), "{text}");
    assert!(text.contains("psiphon-harness-marker"), "{text}");

    // A second connection reuses the tunnel that the first one built.
    let mut again = zero_runtime::outbound::connect(&outbound, &destination)
        .await
        .expect("the second connection reuses the tunnel");
    again
        .write_all(request.as_bytes())
        .await
        .expect("writing through the reused tunnel");
    let mut second = Vec::new();
    again
        .read_to_end(&mut second)
        .await
        .expect("reading through the reused tunnel");
    assert!(
        String::from_utf8_lossy(&second).contains("psiphon-harness-marker"),
        "the reused tunnel carried the request"
    );
}
