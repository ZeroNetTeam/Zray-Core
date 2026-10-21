//! `reality` and `zero-config` must read one `realitySettings` block the same
//! way.
//!
//! A REALITY server listener gets its settings from `zero-config` when it runs
//! inside Zray, and from [`RealityServerConfig`] when a server embeds this
//! crate directly. Two readers of the same JSON is exactly the shape of bug
//! that hides until a customer's `shortId` stops matching: the compiler says
//! one thing, the handshake another, and the symptom on the wire is a silent
//! fallback to the camouflage site rather than an error. So this test compiles
//! a document with `zero-config`, parses the same block with this crate, and
//! compares every field that decides a handshake or a fallback.

use std::time::Duration;

use reality::RealityServerConfig;
use serde_json::{json, Value};

fn server_settings() -> Value {
    json!({
        "show": true,
        "dest": "example.com:443",
        "xver": 2,
        "serverNames": ["example.com", "www.example.com"],
        "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
        "shortIds": ["", "ab12", "0011223344556677"],
        "mldsa65Seed": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE",
        "maxTimeDiff": 60000,
        "minClientVer": "1.0.0",
        "maxClientVer": "26.3.27",
        "masterKeyLog": "/tmp/zray-reality-keys.log",
        "limitFallbackUpload": {"afterBytes": 10, "bytesPerSec": 20, "burstBytesPerSec": 30},
        "limitFallbackDownload": {"afterBytes": 40, "bytesPerSec": 50, "burstBytesPerSec": 60}
    })
}

/// The same block, as part of a document the configuration compiler accepts.
fn document(settings: &Value) -> Value {
    json!({
        "inbounds": [{
            "tag": "reality-in",
            "listen": "127.0.0.1",
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": settings.clone()
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// The compiler's view of the inbound's REALITY settings.
fn compiled(settings: &Value) -> zero_config::InboundRealityConfig {
    let (generation, _) =
        zero_config::compile_config(&document(settings), zero_core::GenerationId(1))
            .expect("the document compiles");
    let inbound = generation
        .config
        .inbounds
        .first()
        .expect("one inbound was compiled");
    match &inbound.security {
        zero_config::InboundSecurity::Reality(reality) => reality.clone(),
        other => panic!("the inbound compiled to {other:?}, not REALITY"),
    }
}

/// A selector as the eight bytes the session id carries.
fn padded(selectors: &[Box<[u8]>]) -> Vec<Vec<u8>> {
    selectors
        .iter()
        .map(|selector| {
            assert!(
                selector.len() <= 8,
                "a selector wider than the session id's field cannot be compared"
            );
            let mut padded = vec![0u8; 8];
            padded[..selector.len()].copy_from_slice(selector);
            padded
        })
        .collect()
}

#[test]
fn both_readers_agree_on_one_reality_block() {
    let settings = server_settings();
    let compiled = compiled(&settings);
    let mine = RealityServerConfig::from_xray_settings(&settings).expect("this crate parses it");

    assert_eq!(mine.private_key, compiled.private_key, "privateKey");
    assert_eq!(mine.server_names, compiled.server_names, "serverNames");
    // The compiler stores a selector as it was written; Xray — and therefore
    // this crate — stores the eight bytes it will be compared against, which
    // are the same value right-padded with zeros (`transport_internet.go:892`).
    // What has to agree is the selector's meaning, so both sides are padded
    // here before they are compared.
    assert_eq!(
        padded(&mine.short_ids),
        padded(&compiled.short_ids),
        "shortIds"
    );
    assert_eq!(
        mine.mldsa65_seed.map(|seed| seed.to_vec()),
        compiled.mldsa65_seed.map(|seed| seed.0.to_vec()),
        "mldsa65Seed"
    );
    assert_eq!(
        mine.max_time_diff,
        Duration::from_millis(compiled.max_time_diff_ms),
        "maxTimeDiff"
    );
    assert_eq!(mine.min_client_ver, compiled.min_client_ver, "minClientVer");
    assert_eq!(mine.max_client_ver, compiled.max_client_ver, "maxClientVer");
    assert_eq!(mine.fallback_xver, compiled.fallback_xver, "xver");
    assert_eq!(mine.show, compiled.show, "show");
    assert_eq!(
        mine.master_key_log.as_deref(),
        compiled.master_key_log.as_deref(),
        "masterKeyLog"
    );
    assert_eq!(
        (
            mine.fallback_limit_up.after_bytes,
            mine.fallback_limit_up.bytes_per_sec,
            mine.fallback_limit_up.burst_bytes_per_sec
        ),
        (
            compiled.fallback_limit_up.after_bytes,
            compiled.fallback_limit_up.bytes_per_sec,
            compiled.fallback_limit_up.burst_bytes_per_sec
        ),
        "limitFallbackUpload"
    );
    assert_eq!(
        (
            mine.fallback_limit_down.after_bytes,
            mine.fallback_limit_down.bytes_per_sec,
            mine.fallback_limit_down.burst_bytes_per_sec
        ),
        (
            compiled.fallback_limit_down.after_bytes,
            compiled.fallback_limit_down.bytes_per_sec,
            compiled.fallback_limit_down.burst_bytes_per_sec
        ),
        "limitFallbackDownload"
    );

    let (host, port) = match mine.target.expect("dest was read") {
        reality::CamouflageTarget::Host(host, port) => (host, port),
        other => panic!("a bare port is a host and a port, not {other:?}"),
    };
    let (address, compiled_port) = match compiled.target.expect("the compiler read dest") {
        zero_config::RealityTarget::Host(address, port) => (address, port),
        other => panic!("a bare port is a host and a port, not {other:?}"),
    };
    assert_eq!(
        (&*host, port),
        (address.to_string().as_str(), compiled_port),
        "dest"
    );
}

#[test]
fn the_readers_agree_on_which_blocks_are_refused() {
    // Each case is a block one reader must not accept while the other does.
    // The compiler reports its reason as a string, so the test asserts that
    // both refused — not that they worded it the same way.
    let refusals: &[(&str, Value)] = &[
        (
            "no privateKey",
            json!({"serverNames": ["example.com"], "shortIds": [""]}),
        ),
        (
            "no serverNames",
            json!({"privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0", "shortIds": [""]}),
        ),
        (
            "no shortIds",
            json!({"privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0", "serverNames": ["example.com"]}),
        ),
        (
            "an odd shortId",
            json!({
                "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
                "serverNames": ["example.com"],
                "shortIds": ["abc"]
            }),
        ),
        (
            "a shortId wider than the session id",
            json!({
                "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
                "serverNames": ["example.com"],
                "shortIds": ["001122334455667788"]
            }),
        ),
        (
            "a privateKey that is not 32 bytes",
            json!({
                "privateKey": "AAAA",
                "serverNames": ["example.com"],
                "shortIds": [""]
            }),
        ),
        (
            "an xver that is not 0, 1 or 2",
            json!({
                "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
                "serverNames": ["example.com"],
                "shortIds": [""],
                "xver": 3
            }),
        ),
        (
            "a show that is not a boolean",
            json!({
                "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
                "serverNames": ["example.com"],
                "shortIds": [""],
                "dest": "example.com:443",
                "show": "yes"
            }),
        ),
        (
            "a masterKeyLog that is not a path",
            json!({
                "privateKey": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0",
                "serverNames": ["example.com"],
                "shortIds": [""],
                "dest": "example.com:443",
                "masterKeyLog": 5
            }),
        ),
    ];
    for (what, settings) in refusals {
        let compiler = zero_config::compile_config(&document(settings), zero_core::GenerationId(1));
        assert!(
            compiler.is_err(),
            "the configuration compiler accepted {what}: {settings:#}"
        );
        assert!(
            RealityServerConfig::from_xray_settings(settings).is_err(),
            "this crate accepted {what}: {settings:#}"
        );
    }
}

#[test]
fn the_readers_agree_about_a_camouflage_target_they_cannot_dial() {
    // Every one of these is a `dest` neither reader can use. Refusing with a
    // reason that names the target matters as much as refusing: a server that
    // came up with no target would answer a censor's probe with a silent
    // nothing, which is the opposite of the protocol's purpose, and the
    // operator would have no line to read that says so.
    for (what, written) in [
        ("no dest at all", None),
        ("a host with no port", Some(json!("example.com"))),
        ("a dest that is not a string", Some(json!(8443))),
    ] {
        let mut settings = server_settings();
        let object = settings.as_object_mut().expect("object");
        match written {
            None => {
                object.remove("dest");
            }
            Some(value) => {
                object.insert("dest".into(), value);
            }
        }

        let compiler =
            zero_config::compile_config(&document(&settings), zero_core::GenerationId(1))
                .err()
                .unwrap_or_else(|| panic!("the configuration compiler accepted {what}"));
        assert!(
            compiler.contains("dest"),
            "{what} was refused for the wrong reason: {compiler}"
        );
        let mine = RealityServerConfig::from_xray_settings(&settings)
            .err()
            .unwrap_or_else(|| panic!("this crate accepted {what}"));
        assert!(
            mine.contains("dest"),
            "{what} was refused for the wrong reason: {mine}"
        );
    }
}

/// Both readers refuse a server block that Xray refuses.
///
/// Two of Xray's refusals are the ones that matter most, because each lets a
/// server come up healthy and then do something other than what the operator
/// asked for:
///
/// * an empty `shortIds` — a server with no selector authenticates nobody,
///   and every client is handed to the camouflage site instead;
/// * an `mldsa65Seed` equal to the `privateKey` — the ML-DSA-65 binding adds
///   nothing, because the two roles share one secret.
///
/// The compiler is the path an inbound actually runs, so these are driven
/// through it as well as through this crate's reader.
#[test]
fn the_readers_agree_about_the_refusals_that_matter_most() {
    for (what, extra) in [
        ("an empty shortIds", json!({"shortIds": []})),
        (
            "an mldsa65Seed equal to the privateKey",
            json!({"mldsa65Seed": "OFD5I7z1nN2rJ0AB1z8o_9W3PpNr6uCkOoDo4Ea0lG0"}),
        ),
    ] {
        let mut settings = server_settings();
        let object = settings.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("object") {
            object.insert(key.clone(), value.clone());
        }

        let compiler =
            zero_config::compile_config(&document(&settings), zero_core::GenerationId(1))
                .err()
                .unwrap_or_else(|| panic!("the configuration compiler accepted {what}"));
        assert!(
            compiler.contains("shortIds") || compiler.contains("mldsa65Seed"),
            "{what} was refused for the wrong reason: {compiler}"
        );
        let mine = RealityServerConfig::from_xray_settings(&settings)
            .err()
            .unwrap_or_else(|| panic!("this crate accepted {what}"));
        assert!(
            mine.contains("shortIds") || mine.contains("mldsa65Seed"),
            "{what} was refused for the wrong reason: {mine}"
        );
    }
}

/// The two readers agree on a unix-socket target, and both carry it as the
/// path it was written as.
///
/// Xray dials unix sockets (`infra/conf/transport_internet.go:824-832`), so a
/// target that names one is a target, not a host name that would fail to
/// resolve.
#[test]
fn the_readers_agree_about_a_unix_socket_target() {
    for written in ["/run/decoy.sock", "@decoy"] {
        let mut settings = server_settings();
        settings
            .as_object_mut()
            .expect("object")
            .insert("dest".into(), json!(written));

        let compiled = compiled(&settings);
        let mine =
            RealityServerConfig::from_xray_settings(&settings).expect("this crate parses it");
        assert_eq!(
            compiled.target,
            Some(zero_config::RealityTarget::Unix(written.into())),
            "the compiler's unix target"
        );
        assert_eq!(
            mine.target,
            Some(reality::CamouflageTarget::Unix(written.into())),
            "this crate's unix target"
        );
    }
}

#[test]
fn the_readers_agree_about_a_diagnostic_switch_of_the_wrong_shape() {
    // Xray decodes this object into a Go struct with a `bool` and a `string`
    // field, so a string `show` or a numeric `masterKeyLog` is a configuration
    // error there too (`infra/conf/transport_internet.go:781-782`). It matters
    // that both readers say so rather than one of them skipping the field: an
    // operator who wrote `"show": "yes"` believes diagnostics are on, and would
    // be reading logs that say nothing.
    for (field, written) in [("show", json!("yes")), ("masterKeyLog", json!(5))] {
        let mut settings = server_settings();
        settings
            .as_object_mut()
            .expect("object")
            .insert(field.into(), written);
        let compiler =
            zero_config::compile_config(&document(&settings), zero_core::GenerationId(1))
                .err()
                .unwrap_or_else(|| panic!("the configuration compiler accepted {field}"));
        assert!(compiler.contains(field), "{compiler}");
        let mine = RealityServerConfig::from_xray_settings(&settings)
            .err()
            .unwrap_or_else(|| panic!("this crate accepted {field}"));
        assert!(mine.contains(field), "{mine}");
    }

    // And a block that sets them the way Xray documents is accepted by both,
    // which is what keeps the switches usable while the listener's plumbing for
    // them is still the handshake's to add.
    let mut settings = server_settings();
    let object = settings.as_object_mut().expect("object");
    object.insert("show".into(), json!(true));
    object.insert("masterKeyLog".into(), json!("none"));
    let compiled = compiled(&settings);
    let mine = RealityServerConfig::from_xray_settings(&settings).expect("this crate parses it");
    assert!(mine.show);
    assert_eq!(
        mine.master_key_log, None,
        "\"none\" is off, not a file called none"
    );
    assert!(
        compiled.target.is_some(),
        "the block still compiled its target"
    );
}

#[test]
fn both_readers_fill_in_a_short_client_version_the_same_way() {
    // Xray accepts one to three parts and pads with zeros, so `"1.2"` is
    // `1.2.0`; a reader that demanded three parts would refuse a config the
    // official implementation runs, and a client would be refused for a
    // version it never claimed.
    let mut settings = server_settings();
    settings
        .as_object_mut()
        .expect("object")
        .insert("minClientVer".into(), json!("1.2"));
    let compiled = compiled(&settings);
    let mine = RealityServerConfig::from_xray_settings(&settings).expect("this crate parses it");
    assert_eq!(compiled.min_client_ver, Some([1, 2, 0]));
    assert_eq!(mine.min_client_ver, compiled.min_client_ver);
}

#[test]
fn both_readers_treat_a_bare_port_dest_as_localhost() {
    // `dest: "443"` is `localhost:443` in Xray; resolving "443" as a host name
    // would send every unauthenticated visitor into a DNS failure instead of
    // to the camouflage site.
    let mut settings = server_settings();
    settings
        .as_object_mut()
        .expect("object")
        .insert("dest".into(), json!("8443"));
    let compiled = compiled(&settings);
    let mine = RealityServerConfig::from_xray_settings(&settings).expect("this crate parses it");
    let (address, port) = match compiled.target.expect("the compiler read dest") {
        zero_config::RealityTarget::Host(address, port) => (address, port),
        other => panic!("the compiler's target is {other:?}"),
    };
    let (host, mine_port) = match mine.target.expect("this crate read dest") {
        reality::CamouflageTarget::Host(host, port) => (host, port),
        other => panic!("this crate's target is {other:?}"),
    };
    assert_eq!((address.to_string().as_str(), port), ("localhost", 8443));
    assert_eq!((&*host, mine_port), ("localhost", 8443));
}
