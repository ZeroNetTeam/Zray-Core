//! `zray connect` and `zray catalog` — the one-click flow on the command
//! line, the same three steps the screens perform: pick a kind from the
//! catalog, hand it a link (or nothing), and build a runnable config.
//!
//! `connect` does all three and prints or saves the config; it never dials —
//! a CLI run is one process, and the person starts it with `zray run`.
//! `catalog` lists the kinds; `catalog doctor <id> [link]` is purely local:
//! it parses the link, checks what a TLS-borne entry needs, and says what to
//! do next in one sentence per problem. Nothing here touches the network.

use anyhow::{bail, Context, Result};
use zero_config::oneclick::{catalog, generate, Entry, EvasionDefaults, Input};

/// The name a catalog entry is addressed by on the command line: the entry's
/// own name, lower-case, spaces and other punctuation as dashes
/// (`warp-link`, `zerov1-tide`, `wireguard-amnezia`), so flags and
/// identifiers never need quoting.
fn slug(entry: &Entry) -> String {
    let cleaned: String = entry
        .name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    // Collapse the dashes a punctuation run became, and trim the ends.
    let mut slug = String::with_capacity(cleaned.len());
    for c in cleaned.chars() {
        if c != '-' || !slug.ends_with('-') {
            slug.push(c);
        }
    }
    slug.trim_matches('-').to_string()
}

fn entry_by_slug(name: &str) -> Option<&'static Entry> {
    catalog()
        .iter()
        .find(|entry| slug(entry) == name.to_ascii_lowercase())
}

/// The evasion defaults the flags ask for: `--no-evasion-defaults` turns the
/// per-entry fragment off, `--fragment-lengths a-b` retunes it. Both go
/// through the config parser's own bounds (via a generated config), so an
/// out-of-range pair is refused here for the same reason it would be refused
/// in a config file.
fn evasion_defaults(args: &[String]) -> Result<EvasionDefaults> {
    let mut defaults = EvasionDefaults::default();
    if args.iter().any(|arg| arg == "--no-evasion-defaults") {
        defaults = EvasionDefaults::off();
    }
    if let Some(lengths) = flag(args, "--fragment-lengths") {
        // A reversed pair is normalised by the range parser (the config
        // parser reads the same spelling), so it works, but the person
        // should write it the way they mean it.
        let reversed = lengths.split_once('-').is_some_and(|(a, b)| {
            a.trim()
                .parse::<u32>()
                .ok()
                .zip(b.trim().parse::<u32>().ok())
                .is_some_and(|(a, b)| a > b)
        });
        let (low, high) = parse_lengths(&lengths)?;
        defaults.fragment_lengths = (low, high);
        // A pair the parser will not take (a zero length, say) must be
        // reported here rather than as a config that fails after writing.
        validate_lengths(&defaults)?;
        if reversed {
            bail!(
                "--fragment-lengths {lengths} is back to front; it now reads as {low}-{high}, write the smaller number first"
            );
        }
    }
    Ok(defaults)
}

/// `"a-b"` or `"a"`, the piece of the flag's value before other flags.
fn parse_lengths(text: &str) -> Result<(u32, u32)> {
    let range = zero_config::model::RangeU32::parse(text)
        .with_context(|| format!("--fragment-lengths must be a number or a-b, got {text:?}"))?;
    Ok((range.min, range.max))
}

/// Build one config the way `generate` does, so the bounds are the parser's.
fn validate_lengths(defaults: &EvasionDefaults) -> Result<()> {
    // ZeroV1 is the catalog entry the fragment default sits on; if a refuser
    // this cheap stops being honest (entry renamed, parser moved), a real
    // link below still exercises the same check.
    let key = "A".repeat(43);
    let user = "A".repeat(22);
    let probe = format!("zerov1://{user}@example.org:443?key={key}&path=/static/ab#n");
    let entry = catalog()
        .iter()
        .find(|entry| entry.name == "ZeroV1 (Tide)")
        .expect("the ZeroV1 entry is in the catalog");
    generate(
        entry,
        Some(&probe),
        &zero_config::IranPreset::default(),
        defaults,
    )
    .map(|_| ())
    .map_err(|error| {
        anyhow::anyhow!(
            "--fragment-lengths {}-{}: {error}",
            defaults.fragment_lengths.0,
            defaults.fragment_lengths.1
        )
    })
}

/// `--name=value` or `--name value`.
fn flag(args: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
        if arg == name {
            return iter.next().cloned();
        }
    }
    None
}

/// The value-taking flags `connect` and `doctor` accept, so a flag's value
/// is never mistaken for the link.
const VALUE_FLAGS: &[&str] = &[
    "--fragment-lengths",
    "--http-port",
    "--socks-port",
    "-o",
    "--output",
];

/// The positional arguments: everything that is not a flag or a value-taking
/// flag's value. A share link is one argument and never begins with a dash,
/// so this cannot split one.
fn positionals(args: &[String]) -> Vec<&String> {
    let mut iter = args.iter();
    let mut found = Vec::new();
    while let Some(arg) = iter.next() {
        if arg.starts_with('-') {
            // `--name=value` carries its own value.
            if !arg.contains('=') && VALUE_FLAGS.contains(&arg.as_str()) {
                iter.next();
            }
            continue;
        }
        found.push(arg);
    }
    found
}

/// `zray connect <entry-slug> [link]` — build a one-click profile and print
/// it as config JSON (or write it with `-o`). The same generation the
/// screens run, so a config that works here is the config the picker makes.
pub(crate) fn connect(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let (slug_name, link) = match positional.len() {
        1 => (positional[0].as_str(), None),
        2 => (positional[0].as_str(), Some(positional[1].as_str())),
        n => bail!("connect needs an entry and at most one link (got {n} positionals)"),
    };
    let entry = entry_by_slug(slug_name).with_context(|| {
        format!(
            "no catalog entry {slug_name:?}; try `zray catalog` ({})",
            catalog().iter().map(slug).collect::<Vec<_>>().join(", ")
        )
    })?;
    if matches!(entry.input, Input::WarpAccount) {
        bail!(
            "{} is set up in the WARP dialog (W in the app); there is no link form",
            entry.name
        );
    }
    if matches!(entry.input, Input::None) && link.is_some() {
        bail!(
            "the {} entry takes no link (it is fully described by the kind); drop the argument",
            entry.name
        );
    }
    let generated = generate(entry, link, &iran_preset(args)?, &evasion_defaults(args)?)?;
    let rendered =
        serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(&generated.json)?)?;
    match flag(args, "-o").or_else(|| flag(args, "--output")) {
        Some(path) => {
            std::fs::write(&path, format!("{rendered}\n"))
                .with_context(|| format!("writing {path}"))?;
            eprintln!("wrote {path} ({} profile)", generated.remark);
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// The `IranPreset` the connect flags name, mirroring `zray preset iran`'s
/// subset that matters for a one-click profile (ports and DNS; the outbound
/// comes from the entry). `--fragment` here would place a second, coarser
/// fragment alongside the catalog's, so it is not offered: retune the
/// catalog's with `--fragment-lengths` or drop it with
/// `--no-evasion-defaults`.
fn iran_preset(args: &[String]) -> Result<zero_config::IranPreset> {
    let mut preset = zero_config::IranPreset {
        manage_assets: false,
        ..zero_config::IranPreset::default()
    };
    if let Some(value) = flag(args, "--socks-port") {
        preset.socks_port = value.parse().context("--socks-port must be a number")?;
    }
    if let Some(value) = flag(args, "--http-port") {
        preset.http_port = if value.eq_ignore_ascii_case("off") {
            None
        } else {
            Some(
                value
                    .parse()
                    .context("--http-port must be a number or `off`")?,
            )
        };
    }
    Ok(preset)
}

/// `zray catalog` — list the kinds, and `zray catalog doctor <id> [link]`
/// run the local checks over one. Also the landing point for `zray connect`.
pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("doctor") => doctor(&args[1..]),
        // `list` names the plain listing explicitly; `show` reads as "show me
        // an entry", so it takes the id as its second word.
        Some("list") => run(&[]),
        Some("show") => match args.get(1).map(String::as_str) {
            Some(id) => show_entry(id),
            None => bail!("show needs a catalog entry; try `zray catalog` for the ids"),
        },
        Some(other) if other.starts_with('-') || entry_by_slug(other).is_some() => {
            // `zray catalog <id>` reads as "show me this entry", which is the
            // doctor without a link: the same local checks, entry only.
            doctor(args)
        }
        Some(other) => bail!("unknown catalog command {other:?}; use `zray catalog` or `zray catalog doctor <id> [link]`"),
        None => {
            println!("one-click kinds, in the order the picker shows them:\n");
            for entry in catalog() {
                let state = if entry.available { "ready" } else { "planned" };
                println!(
                    "  {:<20} {:<7} {}",
                    slug(entry),
                    state,
                    entry.detail
                );
            }
            println!(
                "\nbuild one:  zray connect <id> [link] [-o FILE] [--no-evasion-defaults] [--fragment-lengths a-b]\n\
                 check one:  zray catalog doctor <id> [link]"
            );
            Ok(())
        }
    }
}

/// `zray catalog show <id>` — one entry's detail and the ids it takes, the
/// readable half of the doctor (no checks, no exit-code semantics).
fn show_entry(id: &str) -> Result<()> {
    let entry = entry_by_slug(id).with_context(|| {
        format!(
            "no catalog entry {id:?}; known ids: {}",
            catalog().iter().map(slug).collect::<Vec<_>>().join(", ")
        )
    })?;
    let state = if entry.available { "ready" } else { "planned" };
    println!(
        "{id}\n  {state}  {}\n  link schemes: {}",
        entry.detail,
        if entry.schemes().is_empty() {
            "none (the kind is described by itself, or set up in a dialog)".to_string()
        } else {
            entry.schemes().join(", ")
        },
    );
    Ok(())
}

/// `zray catalog doctor <id> [link]` — purely local sanity checks: the entry
/// exists, an optional link parses and matches the entry's schemes, a
/// TLS-borne entry carries a server name, and the fragment defaults sit
/// within the bounds the config parser enforces. One clear sentence per
/// problem, each saying what to do next; no network is touched.
fn doctor(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let Some(slug_name) = positional.first() else {
        bail!("doctor needs a catalog entry; try `zray catalog` for the ids");
    };
    let link = positional.get(1).map(|arg| arg.as_str());
    let entry = entry_by_slug(slug_name).with_context(|| {
        format!(
            "no catalog entry {slug_name:?}; known ids: {}",
            catalog().iter().map(slug).collect::<Vec<_>>().join(", ")
        )
    })?;

    let mut problems = 0usize;
    let mut say = |problem: String| {
        problems += 1;
        println!("problem {problems}: {problem}");
    };

    if !entry.available {
        say(format!(
            "the {} entry is planned, not built into this binary; rebuild with its feature (see its Cargo.toml) or pick another kind",
            entry.name
        ));
        return finish_doctor(problems);
    }

    let defaults = match evasion_defaults(args) {
        Ok(defaults) => defaults,
        Err(error) => {
            say(format!(
                "the fragment flags do not hold together: {error}; pass lengths the config parser allows, like --fragment-lengths 40-80"
            ));
            return finish_doctor(problems);
        }
    };

    let link = match link {
        None => None,
        // An explicit blank means "no link", the same as omitting it.
        Some(text) if text.trim().is_empty() => None,
        Some(text) => Some(text),
    };
    match (entry.input, link) {
        (Input::WarpAccount, _) => {
            say(format!(
                "the {} entry has no link form; it is set up in the WARP dialog (W in the app), and `zray connect` refuses it too",
                entry.name
            ));
        }
        (Input::None, Some(text)) => {
            say(format!(
                "the {} entry takes no link (it is fully described by the kind); drop the {text:?} argument",
                entry.name
            ));
        }
        // A self-contained kind with nothing pasted: only the flags and the
        // fragment defaults have anything to say.
        (Input::None, None) => {}
        (Input::Link { .. }, None) => {
            println!(
                "note: no link given, so only the entry's own checks ran; pass the link to check it too"
            );
        }
        (Input::Link { .. }, Some(text)) => check_link(entry, text, &defaults, &mut say),
    }
    finish_doctor(problems)
}

/// The link checks: parse, scheme, SNI, and the fragment defaults the
/// generated config would carry.
fn check_link(
    entry: &'static Entry,
    text: &str,
    defaults: &EvasionDefaults,
    mut say: impl FnMut(String),
) {
    let parsed = match zero_config::parse_link(text) {
        Ok(parsed) => parsed,
        Err(reason) => {
            say(format!(
                "the link does not parse as a share link: {reason}; paste it again (say it as the source app wrote it, one line, no shell quoting)"
            ));
            return;
        }
    };
    let scheme = text
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_default();
    let schemes = entry.schemes();
    if !schemes.contains(&scheme.as_str()) {
        // Where this paste does belong, looked up from the pasted scheme
        // itself: a link may parse fine yet belong to no one-click entry,
        // and then the honest answer says so instead of pointing in circles.
        let home = match entry_of_scheme(&scheme) {
            Some(home) => format!("paste it under the matching entry ({} in this list)", slug(home)),
            None => format!(
                "no one-click entry takes {scheme} links; import it through the ordinary import path"
            ),
        };
        say(format!(
            "this is a {scheme:?} link but the {} entry takes {}; {home}",
            entry.name,
            schemes.join(" or "),
        ));
        return;
    }

    // The entry kinds are TLS-borne (WireGuard and Tor carry their own or
    // no crypto; MasterDNS tunnels inside DNS). A link for a TLS-borne kind
    // should show a certificate carrier, and the name the certificate is
    // checked against. `security=none` on such a link parses cleanly, so
    // only a look at the parsed stream catches it.
    let security = &parsed.outbound.stream.security;
    let tls_borne = !matches!(
        parsed.outbound.protocol,
        zero_config::model::OutboundProtocol::Tor(_)
            | zero_config::model::OutboundProtocol::MasterDns(_)
            | zero_config::model::OutboundProtocol::AmneziaWireguard(_)
            | zero_config::model::OutboundProtocol::Socks(_)
    );
    let mut server_name: Option<&str> = None;
    if tls_borne {
        match security {
            zero_config::model::Security::None => say(format!(
                "the parsed link carries no TLS, though the {} kind is served over it; either the link was mangled (its security=?) or the server offers none — re-copy the link from its source, and if plain is really intended, run `zray check` on it and connect knowingly",
                entry.name
            )),
            zero_config::model::Security::Tls(tls) => {
                server_name = tls.server_name.as_deref();
            }
            zero_config::model::Security::Reality(reality) => {
                server_name = Some(&reality.server_name);
            }
            // ShadowTLS wraps another TLS inside; its own check is the
            // handshake it fakes, not a name of ours.
            zero_config::model::Security::ShadowTls(_) => {}
        }
    }
    match server_name.map(str::trim) {
        Some("") => say(
            "the link's server name (sni=) is empty; put the host the certificate must match there, or drop the sni= so the server's host is used"
                .to_string(),
        ),
        Some(_) => {}
        // No name at all on a certificate carrier: the certificate check has
        // nothing to bite on, so any hostile certificate is accepted as any
        // of the names asked. Reality does not hit this (its parser fills
        // the host), but the guard costs nothing and keeps the match honest.
        None if matches!(security, zero_config::model::Security::Tls(_)) => say(
            "the link asks for certificate TLS but names no server (sni=); add the host the certificate must match to the link, or ask the source that gave it out"
                .to_string(),
        ),
        None => {}
    }

    // The config the entry would generate: bound checks run through the
    // parser's own validate, so what passes here is what would run.
    let preset = zero_config::IranPreset {
        outbounds: zero_config::presets::outbounds_from_links([parsed.link.as_str()]),
        manage_assets: false,
        ..zero_config::IranPreset::default()
    };
    if let Err(reason) = generate(entry, Some(text), &preset, defaults) {
        say(format!(
            "generating the {} profile from this link fails: {reason}; fix what it names and run the doctor again",
            entry.name
        ));
    }
}

/// The entry that takes links of `scheme`, for pointing a paste at its kind.
fn entry_of_scheme(scheme: &str) -> Option<&'static Entry> {
    catalog()
        .iter()
        .find(|entry| entry.schemes().contains(&scheme))
}

/// The doctor's exit: a clean bill, or a failure so scripts can tell.
fn finish_doctor(problems: usize) -> Result<()> {
    if problems == 0 {
        println!("all checks passed");
        Ok(())
    } else {
        bail!("{problems} problem(s) found above")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // Real-shaped keys, because the parser correctly refuses anything else.
    fn tide_link(extra: &str) -> String {
        let key = "A".repeat(43);
        let user = "A".repeat(22);
        format!("zerov1://{user}@example.org:443?key={key}&path=/static/ab{extra}#n")
    }

    // The problems `check_link` would print, collected instead of printed.
    fn problems_for(entry_name: &str, link: &str) -> Vec<String> {
        let entry = entry_by_slug(entry_name).expect("entry exists");
        let mut seen = Vec::new();
        check_link(entry, link, &EvasionDefaults::default(), |problem| {
            seen.push(problem)
        });
        seen
    }

    #[test]
    fn slugs_are_quotable_and_still_recognised() {
        let tide = entry_by_slug("zerov1-tide").expect("tide by slug");
        assert_eq!(tide.name, "ZeroV1 (Tide)");
        // Slug lookup is case-insensitive, the way a person types.
        assert!(entry_by_slug("ZeroV1-Tide").is_some());
        assert_eq!(
            slug(entry_by_slug("wireguard-amnezia").unwrap()),
            "wireguard-amnezia"
        );
        // Every entry is reachable through its printed slug: the list the
        // person was told to read from cannot dead-end.
        for entry in catalog() {
            assert_eq!(entry_by_slug(&slug(entry)), Some(entry), "{}", slug(entry));
        }
    }

    #[test]
    fn length_flags_parse_and_bounds_come_from_the_config_parser() {
        let defaults = evasion_defaults(&args(&["--fragment-lengths", "10-20"])).unwrap();
        assert_eq!(defaults.fragment_lengths, (10, 20));
        // The default still carries the catalog's fragment; the override
        // only retunes it.
        assert!(defaults.fragment);

        // A zero length is refused for the same reason the config parser
        // refuses it — a generated config with it would not run.
        let zero = evasion_defaults(&args(&["--fragment-lengths", "0-0"])).unwrap_err();
        assert!(zero.to_string().contains("bad length"), "{zero}");
        assert!(evasion_defaults(&args(&["--fragment-lengths", "soon"])).is_err());
        // A reversed pair is normalised by the range parser, but named for
        // what it is, so the person writes it the way they mean it next time.
        let reversed = evasion_defaults(&args(&["--fragment-lengths", "80-40"])).unwrap_err();
        assert!(reversed.to_string().contains("back to front"), "{reversed}");
    }

    #[test]
    fn a_self_contained_entry_refuses_a_pasted_link() {
        // `direct` builds from nothing; a link after it is a paste aimed at
        // the wrong kind and must be named, not silently dropped.
        let argv = args(&["direct", "zerov1://x"]);
        let error = connect(&argv).unwrap_err();
        assert!(error.to_string().contains("takes no link"), "{error}");
    }

    #[test]
    fn no_evasion_defaults_switches_the_per_kind_fragment_off() {
        let defaults = evasion_defaults(&args(&["--no-evasion-defaults"])).unwrap();
        assert!(!defaults.fragment);
        // And nothing re-arms it: both flags together still mean off for the
        // fragment, with the lengths remembered for nothing hidden.
        let both = evasion_defaults(&args(&[
            "--no-evasion-defaults",
            "--fragment-lengths",
            "10-20",
        ]))
        .unwrap();
        assert!(!both.fragment);
    }

    #[test]
    fn a_good_link_and_entry_pass_the_doctor_checks() {
        assert!(problems_for("zerov1-tide", &tide_link("")).is_empty());
        assert!(problems_for("zerov1-tide", &tide_link("&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A%7B%22packets%22%3A%22tlshello%22%2C%22length%22%3A%2210-20%22%7D%7D%5D%7D")).is_empty());
    }

    #[test]
    fn a_link_that_disables_tls_on_a_tls_kind_is_reported() {
        let problems = problems_for("zerov1-tide", &tide_link("&security=none"));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("carries no TLS"), "{problems:?}");
    }

    #[test]
    fn a_link_of_the_wrong_scheme_says_where_the_paste_belongs() {
        // A vless link belongs to no one-click entry at all, so the sentence
        // must say that plainly instead of pointing back at this entry.
        let vless =
            "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=tls&type=tcp#x";
        let problems = problems_for("zerov1-tide", vless);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("vless"), "{problems:?}");
        assert!(
            problems[0].contains("no one-click entry takes vless"),
            "{problems:?}"
        );

        // A hy2 link does belong somewhere, and the sentence names it.
        let hy2 = "hy2://secretpassword@203.0.113.9:443#h";
        let problems = problems_for("zerov1-tide", hy2);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("quic-proxies"), "{problems:?}");
    }

    #[test]
    fn a_wg_link_is_not_reported_as_missing_tls() {
        // WireGuard has no hello to protect; the doctor must not nag a good
        // link for lacking a carrier kind it never promised.
        assert!(problems_for(
            "wireguard-amnezia",
            "wg://AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=@203.0.113.10:51820\
             ?publickey=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=&address=10.7.0.2/32#WG"
        )
        .is_empty());
    }

    #[test]
    fn positionals_skip_flag_values_but_not_their_own_words() {
        let argv = args(&[
            "zerov1-tide",
            "--fragment-lengths",
            "10-20",
            "--http-port",
            "off",
            "zerov1://x",
            "-o",
            "out.json",
        ]);
        let found: Vec<&str> = positionals(&argv).iter().map(|s| s.as_str()).collect();
        assert_eq!(found, ["zerov1-tide", "zerov1://x"]);
    }
}
