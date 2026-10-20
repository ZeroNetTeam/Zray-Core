//! One-click connectivity — the catalog of connection kinds a person can set
//! up without knowing anything about proxies, and the generator that turns a
//! choice into a runnable config.
//!
//! A VPN client's quick-setup entries ("WARP", "Tor", "my server's link")
//! all share one shape: a name, a plain-language description, what the
//! person has to give (a pasted share link, a WARP account made in its own
//! dialog, or nothing at all) and whether the kind is usable in this build.
//! [`catalog`] lists the entries in a fixed order; [`generate`] takes an
//! entry plus its input and hands back the Xray-JSON text of a full config.
//!
//! Generation always goes through [`IranPreset`], so a one-click profile
//! carries the same DNS, anti-sanction and routing setup as an imported
//! share link, and a caller that already validates output with the standard
//! parser needs no new path.
//!
//! ```no_run
//! # use zero_config::oneclick;
//! # use zero_config::IranPreset;
//! # fn demo(link: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let entry = oneclick::catalog().iter().find(|e| e.name == "WireGuard / Amnezia").unwrap();
//! let generated = oneclick::generate(
//!     entry,
//!     Some(link),
//!     &IranPreset::default(),
//!     &oneclick::EvasionDefaults::default(),
//! )?;
//! println!("remark: {}", generated.remark);
//! # Ok(())
//! # }
//! ```
//!
//! Fragmenting is a property of the person's network rather than of the
//! server, so unlike the rest of the outbound it does not come from the
//! link: the entries carry a small default profile ([`EvasionDefaults`]),
//! aimed per protocol — a ClientHello fragment where a fragment can help,
//! nothing where it would be bytes that do nothing — and one parameter is
//! the whole knob a caller needs to retune or switch it off.

use crate::presets::IranPreset;
use crate::share_link::parse_link;

/// One kind of one-click connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Short name shown in lists. One or two words. `generate` matches on
    /// it for the self-contained kinds, so it is load-bearing.
    pub name: &'static str,
    /// One sentence a newcomer can act on; the picker shows it under the name.
    pub detail: &'static str,
    /// The input the person is walked through after picking the entry.
    pub input: Input,
    /// Whether this build can run the kind at all. A kind that is not yet
    /// usable stays visible so people can see the direction, but its entry
    /// is never connectable — `generate` refuses it.
    pub available: bool,
}

/// What a catalog entry asks for before a config can be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// Nothing to supply; the config is fully described by the entry.
    None,
    /// A share link, pasted or otherwise supplied. The expected schemes are
    /// a screen for pasted content of the wrong kind, not a second parser —
    /// every link is still parsed by [`parse_link`].
    Link {
        /// The share-link schemes this entry expects, without `://`.
        schemes: &'static [&'static str],
    },
    /// A Cloudflare WARP account, made or managed through the WARP dialog.
    /// Nothing is generated here: the dialog stores the account as a normal
    /// profile, so the catalog entry only points the way.
    WarpAccount,
}

impl Entry {
    /// Whether this entry produces a config from a pasted share link.
    pub fn takes_link(&self) -> bool {
        matches!(self.input, Input::Link { .. })
    }

    /// The schemes the entry expects; empty when it takes no link.
    pub fn schemes(&self) -> &'static [&'static str] {
        match self.input {
            Input::Link { schemes } => schemes,
            _ => &[],
        }
    }
}

/// The per-protocol evasion a one-click profile is born with.
///
/// A share link describes the server; fragmentation is a defence against the
/// network in between, so the catalog supplies it. The defaults are a
/// [`FragmentConfig::default`] hello cut on the entries whose own connection
/// to their server is TLS over raw TCP — where the ClientHello carries the
/// server's name in the clear and cutting it up is the one thing this client
/// can do about that — and nothing elsewhere: a QUIC or WireGuard carrier
/// has no ClientHello, a link that set its own `fm=` already says what it
/// wants, and an SNI-desync choice is a rung the person climbs deliberately
/// (see `masterdns`'s `hide=`) rather than something a catalog picks.
///
/// `fragment_lengths` retunes the byte range; the parser's own bounds are
/// the ceiling, because a value they reject would fail the whole config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvasionDefaults {
    /// Fragment sizes, as the low and high end of the byte range drawn per
    /// connection. `(40, 80)`, the measured default.
    pub fragment_lengths: (u32, u32),
    /// Whether the per-entry fragment defaults are applied at all.
    pub fragment: bool,
}

impl Default for EvasionDefaults {
    fn default() -> Self {
        Self {
            fragment_lengths: (40, 80),
            fragment: true,
        }
    }
}

/// The `length` spelling the parser reads (`"40-80"`).
impl std::fmt::Display for EvasionDefaults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.fragment_lengths.0, self.fragment_lengths.1)
    }
}

impl EvasionDefaults {
    /// Fragment defaults turned off: every entry generates exactly what its
    /// link (or its self-contained form) describes.
    pub fn off() -> Self {
        Self {
            fragment: false,
            ..Self::default()
        }
    }

    /// The ClientHello fragment a one-click profile of this outbound is born
    /// with, or `None` when the kind carries none: fragmentation off, a link
    /// that layered its own `fm=` (an answer beats a default), ECH (the name
    /// is already encrypted, and the two cannot be combined), a carrier that
    /// is not certificate TLS (Tor and MasterDNS build their own crypto, a
    /// plain WireGuard link has no hello to cut), or a protocol
    /// whose own connection is QUIC or WireGuard rather than TCP (Hysteria 2,
    /// TUIC, Juicity, WARP) — there a TCP fragment would be config weight
    /// the runtime never reads.
    ///
    /// REALITY is refused as well, matching the dial pass: its ClientHello
    /// already names a real, allow-listed site, so there is no forbidden name
    /// for the split to hide, and REALITY servers commonly reject a hello cut
    /// across segments — a profile born with the mask would fail its own
    /// handshake wherever it runs without the restamp.
    pub fn fragment_for(
        &self,
        outbound: &crate::model::Outbound,
    ) -> Option<crate::model::FragmentConfig> {
        if !self.fragment {
            return None;
        }
        if outbound.stream.evasion.tcp_fragment.is_some() {
            return None;
        }
        match &outbound.stream.security {
            crate::model::Security::Tls(tls) if tls.ech.is_none() => {}
            _ => return None,
        }
        if matches!(
            outbound.protocol,
            crate::model::OutboundProtocol::Hysteria2(_)
                | crate::model::OutboundProtocol::Tuic(_)
                | crate::model::OutboundProtocol::Juicity(_)
                | crate::model::OutboundProtocol::AmneziaWireguard(_)
        ) {
            return None;
        }
        let mask = crate::model::FragmentConfig {
            length: crate::model::RangeU32::new(self.fragment_lengths.0, self.fragment_lengths.1),
            ..crate::model::FragmentConfig::default()
        };
        Some(mask)
    }
}

/// The catalog every client renders, in display order.
///
/// Self-contained kinds first (nothing to paste), then the WARP account,
/// then the link kinds.
pub fn catalog() -> &'static [Entry] {
    &CATALOG
}

/// The catalog itself, all `static`, so names and positions hold across builds.
static CATALOG: [Entry; 9] = [
    Entry {
        name: "Tor",
        detail: "Route through the Tor network with the built-in client.",
        input: Input::None,
        // The embedded Arti client ships behind the `tor` feature (see
        // `zero-runtime`'s outbound dispatch), so a build without it cannot
        // run the entry however good its config would be.
        available: cfg!(feature = "tor"),
    },
    Entry {
        name: "Direct",
        detail: "No proxy: a plain connection with SNI tampering defences, from your own address.",
        input: Input::None,
        available: true,
    },
    Entry {
        name: "Cloudflare WARP",
        detail: "A free anonymous Cloudflare account, set up in its own dialog (W).",
        input: Input::WarpAccount,
        available: true,
    },
    Entry {
        name: "WireGuard / Amnezia",
        detail: "A WireGuard or AmneziaWG server, pasted as its wg:// link.",
        input: Input::Link {
            schemes: &["wg", "wireguard"],
        },
        available: true,
    },
    Entry {
        name: "WARP link",
        detail: "An existing Cloudflare WARP account, pasted as its warp:// link.",
        input: Input::Link { schemes: &["warp"] },
        available: true,
    },
    Entry {
        name: "QUIC proxies",
        detail: "Hysteria2, TUIC or Juicity, pasted as a hy2://, tuic:// or juicity:// link.",
        input: Input::Link {
            schemes: &["hysteria2", "hy2", "tuic", "juicity"],
        },
        available: true,
    },
    Entry {
        name: "ZeroV1 (Tide)",
        detail: "This project's own protocol, pasted as a zerov1:// or tide:// link.",
        input: Input::Link {
            schemes: &["zerov1", "tide"],
        },
        available: true,
    },
    Entry {
        name: "NaiveProxy",
        detail: "An HTTP/2 CONNECT tunnel behind an ordinary site, pasted as its naive:// link.",
        input: Input::Link {
            schemes: &["naive", "naive+https"],
        },
        available: true,
    },
    Entry {
        name: "MasterDNS",
        detail: "A MasterDNSVPN server that tunnels inside ordinary DNS traffic.",
        input: Input::Link {
            schemes: &["masterdns"],
        },
        available: true,
    },
];

/// What generating from a catalog entry produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// The full Xray-JSON config text, ready to parse and run.
    pub json: String,
    /// The profile name: the link's remark when it carried one, the entry
    /// kind otherwise. The person sees this in the profile list.
    pub remark: String,
    /// The main outbound's protocol name, as `OutboundProtocol::name()` spells it.
    pub protocol: String,
    /// The server's host and port, for the profile list's endpoint column.
    pub endpoint: (String, u16),
}

/// Why a one-click generation refused to run.
///
/// Every message says what to supply rather than naming JSON paths, because
/// the caller shows it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// The kind cannot run in this build.
    Unavailable,
    /// The kind needs a share link and got nothing.
    LinkRequired,
    /// The kind has no link form; it is set up elsewhere (the WARP dialog).
    SetupElsewhere,
    /// The pasted text was not a share link, or was not one this entry takes.
    LinkRejected(String),
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "this build cannot run that kind"),
            Self::LinkRequired => write!(f, "paste the share link for this kind first"),
            Self::SetupElsewhere => write!(f, "this kind is set up in its own dialog"),
            Self::LinkRejected(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Build the runnable config for a catalog entry.
///
/// `link` is required for [`Input::Link`] entries and ignored for
/// [`Input::None`]. `preset` carries the caller's choices (ports, DNS,
/// fragmenting); the entry's outbound is layered on top of it, so a one-click
/// profile is configured exactly like an imported one. `defaults` is the
/// per-protocol evasion the profile is born with; [`EvasionDefaults::off`]
/// turns it off and leaves exactly what the link describes.
///
/// When the caller also sets `IranPreset::fragment`, the catalog's mask is
/// layered first and the preset's fills only the outbounds left without one
/// — the more specific choice wins.
pub fn generate(
    entry: &Entry,
    link: Option<&str>,
    preset: &IranPreset,
    defaults: &EvasionDefaults,
) -> Result<Generated, GenerateError> {
    if !entry.available {
        return Err(GenerateError::Unavailable);
    }
    let link = match entry.input {
        Input::None => None,
        Input::WarpAccount => return Err(GenerateError::SetupElsewhere),
        Input::Link { schemes } => {
            let link = link.map(str::trim).filter(|l| !l.is_empty());
            let Some(link) = link else {
                return Err(GenerateError::LinkRequired);
            };
            // Schemes are case-insensitive (RFC 3986 §3.1); reject content of
            // the wrong kind here, where the person can fix the paste, rather
            // than letting the parser read it as a worse error later.
            let scheme = link
                .split_once("://")
                .map(|(scheme, _)| scheme.to_ascii_lowercase())
                .unwrap_or_default();
            if !schemes.contains(&scheme.as_str()) {
                return Err(GenerateError::LinkRejected(format!(
                    "that is a {scheme:?} link; this entry takes {}",
                    schemes.join(" or ")
                )));
            }
            Some(link)
        }
    };

    match link {
        Some(link) => from_link(link, preset, defaults),
        None => self_contained(entry, preset, defaults),
    }
}

/// Build the config for a pasted link: parse, wrap as a link outbound,
/// render through the preset.
fn from_link(
    link: &str,
    preset: &IranPreset,
    defaults: &EvasionDefaults,
) -> Result<Generated, GenerateError> {
    let parsed = parse_link(link).map_err(GenerateError::LinkRejected)?;
    // The link describes the server; the fragment default is the one
    // network-side thing it cannot carry, so it is layered on the way a
    // preset layering would be (`evasion` next to `link`, which the parser
    // reads after the link's own). A link that set its own `fm=` keeps it.
    // `packets: 1-1` cuts the first write — the ClientHello — which is also
    // the preset's own shape; `length` is the byte range drawn per cut.
    let mut outbound = serde_json::json!({"link": parsed.link});
    if let Some(mask) = defaults.fragment_for(&parsed.outbound) {
        outbound["evasion"] = serde_json::json!({"fragment": {
            "packets": "1-1",
            "length": format!("{}-{}", mask.length.min, mask.length.max),
            "interval": format!(
                "{}-{}",
                mask.delay.min.as_millis(),
                mask.delay.max.as_millis()
            ),
        }});
    }
    let preset = IranPreset {
        outbounds: vec![outbound],
        ..preset.clone()
    };
    finish(&parsed, preset)
}

/// Build the config for an entry that needs nothing pasted.
///
/// The two self-contained kinds map to share links the parser already
/// understands, so the preset pipeline and validation are shared with the
/// link path and nothing here hand-builds outbounds.
fn self_contained(
    entry: &Entry,
    preset: &IranPreset,
    defaults: &EvasionDefaults,
) -> Result<Generated, GenerateError> {
    let link = match entry.name {
        // Tor with its defaults; bridges carry spaces and certificates and
        // do not fit a link, so they stay in JSON (see `parse_link`).
        "Tor" => "tor://#Tor",
        // `hide=auto` is the parser's form of "no proxy, SNI desync on".
        // The link carries no server of its own: the connection goes out
        // from the person's own address, and the hello it hides is the one
        // behind the proxy — so the link's own hiding stands, and the
        // catalog adds nothing next to it (a Freedom outbound is not the
        // TLS carrier the fragment default is aimed at).
        "Direct" => "direct://?hide=auto#Direct",
        other => {
            return Err(GenerateError::LinkRejected(format!(
                "the {other} entry is not self-contained"
            )));
        }
    };
    from_link(link, preset, defaults)
}

/// The `Generated` for a parsed link, rendered through the preset.
///
/// The built config is parsed back here — the same check `zray preset` and
/// the screens put their output through — so a preset choice or a default
/// that would not run (an out-of-bounds fragment length, say) is an error at
/// generation, where it names the entry, rather than a profile that fails
/// only when dialled.
fn finish(
    parsed: &crate::share_link::ShareLink,
    preset: IranPreset,
) -> Result<Generated, GenerateError> {
    let value = preset.build();
    crate::parse_config(&value).map_err(GenerateError::LinkRejected)?;
    let json = serde_json::to_string_pretty(&value).unwrap_or_default();
    Ok(Generated {
        json,
        remark: default_remark(parsed),
        protocol: parsed.outbound.protocol.name().to_string(),
        endpoint: parsed
            .outbound
            .endpoint()
            .map(|(address, port)| (address.host_string(), port))
            .unwrap_or_else(|| endpoint_of(&parsed.outbound.protocol)),
    })
}

/// The name a profile gets when the link names nothing, matching the
/// profile-list convention for imported links.
fn default_remark(parsed: &crate::share_link::ShareLink) -> String {
    if parsed.remark.trim().is_empty() {
        format!("{}-Node", parsed.outbound.protocol.name().to_uppercase())
    } else {
        parsed.remark.clone()
    }
}

/// The endpoint shown for the proxy protocols that name no server of their
/// own, matching the profile list's rendering of such rows.
fn endpoint_of(protocol: &crate::model::OutboundProtocol) -> (String, u16) {
    match protocol {
        // A MasterDNS server is named by its tunnel domain; queries go out on
        // port 53 (see the profile list's `endpoint_of`).
        crate::model::OutboundProtocol::MasterDns(m) => (m.domain.to_string(), 53),
        _ => ("proxy".into(), 443),
    }
}

/// The picker screen's own state: the catalog, the highlight, and what the
/// person has typed or pasted so far.
///
/// Kept here rather than in the UI crate so the key rules (which entries
/// take a link today, which refuse because the build lacks them) and their
/// tests travel with the catalog they interpret. It holds no I/O: keys and
/// clicks go in, plain data comes out, and the caller does the storing and
/// dialling through its usual connection path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picker {
    /// Index into [`catalog`] of the highlighted row.
    pub selected: usize,
    /// Text typed into the link field; empty for the kinds that need nothing.
    pub link: String,
    /// Why the last attempt to generate did nothing, shown under the field.
    pub error: Option<String>,
}

impl Default for Picker {
    fn default() -> Self {
        // Start on the first entry that is actually usable: a highlight on a
        // planned entry would make Enter the start of a refusal.
        let selected = catalog().iter().position(|e| e.available).unwrap_or(0);
        Self {
            selected,
            link: String::new(),
            error: None,
        }
    }
}

impl Picker {
    /// The highlighted entry.
    pub fn entry(&self) -> &'static Entry {
        // `selected` is only ever moved by the wrapped moves below or set
        // from a click on a rendered row, both bounded by `catalog().len()`.
        catalog().get(self.selected).unwrap_or(&catalog()[0])
    }

    /// Whether the highlighted entry can be continued on Enter right now.
    pub fn connectable(&self) -> bool {
        let entry = self.entry();
        entry.available
            && match entry.input {
                Input::WarpAccount => false,
                Input::None => true,
                Input::Link { .. } => !self.link.trim().is_empty(),
            }
    }

    /// Move the highlight, wrapping in both directions.
    pub fn move_by(&mut self, delta: i32) {
        let count = catalog().len() as i32;
        self.selected = (self.selected as i32 + delta).rem_euclid(count) as usize;
        // The error names the entry it was raised for; a new highlight
        // invalidates it, while the typed link stays for the next try.
        self.error = None;
    }

    /// Highlight the row clicked at `index`.
    pub fn select(&mut self, index: usize) {
        if index < catalog().len() {
            self.selected = index;
            self.error = None;
        }
    }

    /// Replace the link field's text (a paste).
    pub fn set_link(&mut self, text: &str) {
        self.link = text.chars().filter(|c| !c.is_control()).collect();
        self.error = None;
    }

    /// Type into the link field.
    pub fn push_link(&mut self, c: char) {
        self.link.push(c);
        self.error = None;
    }

    /// Backspace in the link field.
    pub fn pop_link(&mut self) {
        self.link.pop();
        self.error = None;
    }

    /// Try to build the config for the highlighted entry with what the
    /// person has supplied.
    ///
    /// On success the field returns to clean; on failure the reason is kept
    /// for the next frame and the caller changes nothing.
    pub fn generate(
        &mut self,
        preset: &IranPreset,
        defaults: &EvasionDefaults,
    ) -> Result<Generated, GenerateError> {
        let entry = self.entry();
        match generate(entry, Some(self.link.as_str()), preset, defaults) {
            Ok(gen) => {
                self.link.clear();
                self.error = None;
                Ok(gen)
            }
            Err(error) => {
                self.error = Some(error.to_string());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset() -> IranPreset {
        IranPreset::default()
    }

    fn entry_named(name: &str) -> &'static Entry {
        catalog()
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("no catalog entry named {name}"))
    }

    // Real 32-byte keys (base64 of bytes 0..32 for the secret, 7s for the
    // peer), because the parser correctly refuses anything else.
    const WG_LINK: &str = "wg://AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=@203.0.113.10:51820\
        ?publickey=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=&address=10.7.0.2/32#WG Node";

    // A `fm=` finalmask fragmenting 10-20 bytes, URL-encoded — the same shape
    // a link saved from another client carries.
    const FM: &str = "%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A%7B%22packets%22%3A%22tlshello%22%2C%22length%22%3A%2210-20%22%2C%22delay%22%3A%221-1%22%7D%7D%5D%7D";

    #[test]
    fn every_entry_is_presentable() {
        for entry in catalog() {
            assert!(!entry.name.trim().is_empty(), "{entry:?} has no name");
            assert!(!entry.detail.trim().is_empty(), "{entry:?} has no detail");
            // An entry that takes a link names the schemes it takes.
            match entry.input {
                Input::Link { schemes } => assert!(!schemes.is_empty(), "{entry:?}"),
                Input::None | Input::WarpAccount => {}
            }
        }
        // Names are unique: `generate` matches the self-contained kinds on
        // them, and a duplicated name would silently pick the first.
        let mut names: Vec<_> = catalog().iter().map(|e| e.name).collect();
        names.sort();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two entries share a name");
    }

    #[test]
    fn planned_entries_are_visible_but_not_connectable() {
        // The Tor entry runs only in a build with the feature; wherever it
        // is planned rather than available, generation must refuse it rather
        // than produce a config that connects nowhere.
        let tor = entry_named("Tor");
        assert_eq!(tor.available, cfg!(feature = "tor"));
        if !tor.available {
            assert_eq!(
                generate(tor, None, &preset(), &EvasionDefaults::default()),
                Err(GenerateError::Unavailable)
            );
            assert_eq!(
                generate(
                    tor,
                    Some("tor://#x"),
                    &preset(),
                    &EvasionDefaults::default()
                ),
                Err(GenerateError::Unavailable)
            );
        }
    }

    #[test]
    fn a_link_entry_builds_a_config_the_parser_accepts() {
        let entry = entry_named("WireGuard / Amnezia");
        let gen = generate(entry, Some(WG_LINK), &preset(), &EvasionDefaults::default())
            .expect("should build");
        let value: serde_json::Value =
            serde_json::from_str(&gen.json).expect("generated config is JSON");
        crate::parse_config(&value).expect("generated config parses");
        assert_eq!(gen.protocol, "amnezia-wg");
        assert_eq!(gen.endpoint, ("203.0.113.10".into(), 51820));
        assert_eq!(gen.remark, "WG Node");
    }

    // A vless over certificate TLS on raw TCP: the hello carries the server's
    // name in the clear, which is what a fragment default is for. ZeroV1 is
    // the catalog entry that takes such links, and the one the default is
    // measured for.
    fn tide_link() -> String {
        // Real-shaped keys, because the parser correctly refuses anything else.
        let key = "A".repeat(43);
        let user = "A".repeat(22);
        format!("zerov1://{user}@example.org:443?key={key}&path=/static/ab#n")
    }

    /// The fragment byte range the generated config's proxy carries, if any.
    fn fragment_of(gen: &Generated) -> Option<(u32, u32)> {
        let value: serde_json::Value = serde_json::from_str(&gen.json).unwrap();
        let (config, _) = crate::parse_config(&value).expect("generated config parses");
        let mask = config.outbounds[0].stream.evasion.tcp_fragment.as_ref()?;
        Some((mask.length.min, mask.length.max))
    }

    #[test]
    fn a_tls_entry_is_born_with_the_hello_fragment() {
        let gen = generate(
            entry_named("ZeroV1 (Tide)"),
            Some(&tide_link()),
            &preset(),
            &EvasionDefaults::default(),
        )
        .expect("should build");
        assert_eq!(
            fragment_of(&gen),
            Some((40, 80)),
            "the catalog's default lengths did not reach the config"
        );
    }

    #[test]
    fn a_length_override_reaches_the_config_and_a_bad_one_is_refused() {
        let entry = entry_named("ZeroV1 (Tide)");
        let tunned = EvasionDefaults {
            fragment_lengths: (10, 20),
            ..EvasionDefaults::default()
        };
        let gen = generate(entry, Some(&tide_link()), &preset(), &tunned).expect("should build");
        assert_eq!(fragment_of(&gen), Some((10, 20)), "{:?}", gen.json);

        // A length the parser refuses must be an error at generation, not a
        // config that fails later — the same bounds the config parser holds.
        let zero = EvasionDefaults {
            fragment_lengths: (0, 0),
            ..EvasionDefaults::default()
        };
        assert!(generate(entry, Some(&tide_link()), &preset(), &zero).is_err());
    }

    #[test]
    fn a_link_with_its_own_fragment_keeps_it_over_the_default() {
        let tide = format!(
            "zerov1://{user}@example.org:443?key={key}&path=/static/ab&fm={FM}#n",
            user = "A".repeat(22),
            key = "A".repeat(43),
        );
        let gen = generate(
            entry_named("ZeroV1 (Tide)"),
            Some(&tide),
            &preset(),
            &EvasionDefaults::default(),
        )
        .expect("should build");
        assert_eq!(
            fragment_of(&gen),
            Some((10, 20)),
            "the default overwrote the link's own fm="
        );
    }

    // A REALITY-carried ZeroV1 link, the shape the server installer hands
    // out. The pbk is the same real 32-byte key share the share-link tests
    // use; a browser fingerprint is required for REALITY to parse.
    fn tide_reality_link() -> String {
        format!(
            "zerov1://{user}@example.org:443?key={key}&path=/static/ab\
             &security=reality&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=ab&fp=chrome#n",
            user = "A".repeat(22),
            key = "A".repeat(43),
        )
    }

    #[test]
    fn a_reality_link_is_born_without_a_fragment() {
        // REALITY servers reject a split ClientHello, and the dial pass
        // never fragments one (`outbound_shreds_well`): a mask here would be
        // stored, shown and then stripped — or run and fail where the config
        // is used unbundled (`zray run`).
        let parsed = parse_link(&tide_reality_link()).expect("reality tide parses");
        assert!(matches!(
            parsed.outbound.stream.security,
            crate::model::Security::Reality(_)
        ));
        let gen = generate(
            entry_named("ZeroV1 (Tide)"),
            Some(&tide_reality_link()),
            &preset(),
            &EvasionDefaults::default(),
        )
        .expect("should build");
        assert_eq!(
            fragment_of(&gen),
            None,
            "REALITY was born with a fragment the dial refuses"
        );
    }

    #[test]
    fn kinds_without_a_hello_to_cut_carry_no_fragment() {
        use base64::Engine as _;
        // A WARP link carries a whole account; the smallest honest one is a
        // MASQUE route with real-shaped keys (see share_link's own tests).
        let der = base64::engine::general_purpose::STANDARD.encode([3u8; 40]);
        let account = serde_json::json!({
            "route": "masque-h2",
            "masque": {"privateKey": der, "serverPublicKey": der, "address": ["172.16.0.2"]}
        });
        let warp = format!(
            "warp://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(account.to_string())
        );
        let of = |link: &str| {
            let parsed = parse_link(link).unwrap();
            EvasionDefaults::default()
                .fragment_for(&parsed.outbound)
                .is_some()
        };
        // A WireGuard link has no TLS hello at all.
        assert!(!of(WG_LINK));
        // Hysteria 2 builds TLS over QUIC: the fragment would be config
        // weight the runtime never reads.
        assert!(!of("hysteria2://pw@1.2.3.4:443#h"));
        // Tor and MasterDNS name no TLS carrier of their own.
        assert!(!of("tor://#t"));
        // WARP rides MASQUE/WireGuard.
        assert!(!of(&warp));
    }

    #[test]
    fn switching_the_defaults_off_leaves_the_link_exactly_as_parsed() {
        let entry = entry_named("ZeroV1 (Tide)");
        let gen = generate(
            entry,
            Some(&tide_link()),
            &preset(),
            &EvasionDefaults::off(),
        )
        .expect("should build");
        assert_eq!(fragment_of(&gen), None, "off still added a fragment");
    }

    #[test]
    fn a_link_of_the_wrong_kind_is_rejected_with_reason() {
        let entry = entry_named("WireGuard / Amnezia");
        let vless =
            "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=tls&type=tcp#x";
        match generate(entry, Some(vless), &preset(), &EvasionDefaults::default()) {
            Err(GenerateError::LinkRejected(reason)) => {
                assert!(reason.contains("vless"), "says what was pasted: {reason}");
                assert!(reason.contains("wg"), "says what to supply: {reason}");
            }
            other => panic!("expected LinkRejected, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_link_keeps_the_parser_reason() {
        let entry = entry_named("WireGuard / Amnezia");
        match generate(
            entry,
            Some("wg://not-a-link"),
            &preset(),
            &EvasionDefaults::default(),
        ) {
            Err(GenerateError::LinkRejected(reason)) => {
                assert!(!reason.is_empty(), "the parser's reason is kept");
            }
            other => panic!("expected LinkRejected, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_link_is_a_missing_link_not_a_crash() {
        let entry = entry_named("WARP link");
        assert_eq!(
            generate(entry, Some("   "), &preset(), &EvasionDefaults::default()),
            Err(GenerateError::LinkRequired)
        );
        assert_eq!(
            generate(entry, None, &preset(), &EvasionDefaults::default()),
            Err(GenerateError::LinkRequired)
        );
    }

    #[test]
    fn the_warp_account_kind_points_to_its_own_dialog() {
        let entry = entry_named("Cloudflare WARP");
        assert!(!entry.takes_link());
        assert_eq!(
            generate(
                entry,
                Some("warp://abc"),
                &preset(),
                &EvasionDefaults::default()
            ),
            Err(GenerateError::SetupElsewhere)
        );
    }

    #[test]
    fn the_direct_entry_is_self_contained_and_parses() {
        let entry = entry_named("Direct");
        let gen = generate(entry, None, &preset(), &EvasionDefaults::default())
            .expect("direct builds from nothing");
        let value: serde_json::Value = serde_json::from_str(&gen.json).unwrap();
        crate::parse_config(&value).expect("direct config parses");
        assert_eq!(gen.protocol, "freedom");
        assert_eq!(gen.remark, "Direct");
    }

    #[test]
    fn the_callers_preset_choices_reach_the_generated_config() {
        // Ports and DNS the caller set (the app's settings) must survive the
        // one-click build, or generating a profile would silently change
        // what the person configured.
        let entry = entry_named("WireGuard / Amnezia");
        let preset = IranPreset {
            socks_port: 21080,
            http_port: Some(21081),
            ..IranPreset::default()
        };
        let gen = generate(entry, Some(WG_LINK), &preset, &EvasionDefaults::default())
            .expect("should build");
        let value: serde_json::Value = serde_json::from_str(&gen.json).unwrap();
        let ports: Vec<u64> = value["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|i| i["port"].as_u64())
            .collect();
        assert!(
            ports.contains(&21080) && ports.contains(&21081),
            "{ports:?}"
        );
    }

    #[test]
    fn a_link_with_no_remark_gets_the_kind_default_name() {
        let entry = entry_named("MasterDNS");
        let link = "masterdns://k@t.example.com?server=203.0.113.7&resolvers=9.9.9.9";
        let gen = generate(entry, Some(link), &preset(), &EvasionDefaults::default())
            .expect("should build");
        assert_eq!(gen.remark, "MASTERDNS-Node");
        assert_eq!(gen.endpoint, ("t.example.com".into(), 53));
    }

    // ------------------------------------------------------- the picker

    #[test]
    fn the_picker_filters_to_available_entries_usable_now() {
        let mut picker = Picker::default();
        // A link kind with an empty field is shown but not yet runnable, the
        // same rule the screen's Enter and button follow.
        while picker.entry().name != "WireGuard / Amnezia" {
            picker.move_by(1);
        }
        assert!(!picker.connectable(), "empty link field counted as ready");
        picker.set_link(WG_LINK);
        assert!(picker.connectable());

        // The WARP-account kind is never generated here, whatever is typed.
        while picker.entry().name != "Cloudflare WARP" {
            picker.move_by(1);
        }
        assert!(!picker.connectable());
    }

    #[test]
    fn the_picker_starts_on_a_usable_entry_and_wraps() {
        let mut picker = Picker::default();
        assert!(
            picker.entry().available,
            "opened on {:?}, which this build cannot run",
            picker.entry().name
        );
        // A full lap down lands back where it started, and a step up from
        // the first row wraps to the last — the list never dead-ends.
        picker.move_by(catalog().len() as i32);
        assert_eq!(picker.selected, Picker::default().selected);
        picker.select(0);
        picker.move_by(-1);
        assert_eq!(picker.selected, catalog().len() - 1);
        // A click past the end is ignored rather than wrapped, so the
        // highlight always names a row that exists.
        picker.select(catalog().len() + 7);
        assert_eq!(
            picker.selected,
            catalog().len() - 1,
            "a click past the end is ignored, not clamped mid-list"
        );
    }

    #[test]
    fn a_connect_through_the_picker_reaches_generation_with_the_typed_link() {
        // The full gesture the screen performs on Enter: type the link, pick
        // the kind, build. The generated config must be the same one the
        // direct call produces, so nothing is lost between field and profile.
        let mut picker = Picker::default();
        while picker.entry().name != "WARP link" {
            picker.move_by(1);
        }
        picker.set_link("   ");
        assert!(
            picker
                .generate(&preset(), &EvasionDefaults::default())
                .is_err(),
            "a blank field generated a config"
        );
        assert!(picker.error.is_some(), "the reason reached the field");

        picker.set_link(WG_LINK);
        // Still on the wrong kind: a filled field alone is not enough, the
        // highlight decides which link the field is held to be.
        while picker.entry().name != "WireGuard / Amnezia" {
            picker.move_by(1);
        }
        picker.set_link(WG_LINK);
        let gen = picker
            .generate(&preset(), &EvasionDefaults::default())
            .expect("ready entry builds");
        assert_eq!(gen.protocol, "amnezia-wg");
        // A successful build leaves the field clean for the next entry.
        assert!(picker.link.is_empty() && picker.error.is_none());
    }

    #[test]
    fn the_picker_clears_the_stale_reason_as_soon_as_its_input_changes() {
        let mut picker = Picker::default();
        while picker.entry().name != "WireGuard / Amnezia" {
            picker.move_by(1);
        }
        let _ = picker.generate(&preset(), &EvasionDefaults::default());
        assert!(picker.error.is_some());
        picker.push_link('w');
        assert!(picker.error.is_none(), "typing left the old reason up");
        let _ = picker.generate(&preset(), &EvasionDefaults::default());
        assert!(picker.error.is_some());
        picker.pop_link();
        assert!(picker.error.is_none(), "backspacing left the old reason up");

        // Moving the highlight also retires the reason: it described the
        // entry it was raised for, and the highlight has moved on.
        let _ = picker.generate(&preset(), &EvasionDefaults::default());
        assert!(picker.error.is_some());
        picker.move_by(1);
        assert!(picker.error.is_none(), "moving left the old reason up");
        let _ = picker.generate(&preset(), &EvasionDefaults::default());
        assert!(picker.error.is_some());
        if let Some(index) = catalog().iter().position(|e| e.name == "ZeroV1 (Tide)") {
            picker.select(index);
        } else {
            panic!("the catalog lost the ZeroV1 (Tide) entry");
        }
        assert!(
            picker.error.is_none(),
            "clicking a row left the old reason up"
        );
    }
}
