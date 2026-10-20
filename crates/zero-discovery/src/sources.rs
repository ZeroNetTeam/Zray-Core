//! The public config feeds a client searches, tiered by what measurement
//! from inside Iran showed. Tier 0 is this project's own tested (and signed)
//! list; tier 1 is fetched on every cold search that tier 0 did not
//! satisfy; tier 2 only when tier 1 fell short; tier 3 only when asked to
//! search harder. The Android app keeps the same list in `data/Sources.kt`.

use crate::feed::FeedSource;

const RAW: &str = "https://raw.githubusercontent.com";

/// A feed with its display name, for hosts that let the user switch feeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSource {
    pub name: &'static str,
    pub source: FeedSource,
}

fn source(
    id: &str,
    name: &'static str,
    url: String,
    tier: u32,
    sig_url: Option<String>,
) -> NamedSource {
    let mirrors = cdn_mirrors(&url);
    NamedSource {
        name,
        source: FeedSource {
            id: id.into(),
            url,
            tier,
            sig_url,
            mirrors,
        },
    }
}

/// The other CDNs serving the same file.
///
/// GitHub raw, jsDelivr and Fastly are filtered at different times in Iran,
/// so every feed whose URL maps cleanly gets the other paths to the same
/// bytes: `raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>` becomes
/// `cdn.jsdelivr.net/gh/<owner>/<repo>@<branch>/<path>` and
/// `fastly.jsdelivr.net/gh/<owner>/<repo>@<branch>/<path>`, and jsDelivr
/// shapes map back to raw. Nothing is guessed: a URL that does not match any
/// shape gets no mirror.
fn cdn_mirrors(url: &str) -> Vec<String> {
    const RAW: &str = "https://raw.githubusercontent.com/";
    const JSD: &str = "https://cdn.jsdelivr.net/gh/";
    const FASTLY: &str = "https://fastly.jsdelivr.net/gh/";
    if let Some(rest) = url.strip_prefix(RAW) {
        let mut parts = rest.splitn(4, '/');
        let owner = parts.next().unwrap_or_default();
        let repo = parts.next().unwrap_or_default();
        let branch = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();
        if owner.is_empty() || repo.is_empty() || branch.is_empty() || path.is_empty() {
            return Vec::new();
        }
        return vec![
            format!("{JSD}{owner}/{repo}@{branch}/{path}"),
            format!("{FASTLY}{owner}/{repo}@{branch}/{path}"),
        ];
    }
    let jsdelivr = url
        .strip_prefix(JSD)
        .map(|rest| (rest, JSD))
        .or_else(|| url.strip_prefix(FASTLY).map(|rest| (rest, FASTLY)));
    if let Some((rest, _)) = jsdelivr {
        let mut parts = rest.splitn(3, '/');
        let owner = parts.next().unwrap_or_default();
        let repo_ref = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();
        let Some((repo, branch)) = repo_ref.split_once('@') else {
            return Vec::new();
        };
        if owner.is_empty() || repo.is_empty() || branch.is_empty() || path.is_empty() {
            return Vec::new();
        }
        return vec![format!("{RAW}{owner}/{repo}/{branch}/{path}")];
    }
    Vec::new()
}

/// The mirrors implied by a feed URL's CDN shape, for callers that did not
/// carry a mirror list of their own (see [`FeedSource::with_derived_mirrors`]).
pub fn cdn_mirrors_for(url: &str) -> Vec<String> {
    cdn_mirrors(url)
}

/// Every built-in feed.
///
/// **Size is a feature.** These are downloaded by the phone, on the phone's
/// own connection, and every byte and every candidate in them costs the user
/// battery and mobile data. The server-side harvest tests the big aggregators
/// every two hours and publishes whatever works into tier 0, so this list is
/// held to feeds that gzip to roughly a quarter of a megabyte or less. The
/// larger lists are not gone — they live in `deploy/crowd/sources.json`,
/// where testing them is a datacentre's job and not the user's phone. Below,
/// each entry carries its measured gzipped size (2026-10-09) so the next
/// addition can be weighed against the same budget.
pub fn builtin() -> Vec<NamedSource> {
    let verified = "https://cdn.jsdelivr.net/gh/ZeroNetTeam/Zray-Core@crowd-data/verified.txt";
    vec![
        source(
            "zeronet",
            "ZeroNet verified",
            verified.into(),
            0,
            Some(format!("{verified}.sig")),
        ),
        // Tier 1: fetched on every cold search that tier 0 did not satisfy, so
        // the whole tier is kept near 90 KB: the small tested feeds and the
        // small Iranian collections, which are a few good servers each for
        // almost nothing.
        source(
            "sinavm",
            "SVM",
            format!("{RAW}/sinavm/SVM/main/lite/subscriptions/xray/base64/mix"),
            1,
            None,
        ),
        source(
            "anonymou3",
            "Multi Proxy (tested)",
            format!(
                "{RAW}/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt"
            ),
            1,
            None,
        ),
        // Publishes only the configs its own measurer kept, so it is a few
        // hundred tested servers rather than thousands of unproven ones (25 KB).
        source(
            "matin",
            "v2ray-configs (best tested)",
            format!("{RAW}/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"),
            1,
            None,
        ),
        // Re-checked every few minutes before publication (9 KB).
        source(
            "roosterkid",
            "OpenProxyList (hourly)",
            format!("{RAW}/roosterkid/openproxylist/main/V2RAY_RAW.txt"),
            1,
            None,
        ),
        source(
            "yebekhe",
            "vpn-fail",
            format!("{RAW}/yebekhe/vpn-fail/main/sub-link"),
            1,
            None,
        ),
        source(
            "mahdi0024",
            "ProxyCollector (Iran)",
            format!("{RAW}/Mahdi0024/ProxyCollector/master/sub/proxies.txt"),
            1,
            None,
        ),
        source(
            "norouzi",
            "Iran configs (working)",
            format!("{RAW}/MrAbolfazlNorouzi/iran-configs/main/configs/working-configs.txt"),
            1,
            None,
        ),
        // Mobile-carrier specific: configs that still pass on Irancell, which
        // fails differently from the fixed-line providers (6 KB).
        source(
            "irancell",
            "Irancell configs",
            format!("{RAW}/morteza-v2/free-v2ray-irancell-config/main/Sub1.txt"),
            1,
            None,
        ),
        // The list the UAC client ships as its one-tap source: rebuilds daily
        // from a few dozen upstream lists and keeps only nodes it re-tested,
        // three variants each (8 KB gzipped, measured 2026-10-16).
        source(
            "patterniha",
            "Free-Configs (Iran)",
            format!("{RAW}/patterniha/Free-Configs/main/configs.txt"),
            1,
            None,
        ),
        // Tier 2: only when tier 1 fell short (~440 KB in total).
        source(
            "limilco",
            "liMilCo",
            format!("{RAW}/liMilCo/v2r/main/new_configs.txt"),
            2,
            None,
        ),
        source(
            "solvpn",
            "SolVPN (tested)",
            format!("{RAW}/SoliSpirit/SolVPN/main/all_configs.txt"),
            2,
            None,
        ),
        source(
            "miladtahanian",
            "Config-Collector (Iran)",
            format!("{RAW}/miladtahanian/Config-Collector/main/mixed_iran.txt"),
            2,
            None,
        ),
        source(
            "f0rc3run",
            "F0rc3Run",
            format!("{RAW}/F0rc3Run/F0rc3Run/main/Best-Results/sub.txt"),
            2,
            None,
        ),
        source(
            "bahemmat",
            "V2ray-Collector (Iran)",
            format!("{RAW}/MohammadBahemmat/V2ray-Collector/main/all_servers.txt"),
            2,
            None,
        ),
        // Tier 3: only when the caller asked to search harder (~820 KB in
        // total). Medium lists, still bounded; the multi-megabyte aggregators
        // are server-side only (see the doc comment above).
        source(
            "epodonios",
            "Epodonios",
            format!("{RAW}/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"),
            3,
            None,
        ),
        // Tested and sorted by measured speed before it is published, so its
        // first entries tend to be the fastest servers in any feed here.
        source(
            "mahdibland",
            "V2RayAggregator (speed-tested)",
            format!("{RAW}/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"),
            3,
            None,
        ),
        source(
            "freedom",
            "Freedom-V2Ray",
            format!("{RAW}/MahanKenway/Freedom-V2Ray/main/configs/mix.txt"),
            3,
            None,
        ),
        source(
            "proxykma",
            "proxykma (Iran)",
            format!("{RAW}/amirkma/proxykma/main/mix.txt"),
            3,
            None,
        ),
        source(
            "vpnclashfa",
            "VPNClashFa (Iran)",
            format!("{RAW}/10ium/VpnClashFaCollector/main/sub/all/mixed.txt"),
            3,
            None,
        ),
        source(
            "autoaivpn",
            "AutoAiVPN (Iran)",
            format!("{RAW}/penhandev/AutoAiVPN/main/iran.txt"),
            3,
            None,
        ),
    ]
}

/// The feeds to search: every built-in one up to `max_tier` not in `disabled`.
pub fn enabled(disabled: &[String], max_tier: u32) -> Vec<FeedSource> {
    builtin()
        .into_iter()
        .filter(|named| {
            named.source.tier <= max_tier && !disabled.iter().any(|id| id == &named.source.id)
        })
        .map(|named| named.source)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_the_verified_list_is_signed_and_first() {
        let all = builtin();
        let mut ids: Vec<_> = all.iter().map(|n| n.source.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
        assert_eq!(all[0].source.tier, 0);
        assert!(all[0].source.sig_url.is_some());
        assert!(all.iter().all(|n| n.source.url.starts_with("https://")));
    }

    /// The feeds that test their own list before publishing are the likeliest
    /// place a cold search finds a fast server, and the Iran-focused ones are
    /// what a network inside the country reaches when the global aggregators
    /// are thin. Both sets are easy to drop by accident when the list is
    /// edited, so they are pinned here — and the tier-1 ones are pinned to
    /// tier 1, because a cold search must not be able to read a big feed.
    #[test]
    fn the_speed_tested_and_iran_focused_feeds_are_present() {
        let all = builtin();
        let has = |id: &str| all.iter().any(|named| named.source.id == id);
        for id in [
            "sinavm",
            "anonymou3",
            "matin",
            "roosterkid",
            "yebekhe",
            "mahdi0024",
            "norouzi",
            "irancell",
            "patterniha",
        ] {
            let named = all
                .iter()
                .find(|named| named.source.id == id)
                .unwrap_or_else(|| panic!("{id} is missing"));
            assert!(
                named.source.tier == 1,
                "{id} must be a small tier-1 feed, not tier {}",
                named.source.tier
            );
        }
        for id in [
            "limilco",
            "solvpn",
            "miladtahanian",
            "f0rc3run",
            "bahemmat",
            "epodonios",
            "mahdibland",
            "freedom",
            "proxykma",
            "vpnclashfa",
            "autoaivpn",
        ] {
            assert!(has(id), "{id} is missing");
        }
    }

    /// The multi-hundred-KB and multi-MB aggregators are tested by the
    /// server-side harvest instead, whose results reach the device as tier 0.
    /// On the phone they would be paid for in battery and mobile data on
    /// every search that fell past tier 1, so a device must never be told to
    /// fetch one. This is the guard for that rule.
    #[test]
    fn the_big_aggregators_are_not_on_the_device_list() {
        for id in ["radikal", "ebrasha", "delta", "mheidari", "barryfar"] {
            assert!(
                !builtin().iter().any(|named| named.source.id == id),
                "{id} is too large for a phone; keep it server-side"
            );
        }
    }

    #[test]
    fn disabled_feeds_and_higher_tiers_are_left_out() {
        let some = enabled(&["limilco".into()], 1);
        assert!(some.iter().all(|s| s.tier <= 1 && s.id != "limilco"));
        assert!(some.iter().any(|s| s.id == "zeronet"));
    }

    #[test]
    fn every_feed_carries_the_other_cdns_as_mirrors() {
        for named in builtin() {
            let source = &named.source;
            let mirror = source
                .mirrors
                .first()
                .unwrap_or_else(|| panic!("{} has no mirror", source.id));
            assert_ne!(mirror, &source.url);
            assert!(mirror.starts_with("https://"));
            // A raw-primary feed is reachable through both jsDelivr hosts, so
            // all three CDNs have to be filtered together to starve it; the
            // verified feed's primary is itself jsDelivr and maps back to raw.
            if source.url.starts_with("https://raw.githubusercontent.com/") {
                assert!(
                    source.mirrors.len() == 2
                        && source
                            .mirrors
                            .iter()
                            .any(|m| m.starts_with("https://fastly.jsdelivr.net/gh/")),
                    "{} should carry both jsDelivr mirrors",
                    source.id
                );
            }
        }
        assert_eq!(
            cdn_mirrors("https://raw.githubusercontent.com/a/b/main/c.txt"),
            vec![
                "https://cdn.jsdelivr.net/gh/a/b@main/c.txt".to_string(),
                "https://fastly.jsdelivr.net/gh/a/b@main/c.txt".to_string(),
            ]
        );
        assert_eq!(
            cdn_mirrors("https://cdn.jsdelivr.net/gh/a/b@main/c.txt"),
            vec!["https://raw.githubusercontent.com/a/b/main/c.txt".to_string()]
        );
        assert_eq!(
            cdn_mirrors("https://fastly.jsdelivr.net/gh/a/b@main/c.txt"),
            vec!["https://raw.githubusercontent.com/a/b/main/c.txt".to_string()]
        );
        assert!(cdn_mirrors("https://example.com/x").is_empty());
    }
}
