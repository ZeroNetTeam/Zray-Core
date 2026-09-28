//! Which anti-sanction resolver to trust on this network, and for which names.
//!
//! Anti-sanction DNS answers a sanctioned name (a Google developer page, an AI
//! service) with the address of the provider's relay, so the site sees the
//! relay rather than an Iranian address. Measured from Tehran (FANAP) on
//! 2026-09-28 it is far less uniform than a fixed list suggests:
//!
//! * only one provider (Bertina) relayed at all — `developer.android.com` and
//!   `gemini.google.com` went from 403 to 200 through it;
//! * another (begzar) answered every name, domestic ones included, with a
//!   root server's address;
//! * a third (radar) did not answer;
//! * the rest answered honestly, which for a sanctioned name means the
//!   service's real address — and a direct connection there is the 403.
//!
//! So each candidate is measured on the current network: does it answer, are
//! its answers sane (a domestic name resolves where the other candidates say
//! it does), and which address does it relay through — the one it returns
//! for names of *different* companies, since an honest resolver can return
//! one address for two names of the same company. The best relayer wins, ties
//! going to the faster.
//!
//! A sanctioned name then goes direct only when the chosen resolver answers
//! it with its relay address. Any other answer would reach the service from
//! an Iranian address and be refused, so that name goes through the tunnel.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use zero_config::dns::ResolverEndpoint;
use zero_core::Address;

/// The DNS tag the Iran preset gives its anti-sanction resolvers.
pub const TAG: &str = "anti-sanction";
/// Re-measure this often on a network that has not changed.
pub const RECHECK: Duration = Duration::from_secs(30 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// A domestic name every honest Iranian resolver answers the same way.
const DOMESTIC_NAME: &str = "digikala.com";
/// Sanctioned names grouped by who runs them. A relay address is one
/// answered for names of at least two groups.
const PROBE_NAMES: &[(&str, &str)] = &[
    ("google", "developer.android.com"),
    ("google", "gemini.google.com"),
    ("google", "firebase.google.com"),
    ("docker", "docker.io"),
    ("jetbrains", "jetbrains.com"),
    ("anthropic", "anthropic.com"),
];

/// The built-in providers by address, for reporting a choice by name. A
/// resolver the user typed in themselves is never named in a report.
const PROVIDERS: &[(&str, &str)] = &[
    ("bertina", "193.186.32.32"),
    ("shecan", "178.22.122.100"),
    ("shecan", "185.51.200.2"),
    ("electro", "78.157.42.100"),
    ("electro", "78.157.42.101"),
    ("ipm", "194.225.152.10"),
    ("begzar", "185.55.226.26"),
    ("begzar", "185.55.225.25"),
    ("radar", "10.202.10.10"),
    ("radar", "10.202.10.11"),
];

/// The crowd-report id for a measured state: the chosen built-in provider,
/// `sanction:none` when nothing relayed, or nothing for a custom resolver.
pub fn method_id(state: &SanctionState) -> Option<&'static str> {
    let Some(chosen) = state.chosen else {
        return Some("sanction:none");
    };
    let name = PROVIDERS
        .iter()
        .find(|(_, address)| address.parse::<IpAddr>().ok() == Some(chosen))?
        .0;
    Some(match name {
        "bertina" => "sanction:bertina",
        "shecan" => "sanction:shecan",
        "electro" => "sanction:electro",
        "ipm" => "sanction:ipm",
        "begzar" => "sanction:begzar",
        _ => "sanction:radar",
    })
}

/// The measured choice for the current network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanctionState {
    /// The resolver to use, or `None` when no candidate relays anything
    /// here — then sanctioned names go through the tunnel.
    pub chosen: Option<IpAddr>,
    /// The chosen resolver's relay addresses.
    pub relay: Vec<IpAddr>,
}

impl SanctionState {
    /// The resolver tag pinned to the chosen server.
    pub fn pinned_tag(&self) -> Option<String> {
        self.chosen.map(|ip| format!("{TAG}@{ip}"))
    }

    /// Whether `answers` (the chosen resolver's answer for a name) point at
    /// its relay, so a direct connection gets the relayed service.
    pub fn relays(&self, answers: &[IpAddr]) -> bool {
        answers.iter().any(|answer| self.relay.contains(answer))
    }
}

/// One candidate's measurements.
#[derive(Debug, Clone)]
struct Measured {
    server: IpAddr,
    latency: Duration,
    domestic: Vec<IpAddr>,
    /// Probe answers, one entry per probe name that was answered.
    answers: Vec<(&'static str, Vec<IpAddr>)>,
}

/// The anti-sanction candidates in `dns`: plain resolvers on port 53 with an
/// address (the only kind a censored network can reach without a lookup).
pub fn candidates(dns: &zero_config::dns::DnsSettings) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for server in dns.servers.iter() {
        if server.tag.as_deref() != Some(TAG) {
            continue;
        }
        if let ResolverEndpoint::Udp {
            address: Address::Ip(ip),
            port: 53,
        } = server.endpoint
        {
            if !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found
}

/// Measure every candidate at once and choose. Costs one domestic and six
/// sanctioned lookups per candidate, a few kilobytes in all.
pub async fn probe(candidates: &[IpAddr]) -> SanctionState {
    let measured = futures::future::join_all(candidates.iter().map(|ip| measure(*ip))).await;
    choose(measured.into_iter().flatten().collect())
}

async fn measure(server: IpAddr) -> Option<Measured> {
    let address = SocketAddr::new(server, 53);
    let (domestic, latency) = zero_dns::probe_udp(address, DOMESTIC_NAME, QUERY_TIMEOUT)
        .await
        .ok()?;
    if domestic.is_empty() {
        return None;
    }
    let answers = futures::future::join_all(PROBE_NAMES.iter().map(|(group, name)| async move {
        zero_dns::probe_udp(address, name, QUERY_TIMEOUT)
            .await
            .ok()
            .filter(|(ips, _)| !ips.is_empty())
            .map(|(ips, _)| (*group, ips))
    }))
    .await
    .into_iter()
    .flatten()
    .collect();
    Some(Measured {
        server,
        latency,
        domestic,
        answers,
    })
}

/// Pick the candidate that relays the most, among those whose domestic
/// answer agrees with the majority.
fn choose(measured: Vec<Measured>) -> SanctionState {
    // The /16 most candidates put the domestic name in. A resolver that
    // disagrees is broken or lying, and its "relay" means nothing.
    let mut votes: HashMap<[u8; 2], usize> = HashMap::new();
    for candidate in &measured {
        let mut seen = Vec::new();
        for ip in &candidate.domestic {
            if let Some(prefix) = prefix16(*ip) {
                if !seen.contains(&prefix) {
                    seen.push(prefix);
                    *votes.entry(prefix).or_default() += 1;
                }
            }
        }
    }
    let consensus = votes
        .into_iter()
        .max_by_key(|(prefix, count)| (*count, *prefix))
        .map(|(prefix, _)| prefix);

    let mut best: Option<(usize, Duration, IpAddr, Vec<IpAddr>)> = None;
    for candidate in measured {
        let sane = candidate
            .domestic
            .iter()
            .any(|ip| prefix16(*ip).is_some() && prefix16(*ip) == consensus);
        if !sane {
            continue;
        }
        let relay = relay_addresses(&candidate.answers);
        if relay.is_empty() {
            continue;
        }
        let relayed = candidate
            .answers
            .iter()
            .filter(|(_, ips)| ips.iter().any(|ip| relay.contains(ip)))
            .count();
        let better = match &best {
            None => true,
            Some((count, latency, _, _)) => {
                relayed > *count || (relayed == *count && candidate.latency < *latency)
            }
        };
        if better {
            best = Some((relayed, candidate.latency, candidate.server, relay));
        }
    }
    match best {
        Some((_, _, server, relay)) => SanctionState {
            chosen: Some(server),
            relay,
        },
        None => SanctionState {
            chosen: None,
            relay: Vec::new(),
        },
    }
}

/// Addresses answered for names of at least two different groups.
fn relay_addresses(answers: &[(&'static str, Vec<IpAddr>)]) -> Vec<IpAddr> {
    let mut groups: HashMap<IpAddr, Vec<&'static str>> = HashMap::new();
    for (group, ips) in answers {
        for ip in ips {
            let entry = groups.entry(*ip).or_default();
            if !entry.contains(group) {
                entry.push(group);
            }
        }
    }
    let mut relay: Vec<IpAddr> = groups
        .into_iter()
        .filter(|(_, groups)| groups.len() >= 2)
        .map(|(ip, _)| ip)
        .collect();
    relay.sort();
    relay
}

fn prefix16(ip: IpAddr) -> Option<[u8; 2]> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some([octets[0], octets[1]])
        }
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn measured(
        server: &str,
        ms: u64,
        domestic: &str,
        answers: &[(&'static str, &str)],
    ) -> Measured {
        Measured {
            server: ip(server),
            latency: Duration::from_millis(ms),
            domestic: vec![ip(domestic)],
            answers: answers
                .iter()
                .map(|(group, answer)| (*group, vec![ip(answer)]))
                .collect(),
        }
    }

    /// The answers measured from Tehran on 2026-09-28, trimmed.
    fn tehran() -> Vec<Measured> {
        vec![
            // Honest: the services' real addresses; two Google names share one.
            measured(
                "178.22.122.100",
                80,
                "185.188.104.10",
                &[
                    ("google", "142.250.202.174"),
                    ("google", "142.250.202.174"),
                    ("docker", "34.230.221.175"),
                    ("jetbrains", "3.167.227.123"),
                ],
            ),
            // Bertina: one relay address for every company.
            measured(
                "193.186.32.32",
                82,
                "185.188.104.10",
                &[
                    ("google", "132.243.209.113"),
                    ("google", "132.243.209.113"),
                    ("docker", "132.243.209.113"),
                    ("jetbrains", "132.243.209.113"),
                    ("anthropic", "132.243.209.113"),
                ],
            ),
            // begzar: a root server's address for everything, domestic too.
            measured(
                "185.55.226.26",
                76,
                "198.41.0.4",
                &[
                    ("google", "198.41.0.4"),
                    ("docker", "198.41.0.4"),
                    ("jetbrains", "198.41.0.4"),
                ],
            ),
            measured(
                "78.157.42.100",
                81,
                "185.188.104.10",
                &[("google", "142.251.150.2"), ("jetbrains", "3.167.227.89")],
            ),
        ]
    }

    #[test]
    fn picks_the_relaying_resolver_and_rejects_the_broken_one() {
        let state = choose(tehran());
        assert_eq!(state.chosen, Some(ip("193.186.32.32")));
        assert_eq!(state.relay, vec![ip("132.243.209.113")]);
        assert_eq!(
            state.pinned_tag().as_deref(),
            Some("anti-sanction@193.186.32.32")
        );
        assert!(state.relays(&[ip("132.243.209.113")]));
        // Bertina answered chatgpt.com with a plain Cloudflare address:
        // direct there is the 403, so it must not count as relayed.
        assert!(!state.relays(&[ip("188.114.98.0")]));
    }

    #[test]
    fn one_company_sharing_an_address_is_not_a_relay() {
        let honest = &tehran()[0];
        assert!(relay_addresses(&honest.answers).is_empty());
    }

    #[test]
    fn with_no_relay_anywhere_nothing_is_chosen() {
        let mut measured = tehran();
        measured.remove(1);
        let state = choose(measured);
        assert_eq!(state.chosen, None);
        assert!(!state.relays(&[ip("142.250.202.174")]));
    }

    #[test]
    fn reports_name_built_in_providers_only() {
        let chosen = |address: &str| SanctionState {
            chosen: Some(ip(address)),
            relay: Vec::new(),
        };
        assert_eq!(
            method_id(&chosen("193.186.32.32")),
            Some("sanction:bertina")
        );
        assert_eq!(method_id(&chosen("185.51.200.2")), Some("sanction:shecan"));
        // A resolver the user typed in could identify them: never reported.
        assert_eq!(method_id(&chosen("203.0.113.53")), None);
        let none = SanctionState {
            chosen: None,
            relay: Vec::new(),
        };
        assert_eq!(method_id(&none), Some("sanction:none"));
    }

    #[test]
    fn candidates_are_the_tagged_plain_resolvers() {
        let dns = zero_config::dns::DnsSettings {
            servers: vec![
                zero_config::dns::DnsServer {
                    endpoint: ResolverEndpoint::parse("193.186.32.32").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some(TAG.into()),
                },
                zero_config::dns::DnsServer {
                    endpoint: ResolverEndpoint::parse("https://1.1.1.1/dns-query").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some(TAG.into()),
                },
                zero_config::dns::DnsServer {
                    endpoint: ResolverEndpoint::parse("8.8.8.8").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some("remote".into()),
                },
            ]
            .into_boxed_slice(),
            ..Default::default()
        };
        assert_eq!(candidates(&dns), vec![ip("193.186.32.32")]);
    }
}
