//! Public lists the UI offers, grouped by where they come from. A source either has variants of one list, of which
//! one is used at a time (the same list over different periods), or several lists that are each used, or not, on
//! their own (categories, services). Each list has a suggested use; what is used is up to the user.
//!
//! Lists that repeat others are left out: the AI crawlers come from one source, by company and purpose, and the
//! search engines and SEO crawlers from another.

use serde::Serialize;

#[cfg(test)]
use ts_rs::TS;

use super::Content;

const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

/// What a list of the catalog does once added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "snake_case")]
pub enum Use {
    Off,
    Block,
    Allow,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Addresses seen attacking or abusing.
    Threats,
    /// Crawlers, bots and monitors, by their published addresses or their user agents.
    Bots,
    /// Networks: proxies, hosting, anonymizers.
    Networks,
}

/// How a source's lists are picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "snake_case")]
pub enum Pick {
    /// One of the lists at a time: they are the same list over different periods. They share a feed (and its
    /// name), whose URL changes with the choice.
    One,
    /// Each list on its own.
    Many,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub key: String,
    /// The feed's name once added.
    pub name: String,
    /// What the UI calls the choice (for `one`: the period).
    pub label: String,
    pub description: String,
    pub url: String,
    pub select: Option<String>,
    pub content: Content,
    pub suggested: Use,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub id: String,
    pub name: String,
    pub description: String,
    pub homepage: String,
    pub category: Category,
    pub pick: Pick,
    /// How often the lists change upstream, as their maintainers say; `null`: not said.
    pub updates: Option<String>,
    /// The suggested time between fetches.
    #[cfg_attr(test, ts(type = "number"))]
    pub refresh_secs: u64,
    /// What to know before using it.
    pub note: Option<String>,
    pub items: Vec<Item>,
}

struct S {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    homepage: &'static str,
    category: Category,
    pick: Pick,
    updates: Option<&'static str>,
    refresh_secs: u64,
    note: Option<&'static str>,
}

impl S {
    fn with(self, items: Vec<Item>) -> Source {
        Source {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            description: self.description.to_owned(),
            homepage: self.homepage.to_owned(),
            category: self.category,
            pick: self.pick,
            updates: self.updates.map(str::to_owned),
            refresh_secs: self.refresh_secs,
            note: self.note.map(str::to_owned),
            items,
        }
    }
}

/// A list of addresses.
fn item(key: &str, name: &str, label: &str, description: &str, url: &str, suggested: Use) -> Item {
    Item {
        key: key.to_owned(),
        name: name.to_owned(),
        label: label.to_owned(),
        description: description.to_owned(),
        url: url.to_owned(),
        select: None,
        content: Content::Addresses,
        suggested,
    }
}

/// A period of a list that comes in several (`Pick::One`).
fn period(key: &str, name: &str, days: u32, url: &str, suggested: bool) -> Item {
    let label = if days == 1 {
        "1 day".to_owned()
    } else {
        format!("{days} days")
    };
    item(
        key,
        name,
        &label,
        &format!("Addresses seen in the last {label}"),
        url,
        if suggested { Use::Block } else { Use::Off },
    )
}

const IPVERSE_CRAWLERS: &str =
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/crawlers.json";
const IPVERSE_MONITORING: &str =
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/monitoring.json";

/// A service of an ipverse document.
fn service(url: &str, service: &str, name: &str, description: &str, suggested: Use) -> Item {
    Item {
        select: Some(format!(
            "/services/{}",
            service.replace('~', "~0").replace('/', "~1")
        )),
        ..item(service, name, name, description, url, suggested)
    }
}

/// An AI crawler's list of the tbeachill/ai-crawler-ip-ranges repository.
fn ai(file: &str, name: &str, description: &str, suggested: Use) -> Item {
    item(
        file,
        name,
        name,
        description,
        &format!(
            "https://raw.githubusercontent.com/tbeachill/ai-crawler-ip-ranges/main/ip_{file}.txt"
        ),
        suggested,
    )
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn catalog() -> Vec<Source> {
    use Category::{Bots, Networks, Threats};
    use Use::{Allow, Block, Data, Off};
    let firehol = |set: &str, name: &str, description: &str, suggested: Use| {
        item(
            set,
            name,
            name,
            description,
            &format!("https://iplists.firehol.org/files/{set}.netset"),
            suggested,
        )
    };
    let blocklist_de = |list: &str, name: &str, description: &str, suggested: Use| {
        item(
            list,
            name,
            name,
            description,
            &format!("https://lists.blocklist.de/lists/{list}.txt"),
            suggested,
        )
    };
    let shadow = |list: &str, name: &str, description: &str, suggested: Use| {
        item(
            list,
            name,
            name,
            description,
            &format!("https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Lists/{list}"),
            suggested,
        )
    };
    let abuseipdb = |days: u32, suggested: bool| {
        period(
            &format!("{days}d"),
            "AbuseIPDB",
            days,
            &format!(
                "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-{days}d.ipv4"
            ),
            suggested,
        )
    };
    let ipnoise = |days: u32, suggested: bool| {
        period(
            &format!("{days}d"),
            "IPnoise",
            days,
            &format!("https://ipnoise.sekuripy.hr/{days}d.txt"),
            suggested,
        )
    };
    let crawler = |s: &str, name: &str, d: &str, u: Use| service(IPVERSE_CRAWLERS, s, name, d, u);
    let monitor = |s: &str, d: &str| service(IPVERSE_MONITORING, s, s, d, Off);
    vec![
        S {
            id: "spamhaus",
            name: "Spamhaus DROP",
            description: "Networks hijacked or leased by spammers and cybercriminals: \"Don't Route Or Peer\". Small, and \
                          practically free of false positives.",
            homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
            category: Threats,
            pick: Pick::Many,
            updates: None,
            refresh_secs: 12 * HOUR,
            note: None,
        }
        .with(vec![
            item("drop_v4", "Spamhaus DROP", "IPv4", "IPv4 networks", "https://www.spamhaus.org/drop/drop_v4.json", Block),
            item(
                "drop_v6",
                "Spamhaus DROP (IPv6)",
                "IPv6",
                "IPv6 networks",
                "https://www.spamhaus.org/drop/drop_v6.json",
                Block,
            ),
        ]),
        S {
            id: "firehol",
            name: "FireHOL",
            description: "Lists combined from many public blocklists. The levels go from the safest to the widest; each \
                          has what the levels before it don't.",
            homepage: "https://iplists.firehol.org/",
            category: Threats,
            pick: Pick::Many,
            updates: Some("Every few minutes to every few days, by list"),
            refresh_secs: HOUR,
            note: Some("Level 2 includes blocklist.de's whole list: with it, blocklist.de's \"all\" adds nothing."),
        }
        .with(vec![
            firehol(
                "firehol_level1",
                "FireHOL level 1",
                "Spamhaus DROP and EDROP, DShield's top attackers, Feodo and bogons: the safest, meant to be blocked \
                 everywhere",
                Block,
            ),
            firehol(
                "firehol_level2",
                "FireHOL level 2",
                "Addresses attacking in about the last 48 hours (blocklist.de, DShield, GreenSnow and others)",
                Block,
            ),
            firehol(
                "firehol_level3",
                "FireHOL level 3",
                "Addresses attacking, spreading malware or spyware in about the last 30 days",
                Data,
            ),
            firehol(
                "firehol_level4",
                "FireHOL level 4",
                "Wider still: lists with more false positives",
                Off,
            ),
            firehol(
                "firehol_webserver",
                "FireHOL web server attackers",
                "Addresses that should never be a web server's visitors: malware hosts, bots, long criminal records",
                Off,
            ),
            firehol(
                "firehol_abusers_1d",
                "FireHOL abusers (1 day)",
                "Spammers and forum and comment abusers of the last day",
                Off,
            ),
            firehol(
                "firehol_abusers_30d",
                "FireHOL abusers (30 days)",
                "Spammers and forum and comment abusers of the last 30 days",
                Off,
            ),
        ]),
        S {
            id: "abuseipdb",
            name: "AbuseIPDB",
            description: "The addresses AbuseIPDB's users report most, with a confidence of about 100%, as collected by \
                          borestad/blocklist-abuseipdb. The shorter the period, the fewer reassigned addresses.",
            homepage: "https://github.com/borestad/blocklist-abuseipdb",
            category: Threats,
            pick: Pick::One,
            updates: Some("Several times a day"),
            refresh_secs: 3 * HOUR,
            note: Some("IPv4 only. Its maintainer suggests 30 days at most."),
        }
        .with(vec![
            abuseipdb(1, false),
            abuseipdb(3, false),
            abuseipdb(7, true),
            abuseipdb(14, false),
            abuseipdb(30, false),
            abuseipdb(60, false),
            abuseipdb(90, false),
        ]),
        S {
            id: "ipnoise",
            name: "IPnoise",
            description: "Addresses caught attacking honeypots: hosts that run no real service and are advertised \
                          nowhere, so whatever reaches them is hostile. Listed after repeated attacks; dropped once \
                          they stop for the period.",
            homepage: "https://ipnoise.sekuripy.hr/",
            category: Threats,
            pick: Pick::One,
            updates: None,
            refresh_secs: 2 * HOUR,
            note: None,
        }
        .with(vec![
            ipnoise(1, false),
            ipnoise(7, true),
            ipnoise(14, false),
            ipnoise(30, false),
        ]),
        S {
            id: "shadowwhisperer",
            name: "ShadowWhisperer",
            description: "Addresses seen by honeypots in several places, sorted by what they did.",
            homepage: "https://github.com/ShadowWhisperer/IPs",
            category: Threats,
            pick: Pick::Many,
            updates: Some("Hourly"),
            refresh_secs: HOUR,
            note: None,
        }
        .with(vec![
            shadow(
                "Threats",
                "ShadowWhisperer threats",
                "Exploit attempts, compromised systems, malware droppers",
                Block,
            ),
            shadow(
                "Scanners",
                "ShadowWhisperer scanners",
                "Internet scanning companies, mapping every host's services",
                Block,
            ),
            shadow(
                "Probes",
                "ShadowWhisperer probes",
                "Probed five times or more without completing a connection",
                Data,
            ),
            shadow(
                "Threats_Unclassified",
                "ShadowWhisperer unclassified",
                "Seen, not classified yet",
                Off,
            ),
            shadow(
                "Tunnels",
                "ShadowWhisperer tunnels",
                "Proxies and VPNs: shared by many people",
                Off,
            ),
        ]),
        S {
            id: "blocklist.de",
            name: "blocklist.de",
            description: "Addresses reported by servers running fail2ban and similar tools in the last 48 hours, by the \
                          service they attacked.",
            homepage: "https://www.blocklist.de/en/export.html",
            category: Threats,
            pick: Pick::Many,
            updates: None,
            refresh_secs: 6 * HOUR,
            note: None,
        }
        .with(vec![
            blocklist_de("all", "blocklist.de", "Every service's list together", Data),
            blocklist_de("ssh", "blocklist.de SSH", "SSH attacks", Off),
            blocklist_de("mail", "blocklist.de mail", "Attacks on mail servers (Postfix, SpamAssassin)", Off),
            blocklist_de("apache", "blocklist.de web", "Attacks on web servers (RFI, DDoS, bad bots)", Off),
            blocklist_de("imap", "blocklist.de IMAP", "Attacks on IMAP, SASL and POP3", Off),
            blocklist_de("bots", "blocklist.de forum bots", "Spam bots on forums, blogs and registration forms", Off),
            blocklist_de(
                "bruteforcelogin",
                "blocklist.de logins",
                "Brute-forced logins of web applications (WordPress, Joomla)",
                Off,
            ),
            blocklist_de(
                "strongips",
                "blocklist.de persistent",
                "Attacking for more than two months, over 5 000 attacks",
                Off,
            ),
        ]),
        S {
            id: "ai-crawlers",
            name: "AI crawlers",
            description: "The addresses AI companies publish for their crawlers, by company and purpose: training \
                          (collecting data for models), search (indexing for answers) and user fetches (a page a user \
                          asked about). Collected by tbeachill/ai-crawler-ip-ranges.",
            homepage: "https://github.com/tbeachill/ai-crawler-ip-ranges",
            category: Bots,
            pick: Pick::Many,
            updates: Some("Daily"),
            refresh_secs: DAY,
            note: Some(
                "Only crawlers whose companies publish their addresses. Others are known by their user agents: see \
                 AI user agents.",
            ),
        }
        .with(vec![
            ai("openai_train", "OpenAI training (GPTBot)", "Collects data for OpenAI's models", Block),
            ai("openai_search", "OpenAI search (OAI-SearchBot)", "Indexes pages for ChatGPT search", Data),
            ai("openai_user", "OpenAI user fetches (ChatGPT-User)", "Pages ChatGPT users ask about", Data),
            ai(
                "claude_crawl",
                "Anthropic (ClaudeBot)",
                "ClaudeBot, Claude-SearchBot and Claude-User: training, search and user fetches",
                Data,
            ),
            ai("amazon_train", "Amazon training (Amazonbot)", "Collects data for Amazon's models", Block),
            ai("amazon_search", "Amazon search (Amzn-SearchBot)", "Indexes pages for Amazon's search", Data),
            ai("amazon_user", "Amazon user fetches (Amzn-User)", "Pages Alexa users ask about", Data),
            ai("ccbot_train", "Common Crawl (CCBot)", "An open web archive many models are trained on", Block),
            ai(
                "meta_crawl",
                "Meta (meta-externalagent)",
                "Meta's crawlers: training, search and user fetches",
                Data,
            ),
            ai("perplexity_search", "Perplexity search (PerplexityBot)", "Indexes pages for Perplexity", Data),
            ai("perplexity_user", "Perplexity user fetches (Perplexity-User)", "Pages Perplexity users ask about", Data),
            ai("mistral_search", "Mistral search (MistralAI-Index)", "Indexes pages for Le Chat", Data),
            ai("mistral_user", "Mistral user fetches (MistralAI-User)", "Pages Le Chat users ask about", Data),
            ai("google_user", "Google agent (Google-Agent)", "Pages Google's AI agents fetch for users", Data),
            ai("ddgo_user", "DuckDuckGo assistant (DuckAssistBot)", "Pages DuckDuckGo's assistant answers from", Data),
        ]),
        S {
            id: "ai-agents",
            name: "AI user agents",
            description: "The user agents of AI crawlers, assistants and agents, published or not, as collected by \
                          ai.robots.txt. For rules (\"user agent in list\"): crawlers that publish no addresses are \
                          known by their user agent only.",
            homepage: "https://github.com/ai-robots-txt/ai.robots.txt",
            category: Bots,
            pick: Pick::Many,
            updates: Some("As crawlers are reported"),
            refresh_secs: DAY,
            note: Some("A user agent can be faked: a rule on it catches what admits being a crawler."),
        }
        .with(vec![Item {
            content: Content::Agents,
            ..item(
                "robots",
                "AI user agents",
                "AI user agents",
                "Every user agent of the list",
                "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.txt",
                Data,
            )
        }]),
        S {
            id: "ipverse-crawlers",
            name: "Search engines and SEO crawlers",
            description: "The addresses search engines and SEO tools publish for their crawlers, as collected by \
                          ipverse/bot-ip-blocks. Allowed, a crawler is never banned when it trips a rule (a crawler \
                          following old links collects 404s).",
            homepage: "https://github.com/ipverse/bot-ip-blocks",
            category: Bots,
            pick: Pick::Many,
            updates: Some("Daily"),
            refresh_secs: DAY,
            note: None,
        }
        .with(vec![
            crawler("Googlebot", "Googlebot", "Google's search crawler", Allow),
            crawler(
                "Google (special)",
                "Google special crawlers",
                "AdsBot, Mediapartners and other crawlers for one product",
                Allow,
            ),
            crawler(
                "Google (user-triggered)",
                "Google user fetches",
                "Site Verifier, Read Aloud and other fetches a user asked for",
                Data,
            ),
            crawler("Bingbot", "Bingbot", "Microsoft Bing's search crawler", Allow),
            crawler("Applebot", "Applebot", "Apple's crawler for Siri, Spotlight and Safari", Allow),
            crawler("DuckDuckBot", "DuckDuckBot", "DuckDuckGo's search crawler", Allow),
            crawler("Kagibot", "Kagibot", "Kagi's search crawler", Allow),
            crawler(
                "Yandex",
                "Yandex",
                "Yandex's crawlers; the list is Yandex's whole network, not only its crawlers",
                Data,
            ),
            crawler("Ahrefs", "AhrefsBot", "Ahrefs' SEO crawler", Data),
            crawler("SE Ranking", "SE Ranking", "SE Ranking's site audit crawler", Data),
            crawler(
                "SERankingBacklinksBot",
                "SE Ranking backlinks",
                "SE Ranking's backlink crawler",
                Data,
            ),
        ]),
        S {
            id: "ipverse-monitoring",
            name: "Uptime monitors",
            description: "The addresses of uptime and synthetic monitoring services' probes, as collected by \
                          ipverse/bot-ip-blocks. Allow the one watching your sites, so its checks are never banned.",
            homepage: "https://github.com/ipverse/bot-ip-blocks",
            category: Bots,
            pick: Pick::Many,
            updates: Some("Daily"),
            refresh_secs: DAY,
            note: None,
        }
        .with(vec![
            monitor("UptimeRobot", "UptimeRobot's probes"),
            monitor("Better Stack", "Better Stack's (Better Uptime's) probes"),
            monitor("Pingdom", "Pingdom's probes"),
            monitor("StatusCake", "StatusCake's probes"),
            monitor("Datadog", "Datadog Synthetics' probes"),
            monitor("New Relic", "New Relic Synthetics' probes"),
            monitor("Checkly", "Checkly's probes"),
            monitor("HetrixTools", "HetrixTools' probes"),
            monitor("Oh Dear", "Oh Dear's probes"),
            monitor("updown.io", "updown.io's probes"),
        ]),
        S {
            id: "cloudflare",
            name: "Cloudflare",
            description: "Cloudflare's ranges. A site behind Cloudflare's proxy is reached from them, not from its \
                          visitors' addresses; some of them are placed in Asia, Africa or South America by the \
                          geolocation databases, whichever data centre uses them.",
            homepage: "https://www.cloudflare.com/ips/",
            category: Networks,
            pick: Pick::Many,
            updates: None,
            refresh_secs: DAY,
            note: None,
        }
        .with(vec![
            item("ips-v4", "Cloudflare", "IPv4", "IPv4 ranges", "https://www.cloudflare.com/ips-v4", Allow),
            item(
                "ips-v6",
                "Cloudflare (IPv6)",
                "IPv6",
                "IPv6 ranges",
                "https://www.cloudflare.com/ips-v6",
                Allow,
            ),
        ]),
        S {
            id: "tor",
            name: "Tor",
            description: "The Tor network's exit relays: shared by everyone using Tor, attackers among them.",
            homepage: "https://check.torproject.org/",
            category: Networks,
            pick: Pick::Many,
            updates: None,
            refresh_secs: HOUR,
            note: Some("Give them a short ban (Policy, by blocklist) rather than blocking them."),
        }
        .with(vec![item(
            "exits",
            "Tor exit nodes",
            "Exit relays",
            "Addresses Tor traffic leaves the network from",
            "https://check.torproject.org/torbulkexitlist",
            Data,
        )]),
        S {
            id: "hosting",
            name: "Hosting and cloud networks",
            description: "Networks of hosting, cloud and colocation providers (brianhama/bad-asn-list): where most bots, \
                          scanners and VPNs run from, and few visitors. Their prefixes come from the ASN database.",
            homepage: "https://github.com/brianhama/bad-asn-list",
            category: Networks,
            pick: Pick::Many,
            updates: Some("By hand, now and then"),
            refresh_secs: 7 * DAY,
            note: Some(
                "Hundreds of networks, among them the big clouds: for rules and ban lengths rather than a block. Needs \
                 the ASN database.",
            ),
        }
        .with(vec![Item {
            content: Content::Networks,
            ..item(
                "bad-asn-list",
                "Hosting networks",
                "Hosting networks",
                "Every network of the list",
                "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv",
                Data,
            )
        }]),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn catalog_is_consistent() {
        let sources = catalog();
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for s in &sources {
            assert!(ids.insert(&s.id), "source {} twice", s.id);
            assert!(s.refresh_secs >= crate::run::FEED_MIN_REFRESH);
            assert!(!s.items.is_empty());
            let mut keys = HashSet::new();
            for i in &s.items {
                assert!(keys.insert(&i.key), "{}: item {} twice", s.id, i.key);
                assert!(i.url.starts_with("https://"), "{}", i.url);
                if i.content == Content::Agents {
                    assert!(matches!(i.suggested, Use::Data | Use::Off));
                }
            }
            match s.pick {
                // Periods of one list share its feed.
                Pick::One => {
                    assert!(s.items.iter().all(|i| i.name == s.items[0].name));
                    assert_eq!(
                        s.items.iter().filter(|i| i.suggested != Use::Off).count(),
                        1
                    );
                    assert!(names.insert(s.items[0].name.clone()));
                }
                Pick::Many => {
                    for i in &s.items {
                        assert!(names.insert(i.name.clone()), "feed name {} twice", i.name);
                    }
                }
            }
        }
    }

    #[test]
    fn ipverse_services_are_json_pointers() {
        let s = catalog();
        let item = s
            .iter()
            .flat_map(|s| &s.items)
            .find(|i| i.key == "Google (special)")
            .unwrap();
        assert_eq!(item.select.as_deref(), Some("/services/Google (special)"));
    }
}
