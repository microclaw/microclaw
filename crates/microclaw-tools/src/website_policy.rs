//! robots.txt-aware policy gate for `web_fetch`.
//!
//! Before each outbound fetch, consult the host's /robots.txt and honor
//! Disallow entries for a sensible User-agent. Results cached per host.
//!
//! Port of hermes-agent's `tools/website_policy.py`, simplified:
//! - User-agent matching: we treat "MicroClaw" and "*" as equivalent
//! - Disallow + Allow rules; longest-prefix wins for conflicts
//! - Crawl-Delay read and surfaced via `CrawlHint::delay`
//! - Pages that 404 / 5xx / fail network → policy = allow (fail-open)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::Url;

const CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_ROBOTS_BYTES: usize = 500_000;

#[derive(Debug, Clone, Default)]
struct RobotsRules {
    disallow: Vec<String>,
    allow: Vec<String>,
    crawl_delay: Option<f64>,
}

#[derive(Debug, Clone)]
struct CachedRobots {
    fetched_at: Instant,
    rules: RobotsRules,
}

#[derive(Debug, Clone)]
pub struct CrawlHint {
    pub allowed: bool,
    pub reason: Option<String>,
    pub crawl_delay_secs: Option<f64>,
}

fn cache() -> &'static Mutex<HashMap<String, CachedRobots>> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, CachedRobots>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key(scheme: &str, host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

fn parse_robots_txt(text: &str, our_agent: &str) -> RobotsRules {
    // Parse in simple linear mode: track "current User-agent" while reading;
    // collect the union of rules for groups matching our_agent or '*'.
    let mut our_rules = RobotsRules::default();
    let mut star_rules = RobotsRules::default();
    let mut current: Option<Vec<String>> = None; // ua set of current group
    let our_agent_lower = our_agent.to_ascii_lowercase();

    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        match key.as_str() {
            "user-agent" => {
                if current.as_ref().is_some_and(|_| true) {
                    // Previous group ended; decide next
                }
                current = Some(vec![value.to_ascii_lowercase()]);
            }
            "disallow" | "allow" | "crawl-delay" => {
                let Some(uas) = current.as_ref() else {
                    continue;
                };
                let matches_ours = uas.iter().any(|u| u == &our_agent_lower);
                let matches_star = uas.iter().any(|u| u == "*");
                let targets: Vec<&mut RobotsRules> = if matches_ours {
                    vec![&mut our_rules]
                } else if matches_star {
                    vec![&mut star_rules]
                } else {
                    continue;
                };
                for rules in targets {
                    match key.as_str() {
                        "disallow" => {
                            if !value.is_empty() {
                                rules.disallow.push(value.clone());
                            }
                        }
                        "allow" => {
                            if !value.is_empty() {
                                rules.allow.push(value.clone());
                            }
                        }
                        "crawl-delay" => {
                            if let Ok(n) = value.parse::<f64>() {
                                rules.crawl_delay = Some(n);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Our-agent rules take precedence; fall back to '*'.
    if our_rules.disallow.is_empty() && our_rules.allow.is_empty() && our_rules.crawl_delay.is_none()
    {
        our_rules = star_rules;
    }
    our_rules
}

/// Return `CrawlHint::allowed = false` if the path is Disallow'd by the
/// cached rules; otherwise allowed. Longest-prefix match wins between
/// Allow and Disallow.
fn evaluate_path(rules: &RobotsRules, path: &str) -> CrawlHint {
    let mut best_allow = 0usize;
    let mut best_disallow = 0usize;
    for rule in &rules.allow {
        if path.starts_with(rule) && rule.len() > best_allow {
            best_allow = rule.len();
        }
    }
    for rule in &rules.disallow {
        if path.starts_with(rule) && rule.len() > best_disallow {
            best_disallow = rule.len();
        }
    }
    if best_disallow > best_allow {
        CrawlHint {
            allowed: false,
            reason: Some(format!("disallowed by robots.txt (rule len {best_disallow})")),
            crawl_delay_secs: rules.crawl_delay,
        }
    } else {
        CrawlHint {
            allowed: true,
            reason: None,
            crawl_delay_secs: rules.crawl_delay,
        }
    }
}

/// Fetch (or reuse) robots.txt for the host of `url` and return a hint
/// about whether the agent should proceed. Fail-open: network / 4xx /
/// 5xx → allowed.
pub async fn consult_robots(
    client: &reqwest::Client,
    url: &Url,
    user_agent: &str,
) -> CrawlHint {
    let Some(host) = url.host_str() else {
        return CrawlHint {
            allowed: true,
            reason: None,
            crawl_delay_secs: None,
        };
    };
    let scheme = url.scheme();
    let port = url.port();
    let key = cache_key(scheme, host, port);
    let now = Instant::now();
    if let Ok(guard) = cache().lock() {
        if let Some(entry) = guard.get(&key) {
            if now.duration_since(entry.fetched_at) < CACHE_TTL {
                return evaluate_path(&entry.rules, url.path());
            }
        }
    }

    let robots_url = {
        let mut u = url.clone();
        u.set_path("/robots.txt");
        u.set_query(None);
        u.set_fragment(None);
        u
    };
    let body = match client.get(robots_url).send().await {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => String::new(),
    };
    let truncated = if body.len() > MAX_ROBOTS_BYTES {
        body[..MAX_ROBOTS_BYTES].to_string()
    } else {
        body
    };
    let rules = parse_robots_txt(&truncated, user_agent);
    if let Ok(mut guard) = cache().lock() {
        guard.insert(
            key,
            CachedRobots {
                fetched_at: now,
                rules: rules.clone(),
            },
        );
    }
    evaluate_path(&rules, url.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_robots_allows_all() {
        let rules = parse_robots_txt("", "microclaw");
        let hint = evaluate_path(&rules, "/anything");
        assert!(hint.allowed);
    }

    #[test]
    fn disallow_blocks_matching_prefix() {
        let txt = "User-agent: *\nDisallow: /private/\n";
        let rules = parse_robots_txt(txt, "microclaw");
        assert!(!evaluate_path(&rules, "/private/doc").allowed);
        assert!(evaluate_path(&rules, "/public/doc").allowed);
    }

    #[test]
    fn allow_overrides_disallow_when_longer() {
        let txt = "User-agent: *\nDisallow: /private/\nAllow: /private/public/\n";
        let rules = parse_robots_txt(txt, "microclaw");
        assert!(!evaluate_path(&rules, "/private/doc").allowed);
        assert!(evaluate_path(&rules, "/private/public/doc").allowed);
    }

    #[test]
    fn ua_specific_rules_override_star() {
        let txt = "User-agent: *\nDisallow: /\n\nUser-agent: microclaw\nDisallow: /secret/\n";
        let rules = parse_robots_txt(txt, "microclaw");
        // microclaw-specific rules replace '*' fallback, so only /secret/ blocked.
        assert!(!evaluate_path(&rules, "/secret/x").allowed);
        assert!(evaluate_path(&rules, "/open").allowed);
    }

    #[test]
    fn crawl_delay_parsed() {
        let txt = "User-agent: *\nCrawl-Delay: 5\n";
        let rules = parse_robots_txt(txt, "microclaw");
        assert_eq!(rules.crawl_delay, Some(5.0));
    }

    #[test]
    fn comments_stripped() {
        let txt = "User-agent: * # applies to all\nDisallow: /admin # internal\n";
        let rules = parse_robots_txt(txt, "microclaw");
        assert!(!evaluate_path(&rules, "/admin/panel").allowed);
    }
}
