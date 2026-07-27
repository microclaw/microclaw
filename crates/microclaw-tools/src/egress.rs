//! Native outbound-network policy for agent-controlled requests.
//!
//! The policy is evaluated at the shared tool registry before built-in, MCP,
//! or dynamic plugin tools execute. Configured runtime endpoints are validated
//! separately during application config loading. Redirect-capable HTTP clients
//! should continue to use `url_safety::ssrf_redirect_policy` so every hop is
//! checked as well.

use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressPolicyMode {
    #[default]
    Off,
    Warn,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressPolicyConfig {
    #[serde(default)]
    pub mode: EgressPolicyMode,
    /// When non-empty, every HTTP(S) destination must match one entry.
    /// Entries may be exact hosts or `*.example.com` suffix patterns.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    /// Reject loopback, private, link-local, CGNAT, metadata, multicast, and
    /// unresolved destinations. Enabled by default whenever policy is active.
    #[serde(default = "default_block_private_ips")]
    pub block_private_ips: bool,
}

fn default_block_private_ips() -> bool {
    true
}

impl Default for EgressPolicyConfig {
    fn default() -> Self {
        Self {
            mode: EgressPolicyMode::Off,
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
            block_private_ips: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Warn(String),
    Block(String),
}

impl EgressDecision {
    fn violation(config: &EgressPolicyConfig, reason: String) -> Self {
        match config.mode {
            EgressPolicyMode::Off => Self::Allow,
            EgressPolicyMode::Warn => Self::Warn(reason),
            EgressPolicyMode::Block => Self::Block(reason),
        }
    }
}

pub fn evaluate_url(config: &EgressPolicyConfig, raw_url: &str) -> EgressDecision {
    if config.mode == EgressPolicyMode::Off {
        return EgressDecision::Allow;
    }
    let parsed = match Url::parse(raw_url) {
        Ok(url) => url,
        Err(error) => {
            return EgressDecision::violation(
                config,
                format!("invalid outbound URL `{raw_url}`: {error}"),
            )
        }
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return EgressDecision::violation(
            config,
            format!("outbound URL scheme `{}` is not permitted", parsed.scheme()),
        );
    }
    let Some(host) = parsed.host_str().map(|value| value.to_ascii_lowercase()) else {
        return EgressDecision::violation(config, "outbound URL has no host".into());
    };
    if config
        .deny_hosts
        .iter()
        .any(|pattern| host_matches(pattern, &host))
    {
        return EgressDecision::violation(
            config,
            format!("outbound host `{host}` matches egress_policy.deny_hosts"),
        );
    }
    if !config.allow_hosts.is_empty()
        && !config
            .allow_hosts
            .iter()
            .any(|pattern| host_matches(pattern, &host))
    {
        return EgressDecision::violation(
            config,
            format!("outbound host `{host}` is not in egress_policy.allow_hosts"),
        );
    }
    if config.block_private_ips {
        if let Err(error) = crate::url_safety::check_url_private_ip(&parsed) {
            return EgressDecision::violation(config, format!("egress SSRF guard: {error}"));
        }
    }
    EgressDecision::Allow
}

pub fn evaluate_tool_input(
    config: &EgressPolicyConfig,
    input: &serde_json::Value,
) -> Vec<(String, EgressDecision)> {
    if config.mode == EgressPolicyMode::Off {
        return Vec::new();
    }
    let mut urls = Vec::new();
    collect_urls(input, &mut urls);
    urls.sort();
    urls.dedup();
    urls.into_iter()
        .map(|url| {
            let decision = evaluate_url(config, &url);
            (url, decision)
        })
        .filter(|(_, decision)| !matches!(decision, EgressDecision::Allow))
        .collect()
}

fn collect_urls(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            // Capture URLs embedded in shell commands as well as exact URL
            // arguments. Stop at common shell/JSON/Markdown delimiters.
            for prefix in ["https://", "http://"] {
                let mut rest = text.as_str();
                while let Some(index) = rest.find(prefix) {
                    let candidate = &rest[index..];
                    let end = candidate
                        .find(|ch: char| {
                            ch.is_whitespace()
                                || matches!(
                                    ch,
                                    '"' | '\'' | ')' | ']' | '}' | '<' | '>' | '`' | ';' | ','
                                )
                        })
                        .unwrap_or(candidate.len());
                    let url = candidate[..end]
                        .trim_end_matches(['.', ':', '!', '?'])
                        .to_string();
                    if !url.is_empty() {
                        out.push(url);
                    }
                    rest = &candidate[end..];
                    if rest.is_empty() {
                        break;
                    }
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_urls(value, out);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if key != "__microclaw_auth" {
                    collect_urls(value, out);
                }
            }
        }
        _ => {}
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host != suffix && host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocking() -> EgressPolicyConfig {
        EgressPolicyConfig {
            mode: EgressPolicyMode::Block,
            ..Default::default()
        }
    }

    #[test]
    fn blocks_private_and_metadata_destinations() {
        assert!(matches!(
            evaluate_url(&blocking(), "http://127.0.0.1/admin"),
            EgressDecision::Block(_)
        ));
        assert!(matches!(
            evaluate_url(&blocking(), "http://169.254.169.254/latest/meta-data"),
            EgressDecision::Block(_)
        ));
    }

    #[test]
    fn allowlist_supports_subdomain_patterns() {
        let config = EgressPolicyConfig {
            mode: EgressPolicyMode::Block,
            allow_hosts: vec!["api.example.com".into(), "*.trusted.test".into()],
            block_private_ips: false,
            ..Default::default()
        };
        assert_eq!(
            evaluate_url(&config, "https://api.example.com/v1"),
            EgressDecision::Allow
        );
        assert_eq!(
            evaluate_url(&config, "https://a.trusted.test/v1"),
            EgressDecision::Allow
        );
        assert!(matches!(
            evaluate_url(&config, "https://example.net/v1"),
            EgressDecision::Block(_)
        ));
    }

    #[test]
    fn finds_urls_embedded_in_tool_input() {
        let input = serde_json::json!({
            "command": "curl https://allowed.example/a && curl http://127.0.0.1/x"
        });
        let config = EgressPolicyConfig {
            mode: EgressPolicyMode::Block,
            deny_hosts: vec!["127.0.0.1".into()],
            block_private_ips: false,
            ..Default::default()
        };
        let violations = evaluate_tool_input(&config, &input);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "http://127.0.0.1/x");
    }
}
