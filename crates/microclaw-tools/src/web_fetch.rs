use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use microclaw_core::text::floor_char_boundary;
use reqwest::Url;
use tracing::warn;

use crate::web_content_validation::{validate_web_content_with_config, WebContentValidationConfig};
use crate::web_html::{extract_primary_html, html_to_text};

fn http_client(timeout_secs: u64) -> reqwest::Client {
    static CLIENTS: OnceLock<Mutex<HashMap<u64, reqwest::Client>>> = OnceLock::new();
    let cache = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(client) = cache.get(&timeout_secs) {
        return client.clone();
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("MicroClaw/1.0")
        .build()
        .expect("failed to build HTTP client");
    cache.insert(timeout_secs, client.clone());
    client
}

fn http_client_no_redirect(timeout_secs: u64) -> reqwest::Client {
    static CLIENTS: OnceLock<Mutex<HashMap<u64, reqwest::Client>>> = OnceLock::new();
    let cache = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(client) = cache.get(&timeout_secs) {
        return client.clone();
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("MicroClaw/1.0")
        .build()
        .expect("failed to build HTTP client");
    cache.insert(timeout_secs, client.clone());
    client
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebFetchFeedMode {
    Allowlist,
    Denylist,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebFetchFeedFormat {
    Lines,
    CsvFirstColumn,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebFetchFeedSource {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_feed_mode")]
    pub mode: WebFetchFeedMode,
    pub url: String,
    #[serde(default = "default_feed_format")]
    pub format: WebFetchFeedFormat,
    #[serde(default = "default_feed_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_feed_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebFetchFeedSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_feed_fail_open")]
    pub fail_open: bool,
    #[serde(default = "default_feed_max_entries_per_source")]
    pub max_entries_per_source: usize,
    #[serde(default)]
    pub sources: Vec<WebFetchFeedSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebFetchUrlValidationConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_allowed_schemes")]
    pub allowed_schemes: Vec<String>,
    #[serde(default)]
    pub allowlist_hosts: Vec<String>,
    #[serde(default)]
    pub denylist_hosts: Vec<String>,
    #[serde(default)]
    pub feed_sync: WebFetchFeedSyncConfig,
}

struct FeedCacheEntry {
    fetched_at: Instant,
    entries: Vec<String>,
}

const fn default_enabled() -> bool {
    true
}

const fn default_feed_mode() -> WebFetchFeedMode {
    WebFetchFeedMode::Denylist
}

const fn default_feed_format() -> WebFetchFeedFormat {
    WebFetchFeedFormat::Lines
}

const fn default_feed_refresh_interval_secs() -> u64 {
    3600
}

const fn default_feed_timeout_secs() -> u64 {
    10
}

const fn default_feed_fail_open() -> bool {
    true
}

const fn default_feed_max_entries_per_source() -> usize {
    10_000
}

fn default_allowed_schemes() -> Vec<String> {
    vec!["https".to_string(), "http".to_string()]
}

impl Default for WebFetchFeedSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fail_open: default_feed_fail_open(),
            max_entries_per_source: default_feed_max_entries_per_source(),
            sources: Vec::new(),
        }
    }
}

impl WebFetchFeedSyncConfig {
    pub fn normalize(&mut self) {
        if self.max_entries_per_source == 0 {
            self.max_entries_per_source = default_feed_max_entries_per_source();
        }

        for source in &mut self.sources {
            source.url = source.url.trim().to_string();
            if source.refresh_interval_secs == 0 {
                source.refresh_interval_secs = default_feed_refresh_interval_secs();
            }
            if source.timeout_secs == 0 {
                source.timeout_secs = default_feed_timeout_secs();
            }
        }

        self.sources.retain(|s| !s.url.is_empty());
    }
}

impl Default for WebFetchUrlValidationConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            allowed_schemes: default_allowed_schemes(),
            allowlist_hosts: Vec::new(),
            denylist_hosts: Vec::new(),
            feed_sync: WebFetchFeedSyncConfig::default(),
        }
    }
}

impl WebFetchUrlValidationConfig {
    pub fn normalize(&mut self) {
        self.allowed_schemes = self
            .allowed_schemes
            .drain(..)
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        if self.allowed_schemes.is_empty() {
            self.allowed_schemes = default_allowed_schemes();
        }

        normalize_host_list(&mut self.allowlist_hosts);
        normalize_host_list(&mut self.denylist_hosts);
        self.feed_sync.normalize();
    }
}

fn normalize_host_list(hosts: &mut Vec<String>) {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for host in hosts.drain(..) {
        let Some(host) = normalize_host_candidate(&host) else {
            continue;
        };
        if seen.insert(host.clone()) {
            normalized.push(host);
        }
    }

    *hosts = normalized;
}

fn normalize_host_candidate(input: &str) -> Option<String> {
    let mut token = input.trim().to_string();
    if token.is_empty() {
        return None;
    }

    // Support feeds that include full URLs.
    if let Ok(parsed) = Url::parse(&token) {
        token = parsed.host_str()?.to_string();
    }

    // Support CSV and path-like entries.
    if let Some((head, _)) = token.split_once('/') {
        token = head.to_string();
    }

    token = token
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_string();

    // Drop :port for domain and IPv4 host entries.
    if token.matches(':').count() == 1 {
        if let Some((head, _)) = token.split_once(':') {
            token = head.to_string();
        }
    }

    token = token.trim_end_matches('.').to_ascii_lowercase();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn host_matches_rule(host: &str, rule: &str) -> bool {
    host == rule || host.ends_with(&format!(".{rule}"))
}

fn resolve_and_validate_redirect_target(
    current_url: &Url,
    location: &str,
    url_validation: &WebFetchUrlValidationConfig,
) -> Result<Url, String> {
    let next = current_url
        .join(location)
        .map_err(|e| format!("invalid redirect target '{location}': {e}"))?;
    validate_web_fetch_url(next.as_str(), url_validation.clone())?;
    Ok(next)
}

fn feed_cache() -> &'static Mutex<HashMap<String, FeedCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, FeedCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn parse_feed_entries(raw: &str, format: &WebFetchFeedFormat, max_entries: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let candidate = match format {
            WebFetchFeedFormat::Lines => line,
            WebFetchFeedFormat::CsvFirstColumn => line.split(',').next().unwrap_or(""),
        };

        let Some(host) = normalize_host_candidate(candidate) else {
            continue;
        };

        if seen.insert(host.clone()) {
            out.push(host);
            if out.len() >= max_entries {
                break;
            }
        }
    }

    out
}

async fn fetch_feed_entries(
    source: &WebFetchFeedSource,
    fail_open: bool,
    max_entries_per_source: usize,
) -> Result<Vec<String>, String> {
    if let Some(inline) = source.url.strip_prefix("inline:") {
        return Ok(parse_feed_entries(
            inline,
            &source.format,
            max_entries_per_source,
        ));
    }

    let cache_key = format!("{}::{:?}", source.url, source.format);
    let ttl = Duration::from_secs(source.refresh_interval_secs.max(1));

    let stale_entries = {
        let cache = feed_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get(&cache_key) {
            if entry.fetched_at.elapsed() < ttl {
                return Ok(entry.entries.clone());
            }
            Some(entry.entries.clone())
        } else {
            None
        }
    };

    let request_result = async {
        let client = http_client(source.timeout_secs.max(1));
        let resp = client
            .get(&source.url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("feed returned HTTP {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| e.to_string())?;
        Ok(parse_feed_entries(
            &body,
            &source.format,
            max_entries_per_source,
        ))
    }
    .await;

    match request_result {
        Ok(entries) => {
            let mut cache = feed_cache().lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(
                cache_key,
                FeedCacheEntry {
                    fetched_at: Instant::now(),
                    entries: entries.clone(),
                },
            );
            Ok(entries)
        }
        Err(err) => {
            if let Some(stale) = stale_entries {
                warn!(
                    url = source.url,
                    error = err,
                    "Using stale feed cache after refresh error"
                );
                return Ok(stale);
            }
            if fail_open {
                warn!(
                    url = source.url,
                    error = err,
                    "Skipping feed due to fail_open=true"
                );
                Ok(Vec::new())
            } else {
                Err(format!("feed fetch failed for '{}': {err}", source.url))
            }
        }
    }
}

pub async fn resolve_url_validation_config(
    mut config: WebFetchUrlValidationConfig,
) -> Result<WebFetchUrlValidationConfig, String> {
    config.normalize();
    if !config.enabled || !config.feed_sync.enabled || config.feed_sync.sources.is_empty() {
        return Ok(config);
    }

    let fail_open = config.feed_sync.fail_open;
    let max_entries_per_source = config.feed_sync.max_entries_per_source;
    for source in config.feed_sync.sources.iter().filter(|s| s.enabled) {
        let entries = fetch_feed_entries(source, fail_open, max_entries_per_source).await?;
        match source.mode {
            WebFetchFeedMode::Allowlist => config.allowlist_hosts.extend(entries),
            WebFetchFeedMode::Denylist => config.denylist_hosts.extend(entries),
        }
    }

    normalize_host_list(&mut config.allowlist_hosts);
    normalize_host_list(&mut config.denylist_hosts);
    Ok(config)
}

pub fn validate_web_fetch_url(
    raw_url: &str,
    mut config: WebFetchUrlValidationConfig,
) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }
    config.normalize();

    let parsed = Url::parse(raw_url).map_err(|e| format!("invalid URL: {e}"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !config.allowed_schemes.iter().any(|s| s == &scheme) {
        return Err(format!(
            "URL scheme '{}' is not allowed (allowed: {})",
            scheme,
            config.allowed_schemes.join(", ")
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?
        .to_ascii_lowercase();

    if config
        .denylist_hosts
        .iter()
        .any(|rule| host_matches_rule(&host, rule))
    {
        return Err(format!("URL host '{}' is denylisted", host));
    }

    if !config.allowlist_hosts.is_empty()
        && !config
            .allowlist_hosts
            .iter()
            .any(|rule| host_matches_rule(&host, rule))
    {
        return Err(format!("URL host '{}' is not in allowlist", host));
    }

    Ok(())
}

pub async fn fetch_url_with_timeout(url: &str, timeout_secs: u64) -> Result<String, String> {
    fetch_url_with_timeout_and_validation(
        url,
        timeout_secs,
        WebContentValidationConfig::default(),
        WebFetchUrlValidationConfig::default(),
    )
    .await
}

pub async fn fetch_url_with_timeout_and_validation(
    url: &str,
    timeout_secs: u64,
    validation: WebContentValidationConfig,
    url_validation: WebFetchUrlValidationConfig,
) -> Result<String, String> {
    let effective_url_validation = resolve_url_validation_config(url_validation).await?;
    validate_web_fetch_url(url, effective_url_validation.clone())?;

    let client = http_client_no_redirect(timeout_secs.max(1));
    let mut current_url = Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let mut redirects = 0usize;

    let resp = loop {
        let resp = client
            .get(current_url.clone())
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_redirection() {
            break resp;
        }

        if redirects >= 5 {
            return Err("too many redirects (max 5)".to_string());
        }
        redirects += 1;

        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| "redirect response missing Location header".to_string())?
            .to_str()
            .map_err(|e| format!("invalid redirect Location header: {e}"))?;
        current_url = resolve_and_validate_redirect_target(
            &current_url,
            location,
            &effective_url_validation,
        )?;
    };

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let primary = extract_primary_html(&body);
    let text = html_to_text(primary);

    if let Err(failure) = validate_web_content_with_config(&text, validation) {
        warn!(
            matched_rules = failure.rule_names.join(","),
            "Blocked web_fetch content by validation"
        );
        return Err(failure.message());
    }

    const MAX_BYTES: usize = 20_000;
    if text.len() > MAX_BYTES {
        let truncated = &text[..floor_char_boundary(&text, MAX_BYTES)];
        Ok(format!("{truncated}\n\n[Truncated at 20KB]"))
    } else {
        Ok(text)
    }
}

pub async fn fetch_url(url: &str) -> Result<String, String> {
    fetch_url_with_timeout(url, 15).await
}

#[cfg(test)]
mod tests {
    use reqwest::Url;

    use super::{
        resolve_and_validate_redirect_target, resolve_url_validation_config,
        validate_web_fetch_url, WebFetchFeedFormat, WebFetchFeedMode, WebFetchFeedSource,
        WebFetchFeedSyncConfig, WebFetchUrlValidationConfig,
    };

    #[test]
    fn url_validation_allows_default_http_https() {
        assert!(validate_web_fetch_url(
            "https://example.com",
            WebFetchUrlValidationConfig::default()
        )
        .is_ok());
        assert!(validate_web_fetch_url(
            "http://example.com/docs",
            WebFetchUrlValidationConfig::default()
        )
        .is_ok());
    }

    #[test]
    fn url_validation_blocks_scheme() {
        let err =
            validate_web_fetch_url("ftp://example.com", WebFetchUrlValidationConfig::default())
                .unwrap_err();
        assert!(err.contains("not allowed"));
    }

    #[test]
    fn url_validation_blocks_denylist() {
        let cfg = WebFetchUrlValidationConfig {
            denylist_hosts: vec!["example.com".into()],
            ..WebFetchUrlValidationConfig::default()
        };
        let err = validate_web_fetch_url("https://sub.example.com", cfg).unwrap_err();
        assert!(err.contains("denylisted"));
    }

    #[test]
    fn url_validation_enforces_allowlist() {
        let cfg = WebFetchUrlValidationConfig {
            allowlist_hosts: vec!["allowed.com".into()],
            ..WebFetchUrlValidationConfig::default()
        };
        assert!(validate_web_fetch_url("https://api.allowed.com/v1", cfg.clone()).is_ok());
        let err = validate_web_fetch_url("https://other.com", cfg).unwrap_err();
        assert!(err.contains("allowlist"));
    }

    #[test]
    fn url_validation_denylist_precedes_allowlist() {
        let cfg = WebFetchUrlValidationConfig {
            allowlist_hosts: vec!["example.com".into()],
            denylist_hosts: vec!["example.com".into()],
            ..WebFetchUrlValidationConfig::default()
        };
        let err = validate_web_fetch_url("https://api.example.com", cfg).unwrap_err();
        assert!(err.contains("denylisted"));
    }

    #[test]
    fn url_validation_can_be_disabled() {
        let cfg = WebFetchUrlValidationConfig {
            enabled: false,
            allowed_schemes: vec!["https".into()],
            allowlist_hosts: vec!["allowed.com".into()],
            denylist_hosts: vec!["allowed.com".into()],
            feed_sync: WebFetchFeedSyncConfig::default(),
        };
        assert!(validate_web_fetch_url("ftp://bad", cfg).is_ok());
    }

    #[tokio::test]
    async fn feed_sync_merges_denylist_entries() {
        let cfg = WebFetchUrlValidationConfig {
            feed_sync: WebFetchFeedSyncConfig {
                enabled: true,
                fail_open: false,
                max_entries_per_source: 100,
                sources: vec![WebFetchFeedSource {
                    enabled: true,
                    mode: WebFetchFeedMode::Denylist,
                    url: "inline:#comment\nblocked.example\n".to_string(),
                    format: WebFetchFeedFormat::Lines,
                    refresh_interval_secs: 3600,
                    timeout_secs: 5,
                }],
            },
            ..WebFetchUrlValidationConfig::default()
        };

        let resolved = resolve_url_validation_config(cfg).await.unwrap();
        assert!(resolved
            .denylist_hosts
            .iter()
            .any(|h| h == "blocked.example"));
    }

    #[tokio::test]
    async fn feed_sync_supports_csv_first_column() {
        let cfg = WebFetchUrlValidationConfig {
            feed_sync: WebFetchFeedSyncConfig {
                enabled: true,
                fail_open: false,
                max_entries_per_source: 100,
                sources: vec![WebFetchFeedSource {
                    enabled: true,
                    mode: WebFetchFeedMode::Denylist,
                    url: "inline:host,score\nfoo.example,99\nbar.example,88\n".to_string(),
                    format: WebFetchFeedFormat::CsvFirstColumn,
                    refresh_interval_secs: 3600,
                    timeout_secs: 5,
                }],
            },
            ..WebFetchUrlValidationConfig::default()
        };

        let resolved = resolve_url_validation_config(cfg).await.unwrap();
        assert!(resolved.denylist_hosts.iter().any(|h| h == "foo.example"));
        assert!(resolved.denylist_hosts.iter().any(|h| h == "bar.example"));
    }

    #[tokio::test]
    async fn feed_sync_merges_allowlist_and_denylist_sources() {
        let cfg = WebFetchUrlValidationConfig {
            feed_sync: WebFetchFeedSyncConfig {
                enabled: true,
                fail_open: false,
                max_entries_per_source: 100,
                sources: vec![
                    WebFetchFeedSource {
                        enabled: true,
                        mode: WebFetchFeedMode::Allowlist,
                        url: "inline:https://allowed.example/path\n".to_string(),
                        format: WebFetchFeedFormat::Lines,
                        refresh_interval_secs: 3600,
                        timeout_secs: 5,
                    },
                    WebFetchFeedSource {
                        enabled: true,
                        mode: WebFetchFeedMode::Denylist,
                        url: "inline:blocked.example\n".to_string(),
                        format: WebFetchFeedFormat::Lines,
                        refresh_interval_secs: 3600,
                        timeout_secs: 5,
                    },
                ],
            },
            ..WebFetchUrlValidationConfig::default()
        };

        let resolved = resolve_url_validation_config(cfg).await.unwrap();
        assert!(resolved
            .allowlist_hosts
            .iter()
            .any(|h| h == "allowed.example"));
        assert!(resolved
            .denylist_hosts
            .iter()
            .any(|h| h == "blocked.example"));
    }

    #[tokio::test]
    async fn feed_sync_skips_disabled_sources() {
        let cfg = WebFetchUrlValidationConfig {
            feed_sync: WebFetchFeedSyncConfig {
                enabled: true,
                fail_open: false,
                max_entries_per_source: 100,
                sources: vec![WebFetchFeedSource {
                    enabled: false,
                    mode: WebFetchFeedMode::Denylist,
                    url: "inline:blocked.example\n".to_string(),
                    format: WebFetchFeedFormat::Lines,
                    refresh_interval_secs: 3600,
                    timeout_secs: 5,
                }],
            },
            ..WebFetchUrlValidationConfig::default()
        };

        let resolved = resolve_url_validation_config(cfg).await.unwrap();
        assert!(resolved.denylist_hosts.is_empty());
    }

    #[tokio::test]
    async fn feed_sync_fail_closed_returns_error() {
        let cfg = WebFetchUrlValidationConfig {
            feed_sync: WebFetchFeedSyncConfig {
                enabled: true,
                fail_open: false,
                max_entries_per_source: 100,
                sources: vec![WebFetchFeedSource {
                    enabled: true,
                    mode: WebFetchFeedMode::Denylist,
                    url: "http://127.0.0.1:9/unreachable".to_string(),
                    format: WebFetchFeedFormat::Lines,
                    refresh_interval_secs: 3600,
                    timeout_secs: 1,
                }],
            },
            ..WebFetchUrlValidationConfig::default()
        };

        let err = resolve_url_validation_config(cfg).await.unwrap_err();
        assert!(err.contains("feed fetch failed"));
    }

    #[tokio::test]
    async fn feed_sync_fail_open_skips_error() {
        let cfg = WebFetchUrlValidationConfig {
            feed_sync: WebFetchFeedSyncConfig {
                enabled: true,
                fail_open: true,
                max_entries_per_source: 100,
                sources: vec![WebFetchFeedSource {
                    enabled: true,
                    mode: WebFetchFeedMode::Denylist,
                    url: "http://127.0.0.1:9/unreachable".to_string(),
                    format: WebFetchFeedFormat::Lines,
                    refresh_interval_secs: 3600,
                    timeout_secs: 1,
                }],
            },
            ..WebFetchUrlValidationConfig::default()
        };

        let resolved = resolve_url_validation_config(cfg).await.unwrap();
        assert!(resolved.denylist_hosts.is_empty());
    }

    #[test]
    fn redirect_validation_blocks_denylisted_target() {
        let current = Url::parse("https://safe.example/start").unwrap();
        let cfg = WebFetchUrlValidationConfig {
            denylist_hosts: vec!["blocked.example".to_string()],
            ..WebFetchUrlValidationConfig::default()
        };
        let err =
            resolve_and_validate_redirect_target(&current, "https://blocked.example/path", &cfg)
                .unwrap_err();
        assert!(err.contains("denylisted"));
    }

    #[test]
    fn redirect_validation_allows_relative_target() {
        let current = Url::parse("https://safe.example/start").unwrap();
        let cfg = WebFetchUrlValidationConfig::default();
        let next = resolve_and_validate_redirect_target(&current, "/next", &cfg).unwrap();
        assert_eq!(next.as_str(), "https://safe.example/next");
    }
}
