use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::internal::tool_runtime::web_html::{extract_ddg_results, SearchItem};

fn http_client(timeout_secs: u64) -> reqwest::Client {
    static CLIENTS: OnceLock<Mutex<HashMap<u64, reqwest::Client>>> = OnceLock::new();
    let cache = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(client) = cache.get(&timeout_secs) {
        return client.clone();
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("MicroClaw/1.0")
        .build()
        .expect("failed to build HTTP client");
    cache.insert(timeout_secs, client.clone());
    client
}

/// Selectable web-search backend. DuckDuckGo (HTML scrape, no key) is the
/// default and the fallback whenever a richer backend is selected but missing
/// its credentials/endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchBackend {
    #[default]
    Duckduckgo,
    /// Self-hosted SearXNG instance (`{base}/search?format=json`). Ideal for a
    /// $5 VPS: no API key, no rate limit, fully local.
    Searxng,
    /// Brave Search API (`X-Subscription-Token`).
    Brave,
    /// Tavily research API (`POST /search`).
    Tavily,
    /// Keenable web search (`POST /v1/search`). Works without an API key on
    /// the rate-limited public endpoint; `keenable_api_key` raises limits.
    Keenable,
    /// SpecStream Search API (`GET /v1/web-search`, Bearer key).
    Specstream,
}

fn default_search_max_results() -> usize {
    8
}

/// Configuration for the pluggable web-search provider. Defaults preserve the
/// historical behavior exactly (DuckDuckGo, 8 results), so existing
/// deployments see no change until they opt into a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchProviderConfig {
    #[serde(default)]
    pub backend: SearchBackend,
    /// Base URL of a SearXNG instance, e.g. `http://127.0.0.1:8888`.
    #[serde(default)]
    pub searxng_base_url: String,
    #[serde(default)]
    pub brave_api_key: String,
    #[serde(default)]
    pub tavily_api_key: String,
    /// Optional: Keenable works key-free; a key switches to the keyed endpoint.
    #[serde(default)]
    pub keenable_api_key: String,
    #[serde(default)]
    pub specstream_api_key: String,
    #[serde(default = "default_search_max_results")]
    pub max_results: usize,
}

impl Default for SearchProviderConfig {
    fn default() -> Self {
        Self {
            backend: SearchBackend::default(),
            searxng_base_url: String::new(),
            brave_api_key: String::new(),
            tavily_api_key: String::new(),
            keenable_api_key: String::new(),
            specstream_api_key: String::new(),
            max_results: default_search_max_results(),
        }
    }
}

impl SearchProviderConfig {
    pub fn normalize(&mut self) {
        self.searxng_base_url = self
            .searxng_base_url
            .trim()
            .trim_end_matches('/')
            .to_string();
        self.brave_api_key = self.brave_api_key.trim().to_string();
        self.tavily_api_key = self.tavily_api_key.trim().to_string();
        self.keenable_api_key = self.keenable_api_key.trim().to_string();
        self.specstream_api_key = self.specstream_api_key.trim().to_string();
        if self.max_results == 0 {
            self.max_results = default_search_max_results();
        }
        self.max_results = self.max_results.min(20);
    }

    /// The backend that will actually be used, downgrading to DuckDuckGo when
    /// the selected backend lacks the credentials/endpoint it needs. This keeps
    /// search working (degraded) instead of hard-failing on a misconfiguration.
    pub fn effective_backend(&self) -> SearchBackend {
        match self.backend {
            SearchBackend::Searxng if self.searxng_base_url.trim().is_empty() => {
                SearchBackend::Duckduckgo
            }
            SearchBackend::Brave if self.brave_api_key.trim().is_empty() => {
                SearchBackend::Duckduckgo
            }
            SearchBackend::Tavily if self.tavily_api_key.trim().is_empty() => {
                SearchBackend::Duckduckgo
            }
            SearchBackend::Specstream if self.specstream_api_key.trim().is_empty() => {
                SearchBackend::Duckduckgo
            }
            other => other,
        }
    }
}

/// Render structured hits into the numbered text block the agent consumes.
pub fn format_search_hits(hits: &[SearchItem]) -> String {
    let mut output = String::new();
    for (i, item) in hits.iter().enumerate() {
        output.push_str(&format!(
            "{}. {}\n   {}\n   {}\n\n",
            i + 1,
            item.title,
            item.url,
            item.snippet
        ));
    }
    output
}

/// Run a search via the configured provider and return structured hits,
/// transparently falling back to DuckDuckGo when the provider is misconfigured.
pub async fn search_with_provider(
    query: &str,
    config: &SearchProviderConfig,
    timeout_secs: u64,
) -> Result<Vec<SearchItem>, String> {
    let max = config.max_results.clamp(1, 20);
    let t = timeout_secs.max(1);
    match config.effective_backend() {
        SearchBackend::Duckduckgo => ddg_hits(query, t, max).await,
        SearchBackend::Searxng => searxng_hits(query, &config.searxng_base_url, t, max).await,
        SearchBackend::Brave => brave_hits(query, &config.brave_api_key, t, max).await,
        SearchBackend::Tavily => tavily_hits(query, &config.tavily_api_key, t, max).await,
        SearchBackend::Keenable => keenable_hits(query, &config.keenable_api_key, t, max).await,
        SearchBackend::Specstream => {
            specstream_hits(query, &config.specstream_api_key, t, max).await
        }
    }
}

async fn ddg_hits(query: &str, timeout_secs: u64, max: usize) -> Result<Vec<SearchItem>, String> {
    let encoded = urlencoding::encode(query);
    let url = format!("https://html.duckduckgo.com/html/?q={encoded}");
    let client = http_client(timeout_secs);
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok(extract_ddg_results(&body, max))
}

#[derive(Deserialize)]
struct SearxResponse {
    #[serde(default)]
    results: Vec<SearxResult>,
}

#[derive(Deserialize)]
struct SearxResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    content: String,
}

async fn searxng_hits(
    query: &str,
    base_url: &str,
    timeout_secs: u64,
    max: usize,
) -> Result<Vec<SearchItem>, String> {
    let encoded = urlencoding::encode(query);
    let url = format!("{base_url}/search?q={encoded}&format=json");
    let client = http_client(timeout_secs);
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let parsed: SearxResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed
        .results
        .into_iter()
        .filter(|r| !r.url.is_empty())
        .take(max)
        .map(|r| SearchItem {
            title: r.title,
            url: r.url,
            snippet: r.content,
        })
        .collect())
}

#[derive(Deserialize)]
struct BraveResponse {
    #[serde(default)]
    web: Option<BraveWeb>,
}

#[derive(Deserialize)]
struct BraveWeb {
    #[serde(default)]
    results: Vec<BraveResult>,
}

#[derive(Deserialize)]
struct BraveResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    description: String,
}

async fn brave_hits(
    query: &str,
    api_key: &str,
    timeout_secs: u64,
    max: usize,
) -> Result<Vec<SearchItem>, String> {
    let encoded = urlencoding::encode(query);
    let url = format!("https://api.search.brave.com/res/v1/web/search?q={encoded}&count={max}");
    let client = http_client(timeout_secs);
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .header("X-Subscription-Token", api_key)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let parsed: BraveResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed
        .web
        .map(|w| w.results)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| !r.url.is_empty())
        .take(max)
        .map(|r| SearchItem {
            title: r.title,
            url: r.url,
            snippet: r.description,
        })
        .collect())
}

#[derive(Serialize)]
struct TavilyRequest<'a> {
    api_key: &'a str,
    query: &'a str,
    max_results: usize,
}

#[derive(Deserialize)]
struct TavilyResponse {
    #[serde(default)]
    results: Vec<TavilyResult>,
}

#[derive(Deserialize)]
struct TavilyResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    content: String,
}

async fn tavily_hits(
    query: &str,
    api_key: &str,
    timeout_secs: u64,
    max: usize,
) -> Result<Vec<SearchItem>, String> {
    let client = http_client(timeout_secs);
    let resp = client
        .post("https://api.tavily.com/search")
        .json(&TavilyRequest {
            api_key,
            query,
            max_results: max,
        })
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let parsed: TavilyResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed
        .results
        .into_iter()
        .filter(|r| !r.url.is_empty())
        .take(max)
        .map(|r| SearchItem {
            title: r.title,
            url: r.url,
            snippet: r.content,
        })
        .collect())
}

#[derive(Serialize)]
struct KeenableRequest<'a> {
    query: &'a str,
    max_results: usize,
}

#[derive(Deserialize)]
struct KeenableResponse {
    #[serde(default)]
    results: Vec<KeenableResult>,
}

#[derive(Deserialize)]
struct KeenableResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    description: String,
}

fn keenable_request(
    client: &reqwest::Client,
    query: &str,
    api_key: &str,
    max: usize,
) -> reqwest::RequestBuilder {
    let api_key = api_key.trim();
    let builder = if api_key.is_empty() {
        client
            .post("https://api.keenable.ai/v1/search/public")
            .header("X-Keenable-Title", "MicroClaw")
    } else {
        client
            .post("https://api.keenable.ai/v1/search")
            .header("X-API-Key", api_key)
    };
    builder.json(&KeenableRequest {
        query,
        max_results: max,
    })
}

async fn keenable_hits(
    query: &str,
    api_key: &str,
    timeout_secs: u64,
    max: usize,
) -> Result<Vec<SearchItem>, String> {
    let client = http_client(timeout_secs);
    let resp = keenable_request(&client, query, api_key, max)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let parsed: KeenableResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed
        .results
        .into_iter()
        .filter(|r| !r.url.is_empty())
        .take(max)
        .map(|r| SearchItem {
            title: r.title,
            url: r.url,
            snippet: if r.snippet.trim().is_empty() {
                r.description
            } else {
                r.snippet
            },
        })
        .collect())
}

#[derive(Deserialize)]
struct SpecstreamResponse {
    data: SpecstreamData,
}

#[derive(Deserialize)]
struct SpecstreamData {
    #[serde(default)]
    sources: Vec<SpecstreamSource>,
}

#[derive(Deserialize)]
struct SpecstreamSource {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    snippet: String,
}

fn specstream_request(
    client: &reqwest::Client,
    query: &str,
    api_key: &str,
    max: usize,
) -> reqwest::RequestBuilder {
    let encoded = urlencoding::encode(query);
    let url = format!("https://api.specstream.ai/v1/web-search?q={encoded}&num={max}&speed=fast");
    client.get(&url).bearer_auth(api_key.trim())
}

async fn specstream_hits(
    query: &str,
    api_key: &str,
    timeout_secs: u64,
    max: usize,
) -> Result<Vec<SearchItem>, String> {
    let client = http_client(timeout_secs);
    let resp = specstream_request(&client, query, api_key, max)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let parsed: SpecstreamResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed
        .data
        .sources
        .into_iter()
        .filter(|r| !r.url.is_empty())
        .take(max)
        .map(|r| SearchItem {
            title: r.title,
            url: r.url,
            snippet: r.snippet,
        })
        .collect())
}

pub async fn search_ddg_with_timeout(query: &str, timeout_secs: u64) -> Result<String, String> {
    let hits = ddg_hits(query, timeout_secs.max(1), 8).await?;
    Ok(format_search_hits(&hits))
}

pub async fn search_ddg(query: &str) -> Result<String, String> {
    search_ddg_with_timeout(query, 15).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_is_duckduckgo() {
        let cfg = SearchProviderConfig::default();
        assert_eq!(cfg.backend, SearchBackend::Duckduckgo);
        assert_eq!(cfg.effective_backend(), SearchBackend::Duckduckgo);
        assert_eq!(cfg.max_results, 8);
    }

    #[test]
    fn effective_backend_downgrades_when_unconfigured() {
        let cfg = SearchProviderConfig {
            backend: SearchBackend::Searxng,
            ..Default::default()
        };
        assert_eq!(cfg.effective_backend(), SearchBackend::Duckduckgo);

        let cfg = SearchProviderConfig {
            backend: SearchBackend::Brave,
            ..Default::default()
        };
        assert_eq!(cfg.effective_backend(), SearchBackend::Duckduckgo);

        let cfg = SearchProviderConfig {
            backend: SearchBackend::Tavily,
            tavily_api_key: "tvly-xxx".into(),
            ..Default::default()
        };
        assert_eq!(cfg.effective_backend(), SearchBackend::Tavily);
    }

    #[test]
    fn keenable_works_without_a_key() {
        let cfg = SearchProviderConfig {
            backend: SearchBackend::Keenable,
            ..Default::default()
        };
        assert_eq!(cfg.effective_backend(), SearchBackend::Keenable);

        let client = reqwest::Client::new();
        let req = keenable_request(&client, "rust", "", 5).build().unwrap();
        assert_eq!(
            req.url().as_str(),
            "https://api.keenable.ai/v1/search/public"
        );
        assert_eq!(req.headers().get("X-Keenable-Title").unwrap(), "MicroClaw");

        let req = keenable_request(&client, "rust", " kn-test ", 5)
            .build()
            .unwrap();
        assert_eq!(req.url().as_str(), "https://api.keenable.ai/v1/search");
        assert_eq!(req.headers().get("X-API-Key").unwrap(), "kn-test");
    }

    #[test]
    fn specstream_needs_a_key() {
        let cfg = SearchProviderConfig {
            backend: SearchBackend::Specstream,
            ..Default::default()
        };
        assert_eq!(cfg.effective_backend(), SearchBackend::Duckduckgo);

        let cfg = SearchProviderConfig {
            backend: SearchBackend::Specstream,
            specstream_api_key: "ss-test".into(),
            ..Default::default()
        };
        assert_eq!(cfg.effective_backend(), SearchBackend::Specstream);

        let client = reqwest::Client::new();
        let req = specstream_request(&client, "rust async", " ss-test ", 5)
            .build()
            .unwrap();
        assert_eq!(
            req.url().as_str(),
            "https://api.specstream.ai/v1/web-search?q=rust%20async&num=5&speed=fast"
        );
        assert_eq!(
            req.headers().get("Authorization").unwrap(),
            "Bearer ss-test"
        );
    }

    #[test]
    fn specstream_reply_reads_data_sources() {
        let body = r#"{"data": {"query": "rust", "sources": [
            {"url": "https://www.rust-lang.org/", "title": "Rust", "site": "rust-lang.org",
             "snippet": "A language empowering everyone.", "cited": false,
             "published": "2026-10-30"},
            {"url": "", "title": "no url", "site": "", "snippet": "", "cited": false}
        ]}}"#;
        let parsed: SpecstreamResponse = serde_json::from_str(body).unwrap();
        let sources = parsed.data.sources;
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].url, "https://www.rust-lang.org/");
        assert_eq!(sources[0].title, "Rust");
        assert_eq!(sources[0].snippet, "A language empowering everyone.");
    }

    #[test]
    fn normalize_trims_and_bounds() {
        let mut cfg = SearchProviderConfig {
            backend: SearchBackend::Searxng,
            searxng_base_url: "  http://localhost:8888/  ".into(),
            brave_api_key: "  k  ".into(),
            max_results: 0,
            ..Default::default()
        };
        cfg.normalize();
        assert_eq!(cfg.searxng_base_url, "http://localhost:8888");
        assert_eq!(cfg.brave_api_key, "k");
        assert_eq!(cfg.max_results, 8);
        assert_eq!(cfg.effective_backend(), SearchBackend::Searxng);
    }

    #[test]
    fn format_hits_numbers_results() {
        let hits = vec![
            SearchItem {
                title: "A".into(),
                url: "https://a.example".into(),
                snippet: "sa".into(),
            },
            SearchItem {
                title: "B".into(),
                url: "https://b.example".into(),
                snippet: "sb".into(),
            },
        ];
        let out = format_search_hits(&hits);
        assert!(out.contains("1. A"));
        assert!(out.contains("2. B"));
        assert!(out.contains("https://a.example"));
    }
}
