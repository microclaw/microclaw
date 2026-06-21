//! `deep_research` — a deterministic multi-source research gatherer.
//!
//! The tool does the mechanical heavy lifting of a research pass: fan out a set
//! of sub-queries across the configured search provider, deduplicate the
//! sources, concurrently fetch the top pages (reusing the SSRF-guarded
//! `web_fetch` path), and return a citation-numbered evidence digest with
//! source-agreement signals. Semantic cross-verification and synthesis are left
//! to the agent (or the `researcher` specialist) reading the digest — the tool
//! itself runs no LLM, so it is cheap, fully deterministic, and unit-testable.

use async_trait::async_trait;
use futures_util::future::join_all;
use serde_json::json;
use std::collections::BTreeSet;

use super::{schema_object, Tool, ToolResult};
use microclaw_core::llm_types::ToolDefinition;
use microclaw_tools::web_content_validation::WebContentValidationConfig;
use microclaw_tools::web_fetch::WebFetchUrlValidationConfig;
use microclaw_tools::web_search::SearchProviderConfig;

const MAX_SUB_QUERIES: usize = 6;
const MAX_SOURCES: usize = 10;
const DEFAULT_FETCH_TOP_N: usize = 4;
const EXCERPT_CHARS: usize = 600;

pub struct DeepResearchTool {
    default_timeout_secs: u64,
    provider: SearchProviderConfig,
    validation: WebContentValidationConfig,
    url_validation: WebFetchUrlValidationConfig,
}

impl DeepResearchTool {
    pub fn new(
        default_timeout_secs: u64,
        provider: SearchProviderConfig,
        validation: WebContentValidationConfig,
        url_validation: WebFetchUrlValidationConfig,
    ) -> Self {
        Self {
            default_timeout_secs,
            provider,
            validation,
            url_validation,
        }
    }
}

struct Source {
    title: String,
    url: String,
    domain: String,
    snippet: String,
    /// Sub-query indices (1-based, as shown to the agent) that surfaced this URL.
    matched: BTreeSet<usize>,
    excerpt: Option<String>,
}

#[async_trait]
impl Tool for DeepResearchTool {
    fn name(&self) -> &str {
        "deep_research"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "deep_research".into(),
            description:
                "Run a structured multi-source research pass: fans out several sub-queries across \
                 the web, deduplicates sources, fetches the top pages, and returns a \
                 citation-numbered evidence digest with source-agreement signals. Pass a list of \
                 focused `queries` (break the question into distinct angles) for best coverage. \
                 Then synthesize an answer that cites sources by number, e.g. [1][2], and flags \
                 where sources disagree."
                    .into(),
            input_schema: schema_object(
                json!({
                    "queries": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Sub-queries / distinct angles to search (1-6 recommended)."
                    },
                    "query": {
                        "type": "string",
                        "description": "A single query (used when `queries` is omitted)."
                    },
                    "fetch": {
                        "type": "boolean",
                        "description": "Fetch full page text for the top sources (default true)."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Per-request timeout (defaults to the configured tool budget)."
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let queries = match parse_queries(&input) {
            Ok(q) => q,
            Err(msg) => return ToolResult::error(msg),
        };
        let fetch = input.get("fetch").and_then(|v| v.as_bool()).unwrap_or(true);
        let timeout_secs = input
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.default_timeout_secs)
            .clamp(1, 60);

        // Fan out: search every sub-query concurrently.
        let searches = queries.iter().map(|q| {
            microclaw_tools::web_search::search_with_provider(q, &self.provider, timeout_secs)
        });
        let results = join_all(searches).await;

        // Aggregate + dedup by normalized URL, tracking which sub-queries hit it.
        let mut sources: Vec<Source> = Vec::new();
        let mut no_result_queries: Vec<usize> = Vec::new();
        for (idx, result) in results.into_iter().enumerate() {
            let display_idx = idx + 1;
            match result {
                Ok(hits) if !hits.is_empty() => {
                    for hit in hits {
                        let norm = normalize_url(&hit.url);
                        if let Some(existing) =
                            sources.iter_mut().find(|s| normalize_url(&s.url) == norm)
                        {
                            existing.matched.insert(display_idx);
                        } else {
                            let mut matched = BTreeSet::new();
                            matched.insert(display_idx);
                            sources.push(Source {
                                domain: domain_of(&hit.url),
                                title: hit.title,
                                url: hit.url,
                                snippet: hit.snippet,
                                matched,
                                excerpt: None,
                            });
                        }
                    }
                }
                Ok(_) => no_result_queries.push(display_idx),
                Err(_) => no_result_queries.push(display_idx),
            }
        }

        if sources.is_empty() {
            return ToolResult::success(format!(
                "No sources found across {} sub-quer{}.",
                queries.len(),
                if queries.len() == 1 { "y" } else { "ies" }
            ));
        }

        // Rank: sources corroborated by more sub-queries first, then first-seen.
        sources.sort_by(|a, b| b.matched.len().cmp(&a.matched.len()));
        sources.truncate(MAX_SOURCES);

        // Fetch full text for the top sources (SSRF-guarded), concurrently.
        if fetch {
            let fetch_n = DEFAULT_FETCH_TOP_N.min(sources.len());
            let fetches = sources.iter().take(fetch_n).map(|s| {
                let url = s.url.clone();
                let validation = self.validation;
                let url_validation = self.url_validation.clone();
                async move {
                    microclaw_tools::web_fetch::fetch_url_with_timeout_and_validation(
                        &url,
                        timeout_secs,
                        validation,
                        url_validation,
                    )
                    .await
                    .ok()
                }
            });
            let fetched = join_all(fetches).await;
            for (src, text) in sources.iter_mut().zip(fetched.into_iter()) {
                if let Some(text) = text {
                    src.excerpt = Some(truncate_chars(text.trim(), EXCERPT_CHARS));
                }
            }
        }

        ToolResult::success(build_digest(&queries, &sources, &no_result_queries))
    }
}

fn parse_queries(input: &serde_json::Value) -> Result<Vec<String>, String> {
    let mut queries: Vec<String> = Vec::new();
    if let Some(arr) = input.get("queries").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if !t.is_empty() && !queries.iter().any(|q| q == t) {
                    queries.push(t.to_string());
                }
            }
        }
    }
    if queries.is_empty() {
        if let Some(s) = input.get("query").and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                queries.push(t.to_string());
            }
        }
    }
    if queries.is_empty() {
        return Err("Provide `queries` (array) or `query` (string).".to_string());
    }
    queries.truncate(MAX_SUB_QUERIES);
    Ok(queries)
}

fn build_digest(queries: &[String], sources: &[Source], no_result_queries: &[usize]) -> String {
    let mut out = String::new();
    out.push_str("# Research digest\n\n");
    out.push_str(&format!("Sub-queries ({}):\n", queries.len()));
    for (i, q) in queries.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", i + 1, q));
    }
    let domains: BTreeSet<&str> = sources.iter().map(|s| s.domain.as_str()).collect();
    out.push_str(&format!(
        "\n{} unique source{} across {} independent domain{}.\n\n",
        sources.len(),
        plural(sources.len()),
        domains.len(),
        plural(domains.len()),
    ));

    out.push_str("## Sources\n\n");
    for (i, s) in sources.iter().enumerate() {
        let matched: Vec<String> = s.matched.iter().map(|m| m.to_string()).collect();
        out.push_str(&format!("[{}] {}\n", i + 1, s.title));
        out.push_str(&format!("    {}\n", s.url));
        out.push_str(&format!(
            "    {} · surfaced by sub-quer{} {}\n",
            s.domain,
            if s.matched.len() == 1 { "y" } else { "ies" },
            matched.join(", ")
        ));
        if let Some(excerpt) = &s.excerpt {
            out.push_str(&format!("    excerpt: {}\n", excerpt));
        } else if !s.snippet.trim().is_empty() {
            out.push_str(&format!("    snippet: {}\n", s.snippet.trim()));
        }
        out.push('\n');
    }

    out.push_str("## Source-agreement signals\n");
    let corroborated: Vec<String> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.matched.len() >= 2)
        .map(|(i, _)| format!("[{}]", i + 1))
        .collect();
    if corroborated.is_empty() {
        out.push_str("- No source was surfaced by more than one sub-query; corroborate key claims before trusting them.\n");
    } else {
        out.push_str(&format!(
            "- Corroborated (surfaced by multiple sub-queries): {}\n",
            corroborated.join(", ")
        ));
    }
    if !no_result_queries.is_empty() {
        let gaps: Vec<String> = no_result_queries.iter().map(|n| n.to_string()).collect();
        out.push_str(&format!(
            "- ⚠️ Coverage gap: sub-quer{} {} returned no results.\n",
            if no_result_queries.len() == 1 { "y" } else { "ies" },
            gaps.join(", ")
        ));
    }
    out.push_str(
        "\nSynthesize an answer that cites sources by number, e.g. [1][2]. Where sources disagree, say so explicitly.\n",
    );
    out
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn domain_of(url: &str) -> String {
    let no_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let host = no_scheme.split(['/', '?', '#']).next().unwrap_or(no_scheme);
    host.trim_start_matches("www.").to_ascii_lowercase()
}

fn normalize_url(url: &str) -> String {
    let no_frag = url.split('#').next().unwrap_or(url);
    no_frag.trim_end_matches('/').to_ascii_lowercase()
}

fn truncate_chars(s: &str, max: usize) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        return collapsed;
    }
    let truncated: String = collapsed.chars().take(max).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool() -> DeepResearchTool {
        DeepResearchTool::new(
            15,
            SearchProviderConfig::default(),
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig::default(),
        )
    }

    #[test]
    fn definition_has_no_required_fields() {
        let def = tool().definition();
        assert_eq!(def.name, "deep_research");
        assert!(def.input_schema["properties"]["queries"].is_object());
        assert!(def.input_schema["required"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn errors_without_any_query() {
        let result = tool().execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Provide `queries`"));
    }

    #[test]
    fn parse_queries_dedups_and_caps() {
        let parsed = parse_queries(&json!({
            "queries": ["a", "a", " b ", "", "c", "d", "e", "f", "g"]
        }))
        .unwrap();
        assert_eq!(parsed, vec!["a", "b", "c", "d", "e", "f"]); // deduped, trimmed, capped at 6
    }

    #[test]
    fn parse_queries_falls_back_to_single_query() {
        let parsed = parse_queries(&json!({ "query": "hello world" })).unwrap();
        assert_eq!(parsed, vec!["hello world"]);
    }

    #[test]
    fn normalize_and_domain_helpers() {
        assert_eq!(
            normalize_url("https://Example.com/Path/"),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_url("https://x.com/p#frag"),
            "https://x.com/p"
        );
        assert_eq!(domain_of("https://www.Example.com/a/b"), "example.com");
        assert_eq!(domain_of("http://docs.rs/foo?x=1"), "docs.rs");
    }

    #[test]
    fn digest_shows_citations_and_signals() {
        let mut matched_a = BTreeSet::new();
        matched_a.insert(1);
        matched_a.insert(2);
        let mut matched_b = BTreeSet::new();
        matched_b.insert(1);
        let sources = vec![
            Source {
                title: "Alpha".into(),
                url: "https://a.example/x".into(),
                domain: "a.example".into(),
                snippet: "snip a".into(),
                matched: matched_a,
                excerpt: Some("full text a".into()),
            },
            Source {
                title: "Beta".into(),
                url: "https://b.example/y".into(),
                domain: "b.example".into(),
                snippet: "snip b".into(),
                matched: matched_b,
                excerpt: None,
            },
        ];
        let digest = build_digest(
            &["q1".to_string(), "q2".to_string(), "q3".to_string()],
            &sources,
            &[3],
        );
        assert!(digest.contains("[1] Alpha"));
        assert!(digest.contains("[2] Beta"));
        assert!(digest.contains("2 independent domains"));
        assert!(digest.contains("Corroborated"));
        assert!(digest.contains("[1]")); // corroborated list includes [1]
        assert!(digest.contains("Coverage gap"));
        assert!(digest.contains("excerpt: full text a"));
        assert!(digest.contains("snippet: snip b"));
    }

    #[test]
    fn truncate_collapses_whitespace_and_caps() {
        let out = truncate_chars("a   b\n\nc", 100);
        assert_eq!(out, "a b c");
        let long = "x ".repeat(1000);
        let capped = truncate_chars(&long, 10);
        assert!(capped.chars().count() <= 11); // 10 + ellipsis
        assert!(capped.ends_with('…'));
    }
}
