use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use microclaw_core::llm_types::ToolDefinition;

pub struct WebSearchTool {
    default_timeout_secs: u64,
}

const MIN_TIMEOUT_SECS: u64 = 1;
const MAX_TIMEOUT_SECS: u64 = 60;

impl WebSearchTool {
    pub fn new(default_timeout_secs: u64) -> Self {
        Self {
            default_timeout_secs,
        }
    }
}

#[async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        "web_search"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "web_search".into(),
            description: "Search the web using DuckDuckGo. Returns titles, URLs, and snippets."
                .into(),
            input_schema: schema_object(
                json!({
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Timeout in seconds (defaults to configured tool timeout budget)"
                    }
                }),
                &["query"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let query = match parse_query(&input) {
            Ok(q) => q,
            Err(msg) => return ToolResult::error(msg),
        };
        let timeout_secs = resolve_timeout_secs(&input, self.default_timeout_secs);

        match microclaw_tools::web_search::search_ddg_with_timeout(&query, timeout_secs).await {
            Ok(results) => {
                if results.is_empty() {
                    ToolResult::success("No results found.".into())
                } else {
                    ToolResult::success(results)
                }
            }
            Err(e) => ToolResult::error(format!("Search failed: {e}")),
        }
    }
}

fn parse_query(input: &serde_json::Value) -> Result<String, String> {
    let query = input
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: query".to_string())?;
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err("Missing required parameter: query".to_string());
    }
    Ok(trimmed.to_string())
}

fn resolve_timeout_secs(input: &serde_json::Value, default_timeout_secs: u64) -> u64 {
    input
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_timeout_secs)
        .clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_web_search_definition() {
        let tool = WebSearchTool::new(15);
        assert_eq!(tool.name(), "web_search");
        let def = tool.definition();
        assert_eq!(def.name, "web_search");
        assert!(def.description.contains("DuckDuckGo"));
        assert!(def.input_schema["properties"]["query"].is_object());
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "query"));
    }

    #[tokio::test]
    async fn test_web_search_missing_query() {
        let tool = WebSearchTool::new(15);
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: query"));
    }

    #[tokio::test]
    async fn test_web_search_null_query() {
        let tool = WebSearchTool::new(15);
        let result = tool.execute(json!({"query": null})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: query"));
    }

    #[tokio::test]
    async fn test_web_search_empty_query() {
        let tool = WebSearchTool::new(15);
        let result = tool.execute(json!({"query": "   " })).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: query"));
    }

    #[test]
    fn test_resolve_timeout_secs_clamps_bounds() {
        assert_eq!(resolve_timeout_secs(&json!({"timeout_secs": 0}), 15), 1);
        assert_eq!(resolve_timeout_secs(&json!({"timeout_secs": 1000}), 15), 60);
        assert_eq!(resolve_timeout_secs(&json!({"timeout_secs": 5}), 15), 5);
        assert_eq!(resolve_timeout_secs(&json!({}), 120), 60);
    }
}
