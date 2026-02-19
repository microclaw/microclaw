use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use crate::llm_types::ToolDefinition;

pub struct WebSearchTool;

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
                    }
                }),
                &["query"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let query = match input.get("query").and_then(|v| v.as_str()) {
            Some(q) => q,
            None => return ToolResult::error("Missing required parameter: query".into()),
        };

        match microclaw_tools::web_search::search_ddg(query).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_web_search_definition() {
        let tool = WebSearchTool;
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
        let tool = WebSearchTool;
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: query"));
    }

    #[tokio::test]
    async fn test_web_search_null_query() {
        let tool = WebSearchTool;
        let result = tool.execute(json!({"query": null})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: query"));
    }
}
