use async_trait::async_trait;
use microclaw_tools::web_content_validation::WebContentValidationConfig;
use microclaw_tools::web_fetch::WebFetchUrlValidationConfig;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use microclaw_core::llm_types::ToolDefinition;

pub struct WebFetchTool {
    default_timeout_secs: u64,
    validation: WebContentValidationConfig,
    url_validation: WebFetchUrlValidationConfig,
}

impl WebFetchTool {
    pub fn new(
        default_timeout_secs: u64,
        validation: WebContentValidationConfig,
        url_validation: WebFetchUrlValidationConfig,
    ) -> Self {
        Self {
            default_timeout_secs,
            validation,
            url_validation,
        }
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "web_fetch".into(),
            description:
                "Fetch a URL and return its text content (HTML parsed, scripts/styles removed). Max 20KB."
                    .into(),
            input_schema: schema_object(
                json!({
                    "url": {
                        "type": "string",
                        "description": "The URL to fetch"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Timeout in seconds (defaults to configured tool timeout budget)"
                    }
                }),
                &["url"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let url = match input.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => return ToolResult::error("Missing required parameter: url".into()),
        };
        let timeout_secs = input
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.default_timeout_secs);

        match microclaw_tools::web_fetch::fetch_url_with_timeout_and_validation(
            url,
            timeout_secs,
            self.validation,
            self.url_validation.clone(),
        )
        .await
        {
            Ok(text) => ToolResult::success(text),
            Err(e) => ToolResult::error(format!("Failed to fetch URL: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_web_fetch_definition() {
        let tool = WebFetchTool::new(
            15,
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig::default(),
        );
        assert_eq!(tool.name(), "web_fetch");
        let def = tool.definition();
        assert_eq!(def.name, "web_fetch");
        assert!(def.description.contains("20KB"));
        assert!(def.input_schema["properties"]["url"].is_object());
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "url"));
    }

    #[tokio::test]
    async fn test_web_fetch_missing_url() {
        let tool = WebFetchTool::new(
            15,
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig::default(),
        );
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: url"));
    }

    #[tokio::test]
    async fn test_web_fetch_null_url() {
        let tool = WebFetchTool::new(
            15,
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig::default(),
        );
        let result = tool.execute(json!({"url": null})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: url"));
    }

    #[tokio::test]
    async fn test_web_fetch_invalid_url() {
        let tool = WebFetchTool::new(
            1,
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig::default(),
        );
        let result = tool
            .execute(json!({"url": "https://this-domain-does-not-exist-12345.example"}))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Failed to fetch URL"));
    }

    #[tokio::test]
    async fn test_web_fetch_blocks_disallowed_scheme_before_request() {
        let tool = WebFetchTool::new(
            15,
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig::default(),
        );
        let result = tool.execute(json!({"url": "ftp://example.com"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("not allowed"));
    }

    #[tokio::test]
    async fn test_web_fetch_blocks_denylisted_host_before_request() {
        let tool = WebFetchTool::new(
            15,
            WebContentValidationConfig::default(),
            WebFetchUrlValidationConfig {
                denylist_hosts: vec!["example.com".to_string()],
                ..WebFetchUrlValidationConfig::default()
            },
        );
        let result = tool.execute(json!({"url": "https://example.com"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("denylisted"));
    }
}
