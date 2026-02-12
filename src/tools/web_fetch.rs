use async_trait::async_trait;
use serde_json::json;

use super::web_html::{extract_primary_html, html_to_text};
use super::{schema_object, Tool, ToolResult};
use crate::claude::ToolDefinition;
use crate::text::floor_char_boundary;

pub struct WebFetchTool;

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

        match fetch_url(url).await {
            Ok(text) => ToolResult::success(text),
            Err(e) => ToolResult::error(format!("Failed to fetch URL: {e}")),
        }
    }
}

async fn fetch_url(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(url)
        .header("User-Agent", "MicroClaw/1.0")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let primary = extract_primary_html(&body);
    let text = html_to_text(primary);

    const MAX_BYTES: usize = 20_000;
    if text.len() > MAX_BYTES {
        let truncated = &text[..floor_char_boundary(&text, MAX_BYTES)];
        Ok(format!("{truncated}\n\n[Truncated at 20KB]"))
    } else {
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_web_fetch_definition() {
        let tool = WebFetchTool;
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
        let tool = WebFetchTool;
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: url"));
    }

    #[tokio::test]
    async fn test_web_fetch_null_url() {
        let tool = WebFetchTool;
        let result = tool.execute(json!({"url": null})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: url"));
    }

    #[tokio::test]
    async fn test_web_fetch_invalid_url() {
        let tool = WebFetchTool;
        let result = tool
            .execute(json!({"url": "https://this-domain-does-not-exist-12345.example"}))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Failed to fetch URL"));
    }
}
