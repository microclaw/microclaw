use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_tools::media_client::{load_bytes_from_location, MediaClient};

use super::{schema_object, Tool, ToolResult};
use crate::config::{Config, MediaConfig, VisionConfig};

/// OpenAI-compatible vision tool.
///
/// Calls `/v1/chat/completions` with a single image + instruction message.
/// Accepts a local path (inside working_dir), a public URL, or a `data:` URI.
/// Returns the model's text answer. Disabled by default.
pub struct DescribeImageTool {
    working_dir: PathBuf,
    cfg: VisionConfig,
    media: MediaConfig,
    openai_api_key: Option<String>,
    openai_base_url: Option<String>,
    timeout_secs: u64,
}

impl DescribeImageTool {
    pub fn new(config: &Config) -> Self {
        Self {
            working_dir: PathBuf::from(&config.working_dir),
            cfg: config.media.vision.clone(),
            media: config.media.clone(),
            openai_api_key: config.openai_api_key.clone(),
            openai_base_url: config.openai_base_url.clone(),
            timeout_secs: config.tool_timeout_secs("describe_image", 60),
        }
    }

    fn client(&self) -> Result<MediaClient, String> {
        let key = self
            .media
            .resolve_api_key(self.openai_api_key.as_deref())
            .ok_or_else(|| {
                "describe_image requires an API key (media.api_key, \
                 MICROCLAW_OPENAI_API_KEY, OPENAI_API_KEY, or top-level \
                 openai_api_key)."
                    .to_string()
            })?;
        let base = self.media.resolve_base_url(self.openai_base_url.as_deref());
        MediaClient::new(base, key, self.timeout_secs)
    }
}

#[async_trait]
impl Tool for DescribeImageTool {
    fn name(&self) -> &str {
        "describe_image"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Describe / analyze / OCR an image via an OpenAI-compatible \
                vision-capable chat model. Accepts a file path under the working \
                directory, a public URL, or a `data:` URI. Returns the model's text \
                answer. Disabled by default; requires operator opt-in via \
                `media.vision.enabled`."
                .into(),
            input_schema: schema_object(
                json!({
                    "image": {
                        "type": "string",
                        "description": "Image source: local file path (inside working_dir), https:// URL, or data: URI."
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Optional instruction (defaults to 'Describe this image in detail.'). Use to ask for OCR, specific analysis, etc."
                    },
                    "model": {
                        "type": "string",
                        "description": "Optional model override (e.g. gpt-4o, gpt-4o-mini)."
                    }
                }),
                &["image"],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        if !self.cfg.enabled {
            return ToolResult::error(
                "describe_image is disabled. Set media.vision.enabled=true to enable.".into(),
            );
        }
        let image = match input.get("image").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return ToolResult::error("Missing parameter: image".into()),
        };
        let prompt = input
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or("Describe this image in detail.")
            .trim()
            .to_string();
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.cfg.model.clone());

        let client = match self.client() {
            Ok(c) => c,
            Err(e) => return ToolResult::error(e),
        };

        // Build an image_url content block. For local files we inline as
        // data: URI; for remote URLs we pass the URL through (the provider
        // will fetch it). We still call SSRF check on remote URLs through
        // `load_bytes_from_location` to normalize behavior.
        let image_url: String = if image.starts_with("http://")
            || image.starts_with("https://")
        {
            // Remote URLs: run SSRF check via load_bytes then re-encode as
            // data: URI so provider always sees inline bytes (avoids cases
            // where the provider can't reach the URL).
            let (bytes, mime) =
                match load_bytes_from_location(client.client(), &image, &self.working_dir).await {
                    Ok(v) => v,
                    Err(e) => return ToolResult::error(format!("image fetch failed: {e}")),
                };
            let mime = mime.unwrap_or_else(|| "image/png".to_string());
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            format!("data:{mime};base64,{b64}")
        } else if image.starts_with("data:") {
            image.clone()
        } else {
            let (bytes, mime) =
                match load_bytes_from_location(client.client(), &image, &self.working_dir).await {
                    Ok(v) => v,
                    Err(e) => return ToolResult::error(format!("image read failed: {e}")),
                };
            let mime = mime.unwrap_or_else(|| "image/png".to_string());
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            format!("data:{mime};base64,{b64}")
        };

        let body = json!({
            "model": model,
            "max_tokens": self.cfg.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": prompt },
                        { "type": "image_url", "image_url": { "url": image_url } }
                    ]
                }
            ]
        });

        let resp = match client.post_json("chat/completions").json(&body).send().await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("vision API request failed: {e}")),
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return ToolResult::error(format!("vision API HTTP {status}: {text}"));
        }
        let parsed: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("invalid JSON from vision API: {e}")),
        };

        let content = parsed
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"));

        let text = match content {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => {
                return ToolResult::error(
                    "vision API response missing choices[0].message.content".into(),
                );
            }
        };

        ToolResult::success(text)
    }
}

#[cfg(test)]
mod tests {
    // Full e2e with a mock chat/completions server lives in the integration
    // test file; module-level tests here just sanity-check struct wiring
    // once the rest of the PR compiles.
}
