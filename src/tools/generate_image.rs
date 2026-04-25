use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_tools::media_client::{persist_output, MediaClient};
use microclaw_tools::runtime::auth_context_from_input;

use super::{schema_object, Tool, ToolResult};
use crate::config::{Config, ImageGenConfig, MediaConfig};

const ALLOWED_SIZES: &[&str] = &[
    "256x256",
    "512x512",
    "1024x1024",
    "1024x1536",
    "1536x1024",
    "1024x1792",
    "1792x1024",
    "auto",
];

/// OpenAI-compatible image generation tool.
///
/// Calls `/v1/images/generations` on the configured base URL. Saves the
/// returned PNG under `<data_dir>/media/images/<uuid>.png`. When the caller's
/// channel supports `send_attachment`, the tool also delivers the image
/// inline; otherwise the path is returned and the agent can hand it off
/// manually.
pub struct GenerateImageTool {
    data_dir: PathBuf,
    channels: Arc<ChannelRegistry>,
    db: Arc<Database>,
    cfg: ImageGenConfig,
    media: MediaConfig,
    openai_api_key: Option<String>,
    openai_base_url: Option<String>,
    timeout_secs: u64,
}

impl GenerateImageTool {
    pub fn new(config: &Config, channels: Arc<ChannelRegistry>, db: Arc<Database>) -> Self {
        Self {
            data_dir: PathBuf::from(&config.data_dir),
            channels,
            db,
            cfg: config.media.image_gen.clone(),
            media: config.media.clone(),
            openai_api_key: config.openai_api_key.clone(),
            openai_base_url: config.openai_base_url.clone(),
            timeout_secs: config.tool_timeout_secs("generate_image", 120),
        }
    }

    fn client(&self) -> Result<MediaClient, String> {
        let key = self
            .media
            .resolve_api_key(self.openai_api_key.as_deref())
            .ok_or_else(|| {
                "generate_image requires an API key. Set one of media.api_key, \
                 MICROCLAW_OPENAI_API_KEY, OPENAI_API_KEY, or top-level openai_api_key."
                    .to_string()
            })?;
        let base = self.media.resolve_base_url(self.openai_base_url.as_deref());
        MediaClient::new(base, key, self.timeout_secs)
    }
}

#[async_trait]
impl Tool for GenerateImageTool {
    fn name(&self) -> &str {
        "generate_image"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Generate an image from a natural-language prompt via an \
                OpenAI-compatible images endpoint. The PNG is saved under the bot's \
                data directory and — when the active channel supports attachments — \
                also sent back to the user inline. Returns the file path and a \
                confirmation of delivery. Disabled by default; requires operator \
                opt-in via `media.image_gen.enabled`."
                .into(),
            input_schema: schema_object(
                json!({
                    "prompt": {
                        "type": "string",
                        "description": "What to draw. Be specific — style, subject, composition."
                    },
                    "size": {
                        "type": "string",
                        "enum": ALLOWED_SIZES,
                        "description": "Optional image size. Defaults to media.image_gen.default_size."
                    },
                    "model": {
                        "type": "string",
                        "description": "Optional model override (e.g. gpt-image-1, dall-e-3)."
                    },
                    "deliver": {
                        "type": "boolean",
                        "description": "Whether to attempt channel delivery (default true). Set false to only return the path."
                    }
                }),
                &["prompt"],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        if !self.cfg.enabled {
            return ToolResult::error(
                "generate_image is disabled. Set media.image_gen.enabled=true to enable.".into(),
            );
        }
        let prompt = match input.get("prompt").and_then(|v| v.as_str()) {
            Some(p) if !p.trim().is_empty() => p.trim().to_string(),
            _ => return ToolResult::error("Missing or empty parameter: prompt".into()),
        };
        let size = input
            .get("size")
            .and_then(|v| v.as_str())
            .unwrap_or(self.cfg.default_size.as_str())
            .to_string();
        if !ALLOWED_SIZES.iter().any(|s| s == &size.as_str()) {
            return ToolResult::error(format!(
                "invalid size '{size}'. Allowed: {}",
                ALLOWED_SIZES.join(", ")
            ));
        }
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.cfg.model.clone());
        let deliver = input
            .get("deliver")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let client = match self.client() {
            Ok(c) => c,
            Err(e) => return ToolResult::error(e),
        };

        let body = json!({
            "prompt": prompt,
            "size": size,
            "model": model,
            "n": 1,
            // gpt-image-1 returns base64 by default; dall-e-3 returns a URL
            // unless response_format is set. Ask for base64 explicitly so the
            // return-shape is uniform.
            "response_format": "b64_json",
        });

        let resp = match client.post_json("images/generations").json(&body).send().await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("images API request failed: {e}")),
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return ToolResult::error(format!("images API HTTP {status}: {text}"));
        }
        let parsed: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("invalid JSON from images API: {e}")),
        };

        // Support both {"data":[{"b64_json":"..."}]} and
        // {"data":[{"url":"..."}]}.
        let datum = parsed
            .get("data")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .cloned();
        let bytes: Vec<u8> = if let Some(b64) = datum
            .as_ref()
            .and_then(|d| d.get("b64_json"))
            .and_then(|v| v.as_str())
        {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(b) => b,
                Err(e) => return ToolResult::error(format!("bad base64 in image response: {e}")),
            }
        } else if let Some(url) = datum
            .as_ref()
            .and_then(|d| d.get("url"))
            .and_then(|v| v.as_str())
        {
            // Download the URL through the media client (so SSRF check applies).
            let dl = match client
                .client()
                .get(url)
                .send()
                .await
                .map_err(|e| e.to_string())
            {
                Ok(r) => r,
                Err(e) => {
                    return ToolResult::error(format!("failed to download image URL: {e}"))
                }
            };
            if !dl.status().is_success() {
                return ToolResult::error(format!("image download HTTP {}", dl.status()));
            }
            match dl.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => return ToolResult::error(format!("image body read failed: {e}")),
            }
        } else {
            return ToolResult::error(
                "images API response missing both b64_json and url fields".into(),
            );
        };

        let saved = match persist_output(&self.data_dir, "images", "png", &bytes) {
            Ok(p) => p,
            Err(e) => return ToolResult::error(format!("failed to save image: {e}")),
        };

        let mut summary = format!(
            "generated {} ({} bytes) -> {}",
            model,
            bytes.len(),
            saved.display()
        );

        if deliver {
            if let Some(auth) = auth_context_from_input(&input) {
                match deliver_attachment(
                    &self.channels,
                    self.db.clone(),
                    auth.caller_chat_id,
                    &saved,
                    &prompt,
                )
                .await
                {
                    Ok(msg) => summary.push_str(&format!("; {msg}")),
                    Err(e) => summary.push_str(&format!("; delivery skipped: {e}")),
                }
            }
        }

        ToolResult::success(summary).with_metadata(json!({
            "path": saved.to_string_lossy(),
            "model": model,
            "size": size,
        }))
    }
}

async fn deliver_attachment(
    channels: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
    file: &std::path::Path,
    caption: &str,
) -> Result<String, String> {
    let routing = match microclaw_channels::channel::get_required_chat_routing(
        channels,
        db.clone(),
        chat_id,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    let Some(adapter) = channels.get(&routing.channel_name) else {
        return Err(format!("no adapter for channel '{}'", routing.channel_name));
    };
    if adapter.is_local_only() {
        return Ok(format!(
            "channel '{}' is local-only, path retained at: {}",
            routing.channel_name,
            file.display()
        ));
    }
    let external_chat_id = microclaw_storage::db::call_blocking(db.clone(), move |d| {
        d.get_chat_external_id(chat_id)
    })
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_else(|| chat_id.to_string());
    let caption_short = caption.chars().take(120).collect::<String>();
    match adapter
        .send_attachment(&external_chat_id, file, Some(&caption_short))
        .await
    {
        Ok(_) => {
            // Store a chat-visible marker so transcripts reflect the send.
            let _ = deliver_and_store_bot_message(
                channels,
                db,
                "bot",
                chat_id,
                &format!("[image attached: {}]", file.display()),
            )
            .await;
            Ok(format!(
                "delivered via channel '{}'",
                routing.channel_name
            ))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_list_includes_defaults() {
        assert!(ALLOWED_SIZES.contains(&"1024x1024"));
        assert!(ALLOWED_SIZES.contains(&"auto"));
    }
}
