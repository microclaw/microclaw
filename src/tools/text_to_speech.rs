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
use crate::config::{Config, MediaConfig, TtsConfig};

const ALLOWED_FORMATS: &[&str] = &["mp3", "opus", "aac", "flac", "wav", "pcm"];
const ALLOWED_VOICES: &[&str] = &[
    "alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse",
];

/// OpenAI-compatible text-to-speech tool.
///
/// Calls `/v1/audio/speech`. Saves the generated audio under
/// `<data_dir>/media/audio/<uuid>.<fmt>` and, when the channel supports
/// attachments, also delivers it inline.
pub struct TextToSpeechTool {
    data_dir: PathBuf,
    channels: Arc<ChannelRegistry>,
    db: Arc<Database>,
    cfg: TtsConfig,
    media: MediaConfig,
    openai_api_key: Option<String>,
    openai_base_url: Option<String>,
    timeout_secs: u64,
}

impl TextToSpeechTool {
    pub fn new(config: &Config, channels: Arc<ChannelRegistry>, db: Arc<Database>) -> Self {
        Self {
            data_dir: PathBuf::from(&config.data_dir),
            channels,
            db,
            cfg: config.media.tts.clone(),
            media: config.media.clone(),
            openai_api_key: config.openai_api_key.clone(),
            openai_base_url: config.openai_base_url.clone(),
            timeout_secs: config.tool_timeout_secs("text_to_speech", 60),
        }
    }

    fn client(&self) -> Result<MediaClient, String> {
        let key = self
            .media
            .resolve_api_key(self.openai_api_key.as_deref())
            .ok_or_else(|| {
                "text_to_speech requires an API key (media.api_key, \
                 MICROCLAW_OPENAI_API_KEY, OPENAI_API_KEY, or top-level \
                 openai_api_key)."
                    .to_string()
            })?;
        let base = self.media.resolve_base_url(self.openai_base_url.as_deref());
        MediaClient::new(base, key, self.timeout_secs)
    }
}

#[async_trait]
impl Tool for TextToSpeechTool {
    fn name(&self) -> &str {
        "text_to_speech"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Synthesize speech from text via an OpenAI-compatible \
                /audio/speech endpoint. Saves the audio under the bot's data \
                directory and — when the active channel supports attachments — \
                also sends it back to the user inline. Disabled by default; \
                requires operator opt-in via `media.tts.enabled`."
                .into(),
            input_schema: schema_object(
                json!({
                    "text": {
                        "type": "string",
                        "description": "What to say (max ~4096 chars for most providers)."
                    },
                    "voice": {
                        "type": "string",
                        "enum": ALLOWED_VOICES,
                        "description": "Voice preset. Defaults to media.tts.default_voice."
                    },
                    "format": {
                        "type": "string",
                        "enum": ALLOWED_FORMATS,
                        "description": "Audio format. Defaults to media.tts.default_format."
                    },
                    "model": {
                        "type": "string",
                        "description": "Optional model override (e.g. tts-1, tts-1-hd, gpt-4o-mini-tts)."
                    },
                    "deliver": {
                        "type": "boolean",
                        "description": "Whether to attempt channel delivery (default true)."
                    }
                }),
                &["text"],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        if !self.cfg.enabled {
            return ToolResult::error(
                "text_to_speech is disabled. Set media.tts.enabled=true to enable.".into(),
            );
        }
        let text = match input.get("text").and_then(|v| v.as_str()) {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => return ToolResult::error("Missing parameter: text".into()),
        };
        if text.chars().count() > 4096 {
            return ToolResult::error(
                "text exceeds 4096 characters — split into smaller chunks".into(),
            );
        }
        let voice = input
            .get("voice")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.cfg.default_voice.clone());
        if !ALLOWED_VOICES.iter().any(|v| v == &voice.as_str()) {
            return ToolResult::error(format!(
                "invalid voice '{voice}'. Allowed: {}",
                ALLOWED_VOICES.join(", ")
            ));
        }
        let format = input
            .get("format")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.cfg.default_format.clone());
        if !ALLOWED_FORMATS.iter().any(|v| v == &format.as_str()) {
            return ToolResult::error(format!(
                "invalid format '{format}'. Allowed: {}",
                ALLOWED_FORMATS.join(", ")
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
            "model": model,
            "voice": voice,
            "input": text,
            "response_format": format,
        });

        let resp = match client.post_json("audio/speech").json(&body).send().await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("audio/speech request failed: {e}")),
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return ToolResult::error(format!("audio/speech HTTP {status}: {txt}"));
        }
        let bytes = match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => return ToolResult::error(format!("audio body read failed: {e}")),
        };

        let saved = match persist_output(&self.data_dir, "audio", &format, &bytes) {
            Ok(p) => p,
            Err(e) => return ToolResult::error(format!("failed to save audio: {e}")),
        };

        let mut summary = format!(
            "TTS {} voice={} format={} ({} bytes) -> {}",
            model,
            voice,
            format,
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
                    &text,
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
            "voice": voice,
            "format": format,
            "model": model,
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
            let _ = deliver_and_store_bot_message(
                channels,
                db,
                "bot",
                chat_id,
                &format!("[audio attached: {}]", file.display()),
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
    fn voice_and_format_constants_wellformed() {
        assert!(ALLOWED_VOICES.contains(&"alloy"));
        assert!(ALLOWED_FORMATS.contains(&"mp3"));
    }
}
