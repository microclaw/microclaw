use async_trait::async_trait;
use reqwest::multipart;
use serde_json::{json, Value};
use std::path::PathBuf;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_tools::media_client::{load_bytes_from_location, MediaClient};

use super::{schema_object, Tool, ToolResult};
use crate::config::{Config, MediaConfig, SttConfig};

/// OpenAI-compatible speech-to-text tool.
///
/// Calls `/v1/audio/transcriptions` (multipart/form-data). Accepts a local
/// audio path (inside working_dir), a public URL, or a `data:` URI.
/// Disabled by default.
pub struct TranscribeAudioTool {
    working_dir: PathBuf,
    allowed_read_dirs: Vec<PathBuf>,
    cfg: SttConfig,
    media: MediaConfig,
    openai_api_key: Option<String>,
    openai_base_url: Option<String>,
    timeout_secs: u64,
}

impl TranscribeAudioTool {
    pub fn new(config: &Config) -> Self {
        Self {
            working_dir: PathBuf::from(&config.working_dir),
            allowed_read_dirs: config
                .media
                .allowed_read_dirs
                .iter()
                .map(PathBuf::from)
                .collect(),
            cfg: config.media.stt.clone(),
            media: config.media.clone(),
            openai_api_key: config.openai_api_key.clone(),
            openai_base_url: config.openai_base_url.clone(),
            timeout_secs: config.tool_timeout_secs("transcribe_audio", 120),
        }
    }

    fn client(&self) -> Result<MediaClient, String> {
        let key = self
            .media
            .resolve_api_key(self.openai_api_key.as_deref())
            .ok_or_else(|| {
                "transcribe_audio requires an API key (media.api_key, \
                 MICROCLAW_OPENAI_API_KEY, OPENAI_API_KEY, or top-level \
                 openai_api_key)."
                    .to_string()
            })?;
        let base = self.media.resolve_base_url(self.openai_base_url.as_deref());
        MediaClient::new(base, key, self.timeout_secs)
    }
}

fn filename_for_mime(mime: Option<&str>) -> (&'static str, &'static str) {
    match mime.unwrap_or("") {
        "audio/mpeg" => ("audio.mp3", "audio/mpeg"),
        "audio/mp4" => ("audio.m4a", "audio/mp4"),
        "audio/ogg" | "audio/opus" => ("audio.ogg", "audio/ogg"),
        "audio/wav" | "audio/wave" | "audio/x-wav" => ("audio.wav", "audio/wav"),
        "audio/flac" => ("audio.flac", "audio/flac"),
        "audio/webm" => ("audio.webm", "audio/webm"),
        _ => ("audio.ogg", "audio/ogg"),
    }
}

#[async_trait]
impl Tool for TranscribeAudioTool {
    fn name(&self) -> &str {
        "transcribe_audio"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Transcribe an audio file to text via an OpenAI-compatible \
                /audio/transcriptions endpoint (Whisper-style). Accepts a file path \
                under the working directory, a public URL, or a `data:` URI. \
                Returns the transcript. Disabled by default; requires operator \
                opt-in via `media.stt.enabled`."
                .into(),
            input_schema: schema_object(
                json!({
                    "audio": {
                        "type": "string",
                        "description": "Audio source: local file path (inside working_dir), https:// URL, or data: URI."
                    },
                    "language": {
                        "type": "string",
                        "description": "Optional ISO-639-1 hint (e.g. 'en', 'zh'). Defaults to media.stt.language (auto if unset)."
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Optional biasing prompt (e.g. glossary of expected names/terms)."
                    },
                    "model": {
                        "type": "string",
                        "description": "Optional model override (e.g. whisper-1, gpt-4o-transcribe)."
                    }
                }),
                &["audio"],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        if !self.cfg.enabled {
            return ToolResult::error(
                "transcribe_audio is disabled. Set media.stt.enabled=true to enable.".into(),
            );
        }
        let audio = match input.get("audio").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return ToolResult::error("Missing parameter: audio".into()),
        };
        let language = input
            .get("language")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| self.cfg.language.clone());
        let prompt = input
            .get("prompt")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.cfg.model.clone());

        let client = match self.client() {
            Ok(c) => c,
            Err(e) => return ToolResult::error(e),
        };

        let (bytes, mime) = match load_bytes_from_location(
            client.client(),
            &audio,
            &self.working_dir,
            &self.allowed_read_dirs,
        )
        .await
        {
                Ok(v) => v,
                Err(e) => return ToolResult::error(format!("audio fetch failed: {e}")),
            };
        let (file_name, mime_str) = filename_for_mime(mime.as_deref());

        let part = match multipart::Part::bytes(bytes)
            .file_name(file_name)
            .mime_str(mime_str)
        {
            Ok(p) => p,
            Err(e) => return ToolResult::error(format!("invalid audio mime '{mime_str}': {e}")),
        };
        let mut form = multipart::Form::new()
            .text("model", model.clone())
            .part("file", part);
        if let Some(lang) = language.as_deref().filter(|s| !s.is_empty()) {
            form = form.text("language", lang.to_string());
        }
        if let Some(p) = prompt.as_deref().filter(|s| !s.is_empty()) {
            form = form.text("prompt", p.to_string());
        }

        let resp = match client
            .post_multipart("audio/transcriptions", form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("transcriptions request failed: {e}")),
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return ToolResult::error(format!("transcriptions HTTP {status}: {text}"));
        }
        let parsed: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("invalid JSON from transcriptions: {e}")),
        };
        match parsed.get("text").and_then(|v| v.as_str()) {
            Some(t) => ToolResult::success(t.to_string()),
            None => ToolResult::error("transcriptions response missing 'text' field".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_mapping() {
        assert_eq!(filename_for_mime(Some("audio/mpeg")).1, "audio/mpeg");
        assert_eq!(filename_for_mime(Some("audio/wav")).1, "audio/wav");
        assert_eq!(filename_for_mime(None).1, "audio/ogg");
    }
}
