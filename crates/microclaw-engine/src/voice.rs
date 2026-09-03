//! Shared voice/audio inbound transcription used by channel adapters.
//!
//! Each platform exposes audio bytes differently (Telegram voice, Discord
//! attachment, Slack file, Feishu audio message), but once we have raw bytes
//! the dispatch into the configured STT provider — OpenAI Whisper or a local
//! command — is the same. This module owns that dispatch and the format used
//! when injecting transcription into the inbound text the agent sees.
//!
//! Also exposes the inverse path: when a turn was triggered by an inbound
//! voice message and `voice_round_trip` is enabled, channels call
//! [`synth_speech_to_temp`] to render the bot's reply as audio so the user
//! can listen to it on the same surface they spoke into.

use std::path::PathBuf;

use crate::config::Config;

/// Returns true if a transcription provider is configured. Channels can use
/// this to decide between transcribing or surfacing a "voice not supported"
/// notice to the sender.
pub fn can_transcribe(config: &Config) -> bool {
    if config.voice_provider == "local" {
        config.voice_transcription_command.is_some()
    } else {
        config.openai_api_key.is_some()
    }
}

/// Run audio bytes through the configured STT provider.
pub async fn transcribe_audio(config: &Config, audio_bytes: &[u8]) -> Result<String, String> {
    let provider = &config.voice_provider;

    if provider == "local" {
        let Some(ref command) = config.voice_transcription_command else {
            return Err(
                "Local voice transcription configured but voice_transcription_command not set"
                    .into(),
            );
        };

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("voice_{}.ogg", uuid::Uuid::new_v4()));
        tokio::fs::write(&temp_file, audio_bytes)
            .await
            .map_err(|e| e.to_string())?;

        let cmd = command.replace("{file}", temp_file.to_str().unwrap_or(""));

        let output_result = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .await;

        let _ = tokio::fs::remove_file(&temp_file).await;

        let output =
            output_result.map_err(|e| format!("Failed to run transcription command: {e}"))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(format!(
                "Transcription command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    } else {
        let Some(ref openai_key) = config.openai_api_key else {
            return Err("Voice transcription requires openai_api_key".into());
        };
        microclaw_app::transcribe::transcribe_audio(openai_key, audio_bytes).await
    }
}

/// Standard inbound formatting so the agent always sees voice messages with
/// the same shape regardless of platform.
pub fn format_voice_inbound(sender_name: &str, transcription: &str) -> String {
    format!("[voice message from {sender_name}]: {transcription}")
}

/// Standard error shape when transcription was attempted but failed.
pub fn format_voice_inbound_error(sender_name: &str, error: &str) -> String {
    format!("[voice message from {sender_name}]: [transcription failed: {error}]")
}

/// True when this deployment should reply with audio to voice-inbound turns.
/// Requires both the operator opt-in (`voice_round_trip: true`) and the TTS
/// layer to be enabled in `media.tts`.
pub fn round_trip_enabled(config: &Config) -> bool {
    config.voice_round_trip && config.media.tts.enabled
}

/// Synthesize `text` to a temporary audio file using the configured TTS
/// provider, returning the on-disk path. Caller is responsible for sending
/// it to the user and removing the file when done.
///
/// Bypasses the `text_to_speech` tool surface so channel adapters don't
/// have to fabricate a tool-input shape just to play back a reply.
pub async fn synth_speech_to_temp(config: &Config, text: &str) -> Result<PathBuf, String> {
    if !round_trip_enabled(config) {
        return Err("voice_round_trip is disabled".into());
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("empty text".into());
    }
    // The OpenAI /audio/speech endpoint caps input at 4096 chars. Truncate
    // rather than fail — partial audio is more useful than none.
    let payload_text: String = trimmed.chars().take(4096).collect();

    let media = &config.media;
    let tts = &media.tts;
    let api_key = media
        .api_key
        .as_deref()
        .or(config.openai_api_key.as_deref())
        .ok_or_else(|| "media.api_key (or openai_api_key) not set".to_string())?;
    let base_url = media
        .base_url
        .clone()
        .or_else(|| config.openai_base_url.clone())
        .unwrap_or_else(|| "https://api.openai.com/v1".to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("http client build failed: {e}"))?;
    let url = format!("{}/audio/speech", base_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "model": tts.model,
        "voice": tts.default_voice,
        "input": payload_text,
        "response_format": tts.default_format,
    });
    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("audio/speech request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("audio/speech HTTP {status}: {body}"));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("audio body read failed: {e}"))?;

    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join(format!(
        "microclaw_reply_{}.{}",
        uuid::Uuid::new_v4(),
        tts.default_format
    ));
    tokio::fs::write(&path, &bytes)
        .await
        .map_err(|e| format!("failed to write temp audio: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_requires_both_flags() {
        let mut cfg = Config::test_defaults();
        // Default state: TTS disabled and round_trip false → gate is closed.
        assert!(!round_trip_enabled(&cfg));

        cfg.voice_round_trip = true;
        // Round-trip on but TTS still disabled → gate stays closed; we never
        // want to surprise an operator who hasn't opted into TTS billing.
        assert!(!round_trip_enabled(&cfg));

        cfg.media.tts.enabled = true;
        // Both flags on → gate opens.
        assert!(round_trip_enabled(&cfg));
    }

    #[test]
    fn synth_returns_err_when_round_trip_disabled() {
        let cfg = Config::test_defaults();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(synth_speech_to_temp(&cfg, "hi"))
            .expect_err("should refuse when disabled");
        assert!(err.contains("disabled"));
    }

    #[test]
    fn format_voice_inbound_uses_brackets_so_agent_can_distinguish() {
        let s = format_voice_inbound("alice", "ship the patch");
        assert_eq!(s, "[voice message from alice]: ship the patch");
    }
}
