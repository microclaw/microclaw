//! Shared voice/audio inbound transcription used by channel adapters.
//!
//! Each platform exposes audio bytes differently (Telegram voice, Discord
//! attachment, Slack file, Feishu audio message), but once we have raw bytes
//! the dispatch into the configured STT provider — OpenAI Whisper or a local
//! command — is the same. This module owns that dispatch and the format used
//! when injecting transcription into the inbound text the agent sees.

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
