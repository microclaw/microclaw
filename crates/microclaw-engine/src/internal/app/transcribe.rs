use reqwest::multipart;

pub async fn transcribe_audio(api_key: &str, audio_bytes: &[u8]) -> Result<String, String> {
    let client = reqwest::Client::new();

    let part = multipart::Part::bytes(audio_bytes.to_vec())
        .file_name("audio.ogg")
        .mime_str("audio/ogg")
        .map_err(|e| e.to_string())?;

    let form = multipart::Form::new()
        .text("model", "whisper-1")
        .part("file", part);

    let resp = client
        .post("https://api.openai.com/v1/audio/transcriptions")
        .header("Authorization", format!("Bearer {api_key}"))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Whisper API request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Whisper API error HTTP {status}: {body}"));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Whisper response: {e}"))?;

    body.get("text")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Whisper response missing 'text' field".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_transcribe_module_exists() {
        // Basic smoke test that the module compiles
    }
}
