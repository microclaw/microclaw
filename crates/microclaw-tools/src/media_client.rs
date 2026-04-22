//! Shared HTTP helpers for multimedia tools (image gen / vision / TTS / STT).
//!
//! All four tools hit OpenAI-compatible endpoints and share:
//! - API-key secrecy (never logged, never echoed back)
//! - SSRF pre-flight via `crate::url_safety::check_url_private_ip`
//! - Configurable timeout + bounded redirect policy
//! - Minimal request envelope (Bearer auth, JSON or multipart body)

use std::path::PathBuf;
use std::time::Duration;

use reqwest::{Client, Url};

use crate::url_safety::check_url_private_ip;

/// Runtime handle that media tools share: resolved base URL, API key, and
/// HTTP client with a consistent timeout.
pub struct MediaClient {
    base_url: String,
    api_key: String,
    client: Client,
}

impl MediaClient {
    pub fn new(base_url: String, api_key: String, timeout_secs: u64) -> Result<Self, String> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(format!(
                "invalid media base_url '{base_url}' (must be http:// or https://)"
            ));
        }
        // Guard the configured base URL itself — prevents an operator from
        // (accidentally or maliciously) pointing multimedia traffic at
        // internal metadata / localhost.
        let parsed = Url::parse(&base_url).map_err(|e| format!("invalid base_url: {e}"))?;
        check_url_private_ip(&parsed)?;

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs.max(5)))
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("MicroClaw-media/1.0")
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
        Ok(Self {
            base_url,
            api_key,
            client,
        })
    }

    pub fn endpoint(&self, path: &str) -> String {
        let trimmed = path.trim_start_matches('/');
        format!("{}/{}", self.base_url, trimmed)
    }

    pub fn post_json(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .post(self.endpoint(path))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .header(reqwest::header::ACCEPT, "application/json")
    }

    pub fn post_multipart(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
    ) -> reqwest::RequestBuilder {
        self.client
            .post(self.endpoint(path))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .multipart(form)
    }

    fn bearer(&self) -> String {
        // Kept as a method rather than cached to make leak-by-debug less likely:
        // `Debug for MediaClient` won't print this value.
        format!("Bearer {}", self.api_key)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl std::fmt::Debug for MediaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the API key via Debug.
        f.debug_struct("MediaClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

/// Resolve a "location" (absolute URL, file path, or `data:` URI) into
/// bytes + optional mime-type. Applies SSRF check when fetching over HTTP.
pub async fn load_bytes_from_location(
    client: &Client,
    location: &str,
    working_dir: &std::path::Path,
) -> Result<(Vec<u8>, Option<String>), String> {
    if let Some(stripped) = location.strip_prefix("data:") {
        return parse_data_uri(stripped);
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        let parsed = Url::parse(location).map_err(|e| format!("invalid URL: {e}"))?;
        check_url_private_ip(&parsed)?;
        let resp = client
            .get(parsed)
            .send()
            .await
            .map_err(|e| format!("download failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("download HTTP {}", resp.status()));
        }
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("body read failed: {e}"))?;
        return Ok((bytes.to_vec(), mime));
    }
    // File path: must be inside working_dir (reuse existing path guard).
    let canonical = resolve_and_guard_path(location, working_dir)?;
    let bytes = std::fs::read(&canonical).map_err(|e| format!("read failed: {e}"))?;
    let mime = guess_mime_from_extension(&canonical);
    Ok((bytes, mime))
}

fn parse_data_uri(rest: &str) -> Result<(Vec<u8>, Option<String>), String> {
    // data:[<mediatype>][;base64],<data>
    let (meta, data) = rest
        .split_once(',')
        .ok_or_else(|| "malformed data: URI".to_string())?;
    let is_b64 = meta.contains(";base64");
    let mime = {
        let first = meta.split(';').next().unwrap_or("").trim();
        if first.is_empty() {
            None
        } else {
            Some(first.to_string())
        }
    };
    let bytes = if is_b64 {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(data.trim())
            .map_err(|e| format!("invalid base64 in data URI: {e}"))?
    } else {
        data.as_bytes().to_vec()
    };
    Ok((bytes, mime))
}

fn resolve_and_guard_path(path: &str, working_dir: &std::path::Path) -> Result<PathBuf, String> {
    let p = std::path::Path::new(path);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        working_dir.join(p)
    };
    let canonical = std::fs::canonicalize(&joined)
        .map_err(|e| format!("cannot resolve {}: {e}", joined.display()))?;
    let wd_canonical = std::fs::canonicalize(working_dir)
        .map_err(|e| format!("cannot resolve working_dir: {e}"))?;
    if !canonical.starts_with(&wd_canonical) {
        return Err(format!(
            "path {} is outside working_dir",
            canonical.display()
        ));
    }
    if crate::path_guard::is_blocked(&canonical) {
        return Err(format!(
            "access denied: {} is a sensitive path",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn guess_mime_from_extension(path: &std::path::Path) -> Option<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    Some(
        match ext.as_deref()? {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "webp" => "image/webp",
            "gif" => "image/gif",
            "mp3" => "audio/mpeg",
            "m4a" => "audio/mp4",
            "mp4" => "audio/mp4",
            "ogg" | "oga" => "audio/ogg",
            "opus" => "audio/opus",
            "wav" => "audio/wav",
            "flac" => "audio/flac",
            "webm" => "audio/webm",
            _ => return None,
        }
        .to_string(),
    )
}

/// Save bytes to `<data_dir>/media/<subdir>/<uuid>.<ext>` and return the
/// absolute path. Creates the parent directory as needed.
pub fn persist_output(
    data_dir: &std::path::Path,
    subdir: &str,
    extension: &str,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    let dir = data_dir.join("media").join(subdir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir failed: {e}"))?;
    let file_name = format!("{}.{}", uuid::Uuid::new_v4(), extension);
    let path = dir.join(file_name);
    std::fs::write(&path, bytes).map_err(|e| format!("write failed: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_api_key() {
        let mc = MediaClient::new("https://api.openai.com/v1".into(), "sk-secret".into(), 30)
            .unwrap();
        let dbg = format!("{mc:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("sk-secret"));
    }

    #[test]
    fn rejects_loopback_base_url() {
        let err = MediaClient::new("http://127.0.0.1/v1".into(), "k".into(), 30).unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn parses_base64_data_uri() {
        let out = parse_data_uri("image/png;base64,aGVsbG8=").unwrap();
        assert_eq!(out.0, b"hello");
        assert_eq!(out.1.as_deref(), Some("image/png"));
    }

    #[test]
    fn parses_plain_data_uri() {
        let out = parse_data_uri(",hello").unwrap();
        assert_eq!(out.0, b"hello");
    }

    #[test]
    fn guesses_mime_from_extension() {
        assert_eq!(
            guess_mime_from_extension(std::path::Path::new("foo.png")).as_deref(),
            Some("image/png")
        );
        assert_eq!(
            guess_mime_from_extension(std::path::Path::new("foo.mp3")).as_deref(),
            Some("audio/mpeg")
        );
        assert_eq!(
            guess_mime_from_extension(std::path::Path::new("foo.txt")),
            None
        );
    }
}
