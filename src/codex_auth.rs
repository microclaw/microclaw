use base64::Engine;
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::error::MicroClawError;

pub const OPENAI_CODEX_PROVIDER: &str = "openai-codex";

#[derive(Debug, Deserialize)]
struct CodexAuthFile {
    tokens: Option<CodexAuthTokens>,
    #[serde(rename = "OPENAI_API_KEY")]
    openai_api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CodexAuthTokens {
    access_token: Option<String>,
    #[serde(rename = "refresh_token")]
    _refresh_token: Option<String>,
    account_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CodexAuthResolved {
    pub bearer_token: String,
    pub account_id: Option<String>,
}

pub fn provider_allows_empty_api_key(provider: &str) -> bool {
    provider.eq_ignore_ascii_case("ollama") || provider.eq_ignore_ascii_case(OPENAI_CODEX_PROVIDER)
}

pub fn is_openai_codex_provider(provider: &str) -> bool {
    provider.eq_ignore_ascii_case(OPENAI_CODEX_PROVIDER)
}

pub fn default_codex_auth_path() -> PathBuf {
    let base = std::env::var("CODEX_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .as_deref()
        .map(expand_tilde)
        .unwrap_or_else(|| expand_tilde("~/.codex"));
    Path::new(&base).join("auth.json")
}

pub fn default_codex_config_path() -> PathBuf {
    let base = std::env::var("CODEX_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .as_deref()
        .map(expand_tilde)
        .unwrap_or_else(|| expand_tilde("~/.codex"));
    Path::new(&base).join("config.toml")
}

pub fn codex_auth_file_has_access_token() -> Result<bool, MicroClawError> {
    if let Ok(token) = std::env::var("OPENAI_CODEX_ACCESS_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(true);
        }
    }

    let path = default_codex_auth_path();
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to read Codex auth file {}: {e}",
            path.display()
        ))
    })?;
    let parsed: CodexAuthFile = serde_json::from_str(&content).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse Codex auth file {}: {e}",
            path.display()
        ))
    })?;
    let has_access_token = parsed
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.access_token.as_ref())
        .map(|token| !token.trim().is_empty())
        .unwrap_or(false);
    let has_openai_api_key = parsed
        .openai_api_key
        .as_ref()
        .map(|key| !key.trim().is_empty())
        .unwrap_or(false);
    Ok(has_access_token || has_openai_api_key)
}

pub fn resolve_openai_codex_auth(
    _fallback_api_key: &str,
) -> Result<CodexAuthResolved, MicroClawError> {
    if let Ok(token) = std::env::var("OPENAI_CODEX_ACCESS_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(CodexAuthResolved {
                bearer_token: trimmed.to_string(),
                account_id: None,
            });
        }
    }

    let auth_path = default_codex_auth_path();
    if auth_path.exists() {
        let content = std::fs::read_to_string(&auth_path).map_err(|e| {
            MicroClawError::Config(format!(
                "Failed to read Codex auth file {}: {e}",
                auth_path.display()
            ))
        })?;
        let parsed: CodexAuthFile = serde_json::from_str(&content).map_err(|e| {
            MicroClawError::Config(format!(
                "Failed to parse Codex auth file {}: {e}",
                auth_path.display()
            ))
        })?;
        if let Some(token) = parsed
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.as_ref())
            .map(|token| token.trim())
            .filter(|token| !token.is_empty())
        {
            return Ok(CodexAuthResolved {
                bearer_token: token.to_string(),
                account_id: parsed
                    .tokens
                    .as_ref()
                    .and_then(|tokens| tokens.account_id.clone())
                    .map(|id| id.trim().to_string())
                    .filter(|id| !id.is_empty()),
            });
        }

        if let Some(api_key) = parsed
            .openai_api_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())
        {
            return Ok(CodexAuthResolved {
                bearer_token: api_key.to_string(),
                account_id: None,
            });
        }
    }

    Err(MicroClawError::Config(format!(
        "OpenAI Codex provider requires ~/.codex/auth.json (access token or OPENAI_API_KEY), or OPENAI_CODEX_ACCESS_TOKEN. Run `codex login` or update Codex config files (expected auth file: {}).",
        auth_path.display()
    )))
}

pub fn codex_config_default_openai_base_url() -> Option<String> {
    let path = default_codex_config_path();
    let content = std::fs::read_to_string(path).ok()?;
    parse_codex_config_default_openai_base_url(&content)
}

fn parse_codex_config_default_openai_base_url(content: &str) -> Option<String> {
    let mut model_provider: Option<String> = None;

    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("model_provider") {
            model_provider = parse_toml_string_assignment(line, "model_provider");
            if model_provider.is_some() {
                break;
            }
        }
    }

    let provider = model_provider?;
    let target = provider.trim();
    if target.is_empty() {
        return None;
    }

    let mut current_provider: Option<String> = None;
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            current_provider = section
                .strip_prefix("model_providers.")
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty());
            continue;
        }

        if current_provider.as_deref() == Some(target) {
            if let Some(base_url) = parse_toml_string_assignment(line, "base_url") {
                let normalized = base_url.trim().trim_end_matches('/').to_string();
                if !normalized.is_empty() {
                    return Some(normalized);
                }
            }
        }
    }

    None
}

fn parse_toml_string_assignment(line: &str, key: &str) -> Option<String> {
    let (lhs, rhs) = line.split_once('=')?;
    if lhs.trim() != key {
        return None;
    }
    let value = rhs.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        return None;
    }
    Some(value[1..value.len() - 1].to_string())
}

fn expand_tilde(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    if input == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    input.to_string()
}

#[derive(Debug, Deserialize)]
struct CodexRefreshResponse {
    access_token: String,
    refresh_token: Option<String>,
}

pub fn refresh_openai_codex_auth_if_needed() -> Result<(), MicroClawError> {
    let auth_path = default_codex_auth_path();
    if !auth_path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&auth_path).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to read Codex auth file {}: {e}",
            auth_path.display()
        ))
    })?;
    let mut parsed: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse Codex auth file {}: {e}",
            auth_path.display()
        ))
    })?;

    let tokens = parsed
        .get("tokens")
        .and_then(|t| t.as_object())
        .cloned()
        .unwrap_or_default();
    let access = tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let refresh = tokens
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if access.is_empty() || refresh.is_empty() {
        return Ok(());
    }
    if !is_jwt_expired(&access) {
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
    });
    let resp = client
        .post("https://auth.openai.com/oauth/token")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()?;
    if !resp.status().is_success() {
        return Ok(());
    }
    let parsed_resp: CodexRefreshResponse = resp.json().map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse OpenAI Codex refresh response: {e}"
        ))
    })?;
    if parsed_resp.access_token.trim().is_empty() {
        return Ok(());
    }

    if let Some(tokens_obj) = parsed.get_mut("tokens").and_then(|t| t.as_object_mut()) {
        tokens_obj.insert(
            "access_token".to_string(),
            serde_json::Value::String(parsed_resp.access_token),
        );
        if let Some(refresh_token) = parsed_resp.refresh_token {
            if !refresh_token.trim().is_empty() {
                tokens_obj.insert(
                    "refresh_token".to_string(),
                    serde_json::Value::String(refresh_token),
                );
            }
        }
    }
    parsed["last_refresh"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());
    std::fs::write(
        &auth_path,
        serde_json::to_string_pretty(&parsed).map_err(|e| {
            MicroClawError::Config(format!("Failed to serialize refreshed Codex auth: {e}"))
        })?,
    )?;
    Ok(())
}

fn is_jwt_expired(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let mut payload = parts[1].to_string();
    while !payload.len().is_multiple_of(4) {
        payload.push('=');
    }
    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(payload.as_bytes())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let exp = decoded
        .as_ref()
        .and_then(|v| v.get("exp"))
        .and_then(|v| v.as_i64());
    match exp {
        Some(ts) => chrono::Utc::now().timestamp() >= ts,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    #[test]
    fn test_provider_allows_empty_api_key() {
        assert!(provider_allows_empty_api_key("ollama"));
        assert!(provider_allows_empty_api_key("openai-codex"));
        assert!(!provider_allows_empty_api_key("openai"));
    }

    #[test]
    fn test_is_openai_codex_provider() {
        assert!(is_openai_codex_provider("openai-codex"));
        assert!(is_openai_codex_provider("OPENAI-CODEX"));
        assert!(!is_openai_codex_provider("openai"));
    }

    #[test]
    fn test_codex_auth_file_has_access_token_accepts_env_var() {
        let _guard = env_lock();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", "env-token");

        let has = codex_auth_file_has_access_token().unwrap();

        if let Some(prev) = prev_access {
            std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");
        }
        assert!(has);
    }

    #[test]
    fn test_codex_auth_file_has_access_token_accepts_openai_api_key_only() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-openai-key-only-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(
            auth_dir.join("auth.json"),
            r#"{"OPENAI_API_KEY":"sk-user-stale"}"#,
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let has = codex_auth_file_has_access_token().unwrap();

        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        if let Some(prev) = prev_access {
            std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");
        }
        let _ = std::fs::remove_file(auth_dir.join("auth.json"));
        let _ = std::fs::remove_dir(auth_dir);

        assert!(has);
    }

    #[test]
    fn test_resolve_openai_codex_auth_accepts_openai_api_key_only() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-openai-key-reject-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(
            auth_dir.join("auth.json"),
            r#"{"OPENAI_API_KEY":"sk-user-stale"}"#,
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let auth = resolve_openai_codex_auth("").unwrap();

        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        if let Some(prev) = prev_access {
            std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");
        }
        let _ = std::fs::remove_file(auth_dir.join("auth.json"));
        let _ = std::fs::remove_dir(auth_dir);

        assert_eq!(auth.bearer_token, "sk-user-stale");
        assert!(auth.account_id.is_none());
    }

    #[test]
    fn test_parse_codex_config_default_openai_base_url() {
        let content = r#"
model_provider = "tabcode"

[model_providers.tabcode]
name = "openai"
base_url = "https://api.tabcode.cc/openai"
wire_api = "responses"
"#;
        let base = parse_codex_config_default_openai_base_url(content).unwrap();
        assert_eq!(base, "https://api.tabcode.cc/openai");
    }
}
