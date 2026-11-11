use base64::Engine;
use serde::Deserialize;
use std::path::{Path, PathBuf};

use microclaw_core::error::MicroClawError;

pub const OPENAI_CODEX_PROVIDER: &str = "openai-codex";
pub const QWEN_PORTAL_PROVIDER: &str = "qwen-portal";

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

#[derive(Debug, Deserialize)]
struct QwenOauthCredsFile {
    access_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CodexAuthResolved {
    pub bearer_token: String,
    pub account_id: Option<String>,
}

pub fn provider_allows_empty_api_key(provider: &str) -> bool {
    provider.eq_ignore_ascii_case("ollama")
        || provider.eq_ignore_ascii_case(OPENAI_CODEX_PROVIDER)
        || provider.eq_ignore_ascii_case(QWEN_PORTAL_PROVIDER)
}

pub fn is_openai_codex_provider(provider: &str) -> bool {
    provider.eq_ignore_ascii_case(OPENAI_CODEX_PROVIDER)
}

pub fn is_qwen_portal_provider(provider: &str) -> bool {
    provider.eq_ignore_ascii_case(QWEN_PORTAL_PROVIDER)
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

pub fn default_qwen_oauth_creds_path() -> PathBuf {
    let base = std::env::var("QWEN_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .as_deref()
        .map(expand_tilde)
        .unwrap_or_else(|| expand_tilde("~/.qwen"));
    Path::new(&base).join("oauth_creds.json")
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

pub fn qwen_oauth_file_has_access_token() -> Result<bool, MicroClawError> {
    if let Ok(token) = std::env::var("QWEN_PORTAL_ACCESS_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(true);
        }
    }
    if let Ok(token) = std::env::var("QWEN_CODE_ACCESS_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(true);
        }
    }
    let path = default_qwen_oauth_creds_path();
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to read Qwen oauth creds file {}: {e}",
            path.display()
        ))
    })?;
    let parsed: QwenOauthCredsFile = serde_json::from_str(&content).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse Qwen oauth creds file {}: {e}",
            path.display()
        ))
    })?;
    Ok(parsed
        .access_token
        .as_ref()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false))
}

pub fn resolve_qwen_portal_auth(
    fallback_api_key: &str,
) -> Result<CodexAuthResolved, MicroClawError> {
    if let Ok(token) = std::env::var("QWEN_PORTAL_ACCESS_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(CodexAuthResolved {
                bearer_token: trimmed.to_string(),
                account_id: None,
            });
        }
    }
    if let Ok(token) = std::env::var("QWEN_CODE_ACCESS_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(CodexAuthResolved {
                bearer_token: trimmed.to_string(),
                account_id: None,
            });
        }
    }
    let path = default_qwen_oauth_creds_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            MicroClawError::Config(format!(
                "Failed to read Qwen oauth creds file {}: {e}",
                path.display()
            ))
        })?;
        let parsed: QwenOauthCredsFile = serde_json::from_str(&content).map_err(|e| {
            MicroClawError::Config(format!(
                "Failed to parse Qwen oauth creds file {}: {e}",
                path.display()
            ))
        })?;
        if let Some(token) = parsed
            .access_token
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return Ok(CodexAuthResolved {
                bearer_token: token.to_string(),
                account_id: None,
            });
        }
    }
    let fallback = fallback_api_key.trim();
    if !fallback.is_empty() {
        return Ok(CodexAuthResolved {
            bearer_token: fallback.to_string(),
            account_id: None,
        });
    }
    Err(MicroClawError::Config(
        "qwen-portal requires ~/.qwen/oauth_creds.json (access_token), or QWEN_PORTAL_ACCESS_TOKEN, or api_key.".into(),
    ))
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
    id_token: Option<String>,
}

/// OpenAI's OAuth token endpoint, used by `codex login`.
pub(crate) const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
/// The OAuth client id of the Codex CLI.
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// Refresh the access token this long before it expires, so a request never
/// leaves with a token that runs out on the way.
const CODEX_REFRESH_MARGIN_SECS: i64 = 300;

/// The OAuth tokens in a Codex auth file, if it has both.
fn codex_oauth_tokens(parsed: &serde_json::Value) -> Option<(String, String)> {
    let tokens = parsed.get("tokens")?.as_object()?;
    let field = |name: &str| {
        tokens
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    Some((field("access_token")?, field("refresh_token")?))
}

fn codex_refresh_body(refresh_token: &str) -> serde_json::Value {
    serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CODEX_CLIENT_ID,
    })
}

/// Write a refresh response into the parsed auth file. Returns false when the
/// response carries no access token.
fn apply_codex_refresh(parsed: &mut serde_json::Value, resp: CodexRefreshResponse) -> bool {
    if resp.access_token.trim().is_empty() {
        return false;
    }
    let Some(tokens) = parsed.get_mut("tokens").and_then(|t| t.as_object_mut()) else {
        return false;
    };
    tokens.insert(
        "access_token".to_string(),
        serde_json::Value::String(resp.access_token),
    );
    for (name, value) in [
        ("refresh_token", resp.refresh_token),
        ("id_token", resp.id_token),
    ] {
        if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
            tokens.insert(name.to_string(), serde_json::Value::String(value));
        }
    }
    parsed["last_refresh"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());
    true
}

fn read_codex_auth_value(path: &Path) -> Result<serde_json::Value, MicroClawError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to read Codex auth file {}: {e}",
            path.display()
        ))
    })?;
    serde_json::from_str(&content).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse Codex auth file {}: {e}",
            path.display()
        ))
    })
}

/// `std::fs::write` keeps the existing file's mode (Codex creates it 0600).
fn write_codex_auth_value(path: &Path, parsed: &serde_json::Value) -> Result<(), MicroClawError> {
    let text = serde_json::to_string_pretty(parsed).map_err(|e| {
        MicroClawError::Config(format!("Failed to serialize refreshed Codex auth: {e}"))
    })?;
    std::fs::write(path, text)?;
    Ok(())
}

/// Refreshes an expired Codex access token in `~/.codex/auth.json`.
///
/// Blocking: it uses `reqwest::blocking`, so never call it from async code
/// (the client panics when dropped inside a Tokio runtime). Providers use
/// [`openai_codex_auth_for_request`], which refreshes before every request.
pub fn refresh_openai_codex_auth_if_needed() -> Result<(), MicroClawError> {
    let auth_path = default_codex_auth_path();
    if !auth_path.exists() {
        return Ok(());
    }
    let mut parsed = read_codex_auth_value(&auth_path)?;
    let Some((access, refresh)) = codex_oauth_tokens(&parsed) else {
        return Ok(());
    };
    if !jwt_expires_within(&access, 0) {
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client
        .post(CODEX_TOKEN_URL)
        .header("content-type", "application/json")
        .body(codex_refresh_body(&refresh).to_string())
        .send()?;
    if !resp.status().is_success() {
        return Ok(());
    }
    let parsed_resp: CodexRefreshResponse = resp.json().map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse OpenAI Codex refresh response: {e}"
        ))
    })?;
    if apply_codex_refresh(&mut parsed, parsed_resp) {
        write_codex_auth_value(&auth_path, &parsed)?;
    }
    Ok(())
}

/// One refresh at a time: OpenAI rotates refresh tokens, so two concurrent
/// refreshes with the same token would make the second one fail.
fn codex_refresh_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Refreshes the OAuth access token in the Codex auth file at `path` when it
/// expires within [`CODEX_REFRESH_MARGIN_SECS`], or when the server rejected
/// it (`rejected` is the token that was sent). If the file already holds a
/// different token than the rejected one, someone else refreshed it and
/// nothing is done. Returns whether the file was refreshed.
pub(crate) async fn refresh_codex_auth_file(
    http: &reqwest::Client,
    token_url: &str,
    path: &Path,
    rejected: Option<&str>,
) -> Result<bool, MicroClawError> {
    let _guard = codex_refresh_lock().lock().await;
    if !path.exists() {
        return Ok(false);
    }
    let mut parsed = read_codex_auth_value(path)?;
    let Some((access, refresh)) = codex_oauth_tokens(&parsed) else {
        return Ok(false);
    };
    let needed = match rejected.map(str::trim) {
        Some(rejected) => rejected == access,
        None => jwt_expires_within(&access, CODEX_REFRESH_MARGIN_SECS),
    };
    if !needed {
        return Ok(false);
    }

    let resp = http
        .post(token_url)
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .body(codex_refresh_body(&refresh).to_string())
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(MicroClawError::Config(format!(
            "OpenAI Codex token refresh failed (HTTP {status}): {}; run `codex login` again",
            text.chars().take(300).collect::<String>()
        )));
    }
    let parsed_resp: CodexRefreshResponse = resp.json().await.map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to parse OpenAI Codex refresh response: {e}"
        ))
    })?;
    if !apply_codex_refresh(&mut parsed, parsed_resp) {
        return Ok(false);
    }
    write_codex_auth_value(path, &parsed)?;
    Ok(true)
}

/// The Codex credentials for one request. Reads the auth file every time, so
/// a token refreshed by the Codex CLI is picked up too, and refreshes the
/// OAuth token first when it is about to expire or `rejected` (the token the
/// server just turned down) is still the current one. Refresh errors are
/// logged, not returned: the current token is still worth a try.
/// `OPENAI_CODEX_ACCESS_TOKEN` is used as is and never refreshed.
pub async fn openai_codex_auth_for_request(
    http: &reqwest::Client,
    rejected: Option<&str>,
) -> Result<CodexAuthResolved, MicroClawError> {
    let env_token = std::env::var("OPENAI_CODEX_ACCESS_TOKEN")
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false);
    if !env_token {
        let path = default_codex_auth_path();
        match refresh_codex_auth_file(http, &codex_token_url(), &path, rejected).await {
            Ok(true) => tracing::info!("Refreshed the OpenAI Codex access token"),
            Ok(false) => {}
            Err(e) => tracing::warn!("{e}"),
        }
    }
    resolve_openai_codex_auth("")
}

#[cfg(not(test))]
fn codex_token_url() -> String {
    CODEX_TOKEN_URL.to_string()
}

#[cfg(test)]
pub(crate) static TEST_CODEX_TOKEN_URL: std::sync::Mutex<Option<String>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn codex_token_url() -> String {
    TEST_CODEX_TOKEN_URL
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:9/never-called".to_string())
}

/// Whether the JWT's `exp` claim is less than `secs` seconds away (or past).
/// A token without a readable `exp` never counts as expiring.
fn jwt_expires_within(token: &str, secs: i64) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let payload = parts[1].trim_end_matches('=');
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let exp = decoded
        .as_ref()
        .and_then(|v| v.get("exp"))
        .and_then(|v| v.as_i64());
    match exp {
        Some(ts) => chrono::Utc::now().timestamp() + secs >= ts,
        None => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    #[test]
    fn test_provider_allows_empty_api_key() {
        assert!(provider_allows_empty_api_key("ollama"));
        assert!(provider_allows_empty_api_key("openai-codex"));
        assert!(provider_allows_empty_api_key("qwen-portal"));
        assert!(!provider_allows_empty_api_key("openai"));
    }

    #[test]
    fn test_is_openai_codex_provider() {
        assert!(is_openai_codex_provider("openai-codex"));
        assert!(is_openai_codex_provider("OPENAI-CODEX"));
        assert!(!is_openai_codex_provider("openai"));
    }

    #[test]
    fn test_is_qwen_portal_provider() {
        assert!(is_qwen_portal_provider("qwen-portal"));
        assert!(is_qwen_portal_provider("QWEN-PORTAL"));
        assert!(!is_qwen_portal_provider("qwen"));
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

    #[test]
    fn test_qwen_oauth_file_has_access_token() {
        let _guard = env_lock();
        let prev_qwen_home = std::env::var("QWEN_HOME").ok();
        let prev_qwen_access = std::env::var("QWEN_PORTAL_ACCESS_TOKEN").ok();
        std::env::remove_var("QWEN_PORTAL_ACCESS_TOKEN");
        let qwen_dir = std::env::temp_dir().join(format!(
            "microclaw-qwen-oauth-creds-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&qwen_dir).unwrap();
        std::fs::write(
            qwen_dir.join("oauth_creds.json"),
            r#"{"access_token":"qwen-oauth-token"}"#,
        )
        .unwrap();
        std::env::set_var("QWEN_HOME", &qwen_dir);

        let has = qwen_oauth_file_has_access_token().unwrap();

        if let Some(prev) = prev_qwen_home {
            std::env::set_var("QWEN_HOME", prev);
        } else {
            std::env::remove_var("QWEN_HOME");
        }
        if let Some(prev) = prev_qwen_access {
            std::env::set_var("QWEN_PORTAL_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("QWEN_PORTAL_ACCESS_TOKEN");
        }
        let _ = std::fs::remove_file(qwen_dir.join("oauth_creds.json"));
        let _ = std::fs::remove_dir(qwen_dir);

        assert!(has);
    }

    #[test]
    fn test_resolve_qwen_portal_auth_reads_oauth_creds_file() {
        let _guard = env_lock();
        let prev_qwen_home = std::env::var("QWEN_HOME").ok();
        let prev_qwen_access = std::env::var("QWEN_PORTAL_ACCESS_TOKEN").ok();
        std::env::remove_var("QWEN_PORTAL_ACCESS_TOKEN");

        let qwen_dir = std::env::temp_dir().join(format!(
            "microclaw-qwen-oauth-resolve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&qwen_dir).unwrap();
        std::fs::write(
            qwen_dir.join("oauth_creds.json"),
            r#"{"access_token":"qwen-oauth-token"}"#,
        )
        .unwrap();
        std::env::set_var("QWEN_HOME", &qwen_dir);

        let auth = resolve_qwen_portal_auth("").unwrap();

        if let Some(prev) = prev_qwen_home {
            std::env::set_var("QWEN_HOME", prev);
        } else {
            std::env::remove_var("QWEN_HOME");
        }
        if let Some(prev) = prev_qwen_access {
            std::env::set_var("QWEN_PORTAL_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("QWEN_PORTAL_ACCESS_TOKEN");
        }
        let _ = std::fs::remove_file(qwen_dir.join("oauth_creds.json"));
        let _ = std::fs::remove_dir(qwen_dir);

        assert_eq!(auth.bearer_token, "qwen-oauth-token");
        assert!(auth.account_id.is_none());
    }

    pub(crate) fn fake_jwt(exp: i64) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "exp": exp }).to_string());
        format!("eyJhbGciOiJub25lIn0.{payload}.sig")
    }

    /// Serves one canned HTTP response per connection, in order, and sends
    /// back each request's text.
    pub(crate) fn serve_responses(
        responses: Vec<(u16, String)>,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&req);
                    if let Some(head_end) = text.find("\r\n\r\n") {
                        let len = text[..head_end]
                            .lines()
                            .find_map(|l| {
                                let lower = l.to_ascii_lowercase();
                                lower
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if req.len() >= head_end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&req).to_string());
                let reason = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://{addr}"), rx)
    }

    fn write_auth(dir: &Path, access: &str) -> PathBuf {
        let path = dir.join("auth.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "tokens": {
                    "access_token": access,
                    "refresh_token": "refresh-1",
                    "account_id": "acct-1",
                },
                "OPENAI_API_KEY": null,
            })
            .to_string(),
        )
        .unwrap();
        path
    }

    fn read_tokens(path: &Path) -> serde_json::Value {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["tokens"].clone()
    }

    #[test]
    fn test_jwt_expires_within() {
        let now = chrono::Utc::now().timestamp();
        assert!(jwt_expires_within(&fake_jwt(now - 10), 0));
        assert!(jwt_expires_within(&fake_jwt(now + 60), 300));
        assert!(!jwt_expires_within(&fake_jwt(now + 3600), 300));
        assert!(!jwt_expires_within("not-a-jwt", 300));
        // Padded payloads (as some encoders emit) still parse.
        let padded = base64::engine::general_purpose::URL_SAFE
            .encode(serde_json::json!({ "exp": now - 1 }).to_string());
        assert!(jwt_expires_within(&format!("h.{padded}.s"), 0));
    }

    #[tokio::test]
    async fn test_refresh_codex_auth_file_refreshes_expiring_token() {
        let dir = tempfile::tempdir().unwrap();
        let old = fake_jwt(chrono::Utc::now().timestamp() + 60);
        let path = write_auth(dir.path(), &old);
        let (url, requests) = serve_responses(vec![(
            200,
            r#"{"access_token":"new-access","refresh_token":"refresh-2","id_token":"id-2"}"#.into(),
        )]);
        let http = reqwest::Client::new();
        let refreshed = refresh_codex_auth_file(&http, &format!("{url}/oauth/token"), &path, None)
            .await
            .unwrap();
        assert!(refreshed);
        let req = requests.recv().unwrap();
        assert!(req.starts_with("POST /oauth/token"));
        assert!(req.contains(r#""refresh_token":"refresh-1""#));
        assert!(req.contains(CODEX_CLIENT_ID));
        let tokens = read_tokens(&path);
        assert_eq!(tokens["access_token"], "new-access");
        assert_eq!(tokens["refresh_token"], "refresh-2");
        assert_eq!(tokens["id_token"], "id-2");
        assert_eq!(tokens["account_id"], "acct-1");
    }

    #[tokio::test]
    async fn test_refresh_codex_auth_file_keeps_fresh_token() {
        let dir = tempfile::tempdir().unwrap();
        let fresh = fake_jwt(chrono::Utc::now().timestamp() + 3600);
        let path = write_auth(dir.path(), &fresh);
        let http = reqwest::Client::new();
        let refreshed =
            refresh_codex_auth_file(&http, "http://127.0.0.1:9/never-called", &path, None)
                .await
                .unwrap();
        assert!(!refreshed);
        assert_eq!(read_tokens(&path)["access_token"], fresh.as_str());
    }

    #[tokio::test]
    async fn test_refresh_codex_auth_file_refreshes_rejected_token() {
        let dir = tempfile::tempdir().unwrap();
        let fresh = fake_jwt(chrono::Utc::now().timestamp() + 3600);
        let path = write_auth(dir.path(), &fresh);
        let (url, _requests) =
            serve_responses(vec![(200, r#"{"access_token":"new-access"}"#.into())]);
        let http = reqwest::Client::new();
        let refreshed = refresh_codex_auth_file(&http, &url, &path, Some(&fresh))
            .await
            .unwrap();
        assert!(refreshed);
        let tokens = read_tokens(&path);
        assert_eq!(tokens["access_token"], "new-access");
        assert_eq!(tokens["refresh_token"], "refresh-1");
    }

    #[tokio::test]
    async fn test_refresh_codex_auth_file_skips_when_already_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let current = fake_jwt(chrono::Utc::now().timestamp() + 3600);
        let path = write_auth(dir.path(), &current);
        let http = reqwest::Client::new();
        let refreshed = refresh_codex_auth_file(
            &http,
            "http://127.0.0.1:9/never-called",
            &path,
            Some("an-older-token"),
        )
        .await
        .unwrap();
        assert!(!refreshed);
        assert_eq!(read_tokens(&path)["access_token"], current.as_str());
    }

    #[tokio::test]
    async fn test_refresh_codex_auth_file_reports_failed_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let old = fake_jwt(chrono::Utc::now().timestamp() - 10);
        let path = write_auth(dir.path(), &old);
        let (url, _requests) = serve_responses(vec![(400, r#"{"error":"invalid_grant"}"#.into())]);
        let http = reqwest::Client::new();
        let err = refresh_codex_auth_file(&http, &url, &path, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("codex login"));
        assert_eq!(read_tokens(&path)["access_token"], old.as_str());
    }
}
