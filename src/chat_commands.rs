use std::sync::Arc;

use crate::agent_engine::archive_conversation;
use crate::config::{Config, ResolvedLlmProviderProfile};
use crate::runtime::AppState;
use microclaw_core::llm_types::Message;
use microclaw_storage::db::{call_blocking, Database};
use microclaw_storage::usage::build_usage_report;
use serde::Deserialize;

pub fn is_slash_command(text: &str) -> bool {
    text.trim_start().starts_with('/')
}

pub fn unknown_command_response() -> String {
    "Unknown command.".to_string()
}

pub async fn handle_chat_command(
    state: &AppState,
    chat_id: i64,
    caller_channel: &str,
    command_text: &str,
) -> Option<String> {
    let trimmed = command_text.trim();

    if trimmed == "/reset" {
        let _ = call_blocking(state.db.clone(), move |db| db.clear_chat_context(chat_id)).await;
        return Some("Context cleared (session + chat history).".to_string());
    }

    if trimmed == "/skills" {
        return Some(state.skills.list_skills_formatted());
    }

    if trimmed == "/reload-skills" {
        let count = state.skills.reload().len();
        return Some(format!("Reloaded {count} skills from disk."));
    }

    if trimmed == "/archive" {
        if let Ok(Some((json, _))) =
            call_blocking(state.db.clone(), move |db| db.load_session(chat_id)).await
        {
            let messages: Vec<Message> = serde_json::from_str(&json).unwrap_or_default();
            if messages.is_empty() {
                return Some("No session to archive.".to_string());
            }
            archive_conversation(&state.config.data_dir, caller_channel, chat_id, &messages);
            return Some(format!("Archived {} messages.", messages.len()));
        }
        return Some("No session to archive.".to_string());
    }

    if trimmed == "/usage" {
        let text = match build_usage_report(state.db.clone(), chat_id).await {
            Ok(v) => v,
            Err(e) => format!("Failed to query usage statistics: {e}"),
        };
        return Some(text);
    }

    if trimmed == "/status" {
        return Some(
            build_status_response(
                state.db.clone(),
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                chat_id,
                caller_channel,
            )
            .await,
        );
    }

    if trimmed == "/providers" {
        return Some(
            build_providers_response(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
            )
            .await,
        );
    }

    if trimmed == "/provider" || trimmed.starts_with("/provider ") {
        return Some(
            build_provider_response(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
                trimmed,
            )
            .await,
        );
    }

    if trimmed == "/models" || trimmed.starts_with("/models ") {
        return Some(
            build_models_response(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
                trimmed,
            )
            .await,
        );
    }

    if trimmed == "/model" || trimmed.starts_with("/model ") {
        return Some(
            build_model_response(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
                chat_id,
                trimmed,
            )
            .await,
        );
    }

    None
}

pub async fn build_status_response(
    db: Arc<Database>,
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    chat_id: i64,
    caller_channel: &str,
) -> String {
    let (profile, model) = resolve_effective_provider_and_model(
        config,
        &llm_provider_overrides,
        &llm_model_overrides,
        caller_channel,
    )
    .await;
    let provider = profile.alias.clone();

    let session_line = match call_blocking(db.clone(), move |db| db.load_session(chat_id)).await {
        Ok(Some((json, updated_at))) => {
            let messages: Vec<Message> = serde_json::from_str(&json).unwrap_or_default();
            format!(
                "Session: active ({} messages, updated at {})",
                messages.len(),
                updated_at
            )
        }
        Ok(None) => "Session: empty".to_string(),
        Err(e) => format!("Session: unavailable ({e})"),
    };

    let task_line = match call_blocking(db.clone(), move |db| db.get_tasks_for_chat(chat_id)).await
    {
        Ok(tasks) => {
            let mut active = 0usize;
            let mut paused = 0usize;
            let mut completed = 0usize;
            let mut cancelled = 0usize;
            let mut other = 0usize;

            for task in tasks {
                match task.status.as_str() {
                    "active" => active += 1,
                    "paused" => paused += 1,
                    "completed" => completed += 1,
                    "cancelled" => cancelled += 1,
                    _ => other += 1,
                }
            }

            let total = active + paused + completed + cancelled + other;
            if other == 0 {
                format!(
                    "Scheduled tasks: total={total}, active={active}, paused={paused}, completed={completed}, cancelled={cancelled}"
                )
            } else {
                format!(
                    "Scheduled tasks: total={total}, active={active}, paused={paused}, completed={completed}, cancelled={cancelled}, other={other}"
                )
            }
        }
        Err(e) => format!("Scheduled tasks: unavailable ({e})"),
    };

    format!(
        "Status\nChannel: {caller_channel}\nProvider: {provider}\nModel: {model}\n{session_line}\n{task_line}"
    )
}

pub async fn build_model_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    _chat_id: i64,
    command_text: &str,
) -> String {
    let caller_channel = caller_channel.to_string();
    let requested = command_text
        .trim()
        .strip_prefix("/model")
        .map(str::trim)
        .unwrap_or("");
    let (profile, current_model) = resolve_effective_provider_and_model(
        config,
        &llm_provider_overrides,
        &llm_model_overrides,
        &caller_channel,
    )
    .await;
    let provider = profile.alias.clone();

    if requested.is_empty() {
        return format!("Current provider/model: {provider} / {current_model}");
    }

    if requested.eq_ignore_ascii_case("reset") || requested.eq_ignore_ascii_case("default") {
        let mut overrides = llm_model_overrides.write().await;
        overrides.remove(&caller_channel);
        return format!(
            "Model override cleared. Current provider/model: {provider} / {}",
            profile.default_model
        );
    }

    let mut allowed_models = profile.models.clone();
    if is_placeholder_model_list(&allowed_models) {
        if let Ok(live) = fetch_models_from_provider_api(&profile).await {
            if !live.is_empty() {
                allowed_models = live;
            }
        }
    }
    if !allowed_models.is_empty() && !allowed_models.iter().any(|m| m == requested) {
        return format!(
            "Model '{requested}' is not configured for provider '{provider}'. Available: {}",
            allowed_models.join(", ")
        );
    }

    let mut overrides = llm_model_overrides.write().await;
    overrides.insert(caller_channel.clone(), requested.to_string());
    format!("Model switched for this channel to: {provider} / {requested}")
}

pub async fn build_providers_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
) -> String {
    let (active_profile, active_model) = resolve_effective_provider_and_model(
        config,
        &llm_provider_overrides,
        &llm_model_overrides,
        caller_channel,
    )
    .await;
    let mut lines = vec!["Configured providers:".to_string()];
    for profile in config.list_llm_provider_profiles() {
        let marker = if profile.alias == active_profile.alias {
            " (active)"
        } else {
            ""
        };
        lines.push(format!(
            "- {}{} -> backend={}, default_model={}",
            profile.alias, marker, profile.provider, profile.default_model
        ));
    }
    lines.push(format!(
        "Current provider/model: {} / {}",
        active_profile.alias, active_model
    ));
    lines.join("\n")
}

pub async fn build_provider_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    command_text: &str,
) -> String {
    let requested = command_text
        .trim()
        .strip_prefix("/provider")
        .map(str::trim)
        .unwrap_or("");
    if requested.is_empty() {
        let (profile, model) = resolve_effective_provider_and_model(
            config,
            &llm_provider_overrides,
            &llm_model_overrides,
            caller_channel,
        )
        .await;
        return format!(
            "Current provider/model: {} / {} (backend={})",
            profile.alias, model, profile.provider
        );
    }

    if requested.eq_ignore_ascii_case("reset") || requested.eq_ignore_ascii_case("default") {
        {
            let mut provider_overrides = llm_provider_overrides.write().await;
            provider_overrides.remove(caller_channel);
        }
        {
            let mut model_overrides = llm_model_overrides.write().await;
            model_overrides.remove(caller_channel);
        }
        let profile = config
            .resolve_llm_provider_profile(&config.llm_provider)
            .expect("default provider should resolve");
        return format!(
            "Provider override cleared. Current provider/model: {} / {}",
            profile.alias, profile.default_model
        );
    }

    let requested_alias = requested.to_ascii_lowercase();
    let Some(profile) = config.resolve_llm_provider_profile(&requested_alias) else {
        let names = config
            .list_llm_provider_profiles()
            .into_iter()
            .map(|p| p.alias)
            .collect::<Vec<_>>()
            .join(", ");
        return format!("Unknown provider '{requested}'. Available providers: {names}");
    };
    {
        let mut provider_overrides = llm_provider_overrides.write().await;
        provider_overrides.insert(caller_channel.to_string(), profile.alias.clone());
    }
    {
        let mut model_overrides = llm_model_overrides.write().await;
        model_overrides.remove(caller_channel);
    }
    format!(
        "Provider switched for this channel to: {} (backend={}), model reset to {}",
        profile.alias, profile.provider, profile.default_model
    )
}

pub async fn build_models_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    command_text: &str,
) -> String {
    let requested = command_text
        .trim()
        .strip_prefix("/models")
        .map(str::trim)
        .unwrap_or("");
    let (api_mode, provider_arg) = parse_models_command_args(requested);
    let profile = if requested.is_empty() {
        resolve_effective_provider_and_model(
            config,
            &llm_provider_overrides,
            &llm_model_overrides,
            caller_channel,
        )
        .await
        .0
    } else {
        let alias = provider_arg.unwrap_or_default().to_ascii_lowercase();
        if alias.is_empty() && api_mode {
            resolve_effective_provider_and_model(
                config,
                &llm_provider_overrides,
                &llm_model_overrides,
                caller_channel,
            )
            .await
            .0
        } else {
            let Some(profile) = config.resolve_llm_provider_profile(&alias) else {
                return format!(
                    "Unknown provider '{}'. Try /providers",
                    provider_arg.unwrap_or_default()
                );
            };
            profile
        }
    };
    if api_mode {
        return match fetch_models_from_provider_api(&profile).await {
            Ok(models) => {
                let listed = models
                    .iter()
                    .take(50)
                    .map(|m| format!("- {m}"))
                    .collect::<Vec<_>>();
                let suffix = if models.len() > 50 {
                    format!("\n... and {} more", models.len() - 50)
                } else {
                    String::new()
                };
                format!(
                    "Live models from provider '{}' (backend={}):\n{}{}",
                    profile.alias,
                    profile.provider,
                    listed.join("\n"),
                    suffix
                )
            }
            Err(e) => format!("Failed to fetch live models for '{}': {e}", profile.alias),
        };
    }
    if is_placeholder_model_list(&profile.models) {
        return match fetch_models_from_provider_api(&profile).await {
            Ok(models) if !models.is_empty() => format!(
                "Live models for provider '{}': {}",
                profile.alias,
                models.join(", ")
            ),
            _ => format!(
                "Models for provider '{}': {}",
                profile.alias,
                profile.models.join(", ")
            ),
        };
    }
    format!(
        "Models for provider '{}': {}",
        profile.alias,
        profile.models.join(", ")
    )
}

fn is_placeholder_model_list(models: &[String]) -> bool {
    models.len() == 1 && models[0].eq_ignore_ascii_case("custom-model")
}

fn parse_models_command_args(requested: &str) -> (bool, Option<&str>) {
    let trimmed = requested.trim();
    if trimmed.is_empty() {
        return (false, None);
    }
    let parts = trimmed.split_whitespace().collect::<Vec<_>>();
    if parts.first().copied() == Some("api") {
        return (true, parts.get(1).copied());
    }
    (false, parts.first().copied())
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsApiResponse {
    data: Vec<OpenAiModelItem>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelItem {
    id: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicModelsApiResponse {
    data: Vec<AnthropicModelItem>,
}

#[derive(Debug, Deserialize)]
struct AnthropicModelItem {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
}

fn resolve_openai_models_url(profile: &ResolvedLlmProviderProfile) -> String {
    let backend = profile.provider.trim().to_ascii_lowercase();
    let default_base = match backend.as_str() {
        "openai" => "https://api.openai.com/v1",
        "deepseek" => "https://api.deepseek.com/v1",
        "synthetic" => "https://api.synthetic.new/openai/v1",
        "chutes" => "https://llm.chutes.ai/v1",
        _ => "https://api.openai.com/v1",
    };
    let base = profile
        .llm_base_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(default_base)
        .trim_end_matches('/');
    if base.ends_with("/models") {
        base.to_string()
    } else if base.ends_with("/chat/completions") {
        format!(
            "{}/models",
            base.trim_end_matches("/chat/completions")
                .trim_end_matches('/')
        )
    } else {
        format!("{base}/models")
    }
}

fn resolve_anthropic_models_url(profile: &ResolvedLlmProviderProfile) -> String {
    let configured = profile
        .llm_base_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("https://api.anthropic.com/v1/models");
    let base = configured.trim_end_matches('/');
    if base.ends_with("/models") {
        base.to_string()
    } else if base.ends_with("/messages") {
        format!(
            "{}/models",
            base.trim_end_matches("/messages").trim_end_matches('/')
        )
    } else {
        format!("{base}/models")
    }
}

async fn fetch_models_from_provider_api(
    profile: &ResolvedLlmProviderProfile,
) -> Result<Vec<String>, String> {
    let backend = profile.provider.trim().to_ascii_lowercase();
    if backend == "openai-codex" && profile.api_key.trim().is_empty() {
        return Err(
            "openai-codex API listing requires provider api_key in llm_providers.<name>.api_key"
                .to_string(),
        );
    }
    if backend == "anthropic" {
        if profile.api_key.trim().is_empty() {
            return Err("missing api_key for anthropic profile".to_string());
        }
        let url = resolve_anthropic_models_url(profile);
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("x-api-key", profile.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {body}"));
        }
        let mut out = parse_anthropic_models_json_ids(&body)?;
        out.sort();
        out.dedup();
        return Ok(out);
    }

    let url = resolve_openai_models_url(profile);
    let client = reqwest::Client::new();
    let mut request = client.get(&url);
    if !profile.api_key.trim().is_empty() {
        request = request.bearer_auth(profile.api_key.as_str());
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("HTTP {status}: {body}"));
    }
    let mut out = parse_openai_models_json_ids(&body)?;
    out.sort();
    out.dedup();
    Ok(out)
}

fn parse_openai_models_json_ids(body: &str) -> Result<Vec<String>, String> {
    let parsed: OpenAiModelsApiResponse =
        serde_json::from_str(body).map_err(|e| format!("Invalid JSON response: {e}"))?;
    Ok(parsed.data.into_iter().map(|m| m.id).collect())
}

fn parse_anthropic_models_json_ids(body: &str) -> Result<Vec<String>, String> {
    let parsed: AnthropicModelsApiResponse =
        serde_json::from_str(body).map_err(|e| format!("Invalid JSON response: {e}"))?;
    Ok(parsed
        .data
        .into_iter()
        .map(|m| match m.display_name {
            Some(name) if !name.trim().is_empty() => format!("{} ({})", m.id, name),
            _ => m.id,
        })
        .collect())
}

async fn resolve_effective_provider_and_model(
    config: &Config,
    llm_provider_overrides: &Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: &Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
) -> (ResolvedLlmProviderProfile, String) {
    let provider_alias = {
        let provider_overrides = llm_provider_overrides.read().await;
        provider_overrides
            .get(caller_channel)
            .cloned()
            .unwrap_or_else(|| config.llm_provider.clone())
    };
    let profile = config
        .resolve_llm_provider_profile(&provider_alias)
        .or_else(|| config.resolve_llm_provider_profile(&config.llm_provider))
        .expect("default provider should resolve");
    let model = {
        let model_overrides = llm_model_overrides.read().await;
        model_overrides
            .get(caller_channel)
            .cloned()
            .unwrap_or_else(|| profile.default_model.clone())
    };
    (profile, model)
}

pub async fn maybe_handle_plugin_command(
    config: &Config,
    command_text: &str,
    chat_id: i64,
    caller_channel: &str,
) -> Option<String> {
    if let Some(admin) = crate::plugins::handle_plugins_admin_command(config, chat_id, command_text)
    {
        return Some(admin);
    }
    crate::plugins::execute_plugin_slash_command(config, caller_channel, chat_id, command_text)
        .await
}

#[cfg(test)]
mod tests {
    use super::{
        build_model_response, build_models_response, build_provider_response,
        is_placeholder_model_list, parse_anthropic_models_json_ids, parse_models_command_args,
        parse_openai_models_json_ids, resolve_openai_models_url,
    };
    use crate::config::{Config, LlmProviderProfile, ResolvedLlmProviderProfile};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    fn test_config() -> Config {
        let mut cfg = Config::test_defaults();
        cfg.llm_provider = "openai".to_string();
        cfg.model = "gpt-5.2".to_string();
        cfg.llm_providers.insert(
            "openai".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                llm_base_url: None,
                default_model: Some("gpt-5.2".to_string()),
                models: vec!["gpt-5.2".to_string(), "gpt-5".to_string()],
            },
        );
        cfg.llm_providers.insert(
            "anthropic".to_string(),
            LlmProviderProfile {
                provider: Some("anthropic".to_string()),
                api_key: Some("k".to_string()),
                llm_base_url: None,
                default_model: Some("claude-sonnet-4-5-20250929".to_string()),
                models: vec![
                    "claude-sonnet-4-5-20250929".to_string(),
                    "claude-opus-4-6-20260205".to_string(),
                ],
            },
        );
        cfg
    }

    #[tokio::test]
    async fn model_command_reports_current_model() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let overrides = Arc::new(RwLock::new(HashMap::new()));
        let text =
            build_model_response(&cfg, provider_overrides, overrides, "telegram", 1, "/model")
                .await;
        assert_eq!(text, "Current provider/model: openai / gpt-5.2");
    }

    #[tokio::test]
    async fn model_command_sets_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_model_response(
            &cfg,
            provider_overrides,
            overrides.clone(),
            "telegram",
            1,
            "/model gpt-5",
        )
        .await;
        assert_eq!(text, "Model switched for this channel to: openai / gpt-5");
        let guard = overrides.read().await;
        assert_eq!(guard.get("telegram").map(String::as_str), Some("gpt-5"));
    }

    #[tokio::test]
    async fn model_command_resets_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let mut map = HashMap::new();
        map.insert("telegram".to_string(), "qwen".to_string());
        let overrides = Arc::new(RwLock::new(map));
        let text = build_model_response(
            &cfg,
            provider_overrides,
            overrides.clone(),
            "telegram",
            1,
            "/model reset",
        )
        .await;
        assert_eq!(
            text,
            "Model override cleared. Current provider/model: openai / gpt-5.2"
        );
        let guard = overrides.read().await;
        assert!(!guard.contains_key("telegram"));
    }

    #[tokio::test]
    async fn provider_command_switches_provider_and_resets_model() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let mut model_map = HashMap::new();
        model_map.insert("telegram".to_string(), "gpt-5".to_string());
        let model_overrides = Arc::new(RwLock::new(model_map));
        let text = build_provider_response(
            &cfg,
            provider_overrides.clone(),
            model_overrides.clone(),
            "telegram",
            "/provider anthropic",
        )
        .await;
        assert!(
            text.contains("Provider switched for this channel to: anthropic"),
            "unexpected text: {text}"
        );
        let provider_guard = provider_overrides.read().await;
        assert_eq!(
            provider_guard.get("telegram").map(String::as_str),
            Some("anthropic")
        );
        drop(provider_guard);
        let model_guard = model_overrides.read().await;
        assert!(!model_guard.contains_key("telegram"));
    }

    #[tokio::test]
    async fn models_command_lists_profile_models() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_models_response(
            &cfg,
            provider_overrides,
            model_overrides,
            "telegram",
            "/models anthropic",
        )
        .await;
        assert!(text.contains("claude-sonnet-4-5-20250929"));
        assert!(text.contains("claude-opus-4-6-20260205"));
    }

    #[test]
    fn models_command_parses_api_mode() {
        assert_eq!(parse_models_command_args(""), (false, None));
        assert_eq!(
            parse_models_command_args("anthropic"),
            (false, Some("anthropic"))
        );
        assert_eq!(parse_models_command_args("api"), (true, None));
        assert_eq!(
            parse_models_command_args("api openai"),
            (true, Some("openai"))
        );
    }

    #[test]
    fn placeholder_models_detection() {
        assert!(is_placeholder_model_list(&["custom-model".to_string()]));
        assert!(!is_placeholder_model_list(&[
            "custom-model".to_string(),
            "other".to_string()
        ]));
        assert!(!is_placeholder_model_list(&["deepseek-chat".to_string()]));
    }

    #[test]
    fn parse_openai_models_ids() {
        let json = r#"{"data":[{"id":"gpt-5.2"},{"id":"gpt-5"}]}"#;
        let ids = parse_openai_models_json_ids(json).expect("openai parse");
        assert_eq!(ids, vec!["gpt-5.2".to_string(), "gpt-5".to_string()]);
    }

    #[test]
    fn parse_anthropic_models_ids() {
        let json = r#"{"data":[{"id":"claude-sonnet","display_name":"Claude Sonnet"},{"id":"claude-opus"}]}"#;
        let ids = parse_anthropic_models_json_ids(json).expect("anthropic parse");
        assert_eq!(
            ids,
            vec![
                "claude-sonnet (Claude Sonnet)".to_string(),
                "claude-opus".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn models_command_uses_live_models_when_placeholder_profile() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (path_tx, path_rx) = mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let _ = path_tx.send(path);
            let body = r#"{"data":[{"id":"model-live-a"},{"id":"model-live-b"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let mut cfg = Config::test_defaults();
        cfg.llm_provider = "lab-local".to_string();
        cfg.api_key = "k".to_string();
        cfg.model = "custom-model".to_string();
        cfg.llm_base_url = Some(format!("http://{addr}/v1"));
        cfg.llm_providers.insert(
            "lab-local".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                llm_base_url: Some(format!("http://{addr}/v1")),
                default_model: Some("custom-model".to_string()),
                models: vec!["custom-model".to_string()],
            },
        );
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text =
            build_models_response(&cfg, provider_overrides, model_overrides, "web", "/models")
                .await;
        let path = path_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        assert_eq!(path, "/v1/models");
        assert!(text.contains("Live models for provider 'lab-local'"));
        assert!(text.contains("model-live-a"));
    }

    #[tokio::test]
    async fn model_command_validates_against_live_models_for_placeholder_profile() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf).unwrap_or(0);
                let body = r#"{"data":[{"id":"model-live-a"},{"id":"model-live-b"}]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        let mut cfg = Config::test_defaults();
        cfg.llm_provider = "lab-local".to_string();
        cfg.api_key = "k".to_string();
        cfg.model = "custom-model".to_string();
        cfg.llm_base_url = Some(format!("http://{addr}/v1"));
        cfg.llm_providers.insert(
            "lab-local".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                llm_base_url: Some(format!("http://{addr}/v1")),
                default_model: Some("custom-model".to_string()),
                models: vec!["custom-model".to_string()],
            },
        );
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));

        let ok = build_model_response(
            &cfg,
            provider_overrides.clone(),
            model_overrides.clone(),
            "web",
            1,
            "/model model-live-a",
        )
        .await;
        assert_eq!(
            ok,
            "Model switched for this channel to: lab-local / model-live-a"
        );

        let bad = build_model_response(
            &cfg,
            provider_overrides,
            model_overrides,
            "web",
            1,
            "/model not-real",
        )
        .await;
        server.join().unwrap();
        assert!(bad.contains("Model 'not-real' is not configured"));
        assert!(bad.contains("model-live-a"));
    }

    #[test]
    fn resolve_openai_models_url_supports_synthetic_and_chutes_defaults() {
        let mk = |provider: &str| ResolvedLlmProviderProfile {
            alias: provider.to_string(),
            provider: provider.to_string(),
            api_key: String::new(),
            llm_base_url: None,
            default_model: "x".to_string(),
            models: vec!["x".to_string()],
        };
        assert_eq!(
            resolve_openai_models_url(&mk("synthetic")),
            "https://api.synthetic.new/openai/v1/models"
        );
        assert_eq!(
            resolve_openai_models_url(&mk("chutes")),
            "https://llm.chutes.ai/v1/models"
        );
    }
}
