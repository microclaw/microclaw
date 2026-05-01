use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use std::{cell::Cell, cell::RefCell};

use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::codex_auth::{
    codex_config_default_openai_base_url, is_openai_codex_provider, provider_allows_empty_api_key,
    qwen_oauth_file_has_access_token, resolve_openai_codex_auth, resolve_qwen_portal_auth,
};
use crate::config::{Config, LlmProviderProfile, SandboxBackend, SandboxMode};
use crate::http_client::llm_user_agent;
use microclaw_core::error::MicroClawError;
use microclaw_core::text::floor_char_boundary;

#[cfg(feature = "channel-matrix")]
use crate::channels::matrix;
use crate::channels::{
    dingtalk, email, feishu, imessage, irc, nostr, qq, signal, slack, weixin, whatsapp,
};
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};

// Declarative channel metadata is owned by each channel module.
const DYNAMIC_CHANNELS: &[DynamicChannelDef] = &[
    slack::SETUP_DEF,
    feishu::SETUP_DEF,
    irc::SETUP_DEF,
    #[cfg(feature = "channel-matrix")]
    matrix::SETUP_DEF,
    whatsapp::SETUP_DEF,
    imessage::SETUP_DEF,
    email::SETUP_DEF,
    nostr::SETUP_DEF,
    signal::SETUP_DEF,
    dingtalk::SETUP_DEF,
    qq::SETUP_DEF,
    weixin::SETUP_DEF,
];

/// Build the setup-wizard field key from channel name + yaml key.
fn dynamic_field_key(channel: &str, yaml_key: &str) -> String {
    format!("DYN_{}_{}", channel.to_uppercase(), yaml_key.to_uppercase())
}

fn dynamic_account_id_field_key(channel: &str) -> String {
    format!("DYN_{}_ACCOUNT_ID", channel.to_uppercase())
}

fn dynamic_accounts_json_field_key(channel: &str) -> String {
    format!("DYN_{}_ACCOUNTS_JSON", channel.to_uppercase())
}

const MAX_BOT_SLOTS: usize = 10;
const TELEGRAM_DEFAULT_BOT_COUNT: usize = 1;
const UI_FIELD_WINDOW: usize = 14;
// Box widgets with borders need at least 3 rows to render one content line.
// Header contains 2 content lines, so it needs at least 4 rows.
const UI_HEADER_HEIGHT: u16 = 4;
const UI_STATUS_HEIGHT: u16 = 3;
const CONFIG_BACKUP_DIR_NAME: &str = "microclaw.config.backups";
const MAX_CONFIG_BACKUPS: usize = 50;

fn telegram_slot_id_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ID", slot)
}

fn telegram_slot_enabled_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ENABLED", slot)
}

fn telegram_slot_token_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_TOKEN", slot)
}

fn telegram_slot_username_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_USERNAME", slot)
}

fn telegram_slot_model_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_MODEL", slot)
}

fn telegram_slot_soul_path_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_SOUL_PATH", slot)
}

fn telegram_slot_allowed_user_ids_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ALLOWED_USER_IDS", slot)
}

fn telegram_slot_topic_routing_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_TOPIC_ROUTING", slot)
}

fn default_slot_account_id(slot: usize) -> String {
    if slot <= 1 {
        default_account_id().to_string()
    } else {
        format!("bot{slot}")
    }
}

fn telegram_bot_count_key() -> &'static str {
    "TELEGRAM_BOT_COUNT"
}

fn telegram_allowed_user_ids_key() -> &'static str {
    "TELEGRAM_ALLOWED_USER_IDS"
}

fn telegram_topic_routing_key() -> &'static str {
    "TELEGRAM_TOPIC_ROUTING"
}

fn web_hooks_token_key() -> &'static str {
    "WEB_HOOKS_TOKEN"
}

fn web_hooks_default_session_key_key() -> &'static str {
    "WEB_HOOKS_DEFAULT_SESSION_KEY"
}

fn web_hooks_allow_request_session_key_key() -> &'static str {
    "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY"
}

fn web_hooks_allowed_session_key_prefixes_key() -> &'static str {
    "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES"
}

fn a2a_enabled_key() -> &'static str {
    "A2A_ENABLED"
}

fn a2a_public_base_url_key() -> &'static str {
    "A2A_PUBLIC_BASE_URL"
}

fn a2a_agent_name_key() -> &'static str {
    "A2A_AGENT_NAME"
}

fn a2a_agent_description_key() -> &'static str {
    "A2A_AGENT_DESCRIPTION"
}

fn a2a_shared_tokens_key() -> &'static str {
    "A2A_SHARED_TOKENS"
}

fn a2a_peers_json_key() -> &'static str {
    "A2A_PEERS_JSON"
}

fn subagents_max_concurrent_key() -> &'static str {
    "SUBAGENTS_MAX_CONCURRENT"
}

fn subagents_max_active_per_chat_key() -> &'static str {
    "SUBAGENTS_MAX_ACTIVE_PER_CHAT"
}

fn subagents_run_timeout_secs_key() -> &'static str {
    "SUBAGENTS_RUN_TIMEOUT_SECS"
}

fn subagents_announce_to_chat_key() -> &'static str {
    "SUBAGENTS_ANNOUNCE_TO_CHAT"
}

fn subagents_max_spawn_depth_key() -> &'static str {
    "SUBAGENTS_MAX_SPAWN_DEPTH"
}

fn subagents_max_children_per_run_key() -> &'static str {
    "SUBAGENTS_MAX_CHILDREN_PER_RUN"
}

fn subagents_thread_bound_routing_enabled_key() -> &'static str {
    "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED"
}

fn subagents_announce_relay_interval_secs_key() -> &'static str {
    "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS"
}

fn subagents_max_tokens_per_run_key() -> &'static str {
    "SUBAGENTS_MAX_TOKENS_PER_RUN"
}

fn subagents_orchestrate_max_workers_key() -> &'static str {
    "SUBAGENTS_ORCHESTRATE_MAX_WORKERS"
}

fn subagents_acp_enabled_key() -> &'static str {
    "SUBAGENTS_ACP_ENABLED"
}

fn subagents_acp_command_key() -> &'static str {
    "SUBAGENTS_ACP_COMMAND"
}

fn subagents_acp_args_key() -> &'static str {
    "SUBAGENTS_ACP_ARGS"
}

fn subagents_acp_env_json_key() -> &'static str {
    "SUBAGENTS_ACP_ENV_JSON"
}

fn subagents_acp_auto_approve_key() -> &'static str {
    "SUBAGENTS_ACP_AUTO_APPROVE"
}

fn subagents_acp_default_target_key() -> &'static str {
    "SUBAGENTS_ACP_DEFAULT_TARGET"
}

fn subagents_acp_targets_json_key() -> &'static str {
    "SUBAGENTS_ACP_TARGETS_JSON"
}

fn telegram_llm_provider_key() -> &'static str {
    "TELEGRAM_LLM_PROVIDER"
}

fn telegram_llm_api_key_key() -> &'static str {
    "TELEGRAM_LLM_API_KEY"
}

fn telegram_llm_base_url_key() -> &'static str {
    "TELEGRAM_LLM_BASE_URL"
}

fn discord_llm_provider_key() -> &'static str {
    "DISCORD_LLM_PROVIDER"
}

fn discord_llm_api_key_key() -> &'static str {
    "DISCORD_LLM_API_KEY"
}

fn discord_llm_base_url_key() -> &'static str {
    "DISCORD_LLM_BASE_URL"
}

fn llm_provider_profiles_key() -> &'static str {
    "LLM_PROVIDER_PROFILES"
}

fn dynamic_bot_count_field_key(channel: &str) -> String {
    format!("DYN_{}_BOT_COUNT", channel.to_uppercase())
}

fn dynamic_slot_id_field_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_ID", channel.to_uppercase(), slot)
}

fn dynamic_slot_enabled_field_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_ENABLED", channel.to_uppercase(), slot)
}

fn dynamic_slot_field_key(channel: &str, slot: usize, yaml_key: &str) -> String {
    format!(
        "DYN_{}_BOT{}_{}",
        channel.to_uppercase(),
        slot,
        yaml_key.to_uppercase()
    )
}

fn dynamic_slot_llm_provider_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_LLM_PROVIDER", channel.to_uppercase(), slot)
}

fn dynamic_slot_llm_api_key_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_LLM_API_KEY", channel.to_uppercase(), slot)
}

fn dynamic_slot_llm_base_url_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_LLM_BASE_URL", channel.to_uppercase(), slot)
}

fn dynamic_slot_soul_path_field_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_SOUL_PATH", channel.to_uppercase(), slot)
}

fn trim_channel_prefix<'a>(channel: &str, label: &'a str) -> &'a str {
    let trimmed = label.trim();
    let prefix_len = channel.len();
    if trimmed.len() > prefix_len
        && trimmed[..prefix_len].eq_ignore_ascii_case(channel)
        && trimmed.as_bytes().get(prefix_len) == Some(&b' ')
    {
        return trimmed[prefix_len + 1..].trim_start();
    }
    trimmed
}

fn dynamic_channel_uses_minimal_setup(channel: &str) -> bool {
    channel == "weixin"
}

fn effective_dynamic_slot_field_value<F>(
    channel: &str,
    slot: usize,
    field: &ChannelFieldDef,
    get: F,
) -> String
where
    F: Fn(&str) -> String,
{
    let slot_key = dynamic_slot_field_key(channel, slot, field.yaml_key);
    let slot_value = get(&slot_key);
    let slot_value = slot_value.trim();
    if !slot_value.is_empty() {
        return slot_value.to_string();
    }

    let channel_key = dynamic_field_key(channel, field.yaml_key);
    let channel_value = get(&channel_key);
    let channel_value = channel_value.trim();
    if !channel_value.is_empty() {
        return channel_value.to_string();
    }

    field.default.trim().to_string()
}

fn default_account_id() -> &'static str {
    "main"
}

fn account_id_from_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        default_account_id().to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_valid_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn resolve_channel_default_account_id(channel_cfg: &serde_yaml::Value) -> Option<String> {
    let explicit = channel_cfg
        .get("default_account")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);
    if explicit.is_some() {
        return explicit;
    }

    let accounts = channel_cfg.get("accounts").and_then(|v| v.as_mapping())?;
    if accounts.contains_key(serde_yaml::Value::String("default".to_string())) {
        return Some("default".to_string());
    }
    let mut ids: Vec<String> = accounts
        .keys()
        .filter_map(|k| k.as_str().map(ToOwned::to_owned))
        .collect();
    ids.sort();
    ids.first().cloned()
}

fn channel_account_str_value(
    channel_cfg: &serde_yaml::Value,
    account_id: &str,
    key: &str,
) -> Option<String> {
    channel_cfg
        .get("accounts")
        .and_then(|v| v.get(account_id))
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn channel_default_account_str_value(channel_cfg: &serde_yaml::Value, key: &str) -> Option<String> {
    let account_id = resolve_channel_default_account_id(channel_cfg)?;
    channel_account_str_value(channel_cfg, &account_id, key)
}

fn compact_json_string(value: &serde_yaml::Value) -> Option<String> {
    let json_value = serde_json::to_value(value).ok()?;
    serde_json::to_string(&json_value).ok()
}

fn parse_accounts_json_value(
    raw: &str,
    field_key: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, MicroClawError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
        MicroClawError::Config(format!("{field_key} must be valid JSON object: {e}"))
    })?;
    let obj = if let Some(map_obj) = parsed.as_object() {
        map_obj.clone()
    } else if let Some(items) = parsed.as_array() {
        let mut out = serde_json::Map::new();
        for (idx, item) in items.iter().enumerate() {
            let Some(entry) = item.as_object() else {
                return Err(MicroClawError::Config(format!(
                    "{field_key}[{idx}] must be an object with at least 'id'"
                )));
            };
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    MicroClawError::Config(format!(
                        "{field_key}[{idx}] is missing required string field 'id'"
                    ))
                })?;
            if !is_valid_account_id(id) {
                return Err(MicroClawError::Config(format!(
                    "{field_key}[{idx}] has invalid id '{id}' (allowed: letters, numbers, '_' or '-')"
                )));
            }
            let mut account = entry.clone();
            account.remove("id");
            out.insert(id.to_string(), serde_json::Value::Object(account));
        }
        out
    } else {
        return Err(MicroClawError::Config(format!(
            "{field_key} must be a JSON object {{id: config}} or JSON array [{{id, ...config}}]"
        )));
    };
    for account_id in obj.keys() {
        if !is_valid_account_id(account_id) {
            return Err(MicroClawError::Config(format!(
                "{field_key} contains invalid account id '{account_id}' (allowed: letters, numbers, '_' or '-')"
            )));
        }
    }
    Ok(Some(obj))
}

fn parse_provider_presets_json_value(
    raw: &str,
    field_key: &str,
) -> Result<HashMap<String, LlmProviderProfile>, MicroClawError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let mut presets: HashMap<String, LlmProviderProfile> =
        serde_json::from_str(trimmed).map_err(|e| {
            MicroClawError::Config(format!(
                "{field_key} must be a valid JSON object {{preset_id: {{provider,...}}}}: {e}"
            ))
        })?;
    let mut normalized = HashMap::new();
    for (preset_id, profile) in presets.drain() {
        let preset_id = preset_id.trim().to_ascii_lowercase();
        if preset_id.is_empty() {
            return Err(MicroClawError::Config(format!(
                "{field_key} contains an empty preset id"
            )));
        }
        if preset_id == "main" {
            return Err(MicroClawError::Config(format!(
                "{field_key} preset id 'main' is reserved for the global default"
            )));
        }
        if !is_valid_account_id(&preset_id) {
            return Err(MicroClawError::Config(format!(
                "{field_key} contains invalid preset id '{preset_id}' (allowed: letters, numbers, '_' or '-')"
            )));
        }
        normalized.insert(preset_id, profile);
    }
    Ok(normalized)
}

fn append_yaml_value(yaml: &mut String, indent: usize, value: &serde_yaml::Value) {
    if let Ok(rendered) = serde_yaml::to_string(value) {
        let prefix = " ".repeat(indent);
        for line in rendered.lines() {
            if line == "---" || line.trim().is_empty() {
                continue;
            }
            yaml.push_str(&prefix);
            yaml.push_str(line);
            yaml.push('\n');
        }
    }
}

fn yaml_double_quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn parse_boolish(value: &str, default_if_empty: bool) -> Result<bool, MicroClawError> {
    let raw = value.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Ok(default_if_empty);
    }
    match raw.as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(MicroClawError::Config(format!(
            "invalid bool value '{value}', expected true/false"
        ))),
    }
}

fn dynamic_field_is_bool(channel: &str, yaml_key: &str) -> bool {
    matches!(
        (channel, yaml_key),
        ("feishu", "topic_mode" | "show_progress") | ("slack", "capture_unmentioned_images")
    )
}

fn dynamic_field_is_u64(channel: &str, yaml_key: &str) -> bool {
    matches!((channel, yaml_key), ("slack", "inbound_image_max_mb"))
}

fn parse_bot_count(value: &str, field_key: &str) -> Result<usize, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(1);
    }
    let parsed = trimmed.parse::<usize>().map_err(|_| {
        MicroClawError::Config(format!(
            "{field_key} must be an integer between 1 and {MAX_BOT_SLOTS}"
        ))
    })?;
    if !(1..=MAX_BOT_SLOTS).contains(&parsed) {
        return Err(MicroClawError::Config(format!(
            "{field_key} must be between 1 and {MAX_BOT_SLOTS}"
        )));
    }
    Ok(parsed)
}

fn parse_u64_field(value: &str, field_key: &str) -> Result<u64, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MicroClawError::Config(format!(
            "{field_key} must be a positive integer"
        )));
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| MicroClawError::Config(format!("{field_key} must be a positive integer")))
}

fn parse_i64_list_field(value: &str, field_key: &str) -> Result<Vec<i64>, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let parse_item = |raw: &str| -> Result<i64, MicroClawError> {
        raw.trim().parse::<i64>().map_err(|_| {
            MicroClawError::Config(format!(
                "{field_key} must contain integer IDs (csv like '123,456' or JSON array like '[123,456]')"
            ))
        })
    };

    if trimmed.starts_with('[') {
        let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            MicroClawError::Config(format!(
                "{field_key} must be a valid JSON array when using [] syntax: {e}"
            ))
        })?;
        let arr = parsed.as_array().ok_or_else(|| {
            MicroClawError::Config(format!(
                "{field_key} must be a JSON array when using [] syntax"
            ))
        })?;
        let mut out = Vec::new();
        for item in arr {
            match item {
                serde_json::Value::Number(n) => {
                    let id = n.as_i64().ok_or_else(|| {
                        MicroClawError::Config(format!("{field_key} contains non-integer number"))
                    })?;
                    out.push(id);
                }
                serde_json::Value::String(s) => out.push(parse_item(s)?),
                _ => {
                    return Err(MicroClawError::Config(format!(
                        "{field_key} supports only integer values"
                    )));
                }
            }
        }
        return Ok(out);
    }

    trimmed
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(parse_item)
        .collect()
}

fn parse_string_list_field(value: &str) -> Result<Vec<String>, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            MicroClawError::Config(format!("invalid string list JSON array syntax: {e}"))
        })?;
        let arr = parsed.as_array().ok_or_else(|| {
            MicroClawError::Config("string list must be a JSON array when using [] syntax".into())
        })?;
        let mut out = Vec::new();
        for item in arr {
            let s = item
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    MicroClawError::Config(
                        "string list supports only non-empty string values".into(),
                    )
                })?;
            out.push(s.to_string());
        }
        return Ok(out);
    }
    Ok(trimmed
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn normalize_soul_path_input(raw: &str, souls_dir: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return trimmed.to_string();
    }
    let base = souls_dir.trim().trim_end_matches(['/', '\\']);
    let prefix = if base.is_empty() { "souls" } else { base };
    if trimmed.to_ascii_lowercase().ends_with(".md") {
        return format!("{prefix}/{trimmed}");
    }
    format!("{prefix}/{trimmed}.md")
}

fn soul_picker_file_names(data_dir: Option<&str>, souls_dir: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let mut roots = Vec::new();

    if let Some(dir) = souls_dir {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            roots.push(Path::new(trimmed).to_path_buf());
            if let Some(data) = data_dir {
                let data_trimmed = data.trim();
                if !data_trimmed.is_empty() {
                    roots.push(Path::new(data_trimmed).join(trimmed));
                }
            }
        }
    }
    roots.push(Path::new("souls").to_path_buf());
    if let Some(dir) = data_dir {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            roots.push(Path::new(trimmed).join("souls"));
        }
    }

    for root in roots {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let is_md = path
                    .extension()
                    .and_then(|v| v.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("md"))
                    .unwrap_or(false);
                if !is_md {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|v| v.to_str()) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn default_data_dir_for_setup() -> String {
    if std::env::var("SNAP").is_ok() {
        if let Ok(snap_user_common) = std::env::var("SNAP_USER_COMMON") {
            return snap_user_common;
        }
    }
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .map(|p| p.join(".microclaw"))
        .unwrap_or_else(|| std::path::PathBuf::from(".microclaw"))
        .to_string_lossy()
        .to_string()
}

fn default_working_dir_for_setup() -> String {
    Path::new(&default_data_dir_for_setup())
        .join("working_dir")
        .to_string_lossy()
        .to_string()
}

fn default_souls_dir_for_setup() -> String {
    Path::new(&default_data_dir_for_setup())
        .join("souls")
        .to_string_lossy()
        .to_string()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderProtocol {
    Anthropic,
    OpenAiCompat,
}

#[derive(Clone, Copy)]
struct ProviderPreset {
    id: &'static str,
    label: &'static str,
    protocol: ProviderProtocol,
    default_base_url: &'static str,
    models: &'static [&'static str],
}

const PROVIDER_PRESETS: &[ProviderPreset] = &[
    ProviderPreset {
        id: "openai",
        label: "OpenAI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.openai.com/v1",
        models: &["gpt-5.2", "gpt-5", "gpt-5-mini"],
    },
    ProviderPreset {
        id: "openai-codex",
        label: "OpenAI Codex",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "",
        models: &["gpt-5.3-codex", "gpt-5.2-codex", "gpt-5-codex"],
    },
    ProviderPreset {
        id: "openrouter",
        label: "OpenRouter",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://openrouter.ai/api/v1",
        models: &[
            "openrouter/auto",
            "openai/gpt-5.2",
            "anthropic/claude-sonnet-4.5",
        ],
    },
    ProviderPreset {
        id: "anthropic",
        label: "Anthropic",
        protocol: ProviderProtocol::Anthropic,
        default_base_url: "",
        models: &[
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-6-20260205",
            "claude-haiku-4-5-20250929",
        ],
    },
    ProviderPreset {
        id: "ollama",
        label: "Ollama (local)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://127.0.0.1:11434/v1",
        models: &["llama3.2", "qwen2.5-coder:7b", "mistral"],
    },
    ProviderPreset {
        id: "google",
        label: "Google DeepMind",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        models: &[
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
        ],
    },
    ProviderPreset {
        id: "aliyun-bailian",
        label: "Alibaba Cloud Bailian",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://coding.dashscope.aliyuncs.com/v1",
        models: &["qwen3.5-plus", "qwen3-max", "qwen-plus-latest"],
    },
    ProviderPreset {
        id: "alibaba",
        label: "Alibaba Cloud (Qwen / DashScope)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
        models: &["qwen3-max", "qwen3-plus", "qwen-max-latest"],
    },
    ProviderPreset {
        id: "qwen-portal",
        label: "Qwen Portal (OAuth)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://portal.qwen.ai/v1",
        models: &["coder-model", "vision-model", "qwen3.5-plus"],
    },
    ProviderPreset {
        id: "deepseek",
        label: "DeepSeek",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.deepseek.com/v1",
        models: &["deepseek-chat", "deepseek-reasoner", "deepseek-v3"],
    },
    ProviderPreset {
        id: "synthetic",
        label: "Synthetic",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.synthetic.new/openai/v1",
        models: &["hf:openai/gpt-oss-120b", "hf:deepseek-ai/DeepSeek-V3-0324"],
    },
    ProviderPreset {
        id: "chutes",
        label: "Chutes",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://llm.chutes.ai/v1",
        models: &[
            "deepseek-ai/DeepSeek-V3-0324",
            "Qwen/Qwen3-Coder-480B-A35B-Instruct",
        ],
    },
    ProviderPreset {
        id: "moonshot",
        label: "Moonshot AI (Kimi)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.moonshot.cn/v1",
        models: &["kimi-k2.5", "kimi-k2", "kimi-latest"],
    },
    ProviderPreset {
        id: "mistral",
        label: "Mistral AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.mistral.ai/v1",
        models: &[
            "mistral-large-latest",
            "mistral-medium-latest",
            "ministral-8b-latest",
        ],
    },
    ProviderPreset {
        id: "azure",
        label: "Microsoft Azure AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url:
            "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT",
        models: &["gpt-5.2", "gpt-5", "gpt-4.1"],
    },
    ProviderPreset {
        id: "bedrock",
        label: "Amazon AWS Bedrock",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://bedrock-runtime.YOUR-REGION.amazonaws.com/openai/v1",
        models: &[
            "anthropic.claude-opus-4-6-v1",
            "anthropic.claude-sonnet-4-5-v2",
            "anthropic.claude-haiku-4-5-v1",
        ],
    },
    ProviderPreset {
        id: "zhipu",
        label: "Zhipu AI (GLM / Z.AI)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://open.bigmodel.cn/api/paas/v4",
        models: &["glm-4.7", "glm-4.7-flash", "glm-4.5-air"],
    },
    ProviderPreset {
        id: "minimax",
        label: "MiniMax",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.minimax.io/v1",
        models: &["MiniMax-M2.5", "MiniMax-M2.5-Thinking", "MiniMax-M2.1"],
    },
    ProviderPreset {
        id: "xiaomi",
        label: "Xiaomi (MiMo)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.xiaomimimo.com/v1",
        models: &["MiMo-V2.5-Pro", "MiMo-V2.5"],
    },
    ProviderPreset {
        id: "cohere",
        label: "Cohere",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.cohere.ai/compatibility/v1",
        models: &[
            "command-a-03-2025",
            "command-r-plus-08-2024",
            "command-r-08-2024",
        ],
    },
    ProviderPreset {
        id: "tencent",
        label: "Tencent AI Lab",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.hunyuan.cloud.tencent.com/v1",
        models: &[
            "hunyuan-t1-latest",
            "hunyuan-turbos-latest",
            "hunyuan-standard-latest",
        ],
    },
    ProviderPreset {
        id: "xai",
        label: "xAI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.x.ai/v1",
        models: &["grok-4", "grok-4-fast", "grok-3"],
    },
    ProviderPreset {
        id: "nvidia",
        label: "NVIDIA NIM",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://integrate.api.nvidia.com/v1",
        models: &[
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-70b-instruct",
            "nvidia/llama-3.1-nemotron-ultra-253b-v1",
        ],
    },
    ProviderPreset {
        id: "huggingface",
        label: "Hugging Face",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://router.huggingface.co/v1",
        models: &[
            "Qwen/Qwen3-Coder-Next",
            "meta-llama/Llama-3.3-70B-Instruct",
            "deepseek-ai/DeepSeek-V3",
        ],
    },
    ProviderPreset {
        id: "together",
        label: "Together AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.together.xyz/v1",
        models: &[
            "deepseek-ai/DeepSeek-V3",
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8",
        ],
    },
    ProviderPreset {
        id: "custom",
        label: "Custom (manual config)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "",
        models: &["custom-model"],
    },
];

fn find_provider_preset(provider: &str) -> Option<&'static ProviderPreset> {
    PROVIDER_PRESETS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(provider))
}

/// Returns the default base URL for a known provider, or `None` if the
/// provider is unknown or has no preset base URL.
pub fn default_base_url_for_provider(provider: &str) -> Option<&'static str> {
    find_provider_preset(provider)
        .map(|p| p.default_base_url)
        .filter(|url| !url.is_empty())
}

fn provider_protocol(provider: &str) -> ProviderProtocol {
    find_provider_preset(provider)
        .map(|p| p.protocol)
        .unwrap_or(ProviderProtocol::OpenAiCompat)
}

fn default_model_for_provider(provider: &str) -> &'static str {
    find_provider_preset(provider)
        .and_then(|p| p.models.first().copied())
        .unwrap_or("gpt-5.2")
}

fn is_placeholder_provider_model_list(models: &[&str]) -> bool {
    models.len() == 1 && models[0].eq_ignore_ascii_case("custom-model")
}

fn normalize_setup_provider_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if find_provider_preset(trimmed).is_some() {
        return trimmed.to_ascii_lowercase();
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(suffix) = lower.strip_prefix("custom") {
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return "custom".to_string();
        }
    }
    trimmed.to_string()
}

fn provider_display(provider: &str) -> String {
    if let Some(preset) = find_provider_preset(provider) {
        format!("{} - {}", preset.id, preset.label)
    } else {
        format!("{provider} - custom")
    }
}

fn parse_bool_like(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" | "" => Some(false),
        _ => None,
    }
}

const MODEL_PICKER_MANUAL_INPUT: &str = "<Manual input...>";
const SOUL_PICKER_CLEAR: &str = "<None>";
const SOUL_PICKER_MANUAL_INPUT: &str = "<Manual input...>";
const TIMEZONE_PICKER_SYSTEM_DEFAULT: &str = "<Use system timezone (default)>";
const TIMEZONE_PICKER_MANUAL_INPUT: &str = "<Custom timezone (type IANA)...>";

#[derive(Clone)]
struct Field {
    key: String,
    label: String,
    value: String,
    required: bool,
    secret: bool,
}

impl Field {
    fn display_value(&self, editing: bool) -> String {
        if editing || !self.secret {
            return self.value.clone();
        }
        if self.value.is_empty() {
            String::new()
        } else {
            mask_secret(&self.value)
        }
    }
}

#[derive(Clone)]
struct SetupApp {
    fields: Vec<Field>,
    selected: usize,
    field_scroll: usize,
    field_window: usize,
    visible_cache_sig: Cell<u64>,
    visible_cache_indices: RefCell<Vec<usize>>,
    editing: bool,
    picker: Option<PickerState>,
    status: String,
    completed: bool,
    backup_path: Option<String>,
    completion_summary: Vec<String>,
    llm_override_page: Option<LlmOverridePage>,
    llm_override_picker: Option<LlmOverridePicker>,
    provider_preset_page: Option<ProviderPresetPage>,
}

#[derive(Clone)]
struct LlmOverridePage {
    title: String,
    provider_key: String,
    api_key_key: String,
    base_url_key: String,
    show_legacy_fields: bool,
    selected: usize,
    editing: bool,
}

#[derive(Clone)]
struct LlmOverridePicker {
    title: String,
    target_key: String,
    options: Vec<(String, String)>,
    selected: usize,
}

#[derive(Clone)]
struct ProviderPresetDraft {
    id: String,
    provider: String,
    api_key: String,
    base_url: String,
    user_agent: String,
    default_model: String,
    show_thinking: bool,
}

struct ProviderPresetValidationRequest {
    profile_id: String,
    provider: String,
    api_key: String,
    base_url: String,
    user_agent: String,
    model: String,
    codex_account_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderPresetPageMode {
    List,
    Edit,
}

#[derive(Clone)]
struct ProviderPresetPage {
    entries: Vec<ProviderPresetDraft>,
    selected: usize,
    mode: ProviderPresetPageMode,
    field_selected: usize,
    editing: bool,
    picker: Option<LlmOverridePicker>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PickerKind {
    Provider,
    Model,
    Channels,
    SoulPath,
    Timezone,
}

#[derive(Clone)]
struct PickerState {
    kind: PickerKind,
    selected: usize,
    selected_multi: Vec<bool>,
}

impl SetupApp {
    fn channel_options() -> Vec<&'static str> {
        let mut opts = vec!["web", "telegram", "discord"];
        for ch in DYNAMIC_CHANNELS {
            opts.push(ch.name);
        }
        opts
    }

    fn new() -> Self {
        // Try loading from existing config file first, then fall back to env vars
        let existing = Self::load_existing_config();
        let provider = normalize_setup_provider_id(
            &existing
                .get("LLM_PROVIDER")
                .cloned()
                .unwrap_or_else(|| "anthropic".into()),
        );
        let default_model = default_model_for_provider(&provider);
        let default_base_url = find_provider_preset(&provider)
            .map(|p| p.default_base_url)
            .unwrap_or("");
        let llm_api_key = existing.get("LLM_API_KEY").cloned().unwrap_or_default();
        let enabled_channels = existing
            .get("ENABLED_CHANNELS")
            .cloned()
            .unwrap_or_else(|| "web".into());

        let mut app = Self {
            fields: vec![
                Field {
                    key: "ENABLED_CHANNELS".into(),
                    label: "Enabled channels (csv, empty = setup later)".into(),
                    value: enabled_channels,
                    required: false,
                    secret: false,
                },
                Field {
                    key: web_hooks_token_key().into(),
                    label: "Web hook token (optional, for /hooks/* auth)".into(),
                    value: existing
                        .get(web_hooks_token_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: web_hooks_default_session_key_key().into(),
                    label: "Web hook default session key (optional)".into(),
                    value: existing
                        .get(web_hooks_default_session_key_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: web_hooks_allow_request_session_key_key().into(),
                    label: "Web hook allow request session key (optional true/false)".into(),
                    value: existing
                        .get(web_hooks_allow_request_session_key_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: web_hooks_allowed_session_key_prefixes_key().into(),
                    label: "Web hook allowed session key prefixes (csv, optional)".into(),
                    value: existing
                        .get(web_hooks_allowed_session_key_prefixes_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_enabled_key().into(),
                    label: "Enable A2A HTTP integration (true/false)".into(),
                    value: existing
                        .get(a2a_enabled_key())
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_public_base_url_key().into(),
                    label: "A2A public base URL (optional)".into(),
                    value: existing
                        .get(a2a_public_base_url_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_agent_name_key().into(),
                    label: "A2A agent name (optional)".into(),
                    value: existing
                        .get(a2a_agent_name_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_agent_description_key().into(),
                    label: "A2A agent description (optional)".into(),
                    value: existing
                        .get(a2a_agent_description_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_shared_tokens_key().into(),
                    label: "A2A shared bearer tokens (csv, optional)".into(),
                    value: existing
                        .get(a2a_shared_tokens_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: a2a_peers_json_key().into(),
                    label: "A2A peers JSON ({name:{base_url,...}}, optional)".into(),
                    value: existing
                        .get(a2a_peers_json_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_concurrent_key().into(),
                    label: "Subagents max concurrent runs".into(),
                    value: existing
                        .get(subagents_max_concurrent_key())
                        .cloned()
                        .unwrap_or_else(|| "4".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_active_per_chat_key().into(),
                    label: "Subagents max active runs per chat".into(),
                    value: existing
                        .get(subagents_max_active_per_chat_key())
                        .cloned()
                        .unwrap_or_else(|| "5".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_run_timeout_secs_key().into(),
                    label: "Subagents run timeout secs".into(),
                    value: existing
                        .get(subagents_run_timeout_secs_key())
                        .cloned()
                        .unwrap_or_else(|| "900".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_announce_to_chat_key().into(),
                    label: "Subagents announce to chat (true/false)".into(),
                    value: existing
                        .get(subagents_announce_to_chat_key())
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_spawn_depth_key().into(),
                    label: "Subagents max spawn depth".into(),
                    value: existing
                        .get(subagents_max_spawn_depth_key())
                        .cloned()
                        .unwrap_or_else(|| "1".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_children_per_run_key().into(),
                    label: "Subagents max children per run".into(),
                    value: existing
                        .get(subagents_max_children_per_run_key())
                        .cloned()
                        .unwrap_or_else(|| "5".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_thread_bound_routing_enabled_key().into(),
                    label: "Subagents thread-bound routing enabled (true/false)".into(),
                    value: existing
                        .get(subagents_thread_bound_routing_enabled_key())
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_announce_relay_interval_secs_key().into(),
                    label: "Subagents announce relay interval secs".into(),
                    value: existing
                        .get(subagents_announce_relay_interval_secs_key())
                        .cloned()
                        .unwrap_or_else(|| "15".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_tokens_per_run_key().into(),
                    label: "Subagents max tokens per run".into(),
                    value: existing
                        .get(subagents_max_tokens_per_run_key())
                        .cloned()
                        .unwrap_or_else(|| "400000".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_orchestrate_max_workers_key().into(),
                    label: "Subagents orchestrate max workers".into(),
                    value: existing
                        .get(subagents_orchestrate_max_workers_key())
                        .cloned()
                        .unwrap_or_else(|| "5".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_enabled_key().into(),
                    label: "ACP subagent runtime enabled (true/false)".into(),
                    value: existing
                        .get(subagents_acp_enabled_key())
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_command_key().into(),
                    label: "ACP default command (optional)".into(),
                    value: existing
                        .get(subagents_acp_command_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_args_key().into(),
                    label: "ACP default args (csv or JSON array, optional)".into(),
                    value: existing
                        .get(subagents_acp_args_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_env_json_key().into(),
                    label: "ACP default env JSON (optional)".into(),
                    value: existing
                        .get(subagents_acp_env_json_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: subagents_acp_auto_approve_key().into(),
                    label: "ACP default auto-approve permissions (true/false)".into(),
                    value: existing
                        .get(subagents_acp_auto_approve_key())
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_default_target_key().into(),
                    label: "ACP named default target (optional)".into(),
                    value: existing
                        .get(subagents_acp_default_target_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_targets_json_key().into(),
                    label: "ACP named targets JSON (optional)".into(),
                    value: existing
                        .get(subagents_acp_targets_json_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: telegram_bot_count_key().into(),
                    label: format!("Telegram bot count (1-{MAX_BOT_SLOTS})"),
                    value: existing
                        .get(telegram_bot_count_key())
                        .cloned()
                        .unwrap_or_else(|| TELEGRAM_DEFAULT_BOT_COUNT.to_string()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "TELEGRAM_MODEL".into(),
                    label: "Telegram LLM provider profile override (optional)".into(),
                    value: existing.get("TELEGRAM_MODEL").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: telegram_allowed_user_ids_key().into(),
                    label: "Telegram bot allowed user ids (csv/array, optional)".into(),
                    value: existing
                        .get(telegram_allowed_user_ids_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: telegram_topic_routing_key().into(),
                    label: "Telegram topic routing (optional true/false)".into(),
                    value: existing
                        .get(telegram_topic_routing_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: telegram_llm_provider_key().into(),
                    label: "Telegram LLM provider override (optional)".into(),
                    value: existing
                        .get(telegram_llm_provider_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: telegram_llm_api_key_key().into(),
                    label: "Telegram LLM API key override (optional)".into(),
                    value: existing
                        .get(telegram_llm_api_key_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: telegram_llm_base_url_key().into(),
                    label: "Telegram LLM base URL override (optional)".into(),
                    value: existing
                        .get(telegram_llm_base_url_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "DISCORD_BOT_TOKEN".into(),
                    label: "Discord bot token".into(),
                    value: existing
                        .get("DISCORD_BOT_TOKEN")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: "DISCORD_ACCOUNT_ID".into(),
                    label: "Discord default account id".into(),
                    value: existing
                        .get("DISCORD_ACCOUNT_ID")
                        .cloned()
                        .unwrap_or_else(|| default_account_id().to_string()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "DISCORD_MODEL".into(),
                    label: "Discord LLM provider profile override (optional)".into(),
                    value: existing.get("DISCORD_MODEL").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: discord_llm_provider_key().into(),
                    label: "Discord LLM provider override (optional)".into(),
                    value: existing
                        .get(discord_llm_provider_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: discord_llm_api_key_key().into(),
                    label: "Discord LLM API key override (optional)".into(),
                    value: existing
                        .get(discord_llm_api_key_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: discord_llm_base_url_key().into(),
                    label: "Discord LLM base URL override (optional)".into(),
                    value: existing
                        .get(discord_llm_base_url_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "DISCORD_ACCOUNTS_JSON".into(),
                    label: "Discord accounts JSON (optional, multi-bot)".into(),
                    value: existing
                        .get("DISCORD_ACCOUNTS_JSON")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "LLM_PROVIDER".into(),
                    label: "LLM provider (preset/custom)".into(),
                    value: provider,
                    required: true,
                    secret: false,
                },
                Field {
                    key: "LLM_API_KEY".into(),
                    label: "LLM API key".into(),
                    value: llm_api_key,
                    required: true,
                    secret: true,
                },
                Field {
                    key: "LLM_MODEL".into(),
                    label: "LLM model".into(),
                    value: existing
                        .get("LLM_MODEL")
                        .cloned()
                        .unwrap_or_else(|| default_model.into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "LLM_BASE_URL".into(),
                    label: "LLM base URL (optional)".into(),
                    value: existing
                        .get("LLM_BASE_URL")
                        .cloned()
                        .unwrap_or_else(|| default_base_url.to_string()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "LLM_USER_AGENT".into(),
                    label: "LLM user-agent (optional)".into(),
                    value: existing.get("LLM_USER_AGENT").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "SHOW_THINKING".into(),
                    label: "LLM Show thinking/reasoning text (true/false)".into(),
                    value: existing
                        .get("SHOW_THINKING")
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: llm_provider_profiles_key().into(),
                    label: "LLM provider profiles (optional)".into(),
                    value: existing
                        .get(llm_provider_profiles_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "DATA_DIR".into(),
                    label: "Data root directory".into(),
                    value: existing
                        .get("DATA_DIR")
                        .cloned()
                        .unwrap_or_else(default_data_dir_for_setup),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "WORKING_DIR".into(),
                    label: "Working directory".into(),
                    value: existing
                        .get("WORKING_DIR")
                        .cloned()
                        .unwrap_or_else(default_working_dir_for_setup),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "OVERRIDE_TIMEZONE".into(),
                    label: "Override timezone (optional, IANA; default uses system timezone)"
                        .into(),
                    value: existing
                        .get("OVERRIDE_TIMEZONE")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "SOULS_DIR".into(),
                    label: "SOUL files directory (optional)".into(),
                    value: existing
                        .get("SOULS_DIR")
                        .cloned()
                        .unwrap_or_else(default_souls_dir_for_setup),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "SANDBOX_ENABLED".into(),
                    label: "Enable sandbox for bash tool (true/false)".into(),
                    value: existing
                        .get("SANDBOX_ENABLED")
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED".into(),
                    label:
                        "Require explicit confirmation before running high-risk tools (true/false)"
                            .into(),
                    value: existing
                        .get("HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED")
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "REFLECTOR_ENABLED".into(),
                    label: "Memory reflector enabled (true/false)".into(),
                    value: existing
                        .get("REFLECTOR_ENABLED")
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "REFLECTOR_INTERVAL_MINS".into(),
                    label: "Memory reflector interval (minutes)".into(),
                    value: existing
                        .get("REFLECTOR_INTERVAL_MINS")
                        .cloned()
                        .unwrap_or_else(|| "15".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "MEMORY_TOKEN_BUDGET".into(),
                    label: "Memory token budget (structured memories)".into(),
                    value: existing
                        .get("MEMORY_TOKEN_BUDGET")
                        .cloned()
                        .unwrap_or_else(|| "1500".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "EMBEDDING_PROVIDER".into(),
                    label: "Embedding provider (optional: openai/ollama)".into(),
                    value: existing
                        .get("EMBEDDING_PROVIDER")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "EMBEDDING_API_KEY".into(),
                    label: "Embedding API key (optional)".into(),
                    value: existing
                        .get("EMBEDDING_API_KEY")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: "EMBEDDING_BASE_URL".into(),
                    label: "Embedding base URL (optional)".into(),
                    value: existing
                        .get("EMBEDDING_BASE_URL")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "EMBEDDING_MODEL".into(),
                    label: "Embedding model (optional)".into(),
                    value: existing.get("EMBEDDING_MODEL").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "EMBEDDING_DIM".into(),
                    label: "Embedding dimension (optional)".into(),
                    value: existing.get("EMBEDDING_DIM").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
            ],
            selected: 0,
            field_scroll: 0,
            field_window: UI_FIELD_WINDOW,
            visible_cache_sig: Cell::new(u64::MAX),
            visible_cache_indices: RefCell::new(Vec::new()),
            editing: false,
            picker: None,
            status: "Ready. Enter to edit, F2 validate, s save, q quit.".into(),
            completed: false,
            backup_path: None,
            completion_summary: Vec::new(),
            llm_override_page: None,
            llm_override_picker: None,
            provider_preset_page: None,
        };

        for slot in 1..=MAX_BOT_SLOTS {
            app.fields.push(Field {
                key: telegram_slot_id_key(slot),
                label: format!("Telegram bot #{slot}: id"),
                value: existing
                    .get(&telegram_slot_id_key(slot))
                    .cloned()
                    .unwrap_or_else(|| default_slot_account_id(slot)),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_enabled_key(slot),
                label: format!("Telegram bot #{slot}: enabled (true/false)"),
                value: existing
                    .get(&telegram_slot_enabled_key(slot))
                    .cloned()
                    .unwrap_or_else(|| "true".to_string()),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_token_key(slot),
                label: format!("Telegram bot #{slot}: token"),
                value: existing
                    .get(&telegram_slot_token_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: true,
            });
            app.fields.push(Field {
                key: telegram_slot_username_key(slot),
                label: format!("Telegram bot #{slot}: username (no @)"),
                value: existing
                    .get(&telegram_slot_username_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_model_key(slot),
                label: format!("Telegram bot #{slot}: LLM provider profile override (optional)"),
                value: existing
                    .get(&telegram_slot_model_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_soul_path_key(slot),
                label: format!("Telegram bot #{slot}: SOUL.md (optional)"),
                value: existing
                    .get(&telegram_slot_soul_path_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_allowed_user_ids_key(slot),
                label: format!("Telegram bot #{slot}: allowed user ids (csv/array, optional)"),
                value: existing
                    .get(&telegram_slot_allowed_user_ids_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_topic_routing_key(slot),
                label: format!(
                    "Telegram bot #{slot}: topic routing override (optional true/false)"
                ),
                value: existing
                    .get(&telegram_slot_topic_routing_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
        }

        // Generate fields for dynamic channels (slack, feishu, etc.)
        for ch in DYNAMIC_CHANNELS {
            let bot_count_key = dynamic_bot_count_field_key(ch.name);
            app.fields.push(Field {
                key: bot_count_key.clone(),
                label: format!("{} bot count (1-{MAX_BOT_SLOTS})", ch.name),
                value: existing
                    .get(&bot_count_key)
                    .cloned()
                    .unwrap_or_else(|| "1".to_string()),
                required: false,
                secret: false,
            });

            let account_key = dynamic_account_id_field_key(ch.name);
            let account_value = existing
                .get(&account_key)
                .cloned()
                .unwrap_or_else(|| default_account_id().to_string());
            app.fields.push(Field {
                key: account_key.clone(),
                label: format!("{} default account id", ch.name),
                value: account_value,
                required: false,
                secret: false,
            });
            let accounts_json_key = dynamic_accounts_json_field_key(ch.name);
            app.fields.push(Field {
                key: accounts_json_key.clone(),
                label: format!("{} accounts JSON (optional, multi-bot)", ch.name),
                value: existing
                    .get(&accounts_json_key)
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });

            for slot in 1..=MAX_BOT_SLOTS {
                app.fields.push(Field {
                    key: dynamic_slot_id_field_key(ch.name, slot),
                    label: format!("{} bot #{slot}: id", ch.name),
                    value: existing
                        .get(&dynamic_slot_id_field_key(ch.name, slot))
                        .cloned()
                        .unwrap_or_else(|| {
                            if slot == 1 {
                                existing
                                    .get(&account_key)
                                    .cloned()
                                    .unwrap_or_else(|| default_slot_account_id(slot))
                            } else {
                                default_slot_account_id(slot)
                            }
                        }),
                    required: false,
                    secret: false,
                });
                app.fields.push(Field {
                    key: dynamic_slot_enabled_field_key(ch.name, slot),
                    label: format!("{} bot #{slot}: enabled (true/false)", ch.name),
                    value: existing
                        .get(&dynamic_slot_enabled_field_key(ch.name, slot))
                        .cloned()
                        .unwrap_or_else(|| "true".to_string()),
                    required: false,
                    secret: false,
                });
                app.fields.push(Field {
                    key: dynamic_slot_soul_path_field_key(ch.name, slot),
                    label: format!("{} bot #{slot}: SOUL.md (optional)", ch.name),
                    value: existing
                        .get(&dynamic_slot_soul_path_field_key(ch.name, slot))
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                });
                for f in ch.fields {
                    let compact_label = trim_channel_prefix(ch.name, f.label);
                    app.fields.push(Field {
                        key: dynamic_slot_field_key(ch.name, slot, f.yaml_key),
                        label: format!("{} bot #{slot}: {}", ch.name, compact_label),
                        value: existing
                            .get(&dynamic_slot_field_key(ch.name, slot, f.yaml_key))
                            .cloned()
                            .unwrap_or_default(),
                        required: false,
                        secret: f.secret,
                    });
                    if f.yaml_key == "model" {
                        app.fields.push(Field {
                            key: dynamic_slot_llm_provider_key(ch.name, slot),
                            label: format!(
                                "{} bot #{slot}: LLM provider override (optional)",
                                ch.name
                            ),
                            value: existing
                                .get(&dynamic_slot_llm_provider_key(ch.name, slot))
                                .cloned()
                                .unwrap_or_default(),
                            required: false,
                            secret: false,
                        });
                        app.fields.push(Field {
                            key: dynamic_slot_llm_api_key_key(ch.name, slot),
                            label: format!(
                                "{} bot #{slot}: LLM API key override (optional)",
                                ch.name
                            ),
                            value: existing
                                .get(&dynamic_slot_llm_api_key_key(ch.name, slot))
                                .cloned()
                                .unwrap_or_default(),
                            required: false,
                            secret: true,
                        });
                        app.fields.push(Field {
                            key: dynamic_slot_llm_base_url_key(ch.name, slot),
                            label: format!(
                                "{} bot #{slot}: LLM base URL override (optional)",
                                ch.name
                            ),
                            value: existing
                                .get(&dynamic_slot_llm_base_url_key(ch.name, slot))
                                .cloned()
                                .unwrap_or_default(),
                            required: false,
                            secret: false,
                        });
                    }
                }
            }
            for f in ch.fields {
                let key = dynamic_field_key(ch.name, f.yaml_key);
                let value = existing
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| f.default.to_string());
                app.fields.push(Field {
                    key,
                    label: f.label.to_string(),
                    value,
                    required: false,
                    secret: f.secret,
                });
            }
        }

        app.fields
            .sort_by_key(|field| Self::field_display_order(&field.key));
        app
    }

    /// Load existing config values from microclaw.config.yaml/.yml.
    fn load_existing_config() -> HashMap<String, String> {
        let yaml_path = crate::config::Config::config_path_for_setup();

        if yaml_path.exists() {
            if let Ok(content) = fs::read_to_string(&yaml_path) {
                let explicit_enabled_channels = serde_yaml::from_str::<serde_yaml::Value>(&content)
                    .ok()
                    .and_then(|doc| {
                        let channels = doc.get("channels")?.as_mapping()?;
                        let mut enabled = Vec::new();
                        for channel in Self::channel_options() {
                            let is_enabled = channels
                                .get(serde_yaml::Value::String(channel.to_string()))
                                .and_then(|v| v.as_mapping())
                                .and_then(|mapping| {
                                    mapping.get(serde_yaml::Value::String("enabled".to_string()))
                                })
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if is_enabled {
                                enabled.push(channel.to_string());
                            }
                        }
                        Some(enabled)
                    });
                if let Ok(config) = serde_yaml::from_str::<crate::config::Config>(&content) {
                    let mut map = HashMap::new();
                    let mut enabled = explicit_enabled_channels.unwrap_or_default();
                    if enabled.is_empty() {
                        if config.web_enabled {
                            enabled.push("web".to_string());
                        }
                        if !config.telegram_bot_token.trim().is_empty() {
                            enabled.push("telegram".to_string());
                        }
                        if config
                            .discord_bot_token
                            .as_deref()
                            .map(|v| !v.trim().is_empty())
                            .unwrap_or(false)
                        {
                            enabled.push("discord".to_string());
                        }
                    }
                    map.insert("ENABLED_CHANNELS".into(), enabled.join(","));
                    if let Some(web_cfg) = config.channels.get("web").and_then(|v| v.as_mapping()) {
                        if let Some(v) = web_cfg
                            .get(serde_yaml::Value::String("hooks_token".to_string()))
                            .or_else(|| {
                                web_cfg.get(serde_yaml::Value::String("hook_token".to_string()))
                            })
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            map.insert(web_hooks_token_key().into(), v.to_string());
                        }
                        if let Some(v) = web_cfg
                            .get(serde_yaml::Value::String(
                                "hooks_default_session_key".to_string(),
                            ))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            map.insert(web_hooks_default_session_key_key().into(), v.to_string());
                        }
                        if let Some(v) = web_cfg
                            .get(serde_yaml::Value::String(
                                "hooks_allow_request_session_key".to_string(),
                            ))
                            .and_then(|v| v.as_bool())
                        {
                            map.insert(
                                web_hooks_allow_request_session_key_key().into(),
                                v.to_string(),
                            );
                        }
                        if let Some(seq) = web_cfg
                            .get(serde_yaml::Value::String(
                                "hooks_allowed_session_key_prefixes".to_string(),
                            ))
                            .and_then(|v| v.as_sequence())
                        {
                            let prefixes = seq
                                .iter()
                                .filter_map(|item| item.as_str())
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .collect::<Vec<_>>();
                            if !prefixes.is_empty() {
                                map.insert(
                                    web_hooks_allowed_session_key_prefixes_key().into(),
                                    prefixes.join(","),
                                );
                            }
                        }
                    }
                    map.insert(a2a_enabled_key().into(), config.a2a.enabled.to_string());
                    if let Some(v) = config
                        .a2a
                        .public_base_url
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        map.insert(a2a_public_base_url_key().into(), v.to_string());
                    }
                    if let Some(v) = config
                        .a2a
                        .agent_name
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        map.insert(a2a_agent_name_key().into(), v.to_string());
                    }
                    if let Some(v) = config
                        .a2a
                        .agent_description
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        map.insert(a2a_agent_description_key().into(), v.to_string());
                    }
                    if !config.a2a.shared_tokens.is_empty() {
                        map.insert(
                            a2a_shared_tokens_key().into(),
                            config.a2a.shared_tokens.join(","),
                        );
                    }
                    if !config.a2a.peers.is_empty() {
                        let peers_json = serde_yaml::to_value(&config.a2a.peers)
                            .ok()
                            .and_then(|v| compact_json_string(&v));
                        if let Some(peers_json) = peers_json {
                            map.insert(a2a_peers_json_key().into(), peers_json);
                        }
                    }
                    map.insert(
                        subagents_max_concurrent_key().into(),
                        config.subagents.max_concurrent.to_string(),
                    );
                    map.insert(
                        subagents_max_active_per_chat_key().into(),
                        config.subagents.max_active_per_chat.to_string(),
                    );
                    map.insert(
                        subagents_run_timeout_secs_key().into(),
                        config.subagents.run_timeout_secs.to_string(),
                    );
                    map.insert(
                        subagents_announce_to_chat_key().into(),
                        config.subagents.announce_to_chat.to_string(),
                    );
                    map.insert(
                        subagents_max_spawn_depth_key().into(),
                        config.subagents.max_spawn_depth.to_string(),
                    );
                    map.insert(
                        subagents_max_children_per_run_key().into(),
                        config.subagents.max_children_per_run.to_string(),
                    );
                    map.insert(
                        subagents_thread_bound_routing_enabled_key().into(),
                        config.subagents.thread_bound_routing_enabled.to_string(),
                    );
                    map.insert(
                        subagents_announce_relay_interval_secs_key().into(),
                        config.subagents.announce_relay_interval_secs.to_string(),
                    );
                    map.insert(
                        subagents_max_tokens_per_run_key().into(),
                        config.subagents.max_tokens_per_run.to_string(),
                    );
                    map.insert(
                        subagents_orchestrate_max_workers_key().into(),
                        config.subagents.orchestrate_max_workers.to_string(),
                    );
                    map.insert(
                        subagents_acp_enabled_key().into(),
                        config.subagents.acp.default_target.enabled.to_string(),
                    );
                    if !config.subagents.acp.default_target.command.is_empty() {
                        map.insert(
                            subagents_acp_command_key().into(),
                            config.subagents.acp.default_target.command.clone(),
                        );
                    }
                    if !config.subagents.acp.default_target.args.is_empty() {
                        let args_json =
                            serde_json::to_string(&config.subagents.acp.default_target.args).ok();
                        if let Some(args_json) = args_json {
                            map.insert(subagents_acp_args_key().into(), args_json);
                        }
                    }
                    if !config.subagents.acp.default_target.env.is_empty() {
                        let env_json =
                            serde_json::to_string(&config.subagents.acp.default_target.env).ok();
                        if let Some(env_json) = env_json {
                            map.insert(subagents_acp_env_json_key().into(), env_json);
                        }
                    }
                    map.insert(
                        subagents_acp_auto_approve_key().into(),
                        config.subagents.acp.default_target.auto_approve.to_string(),
                    );
                    if let Some(default_target) = config.subagents.acp.default_target_name.clone() {
                        map.insert(subagents_acp_default_target_key().into(), default_target);
                    }
                    if !config.subagents.acp.targets.is_empty() {
                        let targets_json =
                            serde_json::to_string(&config.subagents.acp.targets).ok();
                        if let Some(targets_json) = targets_json {
                            map.insert(subagents_acp_targets_json_key().into(), targets_json);
                        }
                    }
                    let telegram_bot_token = if !config.telegram_bot_token.trim().is_empty() {
                        config.telegram_bot_token
                    } else if let Some(ch_cfg) = config.channels.get("telegram") {
                        channel_default_account_str_value(ch_cfg, "bot_token")
                            .or_else(|| {
                                ch_cfg
                                    .get("bot_token")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|v| !v.is_empty())
                                    .map(ToOwned::to_owned)
                            })
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    let telegram_account_id = config
                        .channels
                        .get("telegram")
                        .and_then(resolve_channel_default_account_id)
                        .unwrap_or_else(|| default_account_id().to_string());
                    let telegram_profile_override = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                                .and_then(|v| {
                                    v.as_str()
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                        .map(ToOwned::to_owned)
                                })
                        })
                        .unwrap_or_default();
                    let telegram_allowed_user_ids = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("allowed_user_ids"))
                        .and_then(|v| v.as_sequence())
                        .map(|seq| {
                            seq.iter()
                                .filter_map(|item| {
                                    item.as_i64()
                                        .map(|id| id.to_string())
                                        .or_else(|| item.as_str().map(|s| s.trim().to_string()))
                                })
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    let telegram_topic_routing = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("topic_routing"))
                        .and_then(|v| v.get("enabled"))
                        .and_then(|v| v.as_bool())
                        .map(|b| b.to_string())
                        .unwrap_or_default();
                    let telegram_llm_provider = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                        })
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_default();
                    let telegram_llm_api_key = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("api_key"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_default();
                    let telegram_llm_base_url = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("llm_base_url"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_default();
                    let telegram_bot_count = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("accounts"))
                        .and_then(|v| v.as_mapping())
                        .map(|m| m.len().max(1))
                        .unwrap_or(1)
                        .min(MAX_BOT_SLOTS);
                    let bot_username = if !config.bot_username.trim().is_empty() {
                        config.bot_username
                    } else if let Some(ch_cfg) = config.channels.get("telegram") {
                        channel_default_account_str_value(ch_cfg, "bot_username")
                            .or_else(|| {
                                ch_cfg
                                    .get("bot_username")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|v| !v.is_empty())
                                    .map(ToOwned::to_owned)
                            })
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    let discord_bot_token = if let Some(v) =
                        config.discord_bot_token.filter(|v| !v.trim().is_empty())
                    {
                        v
                    } else if let Some(ch_cfg) = config.channels.get("discord") {
                        channel_default_account_str_value(ch_cfg, "bot_token")
                            .or_else(|| {
                                ch_cfg
                                    .get("bot_token")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|v| !v.is_empty())
                                    .map(ToOwned::to_owned)
                            })
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    let discord_account_id = config
                        .channels
                        .get("discord")
                        .and_then(resolve_channel_default_account_id)
                        .unwrap_or_else(|| default_account_id().to_string());
                    let discord_profile_override = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                                .and_then(|v| v.as_str())
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .map(ToOwned::to_owned)
                        })
                        .unwrap_or_default();
                    let discord_llm_provider = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                        })
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_default();
                    let discord_llm_api_key = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| ch_cfg.get("api_key"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_default();
                    let discord_llm_base_url = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| ch_cfg.get("llm_base_url"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_default();
                    let discord_accounts_json = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| ch_cfg.get("accounts"))
                        .and_then(compact_json_string)
                        .unwrap_or_default();
                    map.insert("TELEGRAM_BOT_TOKEN".into(), telegram_bot_token.clone());
                    map.insert("TELEGRAM_ACCOUNT_ID".into(), telegram_account_id.clone());
                    map.insert("TELEGRAM_MODEL".into(), telegram_profile_override.clone());
                    map.insert(
                        telegram_allowed_user_ids_key().into(),
                        telegram_allowed_user_ids.clone(),
                    );
                    map.insert(
                        telegram_topic_routing_key().into(),
                        telegram_topic_routing.clone(),
                    );
                    map.insert(
                        telegram_llm_provider_key().into(),
                        telegram_llm_provider.clone(),
                    );
                    map.insert(
                        telegram_llm_api_key_key().into(),
                        telegram_llm_api_key.clone(),
                    );
                    map.insert(
                        telegram_llm_base_url_key().into(),
                        telegram_llm_base_url.clone(),
                    );
                    map.insert(
                        telegram_bot_count_key().into(),
                        telegram_bot_count.to_string(),
                    );
                    if let Some(ch_cfg) = config.channels.get("telegram") {
                        if let Some(accounts) = ch_cfg.get("accounts").and_then(|v| v.as_mapping())
                        {
                            let mut account_ids: Vec<String> = accounts
                                .keys()
                                .filter_map(|k| k.as_str().map(ToOwned::to_owned))
                                .collect();
                            account_ids.sort();
                            if let Some(default_idx) =
                                account_ids.iter().position(|id| id == &telegram_account_id)
                            {
                                let default_id = account_ids.remove(default_idx);
                                account_ids.insert(0, default_id);
                            }
                            for (idx, account_id) in
                                account_ids.into_iter().take(MAX_BOT_SLOTS).enumerate()
                            {
                                let slot = idx + 1;
                                map.insert(telegram_slot_id_key(slot), account_id.clone());
                                if let Some(account) = ch_cfg
                                    .get("accounts")
                                    .and_then(|v| v.get(account_id.as_str()))
                                {
                                    let enabled = account
                                        .get("enabled")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(true);
                                    map.insert(
                                        telegram_slot_enabled_key(slot),
                                        enabled.to_string(),
                                    );
                                    if let Some(v) = account
                                        .get("bot_token")
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(telegram_slot_token_key(slot), v.to_string());
                                    }
                                    if let Some(v) = account
                                        .get("bot_username")
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(telegram_slot_username_key(slot), v.to_string());
                                    }
                                    if let Some(v) = account
                                        .get("provider_preset")
                                        .or_else(|| account.get("llm_provider"))
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(telegram_slot_model_key(slot), v.to_string());
                                    }
                                    if let Some(v) = account
                                        .get("soul_path")
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            telegram_slot_soul_path_key(slot),
                                            v.to_string(),
                                        );
                                    }
                                    if let Some(v) = account.get("allowed_user_ids") {
                                        let mut ids = Vec::new();
                                        if let Some(seq) = v.as_sequence() {
                                            for item in seq {
                                                if let Some(id) = item.as_i64() {
                                                    ids.push(id.to_string());
                                                } else if let Some(s) = item.as_str() {
                                                    let t = s.trim();
                                                    if !t.is_empty() {
                                                        ids.push(t.to_string());
                                                    }
                                                }
                                            }
                                        }
                                        if !ids.is_empty() {
                                            map.insert(
                                                telegram_slot_allowed_user_ids_key(slot),
                                                ids.join(","),
                                            );
                                        }
                                    }
                                    if let Some(v) = account
                                        .get("topic_routing")
                                        .and_then(|v| v.get("enabled"))
                                        .and_then(|v| v.as_bool())
                                    {
                                        map.insert(
                                            telegram_slot_topic_routing_key(slot),
                                            v.to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    map.insert("BOT_USERNAME".into(), bot_username.clone());
                    // Backward compatibility: when Telegram has only legacy top-level values,
                    // prefill slot #1 so setup UI can edit in slot form only.
                    if map
                        .get(&telegram_slot_id_key(1))
                        .map(|v| v.trim().is_empty())
                        .unwrap_or(true)
                    {
                        map.insert(telegram_slot_id_key(1), telegram_account_id.clone());
                    }
                    if map
                        .get(&telegram_slot_token_key(1))
                        .map(|v| v.trim().is_empty())
                        .unwrap_or(true)
                        && !telegram_bot_token.trim().is_empty()
                    {
                        map.insert(telegram_slot_token_key(1), telegram_bot_token.clone());
                    }
                    if map
                        .get(&telegram_slot_username_key(1))
                        .map(|v| v.trim().is_empty())
                        .unwrap_or(true)
                        && !bot_username.trim().is_empty()
                    {
                        map.insert(telegram_slot_username_key(1), bot_username.clone());
                    }
                    map.insert("DISCORD_BOT_TOKEN".into(), discord_bot_token);
                    map.insert("DISCORD_ACCOUNT_ID".into(), discord_account_id);
                    map.insert("DISCORD_MODEL".into(), discord_profile_override);
                    map.insert(discord_llm_provider_key().into(), discord_llm_provider);
                    map.insert(discord_llm_api_key_key().into(), discord_llm_api_key);
                    map.insert(discord_llm_base_url_key().into(), discord_llm_base_url);
                    map.insert("DISCORD_ACCOUNTS_JSON".into(), discord_accounts_json);
                    // Extract dynamic channel configs
                    for ch in DYNAMIC_CHANNELS {
                        if let Some(ch_map) = config.channels.get(ch.name) {
                            let account_key = dynamic_account_id_field_key(ch.name);
                            let account_id = resolve_channel_default_account_id(ch_map)
                                .unwrap_or_else(|| default_account_id().to_string());
                            map.insert(account_key, account_id);
                            let bot_count_key = dynamic_bot_count_field_key(ch.name);
                            if let Some(accounts_json) =
                                ch_map.get("accounts").and_then(compact_json_string)
                            {
                                map.insert(dynamic_accounts_json_field_key(ch.name), accounts_json);
                            }
                            if let Some(accounts) =
                                ch_map.get("accounts").and_then(|v| v.as_mapping())
                            {
                                let mut account_ids: Vec<String> = accounts
                                    .keys()
                                    .filter_map(|k| k.as_str().map(ToOwned::to_owned))
                                    .collect();
                                account_ids.sort();
                                let default_id = resolve_channel_default_account_id(ch_map);
                                if let Some(default_id) = default_id {
                                    if let Some(idx) =
                                        account_ids.iter().position(|id| id == &default_id)
                                    {
                                        let first = account_ids.remove(idx);
                                        account_ids.insert(0, first);
                                    }
                                }
                                let used = account_ids.len().clamp(1, MAX_BOT_SLOTS);
                                map.insert(bot_count_key, used.to_string());
                                for (idx, id) in
                                    account_ids.into_iter().take(MAX_BOT_SLOTS).enumerate()
                                {
                                    let slot = idx + 1;
                                    map.insert(
                                        dynamic_slot_id_field_key(ch.name, slot),
                                        id.clone(),
                                    );
                                    let account =
                                        ch_map.get("accounts").and_then(|v| v.get(id.as_str()));
                                    let enabled = account
                                        .and_then(|a| a.get("enabled"))
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(true);
                                    map.insert(
                                        dynamic_slot_enabled_field_key(ch.name, slot),
                                        enabled.to_string(),
                                    );
                                    for f in ch.fields {
                                        let value =
                                            account.and_then(|a| a.get(f.yaml_key)).and_then(|v| {
                                                if let Some(s) = v.as_str() {
                                                    let trimmed = s.trim();
                                                    if trimmed.is_empty() {
                                                        None
                                                    } else {
                                                        Some(trimmed.to_string())
                                                    }
                                                } else {
                                                    v.as_bool().map(|b| b.to_string()).or_else(
                                                        || v.as_u64().map(|n| n.to_string()),
                                                    )
                                                }
                                            });
                                        if let Some(v) = value {
                                            map.insert(
                                                dynamic_slot_field_key(ch.name, slot, f.yaml_key),
                                                v,
                                            );
                                        }
                                    }
                                    if let Some(v) = account
                                        .and_then(|a| a.get("soul_path"))
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            dynamic_slot_soul_path_field_key(ch.name, slot),
                                            v.to_string(),
                                        );
                                    }
                                    if let Some(v) = account
                                        .and_then(|a| {
                                            a.get("provider_preset")
                                                .or_else(|| a.get("llm_provider"))
                                        })
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            dynamic_slot_llm_provider_key(ch.name, slot),
                                            v.to_string(),
                                        );
                                    }
                                    if let Some(v) = account
                                        .and_then(|a| a.get("api_key"))
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            dynamic_slot_llm_api_key_key(ch.name, slot),
                                            v.to_string(),
                                        );
                                    }
                                    if let Some(v) = account
                                        .and_then(|a| a.get("llm_base_url"))
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            dynamic_slot_llm_base_url_key(ch.name, slot),
                                            v.to_string(),
                                        );
                                    }
                                }
                            }
                            for f in ch.fields {
                                let value = channel_default_account_str_value(ch_map, f.yaml_key)
                                    .or_else(|| {
                                        ch_map.get(f.yaml_key).and_then(|v| {
                                            if let Some(s) = v.as_str() {
                                                let trimmed = s.trim();
                                                if trimmed.is_empty() {
                                                    None
                                                } else {
                                                    Some(trimmed.to_string())
                                                }
                                            } else {
                                                v.as_bool()
                                                    .map(|b| b.to_string())
                                                    .or_else(|| v.as_u64().map(|n| n.to_string()))
                                            }
                                        })
                                    });
                                if let Some(v) = value {
                                    let key = dynamic_field_key(ch.name, f.yaml_key);
                                    map.insert(key, v);
                                }
                            }
                        }
                    }
                    map.insert("LLM_PROVIDER".into(), config.llm_provider);
                    map.insert("LLM_API_KEY".into(), config.api_key);
                    if !config.model.is_empty() {
                        map.insert("LLM_MODEL".into(), config.model);
                    }
                    if let Some(url) = config.llm_base_url {
                        map.insert("LLM_BASE_URL".into(), url);
                    }
                    if config.llm_user_agent != crate::http_client::default_llm_user_agent() {
                        map.insert("LLM_USER_AGENT".into(), config.llm_user_agent);
                    }
                    let presets_for_setup = if !config.provider_presets.is_empty() {
                        config.provider_presets.clone()
                    } else {
                        config
                            .llm_providers
                            .clone()
                            .into_iter()
                            .filter(|(alias, _)| !alias.eq_ignore_ascii_case("main"))
                            .collect()
                    };
                    if !presets_for_setup.is_empty() {
                        let presets_json = serde_json::to_string(&presets_for_setup).ok();
                        if let Some(presets_json) = presets_json {
                            map.insert(llm_provider_profiles_key().into(), presets_json);
                        }
                    }
                    map.insert("SHOW_THINKING".into(), config.show_thinking.to_string());
                    map.insert("DATA_DIR".into(), config.data_dir);
                    map.insert(
                        "OVERRIDE_TIMEZONE".into(),
                        config.override_timezone.clone().unwrap_or_default(),
                    );
                    map.insert("WORKING_DIR".into(), config.working_dir);
                    if let Some(v) = config.souls_dir {
                        map.insert("SOULS_DIR".into(), v);
                    }
                    map.insert(
                        "SANDBOX_ENABLED".into(),
                        (config.sandbox.mode == crate::config::SandboxMode::All).to_string(),
                    );
                    map.insert(
                        "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED".into(),
                        config.high_risk_tool_user_confirmation_required.to_string(),
                    );
                    map.insert(
                        "REFLECTOR_ENABLED".into(),
                        config.reflector_enabled.to_string(),
                    );
                    map.insert(
                        "REFLECTOR_INTERVAL_MINS".into(),
                        config.reflector_interval_mins.to_string(),
                    );
                    map.insert(
                        "MEMORY_TOKEN_BUDGET".into(),
                        config.memory_token_budget.to_string(),
                    );
                    if let Some(v) = config.embedding_provider {
                        map.insert("EMBEDDING_PROVIDER".into(), v);
                    }
                    if let Some(v) = config.embedding_api_key {
                        map.insert("EMBEDDING_API_KEY".into(), v);
                    }
                    if let Some(v) = config.embedding_base_url {
                        map.insert("EMBEDDING_BASE_URL".into(), v);
                    }
                    if let Some(v) = config.embedding_model {
                        map.insert("EMBEDDING_MODEL".into(), v);
                    }
                    if let Some(v) = config.embedding_dim {
                        map.insert("EMBEDDING_DIM".into(), v.to_string());
                    }
                    return map;
                }
            }
        }

        HashMap::new()
    }

    fn next(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        if let Some(pos) = visible.iter().position(|idx| *idx == self.selected) {
            if pos + 1 < visible.len() {
                self.selected = visible[pos + 1];
            }
        } else {
            self.selected = visible[0];
        }
        self.adjust_field_scroll(self.field_window.max(1));
    }

    fn prev(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        if let Some(pos) = visible.iter().position(|idx| *idx == self.selected) {
            if pos > 0 {
                self.selected = visible[pos - 1];
            }
        } else {
            self.selected = visible[0];
        }
        self.adjust_field_scroll(self.field_window.max(1));
    }

    fn selected_field_mut(&mut self) -> &mut Field {
        self.ensure_selected_visible();
        &mut self.fields[self.selected]
    }

    fn selected_field(&self) -> &Field {
        if self.selected < self.fields.len()
            && self.is_field_visible(&self.fields[self.selected].key)
        {
            return &self.fields[self.selected];
        }
        if let Some(first_visible) = self.visible_field_indices().first().copied() {
            return &self.fields[first_visible];
        }
        &self.fields[self.selected]
    }

    fn field_value(&self, key: &str) -> String {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default()
    }

    fn souls_dir_value(&self) -> String {
        let configured = self.field_value("SOULS_DIR");
        if !configured.is_empty() {
            return configured;
        }
        let data_dir = self.field_value("DATA_DIR");
        if data_dir.is_empty() {
            return default_souls_dir_for_setup();
        }
        Path::new(&data_dir)
            .join("souls")
            .to_string_lossy()
            .to_string()
    }

    fn normalize_soul_path_value(&self, raw: &str) -> String {
        normalize_soul_path_input(raw, &self.souls_dir_value())
    }

    fn set_field_value(&mut self, key: &str, value: String) {
        if let Some(field) = self.fields.iter_mut().find(|f| f.key == key) {
            field.value = if key == "LLM_PROVIDER" {
                normalize_setup_provider_id(&value)
            } else {
                value
            };
        }
    }

    fn llm_provider_presets(&self) -> HashMap<String, LlmProviderProfile> {
        parse_provider_presets_json_value(
            &self.field_value(llm_provider_profiles_key()),
            llm_provider_profiles_key(),
        )
        .unwrap_or_default()
    }

    fn provider_preset_drafts(&self) -> Vec<ProviderPresetDraft> {
        let mut entries: Vec<(String, LlmProviderProfile)> =
            self.llm_provider_presets().into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
            .into_iter()
            .map(|(id, profile)| ProviderPresetDraft {
                id,
                provider: profile.provider.unwrap_or_default(),
                api_key: profile.api_key.unwrap_or_default(),
                base_url: profile.llm_base_url.unwrap_or_default(),
                user_agent: profile.llm_user_agent.unwrap_or_default(),
                default_model: profile.default_model.unwrap_or_default(),
                show_thinking: profile.show_thinking.unwrap_or(false),
            })
            .collect()
    }

    fn serialize_provider_preset_drafts(
        drafts: &[ProviderPresetDraft],
    ) -> Result<String, MicroClawError> {
        let mut presets = HashMap::new();
        for draft in drafts {
            let id = draft.id.trim().to_ascii_lowercase();
            if id.is_empty() {
                continue;
            }
            if id == "main" {
                return Err(MicroClawError::Config(
                    "provider preset id 'main' is reserved for the global default".into(),
                ));
            }
            if !is_valid_account_id(&id) {
                return Err(MicroClawError::Config(format!(
                    "provider preset id '{id}' must use only letters, numbers, '_' or '-'"
                )));
            }
            let profile = LlmProviderProfile {
                provider: Some(draft.provider.trim().to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
                api_key: Some(draft.api_key.trim().to_string()).filter(|v| !v.is_empty()),
                llm_base_url: Some(draft.base_url.trim().to_string()).filter(|v| !v.is_empty()),
                llm_user_agent: Some(draft.user_agent.trim().to_string()).filter(|v| !v.is_empty()),
                default_model: Some(draft.default_model.trim().to_string())
                    .filter(|v| !v.is_empty()),
                models: Vec::new(),
                show_thinking: Some(draft.show_thinking),
            };
            presets.insert(id, profile);
        }
        serde_json::to_string(&presets).map_err(|e| {
            MicroClawError::Config(format!("Failed to serialize provider profiles: {e}"))
        })
    }

    fn sync_provider_preset_page_field(&mut self) -> Result<(), MicroClawError> {
        let Some(page) = self.provider_preset_page.as_ref() else {
            return Ok(());
        };
        let json = Self::serialize_provider_preset_drafts(&page.entries)?;
        self.set_field_value(llm_provider_profiles_key(), json);
        Ok(())
    }

    fn next_provider_preset_id(entries: &[ProviderPresetDraft]) -> String {
        let mut used = entries
            .iter()
            .map(|entry| entry.id.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        used.sort();
        for idx in 1usize.. {
            let candidate = format!("provider{idx}");
            if !used.iter().any(|id| id == &candidate) {
                return candidate;
            }
        }
        "provider1".to_string()
    }

    fn next_cloned_provider_preset_id(entries: &[ProviderPresetDraft], source_id: &str) -> String {
        let base = source_id.trim().to_ascii_lowercase();
        if base.is_empty() {
            return Self::next_provider_preset_id(entries);
        }
        let used = entries
            .iter()
            .map(|entry| entry.id.trim().to_ascii_lowercase())
            .collect::<std::collections::HashSet<_>>();
        for idx in 2usize.. {
            let candidate = format!("{base}-{idx}");
            if !used.contains(&candidate) {
                return candidate;
            }
        }
        format!("{base}-2")
    }

    fn open_provider_preset_page(&mut self) {
        self.provider_preset_page = Some(ProviderPresetPage {
            entries: self.provider_preset_drafts(),
            selected: 0,
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });
        self.status = "Editing provider profiles".to_string();
    }

    fn provider_preset_references(&self, preset_id: &str) -> Vec<String> {
        let needle = preset_id.trim();
        if needle.is_empty() {
            return Vec::new();
        }
        let mut refs = Vec::new();
        if self
            .field_value(telegram_llm_provider_key())
            .eq_ignore_ascii_case(needle)
        {
            refs.push("telegram channel".to_string());
        }
        if self
            .field_value(discord_llm_provider_key())
            .eq_ignore_ascii_case(needle)
        {
            refs.push("discord channel".to_string());
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if self
                .field_value(&telegram_slot_model_key(slot))
                .eq_ignore_ascii_case(needle)
            {
                let id = self.field_value(&telegram_slot_id_key(slot));
                let label = if id.trim().is_empty() {
                    format!("telegram.bot{slot}")
                } else {
                    format!("telegram.{}", id.trim())
                };
                refs.push(label);
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = dynamic_slot_llm_provider_key(ch.name, slot);
                if self.field_value(&key).eq_ignore_ascii_case(needle) {
                    let id = self.field_value(&dynamic_slot_id_field_key(ch.name, slot));
                    let label = if id.trim().is_empty() {
                        format!("{}.bot{}", ch.name, slot)
                    } else {
                        format!("{}.{}", ch.name, id.trim())
                    };
                    refs.push(label);
                }
            }
        }
        refs.sort();
        refs.dedup();
        refs
    }

    fn provider_preset_reference_summary(&self, preset_id: &str) -> String {
        let refs = self.provider_preset_references(preset_id);
        if refs.is_empty() {
            "unused".to_string()
        } else {
            format!("{} ref(s)", refs.len())
        }
    }

    fn provider_preset_field_labels() -> [&'static str; 7] {
        [
            "Preset ID",
            "Provider",
            "API key",
            "Default model",
            "Base URL",
            "Show thinking",
            "User-Agent (optional)",
        ]
    }

    fn provider_preset_selected_field_value(page: &ProviderPresetPage) -> String {
        let Some(entry) = page.entries.get(page.selected) else {
            return String::new();
        };
        match page.field_selected {
            0 => entry.id.clone(),
            1 => entry.provider.clone(),
            2 => entry.api_key.clone(),
            3 => entry.default_model.clone(),
            4 => entry.base_url.clone(),
            5 => entry.show_thinking.to_string(),
            6 => entry.user_agent.clone(),
            _ => String::new(),
        }
    }

    fn rename_provider_preset_references(&mut self, old_id: &str, new_id: &str) -> usize {
        let old_id = old_id.trim();
        if old_id.is_empty() || old_id.eq_ignore_ascii_case(new_id.trim()) {
            return 0;
        }
        let mut updated = 0usize;
        let mut maybe_replace = |key: &str, this: &mut SetupApp| {
            if this.field_value(key).eq_ignore_ascii_case(old_id) {
                this.set_field_value(key, new_id.trim().to_string());
                updated += 1;
            }
        };
        maybe_replace(telegram_llm_provider_key(), self);
        maybe_replace(discord_llm_provider_key(), self);
        for slot in 1..=MAX_BOT_SLOTS {
            maybe_replace(&telegram_slot_model_key(slot), self);
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = dynamic_slot_llm_provider_key(ch.name, slot);
                maybe_replace(&key, self);
            }
        }
        updated
    }

    fn selected_provider_preset_id(&self) -> Option<String> {
        self.provider_preset_page
            .as_ref()
            .and_then(|page| page.entries.get(page.selected))
            .map(|entry| entry.id.trim().to_string())
            .filter(|id| !id.is_empty())
    }

    fn clone_selected_provider_preset(&mut self) -> Result<Option<String>, MicroClawError> {
        let Some(page) = self.provider_preset_page.as_mut() else {
            return Ok(None);
        };
        let Some(selected_entry) = page.entries.get(page.selected).cloned() else {
            return Ok(None);
        };
        let mut cloned = selected_entry.clone();
        cloned.id = Self::next_cloned_provider_preset_id(&page.entries, &selected_entry.id);
        page.entries.push(cloned.clone());
        page.selected = page.entries.len().saturating_sub(1);
        page.mode = ProviderPresetPageMode::Edit;
        page.field_selected = 3;
        page.editing = false;
        self.sync_provider_preset_page_field()?;
        Ok(Some(cloned.id))
    }

    fn delete_selected_provider_preset(
        &mut self,
        fallback_to_main: bool,
    ) -> Result<Vec<String>, MicroClawError> {
        let Some(preset_id) = self.selected_provider_preset_id() else {
            return Ok(Vec::new());
        };
        let refs = self.provider_preset_references(&preset_id);
        if !refs.is_empty() && !fallback_to_main {
            return Err(MicroClawError::Config(format!(
                "Preset '{preset_id}' is still referenced by {}. Press x to reset those references to main and delete it.",
                refs.join(", ")
            )));
        }
        let reset_refs = if fallback_to_main { refs } else { Vec::new() };
        if fallback_to_main {
            self.rename_provider_preset_references(&preset_id, "");
        }
        if let Some(page) = self.provider_preset_page.as_mut() {
            if page.selected < page.entries.len() {
                page.entries.remove(page.selected);
                if page.selected >= page.entries.len() && !page.entries.is_empty() {
                    page.selected = page.entries.len() - 1;
                }
            }
        }
        self.sync_provider_preset_page_field()?;
        Ok(reset_refs)
    }

    fn set_provider_preset_selected_field_value(&mut self, value: String) {
        let mut old_id = String::new();
        let mut rename_target = false;
        let new_value_for_rename = value.clone();
        if let Some(page) = self.provider_preset_page.as_ref() {
            if page.field_selected == 0 {
                old_id = Self::provider_preset_selected_field_value(page);
                rename_target = true;
            }
        }
        if let Some(page) = self.provider_preset_page.as_mut() {
            let Some(entry) = page.entries.get_mut(page.selected) else {
                return;
            };
            match page.field_selected {
                0 => entry.id = value.clone(),
                1 => entry.provider = value,
                2 => entry.api_key = value,
                3 => entry.default_model = value,
                4 => entry.base_url = value,
                5 => entry.show_thinking = parse_bool_like(&value).unwrap_or(false),
                6 => entry.user_agent = value,
                _ => {}
            }
        }
        if rename_target {
            self.rename_provider_preset_references(&old_id, &new_value_for_rename);
        }
    }

    fn toggle_selected_provider_preset_show_thinking(&mut self) {
        if let Some(page) = self.provider_preset_page.as_mut() {
            let Some(entry) = page.entries.get_mut(page.selected) else {
                return;
            };
            entry.show_thinking = !entry.show_thinking;
        }
    }

    fn clear_selected_provider_preset_field(&mut self) {
        self.set_provider_preset_selected_field_value(String::new());
    }

    fn provider_preset_selected_field_default(&self) -> Option<String> {
        let page = self.provider_preset_page.as_ref()?;
        let entry = page.entries.get(page.selected)?;
        match page.field_selected {
            0 => Some(SetupApp::next_provider_preset_id(&page.entries)),
            1 => Some("anthropic".to_string()),
            2 => Some(String::new()),
            3 => Some(default_model_for_provider(&entry.provider).to_string()),
            4 => Some(
                find_provider_preset(&entry.provider)
                    .map(|preset| preset.default_base_url.to_string())
                    .unwrap_or_default(),
            ),
            5 => Some("false".to_string()),
            6 => Some(String::new()),
            _ => None,
        }
    }

    fn restore_selected_provider_preset_field_default(&mut self) -> Option<String> {
        let default = self.provider_preset_selected_field_default()?;
        self.set_provider_preset_selected_field_value(default.clone());
        Some(default)
    }

    fn open_provider_preset_provider_picker(&mut self) {
        let Some(page) = self.provider_preset_page.as_ref() else {
            return;
        };
        let current = page
            .entries
            .get(page.selected)
            .map(|entry| entry.provider.clone())
            .unwrap_or_default();
        let mut options = PROVIDER_PRESETS
            .iter()
            .map(|preset| {
                (
                    format!("{} - {}", preset.id, preset.label),
                    preset.id.to_string(),
                )
            })
            .collect::<Vec<_>>();
        if !current.trim().is_empty()
            && !options
                .iter()
                .any(|(_, value)| value.eq_ignore_ascii_case(current.trim()))
        {
            options.push((
                format!("{} - legacy/manual", current.trim()),
                current.clone(),
            ));
        }
        let selected = options
            .iter()
            .position(|(_, value)| value.eq_ignore_ascii_case(current.trim()))
            .unwrap_or(0);
        if let Some(page_mut) = self.provider_preset_page.as_mut() {
            page_mut.picker = Some(LlmOverridePicker {
                title: "Select Provider".to_string(),
                target_key: "provider".to_string(),
                options,
                selected,
            });
        }
    }

    fn open_provider_preset_model_picker(&mut self) {
        let (provider_value, current_default_model) = {
            let Some(page) = self.provider_preset_page.as_ref() else {
                return;
            };
            let Some(entry) = page.entries.get(page.selected) else {
                return;
            };
            (entry.provider.clone(), entry.default_model.clone())
        };
        let provider = provider_value.trim().to_string();
        let Some(preset) = find_provider_preset(&provider) else {
            if let Some(page_mut) = self.provider_preset_page.as_mut() {
                page_mut.editing = true;
            }
            self.status = "Unknown provider; switched to manual model input".to_string();
            return;
        };
        let mut options = if is_placeholder_provider_model_list(preset.models) {
            Vec::new()
        } else {
            preset
                .models
                .iter()
                .map(|model| ((*model).to_string(), (*model).to_string()))
                .collect::<Vec<_>>()
        };
        options.push((
            MODEL_PICKER_MANUAL_INPUT.to_string(),
            MODEL_PICKER_MANUAL_INPUT.to_string(),
        ));
        let selected = options
            .iter()
            .position(|(_, value)| value == &current_default_model)
            .unwrap_or(options.len().saturating_sub(1));
        if let Some(page_mut) = self.provider_preset_page.as_mut() {
            page_mut.picker = Some(LlmOverridePicker {
                title: format!("Select Model ({provider})"),
                target_key: "default_model".to_string(),
                options,
                selected,
            });
        }
    }

    fn apply_provider_preset_picker_selection(&mut self) {
        let status = {
            let Some(page) = self.provider_preset_page.as_mut() else {
                return;
            };
            let Some(picker) = page.picker.take() else {
                return;
            };
            let Some((_, value)) = picker.options.get(picker.selected) else {
                return;
            };
            if value == MODEL_PICKER_MANUAL_INPUT {
                page.editing = true;
                page.field_selected = 3;
                self.status = "Editing default model (manual input)".to_string();
                return;
            }
            let Some(entry) = page.entries.get_mut(page.selected) else {
                return;
            };
            match picker.target_key.as_str() {
                "provider" => {
                    let old_provider = entry.provider.clone();
                    let old_base_url = entry.base_url.clone();
                    let old_model = entry.default_model.clone();
                    entry.provider = value.clone();
                    let old_default_base_url = find_provider_preset(&old_provider)
                        .map(|preset| preset.default_base_url)
                        .unwrap_or("");
                    let next_default_base_url = find_provider_preset(value)
                        .map(|preset| preset.default_base_url)
                        .unwrap_or("");
                    if old_base_url.trim().is_empty() || old_base_url == old_default_base_url {
                        entry.base_url = next_default_base_url.to_string();
                    }
                    let old_model_in_old_preset = find_provider_preset(&old_provider)
                        .map(|preset| preset.models.iter().any(|model| *model == old_model))
                        .unwrap_or(false);
                    if old_model.trim().is_empty() || old_model_in_old_preset {
                        entry.default_model = default_model_for_provider(value).to_string();
                    }
                }
                "default_model" => entry.default_model = value.clone(),
                _ => {}
            }
            Some(format!("Updated provider preset {}", entry.id))
        };
        let _ = self.sync_provider_preset_page_field();
        if let Some(status) = status {
            self.status = status;
        }
    }

    fn handle_provider_preset_enter(&mut self) {
        let selected_field = self
            .provider_preset_page
            .as_ref()
            .map(|page| page.field_selected)
            .unwrap_or(0);
        let editing = self
            .provider_preset_page
            .as_ref()
            .map(|page| page.editing)
            .unwrap_or(false);
        if editing {
            if let Some(page) = self.provider_preset_page.as_mut() {
                page.editing = false;
            }
            let _ = self.sync_provider_preset_page_field();
            self.status = "Updated provider profile field".into();
            return;
        }

        match selected_field {
            1 => self.open_provider_preset_provider_picker(),
            3 => self.open_provider_preset_model_picker(),
            5 => {
                self.toggle_selected_provider_preset_show_thinking();
                let _ = self.sync_provider_preset_page_field();
                self.status = "Toggled provider profile show_thinking".into();
            }
            _ => {
                if let Some(page) = self.provider_preset_page.as_mut() {
                    page.editing = true;
                    self.status = "Editing provider profile field".into();
                }
            }
        }
    }

    fn llm_provider_preset_choices(&self, current: &str) -> Vec<(String, String)> {
        let mut options = vec![("main (global default)".to_string(), String::new())];
        let mut presets: Vec<(String, LlmProviderProfile)> =
            self.llm_provider_presets().into_iter().collect();
        presets.sort_by(|a, b| a.0.cmp(&b.0));
        for (preset_id, profile) in presets {
            let provider = profile.provider.unwrap_or_else(|| preset_id.clone());
            let model = profile.default_model.unwrap_or_default();
            let suffix = if model.is_empty() {
                provider
            } else {
                format!("{provider} / {model}")
            };
            options.push((format!("{preset_id} - {suffix}"), preset_id));
        }
        let trimmed_current = current.trim();
        if !trimmed_current.is_empty()
            && !options
                .iter()
                .any(|(_, value)| value.eq_ignore_ascii_case(trimmed_current))
        {
            options.push((
                format!("{trimmed_current} - legacy/manual"),
                trimmed_current.to_string(),
            ));
        }
        options
    }

    fn llm_override_uses_legacy_fields(
        &self,
        provider_key: &str,
        api_key_key: &str,
        base_url_key: &str,
    ) -> bool {
        let provider = self.field_value(provider_key);
        let api_key = self.field_value(api_key_key);
        let base_url = self.field_value(base_url_key);
        if !api_key.is_empty() || !base_url.is_empty() {
            return true;
        }
        let provider = provider.trim();
        if provider.is_empty() {
            return false;
        }
        !self
            .llm_provider_presets()
            .keys()
            .any(|preset| preset.eq_ignore_ascii_case(provider))
    }

    fn llm_override_label_for_key(key: &str) -> &'static str {
        match key {
            "TELEGRAM_LLM_PROVIDER" => "Preset ID (optional; main=global)",
            "TELEGRAM_LLM_API_KEY" => "API key (optional)",
            "TELEGRAM_LLM_BASE_URL" => "Base URL (optional)",
            "DISCORD_LLM_PROVIDER" => "Preset ID (optional; main=global)",
            "DISCORD_LLM_API_KEY" => "API key (optional)",
            "DISCORD_LLM_BASE_URL" => "Base URL (optional)",
            "TELEGRAM_MODEL" => "Preset ID (optional; main=global)",
            "DISCORD_MODEL" => "Preset ID (optional; main=global)",
            _ if key.ends_with("_LLM_PROVIDER") => "Preset ID (optional; main=global)",
            _ if key.ends_with("_LLM_API_KEY") => "API key (optional)",
            _ if key.ends_with("_LLM_BASE_URL") => "Base URL (optional)",
            _ if key.ends_with("_MODEL") => "Preset ID (optional; main=global)",
            _ => "Value",
        }
    }

    fn open_llm_override_page(
        &mut self,
        title: String,
        provider_key: String,
        api_key_key: String,
        base_url_key: String,
    ) {
        let show_legacy_fields =
            self.llm_override_uses_legacy_fields(&provider_key, &api_key_key, &base_url_key);
        if !show_legacy_fields {
            self.llm_override_page = None;
            self.open_llm_override_provider_picker_for_key(&provider_key);
            self.status = "Selecting LLM provider profile override".to_string();
            return;
        }
        self.llm_override_page = Some(LlmOverridePage {
            title,
            provider_key,
            api_key_key,
            base_url_key,
            show_legacy_fields,
            selected: 0,
            editing: false,
        });
        self.open_llm_override_provider_picker();
        self.status = "Selecting LLM provider profile override".to_string();
    }

    fn open_llm_override_provider_picker(&mut self) {
        let Some(provider_key) = self
            .llm_override_page
            .as_ref()
            .map(|page| page.provider_key.clone())
        else {
            return;
        };
        self.open_llm_override_provider_picker_for_key(&provider_key);
    }

    fn open_llm_override_provider_picker_for_key(&mut self, target_key: &str) {
        let current = self.field_value(target_key);
        let options = self.llm_provider_preset_choices(&current);
        let selected = options
            .iter()
            .position(|(_, value)| value.eq_ignore_ascii_case(&current))
            .unwrap_or(0);
        self.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: target_key.to_string(),
            options,
            selected,
        });
    }

    fn apply_llm_override_picker_selection(&mut self) {
        let Some(picker) = self.llm_override_picker.take() else {
            return;
        };
        let Some((_, value)) = picker.options.get(picker.selected) else {
            return;
        };
        let old_value = self.field_value(&picker.target_key);
        self.set_field_value(&picker.target_key, value.clone());
        // Sync related legacy keys so save_config_yaml does not fall back to
        // a stale value.
        if let Some(related_keys) =
            Self::llm_override_related_keys_for_model_field(&picker.target_key)
        {
            for key in &related_keys {
                if key != &picker.target_key {
                    self.set_field_value(key, value.clone());
                }
            }
        }
        // When a channel-level override changes, also update any bot-slot
        // fields that still carry the old (inherited) value so that save does
        // not write the stale override back into the per-account config.
        if picker.target_key == "TELEGRAM_MODEL" {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = telegram_slot_model_key(slot);
                if self.field_value(&key) == old_value {
                    self.set_field_value(&key, value.clone());
                }
            }
        } else if picker.target_key == "DISCORD_MODEL" {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = dynamic_slot_field_key("discord", slot, "model");
                if self.field_value(&key) == old_value {
                    self.set_field_value(&key, value.clone());
                }
            }
        }
        let close_after_select = self
            .llm_override_page
            .as_ref()
            .map(|page| !page.show_legacy_fields)
            .unwrap_or(false);
        if close_after_select {
            self.llm_override_page = None;
        }
        self.status = if value.trim().is_empty() {
            "Selected main (global default)".to_string()
        } else {
            format!("Selected provider profile: {value}")
        };
    }

    fn llm_override_keys_for_page(page: &LlmOverridePage) -> Vec<&str> {
        let mut keys = vec![page.provider_key.as_str()];
        if page.show_legacy_fields {
            keys.push(page.api_key_key.as_str());
            keys.push(page.base_url_key.as_str());
        }
        keys
    }

    fn open_llm_override_page_for_field(&mut self, field_key: &str) -> bool {
        if field_key == "TELEGRAM_MODEL" {
            self.open_llm_override_page(
                "Telegram Channel LLM Override".to_string(),
                "TELEGRAM_MODEL".to_string(),
                telegram_llm_api_key_key().to_string(),
                telegram_llm_base_url_key().to_string(),
            );
            return true;
        }
        if field_key == "DISCORD_MODEL" {
            self.open_llm_override_page(
                "Discord Channel LLM Override".to_string(),
                "DISCORD_MODEL".to_string(),
                discord_llm_api_key_key().to_string(),
                discord_llm_base_url_key().to_string(),
            );
            return true;
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if field_key == telegram_slot_model_key(slot) {
                self.open_llm_override_page(
                    format!("Telegram Bot #{slot} LLM Override"),
                    telegram_slot_model_key(slot),
                    dynamic_slot_llm_api_key_key("telegram", slot),
                    dynamic_slot_llm_base_url_key("telegram", slot),
                );
                return true;
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let model_key = dynamic_slot_field_key(ch.name, slot, "model");
                if field_key == model_key {
                    self.open_llm_override_page(
                        format!("{} bot #{slot} LLM Override", ch.name),
                        model_key.clone(),
                        dynamic_slot_llm_api_key_key(ch.name, slot),
                        dynamic_slot_llm_base_url_key(ch.name, slot),
                    );
                    return true;
                }
            }
        }
        false
    }

    fn llm_provider_key_for_model_field(field_key: &str) -> Option<String> {
        if field_key == "TELEGRAM_MODEL" {
            return Some("TELEGRAM_MODEL".to_string());
        }
        if field_key == "DISCORD_MODEL" {
            return Some("DISCORD_MODEL".to_string());
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if field_key == telegram_slot_model_key(slot) {
                return Some(telegram_slot_model_key(slot));
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                if field_key == dynamic_slot_field_key(ch.name, slot, "model") {
                    return Some(dynamic_slot_field_key(ch.name, slot, "model"));
                }
            }
        }
        None
    }

    fn llm_override_related_keys_for_model_field(field_key: &str) -> Option<Vec<String>> {
        if field_key == "TELEGRAM_MODEL" {
            return Some(vec![
                "TELEGRAM_MODEL".to_string(),
                telegram_llm_provider_key().to_string(),
                telegram_llm_api_key_key().to_string(),
                telegram_llm_base_url_key().to_string(),
            ]);
        }
        if field_key == "DISCORD_MODEL" {
            return Some(vec![
                "DISCORD_MODEL".to_string(),
                discord_llm_provider_key().to_string(),
                discord_llm_api_key_key().to_string(),
                discord_llm_base_url_key().to_string(),
            ]);
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if field_key == telegram_slot_model_key(slot) {
                return Some(vec![
                    telegram_slot_model_key(slot),
                    dynamic_slot_llm_provider_key("telegram", slot),
                    dynamic_slot_llm_api_key_key("telegram", slot),
                    dynamic_slot_llm_base_url_key("telegram", slot),
                ]);
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let model_key = dynamic_slot_field_key(ch.name, slot, "model");
                if field_key == model_key {
                    return Some(vec![
                        model_key.clone(),
                        dynamic_slot_llm_provider_key(ch.name, slot),
                        dynamic_slot_llm_api_key_key(ch.name, slot),
                        dynamic_slot_llm_base_url_key(ch.name, slot),
                    ]);
                }
            }
        }
        None
    }

    fn to_env_map(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for field in &self.fields {
            out.insert(field.key.to_string(), field.value.trim().to_string());
        }
        out
    }

    fn enabled_channels(&self) -> Vec<String> {
        let raw = self.field_value("ENABLED_CHANNELS");
        let valid_channels: Vec<&str> = Self::channel_options();
        let mut out = Vec::new();
        for part in raw.split(',') {
            let p = part.trim().to_lowercase();
            if !valid_channels.contains(&p.as_str()) {
                continue;
            }
            if !out.iter().any(|v| v == &p) {
                out.push(p);
            }
        }
        out
    }

    fn channel_enabled(&self, channel: &str) -> bool {
        self.enabled_channels().iter().any(|c| c == channel)
    }

    fn telegram_bot_count(&self) -> usize {
        parse_bot_count(
            &self.field_value(telegram_bot_count_key()),
            telegram_bot_count_key(),
        )
        .unwrap_or(1)
    }

    fn telegram_slot_accounts_from_fields(
        &self,
    ) -> Result<serde_json::Map<String, serde_json::Value>, MicroClawError> {
        let mut out = serde_json::Map::new();
        for slot in 1..=self.telegram_bot_count() {
            let id = self.field_value(&telegram_slot_id_key(slot));
            let token = self.field_value(&telegram_slot_token_key(slot));
            let username = self.field_value(&telegram_slot_username_key(slot));
            let model = self.field_value(&telegram_slot_model_key(slot));
            let soul_path = self
                .normalize_soul_path_value(&self.field_value(&telegram_slot_soul_path_key(slot)));
            let allowed_user_ids_raw = self.field_value(&telegram_slot_allowed_user_ids_key(slot));
            let allowed_user_ids = parse_i64_list_field(
                &allowed_user_ids_raw,
                &telegram_slot_allowed_user_ids_key(slot),
            )?;
            let topic_routing_raw = self.field_value(&telegram_slot_topic_routing_key(slot));
            let topic_routing_enabled = if topic_routing_raw.trim().is_empty() {
                None
            } else {
                Some(parse_boolish(&topic_routing_raw, false).map_err(|_| {
                    MicroClawError::Config(format!(
                        "{} must be true/false (or 1/0)",
                        telegram_slot_topic_routing_key(slot)
                    ))
                })?)
            };
            let enabled = parse_boolish(&self.field_value(&telegram_slot_enabled_key(slot)), true)?;
            let has_any = !token.is_empty()
                || !username.is_empty()
                || !model.is_empty()
                || !soul_path.is_empty()
                || !allowed_user_ids.is_empty()
                || topic_routing_enabled.is_some();
            if !has_any {
                continue;
            }
            let account_id = if id.is_empty() {
                return Err(MicroClawError::Config(format!(
                    "{} is required when Telegram bot slot #{slot} is used",
                    telegram_slot_id_key(slot)
                )));
            } else {
                id
            };
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(format!(
                    "{} must use only letters, numbers, '_' or '-'",
                    telegram_slot_id_key(slot)
                )));
            }
            let mut account = serde_json::Map::new();
            account.insert("enabled".to_string(), serde_json::Value::Bool(enabled));
            if !token.is_empty() {
                account.insert("bot_token".to_string(), serde_json::Value::String(token));
            }
            if !username.is_empty() {
                account.insert(
                    "bot_username".to_string(),
                    serde_json::Value::String(username),
                );
            }
            if !model.is_empty() {
                account.insert("model".to_string(), serde_json::Value::String(model));
            }
            if !soul_path.is_empty() {
                account.insert(
                    "soul_path".to_string(),
                    serde_json::Value::String(soul_path),
                );
            }
            if !allowed_user_ids.is_empty() {
                account.insert(
                    "allowed_user_ids".to_string(),
                    serde_json::Value::Array(
                        allowed_user_ids
                            .into_iter()
                            .map(|id| serde_json::Value::Number(id.into()))
                            .collect(),
                    ),
                );
            }
            if let Some(enabled) = topic_routing_enabled {
                account.insert(
                    "topic_routing".to_string(),
                    serde_json::json!({ "enabled": enabled }),
                );
            }
            out.insert(account_id, serde_json::Value::Object(account));
        }
        Ok(out)
    }

    fn dynamic_bot_count(&self, channel: &str) -> usize {
        let key = dynamic_bot_count_field_key(channel);
        parse_bot_count(&self.field_value(&key), &key).unwrap_or(1)
    }

    fn dynamic_field_channel(key: &str) -> Option<&'static str> {
        for ch in DYNAMIC_CHANNELS {
            if key == dynamic_bot_count_field_key(ch.name) {
                return Some(ch.name);
            }
            if key == dynamic_account_id_field_key(ch.name) {
                return Some(ch.name);
            }
            if key == dynamic_accounts_json_field_key(ch.name) {
                return Some(ch.name);
            }
            for slot in 1..=MAX_BOT_SLOTS {
                if key == dynamic_slot_id_field_key(ch.name, slot)
                    || key == dynamic_slot_enabled_field_key(ch.name, slot)
                    || key == dynamic_slot_soul_path_field_key(ch.name, slot)
                    || key == dynamic_slot_llm_provider_key(ch.name, slot)
                    || key == dynamic_slot_llm_api_key_key(ch.name, slot)
                    || key == dynamic_slot_llm_base_url_key(ch.name, slot)
                {
                    return Some(ch.name);
                }
                for f in ch.fields {
                    if key == dynamic_slot_field_key(ch.name, slot, f.yaml_key) {
                        return Some(ch.name);
                    }
                }
            }
            for f in ch.fields {
                if key == dynamic_field_key(ch.name, f.yaml_key) {
                    return Some(ch.name);
                }
            }
        }
        None
    }

    fn is_field_visible(&self, key: &str) -> bool {
        match key {
            "WEB_HOOKS_TOKEN"
            | "WEB_HOOKS_DEFAULT_SESSION_KEY"
            | "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY"
            | "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES" => self.channel_enabled("web"),
            "A2A_ENABLED"
            | "A2A_PUBLIC_BASE_URL"
            | "A2A_AGENT_NAME"
            | "A2A_AGENT_DESCRIPTION"
            | "A2A_SHARED_TOKENS"
            | "A2A_PEERS_JSON" => true,
            "TELEGRAM_MODEL" | "TELEGRAM_ALLOWED_USER_IDS" | "TELEGRAM_TOPIC_ROUTING" => {
                self.channel_enabled("telegram")
            }
            "TELEGRAM_BOT_TOKEN" | "BOT_USERNAME" | "TELEGRAM_ACCOUNT_ID" => false,
            "TELEGRAM_LLM_PROVIDER" | "TELEGRAM_LLM_API_KEY" | "TELEGRAM_LLM_BASE_URL" => false,
            _ if key == telegram_bot_count_key() => self.channel_enabled("telegram"),
            _ if key.starts_with("TELEGRAM_BOT") => {
                if !self.channel_enabled("telegram") {
                    return false;
                }
                for slot in 1..=MAX_BOT_SLOTS {
                    if key == telegram_slot_id_key(slot)
                        || key == telegram_slot_enabled_key(slot)
                        || key == telegram_slot_token_key(slot)
                        || key == telegram_slot_username_key(slot)
                        || key == telegram_slot_model_key(slot)
                        || key == telegram_slot_soul_path_key(slot)
                        || key == telegram_slot_allowed_user_ids_key(slot)
                        || key == telegram_slot_topic_routing_key(slot)
                    {
                        return slot <= self.telegram_bot_count();
                    }
                }
                false
            }
            "DISCORD_BOT_TOKEN"
            | "DISCORD_ACCOUNT_ID"
            | "DISCORD_MODEL"
            | "DISCORD_ACCOUNTS_JSON" => self.channel_enabled("discord"),
            "DISCORD_LLM_PROVIDER" | "DISCORD_LLM_API_KEY" | "DISCORD_LLM_BASE_URL" => false,
            _ => {
                if let Some(ch) = Self::dynamic_field_channel(key) {
                    if !self.channel_enabled(ch) {
                        return false;
                    }
                    if dynamic_channel_uses_minimal_setup(ch) {
                        return false;
                    }
                    if key == dynamic_account_id_field_key(ch)
                        || key == dynamic_accounts_json_field_key(ch)
                    {
                        return false;
                    }
                    if key == dynamic_bot_count_field_key(ch) {
                        return true;
                    }
                    for slot in 1..=MAX_BOT_SLOTS {
                        if key == dynamic_slot_id_field_key(ch, slot)
                            || key == dynamic_slot_enabled_field_key(ch, slot)
                            || key == dynamic_slot_soul_path_field_key(ch, slot)
                        {
                            return slot <= self.dynamic_bot_count(ch);
                        }
                        if key == dynamic_slot_llm_provider_key(ch, slot)
                            || key == dynamic_slot_llm_api_key_key(ch, slot)
                            || key == dynamic_slot_llm_base_url_key(ch, slot)
                        {
                            return false;
                        }
                        for d in DYNAMIC_CHANNELS {
                            if d.name != ch {
                                continue;
                            }
                            for f in d.fields {
                                if key == dynamic_slot_field_key(ch, slot, f.yaml_key) {
                                    return slot <= self.dynamic_bot_count(ch);
                                }
                            }
                        }
                    }
                    // Hide legacy single-account dynamic keys in setup UI.
                    false
                } else {
                    true
                }
            }
        }
    }

    fn visible_field_indices(&self) -> Vec<usize> {
        let sig = self.visibility_signature();
        if self.visible_cache_sig.get() != sig {
            let indices = self
                .fields
                .iter()
                .enumerate()
                .filter_map(|(idx, field)| {
                    if self.is_field_visible(&field.key) {
                        Some(idx)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            *self.visible_cache_indices.borrow_mut() = indices;
            self.visible_cache_sig.set(sig);
        }
        self.visible_cache_indices.borrow().clone()
    }

    fn visibility_signature(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for field in &self.fields {
            let key = field.key.as_str();
            if key == "ENABLED_CHANNELS"
                || key == telegram_bot_count_key()
                || key.starts_with("DYN_") && key.ends_with("_BOT_COUNT")
            {
                key.hash(&mut hasher);
                field.value.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    fn ensure_selected_visible(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        if self.selected >= self.fields.len() {
            self.selected = visible[0];
            return;
        }
        if self.is_field_visible(&self.fields[self.selected].key) {
            return;
        }
        if let Some(next_idx) = visible.iter().copied().find(|idx| *idx > self.selected) {
            self.selected = next_idx;
            return;
        }
        if let Some(last) = visible.last().copied() {
            self.selected = last;
        }
        self.adjust_field_scroll(self.field_window.max(1));
    }

    fn adjust_field_scroll(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            self.field_scroll = 0;
            return;
        }
        let Some(sel_pos) = visible.iter().position(|idx| *idx == self.selected) else {
            self.field_scroll = 0;
            return;
        };
        if self.field_scroll >= visible.len() {
            self.field_scroll = visible.len().saturating_sub(1);
        }
        if sel_pos < self.field_scroll {
            self.field_scroll = sel_pos;
        }
        let window_lines = window.max(1);
        while self.field_scroll < sel_pos {
            let end = self.window_end_for_start_pos(&visible, self.field_scroll, window_lines);
            if sel_pos < end {
                break;
            }
            self.field_scroll += 1;
        }
    }

    fn page_down(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        let start = self.field_scroll.min(visible.len().saturating_sub(1));
        let end = self.window_end_for_start_pos(&visible, start, window.max(1));
        if end >= visible.len() {
            self.selected = visible[visible.len() - 1];
        } else {
            self.field_scroll = end;
            self.selected = visible[end];
        }
        self.adjust_field_scroll(window.max(1));
    }

    fn page_up(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        let step = window.max(1);
        self.field_scroll = self
            .field_scroll
            .saturating_sub(step)
            .min(visible.len() - 1);
        self.selected = visible[self.field_scroll];
        self.adjust_field_scroll(window.max(1));
    }

    fn jump_top(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        self.field_scroll = 0;
        self.selected = visible[0];
        self.adjust_field_scroll(self.field_window.max(1));
    }

    fn jump_bottom(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        self.selected = *visible.last().unwrap_or(&visible[0]);
        self.adjust_field_scroll(self.field_window.max(1));
    }

    fn window_end_for_start_pos(
        &self,
        visible: &[usize],
        start_pos: usize,
        window_lines: usize,
    ) -> usize {
        if visible.is_empty() || start_pos >= visible.len() {
            return visible.len();
        }
        let mut used_lines = 0usize;
        let mut last_section = "";
        let mut pos = start_pos;
        while pos < visible.len() {
            let section = Self::section_for_key(&self.fields[visible[pos]].key);
            let added = if section != last_section {
                if used_lines == 0 {
                    2
                } else {
                    3
                }
            } else {
                1
            };
            if used_lines + added > window_lines {
                if pos == start_pos {
                    return pos + 1;
                }
                break;
            }
            used_lines += added;
            last_section = section;
            pos += 1;
        }
        pos
    }

    fn selected_progress(&self) -> (usize, usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return (1, 1);
        }
        let current = visible
            .iter()
            .position(|idx| *idx == self.selected)
            .map(|v| v + 1)
            .unwrap_or(1);
        (current, visible.len())
    }

    fn is_field_required(&self, field: &Field) -> bool {
        if field.key == "LLM_API_KEY" {
            return !provider_allows_empty_api_key(&self.field_value("LLM_PROVIDER"));
        }
        field.required
    }

    fn validate_local(&self) -> Result<(), MicroClawError> {
        for field in &self.fields {
            if self.is_field_required(field) && field.value.trim().is_empty() {
                return Err(MicroClawError::Config(format!("{} is required", field.key)));
            }
        }

        let hooks_allow_raw = self.field_value(web_hooks_allow_request_session_key_key());
        if !hooks_allow_raw.trim().is_empty() {
            let _ = parse_boolish(&hooks_allow_raw, false).map_err(|_| {
                MicroClawError::Config(format!(
                    "{} must be true/false",
                    web_hooks_allow_request_session_key_key()
                ))
            })?;
        }
        let _ = parse_string_list_field(
            &self.field_value(web_hooks_allowed_session_key_prefixes_key()),
        )
        .map_err(|_| {
            MicroClawError::Config(format!(
                "{} must be csv or JSON string array",
                web_hooks_allowed_session_key_prefixes_key()
            ))
        })?;
        let _ = parse_provider_presets_json_value(
            &self.field_value(llm_provider_profiles_key()),
            llm_provider_profiles_key(),
        )?;

        if self.channel_enabled("telegram") {
            let _ = parse_bot_count(
                &self.field_value(telegram_bot_count_key()),
                telegram_bot_count_key(),
            )?;
            let topic_routing_raw = self.field_value(telegram_topic_routing_key());
            if !topic_routing_raw.trim().is_empty() {
                let _ = parse_boolish(&topic_routing_raw, false).map_err(|_| {
                    MicroClawError::Config(format!(
                        "{} must be true/false (or 1/0)",
                        telegram_topic_routing_key()
                    ))
                })?;
            }
            parse_i64_list_field(
                &self.field_value(telegram_allowed_user_ids_key()),
                telegram_allowed_user_ids_key(),
            )?;
            let account_id = account_id_from_value(&self.field_value(&telegram_slot_id_key(1)));
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(format!(
                    "{} must use only letters, numbers, '_' or '-'",
                    telegram_slot_id_key(1)
                )));
            }
            let telegram_slot_accounts = self.telegram_slot_accounts_from_fields()?;
            let telegram_slot_has_account_token = telegram_slot_accounts.values().any(|account| {
                account
                    .get("bot_token")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_some()
            });
            if self.telegram_bot_count() > 1 && telegram_slot_accounts.is_empty() {
                return Err(MicroClawError::Config(
                    "Provide Telegram multi-bot entries via TELEGRAM_BOT#_* fields when TELEGRAM_BOT_COUNT > 1".into(),
                ));
            }
            if self.field_value("TELEGRAM_BOT_TOKEN").is_empty() && !telegram_slot_has_account_token
            {
                return Err(MicroClawError::Config(
                    "TELEGRAM_BOT_TOKEN or TELEGRAM_BOT#_TOKEN is required when telegram is enabled".into(),
                ));
            }
            let slot_has_username = (1..=self.telegram_bot_count()).any(|slot| {
                !self
                    .field_value(&telegram_slot_username_key(slot))
                    .trim()
                    .is_empty()
            });
            if self.field_value("BOT_USERNAME").is_empty() && !slot_has_username {
                return Err(MicroClawError::Config(
                    "TELEGRAM_BOT#_USERNAME is required when telegram is enabled".into(),
                ));
            }
            let username = self.field_value("BOT_USERNAME");
            if username.starts_with('@') {
                return Err(MicroClawError::Config(
                    "BOT_USERNAME should not include '@'".into(),
                ));
            }
            for slot in 1..=self.telegram_bot_count() {
                let username = self.field_value(&telegram_slot_username_key(slot));
                if username.starts_with('@') {
                    return Err(MicroClawError::Config(format!(
                        "{} should not include '@'",
                        telegram_slot_username_key(slot)
                    )));
                }
            }
        }

        if self.channel_enabled("discord") {
            let account_id = account_id_from_value(&self.field_value("DISCORD_ACCOUNT_ID"));
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(
                    "DISCORD_ACCOUNT_ID must use only letters, numbers, '_' or '-'".into(),
                ));
            }
            let discord_accounts = parse_accounts_json_value(
                &self.field_value("DISCORD_ACCOUNTS_JSON"),
                "DISCORD_ACCOUNTS_JSON",
            )?;
            let discord_has_account_token = discord_accounts
                .as_ref()
                .map(|accounts| {
                    accounts.values().any(|account| {
                        account
                            .get("bot_token")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                            .is_some()
                    })
                })
                .unwrap_or(false);
            if self.field_value("DISCORD_BOT_TOKEN").is_empty() && !discord_has_account_token {
                return Err(MicroClawError::Config(
                    "DISCORD_BOT_TOKEN or DISCORD_ACCOUNTS_JSON(bot_token) is required when discord is enabled".into(),
                ));
            }
        }

        for ch in DYNAMIC_CHANNELS {
            if self.channel_enabled(ch.name) {
                if dynamic_channel_uses_minimal_setup(ch.name) {
                    continue;
                }
                let bot_count_key = dynamic_bot_count_field_key(ch.name);
                let bot_count = parse_bot_count(&self.field_value(&bot_count_key), &bot_count_key)?;
                let mut seen_any = false;
                for slot in 1..=bot_count {
                    let id_key = dynamic_slot_id_field_key(ch.name, slot);
                    let id_raw = self.field_value(&id_key);
                    let soul_path = self.normalize_soul_path_value(
                        &self.field_value(&dynamic_slot_soul_path_field_key(ch.name, slot)),
                    );
                    let has_any = ch.fields.iter().any(|f| {
                        !effective_dynamic_slot_field_value(ch.name, slot, f, |key| {
                            self.field_value(key)
                        })
                        .is_empty()
                    }) || !soul_path.is_empty();
                    if !has_any {
                        continue;
                    }
                    seen_any = true;
                    let account_id = account_id_from_value(&id_raw);
                    if !is_valid_account_id(&account_id) {
                        return Err(MicroClawError::Config(format!(
                            "{} must use only letters, numbers, '_' or '-'",
                            id_key
                        )));
                    }
                    let enabled_key = dynamic_slot_enabled_field_key(ch.name, slot);
                    let _ = parse_boolish(&self.field_value(&enabled_key), true).map_err(|_| {
                        MicroClawError::Config(format!(
                            "{} must be true/false (or 1/0)",
                            enabled_key
                        ))
                    })?;
                    if ch.name == "feishu" {
                        let mut topic_mode = false;
                        for yaml_key in ["topic_mode", "show_progress"] {
                            let field_key = dynamic_slot_field_key(ch.name, slot, yaml_key);
                            let field_raw = self.field_value(&field_key);
                            let parsed = if field_raw.trim().is_empty() {
                                false
                            } else {
                                parse_boolish(&field_raw, false).map_err(|_| {
                                    MicroClawError::Config(format!(
                                        "{} must be true/false (or 1/0)",
                                        field_key
                                    ))
                                })?
                            };
                            if yaml_key == "topic_mode" {
                                topic_mode = parsed;
                            }
                        }
                        if topic_mode {
                            let domain_key = dynamic_slot_field_key(ch.name, slot, "domain");
                            let domain = self.field_value(&domain_key).trim().to_ascii_lowercase();
                            let domain = if domain.is_empty() {
                                "feishu"
                            } else {
                                domain.as_str()
                            };
                            if domain != "feishu" && domain != "lark" {
                                return Err(MicroClawError::Config(format!(
                                    "{} topic_mode is only supported when domain is feishu or lark",
                                    id_key
                                )));
                            }
                        }
                    }
                    for f in ch.fields {
                        if !f.required {
                            continue;
                        }
                        let key = dynamic_slot_field_key(ch.name, slot, f.yaml_key);
                        if effective_dynamic_slot_field_value(ch.name, slot, f, |field_key| {
                            self.field_value(field_key)
                        })
                        .is_empty()
                        {
                            return Err(MicroClawError::Config(format!(
                                "{} is required when {} bot slot #{} is configured",
                                key, ch.name, slot
                            )));
                        }
                    }
                }
                if !seen_any {
                    return Err(MicroClawError::Config(format!(
                        "Provide at least one {} bot slot (1..{}) with required fields",
                        ch.name, bot_count
                    )));
                }
            }
        }

        let provider = self.field_value("LLM_PROVIDER");
        if provider.is_empty() {
            return Err(MicroClawError::Config("LLM_PROVIDER is required".into()));
        }
        if is_openai_codex_provider(&provider) {
            if !self.field_value("LLM_API_KEY").trim().is_empty() {
                return Err(MicroClawError::Config(
                    "openai-codex ignores LLM_API_KEY here. Configure ~/.codex/auth.json or run `codex login`.".into(),
                ));
            }
            if !self.field_value("LLM_BASE_URL").trim().is_empty() {
                return Err(MicroClawError::Config(
                    "openai-codex ignores LLM_BASE_URL here. Configure ~/.codex/config.toml instead.".into(),
                ));
            }
        } else if provider.eq_ignore_ascii_case("qwen-portal")
            && self.field_value("LLM_API_KEY").trim().is_empty()
            && !qwen_oauth_file_has_access_token()?
        {
            return Err(MicroClawError::Config(
                "qwen-portal requires LLM_API_KEY, or ~/.qwen/oauth_creds.json (access_token), or QWEN_PORTAL_ACCESS_TOKEN.".into(),
            ));
        }

        let override_timezone = self.field_value("OVERRIDE_TIMEZONE");
        let tz = override_timezone.trim();
        if !tz.is_empty() && !tz.eq_ignore_ascii_case("auto") {
            tz.parse::<chrono_tz::Tz>()
                .map_err(|_| MicroClawError::Config(format!("Invalid OVERRIDE_TIMEZONE: {tz}")))?;
        }

        let data_dir = self.field_value("DATA_DIR");
        let dir = if data_dir.is_empty() {
            default_data_dir_for_setup()
        } else {
            data_dir
        };
        fs::create_dir_all(&dir)?;
        let probe = Path::new(&dir).join(".setup_probe");
        fs::write(&probe, "ok")?;
        let _ = fs::remove_file(probe);

        let working_dir = self.field_value("WORKING_DIR");
        let workdir = if working_dir.is_empty() {
            default_working_dir_for_setup()
        } else {
            working_dir
        };
        fs::create_dir_all(&workdir)?;

        let sandbox_enabled = self.field_value("SANDBOX_ENABLED");
        if !sandbox_enabled.is_empty() {
            let lower = sandbox_enabled.to_ascii_lowercase();
            let valid = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");
            if !valid {
                return Err(MicroClawError::Config(
                    "SANDBOX_ENABLED must be true/false (or 1/0)".into(),
                ));
            }
        }
        let high_risk_confirm = self.field_value("HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED");
        if !high_risk_confirm.is_empty() {
            let lower = high_risk_confirm.to_ascii_lowercase();
            let valid = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");
            if !valid {
                return Err(MicroClawError::Config(
                    "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED must be true/false (or 1/0)".into(),
                ));
            }
        }
        let show_thinking = self.field_value("SHOW_THINKING");
        if !show_thinking.is_empty() && parse_bool_like(&show_thinking).is_none() {
            return Err(MicroClawError::Config(
                "SHOW_THINKING must be true/false (or 1/0)".into(),
            ));
        }

        let memory_token_budget_raw = self.field_value("MEMORY_TOKEN_BUDGET");
        if !memory_token_budget_raw.is_empty() {
            let memory_token_budget = memory_token_budget_raw.parse::<usize>().map_err(|_| {
                MicroClawError::Config("MEMORY_TOKEN_BUDGET must be a positive integer".into())
            })?;
            if memory_token_budget == 0 {
                return Err(MicroClawError::Config(
                    "MEMORY_TOKEN_BUDGET must be greater than 0".into(),
                ));
            }
        }

        for key in [
            subagents_max_concurrent_key(),
            subagents_max_active_per_chat_key(),
            subagents_run_timeout_secs_key(),
            subagents_max_spawn_depth_key(),
            subagents_max_children_per_run_key(),
            subagents_announce_relay_interval_secs_key(),
            subagents_max_tokens_per_run_key(),
            subagents_orchestrate_max_workers_key(),
        ] {
            let raw = self.field_value(key);
            if raw.is_empty() {
                continue;
            }
            let value = raw
                .parse::<u64>()
                .map_err(|_| MicroClawError::Config(format!("{key} must be a positive integer")))?;
            if value == 0 {
                return Err(MicroClawError::Config(format!(
                    "{key} must be greater than 0"
                )));
            }
        }

        for key in [
            subagents_announce_to_chat_key(),
            subagents_thread_bound_routing_enabled_key(),
            subagents_acp_enabled_key(),
            subagents_acp_auto_approve_key(),
        ] {
            let raw = self.field_value(key);
            if raw.is_empty() {
                continue;
            }
            let lower = raw.to_ascii_lowercase();
            let valid = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");
            if !valid {
                return Err(MicroClawError::Config(format!(
                    "{key} must be true/false (or 1/0)"
                )));
            }
        }

        let acp_args_raw = self.field_value(subagents_acp_args_key());
        if !acp_args_raw.is_empty() {
            parse_string_list_field(&acp_args_raw)?;
        }
        let acp_env_raw = self.field_value(subagents_acp_env_json_key());
        if !acp_env_raw.trim().is_empty() {
            serde_json::from_str::<HashMap<String, String>>(acp_env_raw.trim()).map_err(|e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    subagents_acp_env_json_key()
                ))
            })?;
        }
        let acp_targets_raw = self.field_value(subagents_acp_targets_json_key());
        if !acp_targets_raw.trim().is_empty() {
            serde_json::from_str::<HashMap<String, crate::config::SubagentAcpTargetConfig>>(
                acp_targets_raw.trim(),
            )
            .map_err(|e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    subagents_acp_targets_json_key()
                ))
            })?;
        }

        let embedding_dim_raw = self.field_value("EMBEDDING_DIM");
        if !embedding_dim_raw.is_empty() {
            let embedding_dim = embedding_dim_raw.parse::<usize>().map_err(|_| {
                MicroClawError::Config("EMBEDDING_DIM must be a positive integer".into())
            })?;
            if embedding_dim == 0 {
                return Err(MicroClawError::Config(
                    "EMBEDDING_DIM must be greater than 0".into(),
                ));
            }
        }

        Ok(())
    }

    fn validate_online(&self) -> Result<Vec<String>, MicroClawError> {
        let tg_enabled = self.channel_enabled("telegram");
        let tg_token = if !self.field_value("TELEGRAM_BOT_TOKEN").is_empty() {
            self.field_value("TELEGRAM_BOT_TOKEN")
        } else if !self.field_value(&telegram_slot_token_key(1)).is_empty() {
            self.field_value(&telegram_slot_token_key(1))
        } else {
            self.telegram_slot_accounts_from_fields()?
                .into_values()
                .find_map(|account| {
                    account
                        .get("bot_token")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default()
        };
        let env_username = if !self.field_value("BOT_USERNAME").is_empty() {
            self.field_value("BOT_USERNAME")
        } else if !self.field_value(&telegram_slot_username_key(1)).is_empty() {
            self.field_value(&telegram_slot_username_key(1))
        } else {
            self.telegram_slot_accounts_from_fields()?
                .into_values()
                .find_map(|account| {
                    account
                        .get("bot_username")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default()
        }
        .trim_start_matches('@')
        .to_string();
        let provider = self.field_value("LLM_PROVIDER").to_lowercase();
        let (api_key, codex_account_id) = if is_openai_codex_provider(&provider) {
            let auth = resolve_openai_codex_auth("")?;
            (auth.bearer_token, auth.account_id)
        } else if provider.eq_ignore_ascii_case("qwen-portal")
            && self.field_value("LLM_API_KEY").trim().is_empty()
        {
            let auth = resolve_qwen_portal_auth("")?;
            (auth.bearer_token, None)
        } else {
            (self.field_value("LLM_API_KEY"), None)
        };
        let base_url = self.field_value("LLM_BASE_URL");
        let user_agent = self.field_value("LLM_USER_AGENT");
        let model = self.field_value("LLM_MODEL");
        std::thread::spawn(move || {
            perform_online_validation(
                tg_enabled,
                true,
                &tg_token,
                &env_username,
                &provider,
                &api_key,
                &base_url,
                &user_agent,
                &model,
                codex_account_id.as_deref(),
            )
        })
        .join()
        .map_err(|_| MicroClawError::Config("Validation thread panicked".into()))?
    }

    fn selected_provider_preset_validation_request(
        &self,
    ) -> Result<ProviderPresetValidationRequest, MicroClawError> {
        let Some(page) = self.provider_preset_page.as_ref() else {
            return Err(MicroClawError::Config(
                "No provider profile is currently selected".into(),
            ));
        };
        let Some(entry) = page.entries.get(page.selected) else {
            return Err(MicroClawError::Config(
                "No provider profile is currently selected".into(),
            ));
        };

        let provider = entry.provider.trim().to_ascii_lowercase();
        if provider.is_empty() {
            return Err(MicroClawError::Config(
                "Provider profile must set a provider before testing".into(),
            ));
        }

        let configured_api_key = entry.api_key.trim().to_string();
        let (api_key, codex_account_id) = if is_openai_codex_provider(&provider) {
            let auth = resolve_openai_codex_auth(&configured_api_key)?;
            (auth.bearer_token, auth.account_id)
        } else if provider.eq_ignore_ascii_case("qwen-portal") && configured_api_key.is_empty() {
            let auth = resolve_qwen_portal_auth("")?;
            (auth.bearer_token, None)
        } else {
            (configured_api_key, None)
        };

        let base_url = entry.base_url.trim().to_string();
        let user_agent = entry.user_agent.trim().to_string();
        let model = if entry.default_model.trim().is_empty() {
            default_model_for_provider(&provider).to_string()
        } else {
            entry.default_model.trim().to_string()
        };

        Ok(ProviderPresetValidationRequest {
            profile_id: entry.id.clone(),
            provider,
            api_key,
            base_url,
            user_agent,
            model,
            codex_account_id,
        })
    }

    fn validate_selected_provider_preset_online(
        &self,
    ) -> Result<(String, Vec<String>), MicroClawError> {
        let request = self.selected_provider_preset_validation_request()?;
        let profile_id = request.profile_id.clone();
        let checks = std::thread::spawn(move || {
            perform_online_validation(
                false,
                false,
                "",
                "",
                &request.provider,
                &request.api_key,
                &request.base_url,
                &request.user_agent,
                &request.model,
                request.codex_account_id.as_deref(),
            )
        })
        .join()
        .map_err(|_| MicroClawError::Config("Validation thread panicked".into()))??;
        Ok((profile_id, checks))
    }

    fn set_provider(&mut self, provider: &str) {
        let old_provider = self.field_value("LLM_PROVIDER");
        let old_base_url = self.field_value("LLM_BASE_URL");
        let old_model = self.field_value("LLM_MODEL");

        if let Some(field) = self.fields.iter_mut().find(|f| f.key == "LLM_PROVIDER") {
            field.value = provider.to_string();
        }
        if let Some(base) = self.fields.iter_mut().find(|f| f.key == "LLM_BASE_URL") {
            let next_default = find_provider_preset(provider)
                .map(|p| p.default_base_url)
                .unwrap_or("");
            let old_default = find_provider_preset(&old_provider)
                .map(|p| p.default_base_url)
                .unwrap_or("");
            if old_base_url.trim().is_empty() || old_base_url == old_default {
                base.value = next_default.to_string();
            }
        }
        if let Some(model) = self.fields.iter_mut().find(|f| f.key == "LLM_MODEL") {
            let old_in_old_preset = find_provider_preset(&old_provider)
                .map(|p| p.models.iter().any(|m| *m == old_model))
                .unwrap_or(false);
            if old_model.trim().is_empty() || old_in_old_preset {
                model.value = default_model_for_provider(provider).to_string();
            }
        }
    }

    fn cycle_provider(&mut self, direction: i32) {
        let current = self.field_value("LLM_PROVIDER");
        let current_idx = PROVIDER_PRESETS
            .iter()
            .position(|p| p.id.eq_ignore_ascii_case(&current))
            .unwrap_or(PROVIDER_PRESETS.len() - 1);
        let next_idx = if direction < 0 {
            if current_idx == 0 {
                PROVIDER_PRESETS.len() - 1
            } else {
                current_idx - 1
            }
        } else {
            (current_idx + 1) % PROVIDER_PRESETS.len()
        };
        self.set_provider(PROVIDER_PRESETS[next_idx].id);
    }

    fn cycle_model(&mut self, direction: i32) {
        let provider = self.field_value("LLM_PROVIDER");
        let preset = match find_provider_preset(&provider) {
            Some(p) => p,
            None => return,
        };
        if preset.models.is_empty() {
            return;
        }
        let current = self.field_value("LLM_MODEL");
        let current_idx = preset
            .models
            .iter()
            .position(|m| *m == current)
            .unwrap_or(0);
        let next_idx = if direction < 0 {
            if current_idx == 0 {
                preset.models.len() - 1
            } else {
                current_idx - 1
            }
        } else {
            (current_idx + 1) % preset.models.len()
        };
        if let Some(model) = self.fields.iter_mut().find(|f| f.key == "LLM_MODEL") {
            model.value = preset.models[next_idx].to_string();
        }
    }

    fn provider_index(&self, provider: &str) -> usize {
        PROVIDER_PRESETS
            .iter()
            .position(|p| p.id.eq_ignore_ascii_case(provider))
            .unwrap_or(PROVIDER_PRESETS.len().saturating_sub(1))
    }

    fn model_options(&self) -> Vec<String> {
        let provider = self.field_value("LLM_PROVIDER");
        if let Some(preset) = find_provider_preset(&provider) {
            preset.models.iter().map(|m| (*m).to_string()).collect()
        } else {
            vec![self.field_value("LLM_MODEL")]
        }
    }

    fn model_picker_options(&self) -> Vec<String> {
        let mut options = self.model_options();
        options.push(MODEL_PICKER_MANUAL_INPUT.to_string());
        options
    }

    fn is_soul_field_key(key: &str) -> bool {
        if key.starts_with("TELEGRAM_BOT") && key.ends_with("_SOUL_PATH") {
            return true;
        }
        key.starts_with("DYN_") && key.ends_with("_SOUL_PATH")
    }

    fn soul_picker_options(&self) -> Vec<String> {
        let mut options = vec![
            SOUL_PICKER_CLEAR.to_string(),
            SOUL_PICKER_MANUAL_INPUT.to_string(),
        ];
        let data_dir = self.field_value("DATA_DIR");
        let souls_dir = self.souls_dir_value();
        options.extend(soul_picker_file_names(Some(&data_dir), Some(&souls_dir)));
        options
    }

    fn timezone_picker_options(&self) -> Vec<String> {
        vec![
            TIMEZONE_PICKER_SYSTEM_DEFAULT.to_string(),
            "UTC".to_string(),
            "America/Los_Angeles".to_string(),
            "America/New_York".to_string(),
            "America/Chicago".to_string(),
            "America/Denver".to_string(),
            "America/Phoenix".to_string(),
            "America/Toronto".to_string(),
            "America/Vancouver".to_string(),
            "America/Sao_Paulo".to_string(),
            "Europe/London".to_string(),
            "Europe/Berlin".to_string(),
            "Europe/Paris".to_string(),
            "Europe/Madrid".to_string(),
            "Europe/Rome".to_string(),
            "Europe/Amsterdam".to_string(),
            "Europe/Moscow".to_string(),
            "Asia/Shanghai".to_string(),
            "Asia/Tokyo".to_string(),
            "Asia/Singapore".to_string(),
            "Asia/Kolkata".to_string(),
            "Asia/Hong_Kong".to_string(),
            "Asia/Seoul".to_string(),
            "Asia/Dubai".to_string(),
            "Asia/Bangkok".to_string(),
            "Asia/Jakarta".to_string(),
            "Australia/Sydney".to_string(),
            "Australia/Melbourne".to_string(),
            "Pacific/Auckland".to_string(),
            "Africa/Johannesburg".to_string(),
            TIMEZONE_PICKER_MANUAL_INPUT.to_string(),
        ]
    }

    fn open_picker_for_selected(&mut self) -> bool {
        let selected_key = self.selected_field().key.clone();
        if Self::is_soul_field_key(&selected_key) {
            let options = self.soul_picker_options();
            let current = self.field_value(&selected_key);
            let current_name = Path::new(current.trim())
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("");
            let idx = if current.trim().is_empty() {
                0
            } else {
                options.iter().position(|v| v == current_name).unwrap_or(1)
            };
            self.picker = Some(PickerState {
                kind: PickerKind::SoulPath,
                selected: idx,
                selected_multi: Vec::new(),
            });
            return true;
        }
        match selected_key.as_str() {
            "LLM_PROVIDER" => {
                let idx = self.provider_index(&self.field_value("LLM_PROVIDER"));
                self.picker = Some(PickerState {
                    kind: PickerKind::Provider,
                    selected: idx,
                    selected_multi: Vec::new(),
                });
                true
            }
            "LLM_MODEL" => {
                let provider = self.field_value("LLM_PROVIDER");
                if provider.eq_ignore_ascii_case("custom") {
                    return false;
                }
                let options = self.model_picker_options();
                if options.is_empty() {
                    return false;
                }
                let current_model = self.field_value("LLM_MODEL");
                let idx = options
                    .iter()
                    .position(|m| *m == current_model)
                    .unwrap_or(options.len().saturating_sub(1));
                self.picker = Some(PickerState {
                    kind: PickerKind::Model,
                    selected: idx,
                    selected_multi: Vec::new(),
                });
                true
            }
            "ENABLED_CHANNELS" => {
                let selected_channels = self.enabled_channels();
                let mut selected_multi = Vec::new();
                for channel in Self::channel_options() {
                    selected_multi.push(selected_channels.iter().any(|c| c == channel));
                }
                self.picker = Some(PickerState {
                    kind: PickerKind::Channels,
                    selected: 0,
                    selected_multi,
                });
                true
            }
            _ if selected_key == llm_provider_profiles_key() => {
                self.open_provider_preset_page();
                true
            }
            "OVERRIDE_TIMEZONE" => {
                let options = self.timezone_picker_options();
                let current = {
                    let tz = self.field_value("OVERRIDE_TIMEZONE");
                    if tz.trim().is_empty() {
                        TIMEZONE_PICKER_SYSTEM_DEFAULT.to_string()
                    } else {
                        tz
                    }
                };
                let idx = options
                    .iter()
                    .position(|tz| tz.eq_ignore_ascii_case(&current))
                    .unwrap_or(options.len().saturating_sub(1));
                self.picker = Some(PickerState {
                    kind: PickerKind::Timezone,
                    selected: idx,
                    selected_multi: Vec::new(),
                });
                true
            }
            _ => false,
        }
    }

    fn key_display(key: &str) -> String {
        if key == llm_provider_profiles_key() {
            "LLM_PROVIDER_PROFILES".to_string()
        } else {
            key.to_string()
        }
    }

    fn move_picker(&mut self, direction: i32) {
        let Some(picker) = self.picker.as_ref() else {
            return;
        };
        let kind = picker.kind;
        let selected = picker.selected;
        let options_len = match kind {
            PickerKind::Provider => PROVIDER_PRESETS.len(),
            PickerKind::Model => self.model_picker_options().len(),
            PickerKind::Channels => Self::channel_options().len(),
            PickerKind::SoulPath => self.soul_picker_options().len(),
            PickerKind::Timezone => self.timezone_picker_options().len(),
        };
        if options_len == 0 {
            return;
        }
        let next = if direction < 0 {
            if selected == 0 {
                options_len - 1
            } else {
                selected - 1
            }
        } else {
            (selected + 1) % options_len
        };
        if let Some(picker_mut) = self.picker.as_mut() {
            picker_mut.selected = next;
        }
    }

    fn toggle_picker_multi(&mut self) {
        let Some(picker) = self.picker.as_mut() else {
            return;
        };
        if picker.kind != PickerKind::Channels {
            return;
        }
        if let Some(slot) = picker.selected_multi.get_mut(picker.selected) {
            *slot = !*slot;
        }
    }

    fn apply_picker_selection(&mut self) {
        let Some(picker) = self.picker.take() else {
            return;
        };
        match picker.kind {
            PickerKind::Provider => {
                if let Some(preset) = PROVIDER_PRESETS.get(picker.selected) {
                    self.set_provider(preset.id);
                    self.status = format!("Provider set to {}", preset.id);
                }
            }
            PickerKind::Model => {
                let options = self.model_picker_options();
                if let Some(chosen) = options.get(picker.selected) {
                    if chosen == MODEL_PICKER_MANUAL_INPUT {
                        self.editing = true;
                        self.status = "Editing LLM_MODEL (manual input)".to_string();
                    } else if let Some(model) =
                        self.fields.iter_mut().find(|f| f.key == "LLM_MODEL")
                    {
                        model.value = chosen.clone();
                        self.status = format!("Model set to {chosen}");
                    }
                }
            }
            PickerKind::Channels => {
                let mut enabled = Vec::new();
                for (idx, channel) in Self::channel_options().iter().enumerate() {
                    if picker.selected_multi.get(idx).copied().unwrap_or(false) {
                        enabled.push((*channel).to_string());
                    }
                }
                if let Some(field) = self.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
                    field.value = enabled.join(",");
                }
                if enabled.is_empty() {
                    self.status = "Channels set to setup later (web-only by default)".to_string();
                } else {
                    self.status = format!("Channels set to {}", enabled.join(","));
                }
            }
            PickerKind::SoulPath => {
                let options = self.soul_picker_options();
                let selected_key = self.selected_field().key.clone();
                let souls_dir = self.souls_dir_value();
                if let Some(chosen) = options.get(picker.selected) {
                    if chosen == SOUL_PICKER_MANUAL_INPUT {
                        self.editing = true;
                        self.status = format!("Editing {} (manual input)", selected_key);
                    } else if let Some(field) =
                        self.fields.iter_mut().find(|f| f.key == selected_key)
                    {
                        if chosen == SOUL_PICKER_CLEAR {
                            field.value.clear();
                            self.status = format!("Cleared {}", field.key);
                        } else {
                            let normalized = normalize_soul_path_input(chosen, &souls_dir);
                            field.value = normalized;
                            self.status = format!("{} set to {}", field.key, field.value);
                        }
                    }
                }
            }
            PickerKind::Timezone => {
                let options = self.timezone_picker_options();
                if let Some(chosen) = options.get(picker.selected) {
                    if chosen == TIMEZONE_PICKER_MANUAL_INPUT {
                        self.editing = true;
                        self.status = "Editing OVERRIDE_TIMEZONE (manual input)".to_string();
                    } else if let Some(field) = self
                        .fields
                        .iter_mut()
                        .find(|f| f.key == "OVERRIDE_TIMEZONE")
                    {
                        if chosen == TIMEZONE_PICKER_SYSTEM_DEFAULT {
                            field.value.clear();
                            self.status =
                                "Timezone override cleared (using system timezone)".to_string();
                        } else {
                            field.value = chosen.clone();
                            self.status = format!("Override timezone set to {chosen}");
                        }
                    }
                }
            }
        }
        self.ensure_selected_visible();
    }

    fn default_value_for_field(&self, key: &str) -> String {
        let provider = self.field_value("LLM_PROVIDER");
        match key {
            "ENABLED_CHANNELS" => "web".into(),
            "TELEGRAM_ACCOUNT_ID" | "DISCORD_ACCOUNT_ID" => default_account_id().to_string(),
            "TELEGRAM_BOT_TOKEN"
            | "BOT_USERNAME"
            | "WEB_HOOKS_TOKEN"
            | "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES"
            | "A2A_PUBLIC_BASE_URL"
            | "A2A_AGENT_NAME"
            | "A2A_AGENT_DESCRIPTION"
            | "A2A_SHARED_TOKENS"
            | "A2A_PEERS_JSON"
            | "TELEGRAM_MODEL"
            | "TELEGRAM_ALLOWED_USER_IDS"
            | "TELEGRAM_TOPIC_ROUTING"
            | "TELEGRAM_LLM_PROVIDER"
            | "TELEGRAM_LLM_API_KEY"
            | "TELEGRAM_LLM_BASE_URL"
            | "DISCORD_BOT_TOKEN"
            | "DISCORD_MODEL"
            | "DISCORD_ACCOUNTS_JSON"
            | "LLM_API_KEY" => String::new(),
            "WEB_HOOKS_DEFAULT_SESSION_KEY" => "hook:ingress".into(),
            "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY" => "false".into(),
            "A2A_ENABLED" => "false".into(),
            "SUBAGENTS_MAX_CONCURRENT" => "4".into(),
            "SUBAGENTS_MAX_ACTIVE_PER_CHAT" => "5".into(),
            "SUBAGENTS_RUN_TIMEOUT_SECS" => "900".into(),
            "SUBAGENTS_ANNOUNCE_TO_CHAT" => "true".into(),
            "SUBAGENTS_MAX_SPAWN_DEPTH" => "1".into(),
            "SUBAGENTS_MAX_CHILDREN_PER_RUN" => "5".into(),
            "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED" => "true".into(),
            "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS" => "15".into(),
            "SUBAGENTS_MAX_TOKENS_PER_RUN" => "400000".into(),
            "SUBAGENTS_ORCHESTRATE_MAX_WORKERS" => "5".into(),
            "SUBAGENTS_ACP_ENABLED" => "false".into(),
            "SUBAGENTS_ACP_AUTO_APPROVE" => "true".into(),
            _ if key == telegram_bot_count_key() => TELEGRAM_DEFAULT_BOT_COUNT.to_string(),
            _ if key.starts_with("TELEGRAM_BOT") => {
                if key.ends_with("_ENABLED") {
                    "true".into()
                } else {
                    String::new()
                }
            }
            "LLM_PROVIDER" => "anthropic".into(),
            "LLM_MODEL" => default_model_for_provider(&provider).into(),
            "LLM_BASE_URL" => find_provider_preset(&provider)
                .map(|p| p.default_base_url.to_string())
                .unwrap_or_default(),
            "LLM_USER_AGENT" => String::new(),
            _ if key == llm_provider_profiles_key() => String::new(),
            "SHOW_THINKING" => "false".into(),
            "DATA_DIR" => default_data_dir_for_setup(),
            "OVERRIDE_TIMEZONE" => String::new(),
            "WORKING_DIR" => default_working_dir_for_setup(),
            "SOULS_DIR" => default_souls_dir_for_setup(),
            "SANDBOX_ENABLED" => "false".into(),
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => "true".into(),
            "REFLECTOR_ENABLED" => "true".into(),
            "REFLECTOR_INTERVAL_MINS" => "15".into(),
            "MEMORY_TOKEN_BUDGET" => "1500".into(),
            "EMBEDDING_PROVIDER" | "EMBEDDING_API_KEY" | "EMBEDDING_BASE_URL"
            | "EMBEDDING_MODEL" | "EMBEDDING_DIM" => String::new(),
            _ => {
                for ch in DYNAMIC_CHANNELS {
                    if key == dynamic_bot_count_field_key(ch.name) {
                        return "1".into();
                    }
                    if key == dynamic_account_id_field_key(ch.name) {
                        return default_account_id().to_string();
                    }
                    if key == dynamic_accounts_json_field_key(ch.name) {
                        return String::new();
                    }
                    for slot in 1..=MAX_BOT_SLOTS {
                        if key == dynamic_slot_enabled_field_key(ch.name, slot) {
                            return "true".into();
                        }
                        if key == dynamic_slot_id_field_key(ch.name, slot) {
                            return default_slot_account_id(slot);
                        }
                        for f in ch.fields {
                            if key == dynamic_slot_field_key(ch.name, slot, f.yaml_key) {
                                return String::new();
                            }
                        }
                    }
                }
                String::new()
            }
        }
    }

    fn clear_selected_field(&mut self) {
        let key = self.selected_field().key.clone();
        if let Some(keys) = Self::llm_override_related_keys_for_model_field(&key) {
            for k in keys {
                self.set_field_value(&k, String::new());
            }
        } else {
            self.selected_field_mut().value.clear();
        }
        self.status = format!("Cleared {key}");
    }

    fn restore_selected_field_default(&mut self) {
        let key = self.selected_field().key.clone();
        let default = self.default_value_for_field(&key);
        if default.is_empty() {
            self.status = format!("{key} has no default");
        } else {
            self.selected_field_mut().value = default.clone();
            self.status = format!("Restored {key} to default: {default}");
        }
    }

    fn section_for_key(key: &str) -> &'static str {
        if key.starts_with("DYN_") {
            return "Channel";
        }
        match key {
            "DATA_DIR" | "OVERRIDE_TIMEZONE" | "WORKING_DIR" | "SOULS_DIR" => "App",
            "SANDBOX_ENABLED" | "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => "Sandbox",
            "REFLECTOR_ENABLED" | "REFLECTOR_INTERVAL_MINS" | "MEMORY_TOKEN_BUDGET" => "Memory",
            "LLM_PROVIDER" | "LLM_API_KEY" | "LLM_MODEL" | "LLM_BASE_URL" | "LLM_USER_AGENT"
            | "SHOW_THINKING" => "Model",
            _ if key == llm_provider_profiles_key() => "Model",
            "EMBEDDING_PROVIDER" | "EMBEDDING_API_KEY" | "EMBEDDING_BASE_URL"
            | "EMBEDDING_MODEL" | "EMBEDDING_DIM" => "Embedding",
            "A2A_ENABLED"
            | "A2A_PUBLIC_BASE_URL"
            | "A2A_AGENT_NAME"
            | "A2A_AGENT_DESCRIPTION"
            | "A2A_SHARED_TOKENS"
            | "A2A_PEERS_JSON" => "A2A",
            "SUBAGENTS_MAX_CONCURRENT"
            | "SUBAGENTS_MAX_ACTIVE_PER_CHAT"
            | "SUBAGENTS_RUN_TIMEOUT_SECS"
            | "SUBAGENTS_ANNOUNCE_TO_CHAT"
            | "SUBAGENTS_MAX_SPAWN_DEPTH"
            | "SUBAGENTS_MAX_CHILDREN_PER_RUN"
            | "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED"
            | "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS"
            | "SUBAGENTS_MAX_TOKENS_PER_RUN"
            | "SUBAGENTS_ORCHESTRATE_MAX_WORKERS"
            | "SUBAGENTS_ACP_ENABLED"
            | "SUBAGENTS_ACP_COMMAND"
            | "SUBAGENTS_ACP_ARGS"
            | "SUBAGENTS_ACP_ENV_JSON"
            | "SUBAGENTS_ACP_AUTO_APPROVE"
            | "SUBAGENTS_ACP_DEFAULT_TARGET"
            | "SUBAGENTS_ACP_TARGETS_JSON" => "Sub-agents",
            "ENABLED_CHANNELS"
            | "WEB_HOOKS_TOKEN"
            | "WEB_HOOKS_DEFAULT_SESSION_KEY"
            | "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY"
            | "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES"
            | "TELEGRAM_BOT_TOKEN"
            | "BOT_USERNAME"
            | "TELEGRAM_ACCOUNT_ID"
            | "TELEGRAM_MODEL"
            | "TELEGRAM_ALLOWED_USER_IDS"
            | "TELEGRAM_TOPIC_ROUTING"
            | "TELEGRAM_LLM_PROVIDER"
            | "TELEGRAM_LLM_API_KEY"
            | "TELEGRAM_LLM_BASE_URL"
            | "DISCORD_BOT_TOKEN"
            | "DISCORD_ACCOUNT_ID"
            | "DISCORD_MODEL"
            | "DISCORD_LLM_PROVIDER"
            | "DISCORD_LLM_API_KEY"
            | "DISCORD_LLM_BASE_URL"
            | "DISCORD_ACCOUNTS_JSON" => "Channel",
            _ if key == telegram_bot_count_key() => "Channel",
            _ if key.starts_with("TELEGRAM_BOT") => "Channel",
            _ => "Setup",
        }
    }

    fn field_guidance(key: &str) -> (&'static str, &'static str) {
        match key {
            "LLM_PROVIDER" => (
                "Select the LLM backend. Presets auto-fill a sensible model/base URL. OpenRouter models: https://openrouter.ai/models . NVIDIA models: https://build.nvidia.com/models",
                "Example: openai, anthropic, openrouter, nvidia, custom",
            ),
            "LLM_API_KEY" => (
                "API key for the selected provider. Leave empty only for providers that allow it.",
                "Example: sk-xxxx",
            ),
            "LLM_MODEL" => (
                "Default model used when no per-channel override is set.",
                "Example: qwen3.5-plus",
            ),
            "LLM_BASE_URL" => (
                "Custom OpenAI-compatible endpoint root. Use provider default if empty.",
                "Example: https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            "LLM_USER_AGENT" => (
                "HTTP User-Agent for LLM requests. Empty means automatic MicroClaw/<version>.",
                "Example: OpenClaw-Gateway/1.0",
            ),
            _ if key == llm_provider_profiles_key() => (
                "Reusable profile definitions keyed by profile id. Press Enter to open the profile editor.",
                "Example: create profile provider1 for OpenAI, then let channels/bots select provider1",
            ),
            "SHOW_THINKING" => (
                "Show model reasoning/thinking text in channel output when provider supports it.",
                "Example: true or false",
            ),
            "ENABLED_CHANNELS" => (
                "Comma-separated channel names to enable now. You can configure more later.",
                "Example: web,feishu,telegram",
            ),
            "WEB_HOOKS_TOKEN" => (
                "Bearer token used to authenticate /hooks/* and /api/hooks/* requests.",
                "Example: my-hooks-secret",
            ),
            "WEB_HOOKS_DEFAULT_SESSION_KEY" => (
                "Default session key used by hooks when request payload omits sessionKey.",
                "Example: hook:ingress",
            ),
            "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY" => (
                "Whether hook payload may override sessionKey. Keep false unless you trust callers.",
                "Example: true or false",
            ),
            "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES" => (
                "Allowlist of sessionKey prefixes when request override is enabled (csv/JSON array).",
                "Example: hook:,chat:",
            ),
            "A2A_ENABLED" => (
                "Enable agent-to-agent HTTP endpoints and outbound delegation tools.",
                "Example: true or false",
            ),
            "A2A_PUBLIC_BASE_URL" => (
                "Public base URL remote peers should use for agent-card discovery and message delivery.",
                "Example: https://planner.example.com",
            ),
            "A2A_AGENT_NAME" => (
                "Friendly name exposed in the A2A agent card and outbound calls.",
                "Example: Planner",
            ),
            "A2A_AGENT_DESCRIPTION" => (
                "Short description of this agent's role for other agents.",
                "Example: Routes work to specialized agents",
            ),
            "A2A_SHARED_TOKENS" => (
                "Inbound bearer tokens accepted by /api/a2a/message (csv/JSON array).",
                "Example: shared-a2a-token,backup-token",
            ),
            "A2A_PEERS_JSON" => (
                "JSON object of outbound peers keyed by name. Supports base_url, bearer_token, description, default_session_key, enabled.",
                "Example: {\"worker\":{\"base_url\":\"https://worker.example.com\",\"bearer_token\":\"shared-a2a-token\"}}",
            ),
            "SUBAGENTS_MAX_CONCURRENT" => (
                "Maximum number of subagent runs allowed to execute at the same time across the runtime.",
                "Example: 4",
            ),
            "SUBAGENTS_MAX_ACTIVE_PER_CHAT" => (
                "Maximum number of active subagent runs allowed in one chat.",
                "Example: 5",
            ),
            "SUBAGENTS_RUN_TIMEOUT_SECS" => (
                "Per-run timeout for one subagent before it is marked timed out.",
                "Example: 1800",
            ),
            "SUBAGENTS_ANNOUNCE_TO_CHAT" => (
                "Whether finished subagents post completion notices back to the parent chat.",
                "Example: true or false",
            ),
            "SUBAGENTS_MAX_SPAWN_DEPTH" => (
                "Maximum recursive subagent nesting depth.",
                "Example: 1",
            ),
            "SUBAGENTS_MAX_CHILDREN_PER_RUN" => (
                "Maximum active child runs that one parent run may create.",
                "Example: 5",
            ),
            "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED" => (
                "Route thread replies to the currently focused subagent when the channel supports it.",
                "Example: true or false",
            ),
            "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS" => (
                "Polling interval for relaying pending subagent completion notices.",
                "Example: 15",
            ),
            "SUBAGENTS_MAX_TOKENS_PER_RUN" => (
                "Default token budget ceiling for sessions_spawn and subagents_orchestrate.",
                "Example: 240000",
            ),
            "SUBAGENTS_ORCHESTRATE_MAX_WORKERS" => (
                "Worker cap used by subagents_orchestrate fan-out.",
                "Example: 5",
            ),
            "SUBAGENTS_ACP_ENABLED" => (
                "Enable ACP-backed external subagent execution for sessions_spawn(runtime=\"acp\").",
                "Example: true or false",
            ),
            "SUBAGENTS_ACP_COMMAND" => (
                "Default ACP worker command used when no named target is selected.",
                "Example: codex",
            ),
            "SUBAGENTS_ACP_ARGS" => (
                "Default ACP worker args as csv or JSON array.",
                "Example: [\"--model\",\"gpt-5.4\"]",
            ),
            "SUBAGENTS_ACP_ENV_JSON" => (
                "Default ACP worker env vars as JSON object.",
                "Example: {\"OPENAI_API_KEY\":\"sk-...\"}",
            ),
            "SUBAGENTS_ACP_AUTO_APPROVE" => (
                "Whether the default ACP target auto-approves ACP permission requests.",
                "Example: true or false",
            ),
            "SUBAGENTS_ACP_DEFAULT_TARGET" => (
                "Named ACP target to use by default when runtime_target is omitted.",
                "Example: codex-fast",
            ),
            "SUBAGENTS_ACP_TARGETS_JSON" => (
                "Named ACP worker definitions as JSON object keyed by target name.",
                "Example: {\"codex-fast\":{\"enabled\":true,\"command\":\"codex\",\"args\":[\"--model\",\"gpt-5.4\"]}}",
            ),
            "DATA_DIR" => (
                "Root directory for runtime data (DB, sessions, memory, skills).",
                "Example: ./microclaw.data",
            ),
            "WORKING_DIR" => (
                "Filesystem base path for tools like read/write/bash/glob.",
                "Example: ./tmp",
            ),
            "OVERRIDE_TIMEZONE" => (
                "Optional IANA timezone override for scheduling. Empty uses system timezone.",
                "Example: Asia/Shanghai",
            ),
            "SOULS_DIR" => (
                "Directory storing SOUL.md personalities. Empty uses <data_dir>/souls.",
                "Example: ./microclaw.data/souls",
            ),
            "REFLECTOR_ENABLED" => (
                "Enable periodic memory reflection that extracts structured memories from chat.",
                "Example: true or false",
            ),
            "REFLECTOR_INTERVAL_MINS" => ("How often memory reflection runs.", "Example: 15"),
            "MEMORY_TOKEN_BUDGET" => (
                "Approximate token budget for injected memories in the system prompt.",
                "Example: 1500",
            ),
            "EMBEDDING_PROVIDER" => (
                "Provider for memory embeddings (semantic retrieval). Optional feature.",
                "Example: openai or ollama",
            ),
            "EMBEDDING_API_KEY" => (
                "API key for embedding provider, if required.",
                "Example: sk-xxxx",
            ),
            "EMBEDDING_BASE_URL" => (
                "Custom endpoint for embedding provider.",
                "Example: https://api.openai.com/v1",
            ),
            "EMBEDDING_MODEL" => (
                "Embedding model name for memory vectors.",
                "Example: text-embedding-3-small",
            ),
            "EMBEDDING_DIM" => ("Embedding vector dimension.", "Example: 1536"),
            "SANDBOX_ENABLED" => (
                "Enable sandbox mode for tool execution isolation.",
                "Example: true or false",
            ),
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => (
                "Require explicit confirmation before running high-risk tools.",
                "Example: true or false",
            ),
            _ if key.ends_with("_BOT_TOKEN") => (
                "Bot token for this channel account.",
                "Example: 123456:ABCDEF...",
            ),
            _ if key.ends_with("_MODEL") => (
                "Per-channel/per-account provider profile override entry point. Press Enter to choose profile; model follows the profile.",
                "Example: choose provider1 or leave empty for main",
            ),
            _ if key.ends_with("_LLM_PROVIDER") => (
                "Per-channel/per-account profile id override. Empty means use main/global default.",
                "Example: provider1",
            ),
            _ if key.ends_with("_LLM_API_KEY") => (
                "Per-channel/per-account API key override.",
                "Example: sk-xxxx",
            ),
            _ if key.ends_with("_LLM_BASE_URL") => (
                "Per-channel/per-account base URL override.",
                "Example: https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            _ if key.ends_with("_ALLOWED_USER_IDS") => (
                "Allowed user IDs for this bot/account.",
                "Example: 12345,67890",
            ),
            _ if key.ends_with("_SOUL_PATH") => (
                "SOUL.md filename/path used by this bot/account.",
                "Example: souls/soul-zhang.md",
            ),
            _ if key.starts_with("DYN_") => (
                "Dynamic channel field loaded from channel setup definition.",
                "Example: fill with your channel-specific credential/config value",
            ),
            _ => ("Configuration value used by setup/runtime.", ""),
        }
    }

    fn field_display_order(key: &str) -> usize {
        const ORDER_MODEL_BASE: usize = 0;
        const ORDER_CHANNEL_BASE: usize = 100;
        const ORDER_APP_BASE: usize = 20_000;
        const ORDER_MEMORY_BASE: usize = 21_000;
        const ORDER_EMBED_BASE: usize = 22_000;
        const ORDER_SANDBOX_BASE: usize = 23_000;
        const ORDER_A2A_BASE: usize = 24_000;
        const ORDER_SUBAGENTS_BASE: usize = 25_000;

        if key.starts_with("DYN_") {
            for (ch_idx, ch) in DYNAMIC_CHANNELS.iter().enumerate() {
                let channel_base = ORDER_CHANNEL_BASE + 2_000 + ch_idx * 1_000;
                if key == dynamic_bot_count_field_key(ch.name) {
                    return channel_base;
                }
                for slot in 1..=MAX_BOT_SLOTS {
                    let slot_base = channel_base + slot * 50;
                    if key == dynamic_slot_id_field_key(ch.name, slot) {
                        return slot_base + 1;
                    }
                    if key == dynamic_slot_enabled_field_key(ch.name, slot) {
                        return slot_base + 2;
                    }
                    if key == dynamic_slot_soul_path_field_key(ch.name, slot) {
                        return slot_base + 3;
                    }
                    for (field_idx, f) in ch.fields.iter().enumerate() {
                        if key == dynamic_slot_field_key(ch.name, slot, f.yaml_key) {
                            return slot_base + 4 + field_idx;
                        }
                    }
                    if key == dynamic_slot_llm_provider_key(ch.name, slot) {
                        return slot_base + 30;
                    }
                    if key == dynamic_slot_llm_api_key_key(ch.name, slot) {
                        return slot_base + 31;
                    }
                    if key == dynamic_slot_llm_base_url_key(ch.name, slot) {
                        return slot_base + 32;
                    }
                }
                if key == dynamic_account_id_field_key(ch.name) {
                    return channel_base + 900;
                }
                if key == dynamic_accounts_json_field_key(ch.name) {
                    return channel_base + 901;
                }
                for (field_idx, f) in ch.fields.iter().enumerate() {
                    if key == dynamic_field_key(ch.name, f.yaml_key) {
                        return channel_base + 910 + field_idx;
                    }
                }
            }
            return usize::MAX;
        }
        match key {
            // 1) Model
            "LLM_PROVIDER" => ORDER_MODEL_BASE,
            "LLM_API_KEY" => ORDER_MODEL_BASE + 1,
            "LLM_MODEL" => ORDER_MODEL_BASE + 2,
            "LLM_BASE_URL" => ORDER_MODEL_BASE + 3,
            "LLM_USER_AGENT" => ORDER_MODEL_BASE + 4,
            "SHOW_THINKING" => ORDER_MODEL_BASE + 5,
            _ if key == llm_provider_profiles_key() => ORDER_MODEL_BASE + 6,
            // 2) Channel (dynamic channel fields are placed in the branch above)
            "ENABLED_CHANNELS" => ORDER_CHANNEL_BASE,
            "WEB_HOOKS_TOKEN" => ORDER_CHANNEL_BASE + 1,
            "WEB_HOOKS_DEFAULT_SESSION_KEY" => ORDER_CHANNEL_BASE + 2,
            "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY" => ORDER_CHANNEL_BASE + 3,
            "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES" => ORDER_CHANNEL_BASE + 4,
            "TELEGRAM_BOT_TOKEN" => ORDER_CHANNEL_BASE + 20,
            "BOT_USERNAME" => ORDER_CHANNEL_BASE + 21,
            "TELEGRAM_ACCOUNT_ID" => ORDER_CHANNEL_BASE + 22,
            _ if key == telegram_bot_count_key() => ORDER_CHANNEL_BASE + 23,
            "TELEGRAM_MODEL" => ORDER_CHANNEL_BASE + 24,
            "TELEGRAM_ALLOWED_USER_IDS" => ORDER_CHANNEL_BASE + 25,
            "TELEGRAM_TOPIC_ROUTING" => ORDER_CHANNEL_BASE + 26,
            "TELEGRAM_LLM_PROVIDER" => ORDER_CHANNEL_BASE + 27,
            "TELEGRAM_LLM_API_KEY" => ORDER_CHANNEL_BASE + 28,
            "TELEGRAM_LLM_BASE_URL" => ORDER_CHANNEL_BASE + 29,
            "DISCORD_BOT_TOKEN" => ORDER_CHANNEL_BASE + 900,
            "DISCORD_ACCOUNT_ID" => ORDER_CHANNEL_BASE + 901,
            "DISCORD_MODEL" => ORDER_CHANNEL_BASE + 902,
            "DISCORD_LLM_PROVIDER" => ORDER_CHANNEL_BASE + 903,
            "DISCORD_LLM_API_KEY" => ORDER_CHANNEL_BASE + 904,
            "DISCORD_LLM_BASE_URL" => ORDER_CHANNEL_BASE + 905,
            "DISCORD_ACCOUNTS_JSON" => ORDER_CHANNEL_BASE + 906,
            _ if key.starts_with("TELEGRAM_BOT") => {
                for slot in 1..=MAX_BOT_SLOTS {
                    let base = ORDER_CHANNEL_BASE + 100 + (slot * 10);
                    if key == telegram_slot_id_key(slot) {
                        return base + 1;
                    }
                    if key == telegram_slot_enabled_key(slot) {
                        return base + 2;
                    }
                    if key == telegram_slot_token_key(slot) {
                        return base + 3;
                    }
                    if key == telegram_slot_username_key(slot) {
                        return base + 4;
                    }
                    if key == telegram_slot_model_key(slot) {
                        return base + 5;
                    }
                    if key == telegram_slot_soul_path_key(slot) {
                        return base + 6;
                    }
                    if key == telegram_slot_allowed_user_ids_key(slot) {
                        return base + 7;
                    }
                    if key == telegram_slot_topic_routing_key(slot) {
                        return base + 8;
                    }
                }
                usize::MAX
            }
            // 3) App
            "DATA_DIR" => ORDER_APP_BASE,
            "WORKING_DIR" => ORDER_APP_BASE + 1,
            "OVERRIDE_TIMEZONE" => ORDER_APP_BASE + 2,
            "SOULS_DIR" => ORDER_APP_BASE + 3,
            // 4) Memory
            "REFLECTOR_ENABLED" => ORDER_MEMORY_BASE,
            "REFLECTOR_INTERVAL_MINS" => ORDER_MEMORY_BASE + 1,
            "MEMORY_TOKEN_BUDGET" => ORDER_MEMORY_BASE + 2,
            // 5) Embedding
            "EMBEDDING_PROVIDER" => ORDER_EMBED_BASE,
            "EMBEDDING_API_KEY" => ORDER_EMBED_BASE + 1,
            "EMBEDDING_BASE_URL" => ORDER_EMBED_BASE + 2,
            "EMBEDDING_MODEL" => ORDER_EMBED_BASE + 3,
            "EMBEDDING_DIM" => ORDER_EMBED_BASE + 4,
            // 6) Sandbox
            "SANDBOX_ENABLED" => ORDER_SANDBOX_BASE,
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => ORDER_SANDBOX_BASE + 1,
            // 7) A2A
            "A2A_ENABLED" => ORDER_A2A_BASE,
            "A2A_PUBLIC_BASE_URL" => ORDER_A2A_BASE + 1,
            "A2A_AGENT_NAME" => ORDER_A2A_BASE + 2,
            "A2A_AGENT_DESCRIPTION" => ORDER_A2A_BASE + 3,
            "A2A_SHARED_TOKENS" => ORDER_A2A_BASE + 4,
            "A2A_PEERS_JSON" => ORDER_A2A_BASE + 5,
            // 8) Sub-agents (last)
            "SUBAGENTS_MAX_CONCURRENT" => ORDER_SUBAGENTS_BASE,
            "SUBAGENTS_MAX_ACTIVE_PER_CHAT" => ORDER_SUBAGENTS_BASE + 1,
            "SUBAGENTS_RUN_TIMEOUT_SECS" => ORDER_SUBAGENTS_BASE + 2,
            "SUBAGENTS_ANNOUNCE_TO_CHAT" => ORDER_SUBAGENTS_BASE + 3,
            "SUBAGENTS_MAX_SPAWN_DEPTH" => ORDER_SUBAGENTS_BASE + 4,
            "SUBAGENTS_MAX_CHILDREN_PER_RUN" => ORDER_SUBAGENTS_BASE + 5,
            "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED" => ORDER_SUBAGENTS_BASE + 6,
            "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS" => ORDER_SUBAGENTS_BASE + 7,
            "SUBAGENTS_MAX_TOKENS_PER_RUN" => ORDER_SUBAGENTS_BASE + 8,
            "SUBAGENTS_ORCHESTRATE_MAX_WORKERS" => ORDER_SUBAGENTS_BASE + 9,
            _ => usize::MAX,
        }
    }

    fn current_section(&self) -> &'static str {
        Self::section_for_key(&self.selected_field().key)
    }

    fn progress_bar(&self, width: usize) -> String {
        let (done, total) = self.selected_progress();
        let fill = (done * width) / total;
        let mut s = String::new();
        for i in 0..width {
            if i < fill {
                s.push('█');
            } else {
                s.push('░');
            }
        }
        s
    }
}

#[allow(clippy::too_many_arguments)]
fn perform_online_validation(
    telegram_enabled: bool,
    include_telegram_status: bool,
    tg_token: &str,
    env_username: &str,
    provider: &str,
    api_key: &str,
    base_url: &str,
    configured_user_agent: &str,
    model: &str,
    codex_account_id: Option<&str>,
) -> Result<Vec<String>, MicroClawError> {
    const VALIDATION_MAX_OUTPUT_TOKENS: u32 = 64;
    let mut checks = Vec::new();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(llm_user_agent(configured_user_agent))
        .build()?;

    // --- Telegram validation (optional) ---
    if telegram_enabled {
        let tg_resp: serde_json::Value = client
            .get(format!("https://api.telegram.org/bot{tg_token}/getMe"))
            .send()?
            .json()?;
        let ok = tg_resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            return Err(MicroClawError::Config(
                "Telegram getMe failed (check TELEGRAM_BOT_TOKEN)".into(),
            ));
        }
        let actual_username = tg_resp
            .get("result")
            .and_then(|r| r.get("username"))
            .and_then(|u| u.as_str())
            .unwrap_or_default()
            .to_string();
        if !env_username.is_empty()
            && !actual_username.is_empty()
            && env_username != actual_username
        {
            checks.push(format!(
                "Telegram OK (token user={actual_username}, configured={env_username})"
            ));
        } else {
            checks.push(format!("Telegram OK ({actual_username})"));
        }
    } else {
        push_telegram_disabled_status(&mut checks, include_telegram_status);
    }

    // --- LLM validation: send a minimal "hi" message ---
    let preset = find_provider_preset(provider);
    let protocol = provider_protocol(provider);
    let model = if model.is_empty() {
        default_model_for_provider(provider).to_string()
    } else {
        model.to_string()
    };

    if protocol == ProviderProtocol::Anthropic {
        let mut base = if base_url.is_empty() {
            "https://api.anthropic.com".to_string()
        } else {
            base_url.trim_end_matches('/').to_string()
        };
        if base.ends_with("/v1/messages") {
            base = base.trim_end_matches("/v1/messages").to_string();
        }
        let body = serde_json::json!({
            "model": model,
            "max_tokens": VALIDATION_MAX_OUTPUT_TOKENS,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let resp = client
            .post(format!("{base}/v1/messages"))
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            let detail = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(MicroClawError::Config(format!(
                "LLM validation failed: {detail}"
            )));
        }
        checks.push(format!("LLM OK (anthropic, model={model})"));
    } else {
        let base = resolve_openai_compat_validation_base(provider, base_url, preset);
        let resp = if is_openai_codex_provider(provider) {
            let body = serde_json::json!({
                "model": model,
                "input": [{"type":"message","role":"user","content":"hi"}],
                "instructions": "You are a helpful assistant.",
                "store": false,
                "stream": true,
            });
            let mut req = client
                .post(format!("{}/responses", base.trim_end_matches('/')))
                .header("content-type", "application/json")
                .body(body.to_string());
            if !api_key.trim().is_empty() {
                req = req.bearer_auth(api_key);
            }
            if let Some(account_id) = codex_account_id {
                if !account_id.trim().is_empty() {
                    req = req.header("ChatGPT-Account-ID", account_id.trim());
                }
            }
            req.send()?
        } else {
            let endpoint = format!("{}/chat/completions", base.trim_end_matches('/'));
            let mut body = serde_json::json!({
                "model": model,
                "max_tokens": VALIDATION_MAX_OUTPUT_TOKENS,
                "messages": [{"role": "user", "content": "hi"}]
            });
            let mut resp = send_openai_validation_chat_request(&client, &endpoint, api_key, &body)?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                if should_retry_with_max_completion_tokens(&text)
                    && switch_to_max_completion_tokens(&mut body)
                {
                    resp = send_openai_validation_chat_request(&client, &endpoint, api_key, &body)?;
                } else {
                    return Err(MicroClawError::Config(format!(
                        "LLM validation failed: {}",
                        extract_openai_error_detail(status, &text)
                    )));
                }
            }
            resp
        };
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            if is_validation_output_capped_error(&text) {
                checks.push(format!(
                    "LLM OK (openai-compatible, model={model}; probe output capped)"
                ));
                return Ok(checks);
            }
            let detail = extract_openai_error_detail(status, &text);
            return Err(MicroClawError::Config(format!(
                "LLM validation failed: {detail}"
            )));
        }
        checks.push(format!("LLM OK (openai-compatible, model={model})"));
    }

    Ok(checks)
}

fn push_telegram_disabled_status(checks: &mut Vec<String>, include_telegram_status: bool) {
    if include_telegram_status {
        checks.push("Telegram skipped (disabled)".into());
    }
}

fn send_openai_validation_chat_request(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    api_key: &str,
    body: &serde_json::Value,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let mut req = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body.to_string());
    if !api_key.trim().is_empty() {
        req = req.bearer_auth(api_key);
    }
    req.send()
}

fn extract_openai_error_detail(status: reqwest::StatusCode, text: &str) -> String {
    fn extract_message(value: &serde_json::Value) -> Option<String> {
        if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
            return Some(message.to_string());
        }
        if let Some(error) = value.get("error") {
            if let Some(message) = extract_message(error) {
                return Some(message);
            }
        }
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(message) = extract_message(item) {
                    return Some(message);
                }
            }
        }
        None
    }

    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| extract_message(&v))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

fn should_retry_with_max_completion_tokens(error_text: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(error_text) {
        let param_is_max_tokens = value
            .get("error")
            .and_then(|e| e.get("param"))
            .and_then(|p| p.as_str())
            .map(|p| p == "max_tokens")
            .unwrap_or(false);
        if param_is_max_tokens {
            return true;
        }
    }

    let lower = error_text.to_ascii_lowercase();
    lower.contains("max_tokens") && lower.contains("max_completion_tokens")
}

fn is_validation_output_capped_error(error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    lower.contains("max_tokens or model output limit was reached")
        || (lower.contains("max_tokens") && lower.contains("output limit"))
}

fn switch_to_max_completion_tokens(body: &mut serde_json::Value) -> bool {
    if body.get("max_completion_tokens").is_some() {
        return false;
    }
    let Some(max_tokens) = body.get("max_tokens").cloned() else {
        return false;
    };
    if let Some(obj) = body.as_object_mut() {
        obj.remove("max_tokens");
        obj.insert("max_completion_tokens".to_string(), max_tokens);
        return true;
    }
    false
}

fn resolve_openai_compat_validation_base(
    provider: &str,
    base_url: &str,
    preset: Option<&ProviderPreset>,
) -> String {
    let resolved = if base_url.is_empty() {
        preset
            .map(|p| p.default_base_url)
            .filter(|s| !s.is_empty())
            .unwrap_or("https://api.openai.com/v1")
            .trim_end_matches('/')
            .to_string()
    } else {
        base_url.trim_end_matches('/').to_string()
    };

    if is_openai_codex_provider(provider) {
        if let Some(codex_base) = codex_config_default_openai_base_url() {
            return codex_base.trim_end_matches('/').to_string();
        }
        return "https://chatgpt.com/backend-api/codex".to_string();
    }

    resolved
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 6 {
        return "***".into();
    }
    let left = floor_char_boundary(s, 3.min(s.len()));
    let right_start = floor_char_boundary(s, s.len().saturating_sub(2));
    format!("{}***{}", &s[..left], &s[right_start..])
}

fn truncate_single_line(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    for ch in text.chars().take(max_chars - 1) {
        out.push(ch);
    }
    out.push('…');
    out
}

fn config_backup_dir_for(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CONFIG_BACKUP_DIR_NAME)
}

fn prune_old_config_backups(
    backup_dir: &Path,
    file_name: &str,
    keep_latest: usize,
) -> Result<(), MicroClawError> {
    let prefix = format!("{file_name}.bak.");
    let mut entries = Vec::new();
    for entry in fs::read_dir(backup_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        entries.push((modified, entry.path()));
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in entries.into_iter().skip(keep_latest) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn create_config_backup(path: &Path) -> Result<Option<String>, MicroClawError> {
    if !path.exists() {
        return Ok(None);
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("microclaw.config.yaml");
    let backup_dir = config_backup_dir_for(path);
    fs::create_dir_all(&backup_dir).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to create config backup dir {}: {}",
            backup_dir.display(),
            e
        ))
    })?;
    let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let backup_path = backup_dir.join(format!("{file_name}.bak.{ts}"));
    fs::copy(path, &backup_path).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to write config backup {}: {}",
            backup_path.display(),
            e
        ))
    })?;
    let _ = prune_old_config_backups(&backup_dir, file_name, MAX_CONFIG_BACKUPS);
    Ok(Some(backup_path.display().to_string()))
}

fn save_config_yaml(
    path: &Path,
    values: &HashMap<String, String>,
) -> Result<Option<String>, MicroClawError> {
    let backup = create_config_backup(path)?;

    let get = |key: &str| values.get(key).cloned().unwrap_or_default();
    let get_with_fallback = |key: &str, default: &str| {
        values
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let data_dir = values
        .get("DATA_DIR")
        .cloned()
        .unwrap_or_else(default_data_dir_for_setup);
    let souls_dir = values
        .get("SOULS_DIR")
        .cloned()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| {
            Path::new(&data_dir)
                .join("souls")
                .to_string_lossy()
                .to_string()
        });

    let enabled_raw = get("ENABLED_CHANNELS");
    let valid_channel_names: Vec<&str> = {
        let mut v = vec!["web", "telegram", "discord"];
        for ch in DYNAMIC_CHANNELS {
            v.push(ch.name);
        }
        v
    };
    let mut channels = Vec::new();
    for part in enabled_raw.split(',') {
        let p = part.trim().to_lowercase();
        if valid_channel_names.contains(&p.as_str()) && !channels.iter().any(|v| v == &p) {
            channels.push(p);
        }
    }

    let selected_channels = if channels.is_empty() {
        vec!["web".to_string()]
    } else {
        channels.clone()
    };
    let channel_selected = |name: &str| selected_channels.iter().any(|c| c == name);
    let web_hooks_token = get(web_hooks_token_key());
    let web_hooks_default_session_key = get(web_hooks_default_session_key_key());
    let web_hooks_allow_request_session_key_raw = get(web_hooks_allow_request_session_key_key());
    let web_hooks_allow_request_session_key =
        parse_boolish(&web_hooks_allow_request_session_key_raw, false)?;
    let web_hooks_allowed_session_key_prefixes =
        parse_string_list_field(&get(web_hooks_allowed_session_key_prefixes_key()))?;
    let a2a_enabled = parse_boolish(&get(a2a_enabled_key()), false)?;
    let a2a_public_base_url = get(a2a_public_base_url_key()).trim().to_string();
    let a2a_agent_name = get(a2a_agent_name_key()).trim().to_string();
    let a2a_agent_description = get(a2a_agent_description_key()).trim().to_string();
    let a2a_shared_tokens = parse_string_list_field(&get(a2a_shared_tokens_key()))?;
    let a2a_peers_raw = get(a2a_peers_json_key());
    let a2a_peers = if a2a_peers_raw.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str::<HashMap<String, crate::config::A2APeerConfig>>(a2a_peers_raw.trim())
            .map_err(|e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    a2a_peers_json_key()
                ))
            })?
    };
    let provider_presets = parse_provider_presets_json_value(
        &get(llm_provider_profiles_key()),
        llm_provider_profiles_key(),
    )?;
    let parse_usize_or_default = |raw: String, key: &str, default: usize| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        trimmed
            .parse::<usize>()
            .map_err(|e| MicroClawError::Config(format!("{key} must be a positive integer: {e}")))
    };
    let parse_u64_or_default = |raw: String, key: &str, default: u64| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        trimmed
            .parse::<u64>()
            .map_err(|e| MicroClawError::Config(format!("{key} must be a positive integer: {e}")))
    };
    let parse_i64_or_default = |raw: String, key: &str, default: i64| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        trimmed
            .parse::<i64>()
            .map_err(|e| MicroClawError::Config(format!("{key} must be a positive integer: {e}")))
    };
    let subagents_max_concurrent = parse_usize_or_default(
        get_with_fallback(subagents_max_concurrent_key(), "4"),
        subagents_max_concurrent_key(),
        4,
    )?;
    let subagents_max_active_per_chat = parse_usize_or_default(
        get_with_fallback(subagents_max_active_per_chat_key(), "5"),
        subagents_max_active_per_chat_key(),
        5,
    )?;
    let subagents_run_timeout_secs = parse_u64_or_default(
        get_with_fallback(subagents_run_timeout_secs_key(), "900"),
        subagents_run_timeout_secs_key(),
        900,
    )?;
    let subagents_announce_to_chat = parse_boolish(&get(subagents_announce_to_chat_key()), true)?;
    let subagents_max_spawn_depth = parse_usize_or_default(
        get_with_fallback(subagents_max_spawn_depth_key(), "1"),
        subagents_max_spawn_depth_key(),
        1,
    )?;
    let subagents_max_children_per_run = parse_usize_or_default(
        get_with_fallback(subagents_max_children_per_run_key(), "5"),
        subagents_max_children_per_run_key(),
        5,
    )?;
    let subagents_thread_bound_routing_enabled =
        parse_boolish(&get(subagents_thread_bound_routing_enabled_key()), true)?;
    let subagents_announce_relay_interval_secs = parse_u64_or_default(
        get_with_fallback(subagents_announce_relay_interval_secs_key(), "15"),
        subagents_announce_relay_interval_secs_key(),
        15,
    )?;
    let subagents_max_tokens_per_run = parse_i64_or_default(
        get_with_fallback(subagents_max_tokens_per_run_key(), "400000"),
        subagents_max_tokens_per_run_key(),
        400_000,
    )?;
    let subagents_orchestrate_max_workers = parse_usize_or_default(
        get_with_fallback(subagents_orchestrate_max_workers_key(), "5"),
        subagents_orchestrate_max_workers_key(),
        5,
    )?;
    let subagents_acp_enabled = parse_boolish(&get(subagents_acp_enabled_key()), false)?;
    let subagents_acp_command = get(subagents_acp_command_key()).trim().to_string();
    let subagents_acp_args = parse_string_list_field(&get(subagents_acp_args_key()))?;
    let subagents_acp_env_raw = get(subagents_acp_env_json_key());
    let subagents_acp_env = if subagents_acp_env_raw.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str::<HashMap<String, String>>(subagents_acp_env_raw.trim()).map_err(
            |e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    subagents_acp_env_json_key()
                ))
            },
        )?
    };
    let subagents_acp_auto_approve = parse_boolish(&get(subagents_acp_auto_approve_key()), true)?;
    let subagents_acp_default_target = get(subagents_acp_default_target_key()).trim().to_string();
    let subagents_acp_targets_raw = get(subagents_acp_targets_json_key());
    let subagents_acp_targets = if subagents_acp_targets_raw.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str::<HashMap<String, crate::config::SubagentAcpTargetConfig>>(
            subagents_acp_targets_raw.trim(),
        )
        .map_err(|e| {
            MicroClawError::Config(format!(
                "{} must be valid JSON object: {e}",
                subagents_acp_targets_json_key()
            ))
        })?
    };
    let telegram_token = if !get("TELEGRAM_BOT_TOKEN").trim().is_empty() {
        get("TELEGRAM_BOT_TOKEN")
    } else {
        get(&telegram_slot_token_key(1))
    };
    let telegram_username = if !get("BOT_USERNAME").trim().is_empty() {
        get("BOT_USERNAME")
    } else {
        get(&telegram_slot_username_key(1))
    };
    let telegram_account_id =
        account_id_from_value(&if !get("TELEGRAM_ACCOUNT_ID").trim().is_empty() {
            get("TELEGRAM_ACCOUNT_ID")
        } else {
            get(&telegram_slot_id_key(1))
        });
    let telegram_profile_override = get("TELEGRAM_MODEL");
    let telegram_topic_routing_raw = get(telegram_topic_routing_key());
    let telegram_topic_routing = if telegram_topic_routing_raw.trim().is_empty() {
        false
    } else {
        parse_boolish(telegram_topic_routing_raw.trim(), false).map_err(|_| {
            MicroClawError::Config(format!(
                "{} must be true/false (or 1/0)",
                telegram_topic_routing_key()
            ))
        })?
    };
    let telegram_llm_provider = get(telegram_llm_provider_key());
    // Channel-level provider_preset: slot 1 (the default bot) is the
    // authoritative source when present, so clearing the bot preset also
    // clears the channel-level value.  Fall back to TELEGRAM_MODEL /
    // TELEGRAM_LLM_PROVIDER only for legacy configs that lack slot fields.
    let slot1_preset = get(&telegram_slot_model_key(1));
    let telegram_channel_profile_override = if !slot1_preset.trim().is_empty() {
        slot1_preset.trim().to_string()
    } else if values.contains_key(&telegram_slot_model_key(1)) {
        // Slot 1 field exists but is empty — user explicitly cleared it
        String::new()
    } else if !telegram_profile_override.trim().is_empty() {
        telegram_profile_override.trim().to_string()
    } else {
        telegram_llm_provider.trim().to_string()
    };
    let telegram_llm_api_key = get(telegram_llm_api_key_key());
    let telegram_llm_base_url = get(telegram_llm_base_url_key());
    let telegram_channel_allowed_user_ids = parse_i64_list_field(
        &get(telegram_allowed_user_ids_key()),
        telegram_allowed_user_ids_key(),
    )?;
    let telegram_bot_count =
        parse_bot_count(&get(telegram_bot_count_key()), telegram_bot_count_key())?;
    let mut telegram_slot_accounts = serde_json::Map::new();
    for slot in 1..=telegram_bot_count {
        let id = get(&telegram_slot_id_key(slot));
        let token = get(&telegram_slot_token_key(slot));
        let username = get(&telegram_slot_username_key(slot));
        let provider_preset = get(&telegram_slot_model_key(slot));
        let soul_path =
            normalize_soul_path_input(&get(&telegram_slot_soul_path_key(slot)), &souls_dir);
        let allowed_user_ids_raw = get(&telegram_slot_allowed_user_ids_key(slot));
        let allowed_user_ids = parse_i64_list_field(
            &allowed_user_ids_raw,
            &telegram_slot_allowed_user_ids_key(slot),
        )?;
        let slot_topic_routing_raw = get(&telegram_slot_topic_routing_key(slot));
        let slot_topic_routing_enabled = if slot_topic_routing_raw.trim().is_empty() {
            None
        } else {
            Some(
                parse_boolish(slot_topic_routing_raw.trim(), false).map_err(|_| {
                    MicroClawError::Config(format!(
                        "{} must be true/false (or 1/0)",
                        telegram_slot_topic_routing_key(slot)
                    ))
                })?,
            )
        };
        let enabled = parse_boolish(&get(&telegram_slot_enabled_key(slot)), true)?;
        let has_any = !token.trim().is_empty()
            || !username.trim().is_empty()
            || !provider_preset.trim().is_empty()
            || !soul_path.is_empty()
            || !allowed_user_ids.is_empty()
            || slot_topic_routing_enabled.is_some();
        if !has_any {
            continue;
        }
        let account_id = account_id_from_value(&id);
        if !is_valid_account_id(&account_id) {
            return Err(MicroClawError::Config(format!(
                "{} must use only letters, numbers, '_' or '-'",
                telegram_slot_id_key(slot)
            )));
        }
        let mut account = serde_json::Map::new();
        account.insert("enabled".into(), serde_json::Value::Bool(enabled));
        if !token.trim().is_empty() {
            account.insert(
                "bot_token".into(),
                serde_json::Value::String(token.trim().to_string()),
            );
        }
        if !username.trim().is_empty() {
            account.insert(
                "bot_username".into(),
                serde_json::Value::String(username.trim().to_string()),
            );
        }
        if !provider_preset.trim().is_empty()
            && !provider_preset.trim().eq_ignore_ascii_case("main")
        {
            account.insert(
                "provider_preset".into(),
                serde_json::Value::String(provider_preset.trim().to_string()),
            );
        }
        if let Some(enabled) = slot_topic_routing_enabled {
            account.insert(
                "topic_routing".into(),
                serde_json::json!({ "enabled": enabled }),
            );
        }
        if !soul_path.is_empty() {
            account.insert("soul_path".into(), serde_json::Value::String(soul_path));
        }
        if !allowed_user_ids.is_empty() {
            account.insert(
                "allowed_user_ids".into(),
                serde_json::Value::Array(
                    allowed_user_ids
                        .into_iter()
                        .map(|id| serde_json::Value::Number(id.into()))
                        .collect(),
                ),
            );
        }
        telegram_slot_accounts.insert(account_id, serde_json::Value::Object(account));
    }
    let telegram_accounts = if !telegram_slot_accounts.is_empty() {
        Some(telegram_slot_accounts)
    } else {
        None
    };
    let discord_token = get("DISCORD_BOT_TOKEN");
    let discord_account_id = account_id_from_value(&get("DISCORD_ACCOUNT_ID"));
    let discord_profile_override = get("DISCORD_MODEL");
    let discord_llm_provider = get(discord_llm_provider_key());
    let discord_channel_profile_override = if !discord_profile_override.trim().is_empty() {
        discord_profile_override.trim().to_string()
    } else {
        discord_llm_provider.trim().to_string()
    };
    let discord_llm_api_key = get(discord_llm_api_key_key());
    let discord_llm_base_url = get(discord_llm_base_url_key());
    let discord_accounts_json = get("DISCORD_ACCOUNTS_JSON");
    let discord_accounts =
        parse_accounts_json_value(&discord_accounts_json, "DISCORD_ACCOUNTS_JSON")?;

    let pick_default_account_id =
        |configured: &str, accounts: &serde_json::Map<String, serde_json::Value>| {
            let configured_trimmed = configured.trim();
            if !configured_trimmed.is_empty() && accounts.contains_key(configured_trimmed) {
                return configured_trimmed.to_string();
            }
            if accounts.contains_key("default") {
                return "default".to_string();
            }
            let mut keys: Vec<String> = accounts.keys().cloned().collect();
            keys.sort();
            keys.first()
                .cloned()
                .unwrap_or_else(|| default_account_id().to_string())
        };

    let telegram_present = !telegram_token.trim().is_empty()
        || !telegram_username.trim().is_empty()
        || !telegram_channel_profile_override.trim().is_empty()
        || !telegram_llm_api_key.trim().is_empty()
        || !telegram_llm_base_url.trim().is_empty()
        || !telegram_profile_override.trim().is_empty()
        || !normalize_soul_path_input(&get(&telegram_slot_soul_path_key(1)), &souls_dir).is_empty()
        || !telegram_channel_allowed_user_ids.is_empty()
        || telegram_accounts
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        || telegram_bot_count > 1;
    let discord_present = !discord_token.trim().is_empty()
        || !discord_channel_profile_override.trim().is_empty()
        || !discord_llm_api_key.trim().is_empty()
        || !discord_llm_base_url.trim().is_empty()
        || !discord_profile_override.trim().is_empty()
        || discord_accounts
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
    // Use slot presence keys so optional defaults do not create disabled blocks unexpectedly.
    let dynamic_channel_include: Vec<(&DynamicChannelDef, bool)> = DYNAMIC_CHANNELS
        .iter()
        .map(|ch| {
            let selected = channel_selected(ch.name);
            if dynamic_channel_uses_minimal_setup(ch.name) {
                return (ch, selected);
            }
            let bot_count = parse_bot_count(
                &get(&dynamic_bot_count_field_key(ch.name)),
                &dynamic_bot_count_field_key(ch.name),
            )
            .unwrap_or(1);
            let has_slot_presence = (1..=bot_count).any(|slot| {
                ch.presence_keys.iter().any(|yaml_key| {
                    !get(&dynamic_slot_field_key(ch.name, slot, yaml_key))
                        .trim()
                        .is_empty()
                }) || !normalize_soul_path_input(
                    &get(&dynamic_slot_soul_path_field_key(ch.name, slot)),
                    &souls_dir,
                )
                .is_empty()
                    || !get(&dynamic_slot_llm_provider_key(ch.name, slot))
                        .trim()
                        .is_empty()
                    || !get(&dynamic_slot_llm_api_key_key(ch.name, slot))
                        .trim()
                        .is_empty()
                    || !get(&dynamic_slot_llm_base_url_key(ch.name, slot))
                        .trim()
                        .is_empty()
            });
            (ch, selected || has_slot_presence)
        })
        .collect();

    let mut yaml = String::new();
    yaml.push_str("# MicroClaw configuration\n\n");
    yaml.push_str(
        "# Channel settings (set `enabled: false` to keep credentials without activating the channel)\n",
    );
    yaml.push_str("# setup wizard default: web when no channels are selected\n");
    yaml.push_str("channels:\n");

    yaml.push_str("  web:\n");
    yaml.push_str(&format!("    enabled: {}\n", channel_selected("web")));
    if !web_hooks_token.trim().is_empty() {
        yaml.push_str(&format!(
            "    hooks_token: {}\n",
            yaml_double_quoted(web_hooks_token.trim())
        ));
    }
    if !web_hooks_default_session_key.trim().is_empty() {
        yaml.push_str(&format!(
            "    hooks_default_session_key: {}\n",
            yaml_double_quoted(web_hooks_default_session_key.trim())
        ));
    }
    if !web_hooks_allow_request_session_key_raw.trim().is_empty() {
        yaml.push_str(&format!(
            "    hooks_allow_request_session_key: {}\n",
            web_hooks_allow_request_session_key
        ));
    }
    if !web_hooks_allowed_session_key_prefixes.is_empty() {
        yaml.push_str("    hooks_allowed_session_key_prefixes:\n");
        for prefix in &web_hooks_allowed_session_key_prefixes {
            yaml.push_str(&format!("      - {}\n", yaml_double_quoted(prefix)));
        }
    }

    if channel_selected("telegram") || telegram_present {
        yaml.push_str("  telegram:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("telegram")));
        if !telegram_channel_profile_override.trim().is_empty()
            && !telegram_channel_profile_override
                .trim()
                .eq_ignore_ascii_case("main")
        {
            yaml.push_str(&format!(
                "    provider_preset: \"{}\"\n",
                telegram_channel_profile_override.trim()
            ));
        }
        if !telegram_llm_api_key.trim().is_empty() {
            yaml.push_str(&format!(
                "    api_key: \"{}\"\n",
                telegram_llm_api_key.trim()
            ));
        }
        if !telegram_llm_base_url.trim().is_empty() {
            yaml.push_str(&format!(
                "    llm_base_url: \"{}\"\n",
                telegram_llm_base_url.trim()
            ));
        }
        if !telegram_topic_routing_raw.trim().is_empty() {
            yaml.push_str("    topic_routing:\n");
            yaml.push_str(&format!("      enabled: {}\n", telegram_topic_routing));
        }
        if !telegram_channel_allowed_user_ids.is_empty() {
            yaml.push_str("    allowed_user_ids:\n");
            for id in &telegram_channel_allowed_user_ids {
                yaml.push_str(&format!("      - {}\n", id));
            }
        }
        if let Some(accounts) = &telegram_accounts {
            let default_id = pick_default_account_id(&telegram_account_id, accounts);
            yaml.push_str(&format!("    default_account: \"{}\"\n", default_id));
            yaml.push_str("    accounts:\n");
            let yaml_accounts = serde_yaml::to_value(serde_json::Value::Object(accounts.clone()))
                .map_err(|e| {
                MicroClawError::Config(format!("Failed to render Telegram multi-bot accounts: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_accounts);
        } else if telegram_present {
            yaml.push_str(&format!(
                "    default_account: \"{}\"\n",
                telegram_account_id
            ));
            yaml.push_str("    accounts:\n");
            yaml.push_str(&format!("      {}:\n", telegram_account_id));
            yaml.push_str("        enabled: true\n");
            if !telegram_token.trim().is_empty() {
                yaml.push_str(&format!("        bot_token: \"{}\"\n", telegram_token));
            }
            if !telegram_username.trim().is_empty() {
                yaml.push_str(&format!(
                    "        bot_username: \"{}\"\n",
                    telegram_username
                ));
            }
            let slot1_soul =
                normalize_soul_path_input(&get(&telegram_slot_soul_path_key(1)), &souls_dir);
            if !slot1_soul.is_empty() {
                yaml.push_str(&format!("        soul_path: \"{}\"\n", slot1_soul));
            }
            // Per-account model is still driven by slot fields; channel-level model is emitted above.
        }
    }
    if channel_selected("discord") || discord_present {
        yaml.push_str("  discord:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("discord")));
        if !discord_channel_profile_override.trim().is_empty()
            && !discord_channel_profile_override
                .trim()
                .eq_ignore_ascii_case("main")
        {
            yaml.push_str(&format!(
                "    provider_preset: \"{}\"\n",
                discord_channel_profile_override.trim()
            ));
        }
        if !discord_llm_api_key.trim().is_empty() {
            yaml.push_str(&format!(
                "    api_key: \"{}\"\n",
                discord_llm_api_key.trim()
            ));
        }
        if !discord_llm_base_url.trim().is_empty() {
            yaml.push_str(&format!(
                "    llm_base_url: \"{}\"\n",
                discord_llm_base_url.trim()
            ));
        }
        if let Some(accounts) = &discord_accounts {
            let default_id = pick_default_account_id(&discord_account_id, accounts);
            yaml.push_str(&format!("    default_account: \"{}\"\n", default_id));
            yaml.push_str("    accounts:\n");
            let yaml_accounts = serde_yaml::to_value(serde_json::Value::Object(accounts.clone()))
                .map_err(|e| {
                MicroClawError::Config(format!("Failed to render DISCORD_ACCOUNTS_JSON: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_accounts);
        } else if discord_present {
            yaml.push_str(&format!(
                "    default_account: \"{}\"\n",
                discord_account_id
            ));
            yaml.push_str("    accounts:\n");
            yaml.push_str(&format!("      {}:\n", discord_account_id));
            yaml.push_str("        enabled: true\n");
            if !discord_token.trim().is_empty() {
                yaml.push_str(&format!("        bot_token: \"{}\"\n", discord_token));
            }
        }
    }

    for (ch, include) in &dynamic_channel_include {
        if !include {
            continue;
        }
        if dynamic_channel_uses_minimal_setup(ch.name) {
            yaml.push_str(&format!("  {}:\n", ch.name));
            yaml.push_str(&format!("    enabled: {}\n", channel_selected(ch.name)));
            continue;
        }
        let bot_count_key = dynamic_bot_count_field_key(ch.name);
        let bot_count = parse_bot_count(&get(&bot_count_key), &bot_count_key)?;
        let mut accounts_map = serde_json::Map::new();
        for slot in 1..=bot_count {
            let id = get(&dynamic_slot_id_field_key(ch.name, slot));
            let enabled =
                parse_boolish(&get(&dynamic_slot_enabled_field_key(ch.name, slot)), true)?;
            let soul_path = normalize_soul_path_input(
                &get(&dynamic_slot_soul_path_field_key(ch.name, slot)),
                &souls_dir,
            );
            let has_any = ch
                .fields
                .iter()
                .any(|f| !effective_dynamic_slot_field_value(ch.name, slot, f, get).is_empty())
                || !soul_path.is_empty();
            if !has_any {
                continue;
            }
            let account_id = account_id_from_value(&id);
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(format!(
                    "{} must use only letters, numbers, '_' or '-'",
                    dynamic_slot_id_field_key(ch.name, slot)
                )));
            }
            let mut account = serde_json::Map::new();
            account.insert("enabled".into(), serde_json::Value::Bool(enabled));
            for f in ch.fields {
                let v = effective_dynamic_slot_field_value(ch.name, slot, f, get);
                if v.trim().is_empty() {
                    continue;
                }
                if dynamic_field_is_bool(ch.name, f.yaml_key) {
                    let parsed = parse_boolish(v.trim(), false).map_err(|_| {
                        MicroClawError::Config(format!(
                            "{} must be true/false (or 1/0)",
                            dynamic_slot_field_key(ch.name, slot, f.yaml_key)
                        ))
                    })?;
                    account.insert(f.yaml_key.to_string(), serde_json::Value::Bool(parsed));
                } else if dynamic_field_is_u64(ch.name, f.yaml_key) {
                    let field_key = dynamic_slot_field_key(ch.name, slot, f.yaml_key);
                    let parsed = parse_u64_field(v.trim(), &field_key)?;
                    account.insert(
                        f.yaml_key.to_string(),
                        serde_json::Value::Number(serde_json::Number::from(parsed)),
                    );
                } else {
                    account.insert(
                        f.yaml_key.to_string(),
                        serde_json::Value::String(v.trim().to_string()),
                    );
                }
            }
            if !soul_path.is_empty() {
                account.insert("soul_path".into(), serde_json::Value::String(soul_path));
            }
            if ch.name == "feishu" {
                let topic_mode = account
                    .get("topic_mode")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if topic_mode {
                    let domain = account
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .unwrap_or("feishu")
                        .to_ascii_lowercase();
                    if domain != "feishu" && domain != "lark" {
                        return Err(MicroClawError::Config(format!(
                            "{} topic_mode is only supported when domain is feishu or lark",
                            dynamic_slot_id_field_key(ch.name, slot)
                        )));
                    }
                }
            }
            let llm_provider = get(&dynamic_slot_llm_provider_key(ch.name, slot));
            if !llm_provider.trim().is_empty() && !llm_provider.trim().eq_ignore_ascii_case("main")
            {
                account.insert(
                    "provider_preset".into(),
                    serde_json::Value::String(llm_provider.trim().to_string()),
                );
            }
            let llm_api_key = get(&dynamic_slot_llm_api_key_key(ch.name, slot));
            if !llm_api_key.trim().is_empty() {
                account.insert(
                    "api_key".into(),
                    serde_json::Value::String(llm_api_key.trim().to_string()),
                );
            }
            let llm_base_url = get(&dynamic_slot_llm_base_url_key(ch.name, slot));
            if !llm_base_url.trim().is_empty() {
                account.insert(
                    "llm_base_url".into(),
                    serde_json::Value::String(llm_base_url.trim().to_string()),
                );
            }
            accounts_map.insert(account_id, serde_json::Value::Object(account));
        }
        let has_accounts = !accounts_map.is_empty();
        yaml.push_str(&format!("  {}:\n", ch.name));
        yaml.push_str(&format!("    enabled: {}\n", channel_selected(ch.name)));
        if has_accounts {
            let default_slot_id = get(&dynamic_slot_id_field_key(ch.name, 1));
            let account_id = account_id_from_value(&default_slot_id);
            let default_id = pick_default_account_id(&account_id, &accounts_map);
            yaml.push_str(&format!("    default_account: \"{}\"\n", default_id));
            yaml.push_str("    accounts:\n");
            let yaml_accounts = serde_yaml::to_value(serde_json::Value::Object(accounts_map))
                .map_err(|e| {
                    MicroClawError::Config(format!("Failed to render {} accounts: {e}", ch.name))
                })?;
            append_yaml_value(&mut yaml, 6, &yaml_accounts);
        }
    }
    if a2a_enabled
        || !a2a_public_base_url.is_empty()
        || !a2a_agent_name.is_empty()
        || !a2a_agent_description.is_empty()
        || !a2a_shared_tokens.is_empty()
        || !a2a_peers.is_empty()
    {
        yaml.push_str("a2a:\n");
        yaml.push_str(&format!("  enabled: {}\n", a2a_enabled));
        if !a2a_public_base_url.is_empty() {
            yaml.push_str(&format!(
                "  public_base_url: {}\n",
                yaml_double_quoted(&a2a_public_base_url)
            ));
        }
        if !a2a_agent_name.is_empty() {
            yaml.push_str(&format!(
                "  agent_name: {}\n",
                yaml_double_quoted(&a2a_agent_name)
            ));
        }
        if !a2a_agent_description.is_empty() {
            yaml.push_str(&format!(
                "  agent_description: {}\n",
                yaml_double_quoted(&a2a_agent_description)
            ));
        }
        if !a2a_shared_tokens.is_empty() {
            yaml.push_str("  shared_tokens:\n");
            for token in &a2a_shared_tokens {
                yaml.push_str(&format!("    - {}\n", yaml_double_quoted(token)));
            }
        }
        if !a2a_peers.is_empty() {
            yaml.push_str("  peers:\n");
            let yaml_peers = serde_yaml::to_value(&a2a_peers)
                .map_err(|e| MicroClawError::Config(format!("Failed to render A2A peers: {e}")))?;
            append_yaml_value(&mut yaml, 4, &yaml_peers);
        }
    }
    yaml.push_str("subagents:\n");
    yaml.push_str(&format!("  max_concurrent: {}\n", subagents_max_concurrent));
    yaml.push_str(&format!(
        "  max_active_per_chat: {}\n",
        subagents_max_active_per_chat
    ));
    yaml.push_str(&format!(
        "  run_timeout_secs: {}\n",
        subagents_run_timeout_secs
    ));
    yaml.push_str(&format!(
        "  announce_to_chat: {}\n",
        subagents_announce_to_chat
    ));
    yaml.push_str(&format!(
        "  max_spawn_depth: {}\n",
        subagents_max_spawn_depth
    ));
    yaml.push_str(&format!(
        "  max_children_per_run: {}\n",
        subagents_max_children_per_run
    ));
    yaml.push_str(&format!(
        "  thread_bound_routing_enabled: {}\n",
        subagents_thread_bound_routing_enabled
    ));
    yaml.push_str(&format!(
        "  announce_relay_interval_secs: {}\n",
        subagents_announce_relay_interval_secs
    ));
    yaml.push_str(&format!(
        "  max_tokens_per_run: {}\n",
        subagents_max_tokens_per_run
    ));
    yaml.push_str(&format!(
        "  orchestrate_max_workers: {}\n",
        subagents_orchestrate_max_workers
    ));
    if subagents_acp_enabled
        || !subagents_acp_command.is_empty()
        || !subagents_acp_args.is_empty()
        || !subagents_acp_env.is_empty()
        || !subagents_acp_auto_approve
        || !subagents_acp_default_target.is_empty()
        || !subagents_acp_targets.is_empty()
    {
        yaml.push_str("  acp:\n");
        yaml.push_str(&format!("    enabled: {}\n", subagents_acp_enabled));
        if !subagents_acp_command.is_empty() {
            yaml.push_str(&format!(
                "    command: {}\n",
                yaml_double_quoted(&subagents_acp_command)
            ));
        }
        if !subagents_acp_args.is_empty() {
            yaml.push_str("    args:\n");
            for arg in &subagents_acp_args {
                yaml.push_str(&format!("      - {}\n", yaml_double_quoted(arg)));
            }
        }
        if !subagents_acp_env.is_empty() {
            yaml.push_str("    env:\n");
            let yaml_env = serde_yaml::to_value(&subagents_acp_env).map_err(|e| {
                MicroClawError::Config(format!("Failed to render ACP env config: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_env);
        }
        yaml.push_str(&format!(
            "    auto_approve: {}\n",
            subagents_acp_auto_approve
        ));
        if !subagents_acp_default_target.is_empty() {
            yaml.push_str(&format!(
                "    default_target: {}\n",
                yaml_double_quoted(&subagents_acp_default_target)
            ));
        }
        if !subagents_acp_targets.is_empty() {
            yaml.push_str("    targets:\n");
            let yaml_targets = serde_yaml::to_value(&subagents_acp_targets).map_err(|e| {
                MicroClawError::Config(format!("Failed to render ACP targets config: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_targets);
        }
    }
    yaml.push('\n');

    yaml.push_str(
        "# LLM provider (anthropic, openai-codex, ollama, openai, openrouter, deepseek, synthetic, chutes, google, etc.)\n",
    );
    yaml.push_str(&format!("llm_provider: \"{}\"\n", get("LLM_PROVIDER")));
    yaml.push_str("# API key for LLM provider\n");
    yaml.push_str(&format!("api_key: \"{}\"\n", get("LLM_API_KEY")));

    let model = get("LLM_MODEL");
    if !model.is_empty() {
        yaml.push_str("# Model name (leave empty for provider default)\n");
        yaml.push_str(&format!("model: \"{}\"\n", model));
    }

    let base_url = get("LLM_BASE_URL");
    if !base_url.is_empty() {
        yaml.push_str("# Custom base URL (optional)\n");
        yaml.push_str(&format!("llm_base_url: \"{}\"\n", base_url));
    }
    let llm_user_agent = get("LLM_USER_AGENT");
    if !llm_user_agent.is_empty() {
        yaml.push_str("# LLM HTTP User-Agent (optional)\n");
        yaml.push_str(&format!("llm_user_agent: \"{}\"\n", llm_user_agent));
    }
    if provider_presets.is_empty() {
        yaml.push_str("# Optional reusable provider profiles for per-bot/channel selection\n");
        yaml.push_str("# provider_presets:\n");
        yaml.push_str("#   provider1:\n");
        yaml.push_str("#     provider: \"openai\"\n");
        yaml.push_str("#     api_key: \"sk-...\"\n");
        yaml.push_str("#     llm_base_url: \"https://example.com/v1\"\n");
        yaml.push_str("#     llm_user_agent: \"microclaw/1.0\"\n");
        yaml.push_str("#     default_model: \"gpt-5.2\"\n");
        yaml.push_str("#     show_thinking: false\n");
        yaml.push_str("#   deepseek-hk:\n");
        yaml.push_str("#     provider: \"deepseek\"\n");
        yaml.push_str("#     api_key: \"sk-...\"\n");
    } else {
        yaml.push_str("provider_presets:\n");
        let yaml_presets = serde_yaml::to_value(&provider_presets).map_err(|e| {
            MicroClawError::Config(format!("Failed to render provider_presets: {e}"))
        })?;
        append_yaml_value(&mut yaml, 2, &yaml_presets);
    }
    let show_thinking = values
        .get("SHOW_THINKING")
        .and_then(|v| parse_bool_like(v))
        .unwrap_or(false);
    yaml.push_str("# Show model thinking/reasoning text when available\n");
    yaml.push_str(&format!("show_thinking: {}\n", show_thinking));
    yaml.push_str("# OpenAI-compatible request body overrides (optional)\n");
    yaml.push_str("# Use null to unset a default key for selected provider/model.\n");
    yaml.push_str("# openai_compat_body_overrides: { temperature: 0.2 }\n");
    yaml.push_str("# openai_compat_body_overrides_by_provider:\n");
    yaml.push_str("#   deepseek: { top_p: null, reasoning_effort: \"high\" }\n");
    yaml.push_str("# openai_compat_body_overrides_by_model:\n");
    yaml.push_str("#   gpt-5.2: { response_format: { type: \"json_object\" } }\n");

    yaml.push('\n');
    yaml.push_str(&format!("data_dir: {}\n", yaml_double_quoted(&data_dir)));
    let working_dir = values
        .get("WORKING_DIR")
        .cloned()
        .unwrap_or_else(default_working_dir_for_setup);
    yaml.push_str(&format!(
        "working_dir: {}\n",
        yaml_double_quoted(&working_dir)
    ));
    let override_tz = values.get("OVERRIDE_TIMEZONE").cloned().unwrap_or_default();
    yaml.push_str(
        "# Optional timezone override (IANA), e.g. Asia/Shanghai. Default: system timezone.\n",
    );
    if !override_tz.trim().is_empty() && !override_tz.eq_ignore_ascii_case("auto") {
        yaml.push_str(&format!("override_timezone: \"{}\"\n", override_tz));
    }
    let high_risk_confirm_required = values
        .get("HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED")
        .map(|v| {
            let lower = v.trim().to_ascii_lowercase();
            lower != "false" && lower != "0" && lower != "no"
        })
        .unwrap_or(true);
    yaml.push_str(&format!(
        "high_risk_tool_user_confirmation_required: {}\n",
        high_risk_confirm_required
    ));
    let sandbox_enabled = values
        .get("SANDBOX_ENABLED")
        .map(|v| {
            let lower = v.trim().to_ascii_lowercase();
            lower == "true" || lower == "1" || lower == "yes"
        })
        .unwrap_or(false);
    yaml.push_str("# Optional container sandbox for bash tool execution\n");
    yaml.push_str("sandbox:\n");
    if sandbox_enabled {
        yaml.push_str("  mode: \"all\"\n");
        yaml.push_str("  backend: \"auto\"\n");
    } else {
        yaml.push_str("  mode: \"off\"\n");
    }

    let reflector_enabled = values
        .get("REFLECTOR_ENABLED")
        .map(|v| v.trim().to_lowercase())
        .map(|v| v != "false" && v != "0" && v != "no")
        .unwrap_or(true);
    yaml.push_str(
        "\n# Memory reflector: periodically extracts structured memories from conversations\n",
    );
    yaml.push_str(&format!("reflector_enabled: {}\n", reflector_enabled));
    let reflector_interval = values
        .get("REFLECTOR_INTERVAL_MINS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(15);
    yaml.push_str(&format!(
        "reflector_interval_mins: {}\n",
        reflector_interval
    ));
    let memory_token_budget = values
        .get("MEMORY_TOKEN_BUDGET")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(1500);
    yaml.push_str(&format!("memory_token_budget: {}\n", memory_token_budget));

    let embedding_provider = values
        .get("EMBEDDING_PROVIDER")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let embedding_api_key = values
        .get("EMBEDDING_API_KEY")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let embedding_base_url = values
        .get("EMBEDDING_BASE_URL")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let embedding_model = values
        .get("EMBEDDING_MODEL")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let embedding_dim = values
        .get("EMBEDDING_DIM")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    if !embedding_provider.is_empty()
        || !embedding_api_key.is_empty()
        || !embedding_base_url.is_empty()
        || !embedding_model.is_empty()
        || !embedding_dim.is_empty()
    {
        yaml.push_str(
            "\n# Optional embedding config for semantic memory retrieval (requires sqlite-vec feature)\n",
        );
        if !embedding_provider.is_empty() {
            yaml.push_str(&format!("embedding_provider: \"{}\"\n", embedding_provider));
        }
        if !embedding_api_key.is_empty() {
            yaml.push_str(&format!("embedding_api_key: \"{}\"\n", embedding_api_key));
        }
        if !embedding_base_url.is_empty() {
            yaml.push_str(&format!("embedding_base_url: \"{}\"\n", embedding_base_url));
        }
        if !embedding_model.is_empty() {
            yaml.push_str(&format!("embedding_model: \"{}\"\n", embedding_model));
        }
        if !embedding_dim.is_empty() {
            yaml.push_str(&format!("embedding_dim: {}\n", embedding_dim));
        }
    }

    yaml.push_str("\n# Optional SOUL files directory (defaults to <data_dir>/souls)\n");
    yaml.push_str(&format!("souls_dir: {}\n", yaml_double_quoted(&souls_dir)));

    fs::write(path, yaml).map_err(|e| {
        MicroClawError::Config(format!("Failed to write config to {}: {}", path.display(), e))
    })?;
    Ok(backup)
}

fn field_window_for_area(area: Rect) -> usize {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(UI_HEADER_HEIGHT),
            Constraint::Min(14),
            Constraint::Length(UI_STATUS_HEIGHT),
        ])
        .split(area);
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);
    let left_inner = body_chunks[0].inner(Margin::new(1, 0));
    left_inner.height.saturating_sub(2).max(1) as usize
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &SetupApp) {
    if app.completed {
        let done = Paragraph::new(vec![
            Line::from(Span::styled(
                "✅ Setup saved successfully",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Checks:"),
            Line::from(
                app.completion_summary
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Config validated".into()),
            ),
            Line::from(app.completion_summary.get(1).cloned().unwrap_or_default()),
            Line::from(""),
            Line::from(format!(
                "Backup: {}",
                app.backup_path.as_deref().unwrap_or("none")
            )),
            Line::from(""),
            Line::from("Next:"),
            Line::from("  1) microclaw start"),
            Line::from(""),
            Line::from("Press Enter to finish."),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Setup Complete"),
        );
        frame.render_widget(done, frame.area().inner(Margin::new(2, 2)));
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(UI_HEADER_HEIGHT),
            Constraint::Min(14),
            Constraint::Length(UI_STATUS_HEIGHT),
        ])
        .split(frame.area());

    let (selected_visible, visible_total) = app.selected_progress();
    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "MicroClaw • Interactive Setup",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                format!(
                    "Field {}/{}  ·  Section: {}  ·  ",
                    selected_visible,
                    visible_total,
                    app.current_section()
                ),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(app.progress_bar(16), Style::default().fg(Color::LightCyan)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let mut lines = Vec::<Line>::new();
    let mut last_section = "";
    let visible_indices = app.visible_field_indices();
    let left_inner = body_chunks[0].inner(Margin::new(1, 0));
    let start = app
        .field_scroll
        .min(visible_indices.len().saturating_sub(1));
    let end = app.window_end_for_start_pos(&visible_indices, start, app.field_window.max(1));
    for i in visible_indices[start..end].iter().copied() {
        let f = &app.fields[i];
        let section = SetupApp::section_for_key(&f.key);
        if section != last_section {
            if !lines.is_empty() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!("[{}]", section),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )));
            last_section = section;
        }

        let selected = i == app.selected;
        let is_required = app.is_field_required(f);
        let label = if is_required {
            format!("{}  [required]", f.label)
        } else {
            f.label.to_string()
        };
        let value = if f.key == "LLM_PROVIDER" {
            provider_display(&f.value)
        } else if let Some(provider_key) = SetupApp::llm_provider_key_for_model_field(&f.key) {
            let provider = app.field_value(&provider_key);
            if provider.is_empty() {
                "main".to_string()
            } else {
                provider
            }
        } else if f.key == llm_provider_profiles_key() {
            let presets = app.llm_provider_presets();
            if presets.is_empty() {
                String::new()
            } else {
                let mut ids: Vec<String> = presets.keys().cloned().collect();
                ids.sort();
                format!("{} preset(s): {}", ids.len(), ids.join(", "))
            }
        } else {
            f.display_value(selected && app.editing)
        };
        let prefix = if selected { "▶" } else { " " };
        let color = if selected {
            Color::Yellow
        } else {
            Color::White
        };
        let label_text = format!("{} {}: ", prefix, label);
        let line_width = left_inner.width.max(1) as usize;
        let max_value_chars = line_width.saturating_sub(label_text.chars().count()).max(1);
        let value_single_line = truncate_single_line(&value, max_value_chars);
        lines.push(Line::from(vec![
            Span::styled(label_text, Style::default().fg(color)),
            Span::styled(value_single_line, Style::default().fg(Color::Green)),
        ]));
    }
    if end < visible_indices.len() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("… more fields below ({}/{})", end, visible_indices.len()),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let body = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Fields"));
    frame.render_widget(body, left_inner);

    let field = app.selected_field();
    let (field_desc, field_example_raw) = SetupApp::field_guidance(&field.key);
    let field_example = field_example_raw
        .strip_prefix("Example: ")
        .unwrap_or(field_example_raw);
    let is_required = app.is_field_required(field);
    let mut help_lines = vec![
        Line::from(vec![
            Span::styled("Key: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                SetupApp::key_display(&field.key),
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(vec![
            Span::styled("Required: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if is_required { "yes" } else { "no" }),
        ]),
        Line::from(vec![
            Span::styled("Editing: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if app.editing { "active" } else { "idle" }),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("What: ", Style::default().fg(Color::DarkGray)),
            Span::raw(field_desc),
        ]),
    ];
    if !field_example.is_empty() {
        help_lines.push(Line::from(vec![
            Span::styled("Example: ", Style::default().fg(Color::DarkGray)),
            Span::styled(field_example, Style::default().fg(Color::LightGreen)),
        ]));
    }
    if !is_required {
        let default_value = if field.key == "LLM_USER_AGENT" {
            crate::http_client::default_llm_user_agent()
        } else {
            app.default_value_for_field(&field.key)
        };
        let default_display = if default_value.trim().is_empty() {
            "(empty)".to_string()
        } else {
            default_value
        };
        help_lines.push(Line::from(vec![
            Span::styled("Default value: ", Style::default().fg(Color::DarkGray)),
            Span::styled(default_display, Style::default().fg(Color::LightBlue)),
        ]));
    }
    help_lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "Tips",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("• Enter: edit field / open selection list"),
        Line::from("• Enter on any channel model override: open channel LLM page"),
        Line::from("• Channels picker: Space toggle, Enter apply"),
        Line::from("• Tab / Shift+Tab: next/prev field"),
        Line::from("• ↑/↓ or j/k or Ctrl+N/Ctrl+P: move"),
        Line::from("• In selection list: Enter confirm, Esc close"),
        Line::from("• PgUp/PgDn or Ctrl+U/Ctrl+F: page up/down"),
        Line::from("• g / G: jump to top / bottom"),
        Line::from("• ←/→ on provider/model: rotate presets"),
        Line::from("• e: force manual text edit"),
        Line::from("• Ctrl+D / Del: clear field"),
        Line::from("• Ctrl+R: restore field default"),
        Line::from("• F2: validate + online checks"),
        Line::from("• s: save with online validation"),
        Line::from("• Ctrl+S / Ctrl+Shift+S: save without online model validation"),
    ]);
    let help = Paragraph::new(help_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Details / Help"),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(help, body_chunks[1].inner(Margin::new(1, 0)));

    let (status_icon, status_color) =
        if app.status.contains("failed") || app.status.contains("Cannot save") {
            ("✖ ", Color::LightRed)
        } else if app.status.contains("saved") || app.status.contains("Saved") {
            ("✔ ", Color::LightGreen)
        } else {
            ("• ", Color::White)
        };
    let status = Paragraph::new(vec![Line::from(vec![
        Span::styled(status_icon, Style::default().fg(status_color)),
        Span::styled(app.status.clone(), Style::default().fg(status_color)),
    ])])
    .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);

    if let Some(page) = &app.provider_preset_page {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        if let Some(picker) = &page.picker {
            let mut list_lines = Vec::with_capacity(picker.options.len());
            for (i, (label, _)) in picker.options.iter().enumerate() {
                let selected = i == picker.selected;
                let pointer = if selected { "▶ " } else { "  " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                list_lines.push(Line::from(Span::styled(format!("{pointer}{label}"), style)));
            }
            let overlay = Paragraph::new(list_lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Preset Picker")
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        } else if page.mode == ProviderPresetPageMode::List {
            let mut lines = Vec::new();
            let next_id_hint = SetupApp::next_provider_preset_id(&page.entries);
            if page.entries.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No provider profiles yet. Press a to add one.",
                    Style::default().fg(Color::White),
                )));
            } else {
                for (idx, entry) in page.entries.iter().enumerate() {
                    let selected = idx == page.selected;
                    let pointer = if selected { "▶ " } else { "  " };
                    let model = if entry.default_model.trim().is_empty() {
                        "(no default model)".to_string()
                    } else {
                        entry.default_model.clone()
                    };
                    let ref_summary = app.provider_preset_reference_summary(&entry.id);
                    let in_use_marker = if ref_summary == "unused" {
                        String::new()
                    } else {
                        "  IN USE".to_string()
                    };
                    let summary = format!(
                        "{}  {} / {}  [{}]{}",
                        entry.id, entry.provider, model, ref_summary, in_use_marker
                    );
                    let style = if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{pointer}{summary}"),
                        style,
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "----------------------------------------------------------------",
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(Span::styled(
                format!("Next default preset id: {next_id_hint}"),
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(Span::styled(
                "a add · c clone · Enter edit · d delete only if unused · x reset refs to main and delete · Esc close",
                Style::default().fg(Color::White),
            )));
            let overlay = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Provider Profiles")
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        } else {
            let labels = SetupApp::provider_preset_field_labels();
            let mut lines = Vec::new();
            if let Some(entry) = page.entries.get(page.selected) {
                for (idx, label) in labels.iter().enumerate() {
                    let selected = idx == page.field_selected;
                    let pointer = if selected { "▶ " } else { "  " };
                    let raw = match idx {
                        0 => entry.id.clone(),
                        1 => entry.provider.clone(),
                        2 => {
                            if selected && page.editing {
                                entry.api_key.clone()
                            } else {
                                mask_secret(&entry.api_key)
                            }
                        }
                        3 => entry.default_model.clone(),
                        4 => entry.base_url.clone(),
                        5 => entry.show_thinking.to_string(),
                        6 => entry.user_agent.clone(),
                        _ => String::new(),
                    };
                    let style = if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{pointer}{label}: {raw}"),
                        style,
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "----------------------------------------------------------------",
                    Style::default().fg(Color::Gray),
                )));
                let refs = app.provider_preset_references(&entry.id);
                lines.push(Line::from(Span::styled(
                    format!(
                        "References: {}",
                        if refs.is_empty() {
                            "none".to_string()
                        } else {
                            refs.join(", ")
                        }
                    ),
                    Style::default().fg(Color::Gray),
                )));
                lines.push(Line::from(Span::styled(
                    "Delete actions: d = delete only when unused; x = reset all refs to main, then delete",
                    Style::default().fg(Color::White),
                )));
                lines.push(Line::from(Span::styled(
                    "Use d when you expect zero references. Use x when this preset is still attached somewhere.",
                    Style::default().fg(Color::Gray),
                )));
                if entry.id.strip_prefix("provider").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
                }) {
                    lines.push(Line::from(Span::styled(
                        "Tip: providerN ids are convenient for sequential presets; descriptive ids also work.",
                        Style::default().fg(Color::Gray),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "Tip: next default preset id would be {}",
                            SetupApp::next_provider_preset_id(&page.entries)
                        ),
                        Style::default().fg(Color::Gray),
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter edit/select · t test current profile · Esc back · ↑/↓ move · Ctrl+D clear · Ctrl+R default",
                Style::default().fg(Color::White),
            )));
            let overlay = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Provider Profile Detail")
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        }
    } else if let Some(picker) = &app.llm_override_picker {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        let mut list_lines = Vec::with_capacity(picker.options.len());
        for (i, (label, _)) in picker.options.iter().enumerate() {
            let selected = i == picker.selected;
            let pointer = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            list_lines.push(Line::from(Span::styled(format!("{pointer}{label}"), style)));
        }
        let overlay = Paragraph::new(list_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(picker.title.as_str())
                    .style(Style::default().bg(Color::Black)),
            )
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(Clear, overlay_area);
        frame.render_widget(overlay, overlay_area);
    } else if let Some(page) = &app.llm_override_page {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        {
            let keys = SetupApp::llm_override_keys_for_page(page);
            let mut lines = Vec::new();
            for (idx, key) in keys.iter().enumerate() {
                let selected = idx == page.selected;
                let pointer = if selected { "▶ " } else { "  " };
                let label = SetupApp::llm_override_label_for_key(key);
                let raw = app.field_value(key);
                let value = if *key == page.api_key_key.as_str() {
                    if selected && page.editing {
                        raw
                    } else {
                        mask_secret(&raw)
                    }
                } else if *key == page.provider_key.as_str() && raw.trim().is_empty() {
                    "main (global default)".to_string()
                } else {
                    raw
                };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                lines.push(Line::from(Span::styled(
                    format!("{pointer}{label}: {value}"),
                    style,
                )));
            }
            lines.push(Line::from(""));
            if !page.show_legacy_fields {
                lines.push(Line::from(Span::styled(
                    "Using preset-only mode. Legacy API/base-url fields stay hidden until an old override exists.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                "Enter edit/select · Esc close · ↑/↓/j/k/Ctrl+N/Ctrl+P move",
                Style::default().fg(Color::DarkGray),
            )));
            let overlay = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(page.title.as_str())
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        }
    } else if let Some(picker) = &app.picker {
        let overlay_area = frame.area().inner(Margin::new(8, 4));
        let (title, options): (&str, Vec<String>) = match picker.kind {
            PickerKind::Provider => (
                "Select LLM Provider",
                PROVIDER_PRESETS
                    .iter()
                    .map(|p| format!("{} - {}", p.id, p.label))
                    .collect(),
            ),
            PickerKind::Model => ("Select LLM Model", app.model_picker_options()),
            PickerKind::Channels => (
                "Select Channels (Space=toggle, Enter=apply)",
                SetupApp::channel_options()
                    .iter()
                    .map(|c| (*c).to_string())
                    .collect(),
            ),
            PickerKind::SoulPath => (
                "Select SOUL.md (Enter=apply, choose manual to type filename)",
                app.soul_picker_options(),
            ),
            PickerKind::Timezone => (
                "Select Timezone (Enter=apply, choose custom to type IANA name)",
                app.timezone_picker_options(),
            ),
        };
        let mut list_lines = Vec::with_capacity(options.len());
        for (i, item) in options.iter().enumerate() {
            let selected = i == picker.selected;
            let pointer = if selected { "▶ " } else { "  " };
            let checkbox = if picker.kind == PickerKind::Channels {
                if picker.selected_multi.get(i).copied().unwrap_or(false) {
                    "[x] "
                } else {
                    "[ ] "
                }
            } else {
                ""
            };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            list_lines.push(Line::from(Span::styled(
                format!("{pointer}{checkbox}{item}"),
                style,
            )));
        }
        let overlay = Paragraph::new(list_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .style(Style::default().bg(Color::Black)),
            )
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(Clear, overlay_area);
        frame.render_widget(overlay, overlay_area);
    }
}

fn run_with_spinner<T, F>(
    terminal: &mut DefaultTerminal,
    app: &mut SetupApp,
    label: &str,
    work: F,
) -> Result<T, MicroClawError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, MicroClawError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Result<T, MicroClawError>>();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });

    let frames = ["-", "\\", "|", "/"];
    let mut i = 0usize;
    loop {
        app.status = format!("{label} {}", frames[i % frames.len()]);
        terminal.draw(|f| draw_ui(f, app))?;
        i += 1;

        match rx.recv_timeout(Duration::from_millis(120)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(MicroClawError::Config(
                    "save worker disconnected unexpectedly".into(),
                ));
            }
        }
    }
}

fn try_save(terminal: &mut DefaultTerminal, app: &mut SetupApp) -> Result<(), MicroClawError> {
    app.status = "Saving (1/3): local validation...".into();
    terminal.draw(|f| draw_ui(f, app))?;
    if let Err(e) = app.validate_local() {
        app.status = format!("Cannot save: {e}");
        return Ok(());
    }

    let app_for_online = app.clone();
    let checks = match run_with_spinner(
        terminal,
        app,
        "Saving (2/3): online validation",
        move || app_for_online.validate_online(),
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    let values = app.to_env_map();
    let save_path = crate::config::Config::config_path_for_setup();
    let display_path = save_path.display().to_string();
    let backup = match run_with_spinner(
        terminal,
        app,
        &format!("Saving (3/3): writing {}", display_path),
        move || {
            let p = &save_path;
            save_config_yaml(p, &values)
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    app.backup_path = backup;
    app.completion_summary = checks;
    app.status = format!("Saved {}", display_path);
    app.completed = true;
    Ok(())
}

fn try_save_skip_online(
    terminal: &mut DefaultTerminal,
    app: &mut SetupApp,
) -> Result<(), MicroClawError> {
    app.status = "Saving (1/2): local validation...".into();
    terminal.draw(|f| draw_ui(f, app))?;
    if let Err(e) = app.validate_local() {
        app.status = format!("Cannot save: {e}");
        return Ok(());
    }

    let values = app.to_env_map();
    let save_path = crate::config::Config::config_path_for_setup();
    let display_path = save_path.display().to_string();
    let backup = match run_with_spinner(
        terminal,
        app,
        &format!("Saving (2/2): writing {}", display_path),
        move || {
            let p = &save_path;
            save_config_yaml(p, &values)
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    app.backup_path = backup;
    app.completion_summary = vec!["Online/model validation skipped by user".to_string()];
    app.status = format!("Saved {} (online validation skipped)", display_path);
    app.completed = true;
    Ok(())
}

fn run_wizard(mut terminal: DefaultTerminal) -> Result<bool, MicroClawError> {
    let mut app = SetupApp::new();

    loop {
        if let Ok(size) = terminal.size() {
            let area = Rect::new(0, 0, size.width, size.height);
            app.field_window = field_window_for_area(area);
        }
        app.ensure_selected_visible();
        terminal.draw(|f| draw_ui(f, &app))?;
        if event::poll(Duration::from_millis(250))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if app.completed {
                match key.code {
                    KeyCode::Enter | KeyCode::Char('q') => return Ok(true),
                    _ => continue,
                }
            }

            if app.provider_preset_page.is_some() {
                let mode = app
                    .provider_preset_page
                    .as_ref()
                    .map(|page| page.mode)
                    .unwrap_or(ProviderPresetPageMode::List);
                let field_count = SetupApp::provider_preset_field_labels().len();
                let picker_open = app
                    .provider_preset_page
                    .as_ref()
                    .and_then(|page| page.picker.as_ref())
                    .is_some();
                if picker_open {
                    match key.code {
                        KeyCode::Esc => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.picker = None;
                            }
                            app.status = "Selection closed".into();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = picker.selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = (picker.selected + 1)
                                        .min(picker.options.len().saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = picker.selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = (picker.selected + 1)
                                        .min(picker.options.len().saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Enter => app.apply_provider_preset_picker_selection(),
                        _ => {}
                    }
                    continue;
                }
                match mode {
                    ProviderPresetPageMode::List => match key.code {
                        KeyCode::Esc => {
                            app.provider_preset_page = None;
                            app.status = "Closed provider profiles".into();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected =
                                    (page.selected + 1).min(page.entries.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected =
                                    (page.selected + 1).min(page.entries.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Char('a') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                let next_id = SetupApp::next_provider_preset_id(&page.entries);
                                page.entries.push(ProviderPresetDraft {
                                    id: next_id,
                                    provider: "anthropic".to_string(),
                                    api_key: String::new(),
                                    base_url: String::new(),
                                    user_agent: String::new(),
                                    default_model: default_model_for_provider("anthropic")
                                        .to_string(),
                                    show_thinking: false,
                                });
                                page.selected = page.entries.len().saturating_sub(1);
                                page.mode = ProviderPresetPageMode::Edit;
                                page.field_selected = 0;
                                page.editing = true;
                            }
                            let _ = app.sync_provider_preset_page_field();
                            app.status = "Added provider profile".into();
                        }
                        KeyCode::Char('c') => match app.clone_selected_provider_preset() {
                            Ok(Some(cloned_id)) => {
                                app.status = format!("Cloned provider profile as {cloned_id}")
                            }
                            Ok(None) => app.status = "No provider profile selected to clone".into(),
                            Err(e) => app.status = e.to_string(),
                        },
                        KeyCode::Char('d') => match app.delete_selected_provider_preset(false) {
                            Ok(_) => app.status = "Deleted provider profile".into(),
                            Err(e) => app.status = e.to_string(),
                        },
                        KeyCode::Char('x') => match app.delete_selected_provider_preset(true) {
                            Ok(reset_refs) => {
                                if reset_refs.is_empty() {
                                    app.status =
                                        "Deleted provider profile (no references needed reset)"
                                            .into();
                                } else {
                                    app.status = format!(
                                        "Reset to main and deleted provider preset: {}",
                                        reset_refs.join(", ")
                                    );
                                }
                            }
                            Err(e) => app.status = e.to_string(),
                        },
                        KeyCode::Enter => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if page.entries.is_empty() {
                                    page.entries.push(ProviderPresetDraft {
                                        id: SetupApp::next_provider_preset_id(&page.entries),
                                        provider: "anthropic".to_string(),
                                        api_key: String::new(),
                                        base_url: String::new(),
                                        user_agent: String::new(),
                                        default_model: default_model_for_provider("anthropic")
                                            .to_string(),
                                        show_thinking: false,
                                    });
                                    page.selected = 0;
                                }
                                page.mode = ProviderPresetPageMode::Edit;
                                page.field_selected = 0;
                                page.editing = false;
                            }
                            let _ = app.sync_provider_preset_page_field();
                            app.status = "Editing provider profile".into();
                        }
                        _ => {}
                    },
                    ProviderPresetPageMode::Edit => match key.code {
                        KeyCode::Esc => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if page.editing {
                                    page.editing = false;
                                    app.status = "Preset field edit canceled".into();
                                } else {
                                    page.mode = ProviderPresetPageMode::List;
                                    page.field_selected = 0;
                                    app.status = "Back to provider profile list".into();
                                }
                            }
                        }
                        KeyCode::Char('t')
                            if app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| !page.editing)
                                .unwrap_or(false) =>
                        {
                            let profile_id = app
                                .provider_preset_page
                                .as_ref()
                                .and_then(|page| page.entries.get(page.selected))
                                .map(|entry| entry.id.clone())
                                .unwrap_or_else(|| "current".to_string());
                            let app_for_online = app.clone();
                            match run_with_spinner(
                                &mut terminal,
                                &mut app,
                                &format!("Testing model for provider profile {profile_id}"),
                                move || app_for_online.validate_selected_provider_preset_online(),
                            ) {
                                Ok((validated_profile_id, checks)) => {
                                    app.status = format!(
                                        "Model test for {validated_profile_id} passed: {}",
                                        checks.join(" | ")
                                    );
                                }
                                Err(e) => {
                                    app.status = format!("Model test for {profile_id} failed: {e}");
                                }
                            }
                        }
                        KeyCode::Up => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = page.field_selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Down => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = (page.field_selected + 1)
                                        .min(field_count.saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Char('k')
                            if app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| !page.editing)
                                .unwrap_or(false) =>
                        {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.field_selected = page.field_selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('j')
                            if app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| !page.editing)
                                .unwrap_or(false) =>
                        {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.field_selected =
                                    (page.field_selected + 1).min(field_count.saturating_sub(1));
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = page.field_selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = (page.field_selected + 1)
                                        .min(field_count.saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Enter => {
                            app.handle_provider_preset_enter();
                        }
                        KeyCode::Backspace => {
                            let editing = app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| page.editing)
                                .unwrap_or(false);
                            if editing {
                                let mut value = app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(SetupApp::provider_preset_selected_field_value)
                                    .unwrap_or_default();
                                value.pop();
                                app.set_provider_preset_selected_field_value(value);
                                let _ = app.sync_provider_preset_page_field();
                            }
                        }
                        KeyCode::Char('d')
                            if key.modifiers.contains(KeyModifiers::CONTROL)
                                && app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(|page| !page.editing)
                                    .unwrap_or(false) =>
                        {
                            app.clear_selected_provider_preset_field();
                            let _ = app.sync_provider_preset_page_field();
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.editing = false;
                            }
                            app.status = "Cleared provider profile field".into();
                        }
                        KeyCode::Char('r')
                            if key.modifiers.contains(KeyModifiers::CONTROL)
                                && app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(|page| !page.editing)
                                    .unwrap_or(false) =>
                        {
                            match app.restore_selected_provider_preset_field_default() {
                                Some(default) => {
                                    let _ = app.sync_provider_preset_page_field();
                                    if let Some(page) = app.provider_preset_page.as_mut() {
                                        page.editing = false;
                                    }
                                    app.status = if default.is_empty() {
                                        "Restored provider profile field to default (empty)".into()
                                    } else {
                                        format!(
                                            "Restored provider profile field to default: {default}"
                                        )
                                    };
                                }
                                None => {
                                    app.status =
                                        "Selected provider profile field has no default".into();
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            let editing = app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| page.editing)
                                .unwrap_or(false);
                            if editing {
                                let mut value = app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(SetupApp::provider_preset_selected_field_value)
                                    .unwrap_or_default();
                                value.push(c);
                                app.set_provider_preset_selected_field_value(value);
                                let _ = app.sync_provider_preset_page_field();
                            }
                        }
                        _ => {}
                    },
                }
                continue;
            }

            if app.llm_override_picker.is_some() && app.llm_override_page.is_none() {
                match key.code {
                    KeyCode::Esc => {
                        app.llm_override_picker = None;
                        app.status = "Selection closed".into();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected = picker.selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected =
                                (picker.selected + 1).min(picker.options.len().saturating_sub(1));
                        }
                    }
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected = picker.selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected =
                                (picker.selected + 1).min(picker.options.len().saturating_sub(1));
                        }
                    }
                    KeyCode::Enter => app.apply_llm_override_picker_selection(),
                    _ => {}
                }
                continue;
            }

            if app.llm_override_page.is_some() {
                let keys: Vec<String> = if let Some(page) = app.llm_override_page.as_ref() {
                    SetupApp::llm_override_keys_for_page(page)
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect()
                } else {
                    Vec::new()
                };
                if app.llm_override_picker.is_some() {
                    match key.code {
                        KeyCode::Esc => {
                            app.llm_override_picker = None;
                            app.status = "Selection closed".into();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = picker.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = (picker.selected + 1)
                                    .min(picker.options.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = picker.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = (picker.selected + 1)
                                    .min(picker.options.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Enter => app.apply_llm_override_picker_selection(),
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Esc => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if page.editing {
                                page.editing = false;
                                app.status = "LLM override field edit canceled".into();
                            } else {
                                app.llm_override_page = None;
                                app.status = "Closed channel LLM page".into();
                            }
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected =
                                    (page.selected + 1).min(keys.len().saturating_sub(1));
                            }
                        }
                    }
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected =
                                    (page.selected + 1).min(keys.len().saturating_sub(1));
                            }
                        }
                    }
                    KeyCode::Enter => {
                        let (selected_key, provider_key, editing) =
                            if let Some(page) = app.llm_override_page.as_ref() {
                                (
                                    keys.get(page.selected).cloned().unwrap_or_default(),
                                    page.provider_key.clone(),
                                    page.editing,
                                )
                            } else {
                                (String::new(), String::new(), false)
                            };
                        if editing {
                            if let Some(page) = app.llm_override_page.as_mut() {
                                page.editing = false;
                            }
                            app.status = "Updated channel LLM override field".into();
                        } else if selected_key == provider_key {
                            app.open_llm_override_provider_picker();
                        } else if let Some(page) = app.llm_override_page.as_mut() {
                            page.editing = true;
                            app.status = "Editing channel LLM override field".into();
                        }
                    }
                    KeyCode::Backspace => {
                        let (editing, selected) = if let Some(page) = app.llm_override_page.as_ref()
                        {
                            (page.editing, page.selected)
                        } else {
                            (false, 0)
                        };
                        if editing {
                            let Some(key_name) = keys.get(selected) else {
                                continue;
                            };
                            if let Some(field) = app.fields.iter_mut().find(|f| f.key == *key_name)
                            {
                                field.value.pop();
                            }
                        }
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let (editing, selected) = if let Some(page) = app.llm_override_page.as_ref()
                        {
                            (page.editing, page.selected)
                        } else {
                            (false, 0)
                        };
                        if editing {
                            let Some(key_name) = keys.get(selected) else {
                                continue;
                            };
                            app.set_field_value(key_name, String::new());
                        }
                    }
                    KeyCode::Char(c) => {
                        let (editing, selected) = if let Some(page) = app.llm_override_page.as_ref()
                        {
                            (page.editing, page.selected)
                        } else {
                            (false, 0)
                        };
                        if editing {
                            let Some(key_name) = keys.get(selected) else {
                                continue;
                            };
                            let mut next = app.field_value(key_name);
                            next.push(c);
                            app.set_field_value(key_name, next);
                        }
                    }
                    _ => {}
                }
                continue;
            }

            if app.picker.is_some() {
                match key.code {
                    KeyCode::Esc => {
                        app.picker = None;
                        app.status = "Selection closed".into();
                    }
                    KeyCode::Up => app.move_picker(-1),
                    KeyCode::Down => app.move_picker(1),
                    KeyCode::Char('k') => app.move_picker(-1),
                    KeyCode::Char('j') => app.move_picker(1),
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.move_picker(-1)
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.move_picker(1)
                    }
                    KeyCode::Char(' ') => app.toggle_picker_multi(),
                    KeyCode::Enter => app.apply_picker_selection(),
                    _ => {}
                }
                continue;
            }

            if app.editing {
                match key.code {
                    KeyCode::Esc => {
                        app.editing = false;
                        app.status = "Edit canceled".into();
                    }
                    KeyCode::Enter => {
                        app.editing = false;
                        app.status = format!("Updated {}", app.selected_field().key);
                    }
                    KeyCode::Backspace => {
                        app.selected_field_mut().value.pop();
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.clear_selected_field();
                    }
                    KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.restore_selected_field_default();
                    }
                    KeyCode::Char(c) => {
                        app.selected_field_mut().value.push(c);
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') => return Ok(false),
                KeyCode::Up => app.prev(),
                KeyCode::Down => app.next(),
                KeyCode::Char('k') => app.prev(),
                KeyCode::Char('j') => app.next(),
                KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => app.prev(),
                KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => app.next(),
                KeyCode::PageDown => app.page_down(app.field_window.max(1)),
                KeyCode::PageUp => app.page_up(app.field_window.max(1)),
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.page_up(app.field_window.max(1))
                }
                KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.page_down(app.field_window.max(1))
                }
                KeyCode::Char('g') if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                    app.jump_top()
                }
                KeyCode::Char('G') => app.jump_bottom(),
                KeyCode::Tab => app.next(),
                KeyCode::BackTab => app.prev(),
                KeyCode::Enter => {
                    let selected_key = app.selected_field().key.clone();
                    if app.open_llm_override_page_for_field(&selected_key) {
                        app.status = format!("Editing {}", selected_key);
                    } else if app.open_picker_for_selected() {
                        app.status = format!("Selecting {}", app.selected_field().key);
                    } else {
                        app.editing = true;
                        app.status = format!("Editing {}", app.selected_field().key);
                    }
                }
                KeyCode::Left => {
                    if app.selected_field().key == "LLM_PROVIDER" {
                        app.cycle_provider(-1);
                        app.status = format!("Provider set to {}", app.field_value("LLM_PROVIDER"));
                    } else if app.selected_field().key == "LLM_MODEL" {
                        app.cycle_model(-1);
                        app.status = format!("Model set to {}", app.field_value("LLM_MODEL"));
                    }
                }
                KeyCode::Right => {
                    if app.selected_field().key == "LLM_PROVIDER" {
                        app.cycle_provider(1);
                        app.status = format!("Provider set to {}", app.field_value("LLM_PROVIDER"));
                    } else if app.selected_field().key == "LLM_MODEL" {
                        app.cycle_model(1);
                        app.status = format!("Model set to {}", app.field_value("LLM_MODEL"));
                    }
                }
                KeyCode::Char('e') => {
                    let selected_key = app.selected_field().key.clone();
                    if selected_key == llm_provider_profiles_key() {
                        app.open_provider_preset_page();
                        app.status = "Editing provider profiles".into();
                    } else if app.open_llm_override_page_for_field(&selected_key) {
                        app.status = format!("Editing {}", selected_key);
                    } else {
                        app.editing = true;
                        app.status = format!("Editing {}", app.selected_field().key);
                    }
                }
                KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.clear_selected_field();
                }
                KeyCode::Delete => {
                    app.clear_selected_field();
                }
                KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.restore_selected_field_default();
                }
                KeyCode::F(2) => match app.validate_local().and_then(|_| app.validate_online()) {
                    Ok(checks) => app.status = format!("Validation passed: {}", checks.join(" | ")),
                    Err(e) => app.status = format!("Validation failed: {e}"),
                },
                KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    try_save_skip_online(&mut terminal, &mut app)?;
                }
                KeyCode::Char('S') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    try_save_skip_online(&mut terminal, &mut app)?;
                }
                KeyCode::Char('s') => {
                    try_save(&mut terminal, &mut app)?;
                }
                _ => {}
            }
        }
    }
}

pub fn run_setup_wizard() -> Result<bool, MicroClawError> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let terminal = ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(stdout))?;
    let result = run_wizard(terminal);
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

pub fn enable_sandbox_in_config() -> Result<String, MicroClawError> {
    let Some(path) = Config::resolve_config_path()? else {
        return Err(MicroClawError::Config(
            "No microclaw.config.yaml found. Run `microclaw setup` first.".to_string(),
        ));
    };
    let mut cfg = Config::load()?;
    let before_cfg = cfg.clone();
    cfg.sandbox.mode = SandboxMode::All;
    cfg.sandbox.backend = SandboxBackend::Auto;
    cfg.sandbox.no_network = true;
    cfg.sandbox.require_runtime = true;
    crate::config_persistence::save_config_delta_preserving_comments(&path, &before_cfg, &cfg)?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    #[test]
    fn test_mask_secret() {
        assert_eq!(mask_secret("abcdefghi"), "abc***hi");
        assert_eq!(mask_secret("abc"), "***");
    }

    #[test]
    fn test_channel_options_include_web() {
        let options = SetupApp::channel_options();
        assert!(options.contains(&"web"));
    }

    #[test]
    fn test_setup_defaults_enabled_channels_to_web() {
        let app = SetupApp::new();
        assert_eq!(app.default_value_for_field("ENABLED_CHANNELS"), "web");
    }

    #[test]
    fn test_setup_loads_existing_web_hook_settings() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_web_hooks_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
channels:
  web:
    enabled: true
    hooks_token: "my-hooks-secret"
    hooks_default_session_key: "hook:ingress"
    hooks_allow_request_session_key: false
    hooks_allowed_session_key_prefixes:
      - "hook:"
      - "ops:"
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value(web_hooks_token_key()), "my-hooks-secret");
        assert_eq!(
            app.field_value(web_hooks_default_session_key_key()),
            "hook:ingress"
        );
        assert_eq!(
            app.field_value(web_hooks_allow_request_session_key_key()),
            "false"
        );
        assert_eq!(
            app.field_value(web_hooks_allowed_session_key_prefixes_key()),
            "hook:,ops:"
        );

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_loads_existing_a2a_settings() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_a2a_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
a2a:
  enabled: true
  public_base_url: "https://planner.example.com"
  agent_name: "Planner"
  agent_description: "Routes work"
  shared_tokens:
    - "shared-a2a-token"
  peers:
    worker:
      enabled: true
      base_url: "https://worker.example.com"
      bearer_token: "secret"
      default_session_key: "a2a:worker"
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value(a2a_enabled_key()), "true");
        assert_eq!(
            app.field_value(a2a_public_base_url_key()),
            "https://planner.example.com"
        );
        assert_eq!(app.field_value(a2a_agent_name_key()), "Planner");
        assert_eq!(app.field_value(a2a_agent_description_key()), "Routes work");
        assert_eq!(app.field_value(a2a_shared_tokens_key()), "shared-a2a-token");
        assert!(app.field_value(a2a_peers_json_key()).contains("\"worker\""));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_does_not_auto_enable_channels_from_present_but_disabled_blocks() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_disabled_channel_blocks_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
api_key: key
channels:
  web:
    enabled: true
  discord:
    enabled: false
    default_account: "ops"
    accounts:
      ops:
        bot_token: "discord_token_123"
  slack:
    enabled: false
    app_token: "xapp-1"
    bot_token: "xoxb-1"
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value("ENABLED_CHANNELS"), "web");

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_load_existing_config_keeps_legacy_top_level_channel_inference() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_legacy_channel_inference_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
api_key: key
telegram_bot_token: "tg_token_123"
bot_username: "tg_bot"
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        let enabled = app.field_value("ENABLED_CHANNELS");
        assert!(enabled.split(',').any(|channel| channel == "telegram"));
        assert!(!enabled.split(',').any(|channel| channel == "discord"));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_loads_existing_provider_presets_from_legacy_llm_providers() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_provider_presets_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
llm_provider: anthropic
api_key: key
llm_providers:
  "1":
    provider: openai
    api_key: preset-key
    default_model: gpt-5.2
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        let presets = app.field_value(llm_provider_profiles_key());
        assert!(presets.contains("\"1\""));
        assert!(presets.contains("\"provider\":\"openai\""));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_a2a_fields_render_in_a2a_section() {
        assert_eq!(SetupApp::section_for_key(a2a_enabled_key()), "A2A");
        assert_eq!(SetupApp::section_for_key(a2a_public_base_url_key()), "A2A");
        assert_eq!(SetupApp::section_for_key("ENABLED_CHANNELS"), "Channel");
    }

    #[test]
    fn test_subagent_fields_render_in_subagents_section() {
        assert_eq!(
            SetupApp::section_for_key(subagents_max_tokens_per_run_key()),
            "Sub-agents"
        );
        assert_eq!(
            SetupApp::section_for_key(subagents_run_timeout_secs_key()),
            "Sub-agents"
        );
        assert_eq!(
            SetupApp::section_for_key(subagents_acp_targets_json_key()),
            "Sub-agents"
        );
    }

    #[test]
    fn test_setup_loads_existing_telegram_topic_routing() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_telegram_topic_routing_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
channels:
  telegram:
    enabled: true
    topic_routing:
      enabled: true
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value(telegram_topic_routing_key()), "true");

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_loads_existing_subagents_settings() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_subagents_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
subagents:
  max_concurrent: 8
  max_active_per_chat: 9
  run_timeout_secs: 1800
  announce_to_chat: false
  max_spawn_depth: 2
  max_children_per_run: 7
  thread_bound_routing_enabled: false
  announce_relay_interval_secs: 30
  max_tokens_per_run: 240000
  orchestrate_max_workers: 6
  acp:
    enabled: true
    command: codex
    args: ["--model", "gpt-5.4"]
    env:
      OPENAI_API_KEY: key
    auto_approve: false
    default_target: codex-fast
    targets:
      codex-fast:
        enabled: true
        command: codex
        args: ["--model", "gpt-5.4"]
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value(subagents_max_concurrent_key()), "8");
        assert_eq!(app.field_value(subagents_max_active_per_chat_key()), "9");
        assert_eq!(app.field_value(subagents_run_timeout_secs_key()), "1800");
        assert_eq!(app.field_value(subagents_announce_to_chat_key()), "false");
        assert_eq!(app.field_value(subagents_max_spawn_depth_key()), "2");
        assert_eq!(app.field_value(subagents_max_children_per_run_key()), "7");
        assert_eq!(
            app.field_value(subagents_thread_bound_routing_enabled_key()),
            "false"
        );
        assert_eq!(
            app.field_value(subagents_announce_relay_interval_secs_key()),
            "30"
        );
        assert_eq!(
            app.field_value(subagents_max_tokens_per_run_key()),
            "240000"
        );
        assert_eq!(
            app.field_value(subagents_orchestrate_max_workers_key()),
            "6"
        );
        assert_eq!(app.field_value(subagents_acp_enabled_key()), "true");
        assert_eq!(app.field_value(subagents_acp_command_key()), "codex");
        assert_eq!(
            app.field_value(subagents_acp_args_key()),
            "[\"--model\",\"gpt-5.4\"]"
        );
        assert_eq!(
            app.field_value(subagents_acp_env_json_key()),
            "{\"OPENAI_API_KEY\":\"key\"}"
        );
        assert_eq!(app.field_value(subagents_acp_auto_approve_key()), "false");
        assert_eq!(
            app.field_value(subagents_acp_default_target_key()),
            "codex-fast"
        );
        assert!(app
            .field_value(subagents_acp_targets_json_key())
            .contains("\"codex-fast\""));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_save_config_yaml() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram,web".into());
        values.insert("TELEGRAM_BOT_TOKEN".into(), "new_tok".into());
        values.insert("BOT_USERNAME".into(), "new_bot".into());
        values.insert("TELEGRAM_ACCOUNT_ID".into(), "sales".into());
        values.insert(telegram_topic_routing_key().into(), "true".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert("SANDBOX_ENABLED".into(), "true".into());

        let backup = save_config_yaml(&yaml_path, &values).unwrap();
        assert!(backup.is_none()); // No previous file to back up

        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  telegram:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("    default_account: \"sales\"\n"));
        assert!(s.contains("    accounts:\n"));
        assert!(s.contains("      sales:\n"));
        assert!(s.contains("        enabled: true\n"));
        assert!(s.contains("        bot_token: \"new_tok\"\n"));
        assert!(s.contains("        bot_username: \"new_bot\"\n"));
        assert!(s.contains("    topic_routing:\n"));
        assert!(s.contains("      enabled: true\n"));
        assert!(s.contains("  web:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("llm_provider: \"anthropic\""));
        assert!(s.contains("api_key: \"key\""));
        assert!(s.contains("high_risk_tool_user_confirmation_required: true\n"));
        assert!(s.contains("sandbox:\n"));
        assert!(s.contains("  mode: \"all\"\n"));

        // Save again to test backup
        let backup2 = save_config_yaml(&yaml_path, &values).unwrap();
        assert!(backup2.is_some());
        let backup2_path = backup2.unwrap();
        assert!(backup2_path.contains(CONFIG_BACKUP_DIR_NAME));
        assert!(Path::new(&backup2_path).exists());

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_file(&backup2_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_parse_provider_presets_json_rejects_reserved_main() {
        let err = parse_provider_presets_json_value(
            r#"{"main":{"provider":"openai"}}"#,
            llm_provider_profiles_key(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn test_normalize_setup_provider_id_collapses_custom_suffixes() {
        assert_eq!(normalize_setup_provider_id("custom18"), "custom");
        assert_eq!(normalize_setup_provider_id("CUSTOM42"), "custom");
        assert_eq!(normalize_setup_provider_id("anthropic"), "anthropic");
    }

    #[test]
    fn test_extract_openai_error_detail_handles_array_wrapped_messages() {
        let detail = extract_openai_error_detail(
            reqwest::StatusCode::BAD_REQUEST,
            r#"[{"error":{"message":"Request contains an invalid argument."}}]"#,
        );
        assert_eq!(detail, "Request contains an invalid argument.");
    }

    #[test]
    fn test_save_config_yaml_writes_provider_presets_and_channel_refs() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_provider_presets_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram,web".into());
        values.insert("TELEGRAM_BOT_TOKEN".into(), "new_tok".into());
        values.insert("BOT_USERNAME".into(), "new_bot".into());
        values.insert("TELEGRAM_ACCOUNT_ID".into(), "sales".into());
        values.insert(telegram_llm_provider_key().into(), "1".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert(
            llm_provider_profiles_key().into(),
            r#"{"1":{"provider":"openai","api_key":"preset-key","default_model":"gpt-5.2"}}"#
                .into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();

        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("provider_presets:\n"));
        assert!(s.contains("  \"1\":\n") || s.contains("  '1':\n") || s.contains("  1:\n"));
        assert!(s.contains("    provider: openai\n") || s.contains("    provider: \"openai\"\n"));
        assert!(
            s.contains("    default_model: gpt-5.2\n")
                || s.contains("    default_model: \"gpt-5.2\"\n")
        );
        assert!(s.contains("    provider_preset: \"1\"\n"));

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_save_config_yaml_writes_profile_overrides_as_provider_presets_not_models() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_provider_profile_override_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram,discord".into());
        values.insert("TELEGRAM_MODEL".into(), "gemini".into());
        values.insert(telegram_slot_id_key(1), "main".into());
        values.insert(telegram_slot_token_key(1), "telegram-token".into());
        values.insert(telegram_slot_model_key(1), "gemini".into());
        values.insert("DISCORD_MODEL".into(), "nvidia".into());
        values.insert("DISCORD_BOT_TOKEN".into(), "discord-token".into());
        values.insert("DISCORD_ACCOUNT_ID".into(), "default".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();

        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  telegram:\n"));
        assert!(s.contains("    provider_preset: \"gemini\"\n"));
        assert!(s.contains("        provider_preset: gemini\n"));
        assert!(s.contains("  discord:\n"));
        assert!(s.contains("    provider_preset: \"nvidia\"\n"));
        assert!(!s.contains("    model: \"gemini\"\n"));
        assert!(!s.contains("    model: \"nvidia\"\n"));
        assert!(!s.contains("        model: gemini\n"));

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_save_config_yaml_clears_slot_provider_preset_when_set_to_empty() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_clear_slot_preset_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram".into());
        values.insert(telegram_slot_id_key(1), "main".into());
        values.insert(telegram_slot_token_key(1), "tok123".into());
        values.insert(telegram_slot_username_key(1), "TestBot".into());
        // Simulate selecting "main (global default)" -> empty string
        values.insert(telegram_slot_model_key(1), String::new());
        values.insert("LLM_PROVIDER".into(), "openrouter".into());
        values.insert("LLM_API_KEY".into(), "sk-or-key".into());

        save_config_yaml(&yaml_path, &values).unwrap();

        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  telegram:\n"));
        // The account should NOT have provider_preset when cleared
        // (ignore comment lines like "# provider_presets:")
        let has_active_preset = s
            .lines()
            .any(|line| !line.trim_start().starts_with('#') && line.contains("provider_preset:"));
        assert!(
            !has_active_preset,
            "provider_preset should not appear when set to empty:\n{s}"
        );

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_save_config_yaml_clears_channel_provider_preset_when_set_to_empty() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_clear_channel_preset_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram".into());
        values.insert("TELEGRAM_MODEL".into(), String::new());
        values.insert(telegram_llm_provider_key().into(), String::new());
        values.insert(telegram_slot_id_key(1), "main".into());
        values.insert(telegram_slot_token_key(1), "tok123".into());
        values.insert(telegram_slot_username_key(1), "TestBot".into());
        values.insert(telegram_slot_model_key(1), String::new());
        values.insert("LLM_PROVIDER".into(), "openrouter".into());
        values.insert("LLM_API_KEY".into(), "sk-or-key".into());

        save_config_yaml(&yaml_path, &values).unwrap();

        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  telegram:\n"));
        let has_active_preset = s
            .lines()
            .any(|line| !line.trim_start().starts_with('#') && line.contains("provider_preset:"));
        assert!(
            !has_active_preset,
            "provider_preset should not appear when both TELEGRAM_MODEL and LLM_PROVIDER are empty:\n{s}"
        );

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_next_provider_preset_id_uses_provider_prefix() {
        let entries = vec![
            ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
            ProviderPresetDraft {
                id: "provider3".into(),
                provider: "anthropic".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
        ];
        assert_eq!(SetupApp::next_provider_preset_id(&entries), "provider2");
    }

    #[test]
    fn test_next_cloned_provider_preset_id_uses_incrementing_dash_suffix() {
        let entries = vec![
            ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
            ProviderPresetDraft {
                id: "provider1-2".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
        ];
        assert_eq!(
            SetupApp::next_cloned_provider_preset_id(&entries, "provider1"),
            "provider1-3"
        );
    }

    #[test]
    fn test_provider_preset_serialization_keeps_user_agent_and_show_thinking() {
        let json = SetupApp::serialize_provider_preset_drafts(&[ProviderPresetDraft {
            id: "provider1".into(),
            provider: "openai".into(),
            api_key: "sk-test".into(),
            base_url: "https://example.com/v1".into(),
            user_agent: "microclaw-test/1.0".into(),
            default_model: "gpt-5.2".into(),
            show_thinking: true,
        }])
        .unwrap();
        let presets =
            parse_provider_presets_json_value(&json, llm_provider_profiles_key()).unwrap();
        let preset = presets.get("provider1").unwrap();
        assert_eq!(preset.llm_user_agent.as_deref(), Some("microclaw-test/1.0"));
        assert_eq!(preset.show_thinking, Some(true));
    }

    #[test]
    fn test_clone_selected_provider_preset_creates_dash_suffix_copy_and_focuses_model() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "anthropic".into(),
                api_key: "sk-test".into(),
                base_url: "https://example.com/v1".into(),
                user_agent: "microclaw-test/1.0".into(),
                default_model: "claude-sonnet-4-5-20250929".into(),
                show_thinking: true,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let cloned_id = app.clone_selected_provider_preset().unwrap().unwrap();

        assert_eq!(cloned_id, "provider1-2");
        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.selected, 1);
        assert!(matches!(page.mode, ProviderPresetPageMode::Edit));
        assert_eq!(page.field_selected, 3);
        assert!(!page.editing);
        assert_eq!(page.entries[1].id, "provider1-2");
        assert_eq!(page.entries[1].provider, "anthropic");
        assert_eq!(page.entries[1].default_model, "claude-sonnet-4-5-20250929");
        assert!(page.entries[1].show_thinking);
    }

    #[test]
    fn test_selected_provider_preset_validation_request_uses_current_entry_values() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "anthropic".into(),
                api_key: "sk-test".into(),
                base_url: "https://example.com/v1".into(),
                user_agent: "microclaw-test/1.0".into(),
                default_model: String::new(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let request = app.selected_provider_preset_validation_request().unwrap();

        assert_eq!(request.profile_id, "provider1");
        assert_eq!(request.provider, "anthropic");
        assert_eq!(request.api_key, "sk-test");
        assert_eq!(request.base_url, "https://example.com/v1");
        assert_eq!(request.user_agent, "microclaw-test/1.0");
        assert_eq!(request.model, "claude-sonnet-4-5-20250929");
        assert_eq!(request.codex_account_id, None);
    }

    #[test]
    fn test_clear_selected_provider_preset_field_clears_without_edit_mode() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "google".into(),
                api_key: "secret".into(),
                base_url: "https://example.com/v1".into(),
                user_agent: "ua".into(),
                default_model: "gemini-2.5-pro".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 2,
            editing: false,
            picker: None,
        });

        app.clear_selected_provider_preset_field();

        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries[0].api_key, "");
    }

    #[test]
    fn test_restore_selected_provider_preset_field_default_restores_provider_base_url() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: "https://integrate.api.nvidia.com/v1".into(),
                user_agent: String::new(),
                default_model: "meta/llama-3.3-70b-instruct".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 4,
            editing: false,
            picker: None,
        });

        let restored = app
            .restore_selected_provider_preset_field_default()
            .unwrap();

        assert_eq!(restored, "https://api.openai.com/v1");
        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries[0].base_url, "https://api.openai.com/v1");
    }

    #[test]
    fn test_switching_provider_updates_default_base_url_and_model_when_still_on_old_defaults() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "nvidia".into(),
                api_key: String::new(),
                base_url: "https://integrate.api.nvidia.com/v1".into(),
                user_agent: String::new(),
                default_model: "meta/llama-3.3-70b-instruct".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 1,
            editing: false,
            picker: Some(LlmOverridePicker {
                title: "Select Provider".into(),
                target_key: "provider".into(),
                options: vec![("openai".into(), "openai".into())],
                selected: 0,
            }),
        });

        app.apply_provider_preset_picker_selection();

        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries[0].provider, "openai");
        assert_eq!(page.entries[0].base_url, "https://api.openai.com/v1");
        assert_eq!(page.entries[0].default_model, "gpt-5.2");
    }

    #[test]
    fn test_provider_preset_enter_on_default_model_opens_model_picker() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: "https://api.openai.com/v1".into(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 3,
            editing: false,
            picker: None,
        });

        app.handle_provider_preset_enter();

        let page = app.provider_preset_page.as_ref().unwrap();
        let picker = page.picker.as_ref().unwrap();
        assert_eq!(picker.target_key, "default_model");
        assert!(picker.title.contains("openai"));
        assert!(!page.editing);
    }

    #[test]
    fn test_provider_preset_enter_on_base_url_starts_text_editing() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: "https://api.openai.com/v1".into(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 4,
            editing: false,
            picker: None,
        });

        app.handle_provider_preset_enter();

        let page = app.provider_preset_page.as_ref().unwrap();
        assert!(page.editing);
        assert!(page.picker.is_none());
        assert_eq!(app.status, "Editing provider profile field");
    }

    #[test]
    fn test_custom_provider_model_picker_hides_placeholder_model() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "custom".into(),
                api_key: String::new(),
                base_url: "https://example.com/v1".into(),
                user_agent: String::new(),
                default_model: "custom-model".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 3,
            editing: false,
            picker: None,
        });

        app.open_provider_preset_model_picker();

        let page = app.provider_preset_page.as_ref().unwrap();
        let picker = page.picker.as_ref().unwrap();
        assert_eq!(picker.target_key, "default_model");
        assert_eq!(picker.options.len(), 1);
        assert_eq!(picker.options[0].0, MODEL_PICKER_MANUAL_INPUT);
        assert_eq!(picker.options[0].1, MODEL_PICKER_MANUAL_INPUT);
    }

    #[test]
    fn test_provider_presets_field_comes_after_show_thinking_in_model_section() {
        let app = SetupApp::new();
        let show_idx = app
            .fields
            .iter()
            .position(|f| f.key == "SHOW_THINKING")
            .unwrap();
        let presets_idx = app
            .fields
            .iter()
            .position(|f| f.key == llm_provider_profiles_key())
            .unwrap();
        assert!(presets_idx > show_idx);
    }

    #[test]
    fn test_provider_preset_references_collect_channel_and_dynamic_slots() {
        let mut app = SetupApp::new();
        app.set_field_value(telegram_llm_provider_key(), "1".into());
        app.set_field_value(&telegram_slot_id_key(2), "bot2".into());
        app.set_field_value(&telegram_slot_model_key(2), "1".into());
        app.set_field_value(&dynamic_slot_llm_provider_key("slack", 1), "1".into());
        app.set_field_value(&dynamic_slot_id_field_key("slack", 1), "sales".into());

        let refs = app.provider_preset_references("1");
        assert!(refs.iter().any(|v| v == "telegram channel"));
        assert!(refs.iter().any(|v| v == "telegram.bot2"));
        assert!(refs.iter().any(|v| v == "slack.sales"));
    }

    #[test]
    fn test_renaming_provider_preset_updates_references() {
        let mut app = SetupApp::new();
        app.set_field_value(telegram_llm_provider_key(), "1".into());
        app.set_field_value(&telegram_slot_id_key(2), "bot2".into());
        app.set_field_value(&telegram_slot_model_key(2), "1".into());
        app.set_field_value(&dynamic_slot_llm_provider_key("slack", 1), "1".into());
        app.set_field_value(&dynamic_slot_id_field_key("slack", 1), "sales".into());
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 0,
            editing: true,
            picker: None,
        });

        app.set_provider_preset_selected_field_value("2".into());

        assert_eq!(app.field_value(telegram_llm_provider_key()), "2");
        assert_eq!(app.field_value(&telegram_slot_model_key(2)), "2");
        assert_eq!(
            app.field_value(&dynamic_slot_llm_provider_key("slack", 1)),
            "2"
        );
        let refs = app.provider_preset_references("2");
        assert!(refs.iter().any(|v| v == "telegram channel"));
        assert!(refs.iter().any(|v| v == "telegram.bot2"));
        assert!(refs.iter().any(|v| v == "slack.sales"));
    }

    #[test]
    fn test_delete_selected_provider_preset_blocks_when_referenced() {
        let mut app = SetupApp::new();
        app.set_field_value(telegram_llm_provider_key(), "1".into());
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let err = app.delete_selected_provider_preset(false).unwrap_err();
        assert!(err.to_string().contains("still referenced"));
        assert_eq!(app.field_value(telegram_llm_provider_key()), "1");
        assert_eq!(
            app.provider_preset_page
                .as_ref()
                .map(|page| page.entries.len())
                .unwrap_or_default(),
            1
        );
    }

    #[test]
    fn test_delete_selected_provider_preset_can_reset_refs_to_main() {
        let mut app = SetupApp::new();
        app.set_field_value(telegram_llm_provider_key(), "1".into());
        app.set_field_value(&dynamic_slot_llm_provider_key("slack", 1), "1".into());
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let updated_refs = app.delete_selected_provider_preset(true).unwrap();
        assert_eq!(
            updated_refs,
            vec!["slack.main".to_string(), "telegram channel".to_string()]
        );
        assert_eq!(app.field_value(telegram_llm_provider_key()), "");
        assert_eq!(
            app.field_value(&dynamic_slot_llm_provider_key("slack", 1)),
            ""
        );
        assert_eq!(
            app.provider_preset_page
                .as_ref()
                .map(|page| page.entries.len())
                .unwrap_or_default(),
            0
        );
    }

    #[test]
    fn test_key_display_hides_json_suffix_for_provider_presets() {
        assert_eq!(
            SetupApp::key_display(llm_provider_profiles_key()),
            "LLM_PROVIDER_PROFILES"
        );
    }

    #[test]
    fn test_provider_preset_field_label_uses_default_model() {
        assert_eq!(SetupApp::provider_preset_field_labels()[3], "Default model");
    }

    #[test]
    fn test_push_telegram_disabled_status_included_when_requested() {
        let mut checks = Vec::new();
        push_telegram_disabled_status(&mut checks, true);
        assert_eq!(checks, vec!["Telegram skipped (disabled)".to_string()]);
    }

    #[test]
    fn test_push_telegram_disabled_status_omitted_when_not_requested() {
        let mut checks = Vec::new();
        push_telegram_disabled_status(&mut checks, false);
        assert!(checks.is_empty());
    }

    #[test]
    fn test_save_config_yaml_respects_high_risk_confirmation_toggle() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_high_risk_confirm_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert(
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED".into(),
            "false".into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("high_risk_tool_user_confirmation_required: false\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_writes_a2a_section() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_a2a_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert(a2a_enabled_key().into(), "true".into());
        values.insert(
            a2a_public_base_url_key().into(),
            "https://planner.example.com".into(),
        );
        values.insert(a2a_agent_name_key().into(), "Planner".into());
        values.insert(a2a_agent_description_key().into(), "Routes work".into());
        values.insert(a2a_shared_tokens_key().into(), "shared-a2a-token".into());
        values.insert(
            a2a_peers_json_key().into(),
            r#"{"worker":{"enabled":true,"base_url":"https://worker.example.com","default_session_key":"a2a:worker"}}"#
                .into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("a2a:\n"));
        assert!(s.contains("  enabled: true\n"));
        assert!(s.contains("  public_base_url: \"https://planner.example.com\"\n"));
        assert!(s.contains("  agent_name: \"Planner\"\n"));
        assert!(s.contains("  shared_tokens:\n"));
        assert!(s.contains("    worker:\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_writes_subagents_section() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_subagents_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert(subagents_max_concurrent_key().into(), "8".into());
        values.insert(subagents_max_active_per_chat_key().into(), "9".into());
        values.insert(subagents_run_timeout_secs_key().into(), "1800".into());
        values.insert(subagents_announce_to_chat_key().into(), "false".into());
        values.insert(subagents_max_spawn_depth_key().into(), "2".into());
        values.insert(subagents_max_children_per_run_key().into(), "7".into());
        values.insert(
            subagents_thread_bound_routing_enabled_key().into(),
            "false".into(),
        );
        values.insert(
            subagents_announce_relay_interval_secs_key().into(),
            "30".into(),
        );
        values.insert(subagents_max_tokens_per_run_key().into(), "240000".into());
        values.insert(subagents_orchestrate_max_workers_key().into(), "6".into());
        values.insert(subagents_acp_enabled_key().into(), "true".into());
        values.insert(subagents_acp_command_key().into(), "codex".into());
        values.insert(
            subagents_acp_args_key().into(),
            r#"["--model","gpt-5.4"]"#.into(),
        );
        values.insert(
            subagents_acp_env_json_key().into(),
            r#"{"OPENAI_API_KEY":"key"}"#.into(),
        );
        values.insert(subagents_acp_auto_approve_key().into(), "false".into());
        values.insert(
            subagents_acp_default_target_key().into(),
            "codex-fast".into(),
        );
        values.insert(
            subagents_acp_targets_json_key().into(),
            r#"{"codex-fast":{"enabled":true,"command":"codex","args":["--model","gpt-5.4"],"auto_approve":false}}"#
                .into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("subagents:\n"));
        assert!(s.contains("  max_concurrent: 8\n"));
        assert!(s.contains("  max_active_per_chat: 9\n"));
        assert!(s.contains("  run_timeout_secs: 1800\n"));
        assert!(s.contains("  announce_to_chat: false\n"));
        assert!(s.contains("  max_spawn_depth: 2\n"));
        assert!(s.contains("  max_children_per_run: 7\n"));
        assert!(s.contains("  thread_bound_routing_enabled: false\n"));
        assert!(s.contains("  announce_relay_interval_secs: 30\n"));
        assert!(s.contains("  max_tokens_per_run: 240000\n"));
        assert!(s.contains("  orchestrate_max_workers: 6\n"));
        assert!(s.contains("  acp:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("    command: \"codex\"\n"));
        assert!(s.contains("    args:\n"));
        assert!(s.contains("      - \"--model\"\n"));
        assert!(s.contains("      - \"gpt-5.4\"\n"));
        assert!(s.contains("    env:\n"));
        assert!(s.contains("      OPENAI_API_KEY: key\n"));
        assert!(s.contains("    auto_approve: false\n"));
        assert!(s.contains("    default_target: \"codex-fast\"\n"));
        assert!(s.contains("    targets:\n"));
        assert!(s.contains("      codex-fast:\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_escapes_windows_directory_paths() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_windows_path_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert("DATA_DIR".into(), r#"C:\Users\alice\.microclaw"#.into());
        values.insert(
            "WORKING_DIR".into(),
            r#"C:\Users\alice\.microclaw\working_dir"#.into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains(r#"data_dir: "C:\\Users\\alice\\.microclaw""#));
        assert!(s.contains(r#"working_dir: "C:\\Users\\alice\\.microclaw\\working_dir""#));

        let cfg: crate::config::Config = serde_yaml::from_str(&s).unwrap();
        assert_eq!(cfg.data_dir, r#"C:\Users\alice\.microclaw"#);
        assert_eq!(cfg.working_dir, r#"C:\Users\alice\.microclaw\working_dir"#);

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_keeps_unix_directory_paths_unchanged() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_unix_path_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert("DATA_DIR".into(), "/home/alice/.microclaw".into());
        values.insert(
            "WORKING_DIR".into(),
            "/home/alice/.microclaw/working_dir".into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains(r#"data_dir: "/home/alice/.microclaw""#));
        assert!(s.contains(r#"working_dir: "/home/alice/.microclaw/working_dir""#));

        let cfg: crate::config::Config = serde_yaml::from_str(&s).unwrap();
        assert_eq!(cfg.data_dir, "/home/alice/.microclaw");
        assert_eq!(cfg.working_dir, "/home/alice/.microclaw/working_dir");

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_writes_web_hook_settings() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_web_hooks_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert(web_hooks_token_key().into(), "my-hooks-secret".into());
        values.insert(
            web_hooks_default_session_key_key().into(),
            "hook:ingress".into(),
        );
        values.insert(
            web_hooks_allow_request_session_key_key().into(),
            "false".into(),
        );
        values.insert(
            web_hooks_allowed_session_key_prefixes_key().into(),
            "hook:,ops:".into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  web:\n"));
        assert!(s.contains("    hooks_token: \"my-hooks-secret\"\n"));
        assert!(s.contains("    hooks_default_session_key: \"hook:ingress\"\n"));
        assert!(s.contains("    hooks_allow_request_session_key: false\n"));
        assert!(s.contains("    hooks_allowed_session_key_prefixes:\n"));
        assert!(s.contains("      - \"hook:\"\n"));
        assert!(s.contains("      - \"ops:\"\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_uses_accounts_json_for_telegram_and_discord() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_accounts_json_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram,discord".into());
        values.insert(telegram_bot_count_key().into(), "2".into());
        values.insert(telegram_slot_id_key(1), "main".into());
        values.insert(telegram_slot_enabled_key(1), "true".into());
        values.insert(telegram_slot_token_key(1), "tg_main".into());
        values.insert(telegram_slot_username_key(1), "tg_main_bot".into());
        values.insert(telegram_slot_id_key(2), "ops".into());
        values.insert(telegram_slot_enabled_key(2), "true".into());
        values.insert(telegram_slot_token_key(2), "tg_ops".into());
        values.insert(telegram_slot_username_key(2), "tg_ops_bot".into());
        values.insert(telegram_slot_topic_routing_key(2), "true".into());
        values.insert("TELEGRAM_ACCOUNT_ID".into(), "main".into());
        values.insert(
            "DISCORD_ACCOUNTS_JSON".into(),
            r#"{"main":{"enabled":true,"bot_token":"dc_main","allowed_channels":[111,222]},"ops":{"enabled":false,"bot_token":"dc_ops"}}"#.into(),
        );
        values.insert("DISCORD_ACCOUNT_ID".into(), "main".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  telegram:\n"));
        assert!(s.contains("    accounts:\n"));
        assert!(s.contains("      main:\n"));
        assert!(s.contains("        bot_token: tg_main\n"));
        assert!(s.contains("      ops:\n"));
        assert!(s.contains("        bot_token: tg_ops\n"));
        assert!(s.contains("        topic_routing:\n"));
        assert!(s.contains("          enabled: true\n"));
        assert!(s.contains("  discord:\n"));
        assert!(s.contains("        bot_token: dc_main\n"));
        assert!(s.contains("        allowed_channels:\n"));
        assert!(s.contains("111"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_enable_sandbox_in_config_updates_mode() {
        let _guard = env_lock();
        let path = std::env::temp_dir().join(format!(
            "microclaw_setup_enable_sandbox_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(
            &path,
            r#"
llm_provider: "anthropic"
api_key: "k"
model: "claude-sonnet-4-5-20250929"
telegram_bot_token: "tok"
bot_username: "bot"
sandbox:
  mode: "off"
"#,
        )
        .unwrap();
        std::env::set_var("MICROCLAW_CONFIG", &path);
        let out = enable_sandbox_in_config().unwrap();
        assert!(out.contains(path.to_string_lossy().as_ref()));
        let cfg = Config::load().unwrap();
        assert!(matches!(cfg.sandbox.mode, SandboxMode::All));
        assert!(cfg.sandbox.require_runtime);
        std::env::remove_var("MICROCLAW_CONFIG");
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn test_save_config_yaml_preserves_discord_token_without_enabled_channels() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_discord_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "".into());
        values.insert("DISCORD_BOT_TOKEN".into(), "discord_token_123".into());
        values.insert("DISCORD_ACCOUNT_ID".into(), "ops".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("sandbox:\n"));
        assert!(s.contains("  mode: \"off\"\n"));
        assert!(s.contains("  discord:\n"));
        assert!(s.contains("    enabled: false\n"));
        assert!(s.contains("    default_account: \"ops\"\n"));
        assert!(s.contains("      ops:\n"));
        assert!(s.contains("        bot_token: \"discord_token_123\"\n"));
        assert!(s.contains("  web:\n"));
        assert!(s.contains("    enabled: true\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_disables_web_when_not_selected() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_web_toggle_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "discord".into());
        values.insert("DISCORD_BOT_TOKEN".into(), "discord_token_123".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  discord:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("  web:\n"));
        assert!(s.contains("    enabled: false\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_keeps_telegram_disabled_with_credentials() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_telegram_disabled_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "discord".into());
        values.insert("TELEGRAM_BOT_TOKEN".into(), "tg_token_123".into());
        values.insert("BOT_USERNAME".into(), "tg_bot".into());
        values.insert("TELEGRAM_ACCOUNT_ID".into(), "team_a".into());
        values.insert("DISCORD_BOT_TOKEN".into(), "discord_token_123".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  telegram:\n"));
        assert!(s.contains("    enabled: false\n"));
        assert!(s.contains("    default_account: \"team_a\"\n"));
        assert!(s.contains("      team_a:\n"));
        assert!(s.contains("        bot_token: \"tg_token_123\"\n"));
        assert!(s.contains("        bot_username: \"tg_bot\"\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_channel_dependent_fields_are_hidden_until_enabled() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value.clear();
        }
        app.ensure_selected_visible();

        let visible_keys: Vec<String> = app
            .visible_field_indices()
            .iter()
            .map(|idx| app.fields[*idx].key.clone())
            .collect();
        let hidden_keys = vec![
            telegram_bot_count_key().to_string(),
            telegram_slot_id_key(1),
            telegram_slot_token_key(1),
            telegram_slot_username_key(1),
            telegram_slot_allowed_user_ids_key(1),
            telegram_slot_topic_routing_key(1),
            "DISCORD_BOT_TOKEN".to_string(),
            "DISCORD_ACCOUNT_ID".to_string(),
            dynamic_bot_count_field_key("feishu"),
            dynamic_slot_id_field_key("feishu", 1),
            dynamic_slot_field_key("feishu", 1, "app_id"),
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            dynamic_slot_field_key("feishu", 1, "domain"),
            dynamic_slot_field_key("feishu", 1, "show_progress"),
        ];
        for key in hidden_keys {
            assert!(
                !visible_keys.iter().any(|k| k == &key),
                "{key} should be hidden when channel is not enabled"
            );
        }

        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram,feishu".to_string();
        }
        app.ensure_selected_visible();
        let visible_keys: Vec<String> = app
            .visible_field_indices()
            .iter()
            .map(|idx| app.fields[*idx].key.clone())
            .collect();
        let shown_keys = vec![
            telegram_bot_count_key().to_string(),
            telegram_slot_id_key(1),
            telegram_slot_token_key(1),
            telegram_slot_username_key(1),
            telegram_slot_allowed_user_ids_key(1),
            telegram_slot_topic_routing_key(1),
            dynamic_bot_count_field_key("feishu"),
            dynamic_slot_id_field_key("feishu", 1),
            dynamic_slot_field_key("feishu", 1, "app_id"),
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            dynamic_slot_field_key("feishu", 1, "domain"),
            dynamic_slot_field_key("feishu", 1, "show_progress"),
        ];
        for key in shown_keys {
            assert!(
                visible_keys.iter().any(|k| k == &key),
                "{key} should be visible when channel is enabled"
            );
        }
    }

    #[test]
    fn test_save_config_yaml_keeps_dynamic_channel_disabled_when_not_selected() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_dynamic_skip_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "".into());
        values.insert(dynamic_bot_count_field_key("feishu"), "1".into());
        values.insert(dynamic_slot_id_field_key("feishu", 1), "support".into());
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_id"),
            "app_id_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            "app_secret_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "domain"),
            "feishu".into(),
        );
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  feishu:\n"));
        assert!(s.contains("    enabled: false\n"));
        assert!(s.contains("    default_account: \"support\"\n"));
        assert!(s.contains("      support:\n"));
        assert!(s.contains("app_id_1"));
        assert!(s.contains("app_secret_1"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_includes_dynamic_channel_when_selected() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_dynamic_include_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "feishu".into());
        values.insert(dynamic_bot_count_field_key("feishu"), "1".into());
        values.insert(dynamic_slot_id_field_key("feishu", 1), "ops".into());
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_id"),
            "app_id_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            "app_secret_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "domain"),
            "feishu".into(),
        );
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  feishu:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("    default_account: \"ops\"\n"));
        assert!(s.contains("      ops:\n"));
        assert!(s.contains("app_id_1"));
        assert!(s.contains("app_secret_1"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_keeps_weixin_minimal_when_selected() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_weixin_minimal_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "weixin".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  weixin:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(!s.contains("default_account:"));
        assert!(!s.contains("accounts:"));
        assert!(!s.contains("    base_url:"));
        assert!(!s.contains("    cdn_base_url:"));
        assert!(!s.contains("    webhook_path:"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_writes_feishu_topic_mode_as_bool() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_feishu_topic_mode_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "feishu".into());
        values.insert(dynamic_bot_count_field_key("feishu"), "1".into());
        values.insert(dynamic_slot_id_field_key("feishu", 1), "ops".into());
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_id"),
            "app_id_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            "app_secret_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "domain"),
            "feishu".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "topic_mode"),
            "true".into(),
        );
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("topic_mode: true"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_writes_feishu_show_progress_as_bool() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_feishu_show_progress_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "feishu".into());
        values.insert(dynamic_bot_count_field_key("feishu"), "1".into());
        values.insert(dynamic_slot_id_field_key("feishu", 1), "ops".into());
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_id"),
            "app_id_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            "app_secret_1".into(),
        );
        values.insert(
            dynamic_slot_field_key("feishu", 1, "show_progress"),
            "true".into(),
        );
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("show_progress: true"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_writes_slack_inbound_image_max_mb_as_number() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_slack_inbound_image_max_mb_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "slack".into());
        values.insert(dynamic_bot_count_field_key("slack"), "1".into());
        values.insert(dynamic_slot_id_field_key("slack", 1), "main".into());
        values.insert(
            dynamic_slot_field_key("slack", 1, "bot_token"),
            "xoxb-token".into(),
        );
        values.insert(
            dynamic_slot_field_key("slack", 1, "app_token"),
            "xapp-token".into(),
        );
        values.insert(
            dynamic_slot_field_key("slack", 1, "capture_unmentioned_images"),
            "false".into(),
        );
        values.insert(
            dynamic_slot_field_key("slack", 1, "inbound_image_max_mb"),
            "20".into(),
        );
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("capture_unmentioned_images: false"));
        assert!(s.contains("inbound_image_max_mb: 20"));

        let parsed: crate::config::Config = serde_yaml::from_str(&s).unwrap();
        let slack = parsed
            .channels
            .get("slack")
            .and_then(|v| v.get("accounts"))
            .and_then(|v| v.get("main"))
            .and_then(|v| v.get("inbound_image_max_mb"))
            .and_then(|v| v.as_u64());
        assert_eq!(slack, Some(20));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_validate_local_rejects_invalid_account_id() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_token_key(1))
        {
            field.value = "123456:token".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_username_key(1))
        {
            field.value = "botname".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_id_key(1))
        {
            field.value = "invalid account".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }
        let err = app.validate_local().unwrap_err();
        assert!(err.to_string().contains(&format!(
            "{} must use only letters, numbers, '_' or '-'",
            telegram_slot_id_key(1)
        )));
    }

    #[test]
    fn test_validate_local_accepts_accounts_json_without_legacy_tokens() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram,discord".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_bot_count_key())
        {
            field.value = "2".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_id_key(1))
        {
            field.value = "main".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_token_key(1))
        {
            field.value = "123456:token".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_username_key(1))
        {
            field.value = "botname".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == "DISCORD_ACCOUNTS_JSON")
        {
            field.value =
                r#"{"main":{"enabled":true,"bot_token":"discord_token_123"}}"#.to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }

        let result = app.validate_local();
        assert!(result.is_ok(), "validate_local failed: {result:?}");
    }

    #[test]
    fn test_validate_local_accepts_minimal_weixin() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "weixin".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_PROVIDER") {
            field.value = "anthropic".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }

        let result = app.validate_local();
        assert!(result.is_ok(), "validate_local failed: {result:?}");
    }

    #[test]
    fn test_weixin_setup_fields_hidden_when_enabled() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "weixin".to_string();
        }
        app.ensure_selected_visible();

        let visible_keys: Vec<String> = app
            .visible_field_indices()
            .iter()
            .map(|idx| app.fields[*idx].key.clone())
            .collect();

        assert!(!visible_keys
            .iter()
            .any(|k| k == &dynamic_bot_count_field_key("weixin")));
        assert!(!visible_keys
            .iter()
            .any(|k| k == &dynamic_slot_id_field_key("weixin", 1)));
        assert!(!visible_keys
            .iter()
            .any(|k| k == &dynamic_slot_field_key("weixin", 1, "base_url")));
        assert!(!visible_keys
            .iter()
            .any(|k| k == &dynamic_slot_field_key("weixin", 1, "cdn_base_url")));
    }

    #[test]
    fn test_validate_local_rejects_feishu_topic_mode_on_custom_domain() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "feishu".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == dynamic_bot_count_field_key("feishu"))
        {
            field.value = "1".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == dynamic_slot_id_field_key("feishu", 1))
        {
            field.value = "main".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == dynamic_slot_field_key("feishu", 1, "app_id"))
        {
            field.value = "app_id_1".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == dynamic_slot_field_key("feishu", 1, "app_secret"))
        {
            field.value = "app_secret_1".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == dynamic_slot_field_key("feishu", 1, "domain"))
        {
            field.value = "custom.example.com".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == dynamic_slot_field_key("feishu", 1, "topic_mode"))
        {
            field.value = "true".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }

        let err = app.validate_local().unwrap_err();
        assert!(err.to_string().contains("topic_mode is only supported"));
    }

    #[test]
    fn test_validate_local_accepts_telegram_accounts_array_json() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_bot_count_key())
        {
            field.value = "2".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_id_key(1))
        {
            field.value = "main".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_token_key(1))
        {
            field.value = "123456:token".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_username_key(1))
        {
            field.value = "botname".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_id_key(2))
        {
            field.value = "support".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_token_key(2))
        {
            field.value = "999:token2".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }
        let result = app.validate_local();
        assert!(result.is_ok(), "validate_local failed: {result:?}");
    }

    #[test]
    fn test_validate_local_rejects_invalid_telegram_allowed_user_ids() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_token_key(1))
        {
            field.value = "123456:token".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_username_key(1))
        {
            field.value = "botname".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_allowed_user_ids_key(1))
        {
            field.value = "123,abc".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }
        let err = app.validate_local().unwrap_err();
        assert!(err
            .to_string()
            .contains(&telegram_slot_allowed_user_ids_key(1)));
    }

    #[test]
    fn test_validate_local_requires_slots_when_telegram_bot_count_gt_one() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_bot_count_key())
        {
            field.value = "2".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_slot_id_key(1))
        {
            field.value.clear();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }
        let err = app.validate_local().unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("TELEGRAM_BOT")
                || text.contains("TELEGRAM_BOT_COUNT")
                || text.contains("USERNAME")
        );
    }

    #[test]
    fn test_save_config_yaml_uses_telegram_slot_fields_when_multibot_enabled() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_tg_slots_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram".into());
        values.insert(telegram_bot_count_key().into(), "2".into());
        values.insert(telegram_slot_id_key(1), "main".into());
        values.insert(telegram_slot_enabled_key(1), "true".into());
        values.insert(telegram_slot_token_key(1), "tg_main".into());
        values.insert(telegram_slot_username_key(1), "main_bot".into());
        values.insert(telegram_slot_allowed_user_ids_key(1), "123,456".into());
        values.insert(telegram_slot_id_key(2), "support".into());
        values.insert(telegram_slot_enabled_key(2), "false".into());
        values.insert(telegram_slot_token_key(2), "tg_support".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("  telegram:\n"));
        assert!(s.contains("      main:\n"));
        assert!(s.contains("        bot_token: tg_main\n"));
        assert!(s.contains("        bot_username: main_bot\n"));
        assert!(s.contains("        allowed_user_ids:\n"));
        assert!(s.contains("        - 123\n"));
        assert!(s.contains("        - 456\n"));
        assert!(s.contains("      support:\n"));
        assert!(s.contains("        enabled: false\n"));
        assert!(s.contains("        bot_token: tg_support\n"));
        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_resolve_openai_compat_validation_base_codex() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let temp = std::env::temp_dir().join(format!(
            "microclaw-setup-codex-base-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&temp);
        std::env::set_var("CODEX_HOME", &temp);

        let base = resolve_openai_compat_validation_base("openai-codex", "", None);
        assert_eq!(base, "https://chatgpt.com/backend-api/codex");
        let legacy = resolve_openai_compat_validation_base(
            "openai-codex",
            "https://chatgpt.com/backend-api",
            None,
        );
        assert_eq!(legacy, "https://chatgpt.com/backend-api/codex");

        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        let _ = fs::remove_dir(temp);
    }

    #[test]
    fn test_resolve_openai_compat_validation_base_openai() {
        let base = resolve_openai_compat_validation_base("openai", "https://api.openai.com", None);
        assert_eq!(base, "https://api.openai.com");
    }

    #[test]
    fn test_resolve_openai_compat_validation_base_keeps_non_v1_prefix() {
        let preset = find_provider_preset("zhipu");
        let base = resolve_openai_compat_validation_base("zhipu", "", preset);
        assert_eq!(base, "https://open.bigmodel.cn/api/paas/v4");
    }

    #[test]
    fn test_should_retry_with_max_completion_tokens() {
        let err = r#"{"error":{"message":"Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.","param":"max_tokens"}}"#;
        assert!(should_retry_with_max_completion_tokens(err));
        assert!(!should_retry_with_max_completion_tokens(
            r#"{"error":{"message":"bad request","param":"messages"}}"#
        ));
    }

    #[test]
    fn test_switch_to_max_completion_tokens() {
        let mut body = serde_json::json!({"model":"gpt-5.2","max_tokens":1});
        assert!(switch_to_max_completion_tokens(&mut body));
        assert_eq!(body.get("max_tokens"), None);
        assert_eq!(body["max_completion_tokens"], 1);
        assert!(!switch_to_max_completion_tokens(&mut body));
    }

    #[test]
    fn test_is_validation_output_capped_error() {
        assert!(is_validation_output_capped_error(
            "Could not finish the message because max_tokens or model output limit was reached"
        ));
        assert!(!is_validation_output_capped_error("invalid api key"));
    }

    #[test]
    fn test_llm_api_key_required_depends_on_provider() {
        let mut app = SetupApp::new();
        app.set_provider("openai-codex");
        let api_key_field = app
            .fields
            .iter()
            .find(|f| f.key == "LLM_API_KEY")
            .expect("LLM_API_KEY field missing");
        assert!(!app.is_field_required(api_key_field));

        app.set_provider("openai");
        let api_key_field = app
            .fields
            .iter()
            .find(|f| f.key == "LLM_API_KEY")
            .expect("LLM_API_KEY field missing");
        assert!(app.is_field_required(api_key_field));
    }

    #[test]
    fn test_default_model_for_minimax_is_m2_5() {
        assert_eq!(default_model_for_provider("minimax"), "MiniMax-M2.5");
    }

    #[test]
    fn test_default_model_for_xiaomi_is_mimo_v2_5_pro() {
        assert_eq!(default_model_for_provider("xiaomi"), "MiMo-V2.5-Pro");
    }

    #[test]
    fn test_model_picker_options_include_manual_input() {
        let app = SetupApp::new();
        let options = app.model_picker_options();
        assert_eq!(
            options.last().map(String::as_str),
            Some(MODEL_PICKER_MANUAL_INPUT)
        );
    }

    #[test]
    fn test_model_picker_manual_input_enters_edit_mode() {
        let mut app = SetupApp::new();
        app.set_provider("openai");
        let model_idx = app
            .fields
            .iter()
            .position(|f| f.key == "LLM_MODEL")
            .expect("LLM_MODEL field missing");
        app.selected = model_idx;
        assert!(app.open_picker_for_selected());
        let manual_idx = app.model_picker_options().len().saturating_sub(1);
        if let Some(picker) = app.picker.as_mut() {
            picker.selected = manual_idx;
        }
        app.apply_picker_selection();
        assert!(app.editing);
        assert!(app.status.contains("manual input"));
    }

    #[test]
    fn test_timezone_picker_options_include_system_default_and_manual_input() {
        let app = SetupApp::new();
        let options = app.timezone_picker_options();
        assert_eq!(
            options.first().map(String::as_str),
            Some(TIMEZONE_PICKER_SYSTEM_DEFAULT)
        );
        assert_eq!(
            options.last().map(String::as_str),
            Some(TIMEZONE_PICKER_MANUAL_INPUT)
        );
    }

    #[test]
    fn test_timezone_picker_manual_input_enters_edit_mode() {
        let mut app = SetupApp::new();
        let timezone_idx = app
            .fields
            .iter()
            .position(|f| f.key == "OVERRIDE_TIMEZONE")
            .expect("OVERRIDE_TIMEZONE field missing");
        app.selected = timezone_idx;
        assert!(app.open_picker_for_selected());
        let manual_idx = app.timezone_picker_options().len().saturating_sub(1);
        if let Some(picker) = app.picker.as_mut() {
            picker.selected = manual_idx;
        }
        app.apply_picker_selection();
        assert!(app.editing);
        assert!(app.status.contains("manual input"));
    }

    #[test]
    fn test_clear_model_override_field_clears_related_llm_override_fields() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "telegram".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "TELEGRAM_MODEL") {
            field.value = "gpt-5".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_llm_provider_key())
        {
            field.value = "openai".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_llm_api_key_key())
        {
            field.value = "sk-123".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == telegram_llm_base_url_key())
        {
            field.value = "https://api.openai.com/v1".to_string();
        }

        app.selected = app
            .fields
            .iter()
            .position(|f| f.key == "TELEGRAM_MODEL")
            .expect("TELEGRAM_MODEL field missing");
        app.clear_selected_field();

        assert_eq!(app.field_value("TELEGRAM_MODEL"), "");
        assert_eq!(app.field_value(telegram_llm_provider_key()), "");
        assert_eq!(app.field_value(telegram_llm_api_key_key()), "");
        assert_eq!(app.field_value(telegram_llm_base_url_key()), "");
    }

    #[test]
    fn test_picker_selecting_main_clears_slot_provider_preset() {
        let mut app = SetupApp::new();
        // Set up a Telegram bot slot with a provider preset
        app.set_field_value(&telegram_slot_model_key(1), "nvidia".into());
        assert_eq!(app.field_value(&telegram_slot_model_key(1)), "nvidia");

        // Simulate opening the picker for this slot
        app.open_llm_override_page_for_field(&telegram_slot_model_key(1));

        // Simulate picker selecting "main (global default)" (index 0, value = "")
        app.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: telegram_slot_model_key(1),
            options: vec![
                ("main (global default)".to_string(), String::new()),
                ("nvidia - nvidia / meta/llama".to_string(), "nvidia".into()),
            ],
            selected: 0, // selecting "main"
        });
        app.apply_llm_override_picker_selection();

        // Field should be cleared
        assert_eq!(
            app.field_value(&telegram_slot_model_key(1)),
            "",
            "slot model key should be empty after selecting main"
        );
    }

    #[test]
    fn test_picker_selecting_main_clears_channel_provider_preset() {
        let mut app = SetupApp::new();
        // Set up channel-level override
        app.set_field_value("TELEGRAM_MODEL", "googlegemini".into());
        app.set_field_value(telegram_llm_provider_key(), "googlegemini".into());

        // Simulate picker selecting "main" for channel-level field
        app.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: "TELEGRAM_MODEL".to_string(),
            options: vec![
                ("main (global default)".to_string(), String::new()),
                (
                    "googlegemini - google / gemini-2.5-pro".to_string(),
                    "googlegemini".into(),
                ),
            ],
            selected: 0,
        });
        app.apply_llm_override_picker_selection();

        assert_eq!(
            app.field_value("TELEGRAM_MODEL"),
            "",
            "TELEGRAM_MODEL should be empty after selecting main"
        );
        assert_eq!(
            app.field_value(telegram_llm_provider_key()),
            "",
            "TELEGRAM_LLM_PROVIDER should also be cleared"
        );
    }

    #[test]
    fn test_picker_clearing_channel_also_clears_inherited_slot_values() {
        let mut app = SetupApp::new();
        // Simulate loading: channel has googlegemini, slot inherited the same
        app.set_field_value("TELEGRAM_MODEL", "googlegemini".into());
        app.set_field_value(telegram_llm_provider_key(), "googlegemini".into());
        app.set_field_value(&telegram_slot_model_key(1), "googlegemini".into());

        // User selects "main" on channel-level field
        app.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: "TELEGRAM_MODEL".to_string(),
            options: vec![
                ("main (global default)".to_string(), String::new()),
                (
                    "googlegemini - google / gemini-2.5-pro".to_string(),
                    "googlegemini".into(),
                ),
            ],
            selected: 0,
        });
        app.apply_llm_override_picker_selection();

        assert_eq!(app.field_value("TELEGRAM_MODEL"), "");
        assert_eq!(app.field_value(telegram_llm_provider_key()), "");
        // Slot that inherited the same value should also be cleared
        assert_eq!(
            app.field_value(&telegram_slot_model_key(1)),
            "",
            "slot with inherited channel value should be cleared"
        );
    }

    #[test]
    fn test_end_to_end_clear_bot_provider_preset_via_picker_and_save() {
        // Simulate loading a config where a Telegram bot has provider_preset: nvidia
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_e2e_clear_preset_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        // First create a config with provider_preset set
        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "telegram".into());
        values.insert(telegram_slot_id_key(1), "main".into());
        values.insert(telegram_slot_token_key(1), "tok123".into());
        values.insert(telegram_slot_username_key(1), "GoatBot".into());
        values.insert(telegram_slot_model_key(1), "nvidia".into());
        values.insert("TELEGRAM_MODEL".into(), "nvidia".into());
        values.insert(telegram_llm_provider_key().into(), "nvidia".into());
        values.insert("LLM_PROVIDER".into(), "openrouter".into());
        values.insert("LLM_API_KEY".into(), "sk-or-key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        // Verify it was written with provider_preset
        assert!(
            s.lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains("provider_preset")),
            "initial save should contain provider_preset"
        );

        // Now simulate user selecting "main" in the picker -> set slot model to empty
        values.insert(telegram_slot_model_key(1), String::new());
        values.insert("TELEGRAM_MODEL".into(), String::new());
        values.insert(telegram_llm_provider_key().into(), String::new());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        let has_active_preset = s
            .lines()
            .any(|line| !line.trim_start().starts_with('#') && line.contains("provider_preset"));
        assert!(
            !has_active_preset,
            "after clearing, provider_preset should not appear:\n{s}"
        );

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_provider_presets_include_synthetic_chutes_and_qwen_code() {
        assert!(find_provider_preset("synthetic").is_some());
        assert!(find_provider_preset("chutes").is_some());
        assert!(find_provider_preset("qwen-portal").is_some());
        assert!(find_provider_preset("aliyun-bailian").is_some());
        assert!(find_provider_preset("nvidia").is_some());
    }
}
