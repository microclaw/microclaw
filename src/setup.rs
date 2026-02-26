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
use ratatui::layout::{Constraint, Direction, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::codex_auth::{
    codex_config_default_openai_base_url, is_openai_codex_provider, provider_allows_empty_api_key,
    resolve_openai_codex_auth,
};
use crate::config::{Config, SandboxBackend, SandboxMode};
use microclaw_core::error::MicroClawError;
use microclaw_core::text::floor_char_boundary;

use crate::channels::{
    dingtalk, email, feishu, imessage, irc, matrix, nostr, qq, signal, slack, whatsapp,
};
use crate::setup_def::DynamicChannelDef;

// Declarative channel metadata is owned by each channel module.
const DYNAMIC_CHANNELS: &[DynamicChannelDef] = &[
    slack::SETUP_DEF,
    feishu::SETUP_DEF,
    irc::SETUP_DEF,
    matrix::SETUP_DEF,
    whatsapp::SETUP_DEF,
    imessage::SETUP_DEF,
    email::SETUP_DEF,
    nostr::SETUP_DEF,
    signal::SETUP_DEF,
    dingtalk::SETUP_DEF,
    qq::SETUP_DEF,
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

fn telegram_slot_allowed_user_ids_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ALLOWED_USER_IDS", slot)
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

fn default_data_dir_for_setup() -> String {
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
        id: "alibaba",
        label: "Alibaba Cloud (Qwen / DashScope)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
        models: &["qwen3-max", "qwen3-plus", "qwen-max-latest"],
    },
    ProviderPreset {
        id: "deepseek",
        label: "DeepSeek",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.deepseek.com/v1",
        models: &["deepseek-chat", "deepseek-reasoner", "deepseek-v3"],
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

fn provider_display(provider: &str) -> String {
    if let Some(preset) = find_provider_preset(provider) {
        format!("{} - {}", preset.id, preset.label)
    } else {
        format!("{provider} - custom")
    }
}

const MODEL_PICKER_MANUAL_INPUT: &str = "<Manual input...>";

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
}

#[derive(Clone)]
struct LlmOverridePage {
    title: String,
    model_key: String,
    provider_key: String,
    api_key_key: String,
    base_url_key: String,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum PickerKind {
    Provider,
    Model,
    Channels,
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
        let provider = existing
            .get("LLM_PROVIDER")
            .cloned()
            .unwrap_or_else(|| "anthropic".into());
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
                    label: "Telegram bot model override (optional)".into(),
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
                    value: existing.get("DISCORD_BOT_TOKEN").cloned().unwrap_or_default(),
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
                    label: "Discord bot model override (optional)".into(),
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
                    key: "TIMEZONE".into(),
                    label: "Timezone (IANA)".into(),
                    value: existing.get("TIMEZONE").cloned().unwrap_or_else(|| "UTC".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "WORKING_DIR".into(),
                    label: "Default working directory".into(),
                    value: existing
                        .get("WORKING_DIR")
                        .cloned()
                        .unwrap_or_else(default_working_dir_for_setup),
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
                    value: existing.get("EMBEDDING_PROVIDER").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "EMBEDDING_API_KEY".into(),
                    label: "Embedding API key (optional)".into(),
                    value: existing.get("EMBEDDING_API_KEY").cloned().unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: "EMBEDDING_BASE_URL".into(),
                    label: "Embedding base URL (optional)".into(),
                    value: existing.get("EMBEDDING_BASE_URL").cloned().unwrap_or_default(),
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
            visible_cache_sig: Cell::new(u64::MAX),
            visible_cache_indices: RefCell::new(Vec::new()),
            editing: false,
            picker: None,
            status:
                "Use ↑/↓/j/k/Ctrl+N/Ctrl+P to move, Enter to edit or choose list, F2 validate, s/Ctrl+S save, q quit"
                    .into(),
            completed: false,
            backup_path: None,
            completion_summary: Vec::new(),
            llm_override_page: None,
            llm_override_picker: None,
        };

        for slot in 1..=MAX_BOT_SLOTS {
            app.fields.push(Field {
                key: telegram_slot_id_key(slot),
                label: format!("Telegram bot #{slot} id"),
                value: existing
                    .get(&telegram_slot_id_key(slot))
                    .cloned()
                    .unwrap_or_else(|| default_slot_account_id(slot)),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_enabled_key(slot),
                label: format!("Telegram bot #{slot} enabled (true/false)"),
                value: existing
                    .get(&telegram_slot_enabled_key(slot))
                    .cloned()
                    .unwrap_or_else(|| "true".to_string()),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_token_key(slot),
                label: format!("Telegram bot #{slot} token"),
                value: existing
                    .get(&telegram_slot_token_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: true,
            });
            app.fields.push(Field {
                key: telegram_slot_username_key(slot),
                label: format!("Telegram bot #{slot} username (no @)"),
                value: existing
                    .get(&telegram_slot_username_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_model_key(slot),
                label: format!("Telegram bot #{slot} model override (optional)"),
                value: existing
                    .get(&telegram_slot_model_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_allowed_user_ids_key(slot),
                label: format!("Telegram bot #{slot} allowed user ids (csv/array, optional)"),
                value: existing
                    .get(&telegram_slot_allowed_user_ids_key(slot))
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
                    label: format!("{} bot #{slot} id", ch.name),
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
                    label: format!("{} bot #{slot} enabled (true/false)", ch.name),
                    value: existing
                        .get(&dynamic_slot_enabled_field_key(ch.name, slot))
                        .cloned()
                        .unwrap_or_else(|| "true".to_string()),
                    required: false,
                    secret: false,
                });
                for f in ch.fields {
                    app.fields.push(Field {
                        key: dynamic_slot_field_key(ch.name, slot, f.yaml_key),
                        label: format!("{} bot #{slot}: {}", ch.name, f.label),
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
                                "{} bot #{slot} LLM provider override (optional)",
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
                                "{} bot #{slot} LLM API key override (optional)",
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
                                "{} bot #{slot} LLM base URL override (optional)",
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
        let yaml_path = if Path::new("./microclaw.config.yaml").exists() {
            Some("./microclaw.config.yaml")
        } else if Path::new("./microclaw.config.yml").exists() {
            Some("./microclaw.config.yml")
        } else {
            None
        };

        if let Some(path) = yaml_path {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(config) = serde_yaml::from_str::<crate::config::Config>(&content) {
                    let mut map = HashMap::new();
                    let mut enabled = Vec::new();
                    for channel in Self::channel_options() {
                        if config.channel_enabled(channel) {
                            enabled.push(channel.to_string());
                        }
                    }
                    map.insert("ENABLED_CHANNELS".into(), enabled.join(","));
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
                    let telegram_model = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("model")
                                .and_then(|v| {
                                    v.as_str()
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                        .map(ToOwned::to_owned)
                                })
                                .or_else(|| channel_default_account_str_value(ch_cfg, "model"))
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
                    let telegram_llm_provider = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("llm_provider"))
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
                    let discord_model = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| {
                            channel_default_account_str_value(ch_cfg, "model").or_else(|| {
                                ch_cfg
                                    .get("model")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|v| !v.is_empty())
                                    .map(ToOwned::to_owned)
                            })
                        })
                        .unwrap_or_default();
                    let discord_llm_provider = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| ch_cfg.get("llm_provider"))
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
                    map.insert("TELEGRAM_MODEL".into(), telegram_model.clone());
                    map.insert(
                        telegram_allowed_user_ids_key().into(),
                        telegram_allowed_user_ids.clone(),
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
                                        .get("model")
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(telegram_slot_model_key(slot), v.to_string());
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
                    if map
                        .get(&telegram_slot_model_key(1))
                        .map(|v| v.trim().is_empty())
                        .unwrap_or(true)
                        && !telegram_model.trim().is_empty()
                    {
                        map.insert(telegram_slot_model_key(1), telegram_model.clone());
                    }
                    map.insert("DISCORD_BOT_TOKEN".into(), discord_bot_token);
                    map.insert("DISCORD_ACCOUNT_ID".into(), discord_account_id);
                    map.insert("DISCORD_MODEL".into(), discord_model);
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
                                                    v.as_bool().map(|b| b.to_string())
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
                                        .and_then(|a| a.get("llm_provider"))
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
                                                v.as_bool().map(|b| b.to_string())
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
                    map.insert("DATA_DIR".into(), config.data_dir);
                    map.insert("TIMEZONE".into(), config.timezone);
                    map.insert("WORKING_DIR".into(), config.working_dir);
                    map.insert(
                        "SANDBOX_ENABLED".into(),
                        (config.sandbox.mode == crate::config::SandboxMode::All).to_string(),
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
        self.adjust_field_scroll(UI_FIELD_WINDOW);
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
        self.adjust_field_scroll(UI_FIELD_WINDOW);
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

    fn set_field_value(&mut self, key: &str, value: String) {
        if let Some(field) = self.fields.iter_mut().find(|f| f.key == key) {
            field.value = value;
        }
    }

    fn llm_override_label_for_key(key: &str) -> &'static str {
        match key {
            "TELEGRAM_LLM_PROVIDER" => "Provider (optional)",
            "TELEGRAM_LLM_API_KEY" => "API key (optional)",
            "TELEGRAM_LLM_BASE_URL" => "Base URL (optional)",
            "DISCORD_LLM_PROVIDER" => "Provider (optional)",
            "DISCORD_LLM_API_KEY" => "API key (optional)",
            "DISCORD_LLM_BASE_URL" => "Base URL (optional)",
            "TELEGRAM_MODEL" => "Model (optional)",
            "DISCORD_MODEL" => "Model (optional)",
            _ if key.ends_with("_LLM_PROVIDER") => "Provider (optional)",
            _ if key.ends_with("_LLM_API_KEY") => "API key (optional)",
            _ if key.ends_with("_LLM_BASE_URL") => "Base URL (optional)",
            _ if key.ends_with("_MODEL") => "Model (optional)",
            _ => "Value",
        }
    }

    fn open_llm_override_page(
        &mut self,
        title: String,
        model_key: String,
        provider_key: String,
        api_key_key: String,
        base_url_key: String,
    ) {
        self.llm_override_page = Some(LlmOverridePage {
            title,
            model_key,
            provider_key,
            api_key_key,
            base_url_key,
            selected: 0,
            editing: false,
        });
        self.status = "Editing channel LLM overrides".to_string();
    }

    fn open_llm_override_provider_picker(&mut self) {
        let Some(page) = self.llm_override_page.as_ref() else {
            return;
        };
        let current = self.field_value(&page.provider_key);
        let mut options = Vec::new();
        for preset in PROVIDER_PRESETS {
            options.push((
                format!("{} - {}", preset.id, preset.label),
                preset.id.to_string(),
            ));
        }
        let selected = options
            .iter()
            .position(|(_, value)| value.eq_ignore_ascii_case(&current))
            .unwrap_or(0);
        self.llm_override_picker = Some(LlmOverridePicker {
            title: "Select Provider".to_string(),
            target_key: page.provider_key.clone(),
            options,
            selected,
        });
    }

    fn open_llm_override_model_picker(&mut self) {
        let Some(page) = self.llm_override_page.as_ref() else {
            return;
        };
        let provider = self.field_value(&page.provider_key);
        let Some(preset) = find_provider_preset(&provider) else {
            if let Some(page_mut) = self.llm_override_page.as_mut() {
                page_mut.editing = true;
            }
            self.status = "Unknown provider; switched to manual model input".to_string();
            return;
        };
        if preset.models.is_empty() {
            if let Some(page_mut) = self.llm_override_page.as_mut() {
                page_mut.editing = true;
            }
            self.status = "No preset models; switched to manual model input".to_string();
            return;
        }
        let current = self.field_value(&page.model_key);
        let mut options = preset
            .models
            .iter()
            .map(|m| ((*m).to_string(), (*m).to_string()))
            .collect::<Vec<_>>();
        options.push((
            MODEL_PICKER_MANUAL_INPUT.to_string(),
            MODEL_PICKER_MANUAL_INPUT.to_string(),
        ));
        let selected = options
            .iter()
            .position(|(_, value)| value == &current)
            .unwrap_or(options.len().saturating_sub(1));
        self.llm_override_picker = Some(LlmOverridePicker {
            title: format!("Select Model ({provider})"),
            target_key: page.model_key.clone(),
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
        if value == MODEL_PICKER_MANUAL_INPUT {
            if let Some(page) = self.llm_override_page.as_mut() {
                page.editing = true;
                page.selected = 3;
            }
            self.status = "Editing model (manual input)".to_string();
            return;
        }
        self.set_field_value(&picker.target_key, value.clone());
        self.status = format!("Updated {}", picker.target_key);
    }

    fn llm_override_keys_for_page(page: &LlmOverridePage) -> [&str; 4] {
        [
            page.provider_key.as_str(),
            page.api_key_key.as_str(),
            page.base_url_key.as_str(),
            page.model_key.as_str(),
        ]
    }

    fn open_llm_override_page_for_field(&mut self, field_key: &str) -> bool {
        if field_key == "TELEGRAM_MODEL" {
            self.open_llm_override_page(
                "Telegram Channel LLM Override".to_string(),
                "TELEGRAM_MODEL".to_string(),
                telegram_llm_provider_key().to_string(),
                telegram_llm_api_key_key().to_string(),
                telegram_llm_base_url_key().to_string(),
            );
            return true;
        }
        if field_key == "DISCORD_MODEL" {
            self.open_llm_override_page(
                "Discord Channel LLM Override".to_string(),
                "DISCORD_MODEL".to_string(),
                discord_llm_provider_key().to_string(),
                discord_llm_api_key_key().to_string(),
                discord_llm_base_url_key().to_string(),
            );
            return true;
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let model_key = dynamic_slot_field_key(ch.name, slot, "model");
                if field_key == model_key {
                    self.open_llm_override_page(
                        format!("{} bot #{slot} LLM Override", ch.name),
                        model_key,
                        dynamic_slot_llm_provider_key(ch.name, slot),
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
            return Some(telegram_llm_provider_key().to_string());
        }
        if field_key == "DISCORD_MODEL" {
            return Some(discord_llm_provider_key().to_string());
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                if field_key == dynamic_slot_field_key(ch.name, slot, "model") {
                    return Some(dynamic_slot_llm_provider_key(ch.name, slot));
                }
            }
        }
        None
    }

    fn llm_override_related_keys_for_model_field(field_key: &str) -> Option<[String; 4]> {
        if field_key == "TELEGRAM_MODEL" {
            return Some([
                telegram_llm_provider_key().to_string(),
                telegram_llm_api_key_key().to_string(),
                telegram_llm_base_url_key().to_string(),
                "TELEGRAM_MODEL".to_string(),
            ]);
        }
        if field_key == "DISCORD_MODEL" {
            return Some([
                discord_llm_provider_key().to_string(),
                discord_llm_api_key_key().to_string(),
                discord_llm_base_url_key().to_string(),
                "DISCORD_MODEL".to_string(),
            ]);
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let model_key = dynamic_slot_field_key(ch.name, slot, "model");
                if field_key == model_key {
                    return Some([
                        dynamic_slot_llm_provider_key(ch.name, slot),
                        dynamic_slot_llm_api_key_key(ch.name, slot),
                        dynamic_slot_llm_base_url_key(ch.name, slot),
                        model_key,
                    ]);
                }
            }
        }
        None
    }

    fn to_env_map(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for field in &self.fields {
            if !field.value.trim().is_empty() {
                out.insert(field.key.to_string(), field.value.trim().to_string());
            }
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
            let allowed_user_ids_raw = self.field_value(&telegram_slot_allowed_user_ids_key(slot));
            let allowed_user_ids = parse_i64_list_field(
                &allowed_user_ids_raw,
                &telegram_slot_allowed_user_ids_key(slot),
            )?;
            let enabled = parse_boolish(&self.field_value(&telegram_slot_enabled_key(slot)), true)?;
            let has_any = !token.is_empty()
                || !username.is_empty()
                || !model.is_empty()
                || !allowed_user_ids.is_empty();
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
            "TELEGRAM_MODEL" | "TELEGRAM_ALLOWED_USER_IDS" => self.channel_enabled("telegram"),
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
                        || key == telegram_slot_allowed_user_ids_key(slot)
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
        self.adjust_field_scroll(UI_FIELD_WINDOW);
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
        if sel_pos < self.field_scroll {
            self.field_scroll = sel_pos;
        } else if sel_pos >= self.field_scroll.saturating_add(window) {
            self.field_scroll = sel_pos.saturating_sub(window.saturating_sub(1));
        }
        let max_start = visible.len().saturating_sub(window);
        if self.field_scroll > max_start {
            self.field_scroll = max_start;
        }
    }

    fn page_down(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        let step = window.max(1);
        let max_start = visible.len().saturating_sub(step);
        self.field_scroll = (self.field_scroll + step).min(max_start);
        let target = (self.field_scroll + step.saturating_sub(1)).min(visible.len() - 1);
        self.selected = visible[target];
    }

    fn page_up(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        let step = window.max(1);
        self.field_scroll = self.field_scroll.saturating_sub(step);
        self.selected = visible[self.field_scroll];
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

        if self.channel_enabled("telegram") {
            let _ = parse_bot_count(
                &self.field_value(telegram_bot_count_key()),
                telegram_bot_count_key(),
            )?;
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
                let bot_count_key = dynamic_bot_count_field_key(ch.name);
                let bot_count = parse_bot_count(&self.field_value(&bot_count_key), &bot_count_key)?;
                let mut seen_any = false;
                for slot in 1..=bot_count {
                    let id_key = dynamic_slot_id_field_key(ch.name, slot);
                    let id_raw = self.field_value(&id_key);
                    let has_any = ch.fields.iter().any(|f| {
                        !self
                            .field_value(&dynamic_slot_field_key(ch.name, slot, f.yaml_key))
                            .is_empty()
                    });
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
                        let topic_key = dynamic_slot_field_key(ch.name, slot, "topic_mode");
                        let topic_raw = self.field_value(&topic_key);
                        let topic_mode = if topic_raw.trim().is_empty() {
                            false
                        } else {
                            parse_boolish(&topic_raw, false).map_err(|_| {
                                MicroClawError::Config(format!(
                                    "{} must be true/false (or 1/0)",
                                    topic_key
                                ))
                            })?
                        };
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
                        if self.field_value(&key).is_empty() {
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
        }

        let timezone = self.field_value("TIMEZONE");
        let tz = if timezone.is_empty() {
            "UTC".to_string()
        } else {
            timezone
        };
        tz.parse::<chrono_tz::Tz>()
            .map_err(|_| MicroClawError::Config(format!("Invalid TIMEZONE: {tz}")))?;

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
        } else {
            (self.field_value("LLM_API_KEY"), None)
        };
        let base_url = self.field_value("LLM_BASE_URL");
        let model = self.field_value("LLM_MODEL");
        std::thread::spawn(move || {
            perform_online_validation(
                tg_enabled,
                &tg_token,
                &env_username,
                &provider,
                &api_key,
                &base_url,
                &model,
                codex_account_id.as_deref(),
            )
        })
        .join()
        .map_err(|_| MicroClawError::Config("Validation thread panicked".into()))?
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

    fn open_picker_for_selected(&mut self) -> bool {
        match self.selected_field().key.as_str() {
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
            _ => false,
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
            | "TELEGRAM_MODEL"
            | "TELEGRAM_ALLOWED_USER_IDS"
            | "TELEGRAM_LLM_PROVIDER"
            | "TELEGRAM_LLM_API_KEY"
            | "TELEGRAM_LLM_BASE_URL"
            | "DISCORD_BOT_TOKEN"
            | "DISCORD_MODEL"
            | "DISCORD_ACCOUNTS_JSON"
            | "LLM_API_KEY" => String::new(),
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
            "DATA_DIR" => default_data_dir_for_setup(),
            "TIMEZONE" => "UTC".into(),
            "WORKING_DIR" => default_working_dir_for_setup(),
            "SANDBOX_ENABLED" => "false".into(),
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
            "DATA_DIR" | "TIMEZONE" | "WORKING_DIR" => "App",
            "SANDBOX_ENABLED" => "Sandbox",
            "REFLECTOR_ENABLED" | "REFLECTOR_INTERVAL_MINS" | "MEMORY_TOKEN_BUDGET" => "Memory",
            "LLM_PROVIDER" | "LLM_API_KEY" | "LLM_MODEL" | "LLM_BASE_URL" => "Model",
            "EMBEDDING_PROVIDER" | "EMBEDDING_API_KEY" | "EMBEDDING_BASE_URL"
            | "EMBEDDING_MODEL" | "EMBEDDING_DIM" => "Embedding",
            "ENABLED_CHANNELS"
            | "TELEGRAM_BOT_TOKEN"
            | "BOT_USERNAME"
            | "TELEGRAM_ACCOUNT_ID"
            | "TELEGRAM_MODEL"
            | "TELEGRAM_ALLOWED_USER_IDS"
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

    fn field_display_order(key: &str) -> usize {
        const ORDER_MODEL_BASE: usize = 0;
        const ORDER_CHANNEL_BASE: usize = 100;
        const ORDER_APP_BASE: usize = 20_000;
        const ORDER_MEMORY_BASE: usize = 21_000;
        const ORDER_EMBED_BASE: usize = 22_000;
        const ORDER_SANDBOX_BASE: usize = 23_000;

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
                    for (field_idx, f) in ch.fields.iter().enumerate() {
                        if key == dynamic_slot_field_key(ch.name, slot, f.yaml_key) {
                            return slot_base + 3 + field_idx;
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
            // 2) Channel (dynamic channel fields are placed in the branch above)
            "ENABLED_CHANNELS" => ORDER_CHANNEL_BASE,
            "TELEGRAM_BOT_TOKEN" => ORDER_CHANNEL_BASE + 1,
            "BOT_USERNAME" => ORDER_CHANNEL_BASE + 2,
            "TELEGRAM_ACCOUNT_ID" => ORDER_CHANNEL_BASE + 3,
            _ if key == telegram_bot_count_key() => ORDER_CHANNEL_BASE + 5,
            "TELEGRAM_MODEL" => ORDER_CHANNEL_BASE + 6,
            "TELEGRAM_ALLOWED_USER_IDS" => ORDER_CHANNEL_BASE + 7,
            "TELEGRAM_LLM_PROVIDER" => ORDER_CHANNEL_BASE + 8,
            "TELEGRAM_LLM_API_KEY" => ORDER_CHANNEL_BASE + 9,
            "TELEGRAM_LLM_BASE_URL" => ORDER_CHANNEL_BASE + 10,
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
                    if key == telegram_slot_allowed_user_ids_key(slot) {
                        return base + 6;
                    }
                }
                usize::MAX
            }
            // 3) App
            "DATA_DIR" => ORDER_APP_BASE,
            "TIMEZONE" => ORDER_APP_BASE + 1,
            "WORKING_DIR" => ORDER_APP_BASE + 2,
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
            // 6) Sandbox (last)
            "SANDBOX_ENABLED" => ORDER_SANDBOX_BASE,
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
    tg_token: &str,
    env_username: &str,
    provider: &str,
    api_key: &str,
    base_url: &str,
    model: &str,
    codex_account_id: Option<&str>,
) -> Result<Vec<String>, MicroClawError> {
    const VALIDATION_MAX_OUTPUT_TOKENS: u32 = 64;
    let mut checks = Vec::new();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
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
        checks.push("Telegram skipped (disabled)".into());
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
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
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
    fs::create_dir_all(&backup_dir)?;
    let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let backup_path = backup_dir.join(format!("{file_name}.bak.{ts}"));
    fs::copy(path, &backup_path)?;
    let _ = prune_old_config_backups(&backup_dir, file_name, MAX_CONFIG_BACKUPS);
    Ok(Some(backup_path.display().to_string()))
}

fn save_config_yaml(
    path: &Path,
    values: &HashMap<String, String>,
) -> Result<Option<String>, MicroClawError> {
    let backup = create_config_backup(path)?;

    let get = |key: &str| values.get(key).cloned().unwrap_or_default();

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
    let telegram_model = if !get("TELEGRAM_MODEL").trim().is_empty() {
        get("TELEGRAM_MODEL")
    } else {
        get(&telegram_slot_model_key(1))
    };
    let telegram_llm_provider = get(telegram_llm_provider_key());
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
        let model = get(&telegram_slot_model_key(slot));
        let allowed_user_ids_raw = get(&telegram_slot_allowed_user_ids_key(slot));
        let allowed_user_ids = parse_i64_list_field(
            &allowed_user_ids_raw,
            &telegram_slot_allowed_user_ids_key(slot),
        )?;
        let enabled = parse_boolish(&get(&telegram_slot_enabled_key(slot)), true)?;
        let has_any = !token.trim().is_empty()
            || !username.trim().is_empty()
            || !model.trim().is_empty()
            || !allowed_user_ids.is_empty();
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
        if !model.trim().is_empty() {
            account.insert(
                "model".into(),
                serde_json::Value::String(model.trim().to_string()),
            );
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
    let discord_model = get("DISCORD_MODEL");
    let discord_llm_provider = get(discord_llm_provider_key());
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
        || !telegram_llm_provider.trim().is_empty()
        || !telegram_llm_api_key.trim().is_empty()
        || !telegram_llm_base_url.trim().is_empty()
        || !telegram_model.trim().is_empty()
        || !telegram_channel_allowed_user_ids.is_empty()
        || telegram_accounts
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        || telegram_bot_count > 1;
    let discord_present = !discord_token.trim().is_empty()
        || !discord_llm_provider.trim().is_empty()
        || !discord_llm_api_key.trim().is_empty()
        || !discord_llm_base_url.trim().is_empty()
        || !discord_model.trim().is_empty()
        || discord_accounts
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
    // Use slot presence keys so optional defaults do not create disabled blocks unexpectedly.
    let dynamic_channel_include: Vec<(&DynamicChannelDef, bool)> = DYNAMIC_CHANNELS
        .iter()
        .map(|ch| {
            let selected = channel_selected(ch.name);
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
                }) || !get(&dynamic_slot_llm_provider_key(ch.name, slot))
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

    if channel_selected("telegram") || telegram_present {
        yaml.push_str("  telegram:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("telegram")));
        if !telegram_llm_provider.trim().is_empty() {
            yaml.push_str(&format!(
                "    llm_provider: \"{}\"\n",
                telegram_llm_provider.trim()
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
        if !telegram_model.trim().is_empty() {
            yaml.push_str(&format!("    model: \"{}\"\n", telegram_model.trim()));
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
            // Per-account model is still driven by slot fields; channel-level model is emitted above.
        }
    }
    if channel_selected("discord") || discord_present {
        yaml.push_str("  discord:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("discord")));
        if !discord_llm_provider.trim().is_empty() {
            yaml.push_str(&format!(
                "    llm_provider: \"{}\"\n",
                discord_llm_provider.trim()
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
        if !discord_model.trim().is_empty() {
            yaml.push_str(&format!("    model: \"{}\"\n", discord_model.trim()));
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
        let bot_count_key = dynamic_bot_count_field_key(ch.name);
        let bot_count = parse_bot_count(&get(&bot_count_key), &bot_count_key)?;
        let mut accounts_map = serde_json::Map::new();
        for slot in 1..=bot_count {
            let id = get(&dynamic_slot_id_field_key(ch.name, slot));
            let enabled =
                parse_boolish(&get(&dynamic_slot_enabled_field_key(ch.name, slot)), true)?;
            let has_any = ch.fields.iter().any(|f| {
                !get(&dynamic_slot_field_key(ch.name, slot, f.yaml_key))
                    .trim()
                    .is_empty()
            });
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
                let v = get(&dynamic_slot_field_key(ch.name, slot, f.yaml_key));
                if v.trim().is_empty() {
                    continue;
                }
                if f.yaml_key == "topic_mode" {
                    let parsed = parse_boolish(v.trim(), false).map_err(|_| {
                        MicroClawError::Config(format!(
                            "{} must be true/false (or 1/0)",
                            dynamic_slot_field_key(ch.name, slot, f.yaml_key)
                        ))
                    })?;
                    account.insert(f.yaml_key.to_string(), serde_json::Value::Bool(parsed));
                } else {
                    account.insert(
                        f.yaml_key.to_string(),
                        serde_json::Value::String(v.trim().to_string()),
                    );
                }
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
            if !llm_provider.trim().is_empty() {
                account.insert(
                    "llm_provider".into(),
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
    yaml.push('\n');

    yaml.push_str(
        "# LLM provider (anthropic, openai-codex, ollama, openai, openrouter, deepseek, google, etc.)\n",
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
    yaml.push_str("# OpenAI-compatible request body overrides (optional)\n");
    yaml.push_str("# Use null to unset a default key for selected provider/model.\n");
    yaml.push_str("# openai_compat_body_overrides: { temperature: 0.2 }\n");
    yaml.push_str("# openai_compat_body_overrides_by_provider:\n");
    yaml.push_str("#   deepseek: { top_p: null, reasoning_effort: \"high\" }\n");
    yaml.push_str("# openai_compat_body_overrides_by_model:\n");
    yaml.push_str("#   gpt-5.2: { response_format: { type: \"json_object\" } }\n");

    yaml.push('\n');
    let data_dir = values
        .get("DATA_DIR")
        .cloned()
        .unwrap_or_else(default_data_dir_for_setup);
    yaml.push_str(&format!("data_dir: \"{}\"\n", data_dir));
    let tz = values
        .get("TIMEZONE")
        .cloned()
        .unwrap_or_else(|| "UTC".into());
    yaml.push_str(&format!("timezone: \"{}\"\n", tz));
    let working_dir = values
        .get("WORKING_DIR")
        .cloned()
        .unwrap_or_else(default_working_dir_for_setup);
    yaml.push_str(&format!("working_dir: \"{}\"\n", working_dir));
    yaml.push_str("high_risk_tool_user_confirmation_required: true\n");
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

    fs::write(path, yaml)?;
    Ok(backup)
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
            Constraint::Length(4),
            Constraint::Min(14),
            Constraint::Length(3),
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
    let window_fields = left_inner.height.saturating_sub(2) as usize;
    let start = app
        .field_scroll
        .min(visible_indices.len().saturating_sub(window_fields.max(1)));
    let end = (start + window_fields.max(1)).min(visible_indices.len());
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
            let model = app.field_value(&f.key);
            if provider.is_empty() && model.is_empty() {
                String::new()
            } else if provider.is_empty() {
                model
            } else if model.is_empty() {
                format!("provider={provider}")
            } else {
                format!("provider={provider}, model={model}")
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
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} {}: ", prefix, label),
                Style::default().fg(color),
            ),
            Span::styled(value, Style::default().fg(Color::Green)),
        ]));
    }
    if end < visible_indices.len() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("… more fields below ({}/{})", end, visible_indices.len()),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let body = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Fields"))
        .wrap(Wrap { trim: false });
    frame.render_widget(body, left_inner);

    let field = app.selected_field();
    let help = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Key: ", Style::default().fg(Color::DarkGray)),
            Span::styled(field.key.clone(), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled("Required: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if app.is_field_required(field) {
                "yes"
            } else {
                "no"
            }),
        ]),
        Line::from(vec![
            Span::styled("Editing: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if app.editing { "active" } else { "idle" }),
        ]),
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
        Line::from("• PgUp/PgDn: scroll field list"),
        Line::from("• ←/→ on provider/model: rotate presets"),
        Line::from("• e: force manual text edit"),
        Line::from("• Ctrl+D / Del: clear field"),
        Line::from("• Ctrl+R: restore field default"),
        Line::from("• F2: validate + online checks"),
        Line::from("• s / Ctrl+S: save with online validation"),
        Line::from("• Ctrl+Shift+S: save without online model validation"),
    ])
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

    if let Some(page) = &app.llm_override_page {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        if let Some(picker) = &app.llm_override_picker {
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
        } else {
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
    let backup = match run_with_spinner(
        terminal,
        app,
        "Saving (3/3): writing microclaw.config.yaml",
        move || save_config_yaml(Path::new("microclaw.config.yaml"), &values),
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    app.backup_path = backup;
    app.completion_summary = checks;
    app.status = "Saved microclaw.config.yaml".into();
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
    let backup = match run_with_spinner(
        terminal,
        app,
        "Saving (2/2): writing microclaw.config.yaml",
        move || save_config_yaml(Path::new("microclaw.config.yaml"), &values),
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    app.backup_path = backup;
    app.completion_summary = vec!["Online/model validation skipped by user".to_string()];
    app.status = "Saved microclaw.config.yaml (online validation skipped)".into();
    app.completed = true;
    Ok(())
}

fn run_wizard(mut terminal: DefaultTerminal) -> Result<bool, MicroClawError> {
    let mut app = SetupApp::new();

    loop {
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

            if app.llm_override_page.is_some() {
                let keys: [String; 4] = if let Some(page) = app.llm_override_page.as_ref() {
                    [
                        page.provider_key.clone(),
                        page.api_key_key.clone(),
                        page.base_url_key.clone(),
                        page.model_key.clone(),
                    ]
                } else {
                    [String::new(), String::new(), String::new(), String::new()]
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
                        let (selected_key, provider_key, model_key, editing) =
                            if let Some(page) = app.llm_override_page.as_ref() {
                                (
                                    keys[page.selected].clone(),
                                    page.provider_key.clone(),
                                    page.model_key.clone(),
                                    page.editing,
                                )
                            } else {
                                (String::new(), String::new(), String::new(), false)
                            };
                        if editing {
                            if let Some(page) = app.llm_override_page.as_mut() {
                                page.editing = false;
                            }
                            app.status = "Updated channel LLM override field".into();
                        } else if selected_key == provider_key {
                            app.open_llm_override_provider_picker();
                        } else if selected_key == model_key {
                            app.open_llm_override_model_picker();
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
                            let key_name = &keys[selected];
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
                            let key_name = &keys[selected];
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
                            let key_name = &keys[selected];
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
                KeyCode::PageDown => app.page_down(UI_FIELD_WINDOW),
                KeyCode::PageUp => app.page_up(UI_FIELD_WINDOW),
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
                    app.editing = true;
                    app.status = format!("Editing {}", app.selected_field().key);
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
                    if key.modifiers.contains(KeyModifiers::SHIFT) || key.code == KeyCode::Char('S')
                    {
                        try_save_skip_online(&mut terminal, &mut app)?;
                    } else {
                        try_save(&mut terminal, &mut app)?;
                    }
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
    cfg.sandbox.mode = SandboxMode::All;
    cfg.sandbox.backend = SandboxBackend::Auto;
    cfg.sandbox.no_network = true;
    cfg.sandbox.require_runtime = false;
    cfg.save_yaml(&path.to_string_lossy())?;
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
        assert!(s.contains("  web:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("llm_provider: \"anthropic\""));
        assert!(s.contains("api_key: \"key\""));
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
            "DISCORD_BOT_TOKEN".to_string(),
            "DISCORD_ACCOUNT_ID".to_string(),
            dynamic_bot_count_field_key("feishu"),
            dynamic_slot_id_field_key("feishu", 1),
            dynamic_slot_field_key("feishu", 1, "app_id"),
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            dynamic_slot_field_key("feishu", 1, "domain"),
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
            dynamic_bot_count_field_key("feishu"),
            dynamic_slot_id_field_key("feishu", 1),
            dynamic_slot_field_key("feishu", 1, "app_id"),
            dynamic_slot_field_key("feishu", 1, "app_secret"),
            dynamic_slot_field_key("feishu", 1, "domain"),
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
}
