use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

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
    editing: bool,
    picker: Option<PickerState>,
    status: String,
    completed: bool,
    backup_path: Option<String>,
    completion_summary: Vec<String>,
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
                    key: "TELEGRAM_BOT_TOKEN".into(),
                    label: "Telegram bot token".into(),
                    value: existing.get("TELEGRAM_BOT_TOKEN").cloned().unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: "BOT_USERNAME".into(),
                    label: "Telegram username (no @)".into(),
                    value: existing.get("BOT_USERNAME").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "TELEGRAM_ACCOUNT_ID".into(),
                    label: "Telegram default account id".into(),
                    value: existing
                        .get("TELEGRAM_ACCOUNT_ID")
                        .cloned()
                        .unwrap_or_else(|| default_account_id().to_string()),
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
            editing: false,
            picker: None,
            status:
                "Use ↑/↓ select field, Enter to edit or choose list, F2 validate, s/Ctrl+S save, q quit"
                    .into(),
            completed: false,
            backup_path: None,
            completion_summary: Vec::new(),
        };

        // Generate fields for dynamic channels (slack, feishu, etc.)
        for ch in DYNAMIC_CHANNELS {
            let account_key = dynamic_account_id_field_key(ch.name);
            let account_value = existing
                .get(&account_key)
                .cloned()
                .unwrap_or_else(|| default_account_id().to_string());
            app.fields.push(Field {
                key: account_key,
                label: format!("{} default account id", ch.name),
                value: account_value,
                required: false,
                secret: false,
            });
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
                    map.insert("TELEGRAM_BOT_TOKEN".into(), telegram_bot_token);
                    map.insert("TELEGRAM_ACCOUNT_ID".into(), telegram_account_id);
                    map.insert("TELEGRAM_MODEL".into(), telegram_model);
                    map.insert("BOT_USERNAME".into(), bot_username);
                    map.insert("DISCORD_BOT_TOKEN".into(), discord_bot_token);
                    map.insert("DISCORD_ACCOUNT_ID".into(), discord_account_id);
                    map.insert("DISCORD_MODEL".into(), discord_model);
                    // Extract dynamic channel configs
                    for ch in DYNAMIC_CHANNELS {
                        if let Some(ch_map) = config.channels.get(ch.name) {
                            let account_key = dynamic_account_id_field_key(ch.name);
                            let account_id = resolve_channel_default_account_id(ch_map)
                                .unwrap_or_else(|| default_account_id().to_string());
                            map.insert(account_key, account_id);
                            for f in ch.fields {
                                let value = channel_default_account_str_value(ch_map, f.yaml_key)
                                    .or_else(|| {
                                        ch_map
                                            .get(f.yaml_key)
                                            .and_then(|v| v.as_str())
                                            .map(str::trim)
                                            .filter(|v| !v.is_empty())
                                            .map(ToOwned::to_owned)
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

    fn dynamic_field_channel(key: &str) -> Option<&'static str> {
        for ch in DYNAMIC_CHANNELS {
            if key == dynamic_account_id_field_key(ch.name) {
                return Some(ch.name);
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
            "TELEGRAM_BOT_TOKEN" | "BOT_USERNAME" | "TELEGRAM_ACCOUNT_ID" | "TELEGRAM_MODEL" => {
                self.channel_enabled("telegram")
            }
            "DISCORD_BOT_TOKEN" | "DISCORD_ACCOUNT_ID" | "DISCORD_MODEL" => {
                self.channel_enabled("discord")
            }
            _ => Self::dynamic_field_channel(key)
                .map(|ch| self.channel_enabled(ch))
                .unwrap_or(true),
        }
    }

    fn visible_field_indices(&self) -> Vec<usize> {
        self.fields
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| {
                if self.is_field_visible(&field.key) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
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
            let account_id = account_id_from_value(&self.field_value("TELEGRAM_ACCOUNT_ID"));
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(
                    "TELEGRAM_ACCOUNT_ID must use only letters, numbers, '_' or '-'".into(),
                ));
            }
            if self.field_value("TELEGRAM_BOT_TOKEN").is_empty() {
                return Err(MicroClawError::Config(
                    "TELEGRAM_BOT_TOKEN is required when telegram is enabled".into(),
                ));
            }
            let username = self.field_value("BOT_USERNAME");
            if username.is_empty() {
                return Err(MicroClawError::Config(
                    "BOT_USERNAME is required when telegram is enabled".into(),
                ));
            }
            if username.starts_with('@') {
                return Err(MicroClawError::Config(
                    "BOT_USERNAME should not include '@'".into(),
                ));
            }
        }

        if self.channel_enabled("discord") {
            let account_id = account_id_from_value(&self.field_value("DISCORD_ACCOUNT_ID"));
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(
                    "DISCORD_ACCOUNT_ID must use only letters, numbers, '_' or '-'".into(),
                ));
            }
        }

        for ch in DYNAMIC_CHANNELS {
            if self.channel_enabled(ch.name) {
                let account_key = dynamic_account_id_field_key(ch.name);
                let account_id = account_id_from_value(&self.field_value(&account_key));
                if !is_valid_account_id(&account_id) {
                    return Err(MicroClawError::Config(format!(
                        "{} must use only letters, numbers, '_' or '-'",
                        account_key
                    )));
                }
                for f in ch.fields {
                    if f.required {
                        let key = dynamic_field_key(ch.name, f.yaml_key);
                        if self.field_value(&key).is_empty() {
                            return Err(MicroClawError::Config(format!(
                                "{} is required when {} is enabled",
                                key, ch.name
                            )));
                        }
                    }
                }
            }
        }

        if self.channel_enabled("discord") && self.field_value("DISCORD_BOT_TOKEN").is_empty() {
            return Err(MicroClawError::Config(
                "DISCORD_BOT_TOKEN is required when discord is enabled".into(),
            ));
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
        let tg_token = self.field_value("TELEGRAM_BOT_TOKEN");
        let env_username = self
            .field_value("BOT_USERNAME")
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
            "TELEGRAM_BOT_TOKEN" | "BOT_USERNAME" | "TELEGRAM_MODEL" | "DISCORD_BOT_TOKEN"
            | "DISCORD_MODEL" | "LLM_API_KEY" => String::new(),
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
                    if key == dynamic_account_id_field_key(ch.name) {
                        return default_account_id().to_string();
                    }
                }
                String::new()
            }
        }
    }

    fn clear_selected_field(&mut self) {
        let key = self.selected_field().key.clone();
        self.selected_field_mut().value.clear();
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
            | "DISCORD_BOT_TOKEN"
            | "DISCORD_ACCOUNT_ID"
            | "DISCORD_MODEL" => "Channel",
            _ => "Setup",
        }
    }

    fn field_display_order(key: &str) -> usize {
        if key.starts_with("DYN_") {
            // Compute ordering based on position in DYNAMIC_CHANNELS
            let mut offset = 0usize;
            for ch in DYNAMIC_CHANNELS {
                let account_expected = dynamic_account_id_field_key(ch.name);
                if account_expected == key {
                    return 20 + offset;
                }
                offset += 1;
                for f in ch.fields {
                    let expected = dynamic_field_key(ch.name, f.yaml_key);
                    if expected == key {
                        return 20 + offset;
                    }
                    offset += 1;
                }
            }
            return 20 + offset;
        }
        match key {
            // 1) Model
            "LLM_PROVIDER" => 0,
            "LLM_API_KEY" => 1,
            "LLM_MODEL" => 2,
            "LLM_BASE_URL" => 3,
            // 2) Channel (dynamic channel fields start at 20 via branch above)
            "ENABLED_CHANNELS" => 10,
            "TELEGRAM_BOT_TOKEN" => 11,
            "BOT_USERNAME" => 12,
            "TELEGRAM_ACCOUNT_ID" => 13,
            "TELEGRAM_MODEL" => 14,
            "DISCORD_BOT_TOKEN" => 15,
            "DISCORD_ACCOUNT_ID" => 16,
            "DISCORD_MODEL" => 17,
            // 3) App
            "DATA_DIR" => 40,
            "TIMEZONE" => 41,
            "WORKING_DIR" => 42,
            // 4) Memory
            "REFLECTOR_ENABLED" => 50,
            "REFLECTOR_INTERVAL_MINS" => 51,
            "MEMORY_TOKEN_BUDGET" => 52,
            // 5) Embedding
            "EMBEDDING_PROVIDER" => 60,
            "EMBEDDING_API_KEY" => 61,
            "EMBEDDING_BASE_URL" => 62,
            "EMBEDDING_MODEL" => 63,
            "EMBEDDING_DIM" => 64,
            // 6) Sandbox (last)
            "SANDBOX_ENABLED" => 100,
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
    let trimmed = if base_url.is_empty() {
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

    if trimmed.ends_with("/v1") {
        trimmed
    } else {
        format!("{}/v1", trimmed)
    }
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 6 {
        return "***".into();
    }
    let left = floor_char_boundary(s, 3.min(s.len()));
    let right_start = floor_char_boundary(s, s.len().saturating_sub(2));
    format!("{}***{}", &s[..left], &s[right_start..])
}

fn save_config_yaml(
    path: &Path,
    values: &HashMap<String, String>,
) -> Result<Option<String>, MicroClawError> {
    let mut backup = None;
    if path.exists() {
        let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
        let backup_path = format!("{}.bak.{ts}", path.display());
        fs::copy(path, &backup_path)?;
        backup = Some(backup_path);
    }

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
    let telegram_token = get("TELEGRAM_BOT_TOKEN");
    let telegram_username = get("BOT_USERNAME");
    let telegram_account_id = account_id_from_value(&get("TELEGRAM_ACCOUNT_ID"));
    let telegram_model = get("TELEGRAM_MODEL");
    let discord_token = get("DISCORD_BOT_TOKEN");
    let discord_account_id = account_id_from_value(&get("DISCORD_ACCOUNT_ID"));
    let discord_model = get("DISCORD_MODEL");

    let telegram_present =
        !telegram_token.trim().is_empty() || !telegram_username.trim().is_empty();
    let discord_present = !discord_token.trim().is_empty();
    // Use presence keys so optional defaults (e.g. feishu.domain = "feishu")
    // do not create disabled channel blocks unexpectedly.
    let dynamic_channel_include: Vec<(&DynamicChannelDef, bool)> = DYNAMIC_CHANNELS
        .iter()
        .map(|ch| {
            let selected = channel_selected(ch.name);
            let has_presence = ch.presence_keys.iter().any(|yaml_key| {
                let key = dynamic_field_key(ch.name, yaml_key);
                !get(&key).trim().is_empty()
            });
            (ch, selected || has_presence)
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
        if telegram_present {
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
            if !telegram_model.trim().is_empty() {
                yaml.push_str(&format!("        model: \"{}\"\n", telegram_model));
            }
        }
    }
    if channel_selected("discord") || discord_present {
        yaml.push_str("  discord:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("discord")));
        if discord_present {
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
            if !discord_model.trim().is_empty() {
                yaml.push_str(&format!("        model: \"{}\"\n", discord_model));
            }
        }
    }

    for (ch, include) in &dynamic_channel_include {
        if !include {
            continue;
        }
        let has_presence = ch.presence_keys.iter().any(|yaml_key| {
            let key = dynamic_field_key(ch.name, yaml_key);
            !get(&key).trim().is_empty()
        });
        yaml.push_str(&format!("  {}:\n", ch.name));
        yaml.push_str(&format!("    enabled: {}\n", channel_selected(ch.name)));
        if has_presence {
            let account_id = account_id_from_value(&get(&dynamic_account_id_field_key(ch.name)));
            yaml.push_str(&format!("    default_account: \"{}\"\n", account_id));
            yaml.push_str("    accounts:\n");
            yaml.push_str(&format!("      {}:\n", account_id));
            yaml.push_str("        enabled: true\n");
            for f in ch.fields {
                let key = dynamic_field_key(ch.name, f.yaml_key);
                let val = get(&key);
                if val.trim().is_empty() {
                    continue;
                }
                // Skip optional fields that match the default value.
                if !f.required && val == f.default && !val.is_empty() {
                    continue;
                }
                yaml.push_str(&format!("        {}: \"{}\"\n", f.yaml_key, val));
            }
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
    for i in visible_indices {
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
    let body = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Fields"))
        .wrap(Wrap { trim: false });
    frame.render_widget(body, body_chunks[0].inner(Margin::new(1, 0)));

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
        Line::from("• Channels picker: Space toggle, Enter apply"),
        Line::from("• Tab / Shift+Tab: next/prev field"),
        Line::from("• ↑/↓ in list: move, Enter: confirm, Esc: close"),
        Line::from("• ←/→ on provider/model: rotate presets"),
        Line::from("• e: force manual text edit"),
        Line::from("• Ctrl+D / Del: clear field"),
        Line::from("• Ctrl+R: restore field default"),
        Line::from("• F2: validate + online checks"),
        Line::from("• s / Ctrl+S: save config"),
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

    if let Some(picker) = &app.picker {
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

            if app.picker.is_some() {
                match key.code {
                    KeyCode::Esc => {
                        app.picker = None;
                        app.status = "Selection closed".into();
                    }
                    KeyCode::Up => app.move_picker(-1),
                    KeyCode::Down => app.move_picker(1),
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
                KeyCode::Tab => app.next(),
                KeyCode::BackTab => app.prev(),
                KeyCode::Enter => {
                    if app.open_picker_for_selected() {
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
                    try_save(&mut terminal, &mut app)?;
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
            "TELEGRAM_BOT_TOKEN".to_string(),
            "BOT_USERNAME".to_string(),
            "TELEGRAM_ACCOUNT_ID".to_string(),
            "DISCORD_BOT_TOKEN".to_string(),
            "DISCORD_ACCOUNT_ID".to_string(),
            dynamic_account_id_field_key("feishu"),
            dynamic_field_key("feishu", "app_id"),
            dynamic_field_key("feishu", "app_secret"),
            dynamic_field_key("feishu", "domain"),
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
            "TELEGRAM_BOT_TOKEN".to_string(),
            "BOT_USERNAME".to_string(),
            "TELEGRAM_ACCOUNT_ID".to_string(),
            dynamic_account_id_field_key("feishu"),
            dynamic_field_key("feishu", "app_id"),
            dynamic_field_key("feishu", "app_secret"),
            dynamic_field_key("feishu", "domain"),
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
        values.insert(dynamic_account_id_field_key("feishu"), "support".into());
        values.insert(dynamic_field_key("feishu", "app_id"), "app_id_1".into());
        values.insert(
            dynamic_field_key("feishu", "app_secret"),
            "app_secret_1".into(),
        );
        values.insert(dynamic_field_key("feishu", "domain"), "feishu".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  feishu:\n"));
        assert!(s.contains("    enabled: false\n"));
        assert!(s.contains("    default_account: \"support\"\n"));
        assert!(s.contains("      support:\n"));
        assert!(s.contains("        app_id: \"app_id_1\""));
        assert!(s.contains("        app_secret: \"app_secret_1\""));

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
        values.insert(dynamic_account_id_field_key("feishu"), "ops".into());
        values.insert(dynamic_field_key("feishu", "app_id"), "app_id_1".into());
        values.insert(
            dynamic_field_key("feishu", "app_secret"),
            "app_secret_1".into(),
        );
        values.insert(dynamic_field_key("feishu", "domain"), "feishu".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  feishu:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("    default_account: \"ops\"\n"));
        assert!(s.contains("      ops:\n"));
        assert!(s.contains("        app_id: \"app_id_1\""));
        assert!(s.contains("        app_secret: \"app_secret_1\""));
        assert!(!s.contains("        domain: \"feishu\""));

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
            .find(|f| f.key == "TELEGRAM_BOT_TOKEN")
        {
            field.value = "123456:token".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "BOT_USERNAME") {
            field.value = "botname".to_string();
        }
        if let Some(field) = app
            .fields
            .iter_mut()
            .find(|f| f.key == "TELEGRAM_ACCOUNT_ID")
        {
            field.value = "invalid account".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }
        let err = app.validate_local().unwrap_err();
        assert!(err
            .to_string()
            .contains("TELEGRAM_ACCOUNT_ID must use only letters, numbers, '_' or '-'"));
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
        assert_eq!(base, "https://api.openai.com/v1");
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
}
