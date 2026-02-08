use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
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

use crate::error::MicroClawError;

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
        id: "openrouter",
        label: "OpenRouter",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://openrouter.ai/api/v1",
        models: &[
            "openrouter/auto",
            "anthropic/claude-sonnet-4.5",
            "openai/gpt-5.2",
        ],
    },
    ProviderPreset {
        id: "anthropic",
        label: "Anthropic",
        protocol: ProviderProtocol::Anthropic,
        default_base_url: "",
        models: &["claude-sonnet-4-5-20250929", "claude-opus-4-6-20260205"],
    },
    ProviderPreset {
        id: "google",
        label: "Google DeepMind",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        models: &["gemini-2.5-pro", "gemini-2.5-flash"],
    },
    ProviderPreset {
        id: "alibaba",
        label: "Alibaba Cloud (Qwen / DashScope)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
        models: &["qwen3-max", "qwen-max-latest"],
    },
    ProviderPreset {
        id: "deepseek",
        label: "DeepSeek",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.deepseek.com/v1",
        models: &["deepseek-chat", "deepseek-reasoner"],
    },
    ProviderPreset {
        id: "moonshot",
        label: "Moonshot AI (Kimi)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.moonshot.cn/v1",
        models: &["kimi-k2.5", "kimi-k2"],
    },
    ProviderPreset {
        id: "mistral",
        label: "Mistral AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.mistral.ai/v1",
        models: &["mistral-large-latest", "ministral-8b-latest"],
    },
    ProviderPreset {
        id: "azure",
        label: "Microsoft Azure AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url:
            "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT",
        models: &["gpt-5.2", "gpt-5"],
    },
    ProviderPreset {
        id: "bedrock",
        label: "Amazon AWS Bedrock",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://bedrock-runtime.YOUR-REGION.amazonaws.com/openai/v1",
        models: &[
            "anthropic.claude-opus-4-6-v1",
            "anthropic.claude-sonnet-4-5-v2",
        ],
    },
    ProviderPreset {
        id: "zhipu",
        label: "Zhipu AI (GLM / Z.AI)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://open.bigmodel.cn/api/paas/v4",
        models: &["glm-4.7", "glm-4.7-flash"],
    },
    ProviderPreset {
        id: "minimax",
        label: "MiniMax",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.minimax.io/v1",
        models: &["MiniMax-M2.1"],
    },
    ProviderPreset {
        id: "cohere",
        label: "Cohere",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.cohere.ai/compatibility/v1",
        models: &["command-a-03-2025", "command-r-plus-08-2024"],
    },
    ProviderPreset {
        id: "tencent",
        label: "Tencent AI Lab",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.hunyuan.cloud.tencent.com/v1",
        models: &["hunyuan-t1-latest", "hunyuan-turbos-latest"],
    },
    ProviderPreset {
        id: "xai",
        label: "xAI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.x.ai/v1",
        models: &["grok-4", "grok-3"],
    },
    ProviderPreset {
        id: "huggingface",
        label: "Hugging Face",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://router.huggingface.co/v1",
        models: &["Qwen/Qwen3-Coder-Next", "meta-llama/Llama-3.3-70B-Instruct"],
    },
    ProviderPreset {
        id: "together",
        label: "Together AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.together.xyz/v1",
        models: &[
            "deepseek-ai/DeepSeek-V3",
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
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
        format!("{} ({})", preset.id, preset.label)
    } else {
        format!("{provider} (custom)")
    }
}

#[derive(Clone)]
struct Field {
    key: &'static str,
    label: &'static str,
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

#[derive(Clone, Copy)]
enum PickerKind {
    Provider,
    Model,
}

#[derive(Clone, Copy)]
struct PickerState {
    kind: PickerKind,
    selected: usize,
}

impl SetupApp {
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

        Self {
            fields: vec![
                Field {
                    key: "TELEGRAM_BOT_TOKEN",
                    label: "Telegram bot token",
                    value: existing.get("TELEGRAM_BOT_TOKEN").cloned().unwrap_or_default(),
                    required: true,
                    secret: true,
                },
                Field {
                    key: "BOT_USERNAME",
                    label: "Bot username (without @)",
                    value: existing.get("BOT_USERNAME").cloned().unwrap_or_default(),
                    required: true,
                    secret: false,
                },
                Field {
                    key: "LLM_PROVIDER",
                    label: "LLM provider (preset/custom)",
                    value: provider,
                    required: true,
                    secret: false,
                },
                Field {
                    key: "LLM_API_KEY",
                    label: "LLM API key",
                    value: llm_api_key,
                    required: true,
                    secret: true,
                },
                Field {
                    key: "LLM_MODEL",
                    label: "LLM model",
                    value: existing.get("LLM_MODEL").cloned().unwrap_or_else(|| default_model.into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "LLM_BASE_URL",
                    label: "LLM base URL (optional)",
                    value: existing.get("LLM_BASE_URL").cloned().unwrap_or_else(|| default_base_url.to_string()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "DATA_DIR",
                    label: "Data root directory",
                    value: existing
                        .get("DATA_DIR")
                        .cloned()
                        .unwrap_or_else(|| "./microclaw.data".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "TIMEZONE",
                    label: "Timezone (IANA)",
                    value: existing.get("TIMEZONE").cloned().unwrap_or_else(|| "UTC".into()),
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
        }
    }

    /// Load existing config values from microclaw.config.yaml/.yml, or .env (legacy).
    fn load_existing_config() -> HashMap<String, String> {
        // Try microclaw config name first.
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
                    map.insert("TELEGRAM_BOT_TOKEN".into(), config.telegram_bot_token);
                    map.insert("BOT_USERNAME".into(), config.bot_username);
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
                    return map;
                }
            }
        }

        // Fall back to .env
        if let Ok(content) = fs::read_to_string(".env") {
            let mut map = HashMap::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = trimmed.split_once('=') {
                    map.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
            // Normalize API key
            if !map.contains_key("LLM_API_KEY") {
                if let Some(v) = map.get("ANTHROPIC_API_KEY") {
                    map.insert("LLM_API_KEY".into(), v.clone());
                }
            }
            return map;
        }

        HashMap::new()
    }

    fn next(&mut self) {
        if self.selected + 1 < self.fields.len() {
            self.selected += 1;
        }
    }

    fn prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn selected_field_mut(&mut self) -> &mut Field {
        &mut self.fields[self.selected]
    }

    fn selected_field(&self) -> &Field {
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

    fn validate_local(&self) -> Result<(), MicroClawError> {
        for field in &self.fields {
            if field.required && field.value.trim().is_empty() {
                return Err(MicroClawError::Config(format!("{} is required", field.key)));
            }
        }

        let provider = self.field_value("LLM_PROVIDER");
        if provider.is_empty() {
            return Err(MicroClawError::Config("LLM_PROVIDER is required".into()));
        }

        let username = self.field_value("BOT_USERNAME");
        if username.starts_with('@') {
            return Err(MicroClawError::Config(
                "BOT_USERNAME should not include '@'".into(),
            ));
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
            "./microclaw.data".to_string()
        } else {
            data_dir
        };
        fs::create_dir_all(&dir)?;
        let probe = Path::new(&dir).join(".setup_probe");
        fs::write(&probe, "ok")?;
        let _ = fs::remove_file(probe);

        Ok(())
    }

    fn validate_online(&self) -> Result<Vec<String>, MicroClawError> {
        let tg_token = self.field_value("TELEGRAM_BOT_TOKEN");
        let env_username = self
            .field_value("BOT_USERNAME")
            .trim_start_matches('@')
            .to_string();
        let provider = self.field_value("LLM_PROVIDER").to_lowercase();
        let api_key = self.field_value("LLM_API_KEY");
        let base_url = self.field_value("LLM_BASE_URL");
        let model = self.field_value("LLM_MODEL");
        std::thread::spawn(move || {
            perform_online_validation(
                &tg_token,
                &env_username,
                &provider,
                &api_key,
                &base_url,
                &model,
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

    fn open_picker_for_selected(&mut self) -> bool {
        match self.selected_field().key {
            "LLM_PROVIDER" => {
                let idx = self.provider_index(&self.field_value("LLM_PROVIDER"));
                self.picker = Some(PickerState {
                    kind: PickerKind::Provider,
                    selected: idx,
                });
                true
            }
            "LLM_MODEL" => {
                let provider = self.field_value("LLM_PROVIDER");
                if provider.eq_ignore_ascii_case("custom") {
                    return false;
                }
                let options = self.model_options();
                if options.is_empty() {
                    return false;
                }
                let current_model = self.field_value("LLM_MODEL");
                let idx = options
                    .iter()
                    .position(|m| *m == current_model)
                    .unwrap_or(0);
                self.picker = Some(PickerState {
                    kind: PickerKind::Model,
                    selected: idx,
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
            PickerKind::Model => self.model_options().len(),
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
                let options = self.model_options();
                if let Some(chosen) = options.get(picker.selected) {
                    if let Some(model) = self.fields.iter_mut().find(|f| f.key == "LLM_MODEL") {
                        model.value = chosen.clone();
                        self.status = format!("Model set to {chosen}");
                    }
                }
            }
        }
    }

    fn default_value_for_field(&self, key: &str) -> String {
        let provider = self.field_value("LLM_PROVIDER");
        match key {
            "TELEGRAM_BOT_TOKEN" | "BOT_USERNAME" | "LLM_API_KEY" => String::new(),
            "LLM_PROVIDER" => "anthropic".into(),
            "LLM_MODEL" => default_model_for_provider(&provider).into(),
            "LLM_BASE_URL" => find_provider_preset(&provider)
                .map(|p| p.default_base_url.to_string())
                .unwrap_or_default(),
            "DATA_DIR" => "./microclaw.data".into(),
            "TIMEZONE" => "UTC".into(),
            _ => String::new(),
        }
    }

    fn clear_selected_field(&mut self) {
        let key = self.selected_field().key;
        self.selected_field_mut().value.clear();
        self.status = format!("Cleared {key}");
    }

    fn restore_selected_field_default(&mut self) {
        let key = self.selected_field().key;
        let default = self.default_value_for_field(key);
        if default.is_empty() {
            self.status = format!("{key} has no default");
        } else {
            self.selected_field_mut().value = default.clone();
            self.status = format!("Restored {key} to default: {default}");
        }
    }

    fn current_section(&self) -> &'static str {
        match self.selected {
            0..=1 => "Telegram",
            2..=5 => "LLM",
            6..=7 => "Runtime",
            _ => "Setup",
        }
    }

    fn progress_bar(&self, width: usize) -> String {
        let total = self.fields.len().max(1);
        let done = self.selected + 1;
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

fn perform_online_validation(
    tg_token: &str,
    env_username: &str,
    provider: &str,
    api_key: &str,
    base_url: &str,
    model: &str,
) -> Result<Vec<String>, MicroClawError> {
    let mut checks = Vec::new();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // --- Telegram validation ---
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
    if !env_username.is_empty() && !actual_username.is_empty() && env_username != actual_username {
        checks.push(format!(
            "Telegram OK (token user={actual_username}, configured={env_username})"
        ));
    } else {
        checks.push(format!("Telegram OK ({actual_username})"));
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
            "max_tokens": 1,
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
        let mut base = if base_url.is_empty() {
            preset
                .map(|p| p.default_base_url)
                .filter(|s| !s.is_empty())
                .unwrap_or("https://api.openai.com/v1")
                .to_string()
        } else {
            base_url.trim_end_matches('/').to_string()
        };
        if !base.ends_with("/v1") {
            base = format!("{}/v1", base.trim_end_matches('/'));
        }
        let body = serde_json::json!({
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let resp = client
            .post(format!("{base}/chat/completions"))
            .bearer_auth(api_key)
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
        checks.push(format!("LLM OK (openai-compatible, model={model})"));
    }

    Ok(checks)
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 6 {
        return "***".into();
    }
    format!("{}***{}", &s[..3], &s[s.len() - 2..])
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

    let mut yaml = String::new();
    yaml.push_str("# MicroClaw configuration\n\n");
    yaml.push_str("# Telegram bot token from @BotFather\n");
    yaml.push_str(&format!(
        "telegram_bot_token: \"{}\"\n",
        get("TELEGRAM_BOT_TOKEN")
    ));
    yaml.push_str("# Bot username without @\n");
    yaml.push_str(&format!("bot_username: \"{}\"\n\n", get("BOT_USERNAME")));

    yaml.push_str("# LLM provider (anthropic, openai, openrouter, deepseek, google, etc.)\n");
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

    yaml.push('\n');
    let data_dir = values
        .get("DATA_DIR")
        .cloned()
        .unwrap_or_else(|| "./microclaw.data".into());
    yaml.push_str(&format!("data_dir: \"{}\"\n", data_dir));
    let tz = values
        .get("TIMEZONE")
        .cloned()
        .unwrap_or_else(|| "UTC".into());
    yaml.push_str(&format!("timezone: \"{}\"\n", tz));

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
                    app.selected + 1,
                    app.fields.len(),
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
    for (i, f) in app.fields.iter().enumerate() {
        let selected = i == app.selected;
        let label = if f.required {
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
            Span::styled(format!("{prefix} {label}: "), Style::default().fg(color)),
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
            Span::styled(field.key, Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled("Required: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if field.required { "yes" } else { "no" }),
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

    if let Some(picker) = app.picker {
        let overlay_area = frame.area().inner(Margin::new(8, 4));
        let (title, options): (&str, Vec<String>) = match picker.kind {
            PickerKind::Provider => (
                "Select LLM Provider",
                PROVIDER_PRESETS
                    .iter()
                    .map(|p| format!("{} ({})", p.id, p.label))
                    .collect(),
            ),
            PickerKind::Model => ("Select LLM Model", app.model_options()),
        };
        let mut list_lines = Vec::with_capacity(options.len());
        for (i, item) in options.iter().enumerate() {
            let selected = i == picker.selected;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            list_lines.push(Line::from(Span::styled(format!("{prefix}{item}"), style)));
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

fn try_save(app: &mut SetupApp) {
    match app
        .validate_local()
        .and_then(|_| app.validate_online())
        .and_then(|checks| {
            let values = app.to_env_map();
            let backup = save_config_yaml(Path::new("microclaw.config.yaml"), &values)?;
            app.backup_path = backup;
            app.completion_summary = checks;
            Ok(())
        }) {
        Ok(_) => {
            app.status = "Saved microclaw.config.yaml".into();
            app.completed = true;
        }
        Err(e) => app.status = format!("Cannot save: {e}"),
    }
}

fn run_wizard(mut terminal: DefaultTerminal) -> Result<bool, MicroClawError> {
    let mut app = SetupApp::new();

    loop {
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
                    try_save(&mut app);
                }
                KeyCode::Char('s') => {
                    try_save(&mut app);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_secret() {
        assert_eq!(mask_secret("abcdefghi"), "abc***hi");
        assert_eq!(mask_secret("abc"), "***");
    }

    #[test]
    fn test_save_config_yaml() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("TELEGRAM_BOT_TOKEN".into(), "new_tok".into());
        values.insert("BOT_USERNAME".into(), "new_bot".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        let backup = save_config_yaml(&yaml_path, &values).unwrap();
        assert!(backup.is_none()); // No previous file to back up

        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("telegram_bot_token: \"new_tok\""));
        assert!(s.contains("bot_username: \"new_bot\""));
        assert!(s.contains("llm_provider: \"anthropic\""));
        assert!(s.contains("api_key: \"key\""));

        // Save again to test backup
        let backup2 = save_config_yaml(&yaml_path, &values).unwrap();
        assert!(backup2.is_some());

        let _ = fs::remove_file(&yaml_path);
    }
}
