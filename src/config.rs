use std::collections::HashMap;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::codex_auth::{
    codex_auth_file_has_access_token, is_openai_codex_provider, provider_allows_empty_api_key,
};
use crate::plugins::PluginsConfig;
use microclaw_core::error::MicroClawError;
pub use microclaw_tools::sandbox::{SandboxBackend, SandboxConfig, SandboxMode, SecurityProfile};
pub use microclaw_tools::types::WorkingDirIsolation;
use microclaw_tools::web_content_validation::WebContentValidationConfig;
use microclaw_tools::web_fetch::WebFetchUrlValidationConfig;

fn default_telegram_bot_token() -> String {
    String::new()
}
fn default_bot_username() -> String {
    String::new()
}
fn default_llm_provider() -> String {
    "anthropic".into()
}
fn default_api_key() -> String {
    String::new()
}
fn default_model() -> String {
    String::new()
}
fn default_max_tokens() -> u32 {
    8192
}
fn default_max_tool_iterations() -> usize {
    100
}
fn default_compaction_timeout_secs() -> u64 {
    180
}
fn default_max_history_messages() -> usize {
    50
}
fn default_max_document_size_mb() -> u64 {
    100
}
fn default_memory_token_budget() -> usize {
    1500
}
fn default_data_dir() -> String {
    default_data_root().to_string_lossy().to_string()
}
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn default_data_root() -> PathBuf {
    home_dir()
        .map(|h| h.join(".microclaw"))
        .unwrap_or_else(|| PathBuf::from(".microclaw"))
}

fn default_working_dir() -> String {
    default_data_root()
        .join("working_dir")
        .to_string_lossy()
        .to_string()
}
fn default_working_dir_isolation() -> WorkingDirIsolation {
    WorkingDirIsolation::Chat
}
fn default_sandbox_image() -> String {
    "ubuntu:25.10".into()
}
fn default_sandbox_container_prefix() -> String {
    "microclaw-sandbox".into()
}
fn default_timezone() -> String {
    "UTC".into()
}
fn default_max_session_messages() -> usize {
    40
}
fn default_compact_keep_recent() -> usize {
    20
}
fn default_tool_timeout_secs() -> u64 {
    30
}
fn default_mcp_request_timeout_secs() -> u64 {
    120
}
fn default_control_chat_ids() -> Vec<i64> {
    Vec::new()
}
fn default_web_enabled() -> bool {
    true
}
fn default_web_host() -> String {
    "127.0.0.1".into()
}
fn default_web_port() -> u16 {
    10961
}
fn default_web_max_inflight_per_session() -> usize {
    2
}
fn default_web_max_requests_per_window() -> usize {
    8
}
fn default_web_rate_window_seconds() -> u64 {
    10
}
fn default_web_run_history_limit() -> usize {
    512
}
fn default_web_session_idle_ttl_seconds() -> u64 {
    300
}
fn default_allow_group_slash_without_mention() -> bool {
    false
}

fn default_model_prices() -> Vec<ModelPrice> {
    Vec::new()
}
fn default_reflector_enabled() -> bool {
    true
}
fn default_reflector_interval_mins() -> u64 {
    15
}
fn default_soul_path() -> Option<String> {
    None
}
fn default_clawhub_registry() -> String {
    "https://clawhub.ai".into()
}
fn default_voice_provider() -> String {
    "openai".into()
}
fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClawHubConfig {
    /// ClawHub registry URL
    #[serde(default = "default_clawhub_registry", rename = "clawhub_registry")]
    pub registry: String,
    /// ClawHub API token (optional)
    #[serde(default, rename = "clawhub_token")]
    pub token: Option<String>,
    /// Enable agent tools for ClawHub (search, install)
    #[serde(default = "default_true", rename = "clawhub_agent_tools_enabled")]
    pub agent_tools_enabled: bool,
    /// Skip security warnings for ClawHub installs
    #[serde(default, rename = "clawhub_skip_security_warnings")]
    pub skip_security_warnings: bool,
}

impl Default for ClawHubConfig {
    fn default() -> Self {
        Self {
            registry: default_clawhub_registry(),
            token: None,
            agent_tools_enabled: default_true(),
            skip_security_warnings: false,
        }
    }
}
fn is_local_web_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelPrice {
    pub model: String,
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    // --- LLM / API ---
    #[serde(default = "default_llm_provider")]
    pub llm_provider: String,
    #[serde(default = "default_api_key")]
    pub api_key: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub llm_base_url: Option<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_max_tool_iterations")]
    pub max_tool_iterations: usize,
    #[serde(default = "default_compaction_timeout_secs")]
    pub compaction_timeout_secs: u64,
    #[serde(default = "default_max_history_messages")]
    pub max_history_messages: usize,
    #[serde(default = "default_max_document_size_mb")]
    pub max_document_size_mb: u64,
    #[serde(default = "default_memory_token_budget")]
    pub memory_token_budget: usize,
    #[serde(default = "default_max_session_messages")]
    pub max_session_messages: usize,
    #[serde(default = "default_compact_keep_recent")]
    pub compact_keep_recent: usize,
    #[serde(default = "default_tool_timeout_secs")]
    pub default_tool_timeout_secs: u64,
    #[serde(default)]
    pub tool_timeout_overrides: HashMap<String, u64>,
    #[serde(default = "default_mcp_request_timeout_secs")]
    pub default_mcp_request_timeout_secs: u64,
    #[serde(default)]
    pub show_thinking: bool,
    /// OpenAI-compatible request-body overrides applied for all models/providers.
    /// Set a key to `null` to remove that field from the outgoing JSON body.
    #[serde(default)]
    pub openai_compat_body_overrides: HashMap<String, serde_json::Value>,
    /// OpenAI-compatible request-body overrides keyed by provider name.
    /// Provider keys are normalized to lowercase.
    #[serde(default)]
    pub openai_compat_body_overrides_by_provider:
        HashMap<String, HashMap<String, serde_json::Value>>,
    /// OpenAI-compatible request-body overrides keyed by model name.
    #[serde(default)]
    pub openai_compat_body_overrides_by_model: HashMap<String, HashMap<String, serde_json::Value>>,

    // --- Paths & environment ---
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub skills_dir: Option<String>,
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    #[serde(default = "default_working_dir_isolation")]
    pub working_dir_isolation: WorkingDirIsolation,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default = "default_control_chat_ids")]
    pub control_chat_ids: Vec<i64>,
    #[serde(default)]
    pub discord_bot_token: Option<String>,
    #[serde(default)]
    pub discord_allowed_channels: Vec<u64>,
    #[serde(default)]
    pub discord_no_mention: bool,
    #[serde(default = "default_allow_group_slash_without_mention")]
    pub allow_group_slash_without_mention: bool,

    // --- Web UI ---
    #[serde(default = "default_web_enabled")]
    pub web_enabled: bool,
    #[serde(default = "default_web_host")]
    pub web_host: String,
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    #[serde(default)]
    pub web_auth_token: Option<String>,
    #[serde(default = "default_web_max_inflight_per_session")]
    pub web_max_inflight_per_session: usize,
    #[serde(default = "default_web_max_requests_per_window")]
    pub web_max_requests_per_window: usize,
    #[serde(default = "default_web_rate_window_seconds")]
    pub web_rate_window_seconds: u64,
    #[serde(default = "default_web_run_history_limit")]
    pub web_run_history_limit: usize,
    #[serde(default = "default_web_session_idle_ttl_seconds")]
    pub web_session_idle_ttl_seconds: u64,
    #[serde(default)]
    pub web_fetch_validation: WebContentValidationConfig,
    #[serde(default)]
    pub web_fetch_url_validation: WebFetchUrlValidationConfig,

    // --- Embedding ---
    #[serde(default)]
    pub embedding_provider: Option<String>,
    #[serde(default)]
    pub embedding_api_key: Option<String>,
    #[serde(default)]
    pub embedding_base_url: Option<String>,
    #[serde(default)]
    pub embedding_model: Option<String>,
    #[serde(default)]
    pub embedding_dim: Option<usize>,
    #[serde(default)]
    pub openai_api_key: Option<String>,

    // --- Pricing ---
    #[serde(default = "default_model_prices")]
    pub model_prices: Vec<ModelPrice>,

    // --- Reflector ---
    #[serde(default = "default_reflector_enabled")]
    pub reflector_enabled: bool,
    #[serde(default = "default_reflector_interval_mins")]
    pub reflector_interval_mins: u64,

    // --- Soul ---
    /// Path to a SOUL.md file that defines the bot's personality, voice, and values.
    /// If not set, looks for SOUL.md in data_dir root, then current directory.
    #[serde(default = "default_soul_path")]
    pub soul_path: Option<String>,

    // --- ClawHub ---
    #[serde(flatten)]
    pub clawhub: ClawHubConfig,

    // --- Plugins ---
    #[serde(default)]
    pub plugins: PluginsConfig,

    // --- Voice / Speech-to-text ---
    /// Voice transcription provider: "openai" uses OpenAI Whisper API, "local" uses voice_transcription_command
    #[serde(default = "default_voice_provider", rename = "voice_provider")]
    pub voice_provider: String,
    /// Command template for local voice transcription. Use {file} as placeholder for audio file path.
    /// Example: "whisper-mlx --file {file}" or "/usr/local/bin/whisper {file}"
    #[serde(default, rename = "voice_transcription_command")]
    pub voice_transcription_command: Option<String>,

    // --- Channel registry (new dynamic config) ---
    /// Per-channel configuration. Keys are channel names (e.g. "telegram", "discord", "slack", "irc", "web").
    /// Each value is channel-specific config deserialized by the adapter.
    /// If empty, synthesized from legacy flat fields below in post_deserialize().
    #[serde(default)]
    pub channels: HashMap<String, serde_yaml::Value>,

    // --- Legacy channel fields (deprecated, use `channels:` instead) ---
    #[serde(default = "default_telegram_bot_token")]
    pub telegram_bot_token: String,
    #[serde(default = "default_bot_username")]
    pub bot_username: String,
    #[serde(default)]
    pub allowed_groups: Vec<i64>,
}

impl Config {
    fn channel_default_account_id(&self, channel: &str) -> Option<String> {
        let channel_cfg = self.channels.get(channel)?;
        let mut account_ids: Vec<String> = channel_cfg
            .get("accounts")
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        account_ids.sort();
        channel_cfg
            .get("default_account")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| {
                if channel_cfg
                    .get("accounts")
                    .and_then(|v| v.get("default"))
                    .is_some()
                {
                    Some("default".to_string())
                } else {
                    account_ids.first().cloned()
                }
            })
    }

    fn channel_account_bot_username(&self, channel: &str, account_id: &str) -> Option<String> {
        self.channels
            .get(channel)
            .and_then(|v| v.get("accounts"))
            .and_then(|v| v.get(account_id))
            .and_then(|v| v.get("bot_username"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
    }

    pub fn bot_username_for_channel(&self, channel: &str) -> String {
        let channel_override = self
            .channels
            .get(channel)
            .and_then(|v| v.get("bot_username"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty());
        if let Some(v) = channel_override {
            return v.to_string();
        }

        if let Some((base_channel, account_id)) = channel.split_once('.') {
            if let Some(v) = self.channel_account_bot_username(base_channel, account_id) {
                return v;
            }
        } else if let Some(default_account) = self.channel_default_account_id(channel) {
            if let Some(v) = self.channel_account_bot_username(channel, &default_account) {
                return v;
            }
        }

        let global = self.bot_username.trim();
        if !global.is_empty() {
            global.to_string()
        } else {
            default_bot_username()
        }
    }

    pub fn bot_username_overrides(&self) -> HashMap<String, String> {
        let mut overrides: HashMap<String, String> = self
            .channels
            .iter()
            .filter_map(|(channel, cfg)| {
                cfg.get("bot_username")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(|v| (channel.clone(), v.to_string()))
            })
            .collect();

        for (channel, channel_cfg) in &self.channels {
            let accounts = channel_cfg.get("accounts").and_then(|v| v.as_mapping());
            let Some(accounts) = accounts else {
                continue;
            };
            let default_account = self.channel_default_account_id(channel);
            for (key, value) in accounts {
                let Some(account_id) = key.as_str() else {
                    continue;
                };
                let username = value
                    .get("bot_username")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty());
                let Some(username) = username else {
                    continue;
                };
                if default_account
                    .as_deref()
                    .map(|v| v == account_id)
                    .unwrap_or(false)
                {
                    overrides.insert(channel.clone(), username.to_string());
                } else {
                    overrides.insert(format!("{channel}.{account_id}"), username.to_string());
                }
            }
        }

        overrides
    }

    #[cfg(test)]
    pub(crate) fn test_defaults() -> Self {
        Self {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "anthropic".into(),
            api_key: "key".into(),
            model: "claude-sonnet-4-5-20250929".into(),
            llm_base_url: None,
            max_tokens: 8192,
            max_tool_iterations: 100,
            compaction_timeout_secs: 180,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: default_data_dir(),
            skills_dir: None,
            working_dir: default_working_dir(),
            working_dir_isolation: WorkingDirIsolation::Chat,
            sandbox: SandboxConfig::default(),
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            default_tool_timeout_secs: default_tool_timeout_secs(),
            tool_timeout_overrides: HashMap::new(),
            default_mcp_request_timeout_secs: default_mcp_request_timeout_secs(),
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            discord_no_mention: false,
            allow_group_slash_without_mention: false,
            show_thinking: false,
            openai_compat_body_overrides: HashMap::new(),
            openai_compat_body_overrides_by_provider: HashMap::new(),
            openai_compat_body_overrides_by_model: HashMap::new(),
            web_enabled: true,
            web_host: "127.0.0.1".into(),
            web_port: 10961,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            web_fetch_validation: WebContentValidationConfig::default(),
            web_fetch_url_validation: WebFetchUrlValidationConfig::default(),
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            clawhub: ClawHubConfig::default(),
            plugins: PluginsConfig::default(),
            voice_provider: "openai".into(),
            voice_transcription_command: None,
            channels: HashMap::new(),
        }
    }

    /// Data root directory from config.
    pub fn data_root_dir(&self) -> PathBuf {
        PathBuf::from(&self.data_dir)
    }

    /// Runtime data directory (db, memory, exports, etc.).
    pub fn runtime_data_dir(&self) -> String {
        self.data_root_dir()
            .join("runtime")
            .to_string_lossy()
            .to_string()
    }

    /// Skills directory. Priority: MICROCLAW_SKILLS_DIR env var > skills_dir config > <data_dir>/skills
    pub fn skills_data_dir(&self) -> String {
        // 1. Check env var first
        if let Ok(explicit_dir) = std::env::var("MICROCLAW_SKILLS_DIR") {
            let trimmed = explicit_dir.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        // 2. Check config file
        if let Some(configured) = &self.skills_dir {
            let trimmed = configured.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        // 3. Default to <data_dir>/skills
        self.data_root_dir()
            .join("skills")
            .to_string_lossy()
            .to_string()
    }

    pub fn clawhub_lockfile_path(&self) -> PathBuf {
        self.data_root_dir().join("clawhub.lock.json")
    }

    pub fn resolve_config_path() -> Result<Option<PathBuf>, MicroClawError> {
        // 1. Check MICROCLAW_CONFIG env var for custom path
        if let Ok(custom) = std::env::var("MICROCLAW_CONFIG") {
            if std::path::Path::new(&custom).exists() {
                return Ok(Some(PathBuf::from(custom)));
            }
            return Err(MicroClawError::Config(format!(
                "MICROCLAW_CONFIG points to non-existent file: {custom}"
            )));
        }

        if std::path::Path::new("./microclaw.config.yaml").exists() {
            return Ok(Some(PathBuf::from("./microclaw.config.yaml")));
        }
        if std::path::Path::new("./microclaw.config.yml").exists() {
            return Ok(Some(PathBuf::from("./microclaw.config.yml")));
        }
        Ok(None)
    }

    fn inferred_channel_enabled(&self, channel: &str) -> bool {
        match channel {
            "telegram" => {
                !self.telegram_bot_token.trim().is_empty() || self.channels.contains_key("telegram")
            }
            "discord" => {
                self.discord_bot_token
                    .as_deref()
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
                    || self.channels.contains_key("discord")
            }
            "web" => self.web_enabled || self.channels.contains_key("web"),
            _ => self.channels.contains_key(channel),
        }
    }

    fn explicit_channel_enabled(&self, channel: &str) -> Option<bool> {
        self.channels
            .get(channel)
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
    }

    pub fn channel_enabled(&self, channel: &str) -> bool {
        let needle = channel.trim().to_lowercase();
        if let Some(explicit) = self.explicit_channel_enabled(&needle) {
            return explicit;
        }
        self.inferred_channel_enabled(&needle)
    }

    /// Load config from YAML file.
    pub fn load() -> Result<Self, MicroClawError> {
        let yaml_path = Self::resolve_config_path()?;

        if let Some(path) = yaml_path {
            let path_str = path.to_string_lossy().to_string();
            let content = std::fs::read_to_string(&path)
                .map_err(|e| MicroClawError::Config(format!("Failed to read {path_str}: {e}")))?;
            let mut config: Config = serde_yaml::from_str(&content)
                .map_err(|e| MicroClawError::Config(format!("Failed to parse {path_str}: {e}")))?;
            config.post_deserialize()?;
            return Ok(config);
        }

        // No config file found at all
        Err(MicroClawError::Config(
            "No microclaw.config.yaml found. Run `microclaw setup` to create one.".into(),
        ))
    }

    /// Apply post-deserialization normalization and validation.
    pub(crate) fn post_deserialize(&mut self) -> Result<(), MicroClawError> {
        self.llm_provider = self.llm_provider.trim().to_lowercase();

        // Apply provider-specific default model if empty
        if self.model.is_empty() {
            self.model = match self.llm_provider.as_str() {
                "anthropic" => "claude-sonnet-4-5-20250929".into(),
                "ollama" => "llama3.2".into(),
                "openai-codex" => "gpt-5.3-codex".into(),
                _ => "gpt-5.2".into(),
            };
        }

        // Validate timezone
        self.timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| MicroClawError::Config(format!("Invalid timezone: {}", self.timezone)))?;

        // Filter empty llm_base_url
        if let Some(ref url) = self.llm_base_url {
            if url.trim().is_empty() {
                self.llm_base_url = None;
            }
        }
        if let Some(dir) = &self.skills_dir {
            let trimmed = dir.trim().to_string();
            self.skills_dir = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            };
        }
        if let Some(dir) = &self.plugins.dir {
            let trimmed = dir.trim().to_string();
            self.plugins.dir = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            };
        }
        if self.working_dir.trim().is_empty() {
            self.working_dir = default_working_dir();
        }
        self.sandbox.image = self.sandbox.image.trim().to_string();
        if self.sandbox.image.is_empty() {
            self.sandbox.image = default_sandbox_image();
        }
        self.sandbox.container_prefix = self.sandbox.container_prefix.trim().to_string();
        if self.sandbox.container_prefix.is_empty() {
            self.sandbox.container_prefix = default_sandbox_container_prefix();
        }
        if self.web_host.trim().is_empty() {
            self.web_host = default_web_host();
        }
        if let Some(token) = &self.web_auth_token {
            if token.trim().is_empty() {
                self.web_auth_token = None;
            }
        }
        if let Some(provider) = &self.embedding_provider {
            let p = provider.trim().to_lowercase();
            self.embedding_provider = if p.is_empty() { None } else { Some(p) };
        }
        if let Some(v) = &self.embedding_api_key {
            if v.trim().is_empty() {
                self.embedding_api_key = None;
            }
        }
        if let Some(v) = &self.embedding_base_url {
            if v.trim().is_empty() {
                self.embedding_base_url = None;
            }
        }
        if let Some(v) = &self.embedding_model {
            let m = v.trim().to_string();
            self.embedding_model = if m.is_empty() { None } else { Some(m) };
        }
        if let Some(v) = self.embedding_dim {
            if v == 0 {
                self.embedding_dim = None;
            }
        }
        let web_enabled_effective = self
            .explicit_channel_enabled("web")
            .unwrap_or(self.web_enabled);
        if web_enabled_effective
            && !is_local_web_host(&self.web_host)
            && self.web_auth_token.is_none()
        {
            return Err(MicroClawError::Config(
                "web_auth_token is required when web channel is enabled and web_host is not local"
                    .into(),
            ));
        }
        if self.web_max_inflight_per_session == 0 {
            self.web_max_inflight_per_session = default_web_max_inflight_per_session();
        }
        if self.web_max_requests_per_window == 0 {
            self.web_max_requests_per_window = default_web_max_requests_per_window();
        }
        if self.web_rate_window_seconds == 0 {
            self.web_rate_window_seconds = default_web_rate_window_seconds();
        }
        if self.web_run_history_limit == 0 {
            self.web_run_history_limit = default_web_run_history_limit();
        }
        if self.web_session_idle_ttl_seconds == 0 {
            self.web_session_idle_ttl_seconds = default_web_session_idle_ttl_seconds();
        }
        self.web_fetch_validation.normalize();
        self.web_fetch_url_validation.normalize();
        if self.max_document_size_mb == 0 {
            self.max_document_size_mb = default_max_document_size_mb();
        }
        if self.default_tool_timeout_secs == 0 {
            self.default_tool_timeout_secs = default_tool_timeout_secs();
        }
        if self.default_mcp_request_timeout_secs == 0 {
            self.default_mcp_request_timeout_secs = default_mcp_request_timeout_secs();
        }
        self.tool_timeout_overrides = self
            .tool_timeout_overrides
            .drain()
            .filter_map(|(name, timeout_secs)| {
                let normalized = name.trim().to_ascii_lowercase();
                if normalized.is_empty() || timeout_secs == 0 {
                    None
                } else {
                    Some((normalized, timeout_secs))
                }
            })
            .collect();
        self.openai_compat_body_overrides =
            normalize_body_override_params(std::mem::take(&mut self.openai_compat_body_overrides));
        self.openai_compat_body_overrides_by_provider = self
            .openai_compat_body_overrides_by_provider
            .drain()
            .filter_map(|(provider, params)| {
                let provider = provider.trim().to_ascii_lowercase();
                if provider.is_empty() {
                    return None;
                }
                let params = normalize_body_override_params(params);
                if params.is_empty() {
                    None
                } else {
                    Some((provider, params))
                }
            })
            .collect();
        self.openai_compat_body_overrides_by_model = self
            .openai_compat_body_overrides_by_model
            .drain()
            .filter_map(|(model, params)| {
                let model = model.trim().to_string();
                if model.is_empty() {
                    return None;
                }
                let params = normalize_body_override_params(params);
                if params.is_empty() {
                    None
                } else {
                    Some((model, params))
                }
            })
            .collect();
        if self.memory_token_budget == 0 {
            self.memory_token_budget = default_memory_token_budget();
        }
        for price in &mut self.model_prices {
            price.model = price.model.trim().to_string();
            if price.model.is_empty() {
                return Err(MicroClawError::Config(
                    "model_prices entries must include non-empty model".into(),
                ));
            }
            if !(price.input_per_million_usd.is_finite() && price.input_per_million_usd >= 0.0) {
                return Err(MicroClawError::Config(format!(
                    "model_prices[{}].input_per_million_usd must be >= 0",
                    price.model
                )));
            }
            if !(price.output_per_million_usd.is_finite() && price.output_per_million_usd >= 0.0) {
                return Err(MicroClawError::Config(format!(
                    "model_prices[{}].output_per_million_usd must be >= 0",
                    price.model
                )));
            }
        }

        // Synthesize `channels` map from legacy flat fields if empty
        if self.channels.is_empty() {
            if !self.telegram_bot_token.trim().is_empty() {
                self.channels.insert(
                    "telegram".into(),
                    serde_yaml::to_value(serde_json::json!({
                        "enabled": true,
                        "bot_token": self.telegram_bot_token,
                        "bot_username": self.bot_username,
                        "allowed_groups": self.allowed_groups,
                    }))
                    .unwrap(),
                );
            }
            if let Some(ref token) = self.discord_bot_token {
                if !token.trim().is_empty() {
                    self.channels.insert(
                        "discord".into(),
                        serde_yaml::to_value(serde_json::json!({
                            "enabled": true,
                            "bot_token": token,
                            "allowed_channels": self.discord_allowed_channels,
                            "no_mention": self.discord_no_mention,
                        }))
                        .unwrap(),
                    );
                }
            }
            if self.web_enabled {
                self.channels.insert(
                    "web".into(),
                    serde_yaml::to_value(serde_json::json!({
                        "enabled": true,
                        "host": self.web_host,
                        "port": self.web_port,
                        "auth_token": self.web_auth_token,
                    }))
                    .unwrap(),
                );
            }
        }

        // Validate required fields
        let configured_telegram =
            !self.telegram_bot_token.trim().is_empty() || self.channels.contains_key("telegram");
        let configured_discord = self
            .discord_bot_token
            .as_deref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            || self.channels.contains_key("discord");
        let configured_slack = self.channels.contains_key("slack");
        let configured_feishu = self.channels.contains_key("feishu");
        let configured_matrix = self.channels.contains_key("matrix");
        let configured_irc = self.channels.contains_key("irc");
        let configured_web = self.web_enabled || self.channels.contains_key("web");

        let has_telegram = self.channel_enabled("telegram") && configured_telegram;
        let has_discord = self.channel_enabled("discord") && configured_discord;
        let has_slack = self.channel_enabled("slack") && configured_slack;
        let has_feishu = self.channel_enabled("feishu") && configured_feishu;
        let has_matrix = self.channel_enabled("matrix") && configured_matrix;
        let has_irc = self.channel_enabled("irc") && configured_irc;
        let has_web = self.channel_enabled("web") && configured_web;

        if !(has_telegram
            || has_discord
            || has_slack
            || has_feishu
            || has_matrix
            || has_irc
            || has_web)
        {
            return Err(MicroClawError::Config(
                "At least one channel must be enabled and configured (via channels.<name>.enabled or legacy channel settings)".into(),
            ));
        }
        if self.api_key.is_empty() && !provider_allows_empty_api_key(&self.llm_provider) {
            return Err(MicroClawError::Config("api_key is required".into()));
        }
        if is_openai_codex_provider(&self.llm_provider) {
            if !self.api_key.trim().is_empty() {
                return Err(MicroClawError::Config(
                    "openai-codex ignores microclaw.config.yaml api_key. Configure ~/.codex/auth.json or run `codex login` instead.".into(),
                ));
            }
            if self
                .llm_base_url
                .as_ref()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(MicroClawError::Config(
                    "openai-codex ignores microclaw.config.yaml llm_base_url. Configure ~/.codex/config.toml instead.".into(),
                ));
            }
            let has_codex_auth = codex_auth_file_has_access_token()?;
            if !has_codex_auth {
                return Err(MicroClawError::Config(
                    "openai-codex requires ~/.codex/auth.json (access token or OPENAI_API_KEY), or OPENAI_CODEX_ACCESS_TOKEN. Run `codex login` or update Codex config files.".into(),
                ));
            }
        }

        Ok(())
    }

    /// Deserialize a typed channel config from the `channels` map.
    pub fn channel_config<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.channels
            .get(name)
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
    }

    pub fn model_price(&self, model: &str) -> Option<&ModelPrice> {
        let needle = model.trim();
        self.model_prices
            .iter()
            .find(|p| p.model.eq_ignore_ascii_case(needle))
            .or_else(|| self.model_prices.iter().find(|p| p.model == "*"))
    }

    pub fn estimate_cost_usd(
        &self,
        model: &str,
        input_tokens: i64,
        output_tokens: i64,
    ) -> Option<f64> {
        let price = self.model_price(model)?;
        let in_tok = input_tokens.max(0) as f64;
        let out_tok = output_tokens.max(0) as f64;
        Some(
            (in_tok / 1_000_000.0) * price.input_per_million_usd
                + (out_tok / 1_000_000.0) * price.output_per_million_usd,
        )
    }

    pub fn tool_timeout_secs(&self, tool_name: &str, fallback: u64) -> u64 {
        let normalized = tool_name.trim().to_ascii_lowercase();
        if let Some(timeout_secs) = self.tool_timeout_overrides.get(&normalized) {
            return *timeout_secs;
        }
        if self.default_tool_timeout_secs == 0 {
            fallback
        } else {
            self.default_tool_timeout_secs
        }
    }

    pub fn mcp_request_timeout_secs(&self) -> u64 {
        if self.default_mcp_request_timeout_secs == 0 {
            default_mcp_request_timeout_secs()
        } else {
            self.default_mcp_request_timeout_secs
        }
    }

    /// Save config as YAML to the given path.
    #[allow(dead_code)]
    pub fn save_yaml(&self, path: &str) -> Result<(), MicroClawError> {
        let content = serde_yaml::to_string(self)
            .map_err(|e| MicroClawError::Config(format!("Failed to serialize config: {e}")))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

fn normalize_body_override_params(
    params: HashMap<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    params
        .into_iter()
        .filter_map(|(key, value)| {
            let key = key.trim().to_string();
            if key.is_empty() {
                None
            } else {
                Some((key, value))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    #[test]
    fn test_clawhub_config_defaults() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.clawhub.registry, "https://clawhub.ai");
        assert!(config.clawhub.agent_tools_enabled);
    }

    #[test]
    fn test_voice_config_defaults() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.voice_provider, "openai");
        assert!(config.voice_transcription_command.is_none());
    }

    #[test]
    fn test_voice_config_local_provider() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
voice_provider: "local"
voice_transcription_command: "whisper-mlx --file {file}"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.voice_provider, "local");
        assert_eq!(
            config.voice_transcription_command,
            Some("whisper-mlx --file {file}".into())
        );
    }

    pub fn test_config() -> Config {
        Config::test_defaults()
    }

    #[test]
    fn test_config_struct_clone_and_debug() {
        let config = test_config();
        let cloned = config.clone();
        assert_eq!(cloned.telegram_bot_token, "tok");
        assert_eq!(cloned.max_tokens, 8192);
        assert_eq!(cloned.max_tool_iterations, 100);
        assert_eq!(cloned.max_history_messages, 50);
        assert_eq!(cloned.max_document_size_mb, 100);
        assert_eq!(cloned.memory_token_budget, 1500);
        assert!(cloned.openai_api_key.is_none());
        assert_eq!(cloned.timezone, "UTC");
        assert!(cloned.allowed_groups.is_empty());
        assert!(cloned.control_chat_ids.is_empty());
        assert_eq!(cloned.max_session_messages, 40);
        assert_eq!(cloned.compact_keep_recent, 20);
        assert_eq!(cloned.default_tool_timeout_secs, 30);
        assert!(cloned.tool_timeout_overrides.is_empty());
        assert_eq!(cloned.default_mcp_request_timeout_secs, 120);
        assert!(cloned.discord_bot_token.is_none());
        assert!(cloned.discord_allowed_channels.is_empty());
        let _ = format!("{:?}", config);
    }

    #[test]
    fn test_config_default_values() {
        let mut config = test_config();
        config.openai_api_key = Some("sk-test".into());
        config.timezone = "US/Eastern".into();
        config.allowed_groups = vec![123, 456];
        config.control_chat_ids = vec![999];
        assert_eq!(config.model, "claude-sonnet-4-5-20250929");
        assert!(config.data_dir.ends_with(".microclaw"));
        assert!(std::path::PathBuf::from(&config.working_dir)
            .ends_with(std::path::Path::new(".microclaw").join("working_dir")));
        assert_eq!(config.openai_api_key.as_deref(), Some("sk-test"));
        assert_eq!(config.timezone, "US/Eastern");
        assert_eq!(config.allowed_groups, vec![123, 456]);
        assert_eq!(config.control_chat_ids, vec![999]);
    }

    #[test]
    fn test_config_yaml_roundtrip() {
        let config = test_config();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.telegram_bot_token, "tok");
        assert_eq!(parsed.max_tokens, 8192);
        assert_eq!(parsed.llm_provider, "anthropic");
    }

    #[test]
    fn test_config_yaml_defaults() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.llm_provider, "anthropic");
        assert_eq!(config.max_tokens, 8192);
        assert_eq!(config.max_tool_iterations, 100);
        assert!(config.data_dir.ends_with(".microclaw"));
        assert!(std::path::PathBuf::from(&config.working_dir)
            .ends_with(std::path::Path::new(".microclaw").join("working_dir")));
        assert_eq!(config.memory_token_budget, 1500);
        assert!(matches!(
            config.working_dir_isolation,
            WorkingDirIsolation::Chat
        ));
        assert!(matches!(config.sandbox.mode, SandboxMode::Off));
        assert_eq!(config.max_document_size_mb, 100);
        assert_eq!(config.timezone, "UTC");
        assert_eq!(config.default_tool_timeout_secs, 30);
        assert!(config.tool_timeout_overrides.is_empty());
        assert_eq!(config.default_mcp_request_timeout_secs, 120);
        assert!(config.web_fetch_validation.enabled);
        assert!(config.web_fetch_validation.strict_mode);
        assert_eq!(config.web_fetch_validation.max_scan_bytes, 100_000);
        assert!(config.web_fetch_url_validation.enabled);
        assert_eq!(
            config.web_fetch_url_validation.allowed_schemes,
            vec!["https".to_string(), "http".to_string()]
        );
        assert!(config.web_fetch_url_validation.allowlist_hosts.is_empty());
        assert!(config.web_fetch_url_validation.denylist_hosts.is_empty());
    }

    #[test]
    fn test_post_deserialize_timeout_defaults_and_overrides() {
        let mut config = test_config();
        config.default_tool_timeout_secs = 0;
        config.default_mcp_request_timeout_secs = 0;
        config.web_fetch_validation.max_scan_bytes = 0;
        config.web_fetch_url_validation.allowed_schemes.clear();
        config.web_fetch_url_validation.allowlist_hosts = vec!["  Example.COM  ".into()];
        config.web_fetch_url_validation.denylist_hosts = vec![" .Bad.EXAMPLE ".into()];
        config.tool_timeout_overrides = HashMap::from([
            ("  bash ".to_string(), 90),
            ("".to_string(), 5),
            ("browser".to_string(), 0),
        ]);
        config.post_deserialize().unwrap();

        assert_eq!(config.default_tool_timeout_secs, 30);
        assert_eq!(config.default_mcp_request_timeout_secs, 120);
        assert_eq!(config.web_fetch_validation.max_scan_bytes, 100_000);
        assert_eq!(
            config.web_fetch_url_validation.allowed_schemes,
            vec!["https".to_string(), "http".to_string()]
        );
        assert_eq!(
            config.web_fetch_url_validation.allowlist_hosts,
            vec!["example.com".to_string()]
        );
        assert_eq!(
            config.web_fetch_url_validation.denylist_hosts,
            vec!["bad.example".to_string()]
        );
        assert_eq!(config.tool_timeout_overrides.len(), 1);
        assert_eq!(config.tool_timeout_overrides.get("bash"), Some(&90));
    }

    #[test]
    fn test_tool_timeout_lookup_prefers_override_then_default() {
        let mut config = test_config();
        config.default_tool_timeout_secs = 45;
        config.tool_timeout_overrides.insert("bash".to_string(), 75);

        assert_eq!(config.tool_timeout_secs("bash", 120), 75);
        assert_eq!(config.tool_timeout_secs("browser", 120), 45);
    }

    #[test]
    fn test_default_data_dir_uses_microclaw_home() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.data_dir.ends_with(".microclaw"));
    }

    #[test]
    fn test_config_sandbox_defaults_to_off() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(config.sandbox.mode, SandboxMode::Off));
        assert!(matches!(config.sandbox.backend, SandboxBackend::Auto));
        assert_eq!(config.sandbox.image, "ubuntu:25.10");
    }

    #[test]
    fn test_post_deserialize_empty_working_dir_uses_default() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nworking_dir: '  '\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert!(std::path::PathBuf::from(&config.working_dir)
            .ends_with(std::path::Path::new(".microclaw").join("working_dir")));
    }

    #[test]
    fn test_post_deserialize_zero_memory_budget_uses_default() {
        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nmemory_token_budget: 0\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.memory_token_budget, 1500);
    }

    #[test]
    fn test_config_working_dir_isolation_defaults_to_chat() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            config.working_dir_isolation,
            WorkingDirIsolation::Chat
        ));
    }

    #[test]
    fn test_config_working_dir_isolation_accepts_chat() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nworking_dir_isolation: chat\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            config.working_dir_isolation,
            WorkingDirIsolation::Chat
        ));
    }

    #[test]
    fn test_config_post_deserialize() {
        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nllm_provider: ANTHROPIC\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.llm_provider, "anthropic");
        assert_eq!(config.model, "claude-sonnet-4-5-20250929");
    }

    #[test]
    fn test_runtime_and_skills_dirs_from_root_data_dir() {
        let mut config = test_config();
        config.data_dir = "./microclaw.data".into();

        let runtime = std::path::PathBuf::from(config.runtime_data_dir());
        let skills = std::path::PathBuf::from(config.skills_data_dir());

        assert!(runtime.ends_with(std::path::Path::new("microclaw.data").join("runtime")));
        assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
    }

    #[test]
    fn test_runtime_and_skills_dirs_from_runtime_data_dir() {
        let mut config = test_config();
        config.data_dir = "./microclaw.data/runtime".into();

        let runtime = std::path::PathBuf::from(config.runtime_data_dir());
        let skills = std::path::PathBuf::from(config.skills_data_dir());

        assert!(runtime.ends_with(
            std::path::Path::new("microclaw.data")
                .join("runtime")
                .join("runtime")
        ));
        assert!(skills.ends_with(
            std::path::Path::new("microclaw.data")
                .join("runtime")
                .join("skills")
        ));
    }

    #[test]
    fn test_skills_dir_uses_config_override() {
        let mut config = test_config();
        config.skills_dir = Some("./microclaw.data/skills".to_string());
        let skills = std::path::PathBuf::from(config.skills_data_dir());
        assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
    }

    #[test]
    fn test_post_deserialize_invalid_timezone() {
        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\napi_key: key\ntimezone: Mars/Olympus\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Invalid timezone"));
    }

    #[test]
    fn test_post_deserialize_missing_api_key() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("api_key is required"));
    }

    #[test]
    fn test_post_deserialize_openai_codex_allows_empty_api_key() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(
            auth_dir.join("auth.json"),
            r#"{"tokens":{"access_token":"tok"}}"#,
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\nllm_provider: openai-codex\nmodel: gpt-5.3-codex\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

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
        assert_eq!(config.llm_provider, "openai-codex");
    }

    #[test]
    fn test_post_deserialize_missing_bot_tokens() {
        let yaml = "bot_username: bot\napi_key: key\nweb_enabled: false\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("channel must be enabled"));
    }

    #[test]
    fn test_post_deserialize_discord_only() {
        let yaml = "bot_username: bot\napi_key: key\ndiscord_bot_token: discord_tok\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        // Should succeed: discord_bot_token is set even though telegram_bot_token is empty
        config.post_deserialize().unwrap();
    }

    #[test]
    fn test_post_deserialize_irc_only() {
        let yaml = r##"
api_key: key
channels:
  irc:
    enabled: true
    server: "irc.example.com"
    nick: "microclaw"
    channels: "#microclaw"
"##;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert!(config.channel_enabled("irc"));
    }

    #[test]
    fn test_post_deserialize_matrix_only() {
        let yaml = r##"
api_key: key
channels:
  matrix:
    enabled: true
    homeserver_url: "https://matrix.example.com"
    access_token: "syt_xxx"
    bot_user_id: "@microclaw:example.com"
"##;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert!(config.channel_enabled("matrix"));
    }

    #[test]
    fn test_post_deserialize_channel_enabled_flag_overrides_legacy_inference() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\ndiscord_bot_token: discord_tok\napi_key: key\nchannels:\n  telegram:\n    enabled: false\n  discord:\n    enabled: true\n  web:\n    enabled: false\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        assert!(!config.channel_enabled("telegram"));
        assert!(config.channel_enabled("discord"));
        assert!(!config.channel_enabled("web"));
    }

    #[test]
    fn test_post_deserialize_channel_enabled_flag_controls_web() {
        let yaml =
            "api_key: key\ndiscord_bot_token: discord_tok\nchannels:\n  web:\n    enabled: false\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        assert!(!config.channel_enabled("web"));
    }

    #[test]
    fn test_post_deserialize_openai_default_model() {
        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nllm_provider: openai\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.model, "gpt-5.2");
    }

    #[test]
    fn test_post_deserialize_openai_codex_default_model() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(
            auth_dir.join("auth.json"),
            r#"{"tokens":{"access_token":"tok"}}"#,
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: openai-codex\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

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
        assert_eq!(config.model, "gpt-5.3-codex");
    }

    #[test]
    fn test_post_deserialize_openai_codex_missing_oauth_token() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-missing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: openai-codex\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();

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
        let _ = std::fs::remove_dir(auth_dir);

        assert!(msg.contains("openai-codex requires ~/.codex/auth.json"));
    }

    #[test]
    fn test_post_deserialize_openai_codex_rejects_plain_api_key_without_oauth() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-plain-key-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: openai-codex\napi_key: sk-user-stale\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();

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
        let _ = std::fs::remove_dir(auth_dir);

        assert!(msg.contains("ignores microclaw.config.yaml api_key"));
    }

    #[test]
    fn test_post_deserialize_openai_codex_allows_env_access_token() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        std::env::remove_var("CODEX_HOME");
        std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", "env-token");

        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: openai-codex\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

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

        assert_eq!(config.llm_provider, "openai-codex");
    }

    #[test]
    fn test_post_deserialize_ollama_default_model_and_empty_key() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: ollama\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.model, "llama3.2");
    }

    #[test]
    fn test_post_deserialize_empty_base_url_becomes_none() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nllm_base_url: '  '\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert!(config.llm_base_url.is_none());
    }

    #[test]
    fn test_post_deserialize_provider_case_insensitive() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nllm_provider: '  ANTHROPIC  '\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.llm_provider, "anthropic");
        assert_eq!(config.model, "claude-sonnet-4-5-20250929");
    }

    #[test]
    fn test_post_deserialize_normalizes_openai_compat_body_overrides() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
openai_compat_body_overrides:
  " temperature ": 0.2
  "  ": 1
openai_compat_body_overrides_by_provider:
  " OPENAI ":
    " top_p ": 0.95
    "": 1
  "  ":
    seed: 7
openai_compat_body_overrides_by_model:
  " gpt-5.2 ":
    " frequency_penalty ": 0.1
    "": 1
  " ":
    seed: 7
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        assert_eq!(
            config.openai_compat_body_overrides.get("temperature"),
            Some(&serde_json::json!(0.2))
        );
        assert!(!config.openai_compat_body_overrides.contains_key("  "));

        let provider_params = config
            .openai_compat_body_overrides_by_provider
            .get("openai")
            .unwrap();
        assert_eq!(provider_params.get("top_p"), Some(&serde_json::json!(0.95)));
        assert!(!provider_params.contains_key(""));
        assert!(!config
            .openai_compat_body_overrides_by_provider
            .contains_key(" OPENAI "));

        let model_params = config
            .openai_compat_body_overrides_by_model
            .get("gpt-5.2")
            .unwrap();
        assert_eq!(
            model_params.get("frequency_penalty"),
            Some(&serde_json::json!(0.1))
        );
        assert!(!model_params.contains_key(""));
    }

    #[test]
    fn test_post_deserialize_web_non_local_requires_token() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nweb_enabled: true\nweb_host: 0.0.0.0\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        assert!(err
            .to_string()
            .contains("web_auth_token is required when web channel is enabled"));
    }

    #[test]
    fn test_post_deserialize_web_non_local_with_token_ok() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nweb_enabled: true\nweb_host: 0.0.0.0\nweb_auth_token: token123\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.web_auth_token.as_deref(), Some("token123"));
    }

    #[test]
    fn test_model_prices_parse_and_estimate() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
model_prices:
  - model: claude-sonnet-4-5-20250929
    input_per_million_usd: 3.0
    output_per_million_usd: 15.0
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        let est = config
            .estimate_cost_usd("claude-sonnet-4-5-20250929", 1000, 2000)
            .unwrap();
        assert!((est - 0.033).abs() < 1e-9);
    }

    #[test]
    fn test_model_prices_invalid_rejected() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
model_prices:
  - model: ""
    input_per_million_usd: 1.0
    output_per_million_usd: 1.0
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        assert!(err
            .to_string()
            .contains("model_prices entries must include non-empty model"));
    }

    #[test]
    fn test_config_yaml_with_all_optional_fields() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
openai_api_key: sk-test
timezone: US/Eastern
allowed_groups: [123, 456]
control_chat_ids: [999]
max_session_messages: 60
compact_keep_recent: 30
discord_bot_token: discord_tok
discord_allowed_channels: [111, 222]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.openai_api_key.as_deref(), Some("sk-test"));
        assert_eq!(config.timezone, "US/Eastern");
        assert_eq!(config.allowed_groups, vec![123, 456]);
        assert_eq!(config.control_chat_ids, vec![999]);
        assert_eq!(config.max_session_messages, 60);
        assert_eq!(config.compact_keep_recent, 30);
        assert_eq!(config.discord_allowed_channels, vec![111, 222]);
    }

    #[test]
    fn test_config_save_yaml() {
        let config = test_config();
        let dir = std::env::temp_dir();
        let path = dir.join("microclaw_test_config.yaml");
        config.save_yaml(path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("telegram_bot_token"));
        std::fs::remove_file(path).ok();
    }
}
