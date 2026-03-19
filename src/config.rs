use std::collections::HashMap;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::codex_auth::{
    codex_auth_file_has_access_token, is_openai_codex_provider, is_qwen_portal_provider,
    provider_allows_empty_api_key, qwen_oauth_file_has_access_token,
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
fn default_llm_user_agent() -> String {
    crate::http_client::default_llm_user_agent()
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

/// Expands a path string, replacing `~` with the user's home directory.
fn expand_path(path: &str) -> PathBuf {
    match shellexpand::tilde(path) {
        std::borrow::Cow::Borrowed(p) => PathBuf::from(p),
        std::borrow::Cow::Owned(p) => PathBuf::from(p),
    }
}

fn default_data_root() -> PathBuf {
    expand_path("~/.microclaw")
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
fn default_high_risk_tool_user_confirmation_required() -> bool {
    true
}
fn default_sandbox_image() -> String {
    "ubuntu:25.10".into()
}
fn default_sandbox_container_prefix() -> String {
    "microclaw-sandbox".into()
}
fn default_timezone() -> String {
    "auto".into()
}

fn detect_system_timezone() -> String {
    match iana_time_zone::get_timezone() {
        Ok(tz_name) => tz_name,
        Err(e) => {
            warn!("Failed to detect system timezone automatically: {e}. Falling back to UTC.");
            "UTC".into()
        }
    }
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
    10
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
fn default_subagent_max_concurrent() -> usize {
    4
}
fn default_subagent_max_active_per_chat() -> usize {
    5
}
fn default_subagent_run_timeout_secs() -> u64 {
    900
}
fn default_subagent_announce() -> bool {
    true
}
fn default_subagent_max_spawn_depth() -> usize {
    1
}
fn default_subagent_max_children_per_run() -> usize {
    5
}
fn default_subagent_thread_bound_routing_enabled() -> bool {
    true
}
fn default_subagent_announce_relay_interval_secs() -> u64 {
    15
}
fn default_subagent_max_tokens_per_run() -> i64 {
    400_000
}
fn default_subagent_orchestrate_max_workers() -> usize {
    5
}
fn default_subagent_acp_auto_approve() -> bool {
    true
}
fn default_a2a_enabled() -> bool {
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
fn default_souls_dir() -> Option<String> {
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelPrice {
    pub model: String,
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LlmProviderProfile {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub llm_base_url: Option<String>,
    #[serde(default)]
    pub llm_user_agent: Option<String>,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub show_thinking: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct ResolvedLlmProviderProfile {
    pub alias: String,
    pub provider: String,
    pub api_key: String,
    pub llm_base_url: Option<String>,
    pub llm_user_agent: String,
    pub default_model: String,
    pub models: Vec<String>,
    pub show_thinking: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubagentAcpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default = "default_subagent_acp_auto_approve")]
    pub auto_approve: bool,
}

impl Default for SubagentAcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: String::new(),
            args: Vec::new(),
            env: HashMap::new(),
            auto_approve: default_subagent_acp_auto_approve(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubagentConfig {
    #[serde(default = "default_subagent_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_subagent_max_active_per_chat")]
    pub max_active_per_chat: usize,
    #[serde(default = "default_subagent_run_timeout_secs")]
    pub run_timeout_secs: u64,
    #[serde(default = "default_subagent_announce")]
    pub announce_to_chat: bool,
    #[serde(default = "default_subagent_max_spawn_depth")]
    pub max_spawn_depth: usize,
    #[serde(default = "default_subagent_max_children_per_run")]
    pub max_children_per_run: usize,
    #[serde(default = "default_subagent_thread_bound_routing_enabled")]
    pub thread_bound_routing_enabled: bool,
    #[serde(default = "default_subagent_announce_relay_interval_secs")]
    pub announce_relay_interval_secs: u64,
    #[serde(default = "default_subagent_max_tokens_per_run")]
    pub max_tokens_per_run: i64,
    #[serde(default = "default_subagent_orchestrate_max_workers")]
    pub orchestrate_max_workers: usize,
    #[serde(default)]
    pub acp: SubagentAcpConfig,
}

impl Default for SubagentConfig {
    fn default() -> Self {
        Self {
            max_concurrent: default_subagent_max_concurrent(),
            max_active_per_chat: default_subagent_max_active_per_chat(),
            run_timeout_secs: default_subagent_run_timeout_secs(),
            announce_to_chat: default_subagent_announce(),
            max_spawn_depth: default_subagent_max_spawn_depth(),
            max_children_per_run: default_subagent_max_children_per_run(),
            thread_bound_routing_enabled: default_subagent_thread_bound_routing_enabled(),
            announce_relay_interval_secs: default_subagent_announce_relay_interval_secs(),
            max_tokens_per_run: default_subagent_max_tokens_per_run(),
            orchestrate_max_workers: default_subagent_orchestrate_max_workers(),
            acp: SubagentAcpConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct A2APeerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_session_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A2AConfig {
    #[serde(default = "default_a2a_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub agent_description: Option<String>,
    #[serde(default)]
    pub shared_tokens: Vec<String>,
    #[serde(default)]
    pub peers: HashMap<String, A2APeerConfig>,
}

impl Default for A2AConfig {
    fn default() -> Self {
        Self {
            enabled: default_a2a_enabled(),
            public_base_url: None,
            agent_name: None,
            agent_description: None,
            shared_tokens: Vec::new(),
            peers: HashMap::new(),
        }
    }
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
    pub provider_presets: HashMap<String, LlmProviderProfile>,
    #[serde(default)]
    pub llm_providers: HashMap<String, LlmProviderProfile>,
    #[serde(default)]
    pub llm_base_url: Option<String>,
    #[serde(default = "default_llm_user_agent")]
    pub llm_user_agent: String,
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
    #[serde(default)]
    pub subagents: SubagentConfig,
    #[serde(default)]
    pub a2a: A2AConfig,
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
    #[serde(default = "default_high_risk_tool_user_confirmation_required")]
    pub high_risk_tool_user_confirmation_required: bool,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_timezone: Option<String>,
    #[serde(default = "default_timezone", skip_serializing)]
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
    /// Directory for per-bot SOUL files. Defaults to <data_dir>/souls when unset.
    #[serde(default = "default_souls_dir")]
    pub souls_dir: Option<String>,

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

    // --- Observability ---
    #[serde(default)]
    pub observability: Option<serde_yaml::Value>,

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
    fn ensure_mapping_mut(value: &mut serde_yaml::Value) -> &mut serde_yaml::Mapping {
        if !matches!(value, serde_yaml::Value::Mapping(_)) {
            *value = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        value
            .as_mapping_mut()
            .expect("value should be a mapping after initialization")
    }

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

    fn llm_override_target(&self, channel: &str) -> Option<(String, Option<String>)> {
        let channel = channel.trim();
        if channel.is_empty() {
            return None;
        }
        if let Some((base_channel, account_id)) = channel.split_once('.') {
            let base_channel = base_channel.trim();
            let account_id = account_id.trim();
            if base_channel.is_empty() || account_id.is_empty() {
                return None;
            }
            return Some((base_channel.to_string(), Some(account_id.to_string())));
        }

        Some((
            channel.to_string(),
            self.channel_default_account_id(channel),
        ))
    }

    fn llm_override_mapping_mut(&mut self, channel: &str) -> Option<&mut serde_yaml::Mapping> {
        let (base_channel, account_id) = self.llm_override_target(channel)?;
        let channel_value = self
            .channels
            .entry(base_channel)
            .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        let channel_map = Self::ensure_mapping_mut(channel_value);
        if let Some(account_id) = account_id {
            let accounts_key = serde_yaml::Value::String("accounts".to_string());
            let accounts_value = channel_map
                .entry(accounts_key)
                .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
            let accounts_map = Self::ensure_mapping_mut(accounts_value);
            let account_value = accounts_map
                .entry(serde_yaml::Value::String(account_id))
                .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
            return Some(Self::ensure_mapping_mut(account_value));
        }
        Some(channel_map)
    }

    pub fn set_provider_override_for_channel(&mut self, channel: &str, provider: Option<&str>) {
        let Some(target) = self.llm_override_mapping_mut(channel) else {
            return;
        };
        let provider_preset_key = serde_yaml::Value::String("provider_preset".to_string());
        let llm_provider_key = serde_yaml::Value::String("llm_provider".to_string());
        target.remove(&provider_preset_key);
        target.remove(&llm_provider_key);
        if let Some(provider) = provider
            .map(str::trim)
            .filter(|provider| !provider.is_empty())
            .map(|provider| provider.to_ascii_lowercase())
        {
            target.insert(
                provider_preset_key,
                serde_yaml::Value::String(provider.to_string()),
            );
        }
    }

    pub fn set_model_override_for_channel(&mut self, channel: &str, model: Option<&str>) {
        let Some(target) = self.llm_override_mapping_mut(channel) else {
            return;
        };
        let model_key = serde_yaml::Value::String("model".to_string());
        target.remove(&model_key);
        if let Some(model) = model.map(str::trim).filter(|model| !model.is_empty()) {
            target.insert(model_key, serde_yaml::Value::String(model.to_string()));
        }
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

    fn channel_account_soul_path(&self, channel: &str, account_id: &str) -> Option<String> {
        self.channels
            .get(channel)
            .and_then(|v| v.get("accounts"))
            .and_then(|v| v.get(account_id))
            .and_then(|v| v.get("soul_path"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
    }

    fn provider_override_from_value(value: &serde_yaml::Value) -> Option<String> {
        value
            .get("provider_preset")
            .and_then(|v| v.as_str())
            .or_else(|| value.get("llm_provider").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase())
    }

    fn channel_account_provider_override(&self, channel: &str, account_id: &str) -> Option<String> {
        self.channels
            .get(channel)
            .and_then(|v| v.get("accounts"))
            .and_then(|v| v.get(account_id))
            .and_then(Self::provider_override_from_value)
    }

    fn model_override_from_value(value: &serde_yaml::Value) -> Option<String> {
        value
            .get("model")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
    }

    fn channel_account_model_override(&self, channel: &str, account_id: &str) -> Option<String> {
        self.channels
            .get(channel)
            .and_then(|v| v.get("accounts"))
            .and_then(|v| v.get(account_id))
            .and_then(Self::model_override_from_value)
    }

    pub fn provider_override_for_channel(&self, channel: &str) -> Option<String> {
        if let Some((base_channel, account_id)) = channel.split_once('.') {
            if let Some(v) = self.channel_account_provider_override(base_channel, account_id) {
                return Some(v);
            }
            return self
                .channels
                .get(base_channel)
                .and_then(Self::provider_override_from_value);
        }

        if let Some(default_account) = self.channel_default_account_id(channel) {
            if let Some(v) = self.channel_account_provider_override(channel, &default_account) {
                return Some(v);
            }
        }

        self.channels
            .get(channel)
            .and_then(Self::provider_override_from_value)
    }

    pub fn model_override_for_channel(&self, channel: &str) -> Option<String> {
        if let Some((base_channel, account_id)) = channel.split_once('.') {
            if let Some(v) = self.channel_account_model_override(base_channel, account_id) {
                return Some(v);
            }
            return self
                .channels
                .get(base_channel)
                .and_then(Self::model_override_from_value);
        }

        if let Some(default_account) = self.channel_default_account_id(channel) {
            if let Some(v) = self.channel_account_model_override(channel, &default_account) {
                return Some(v);
            }
        }

        self.channels
            .get(channel)
            .and_then(Self::model_override_from_value)
    }

    pub fn soul_path_for_channel(&self, channel: &str) -> Option<String> {
        let channel_override = self
            .channels
            .get(channel)
            .and_then(|v| v.get("soul_path"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned);
        if channel_override.is_some() {
            return channel_override;
        }

        if let Some((base_channel, account_id)) = channel.split_once('.') {
            if let Some(v) = self.channel_account_soul_path(base_channel, account_id) {
                return Some(v);
            }
            return self
                .channels
                .get(base_channel)
                .and_then(|v| v.get("soul_path"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned);
        }

        if let Some(default_account) = self.channel_default_account_id(channel) {
            if let Some(v) = self.channel_account_soul_path(channel, &default_account) {
                return Some(v);
            }
        }

        self.channels
            .get(channel)
            .and_then(|v| v.get("soul_path"))
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

    pub fn llm_provider_overrides(&self) -> HashMap<String, String> {
        let mut overrides: HashMap<String, String> = self
            .channels
            .iter()
            .filter_map(|(channel, cfg)| {
                Self::provider_override_from_value(cfg).map(|provider| (channel.clone(), provider))
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
                let Some(provider) = Self::provider_override_from_value(value) else {
                    continue;
                };
                if default_account
                    .as_deref()
                    .map(|v| v == account_id)
                    .unwrap_or(false)
                {
                    overrides.insert(channel.clone(), provider);
                } else {
                    overrides.insert(format!("{channel}.{account_id}"), provider);
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
            provider_presets: HashMap::new(),
            llm_providers: HashMap::new(),
            llm_base_url: None,
            llm_user_agent: default_llm_user_agent(),
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
            high_risk_tool_user_confirmation_required: true,
            sandbox: SandboxConfig::default(),
            openai_api_key: None,
            override_timezone: None,
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
            subagents: SubagentConfig::default(),
            a2a: A2AConfig::default(),
            openai_compat_body_overrides: HashMap::new(),
            openai_compat_body_overrides_by_provider: HashMap::new(),
            openai_compat_body_overrides_by_model: HashMap::new(),
            web_enabled: true,
            web_host: "127.0.0.1".into(),
            web_port: 10961,
            web_max_inflight_per_session: 10,
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
            souls_dir: None,
            clawhub: ClawHubConfig::default(),
            plugins: PluginsConfig::default(),
            voice_provider: "openai".into(),
            voice_transcription_command: None,
            observability: None,
            channels: HashMap::new(),
        }
    }

    /// Data root directory from config.
    pub fn data_root_dir(&self) -> PathBuf {
        expand_path(&self.data_dir)
    }

    /// Runtime data directory (db, memory, exports, etc.).
    pub fn runtime_data_dir(&self) -> String {
        let root = self.data_root_dir();
        // Avoid nested runtime/runtime if data_dir is already runtime
        if root.file_name().and_then(|n| n.to_str()) == Some("runtime") {
            return root.to_string_lossy().to_string();
        }
        root.join("runtime").to_string_lossy().to_string()
    }

    /// Skills directory. Priority: MICROCLAW_SKILLS_DIR env var > skills_dir config > <data_dir>/skills
    pub fn skills_data_dir(&self) -> String {
        // 1. Check env var first
        if let Ok(explicit_dir) = std::env::var("MICROCLAW_SKILLS_DIR") {
            let trimmed = explicit_dir.trim();
            if !trimmed.is_empty() {
                return expand_path(trimmed).to_string_lossy().to_string();
            }
        }
        // 2. Check config file
        if let Some(configured) = &self.skills_dir {
            let trimmed = configured.trim();
            if !trimmed.is_empty() {
                return expand_path(trimmed).to_string_lossy().to_string();
            }
        }
        // 3. Default to <data_dir>/skills
        self.data_root_dir()
            .join("skills")
            .to_string_lossy()
            .to_string()
    }

    /// Souls directory. Priority: souls_dir config > <data_dir>/souls
    pub fn souls_data_dir(&self) -> String {
        if let Some(configured) = &self.souls_dir {
            let trimmed = configured.trim();
            if !trimmed.is_empty() {
                return expand_path(trimmed).to_string_lossy().to_string();
            }
        }
        self.data_root_dir()
            .join("souls")
            .to_string_lossy()
            .to_string()
    }

    pub fn clawhub_lockfile_path(&self) -> PathBuf {
        self.data_root_dir().join("clawhub.lock.json")
    }

    pub fn resolve_config_path() -> Result<Option<PathBuf>, MicroClawError> {
        // 1. Check MICROCLAW_CONFIG env var for custom path
        if let Ok(custom) = std::env::var("MICROCLAW_CONFIG") {
            let expanded = expand_path(&custom);
            if expanded.exists() {
                return Ok(Some(expanded));
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
            if let Ok(raw) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                if let Some(map) = raw.as_mapping() {
                    let old_top_level = map
                        .get(serde_yaml::Value::String("web_auth_token".to_string()))
                        .is_some();
                    let old_channel_level = map
                        .get(serde_yaml::Value::String("channels".to_string()))
                        .and_then(|v| v.as_mapping())
                        .and_then(|channels| {
                            channels.get(serde_yaml::Value::String("web".to_string()))
                        })
                        .and_then(|v| v.as_mapping())
                        .map(|web| {
                            web.contains_key(serde_yaml::Value::String("auth_token".to_string()))
                        })
                        .unwrap_or(false);
                    if old_top_level || old_channel_level {
                        warn!(
                            "Deprecated web auth token config detected in {}. \
`web_auth_token` / `channels.web.auth_token` are ignored; migrate to operator password + API keys.",
                            path_str
                        );
                    }
                }
            }
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
        self.model = self.model.trim().to_string();
        if self.model.is_empty() {
            self.model = "gpt-5.2".into();
        }
        self.provider_presets =
            normalize_provider_profiles(std::mem::take(&mut self.provider_presets));
        self.llm_providers = normalize_provider_profiles(std::mem::take(&mut self.llm_providers));
        for (alias, preset) in self.provider_presets.clone() {
            self.llm_providers
                .entry(alias)
                .and_modify(|existing| {
                    *existing = merge_provider_profile(preset.clone(), existing.clone());
                })
                .or_insert(preset);
        }
        for channel_cfg in self.channels.values_mut() {
            migrate_model_override_alias_to_provider_preset(channel_cfg, &self.provider_presets);
        }

        self.override_timezone = self
            .override_timezone
            .as_ref()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        if self
            .override_timezone
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("auto"))
        {
            self.override_timezone = None;
        }

        // Normalize and validate timezone.
        // Priority: override_timezone > system auto-detect.
        let tz_raw = self
            .override_timezone
            .clone()
            .unwrap_or_else(|| "auto".to_string());

        if tz_raw.eq_ignore_ascii_case("auto") {
            let detected = detect_system_timezone();
            if detected.parse::<chrono_tz::Tz>().is_ok() {
                self.timezone = detected;
            } else {
                warn!(
                    "Detected system timezone '{}' is not recognized by chrono-tz. Falling back to UTC.",
                    detected
                );
                self.timezone = "UTC".into();
            }
        } else {
            tz_raw
                .parse::<chrono_tz::Tz>()
                .map_err(|_| MicroClawError::Config(format!("Invalid timezone: {tz_raw}")))?;
            self.timezone = tz_raw;
        }

        // Filter empty llm_base_url
        if let Some(ref url) = self.llm_base_url {
            if url.trim().is_empty() {
                self.llm_base_url = None;
            }
        }
        self.llm_user_agent = self.llm_user_agent.trim().to_string();
        if self.llm_user_agent.is_empty() {
            self.llm_user_agent = default_llm_user_agent();
        }
        if let Some(dir) = &self.skills_dir {
            let trimmed = dir.trim().to_string();
            self.skills_dir = if trimmed.is_empty() {
                None
            } else {
                Some(expand_path(&trimmed).to_string_lossy().to_string())
            };
        }
        if let Some(dir) = &self.souls_dir {
            let trimmed = dir.trim().to_string();
            self.souls_dir = if trimmed.is_empty() {
                None
            } else {
                Some(expand_path(&trimmed).to_string_lossy().to_string())
            };
        }
        if let Some(dir) = &self.plugins.dir {
            let trimmed = dir.trim().to_string();
            self.plugins.dir = if trimmed.is_empty() {
                None
            } else {
                Some(expand_path(&trimmed).to_string_lossy().to_string())
            };
        }
        if self.working_dir.trim().is_empty() {
            self.working_dir = default_working_dir();
        } else {
            self.working_dir = expand_path(&self.working_dir).to_string_lossy().to_string();
        }
        self.data_dir = expand_path(&self.data_dir).to_string_lossy().to_string();
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
        self.a2a.public_base_url = self
            .a2a
            .public_base_url
            .as_ref()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());
        self.a2a.agent_name = self
            .a2a
            .agent_name
            .as_ref()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        self.a2a.agent_description = self
            .a2a
            .agent_description
            .as_ref()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        self.a2a.shared_tokens = self
            .a2a
            .shared_tokens
            .drain(..)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        self.a2a.peers = self
            .a2a
            .peers
            .drain()
            .filter_map(|(name, mut peer)| {
                let normalized = name.trim().to_ascii_lowercase();
                if normalized.is_empty() {
                    return None;
                }
                peer.base_url = peer.base_url.trim().trim_end_matches('/').to_string();
                if peer.base_url.is_empty() {
                    return None;
                }
                peer.bearer_token = peer
                    .bearer_token
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());
                peer.description = peer
                    .description
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());
                peer.default_session_key = peer
                    .default_session_key
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());
                Some((normalized, peer))
            })
            .collect();
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
        if let Some(web_cfg) = self
            .channels
            .get_mut("web")
            .and_then(|v| v.as_mapping_mut())
        {
            if web_cfg
                .remove(serde_yaml::Value::String("auth_token".to_string()))
                .is_some()
            {
                warn!(
                    "Deprecated `channels.web.auth_token` detected and ignored. \
Use operator password + API keys for Web auth."
                );
            }
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
        if self.subagents.max_concurrent == 0 {
            self.subagents.max_concurrent = default_subagent_max_concurrent();
        }
        if self.subagents.max_active_per_chat == 0 {
            self.subagents.max_active_per_chat = default_subagent_max_active_per_chat();
        }
        if self.subagents.run_timeout_secs == 0 {
            self.subagents.run_timeout_secs = default_subagent_run_timeout_secs();
        }
        if self.subagents.max_spawn_depth == 0 {
            self.subagents.max_spawn_depth = default_subagent_max_spawn_depth();
        }
        self.subagents.max_spawn_depth = self.subagents.max_spawn_depth.min(5);
        if self.subagents.max_children_per_run == 0 {
            self.subagents.max_children_per_run = default_subagent_max_children_per_run();
        }
        if self.subagents.announce_relay_interval_secs == 0 {
            self.subagents.announce_relay_interval_secs =
                default_subagent_announce_relay_interval_secs();
        }
        self.subagents.announce_relay_interval_secs =
            self.subagents.announce_relay_interval_secs.clamp(1, 300);
        if self.subagents.max_tokens_per_run <= 0 {
            self.subagents.max_tokens_per_run = default_subagent_max_tokens_per_run();
        }
        self.subagents.max_tokens_per_run =
            self.subagents.max_tokens_per_run.clamp(2_000, 2_000_000);
        if self.subagents.orchestrate_max_workers == 0 {
            self.subagents.orchestrate_max_workers = default_subagent_orchestrate_max_workers();
        }
        self.subagents.orchestrate_max_workers =
            self.subagents.orchestrate_max_workers.clamp(1, 12);
        self.subagents.acp.command = self.subagents.acp.command.trim().to_string();
        self.subagents.acp.args = self
            .subagents
            .acp
            .args
            .drain(..)
            .map(|arg| arg.trim().to_string())
            .filter(|arg| !arg.is_empty())
            .collect();
        self.subagents.acp.env = self
            .subagents
            .acp
            .env
            .drain()
            .filter_map(|(key, value)| {
                let normalized = key.trim().to_string();
                if normalized.is_empty() {
                    None
                } else {
                    Some((normalized, value))
                }
            })
            .collect();
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
        if is_qwen_portal_provider(&self.llm_provider) && self.api_key.trim().is_empty() {
            let has_qwen_auth = qwen_oauth_file_has_access_token()?;
            if !has_qwen_auth {
                return Err(MicroClawError::Config(
                    "qwen-portal requires api_key, or ~/.qwen/oauth_creds.json (access_token), or QWEN_PORTAL_ACCESS_TOKEN.".into(),
                ));
            }
        }

        Ok(())
    }

    fn merged_profile_from_alias(&self, alias: &str) -> Option<ResolvedLlmProviderProfile> {
        let alias = alias.trim().to_ascii_lowercase();
        if alias.is_empty() {
            return None;
        }
        if alias == self.llm_provider {
            let mut provider = self.llm_provider.clone();
            let mut api_key = self.api_key.clone();
            let mut llm_base_url = self.llm_base_url.clone();
            let mut llm_user_agent = self.llm_user_agent.clone();
            let mut default_model = self.model.clone();
            let mut models = vec![default_model.clone()];
            let mut show_thinking = self.show_thinking;
            if let Some(profile) = self.llm_providers.get(&alias) {
                if let Some(v) = &profile.provider {
                    provider = v.clone();
                }
                if let Some(v) = &profile.api_key {
                    api_key = v.clone();
                }
                if let Some(v) = &profile.llm_base_url {
                    llm_base_url = Some(v.clone());
                }
                if let Some(v) = &profile.llm_user_agent {
                    llm_user_agent = v.clone();
                }
                if let Some(v) = &profile.default_model {
                    default_model = v.clone();
                }
                if !profile.models.is_empty() {
                    models = profile.models.clone();
                }
                if let Some(v) = profile.show_thinking {
                    show_thinking = v;
                }
            }
            if !models.iter().any(|m| m == &default_model) {
                models.push(default_model.clone());
            }
            models.sort();
            models.dedup();
            return Some(ResolvedLlmProviderProfile {
                alias,
                provider,
                api_key,
                llm_base_url,
                llm_user_agent,
                default_model,
                models,
                show_thinking,
            });
        }

        let profile = self.llm_providers.get(&alias)?;
        let provider = profile.provider.clone().unwrap_or_else(|| alias.clone());
        let api_key = profile
            .api_key
            .clone()
            .unwrap_or_else(|| self.api_key.clone());
        let llm_base_url = profile
            .llm_base_url
            .clone()
            .or_else(|| self.llm_base_url.clone());
        let llm_user_agent = profile
            .llm_user_agent
            .clone()
            .unwrap_or_else(|| self.llm_user_agent.clone());
        let default_model = profile
            .default_model
            .clone()
            .unwrap_or_else(|| self.model.clone());
        let mut models = if profile.models.is_empty() {
            vec![default_model.clone()]
        } else {
            profile.models.clone()
        };
        let show_thinking = profile.show_thinking.unwrap_or(self.show_thinking);
        if !models.iter().any(|m| m == &default_model) {
            models.push(default_model.clone());
        }
        models.sort();
        models.dedup();
        Some(ResolvedLlmProviderProfile {
            alias,
            provider,
            api_key,
            llm_base_url,
            llm_user_agent,
            default_model,
            models,
            show_thinking,
        })
    }

    pub fn resolve_llm_provider_profile(&self, alias: &str) -> Option<ResolvedLlmProviderProfile> {
        self.merged_profile_from_alias(alias)
    }

    pub fn list_llm_provider_profiles(&self) -> Vec<ResolvedLlmProviderProfile> {
        let mut out = Vec::new();
        if let Some(default_profile) = self.resolve_llm_provider_profile(&self.llm_provider) {
            out.push(default_profile);
        }
        let mut aliases: Vec<String> = self.llm_providers.keys().cloned().collect();
        aliases.sort();
        aliases.dedup();
        for alias in aliases {
            if alias == self.llm_provider {
                continue;
            }
            if let Some(profile) = self.resolve_llm_provider_profile(&alias) {
                out.push(profile);
            }
        }
        out
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

fn normalize_provider_profiles(
    profiles: HashMap<String, LlmProviderProfile>,
) -> HashMap<String, LlmProviderProfile> {
    profiles
        .into_iter()
        .filter_map(|(alias, mut profile)| {
            let alias = alias.trim().to_ascii_lowercase();
            if alias.is_empty() {
                return None;
            }
            profile.provider = profile
                .provider
                .as_ref()
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty());
            profile.api_key = profile
                .api_key
                .as_ref()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            profile.llm_base_url = profile
                .llm_base_url
                .as_ref()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            profile.llm_user_agent = profile
                .llm_user_agent
                .as_ref()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            profile.default_model = profile
                .default_model
                .as_ref()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            profile.models = profile
                .models
                .into_iter()
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect::<Vec<_>>();
            profile.models.sort();
            profile.models.dedup();
            Some((alias, profile))
        })
        .collect()
}

fn migrate_model_override_alias_to_provider_preset(
    value: &mut serde_yaml::Value,
    known_profiles: &HashMap<String, LlmProviderProfile>,
) {
    let Some(map) = value.as_mapping_mut() else {
        return;
    };

    let provider_preset_key = serde_yaml::Value::String("provider_preset".to_string());
    let llm_provider_key = serde_yaml::Value::String("llm_provider".to_string());
    let model_key = serde_yaml::Value::String("model".to_string());

    let has_provider_override =
        map.contains_key(&provider_preset_key) || map.contains_key(&llm_provider_key);
    if !has_provider_override {
        let maybe_profile_alias = map
            .get(&model_key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase());
        if let Some(alias) = maybe_profile_alias {
            if known_profiles.contains_key(&alias) {
                map.insert(
                    provider_preset_key.clone(),
                    serde_yaml::Value::String(alias),
                );
                map.remove(&model_key);
            }
        }
    }

    let accounts_key = serde_yaml::Value::String("accounts".to_string());
    if let Some(accounts) = map.get_mut(&accounts_key).and_then(|v| v.as_mapping_mut()) {
        for (_, account) in accounts.iter_mut() {
            migrate_model_override_alias_to_provider_preset(account, known_profiles);
        }
    }
}

fn merge_provider_profile(
    base: LlmProviderProfile,
    override_profile: LlmProviderProfile,
) -> LlmProviderProfile {
    let mut models = if override_profile.models.is_empty() {
        base.models
    } else {
        override_profile.models
    };
    models.sort();
    models.dedup();

    LlmProviderProfile {
        provider: override_profile.provider.or(base.provider),
        api_key: override_profile.api_key.or(base.api_key),
        llm_base_url: override_profile.llm_base_url.or(base.llm_base_url),
        llm_user_agent: override_profile.llm_user_agent.or(base.llm_user_agent),
        default_model: override_profile.default_model.or(base.default_model),
        models,
        show_thinking: override_profile.show_thinking.or(base.show_thinking),
    }
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
        assert_eq!(config.timezone, "auto");
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
    fn test_post_deserialize_merges_provider_presets_with_legacy_profiles() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
provider_presets:
  lab:
    provider: OPENAI
    api_key: preset-key
    llm_base_url: https://preset.example/v1
    llm_user_agent: preset-agent
    default_model: preset-model
    models: [preset-model, preset-model]
    show_thinking: true
llm_providers:
  lab:
    api_key: legacy-key
    models: [legacy-model]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        let profile = config.resolve_llm_provider_profile("lab").unwrap();
        assert_eq!(profile.provider, "openai");
        assert_eq!(profile.api_key, "legacy-key");
        assert_eq!(
            profile.llm_base_url.as_deref(),
            Some("https://preset.example/v1")
        );
        assert_eq!(profile.llm_user_agent, "preset-agent");
        assert_eq!(profile.default_model, "preset-model");
        assert_eq!(
            profile.models,
            vec!["legacy-model".to_string(), "preset-model".to_string()]
        );
        assert!(profile.show_thinking);
    }

    #[test]
    fn test_llm_provider_overrides_support_provider_preset_and_legacy_llm_provider_keys() {
        let mut config = test_config();
        config.channels = serde_yaml::from_str(
            r#"
telegram:
  enabled: true
  provider_preset: channel-default
  default_account: sales
  accounts:
    sales:
      enabled: true
      bot_token: tg_sales
      provider_preset: sales-preset
    ops:
      enabled: true
      bot_token: tg_ops
      llm_provider: ops-legacy
discord:
  enabled: true
  llm_provider: discord-legacy
"#,
        )
        .unwrap();

        assert_eq!(
            config.provider_override_for_channel("telegram").as_deref(),
            Some("sales-preset")
        );
        assert_eq!(
            config
                .provider_override_for_channel("telegram.ops")
                .as_deref(),
            Some("ops-legacy")
        );
        assert_eq!(
            config.provider_override_for_channel("discord").as_deref(),
            Some("discord-legacy")
        );

        let overrides = config.llm_provider_overrides();
        assert_eq!(
            overrides.get("telegram").map(String::as_str),
            Some("sales-preset")
        );
        assert_eq!(
            overrides.get("telegram.ops").map(String::as_str),
            Some("ops-legacy")
        );
        assert_eq!(
            overrides.get("discord").map(String::as_str),
            Some("discord-legacy")
        );
    }

    #[test]
    fn test_post_deserialize_migrates_profile_aliases_out_of_channel_model_fields() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
provider_presets:
  googlegemini:
    provider: google
    default_model: gemini-2.5-pro
channels:
  telegram:
    enabled: true
    model: googlegemini
    default_account: sales
    accounts:
      sales:
        enabled: true
        bot_token: tg_sales
        model: googlegemini
  discord:
    enabled: true
    model: googlegemini
    accounts:
      default:
        enabled: true
        bot_token: dc_tok
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        assert_eq!(
            config.provider_override_for_channel("telegram").as_deref(),
            Some("googlegemini")
        );
        assert_eq!(
            config.provider_override_for_channel("discord").as_deref(),
            Some("googlegemini")
        );

        let telegram = config.channels.get("telegram").unwrap();
        assert_eq!(
            telegram
                .get("provider_preset")
                .and_then(|v| v.as_str())
                .map(str::trim),
            Some("googlegemini")
        );
        assert!(telegram.get("model").is_none());

        let sales = telegram
            .get("accounts")
            .and_then(|v| v.get("sales"))
            .unwrap();
        assert_eq!(
            sales
                .get("provider_preset")
                .and_then(|v| v.as_str())
                .map(str::trim),
            Some("googlegemini")
        );
        assert!(sales.get("model").is_none());
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
        assert!(config.sandbox.require_runtime);
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
    fn test_config_working_dir_isolation_accepts_true() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nworking_dir_isolation: true\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            config.working_dir_isolation,
            WorkingDirIsolation::Chat
        ));
    }

    #[test]
    fn test_config_working_dir_isolation_accepts_false() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nworking_dir_isolation: false\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            config.working_dir_isolation,
            WorkingDirIsolation::Shared
        ));
    }

    #[test]
    fn test_high_risk_tool_user_confirmation_required_defaults_true() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.high_risk_tool_user_confirmation_required);
    }

    #[test]
    fn test_high_risk_tool_user_confirmation_required_accepts_false() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nhigh_risk_tool_user_confirmation_required: false\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.high_risk_tool_user_confirmation_required);
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
        config.data_dir = "./microclaw.data".into();

        let runtime = std::path::PathBuf::from(config.runtime_data_dir());
        let skills = std::path::PathBuf::from(config.skills_data_dir());

        assert!(runtime.ends_with(std::path::Path::new("microclaw.data").join("runtime")));
        assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
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
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\noverride_timezone: Mars/Olympus\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Invalid timezone"));
    }

    #[test]
    fn test_post_deserialize_auto_timezone_resolves_to_valid_tz() {
        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\napi_key: key\noverride_timezone: auto\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert!(config.timezone.parse::<chrono_tz::Tz>().is_ok());
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
    fn test_post_deserialize_qwen_code_allows_oauth_without_api_key() {
        let _guard = env_lock();
        let prev_qwen_home = std::env::var("QWEN_HOME").ok();
        let prev_qwen_access = std::env::var("QWEN_PORTAL_ACCESS_TOKEN").ok();
        std::env::remove_var("QWEN_PORTAL_ACCESS_TOKEN");

        let qwen_dir = std::env::temp_dir().join(format!(
            "microclaw-qwen-auth-{}",
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

        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: qwen-portal\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

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

        assert_eq!(config.llm_provider, "qwen-portal");
    }

    #[test]
    fn test_post_deserialize_qwen_code_missing_oauth_and_api_key() {
        let _guard = env_lock();
        let prev_qwen_home = std::env::var("QWEN_HOME").ok();
        let prev_qwen_access = std::env::var("QWEN_PORTAL_ACCESS_TOKEN").ok();
        std::env::remove_var("QWEN_PORTAL_ACCESS_TOKEN");

        let qwen_dir = std::env::temp_dir().join(format!(
            "microclaw-qwen-auth-missing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&qwen_dir).unwrap();
        std::env::set_var("QWEN_HOME", &qwen_dir);

        let yaml = "telegram_bot_token: tok\nbot_username: bot\nllm_provider: qwen-portal\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();

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
        let _ = std::fs::remove_dir(qwen_dir);

        assert!(err
            .to_string()
            .contains("qwen-portal requires api_key, or ~/.qwen/oauth_creds.json"));
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
    fn test_post_deserialize_empty_llm_user_agent_uses_default() {
        let yaml =
            "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nllm_user_agent: '  '\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(
            config.llm_user_agent,
            crate::http_client::default_llm_user_agent()
        );
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
    fn test_post_deserialize_normalizes_subagent_acp_config() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
subagents:
  acp:
    enabled: true
    command: "  codex  "
    args: ["  --model  ", " ", "gpt-5.4"]
    env:
      " OPENAI_API_KEY ": abc
      "   ": ignored
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        assert!(config.subagents.acp.enabled);
        assert_eq!(config.subagents.acp.command, "codex");
        assert_eq!(
            config.subagents.acp.args,
            vec!["--model".to_string(), "gpt-5.4".to_string()]
        );
        assert_eq!(
            config.subagents.acp.env.get("OPENAI_API_KEY"),
            Some(&"abc".to_string())
        );
        assert!(!config.subagents.acp.env.contains_key("   "));
    }

    #[test]
    fn test_post_deserialize_web_non_local_no_token_required() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nweb_enabled: true\nweb_host: 0.0.0.0\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
    }

    #[test]
    fn test_post_deserialize_web_channel_auth_token_is_removed() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nweb_enabled: true\nweb_host: 0.0.0.0\nchannels:\n  web:\n    enabled: true\n    auth_token: token123\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        let has_auth_token = config
            .channels
            .get("web")
            .and_then(|v| v.as_mapping())
            .map(|map| map.contains_key(serde_yaml::Value::String("auth_token".to_string())))
            .unwrap_or(false);
        assert!(!has_auth_token);
    }

    #[test]
    fn test_post_deserialize_normalizes_a2a_config() {
        let mut config = Config::test_defaults();
        config.a2a.enabled = true;
        config.a2a.public_base_url = Some(" https://mc.example.com/ ".into());
        config.a2a.agent_name = Some(" Planner ".into());
        config.a2a.agent_description = Some(" Plans ".into());
        config.a2a.shared_tokens = vec!["  ".into(), " secret ".into()];
        config.a2a.peers.insert(
            " Worker ".into(),
            A2APeerConfig {
                enabled: true,
                base_url: " https://worker.example.com/ ".into(),
                bearer_token: Some(" token ".into()),
                description: Some(" executes ".into()),
                default_session_key: Some(" team/work ".into()),
            },
        );

        config.post_deserialize().unwrap();

        assert_eq!(
            config.a2a.public_base_url.as_deref(),
            Some("https://mc.example.com")
        );
        assert_eq!(config.a2a.agent_name.as_deref(), Some("Planner"));
        assert_eq!(config.a2a.agent_description.as_deref(), Some("Plans"));
        assert_eq!(config.a2a.shared_tokens, vec!["secret".to_string()]);
        let peer = config.a2a.peers.get("worker").unwrap();
        assert_eq!(peer.base_url, "https://worker.example.com");
        assert_eq!(peer.bearer_token.as_deref(), Some("token"));
        assert_eq!(peer.description.as_deref(), Some("executes"));
        assert_eq!(peer.default_session_key.as_deref(), Some("team/work"));
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
override_timezone: US/Eastern
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

    #[test]
    fn test_expand_path_with_tilde() {
        let home = PathBuf::from(shellexpand::tilde("~").as_ref());
        let path = "~/foo/bar";
        let expanded = expand_path(path);
        assert_eq!(expanded, home.join("foo/bar"));

        let path = "~";
        let expanded = expand_path(path);
        assert_eq!(expanded, home);

        let path = "/absolute/path";
        let expanded = expand_path(path);
        assert_eq!(expanded, std::path::PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_post_deserialize_expands_paths() {
        let mut config = test_config();
        config.data_dir = "~/.microclaw".into();
        config.working_dir = "~/workspace".into();
        config.skills_dir = Some("~/skills".into());

        config.post_deserialize().unwrap();

        let home = PathBuf::from(shellexpand::tilde("~").as_ref());
        // Use PathBuf comparison to handle separator differences on Windows
        assert_eq!(PathBuf::from(&config.data_dir), home.join(".microclaw"));
        assert_eq!(PathBuf::from(&config.working_dir), home.join("workspace"));
        assert_eq!(
            PathBuf::from(config.skills_dir.unwrap()),
            home.join("skills")
        );
    }
}
