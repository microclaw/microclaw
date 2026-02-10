use crate::error::MicroClawError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
fn default_max_history_messages() -> usize {
    50
}
fn default_max_document_size_mb() -> u64 {
    100
}
fn default_data_dir() -> String {
    "./microclaw.data".into()
}
fn default_working_dir() -> String {
    "./tmp".into()
}
fn default_working_dir_isolation() -> WorkingDirIsolation {
    WorkingDirIsolation::Chat
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
fn default_whatsapp_webhook_port() -> u16 {
    8080
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
fn is_local_web_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingDirIsolation {
    Shared,
    Chat,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_telegram_bot_token")]
    pub telegram_bot_token: String,
    #[serde(default = "default_bot_username")]
    pub bot_username: String,
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
    #[serde(default = "default_max_history_messages")]
    pub max_history_messages: usize,
    #[serde(default = "default_max_document_size_mb")]
    pub max_document_size_mb: u64,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    #[serde(default = "default_working_dir_isolation")]
    pub working_dir_isolation: WorkingDirIsolation,
    #[serde(default)]
    pub openai_api_key: Option<String>,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub allowed_groups: Vec<i64>,
    #[serde(default = "default_control_chat_ids")]
    pub control_chat_ids: Vec<i64>,
    #[serde(default = "default_max_session_messages")]
    pub max_session_messages: usize,
    #[serde(default = "default_compact_keep_recent")]
    pub compact_keep_recent: usize,
    #[serde(default)]
    pub whatsapp_access_token: Option<String>,
    #[serde(default)]
    pub whatsapp_phone_number_id: Option<String>,
    #[serde(default)]
    pub whatsapp_verify_token: Option<String>,
    #[serde(default = "default_whatsapp_webhook_port")]
    pub whatsapp_webhook_port: u16,
    #[serde(default)]
    pub discord_bot_token: Option<String>,
    #[serde(default)]
    pub discord_allowed_channels: Vec<u64>,
    #[serde(default)]
    pub show_thinking: bool,
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
}

impl Config {
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

    /// Skills directory under data root.
    pub fn skills_data_dir(&self) -> String {
        self.data_root_dir()
            .join("skills")
            .to_string_lossy()
            .to_string()
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
            "No microclaw.config.yaml found. Run `microclaw config` to create one.".into(),
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
        if self.working_dir.trim().is_empty() {
            self.working_dir = default_working_dir();
        }
        if self.web_host.trim().is_empty() {
            self.web_host = default_web_host();
        }
        if let Some(token) = &self.web_auth_token {
            if token.trim().is_empty() {
                self.web_auth_token = None;
            }
        }
        if self.web_enabled && !is_local_web_host(&self.web_host) && self.web_auth_token.is_none() {
            return Err(MicroClawError::Config(
                "web_auth_token is required when web_enabled=true and web_host is not local".into(),
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
        if self.max_document_size_mb == 0 {
            self.max_document_size_mb = default_max_document_size_mb();
        }

        // Validate required fields
        if self.telegram_bot_token.is_empty() && self.discord_bot_token.is_none() {
            return Err(MicroClawError::Config(
                "At least one of telegram_bot_token or discord_bot_token must be set".into(),
            ));
        }
        if self.api_key.is_empty() && self.llm_provider != "ollama" {
            return Err(MicroClawError::Config("api_key is required".into()));
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    pub fn test_config() -> Config {
        Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "anthropic".into(),
            api_key: "key".into(),
            model: "claude-sonnet-4-5-20250929".into(),
            llm_base_url: None,
            max_tokens: 8192,
            max_tool_iterations: 100,
            max_history_messages: 50,
            max_document_size_mb: 100,
            data_dir: "./microclaw.data".into(),
            working_dir: "./tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Chat,
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            whatsapp_access_token: None,
            whatsapp_phone_number_id: None,
            whatsapp_verify_token: None,
            whatsapp_webhook_port: 8080,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            show_thinking: false,
            web_enabled: true,
            web_host: "127.0.0.1".into(),
            web_port: 10961,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
        }
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
        assert!(cloned.openai_api_key.is_none());
        assert_eq!(cloned.timezone, "UTC");
        assert!(cloned.allowed_groups.is_empty());
        assert!(cloned.control_chat_ids.is_empty());
        assert_eq!(cloned.max_session_messages, 40);
        assert_eq!(cloned.compact_keep_recent, 20);
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
        assert_eq!(config.data_dir, "./microclaw.data");
        assert_eq!(config.working_dir, "./tmp");
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
        assert_eq!(config.data_dir, "./microclaw.data");
        assert_eq!(config.working_dir, "./tmp");
        assert!(matches!(
            config.working_dir_isolation,
            WorkingDirIsolation::Chat
        ));
        assert_eq!(config.max_document_size_mb, 100);
        assert_eq!(config.timezone, "UTC");
    }

    #[test]
    fn test_post_deserialize_empty_working_dir_uses_default() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nworking_dir: '  '\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.working_dir, "./tmp");
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
        assert!(config
            .runtime_data_dir()
            .ends_with("microclaw.data/runtime"));
        assert!(config.skills_data_dir().ends_with("microclaw.data/skills"));
    }

    #[test]
    fn test_runtime_and_skills_dirs_from_runtime_data_dir() {
        let mut config = test_config();
        config.data_dir = "./microclaw.data/runtime".into();
        assert!(config
            .runtime_data_dir()
            .ends_with("microclaw.data/runtime/runtime"));
        assert!(config
            .skills_data_dir()
            .ends_with("microclaw.data/runtime/skills"));
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
    fn test_post_deserialize_missing_bot_tokens() {
        let yaml = "bot_username: bot\napi_key: key\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("telegram_bot_token or discord_bot_token"));
    }

    #[test]
    fn test_post_deserialize_discord_only() {
        let yaml = "bot_username: bot\napi_key: key\ndiscord_bot_token: discord_tok\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        // Should succeed: discord_bot_token is set even though telegram_bot_token is empty
        config.post_deserialize().unwrap();
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
    fn test_post_deserialize_web_non_local_requires_token() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nweb_enabled: true\nweb_host: 0.0.0.0\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.post_deserialize().unwrap_err();
        assert!(err
            .to_string()
            .contains("web_auth_token is required when web_enabled=true"));
    }

    #[test]
    fn test_post_deserialize_web_non_local_with_token_ok() {
        let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nweb_enabled: true\nweb_host: 0.0.0.0\nweb_auth_token: token123\n";
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();
        assert_eq!(config.web_auth_token.as_deref(), Some("token123"));
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
whatsapp_access_token: wa_token
whatsapp_phone_number_id: phone_id
whatsapp_verify_token: verify
whatsapp_webhook_port: 9090
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
        assert_eq!(config.whatsapp_webhook_port, 9090);
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
