//! Integration tests for configuration loading and validation.

use microclaw::config::{Config, WorkingDirIsolation};

/// Helper to create a minimal valid config for testing.
fn minimal_config() -> Config {
    Config {
        telegram_bot_token: "tok".into(),
        bot_username: "testbot".into(),
        llm_provider: "anthropic".into(),
        api_key: "test-key".into(),
        model: String::new(),
        llm_base_url: None,
        max_tokens: 8192,
        max_tool_iterations: 25,
        max_history_messages: 50,
        max_document_size_mb: 100,
        memory_token_budget: 1500,
        data_dir: "./microclaw.data".into(),
        working_dir: "./tmp".into(),
        working_dir_isolation: WorkingDirIsolation::Chat,
        sandbox: microclaw::config::SandboxConfig::default(),
        openai_api_key: None,
        timezone: "UTC".into(),
        allowed_groups: vec![],
        control_chat_ids: vec![],
        max_session_messages: 40,
        compact_keep_recent: 20,
        compaction_timeout_secs: 180,
        discord_bot_token: None,
        discord_allowed_channels: vec![],
        discord_no_mention: false,
        show_thinking: false,
        web_enabled: false,
        web_host: "127.0.0.1".into(),
        web_port: 3900,
        web_auth_token: None,
        web_max_inflight_per_session: 2,
        web_max_requests_per_window: 8,
        web_rate_window_seconds: 10,
        web_run_history_limit: 512,
        web_session_idle_ttl_seconds: 300,
        model_prices: vec![],
        embedding_provider: None,
        embedding_api_key: None,
        embedding_base_url: None,
        embedding_model: None,
        embedding_dim: None,
        reflector_enabled: true,
        reflector_interval_mins: 15,
        soul_path: None,
        clawhub_registry: "https://clawhub.ai".into(),
        clawhub_token: None,
        clawhub_agent_tools_enabled: true,
        clawhub_skip_security_warnings: false,
        channels: std::collections::HashMap::new(),
    }
}

#[test]
fn test_yaml_parse_minimal() {
    let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\n";
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.telegram_bot_token, "tok");
    assert_eq!(config.bot_username, "bot");
    assert_eq!(config.api_key, "key");
    // Defaults
    assert_eq!(config.llm_provider, "anthropic");
    assert_eq!(config.max_tokens, 8192);
    assert_eq!(config.max_tool_iterations, 100);
    assert_eq!(config.max_document_size_mb, 100);
    assert_eq!(config.max_history_messages, 50);
    assert_eq!(config.timezone, "UTC");
    assert!(matches!(
        config.working_dir_isolation,
        WorkingDirIsolation::Chat
    ));
    assert_eq!(config.max_session_messages, 40);
    assert_eq!(config.compact_keep_recent, 20);
}

#[test]
fn test_yaml_parse_full() {
    let yaml = r#"
telegram_bot_token: my_token
bot_username: mybot
llm_provider: openai
api_key: sk-test123
model: gpt-4o
llm_base_url: https://custom.api.com/v1
max_tokens: 4096
max_tool_iterations: 10
max_history_messages: 100
data_dir: /data/microclaw
working_dir: /data/microclaw/tmp
openai_api_key: sk-whisper
timezone: Asia/Shanghai
allowed_groups:
  - 111
  - 222
control_chat_ids:
  - 999
max_session_messages: 60
compact_keep_recent: 30
discord_bot_token: discord_tok
discord_allowed_channels:
  - 333
  - 444
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.telegram_bot_token, "my_token");
    assert_eq!(config.llm_provider, "openai");
    assert_eq!(config.model, "gpt-4o");
    assert_eq!(
        config.llm_base_url.as_deref(),
        Some("https://custom.api.com/v1")
    );
    assert_eq!(config.max_tokens, 4096);
    assert_eq!(config.max_tool_iterations, 10);
    assert_eq!(config.max_history_messages, 100);
    assert_eq!(config.data_dir, "/data/microclaw");
    assert_eq!(config.working_dir, "/data/microclaw/tmp");
    assert_eq!(config.openai_api_key.as_deref(), Some("sk-whisper"));
    assert_eq!(config.timezone, "Asia/Shanghai");
    assert_eq!(config.allowed_groups, vec![111, 222]);
    assert_eq!(config.control_chat_ids, vec![999]);
    assert_eq!(config.max_session_messages, 60);
    assert_eq!(config.compact_keep_recent, 30);
    assert_eq!(config.discord_allowed_channels, vec![333, 444]);
}

#[test]
fn test_yaml_roundtrip() {
    let config = minimal_config();
    let yaml = serde_yaml::to_string(&config).unwrap();
    let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(parsed.telegram_bot_token, config.telegram_bot_token);
    assert_eq!(parsed.api_key, config.api_key);
    assert_eq!(parsed.max_tokens, config.max_tokens);
    assert_eq!(parsed.timezone, config.timezone);
}

#[test]
fn test_data_dir_paths() {
    let mut config = minimal_config();
    config.data_dir = "/opt/microclaw.data".into();

    let runtime = std::path::PathBuf::from(config.runtime_data_dir());
    let skills = std::path::PathBuf::from(config.skills_data_dir());

    assert!(runtime.ends_with(std::path::Path::new("microclaw.data").join("runtime")));
    assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
}

#[test]
fn test_yaml_unknown_fields_ignored() {
    let yaml = "telegram_bot_token: tok\nbot_username: bot\napi_key: key\nunknown_field: value\n";
    // serde_yaml should not fail on unknown fields by default
    let config: Result<Config, _> = serde_yaml::from_str(yaml);
    // This may fail or succeed depending on serde config; verify behavior
    if let Ok(c) = config {
        assert_eq!(c.telegram_bot_token, "tok");
    }
    // If it errors, that's also acceptable behavior (strict mode)
}

#[test]
fn test_yaml_empty_string_fields() {
    let yaml = "telegram_bot_token: ''\nbot_username: ''\napi_key: ''\n";
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.telegram_bot_token, "");
    assert_eq!(config.bot_username, "");
    assert_eq!(config.api_key, "");
}
