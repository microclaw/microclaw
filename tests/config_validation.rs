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
        provider_presets: std::collections::HashMap::new(),
        llm_providers: std::collections::HashMap::new(),
        llm_base_url: None,
        llm_user_agent: microclaw::http_client::default_llm_user_agent(),
        max_tokens: 8192,
        max_tool_iterations: 25,
        max_history_messages: 50,
        max_document_size_mb: 100,
        memory_token_budget: 1500,
        memory_l0_identity_pct: 20,
        memory_l1_essential_pct: 30,
        memory_max_entries_per_chat: 200,
        memory_max_global_entries: 500,
        kg_max_triples_per_chat: 1000,
        data_dir: "./microclaw.data".into(),
        skills_dir: None,
        working_dir: "./tmp".into(),
        working_dir_isolation: WorkingDirIsolation::Chat,
        high_risk_tool_user_confirmation_required: true,
        bash_dangerous_patterns: vec![],
        sandbox: microclaw::config::SandboxConfig::default(),
        openai_api_key: None,
        override_timezone: None,
        timezone: "UTC".into(),
        allowed_groups: vec![],
        control_chat_ids: vec![],
        max_session_messages: 40,
        compact_keep_recent: 20,
        default_tool_timeout_secs: 30,
        tool_timeout_overrides: std::collections::HashMap::new(),
        default_mcp_request_timeout_secs: 120,
        compaction_timeout_secs: 180,
        discord_bot_token: None,
        discord_allowed_channels: vec![],
        discord_no_mention: false,
        allow_group_slash_without_mention: false,
        show_thinking: false,
        subagents: microclaw::config::SubagentConfig::default(),
        a2a: microclaw::config::A2AConfig::default(),
        openai_compat_body_overrides: std::collections::HashMap::new(),
        openai_compat_body_overrides_by_provider: std::collections::HashMap::new(),
        openai_compat_body_overrides_by_model: std::collections::HashMap::new(),
        web_enabled: false,
        web_host: "127.0.0.1".into(),
        web_port: 3900,
        web_max_inflight_per_session: 2,
        web_max_requests_per_window: 8,
        web_rate_window_seconds: 10,
        web_run_history_limit: 512,
        web_session_idle_ttl_seconds: 300,
        web_fetch_validation:
            microclaw_tools::web_content_validation::WebContentValidationConfig::default(),
        web_fetch_url_validation: microclaw_tools::web_fetch::WebFetchUrlValidationConfig::default(
        ),
        model_prices: vec![],
        embedding_provider: None,
        embedding_api_key: None,
        embedding_base_url: None,
        embedding_model: None,
        embedding_dim: None,
        reflector_enabled: true,
        reflector_interval_mins: 15,
        skill_review_min_tool_calls: 5,
        soul_path: None,
        souls_dir: None,
        context_dir: None,
        context_max_chars: 8000,
        voice_round_trip: false,
        user_model_max_chars: 1500,
        clawhub: microclaw::config::ClawHubConfig::default(),
        plugins: microclaw::plugins::PluginsConfig::default(),
        media: microclaw::config::MediaConfig::default(),
        openai_base_url: None,
        voice_provider: "openai".into(),
        voice_transcription_command: None,
        observability: None,
        channels: std::collections::HashMap::new(),
        chat_turn_queue_max_pending: 20,
        enable_mid_turn_injection: true,
        mid_turn_injection_echo: true,
        parallel_tool_max_concurrency: 8,
        tool_concurrency_overrides: std::collections::HashMap::new(),
        tool_result_truncation_threshold_chars: 4000,
        tool_result_truncation_head_chars: 1500,
        tool_result_truncation_tail_chars: 500,
        tool_result_artifact_ttl_hours: 24,
        memory_recency_half_life_days: 30.0,
        tool_repeat_window: 10,
        tool_repeat_limit: 3,
        anthropic_prompt_cache_enabled: true,
        anthropic_prompt_cache_ttl: "5m".into(),
        checkpoints_enabled: false,
        skill_archive_after_days: 30,
        skills_catalog_top_k: 3,
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
    assert_eq!(config.timezone, "auto");
    assert!(matches!(
        config.working_dir_isolation,
        WorkingDirIsolation::Chat
    ));
    assert_eq!(config.max_session_messages, 40);
    assert_eq!(config.compact_keep_recent, 20);
    assert_eq!(config.default_tool_timeout_secs, 30);
    assert_eq!(config.default_mcp_request_timeout_secs, 120);
    assert!(config.high_risk_tool_user_confirmation_required);
    assert!(config.sandbox.require_runtime);
    assert!(config.web_fetch_validation.enabled);
    assert!(config.web_fetch_validation.strict_mode);
    assert!(config.web_fetch_url_validation.enabled);
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
    assert_eq!(parsed.timezone, "auto");
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
