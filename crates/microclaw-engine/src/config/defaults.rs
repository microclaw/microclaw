use super::*;

pub(crate) fn default_telegram_bot_token() -> String {
    String::new()
}

pub(crate) fn default_bot_username() -> String {
    String::new()
}

pub(crate) fn default_llm_provider() -> String {
    "anthropic".into()
}

pub(crate) fn default_api_key() -> String {
    String::new()
}

pub fn default_model_for_provider_name(provider: &str) -> &'static str {
    match provider.trim().to_ascii_lowercase().as_str() {
        "anthropic" => "claude-sonnet-4-5-20250929",
        "ollama" => "llama3.2",
        "openai-codex" => "gpt-5.3-codex",
        _ => "gpt-5.2",
    }
}

pub(crate) fn default_llm_user_agent() -> String {
    crate::http_client::default_llm_user_agent()
}

pub(crate) fn default_max_tokens() -> u32 {
    8192
}

pub(crate) fn default_max_tool_iterations() -> usize {
    100
}

pub(crate) fn default_chat_turn_queue_max_pending() -> usize {
    20
}

pub(crate) fn default_parallel_tool_max_concurrency() -> usize {
    8
}

pub(crate) fn default_compaction_timeout_secs() -> u64 {
    180
}

pub(crate) fn default_max_history_messages() -> usize {
    50
}

pub(crate) fn default_max_document_size_mb() -> u64 {
    100
}

pub(crate) fn default_memory_token_budget() -> usize {
    1500
}

pub(crate) fn default_memory_l0_identity_pct() -> usize {
    20
}

pub(crate) fn default_memory_l1_essential_pct() -> usize {
    30
}

pub(crate) fn default_memory_max_entries_per_chat() -> usize {
    200
}

pub(crate) fn default_memory_max_global_entries() -> usize {
    500
}

pub(crate) fn default_kg_max_triples_per_chat() -> usize {
    1000
}

pub(crate) fn default_tool_result_truncation_threshold_chars() -> usize {
    4000
}

pub(crate) fn default_tool_result_truncation_head_chars() -> usize {
    1500
}

pub(crate) fn default_tool_result_truncation_tail_chars() -> usize {
    500
}

pub(crate) fn default_tool_result_artifact_ttl_hours() -> u64 {
    24
}

pub(crate) fn default_memory_recency_half_life_days() -> f64 {
    30.0
}

pub(crate) fn default_memory_graph_recall_enabled() -> bool {
    true
}

pub(crate) fn default_memory_graph_max_hops() -> usize {
    2
}

pub(crate) fn default_memory_graph_max_triples() -> usize {
    10
}

pub(crate) fn default_tool_repeat_window() -> usize {
    10
}

pub(crate) fn default_tool_repeat_limit() -> usize {
    3
}

pub(crate) fn default_anthropic_prompt_cache_enabled() -> bool {
    true
}

pub(crate) fn default_anthropic_prompt_cache_ttl() -> String {
    "5m".to_string()
}

pub(crate) fn default_checkpoints_enabled() -> bool {
    false
}

pub(crate) fn default_skill_archive_after_days() -> u64 {
    30
}

pub(crate) fn default_skills_catalog_top_k() -> usize {
    3
}

pub(crate) fn default_skill_review_min_tool_calls() -> usize {
    5
}

pub(crate) fn default_data_dir() -> String {
    default_data_root().to_string_lossy().to_string()
}

pub(crate) fn default_data_root() -> PathBuf {
    if std::env::var("SNAP").is_ok() {
        if let Ok(snap_user_common) = std::env::var("SNAP_USER_COMMON") {
            return PathBuf::from(snap_user_common);
        }
    }
    expand_path("~/.microclaw")
}

pub(crate) fn default_working_dir() -> String {
    default_data_root()
        .join("working_dir")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn default_working_dir_isolation() -> WorkingDirIsolation {
    WorkingDirIsolation::Chat
}

pub(crate) fn default_bash_dangerous_patterns() -> Vec<String> {
    vec![
        // Destructive recursive deletes against root or wildcards.
        r"\brm\s+(-[a-zA-Z]*[rfRF][a-zA-Z]*\s+)+(/|\*|~|\$HOME)".into(),
        // Pipe-to-shell installer pattern.
        r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|fish)\b".into(),
        // Privilege escalation.
        r"\bsudo\b".into(),
        // Disk-overwrite.
        r"\bdd\s+if=".into(),
        // Forkbomb.
        r":\(\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;\s*:".into(),
        // Filesystem format.
        r"\bmkfs(\.[a-z0-9]+)?\b".into(),
        // Recursive chmod/chown on root.
        r"\bch(mod|own)\s+-R\s+[^/]*\s+/(\s|$)".into(),
    ]
}

pub(crate) fn default_high_risk_tool_user_confirmation_required() -> bool {
    true
}

pub(crate) fn default_sandbox_image() -> String {
    "ubuntu:25.10".into()
}

pub(crate) fn default_sandbox_container_prefix() -> String {
    "microclaw-sandbox".into()
}

pub(crate) fn default_timezone() -> String {
    "auto".into()
}

pub(crate) fn default_max_session_messages() -> usize {
    40
}

pub(crate) fn default_diff_max_lines() -> usize {
    microclaw_core::diff::DEFAULT_DIFF_MAX_LINES
}

pub(crate) fn default_model_context_window() -> usize {
    200_000
}

pub(crate) fn default_context_pressure_compact_pct() -> usize {
    85
}

pub(crate) fn default_file_diffs_in_chat() -> bool {
    true
}

pub(crate) fn default_compact_keep_recent() -> usize {
    20
}

pub(crate) fn default_tool_timeout_secs() -> u64 {
    30
}

pub(crate) fn default_mcp_request_timeout_secs() -> u64 {
    120
}

pub(crate) fn default_control_chat_ids() -> Vec<i64> {
    Vec::new()
}

pub(crate) fn default_web_enabled() -> bool {
    true
}

pub(crate) fn default_web_host() -> String {
    "127.0.0.1".into()
}

pub(crate) fn default_web_port() -> u16 {
    10961
}

pub(crate) fn default_web_max_inflight_per_session() -> usize {
    10
}

pub(crate) fn default_web_max_requests_per_window() -> usize {
    8
}

pub(crate) fn default_web_rate_window_seconds() -> u64 {
    10
}

pub(crate) fn default_web_run_history_limit() -> usize {
    512
}

pub(crate) fn default_web_session_idle_ttl_seconds() -> u64 {
    300
}

pub(crate) fn default_allow_group_slash_without_mention() -> bool {
    false
}

pub(crate) fn default_model_prices() -> Vec<ModelPrice> {
    Vec::new()
}

pub(crate) fn default_reflector_enabled() -> bool {
    true
}

pub(crate) fn default_reflector_interval_mins() -> u64 {
    15
}

pub(crate) fn default_dlq_replay_enabled() -> bool {
    true
}

pub(crate) fn default_dlq_replay_interval_secs() -> u64 {
    300
}

pub(crate) fn default_dlq_max_replay_attempts() -> u32 {
    3
}

pub(crate) fn default_soul_path() -> Option<String> {
    None
}

pub(crate) fn default_souls_dir() -> Option<String> {
    None
}

pub(crate) fn default_context_max_chars() -> usize {
    8000
}

pub(crate) fn default_user_model_max_chars() -> usize {
    1500
}

pub(crate) fn default_voice_provider() -> String {
    "openai".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::test_prelude::*;

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
}
