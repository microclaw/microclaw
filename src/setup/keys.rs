use super::*;

// Declarative channel metadata is owned by each channel module.
pub(crate) const DYNAMIC_CHANNELS: &[DynamicChannelDef] = &[
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
pub(crate) fn dynamic_field_key(channel: &str, yaml_key: &str) -> String {
    format!("DYN_{}_{}", channel.to_uppercase(), yaml_key.to_uppercase())
}

pub(crate) fn dynamic_account_id_field_key(channel: &str) -> String {
    format!("DYN_{}_ACCOUNT_ID", channel.to_uppercase())
}

pub(crate) fn dynamic_accounts_json_field_key(channel: &str) -> String {
    format!("DYN_{}_ACCOUNTS_JSON", channel.to_uppercase())
}

pub(crate) const MAX_BOT_SLOTS: usize = 10;

pub(crate) const TELEGRAM_DEFAULT_BOT_COUNT: usize = 1;

pub(crate) fn telegram_slot_id_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ID", slot)
}

pub(crate) fn telegram_slot_enabled_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ENABLED", slot)
}

pub(crate) fn telegram_slot_token_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_TOKEN", slot)
}

pub(crate) fn telegram_slot_username_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_USERNAME", slot)
}

pub(crate) fn telegram_slot_model_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_MODEL", slot)
}

pub(crate) fn telegram_slot_soul_path_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_SOUL_PATH", slot)
}

pub(crate) fn telegram_slot_allowed_user_ids_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_ALLOWED_USER_IDS", slot)
}

pub(crate) fn telegram_slot_topic_routing_key(slot: usize) -> String {
    format!("TELEGRAM_BOT{}_TOPIC_ROUTING", slot)
}

pub(crate) fn default_slot_account_id(slot: usize) -> String {
    if slot <= 1 {
        default_account_id().to_string()
    } else {
        format!("bot{slot}")
    }
}

pub(crate) fn telegram_bot_count_key() -> &'static str {
    "TELEGRAM_BOT_COUNT"
}

pub(crate) fn telegram_allowed_user_ids_key() -> &'static str {
    "TELEGRAM_ALLOWED_USER_IDS"
}

pub(crate) fn telegram_topic_routing_key() -> &'static str {
    "TELEGRAM_TOPIC_ROUTING"
}

pub(crate) fn web_hooks_token_key() -> &'static str {
    "WEB_HOOKS_TOKEN"
}

pub(crate) fn web_hooks_default_session_key_key() -> &'static str {
    "WEB_HOOKS_DEFAULT_SESSION_KEY"
}

pub(crate) fn web_hooks_allow_request_session_key_key() -> &'static str {
    "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY"
}

pub(crate) fn web_hooks_allowed_session_key_prefixes_key() -> &'static str {
    "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES"
}

pub(crate) fn a2a_enabled_key() -> &'static str {
    "A2A_ENABLED"
}

pub(crate) fn a2a_public_base_url_key() -> &'static str {
    "A2A_PUBLIC_BASE_URL"
}

pub(crate) fn a2a_agent_name_key() -> &'static str {
    "A2A_AGENT_NAME"
}

pub(crate) fn a2a_agent_description_key() -> &'static str {
    "A2A_AGENT_DESCRIPTION"
}

pub(crate) fn a2a_shared_tokens_key() -> &'static str {
    "A2A_SHARED_TOKENS"
}

pub(crate) fn a2a_peers_json_key() -> &'static str {
    "A2A_PEERS_JSON"
}

pub(crate) fn subagents_max_concurrent_key() -> &'static str {
    "SUBAGENTS_MAX_CONCURRENT"
}

pub(crate) fn subagents_max_active_per_chat_key() -> &'static str {
    "SUBAGENTS_MAX_ACTIVE_PER_CHAT"
}

pub(crate) fn subagents_run_timeout_secs_key() -> &'static str {
    "SUBAGENTS_RUN_TIMEOUT_SECS"
}

pub(crate) fn subagents_announce_to_chat_key() -> &'static str {
    "SUBAGENTS_ANNOUNCE_TO_CHAT"
}

pub(crate) fn subagents_max_spawn_depth_key() -> &'static str {
    "SUBAGENTS_MAX_SPAWN_DEPTH"
}

pub(crate) fn subagents_max_children_per_run_key() -> &'static str {
    "SUBAGENTS_MAX_CHILDREN_PER_RUN"
}

pub(crate) fn subagents_thread_bound_routing_enabled_key() -> &'static str {
    "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED"
}

pub(crate) fn subagents_announce_relay_interval_secs_key() -> &'static str {
    "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS"
}

pub(crate) fn subagents_max_tokens_per_run_key() -> &'static str {
    "SUBAGENTS_MAX_TOKENS_PER_RUN"
}

pub(crate) fn subagents_orchestrate_max_workers_key() -> &'static str {
    "SUBAGENTS_ORCHESTRATE_MAX_WORKERS"
}

pub(crate) fn subagents_acp_enabled_key() -> &'static str {
    "SUBAGENTS_ACP_ENABLED"
}

pub(crate) fn subagents_acp_command_key() -> &'static str {
    "SUBAGENTS_ACP_COMMAND"
}

pub(crate) fn subagents_acp_args_key() -> &'static str {
    "SUBAGENTS_ACP_ARGS"
}

pub(crate) fn subagents_acp_env_json_key() -> &'static str {
    "SUBAGENTS_ACP_ENV_JSON"
}

pub(crate) fn subagents_acp_auto_approve_key() -> &'static str {
    "SUBAGENTS_ACP_AUTO_APPROVE"
}

pub(crate) fn subagents_acp_default_target_key() -> &'static str {
    "SUBAGENTS_ACP_DEFAULT_TARGET"
}

pub(crate) fn subagents_acp_targets_json_key() -> &'static str {
    "SUBAGENTS_ACP_TARGETS_JSON"
}

pub(crate) fn telegram_llm_provider_key() -> &'static str {
    "TELEGRAM_LLM_PROVIDER"
}

pub(crate) fn telegram_llm_api_key_key() -> &'static str {
    "TELEGRAM_LLM_API_KEY"
}

pub(crate) fn telegram_llm_base_url_key() -> &'static str {
    "TELEGRAM_LLM_BASE_URL"
}

pub(crate) fn discord_llm_provider_key() -> &'static str {
    "DISCORD_LLM_PROVIDER"
}

pub(crate) fn discord_llm_api_key_key() -> &'static str {
    "DISCORD_LLM_API_KEY"
}

pub(crate) fn discord_llm_base_url_key() -> &'static str {
    "DISCORD_LLM_BASE_URL"
}

pub(crate) fn llm_provider_profiles_key() -> &'static str {
    "LLM_PROVIDER_PROFILES"
}

pub(crate) fn dynamic_bot_count_field_key(channel: &str) -> String {
    format!("DYN_{}_BOT_COUNT", channel.to_uppercase())
}

pub(crate) fn dynamic_slot_id_field_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_ID", channel.to_uppercase(), slot)
}

pub(crate) fn dynamic_slot_enabled_field_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_ENABLED", channel.to_uppercase(), slot)
}

pub(crate) fn dynamic_slot_field_key(channel: &str, slot: usize, yaml_key: &str) -> String {
    format!(
        "DYN_{}_BOT{}_{}",
        channel.to_uppercase(),
        slot,
        yaml_key.to_uppercase()
    )
}

pub(crate) fn dynamic_slot_llm_provider_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_LLM_PROVIDER", channel.to_uppercase(), slot)
}

pub(crate) fn dynamic_slot_llm_api_key_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_LLM_API_KEY", channel.to_uppercase(), slot)
}

pub(crate) fn dynamic_slot_llm_base_url_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_LLM_BASE_URL", channel.to_uppercase(), slot)
}

pub(crate) fn dynamic_slot_soul_path_field_key(channel: &str, slot: usize) -> String {
    format!("DYN_{}_BOT{}_SOUL_PATH", channel.to_uppercase(), slot)
}

pub(crate) fn trim_channel_prefix<'a>(channel: &str, label: &'a str) -> &'a str {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

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
    fn test_parse_provider_presets_json_rejects_reserved_main() {
        let err = parse_provider_presets_json_value(
            r#"{"main":{"provider":"openai"}}"#,
            llm_provider_profiles_key(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("reserved"));
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
    fn test_key_display_hides_json_suffix_for_provider_presets() {
        assert_eq!(
            SetupApp::key_display(llm_provider_profiles_key()),
            "LLM_PROVIDER_PROFILES"
        );
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
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_PROVIDER") {
            field.value = "anthropic".to_string();
        }
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
}
