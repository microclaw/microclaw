use super::*;

#[derive(Clone)]
pub(crate) struct Field {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) value: String,
    pub(crate) required: bool,
    pub(crate) secret: bool,
}

impl Field {
    pub(crate) fn display_value(&self, editing: bool) -> String {
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
pub(crate) struct SetupApp {
    pub(crate) fields: Vec<Field>,
    pub(crate) selected: usize,
    pub(crate) field_scroll: usize,
    pub(crate) field_window: usize,
    pub(crate) visible_cache_sig: Cell<u64>,
    pub(crate) visible_cache_indices: RefCell<Vec<usize>>,
    pub(crate) editing: bool,
    pub(crate) picker: Option<PickerState>,
    pub(crate) status: String,
    pub(crate) completed: bool,
    pub(crate) backup_path: Option<String>,
    pub(crate) completion_summary: Vec<String>,
    pub(crate) llm_override_page: Option<LlmOverridePage>,
    pub(crate) llm_override_picker: Option<LlmOverridePicker>,
    pub(crate) provider_preset_page: Option<ProviderPresetPage>,
}

impl SetupApp {
    pub(crate) fn channel_options() -> Vec<&'static str> {
        let mut opts = vec!["web", "telegram", "discord"];
        for ch in DYNAMIC_CHANNELS {
            opts.push(ch.name);
        }
        opts
    }

    pub(crate) fn new() -> Self {
        // Try loading from existing config file first, then fall back to env vars
        let existing = Self::load_existing_config();
        let provider = normalize_setup_provider_id(
            &existing
                .get("LLM_PROVIDER")
                .cloned()
                .unwrap_or_else(|| "anthropic".into()),
        );
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
                    key: web_hooks_token_key().into(),
                    label: "Web hook token (optional, for /hooks/* auth)".into(),
                    value: existing
                        .get(web_hooks_token_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: web_hooks_default_session_key_key().into(),
                    label: "Web hook default session key (optional)".into(),
                    value: existing
                        .get(web_hooks_default_session_key_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: web_hooks_allow_request_session_key_key().into(),
                    label: "Web hook allow request session key (optional true/false)".into(),
                    value: existing
                        .get(web_hooks_allow_request_session_key_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: web_hooks_allowed_session_key_prefixes_key().into(),
                    label: "Web hook allowed session key prefixes (csv, optional)".into(),
                    value: existing
                        .get(web_hooks_allowed_session_key_prefixes_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_enabled_key().into(),
                    label: "Enable A2A HTTP integration (true/false)".into(),
                    value: existing
                        .get(a2a_enabled_key())
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_public_base_url_key().into(),
                    label: "A2A public base URL (optional)".into(),
                    value: existing
                        .get(a2a_public_base_url_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_agent_name_key().into(),
                    label: "A2A agent name (optional)".into(),
                    value: existing
                        .get(a2a_agent_name_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_agent_description_key().into(),
                    label: "A2A agent description (optional)".into(),
                    value: existing
                        .get(a2a_agent_description_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: a2a_shared_tokens_key().into(),
                    label: "A2A shared bearer tokens (csv, optional)".into(),
                    value: existing
                        .get(a2a_shared_tokens_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: a2a_peers_json_key().into(),
                    label: "A2A peers JSON ({name:{base_url,...}}, optional)".into(),
                    value: existing
                        .get(a2a_peers_json_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_concurrent_key().into(),
                    label: "Subagents max concurrent runs".into(),
                    value: existing
                        .get(subagents_max_concurrent_key())
                        .cloned()
                        .unwrap_or_else(|| "4".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_active_per_chat_key().into(),
                    label: "Subagents max active runs per chat".into(),
                    value: existing
                        .get(subagents_max_active_per_chat_key())
                        .cloned()
                        .unwrap_or_else(|| "5".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_run_timeout_secs_key().into(),
                    label: "Subagents run timeout secs".into(),
                    value: existing
                        .get(subagents_run_timeout_secs_key())
                        .cloned()
                        .unwrap_or_else(|| "900".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_announce_to_chat_key().into(),
                    label: "Subagents announce to chat (true/false)".into(),
                    value: existing
                        .get(subagents_announce_to_chat_key())
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_spawn_depth_key().into(),
                    label: "Subagents max spawn depth".into(),
                    value: existing
                        .get(subagents_max_spawn_depth_key())
                        .cloned()
                        .unwrap_or_else(|| "1".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_children_per_run_key().into(),
                    label: "Subagents max children per run".into(),
                    value: existing
                        .get(subagents_max_children_per_run_key())
                        .cloned()
                        .unwrap_or_else(|| "5".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_thread_bound_routing_enabled_key().into(),
                    label: "Subagents thread-bound routing enabled (true/false)".into(),
                    value: existing
                        .get(subagents_thread_bound_routing_enabled_key())
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_announce_relay_interval_secs_key().into(),
                    label: "Subagents announce relay interval secs".into(),
                    value: existing
                        .get(subagents_announce_relay_interval_secs_key())
                        .cloned()
                        .unwrap_or_else(|| "15".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_max_tokens_per_run_key().into(),
                    label: "Subagents max tokens per run".into(),
                    value: existing
                        .get(subagents_max_tokens_per_run_key())
                        .cloned()
                        .unwrap_or_else(|| "400000".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_orchestrate_max_workers_key().into(),
                    label: "Subagents orchestrate max workers".into(),
                    value: existing
                        .get(subagents_orchestrate_max_workers_key())
                        .cloned()
                        .unwrap_or_else(|| "5".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_enabled_key().into(),
                    label: "ACP subagent runtime enabled (true/false)".into(),
                    value: existing
                        .get(subagents_acp_enabled_key())
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_command_key().into(),
                    label: "ACP default command (optional)".into(),
                    value: existing
                        .get(subagents_acp_command_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_args_key().into(),
                    label: "ACP default args (csv or JSON array, optional)".into(),
                    value: existing
                        .get(subagents_acp_args_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_env_json_key().into(),
                    label: "ACP default env JSON (optional)".into(),
                    value: existing
                        .get(subagents_acp_env_json_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: subagents_acp_auto_approve_key().into(),
                    label: "ACP default auto-approve permissions (true/false)".into(),
                    value: existing
                        .get(subagents_acp_auto_approve_key())
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_default_target_key().into(),
                    label: "ACP named default target (optional)".into(),
                    value: existing
                        .get(subagents_acp_default_target_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: subagents_acp_targets_json_key().into(),
                    label: "ACP named targets JSON (optional)".into(),
                    value: existing
                        .get(subagents_acp_targets_json_key())
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
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
                    label: "Telegram LLM provider profile override (optional)".into(),
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
                    key: telegram_topic_routing_key().into(),
                    label: "Telegram topic routing (optional true/false)".into(),
                    value: existing
                        .get(telegram_topic_routing_key())
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
                    value: existing
                        .get("DISCORD_BOT_TOKEN")
                        .cloned()
                        .unwrap_or_default(),
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
                    label: "Discord LLM provider profile override (optional)".into(),
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
                    key: "LLM_USER_AGENT".into(),
                    label: "LLM user-agent (optional)".into(),
                    value: existing.get("LLM_USER_AGENT").cloned().unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "SHOW_THINKING".into(),
                    label: "LLM Show thinking/reasoning text (true/false)".into(),
                    value: existing
                        .get("SHOW_THINKING")
                        .cloned()
                        .unwrap_or_else(|| "false".into()),
                    required: false,
                    secret: false,
                },
                Field {
                    key: llm_provider_profiles_key().into(),
                    label: "LLM provider profiles (optional)".into(),
                    value: existing
                        .get(llm_provider_profiles_key())
                        .cloned()
                        .unwrap_or_default(),
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
                    key: "WORKING_DIR".into(),
                    label: "Working directory".into(),
                    value: existing
                        .get("WORKING_DIR")
                        .cloned()
                        .unwrap_or_else(default_working_dir_for_setup),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "OVERRIDE_TIMEZONE".into(),
                    label: "Override timezone (optional, IANA; default uses system timezone)"
                        .into(),
                    value: existing
                        .get("OVERRIDE_TIMEZONE")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "SOULS_DIR".into(),
                    label: "SOUL files directory (optional)".into(),
                    value: existing
                        .get("SOULS_DIR")
                        .cloned()
                        .unwrap_or_else(default_souls_dir_for_setup),
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
                    key: "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED".into(),
                    label:
                        "Require explicit confirmation before running high-risk tools (true/false)"
                            .into(),
                    value: existing
                        .get("HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED")
                        .cloned()
                        .unwrap_or_else(|| "true".into()),
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
                    value: existing
                        .get("EMBEDDING_PROVIDER")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                },
                Field {
                    key: "EMBEDDING_API_KEY".into(),
                    label: "Embedding API key (optional)".into(),
                    value: existing
                        .get("EMBEDDING_API_KEY")
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: true,
                },
                Field {
                    key: "EMBEDDING_BASE_URL".into(),
                    label: "Embedding base URL (optional)".into(),
                    value: existing
                        .get("EMBEDDING_BASE_URL")
                        .cloned()
                        .unwrap_or_default(),
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
            field_window: UI_FIELD_WINDOW,
            visible_cache_sig: Cell::new(u64::MAX),
            visible_cache_indices: RefCell::new(Vec::new()),
            editing: false,
            picker: None,
            status: "Ready. Enter to edit, F2 validate, s save, q quit.".into(),
            completed: false,
            backup_path: None,
            completion_summary: Vec::new(),
            llm_override_page: None,
            llm_override_picker: None,
            provider_preset_page: None,
        };

        for slot in 1..=MAX_BOT_SLOTS {
            app.fields.push(Field {
                key: telegram_slot_id_key(slot),
                label: format!("Telegram bot #{slot}: id"),
                value: existing
                    .get(&telegram_slot_id_key(slot))
                    .cloned()
                    .unwrap_or_else(|| default_slot_account_id(slot)),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_enabled_key(slot),
                label: format!("Telegram bot #{slot}: enabled (true/false)"),
                value: existing
                    .get(&telegram_slot_enabled_key(slot))
                    .cloned()
                    .unwrap_or_else(|| "true".to_string()),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_token_key(slot),
                label: format!("Telegram bot #{slot}: token"),
                value: existing
                    .get(&telegram_slot_token_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: true,
            });
            app.fields.push(Field {
                key: telegram_slot_username_key(slot),
                label: format!("Telegram bot #{slot}: username (no @)"),
                value: existing
                    .get(&telegram_slot_username_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_model_key(slot),
                label: format!("Telegram bot #{slot}: LLM provider profile override (optional)"),
                value: existing
                    .get(&telegram_slot_model_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_soul_path_key(slot),
                label: format!("Telegram bot #{slot}: SOUL.md (optional)"),
                value: existing
                    .get(&telegram_slot_soul_path_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_allowed_user_ids_key(slot),
                label: format!("Telegram bot #{slot}: allowed user ids (csv/array, optional)"),
                value: existing
                    .get(&telegram_slot_allowed_user_ids_key(slot))
                    .cloned()
                    .unwrap_or_default(),
                required: false,
                secret: false,
            });
            app.fields.push(Field {
                key: telegram_slot_topic_routing_key(slot),
                label: format!(
                    "Telegram bot #{slot}: topic routing override (optional true/false)"
                ),
                value: existing
                    .get(&telegram_slot_topic_routing_key(slot))
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
                    label: format!("{} bot #{slot}: id", ch.name),
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
                    label: format!("{} bot #{slot}: enabled (true/false)", ch.name),
                    value: existing
                        .get(&dynamic_slot_enabled_field_key(ch.name, slot))
                        .cloned()
                        .unwrap_or_else(|| "true".to_string()),
                    required: false,
                    secret: false,
                });
                app.fields.push(Field {
                    key: dynamic_slot_soul_path_field_key(ch.name, slot),
                    label: format!("{} bot #{slot}: SOUL.md (optional)", ch.name),
                    value: existing
                        .get(&dynamic_slot_soul_path_field_key(ch.name, slot))
                        .cloned()
                        .unwrap_or_default(),
                    required: false,
                    secret: false,
                });
                for f in ch.fields {
                    let compact_label = trim_channel_prefix(ch.name, f.label);
                    app.fields.push(Field {
                        key: dynamic_slot_field_key(ch.name, slot, f.yaml_key),
                        label: format!("{} bot #{slot}: {}", ch.name, compact_label),
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
                                "{} bot #{slot}: LLM provider override (optional)",
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
                                "{} bot #{slot}: LLM API key override (optional)",
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
                                "{} bot #{slot}: LLM base URL override (optional)",
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
    pub(crate) fn load_existing_config() -> HashMap<String, String> {
        let yaml_path = crate::config::Config::config_path_for_setup();

        if yaml_path.exists() {
            if let Ok(content) = fs::read_to_string(&yaml_path) {
                let explicit_enabled_channels = serde_yaml::from_str::<serde_yaml::Value>(&content)
                    .ok()
                    .and_then(|doc| {
                        let channels = doc.get("channels")?.as_mapping()?;
                        let mut enabled = Vec::new();
                        for channel in Self::channel_options() {
                            let is_enabled = channels
                                .get(serde_yaml::Value::String(channel.to_string()))
                                .and_then(|v| v.as_mapping())
                                .and_then(|mapping| {
                                    mapping.get(serde_yaml::Value::String("enabled".to_string()))
                                })
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if is_enabled {
                                enabled.push(channel.to_string());
                            }
                        }
                        Some(enabled)
                    });
                if let Ok(config) = serde_yaml::from_str::<crate::config::Config>(&content) {
                    let mut map = HashMap::new();
                    let mut enabled = explicit_enabled_channels.unwrap_or_default();
                    if enabled.is_empty() {
                        if config.web_enabled {
                            enabled.push("web".to_string());
                        }
                        if !config.telegram_bot_token.trim().is_empty() {
                            enabled.push("telegram".to_string());
                        }
                        if config
                            .discord_bot_token
                            .as_deref()
                            .map(|v| !v.trim().is_empty())
                            .unwrap_or(false)
                        {
                            enabled.push("discord".to_string());
                        }
                    }
                    map.insert("ENABLED_CHANNELS".into(), enabled.join(","));
                    if let Some(web_cfg) = config.channels.get("web").and_then(|v| v.as_mapping()) {
                        if let Some(v) = web_cfg
                            .get(serde_yaml::Value::String("hooks_token".to_string()))
                            .or_else(|| {
                                web_cfg.get(serde_yaml::Value::String("hook_token".to_string()))
                            })
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            map.insert(web_hooks_token_key().into(), v.to_string());
                        }
                        if let Some(v) = web_cfg
                            .get(serde_yaml::Value::String(
                                "hooks_default_session_key".to_string(),
                            ))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            map.insert(web_hooks_default_session_key_key().into(), v.to_string());
                        }
                        if let Some(v) = web_cfg
                            .get(serde_yaml::Value::String(
                                "hooks_allow_request_session_key".to_string(),
                            ))
                            .and_then(|v| v.as_bool())
                        {
                            map.insert(
                                web_hooks_allow_request_session_key_key().into(),
                                v.to_string(),
                            );
                        }
                        if let Some(seq) = web_cfg
                            .get(serde_yaml::Value::String(
                                "hooks_allowed_session_key_prefixes".to_string(),
                            ))
                            .and_then(|v| v.as_sequence())
                        {
                            let prefixes = seq
                                .iter()
                                .filter_map(|item| item.as_str())
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .collect::<Vec<_>>();
                            if !prefixes.is_empty() {
                                map.insert(
                                    web_hooks_allowed_session_key_prefixes_key().into(),
                                    prefixes.join(","),
                                );
                            }
                        }
                    }
                    map.insert(a2a_enabled_key().into(), config.a2a.enabled.to_string());
                    if let Some(v) = config
                        .a2a
                        .public_base_url
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        map.insert(a2a_public_base_url_key().into(), v.to_string());
                    }
                    if let Some(v) = config
                        .a2a
                        .agent_name
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        map.insert(a2a_agent_name_key().into(), v.to_string());
                    }
                    if let Some(v) = config
                        .a2a
                        .agent_description
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        map.insert(a2a_agent_description_key().into(), v.to_string());
                    }
                    if !config.a2a.shared_tokens.is_empty() {
                        map.insert(
                            a2a_shared_tokens_key().into(),
                            config.a2a.shared_tokens.join(","),
                        );
                    }
                    if !config.a2a.peers.is_empty() {
                        let peers_json = serde_yaml::to_value(&config.a2a.peers)
                            .ok()
                            .and_then(|v| compact_json_string(&v));
                        if let Some(peers_json) = peers_json {
                            map.insert(a2a_peers_json_key().into(), peers_json);
                        }
                    }
                    map.insert(
                        subagents_max_concurrent_key().into(),
                        config.subagents.max_concurrent.to_string(),
                    );
                    map.insert(
                        subagents_max_active_per_chat_key().into(),
                        config.subagents.max_active_per_chat.to_string(),
                    );
                    map.insert(
                        subagents_run_timeout_secs_key().into(),
                        config.subagents.run_timeout_secs.to_string(),
                    );
                    map.insert(
                        subagents_announce_to_chat_key().into(),
                        config.subagents.announce_to_chat.to_string(),
                    );
                    map.insert(
                        subagents_max_spawn_depth_key().into(),
                        config.subagents.max_spawn_depth.to_string(),
                    );
                    map.insert(
                        subagents_max_children_per_run_key().into(),
                        config.subagents.max_children_per_run.to_string(),
                    );
                    map.insert(
                        subagents_thread_bound_routing_enabled_key().into(),
                        config.subagents.thread_bound_routing_enabled.to_string(),
                    );
                    map.insert(
                        subagents_announce_relay_interval_secs_key().into(),
                        config.subagents.announce_relay_interval_secs.to_string(),
                    );
                    map.insert(
                        subagents_max_tokens_per_run_key().into(),
                        config.subagents.max_tokens_per_run.to_string(),
                    );
                    map.insert(
                        subagents_orchestrate_max_workers_key().into(),
                        config.subagents.orchestrate_max_workers.to_string(),
                    );
                    map.insert(
                        subagents_acp_enabled_key().into(),
                        config.subagents.acp.default_target.enabled.to_string(),
                    );
                    if !config.subagents.acp.default_target.command.is_empty() {
                        map.insert(
                            subagents_acp_command_key().into(),
                            config.subagents.acp.default_target.command.clone(),
                        );
                    }
                    if !config.subagents.acp.default_target.args.is_empty() {
                        let args_json =
                            serde_json::to_string(&config.subagents.acp.default_target.args).ok();
                        if let Some(args_json) = args_json {
                            map.insert(subagents_acp_args_key().into(), args_json);
                        }
                    }
                    if !config.subagents.acp.default_target.env.is_empty() {
                        let env_json =
                            serde_json::to_string(&config.subagents.acp.default_target.env).ok();
                        if let Some(env_json) = env_json {
                            map.insert(subagents_acp_env_json_key().into(), env_json);
                        }
                    }
                    map.insert(
                        subagents_acp_auto_approve_key().into(),
                        config.subagents.acp.default_target.auto_approve.to_string(),
                    );
                    if let Some(default_target) = config.subagents.acp.default_target_name.clone() {
                        map.insert(subagents_acp_default_target_key().into(), default_target);
                    }
                    if !config.subagents.acp.targets.is_empty() {
                        let targets_json =
                            serde_json::to_string(&config.subagents.acp.targets).ok();
                        if let Some(targets_json) = targets_json {
                            map.insert(subagents_acp_targets_json_key().into(), targets_json);
                        }
                    }
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
                    let telegram_profile_override = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                                .and_then(|v| {
                                    v.as_str()
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                        .map(ToOwned::to_owned)
                                })
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
                    let telegram_topic_routing = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| ch_cfg.get("topic_routing"))
                        .and_then(|v| v.get("enabled"))
                        .and_then(|v| v.as_bool())
                        .map(|b| b.to_string())
                        .unwrap_or_default();
                    let telegram_llm_provider = config
                        .channels
                        .get("telegram")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                        })
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
                    let discord_profile_override = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                                .and_then(|v| v.as_str())
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .map(ToOwned::to_owned)
                        })
                        .unwrap_or_default();
                    let discord_llm_provider = config
                        .channels
                        .get("discord")
                        .and_then(|ch_cfg| {
                            ch_cfg
                                .get("provider_preset")
                                .or_else(|| ch_cfg.get("llm_provider"))
                        })
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
                    map.insert("TELEGRAM_MODEL".into(), telegram_profile_override.clone());
                    map.insert(
                        telegram_allowed_user_ids_key().into(),
                        telegram_allowed_user_ids.clone(),
                    );
                    map.insert(
                        telegram_topic_routing_key().into(),
                        telegram_topic_routing.clone(),
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
                                        .get("provider_preset")
                                        .or_else(|| account.get("llm_provider"))
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(telegram_slot_model_key(slot), v.to_string());
                                    }
                                    if let Some(v) = account
                                        .get("soul_path")
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            telegram_slot_soul_path_key(slot),
                                            v.to_string(),
                                        );
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
                                    if let Some(v) = account
                                        .get("topic_routing")
                                        .and_then(|v| v.get("enabled"))
                                        .and_then(|v| v.as_bool())
                                    {
                                        map.insert(
                                            telegram_slot_topic_routing_key(slot),
                                            v.to_string(),
                                        );
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
                    map.insert("DISCORD_BOT_TOKEN".into(), discord_bot_token);
                    map.insert("DISCORD_ACCOUNT_ID".into(), discord_account_id);
                    map.insert("DISCORD_MODEL".into(), discord_profile_override);
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
                                                    v.as_bool().map(|b| b.to_string()).or_else(
                                                        || v.as_u64().map(|n| n.to_string()),
                                                    )
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
                                        .and_then(|a| a.get("soul_path"))
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                    {
                                        map.insert(
                                            dynamic_slot_soul_path_field_key(ch.name, slot),
                                            v.to_string(),
                                        );
                                    }
                                    if let Some(v) = account
                                        .and_then(|a| {
                                            a.get("provider_preset")
                                                .or_else(|| a.get("llm_provider"))
                                        })
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
                                                v.as_bool()
                                                    .map(|b| b.to_string())
                                                    .or_else(|| v.as_u64().map(|n| n.to_string()))
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
                    if config.llm_user_agent != crate::http_client::default_llm_user_agent() {
                        map.insert("LLM_USER_AGENT".into(), config.llm_user_agent);
                    }
                    let presets_for_setup = if !config.provider_presets.is_empty() {
                        config.provider_presets.clone()
                    } else {
                        config
                            .llm_providers
                            .clone()
                            .into_iter()
                            .filter(|(alias, _)| !alias.eq_ignore_ascii_case("main"))
                            .collect()
                    };
                    if !presets_for_setup.is_empty() {
                        let presets_json = serde_json::to_string(&presets_for_setup).ok();
                        if let Some(presets_json) = presets_json {
                            map.insert(llm_provider_profiles_key().into(), presets_json);
                        }
                    }
                    map.insert("SHOW_THINKING".into(), config.show_thinking.to_string());
                    map.insert("DATA_DIR".into(), config.data_dir);
                    map.insert(
                        "OVERRIDE_TIMEZONE".into(),
                        config.override_timezone.clone().unwrap_or_default(),
                    );
                    map.insert("WORKING_DIR".into(), config.working_dir);
                    if let Some(v) = config.souls_dir {
                        map.insert("SOULS_DIR".into(), v);
                    }
                    map.insert(
                        "SANDBOX_ENABLED".into(),
                        (config.sandbox.mode == crate::config::SandboxMode::All).to_string(),
                    );
                    map.insert(
                        "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED".into(),
                        config.high_risk_tool_user_confirmation_required.to_string(),
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

    pub(crate) fn to_env_map(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for field in &self.fields {
            out.insert(field.key.to_string(), field.value.trim().to_string());
        }
        out
    }

    pub(crate) fn enabled_channels(&self) -> Vec<String> {
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

    pub(crate) fn channel_enabled(&self, channel: &str) -> bool {
        self.enabled_channels().iter().any(|c| c == channel)
    }

    pub(crate) fn telegram_bot_count(&self) -> usize {
        parse_bot_count(
            &self.field_value(telegram_bot_count_key()),
            telegram_bot_count_key(),
        )
        .unwrap_or(1)
    }

    pub(crate) fn telegram_slot_accounts_from_fields(
        &self,
    ) -> Result<serde_json::Map<String, serde_json::Value>, MicroClawError> {
        let mut out = serde_json::Map::new();
        for slot in 1..=self.telegram_bot_count() {
            let id = self.field_value(&telegram_slot_id_key(slot));
            let token = self.field_value(&telegram_slot_token_key(slot));
            let username = self.field_value(&telegram_slot_username_key(slot));
            let model = self.field_value(&telegram_slot_model_key(slot));
            let soul_path = self
                .normalize_soul_path_value(&self.field_value(&telegram_slot_soul_path_key(slot)));
            let allowed_user_ids_raw = self.field_value(&telegram_slot_allowed_user_ids_key(slot));
            let allowed_user_ids = parse_i64_list_field(
                &allowed_user_ids_raw,
                &telegram_slot_allowed_user_ids_key(slot),
            )?;
            let topic_routing_raw = self.field_value(&telegram_slot_topic_routing_key(slot));
            let topic_routing_enabled = if topic_routing_raw.trim().is_empty() {
                None
            } else {
                Some(parse_boolish(&topic_routing_raw, false).map_err(|_| {
                    MicroClawError::Config(format!(
                        "{} must be true/false (or 1/0)",
                        telegram_slot_topic_routing_key(slot)
                    ))
                })?)
            };
            let enabled = parse_boolish(&self.field_value(&telegram_slot_enabled_key(slot)), true)?;
            let has_any = !token.is_empty()
                || !username.is_empty()
                || !model.is_empty()
                || !soul_path.is_empty()
                || !allowed_user_ids.is_empty()
                || topic_routing_enabled.is_some();
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
            if !soul_path.is_empty() {
                account.insert(
                    "soul_path".to_string(),
                    serde_json::Value::String(soul_path),
                );
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
            if let Some(enabled) = topic_routing_enabled {
                account.insert(
                    "topic_routing".to_string(),
                    serde_json::json!({ "enabled": enabled }),
                );
            }
            out.insert(account_id, serde_json::Value::Object(account));
        }
        Ok(out)
    }

    pub(crate) fn dynamic_bot_count(&self, channel: &str) -> usize {
        let key = dynamic_bot_count_field_key(channel);
        parse_bot_count(&self.field_value(&key), &key).unwrap_or(1)
    }

    pub(crate) fn dynamic_field_channel(key: &str) -> Option<&'static str> {
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
                    || key == dynamic_slot_soul_path_field_key(ch.name, slot)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

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
    fn test_setup_does_not_auto_enable_channels_from_present_but_disabled_blocks() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_disabled_channel_blocks_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
api_key: key
channels:
  web:
    enabled: true
  discord:
    enabled: false
    default_account: "ops"
    accounts:
      ops:
        bot_token: "discord_token_123"
  slack:
    enabled: false
    app_token: "xapp-1"
    bot_token: "xoxb-1"
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value("ENABLED_CHANNELS"), "web");

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_load_existing_config_keeps_legacy_top_level_channel_inference() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_legacy_channel_inference_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
api_key: key
telegram_bot_token: "tg_token_123"
bot_username: "tg_bot"
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        let enabled = app.field_value("ENABLED_CHANNELS");
        assert!(enabled.split(',').any(|channel| channel == "telegram"));
        assert!(!enabled.split(',').any(|channel| channel == "discord"));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_setup_loads_existing_provider_presets_from_legacy_llm_providers() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_provider_presets_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        std::fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
llm_provider: anthropic
api_key: key
llm_providers:
  "1":
    provider: openai
    api_key: preset-key
    default_model: gpt-5.2
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        let presets = app.field_value(llm_provider_profiles_key());
        assert!(presets.contains("\"1\""));
        assert!(presets.contains("\"provider\":\"openai\""));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_a2a_fields_render_in_a2a_section() {
        assert_eq!(SetupApp::section_for_key(a2a_enabled_key()), "A2A");
        assert_eq!(SetupApp::section_for_key(a2a_public_base_url_key()), "A2A");
        assert_eq!(SetupApp::section_for_key("ENABLED_CHANNELS"), "Channel");
    }

    #[test]
    fn test_setup_loads_existing_telegram_topic_routing() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_setup_load_telegram_topic_routing_{}",
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
  telegram:
    enabled: true
    topic_routing:
      enabled: true
"#,
        )
        .unwrap();

        let app = SetupApp::new();
        assert_eq!(app.field_value(telegram_topic_routing_key()), "true");

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_next_provider_preset_id_uses_provider_prefix() {
        let entries = vec![
            ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
            ProviderPresetDraft {
                id: "provider3".into(),
                provider: "anthropic".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
        ];
        assert_eq!(SetupApp::next_provider_preset_id(&entries), "provider2");
    }

    #[test]
    fn test_next_cloned_provider_preset_id_uses_incrementing_dash_suffix() {
        let entries = vec![
            ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
            ProviderPresetDraft {
                id: "provider1-2".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: String::new(),
                user_agent: String::new(),
                default_model: String::new(),
                show_thinking: false,
            },
        ];
        assert_eq!(
            SetupApp::next_cloned_provider_preset_id(&entries, "provider1"),
            "provider1-3"
        );
    }

    #[test]
    fn test_provider_presets_field_comes_after_show_thinking_in_model_section() {
        let app = SetupApp::new();
        let show_idx = app
            .fields
            .iter()
            .position(|f| f.key == "SHOW_THINKING")
            .unwrap();
        let presets_idx = app
            .fields
            .iter()
            .position(|f| f.key == llm_provider_profiles_key())
            .unwrap();
        assert!(presets_idx > show_idx);
    }

    #[test]
    fn test_delete_selected_provider_preset_blocks_when_referenced() {
        let mut app = SetupApp::new();
        app.set_field_value(telegram_llm_provider_key(), "1".into());
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
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let err = app.delete_selected_provider_preset(false).unwrap_err();
        assert!(err.to_string().contains("still referenced"));
        assert_eq!(app.field_value(telegram_llm_provider_key()), "1");
        assert_eq!(
            app.provider_preset_page
                .as_ref()
                .map(|page| page.entries.len())
                .unwrap_or_default(),
            1
        );
    }

    #[test]
    fn test_delete_selected_provider_preset_can_reset_refs_to_main() {
        let mut app = SetupApp::new();
        app.set_field_value(telegram_llm_provider_key(), "1".into());
        app.set_field_value(&dynamic_slot_llm_provider_key("slack", 1), "1".into());
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
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let updated_refs = app.delete_selected_provider_preset(true).unwrap();
        assert_eq!(
            updated_refs,
            vec!["slack.main".to_string(), "telegram channel".to_string()]
        );
        assert_eq!(app.field_value(telegram_llm_provider_key()), "");
        assert_eq!(
            app.field_value(&dynamic_slot_llm_provider_key("slack", 1)),
            ""
        );
        assert_eq!(
            app.provider_preset_page
                .as_ref()
                .map(|page| page.entries.len())
                .unwrap_or_default(),
            0
        );
    }

    #[test]
    fn test_provider_preset_field_label_uses_default_model() {
        assert_eq!(SetupApp::provider_preset_field_labels()[3], "Default model");
    }

    #[test]
    fn test_validate_local_accepts_minimal_weixin() {
        let mut app = SetupApp::new();
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            field.value = "weixin".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_PROVIDER") {
            field.value = "anthropic".to_string();
        }
        if let Some(field) = app.fields.iter_mut().find(|f| f.key == "LLM_API_KEY") {
            field.value = "key".to_string();
        }

        let result = app.validate_local();
        assert!(result.is_ok(), "validate_local failed: {result:?}");
    }

    #[test]
    fn validate_local_requires_an_enabled_channel() {
        let mut app = SetupApp::new();
        // Fresh app defaults to `web` enabled, so the channel gate passes.
        assert!(!app.enabled_channels().is_empty());
        // Clearing all channels must block save with a clear message.
        if let Some(f) = app.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
            f.value = String::new();
        }
        let err = app.validate_local().unwrap_err().to_string();
        assert!(err.contains("at least one channel"), "got: {err}");
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
}
