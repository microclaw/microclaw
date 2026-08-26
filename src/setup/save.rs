use super::*;

pub(crate) const CONFIG_BACKUP_DIR_NAME: &str = "microclaw.config.backups";

pub(crate) const MAX_CONFIG_BACKUPS: usize = 50;

pub(crate) fn config_backup_dir_for(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CONFIG_BACKUP_DIR_NAME)
}

pub(crate) fn prune_old_config_backups(
    backup_dir: &Path,
    file_name: &str,
    keep_latest: usize,
) -> Result<(), MicroClawError> {
    let prefix = format!("{file_name}.bak.");
    let mut entries = Vec::new();
    for entry in fs::read_dir(backup_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        entries.push((modified, entry.path()));
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, path) in entries.into_iter().skip(keep_latest) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

pub(crate) fn create_config_backup(path: &Path) -> Result<Option<String>, MicroClawError> {
    if !path.exists() {
        return Ok(None);
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("microclaw.config.yaml");
    let backup_dir = config_backup_dir_for(path);
    fs::create_dir_all(&backup_dir).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to create config backup dir {}: {}",
            backup_dir.display(),
            e
        ))
    })?;
    let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let backup_path = backup_dir.join(format!("{file_name}.bak.{ts}"));
    fs::copy(path, &backup_path).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to write config backup {}: {}",
            backup_path.display(),
            e
        ))
    })?;
    let _ = prune_old_config_backups(&backup_dir, file_name, MAX_CONFIG_BACKUPS);
    Ok(Some(backup_path.display().to_string()))
}

pub(crate) fn save_config_yaml(
    path: &Path,
    values: &HashMap<String, String>,
) -> Result<Option<String>, MicroClawError> {
    let backup = create_config_backup(path)?;

    let get = |key: &str| values.get(key).cloned().unwrap_or_default();
    let get_with_fallback = |key: &str, default: &str| {
        values
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let data_dir = values
        .get("DATA_DIR")
        .cloned()
        .unwrap_or_else(default_data_dir_for_setup);
    let souls_dir = values
        .get("SOULS_DIR")
        .cloned()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| {
            Path::new(&data_dir)
                .join("souls")
                .to_string_lossy()
                .to_string()
        });

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
    let web_hooks_token = get(web_hooks_token_key());
    let web_hooks_default_session_key = get(web_hooks_default_session_key_key());
    let web_hooks_allow_request_session_key_raw = get(web_hooks_allow_request_session_key_key());
    let web_hooks_allow_request_session_key =
        parse_boolish(&web_hooks_allow_request_session_key_raw, false)?;
    let web_hooks_allowed_session_key_prefixes =
        parse_string_list_field(&get(web_hooks_allowed_session_key_prefixes_key()))?;
    let a2a_enabled = parse_boolish(&get(a2a_enabled_key()), false)?;
    let a2a_public_base_url = get(a2a_public_base_url_key()).trim().to_string();
    let a2a_agent_name = get(a2a_agent_name_key()).trim().to_string();
    let a2a_agent_description = get(a2a_agent_description_key()).trim().to_string();
    let a2a_shared_tokens = parse_string_list_field(&get(a2a_shared_tokens_key()))?;
    let a2a_peers_raw = get(a2a_peers_json_key());
    let a2a_peers = if a2a_peers_raw.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str::<HashMap<String, crate::config::A2APeerConfig>>(a2a_peers_raw.trim())
            .map_err(|e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    a2a_peers_json_key()
                ))
            })?
    };
    let provider_presets = parse_provider_presets_json_value(
        &get(llm_provider_profiles_key()),
        llm_provider_profiles_key(),
    )?;
    let parse_usize_or_default = |raw: String, key: &str, default: usize| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        trimmed
            .parse::<usize>()
            .map_err(|e| MicroClawError::Config(format!("{key} must be a positive integer: {e}")))
    };
    let parse_u64_or_default = |raw: String, key: &str, default: u64| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        trimmed
            .parse::<u64>()
            .map_err(|e| MicroClawError::Config(format!("{key} must be a positive integer: {e}")))
    };
    let parse_i64_or_default = |raw: String, key: &str, default: i64| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        trimmed
            .parse::<i64>()
            .map_err(|e| MicroClawError::Config(format!("{key} must be a positive integer: {e}")))
    };
    let subagents_max_concurrent = parse_usize_or_default(
        get_with_fallback(subagents_max_concurrent_key(), "4"),
        subagents_max_concurrent_key(),
        4,
    )?;
    let subagents_max_active_per_chat = parse_usize_or_default(
        get_with_fallback(subagents_max_active_per_chat_key(), "5"),
        subagents_max_active_per_chat_key(),
        5,
    )?;
    let subagents_run_timeout_secs = parse_u64_or_default(
        get_with_fallback(subagents_run_timeout_secs_key(), "900"),
        subagents_run_timeout_secs_key(),
        900,
    )?;
    let subagents_announce_to_chat = parse_boolish(&get(subagents_announce_to_chat_key()), false)?;
    let subagents_max_spawn_depth = parse_usize_or_default(
        get_with_fallback(subagents_max_spawn_depth_key(), "1"),
        subagents_max_spawn_depth_key(),
        1,
    )?;
    let subagents_max_children_per_run = parse_usize_or_default(
        get_with_fallback(subagents_max_children_per_run_key(), "5"),
        subagents_max_children_per_run_key(),
        5,
    )?;
    let subagents_thread_bound_routing_enabled =
        parse_boolish(&get(subagents_thread_bound_routing_enabled_key()), true)?;
    let subagents_announce_relay_interval_secs = parse_u64_or_default(
        get_with_fallback(subagents_announce_relay_interval_secs_key(), "15"),
        subagents_announce_relay_interval_secs_key(),
        15,
    )?;
    let subagents_max_tokens_per_run = parse_i64_or_default(
        get_with_fallback(subagents_max_tokens_per_run_key(), "400000"),
        subagents_max_tokens_per_run_key(),
        400_000,
    )?;
    let subagents_orchestrate_max_workers = parse_usize_or_default(
        get_with_fallback(subagents_orchestrate_max_workers_key(), "5"),
        subagents_orchestrate_max_workers_key(),
        5,
    )?;
    let subagents_acp_enabled = parse_boolish(&get(subagents_acp_enabled_key()), false)?;
    let subagents_acp_command = get(subagents_acp_command_key()).trim().to_string();
    let subagents_acp_args = parse_string_list_field(&get(subagents_acp_args_key()))?;
    let subagents_acp_env_raw = get(subagents_acp_env_json_key());
    let subagents_acp_env = if subagents_acp_env_raw.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str::<HashMap<String, String>>(subagents_acp_env_raw.trim()).map_err(
            |e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    subagents_acp_env_json_key()
                ))
            },
        )?
    };
    let subagents_acp_auto_approve = parse_boolish(&get(subagents_acp_auto_approve_key()), true)?;
    let subagents_acp_default_target = get(subagents_acp_default_target_key()).trim().to_string();
    let subagents_acp_targets_raw = get(subagents_acp_targets_json_key());
    let subagents_acp_targets = if subagents_acp_targets_raw.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str::<HashMap<String, crate::config::SubagentAcpTargetConfig>>(
            subagents_acp_targets_raw.trim(),
        )
        .map_err(|e| {
            MicroClawError::Config(format!(
                "{} must be valid JSON object: {e}",
                subagents_acp_targets_json_key()
            ))
        })?
    };
    let telegram_token = if !get("TELEGRAM_BOT_TOKEN").trim().is_empty() {
        get("TELEGRAM_BOT_TOKEN")
    } else {
        get(&telegram_slot_token_key(1))
    };
    let telegram_username = if !get("BOT_USERNAME").trim().is_empty() {
        get("BOT_USERNAME")
    } else {
        get(&telegram_slot_username_key(1))
    };
    let telegram_account_id =
        account_id_from_value(&if !get("TELEGRAM_ACCOUNT_ID").trim().is_empty() {
            get("TELEGRAM_ACCOUNT_ID")
        } else {
            get(&telegram_slot_id_key(1))
        });
    let telegram_profile_override = get("TELEGRAM_MODEL");
    let telegram_topic_routing_raw = get(telegram_topic_routing_key());
    let telegram_topic_routing = if telegram_topic_routing_raw.trim().is_empty() {
        false
    } else {
        parse_boolish(telegram_topic_routing_raw.trim(), false).map_err(|_| {
            MicroClawError::Config(format!(
                "{} must be true/false (or 1/0)",
                telegram_topic_routing_key()
            ))
        })?
    };
    let telegram_llm_provider = get(telegram_llm_provider_key());
    // Channel-level provider_preset: slot 1 (the default bot) is the
    // authoritative source when present, so clearing the bot preset also
    // clears the channel-level value.  Fall back to TELEGRAM_MODEL /
    // TELEGRAM_LLM_PROVIDER only for legacy configs that lack slot fields.
    let slot1_preset = get(&telegram_slot_model_key(1));
    let telegram_channel_profile_override = if !slot1_preset.trim().is_empty() {
        slot1_preset.trim().to_string()
    } else if values.contains_key(&telegram_slot_model_key(1)) {
        // Slot 1 field exists but is empty — user explicitly cleared it
        String::new()
    } else if !telegram_profile_override.trim().is_empty() {
        telegram_profile_override.trim().to_string()
    } else {
        telegram_llm_provider.trim().to_string()
    };
    let telegram_llm_api_key = get(telegram_llm_api_key_key());
    let telegram_llm_base_url = get(telegram_llm_base_url_key());
    let telegram_channel_allowed_user_ids = parse_i64_list_field(
        &get(telegram_allowed_user_ids_key()),
        telegram_allowed_user_ids_key(),
    )?;
    let telegram_bot_count =
        parse_bot_count(&get(telegram_bot_count_key()), telegram_bot_count_key())?;
    let mut telegram_slot_accounts = serde_json::Map::new();
    for slot in 1..=telegram_bot_count {
        let id = get(&telegram_slot_id_key(slot));
        let token = get(&telegram_slot_token_key(slot));
        let username = get(&telegram_slot_username_key(slot));
        let provider_preset = get(&telegram_slot_model_key(slot));
        let soul_path =
            normalize_soul_path_input(&get(&telegram_slot_soul_path_key(slot)), &souls_dir);
        let allowed_user_ids_raw = get(&telegram_slot_allowed_user_ids_key(slot));
        let allowed_user_ids = parse_i64_list_field(
            &allowed_user_ids_raw,
            &telegram_slot_allowed_user_ids_key(slot),
        )?;
        let slot_topic_routing_raw = get(&telegram_slot_topic_routing_key(slot));
        let slot_topic_routing_enabled = if slot_topic_routing_raw.trim().is_empty() {
            None
        } else {
            Some(
                parse_boolish(slot_topic_routing_raw.trim(), false).map_err(|_| {
                    MicroClawError::Config(format!(
                        "{} must be true/false (or 1/0)",
                        telegram_slot_topic_routing_key(slot)
                    ))
                })?,
            )
        };
        let enabled = parse_boolish(&get(&telegram_slot_enabled_key(slot)), true)?;
        let has_any = !token.trim().is_empty()
            || !username.trim().is_empty()
            || !provider_preset.trim().is_empty()
            || !soul_path.is_empty()
            || !allowed_user_ids.is_empty()
            || slot_topic_routing_enabled.is_some();
        if !has_any {
            continue;
        }
        let account_id = account_id_from_value(&id);
        if !is_valid_account_id(&account_id) {
            return Err(MicroClawError::Config(format!(
                "{} must use only letters, numbers, '_' or '-'",
                telegram_slot_id_key(slot)
            )));
        }
        let mut account = serde_json::Map::new();
        account.insert("enabled".into(), serde_json::Value::Bool(enabled));
        if !token.trim().is_empty() {
            account.insert(
                "bot_token".into(),
                serde_json::Value::String(token.trim().to_string()),
            );
        }
        if !username.trim().is_empty() {
            account.insert(
                "bot_username".into(),
                serde_json::Value::String(username.trim().to_string()),
            );
        }
        if !provider_preset.trim().is_empty()
            && !provider_preset.trim().eq_ignore_ascii_case("main")
        {
            account.insert(
                "provider_preset".into(),
                serde_json::Value::String(provider_preset.trim().to_string()),
            );
        }
        if let Some(enabled) = slot_topic_routing_enabled {
            account.insert(
                "topic_routing".into(),
                serde_json::json!({ "enabled": enabled }),
            );
        }
        if !soul_path.is_empty() {
            account.insert("soul_path".into(), serde_json::Value::String(soul_path));
        }
        if !allowed_user_ids.is_empty() {
            account.insert(
                "allowed_user_ids".into(),
                serde_json::Value::Array(
                    allowed_user_ids
                        .into_iter()
                        .map(|id| serde_json::Value::Number(id.into()))
                        .collect(),
                ),
            );
        }
        telegram_slot_accounts.insert(account_id, serde_json::Value::Object(account));
    }
    let telegram_accounts = if !telegram_slot_accounts.is_empty() {
        Some(telegram_slot_accounts)
    } else {
        None
    };
    let discord_token = get("DISCORD_BOT_TOKEN");
    let discord_account_id = account_id_from_value(&get("DISCORD_ACCOUNT_ID"));
    let discord_profile_override = get("DISCORD_MODEL");
    let discord_llm_provider = get(discord_llm_provider_key());
    let discord_channel_profile_override = if !discord_profile_override.trim().is_empty() {
        discord_profile_override.trim().to_string()
    } else {
        discord_llm_provider.trim().to_string()
    };
    let discord_llm_api_key = get(discord_llm_api_key_key());
    let discord_llm_base_url = get(discord_llm_base_url_key());
    let discord_accounts_json = get("DISCORD_ACCOUNTS_JSON");
    let discord_accounts =
        parse_accounts_json_value(&discord_accounts_json, "DISCORD_ACCOUNTS_JSON")?;

    let pick_default_account_id =
        |configured: &str, accounts: &serde_json::Map<String, serde_json::Value>| {
            let configured_trimmed = configured.trim();
            if !configured_trimmed.is_empty() && accounts.contains_key(configured_trimmed) {
                return configured_trimmed.to_string();
            }
            if accounts.contains_key("default") {
                return "default".to_string();
            }
            let mut keys: Vec<String> = accounts.keys().cloned().collect();
            keys.sort();
            keys.first()
                .cloned()
                .unwrap_or_else(|| default_account_id().to_string())
        };

    let telegram_present = !telegram_token.trim().is_empty()
        || !telegram_username.trim().is_empty()
        || !telegram_channel_profile_override.trim().is_empty()
        || !telegram_llm_api_key.trim().is_empty()
        || !telegram_llm_base_url.trim().is_empty()
        || !telegram_profile_override.trim().is_empty()
        || !normalize_soul_path_input(&get(&telegram_slot_soul_path_key(1)), &souls_dir).is_empty()
        || !telegram_channel_allowed_user_ids.is_empty()
        || telegram_accounts
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        || telegram_bot_count > 1;
    let discord_present = !discord_token.trim().is_empty()
        || !discord_channel_profile_override.trim().is_empty()
        || !discord_llm_api_key.trim().is_empty()
        || !discord_llm_base_url.trim().is_empty()
        || !discord_profile_override.trim().is_empty()
        || discord_accounts
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
    // Use slot presence keys so optional defaults do not create disabled blocks unexpectedly.
    let dynamic_channel_include: Vec<(&DynamicChannelDef, bool)> = DYNAMIC_CHANNELS
        .iter()
        .map(|ch| {
            let selected = channel_selected(ch.name);
            if dynamic_channel_uses_minimal_setup(ch.name) {
                return (ch, selected);
            }
            let bot_count = parse_bot_count(
                &get(&dynamic_bot_count_field_key(ch.name)),
                &dynamic_bot_count_field_key(ch.name),
            )
            .unwrap_or(1);
            let has_slot_presence = (1..=bot_count).any(|slot| {
                ch.presence_keys.iter().any(|yaml_key| {
                    !get(&dynamic_slot_field_key(ch.name, slot, yaml_key))
                        .trim()
                        .is_empty()
                }) || !normalize_soul_path_input(
                    &get(&dynamic_slot_soul_path_field_key(ch.name, slot)),
                    &souls_dir,
                )
                .is_empty()
                    || !get(&dynamic_slot_llm_provider_key(ch.name, slot))
                        .trim()
                        .is_empty()
                    || !get(&dynamic_slot_llm_api_key_key(ch.name, slot))
                        .trim()
                        .is_empty()
                    || !get(&dynamic_slot_llm_base_url_key(ch.name, slot))
                        .trim()
                        .is_empty()
            });
            (ch, selected || has_slot_presence)
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
    if !web_hooks_token.trim().is_empty() {
        yaml.push_str(&format!(
            "    hooks_token: {}\n",
            yaml_double_quoted(web_hooks_token.trim())
        ));
    }
    if !web_hooks_default_session_key.trim().is_empty() {
        yaml.push_str(&format!(
            "    hooks_default_session_key: {}\n",
            yaml_double_quoted(web_hooks_default_session_key.trim())
        ));
    }
    if !web_hooks_allow_request_session_key_raw.trim().is_empty() {
        yaml.push_str(&format!(
            "    hooks_allow_request_session_key: {}\n",
            web_hooks_allow_request_session_key
        ));
    }
    if !web_hooks_allowed_session_key_prefixes.is_empty() {
        yaml.push_str("    hooks_allowed_session_key_prefixes:\n");
        for prefix in &web_hooks_allowed_session_key_prefixes {
            yaml.push_str(&format!("      - {}\n", yaml_double_quoted(prefix)));
        }
    }

    if channel_selected("telegram") || telegram_present {
        yaml.push_str("  telegram:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("telegram")));
        if !telegram_channel_profile_override.trim().is_empty()
            && !telegram_channel_profile_override
                .trim()
                .eq_ignore_ascii_case("main")
        {
            yaml.push_str(&format!(
                "    provider_preset: \"{}\"\n",
                telegram_channel_profile_override.trim()
            ));
        }
        if !telegram_llm_api_key.trim().is_empty() {
            yaml.push_str(&format!(
                "    api_key: \"{}\"\n",
                telegram_llm_api_key.trim()
            ));
        }
        if !telegram_llm_base_url.trim().is_empty() {
            yaml.push_str(&format!(
                "    llm_base_url: \"{}\"\n",
                telegram_llm_base_url.trim()
            ));
        }
        if !telegram_topic_routing_raw.trim().is_empty() {
            yaml.push_str("    topic_routing:\n");
            yaml.push_str(&format!("      enabled: {}\n", telegram_topic_routing));
        }
        if !telegram_channel_allowed_user_ids.is_empty() {
            yaml.push_str("    allowed_user_ids:\n");
            for id in &telegram_channel_allowed_user_ids {
                yaml.push_str(&format!("      - {}\n", id));
            }
        }
        if let Some(accounts) = &telegram_accounts {
            let default_id = pick_default_account_id(&telegram_account_id, accounts);
            yaml.push_str(&format!("    default_account: \"{}\"\n", default_id));
            yaml.push_str("    accounts:\n");
            let yaml_accounts = serde_yaml::to_value(serde_json::Value::Object(accounts.clone()))
                .map_err(|e| {
                MicroClawError::Config(format!("Failed to render Telegram multi-bot accounts: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_accounts);
        } else if telegram_present {
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
            let slot1_soul =
                normalize_soul_path_input(&get(&telegram_slot_soul_path_key(1)), &souls_dir);
            if !slot1_soul.is_empty() {
                yaml.push_str(&format!("        soul_path: \"{}\"\n", slot1_soul));
            }
            // Per-account model is still driven by slot fields; channel-level model is emitted above.
        }
    }
    if channel_selected("discord") || discord_present {
        yaml.push_str("  discord:\n");
        yaml.push_str(&format!("    enabled: {}\n", channel_selected("discord")));
        if !discord_channel_profile_override.trim().is_empty()
            && !discord_channel_profile_override
                .trim()
                .eq_ignore_ascii_case("main")
        {
            yaml.push_str(&format!(
                "    provider_preset: \"{}\"\n",
                discord_channel_profile_override.trim()
            ));
        }
        if !discord_llm_api_key.trim().is_empty() {
            yaml.push_str(&format!(
                "    api_key: \"{}\"\n",
                discord_llm_api_key.trim()
            ));
        }
        if !discord_llm_base_url.trim().is_empty() {
            yaml.push_str(&format!(
                "    llm_base_url: \"{}\"\n",
                discord_llm_base_url.trim()
            ));
        }
        if let Some(accounts) = &discord_accounts {
            let default_id = pick_default_account_id(&discord_account_id, accounts);
            yaml.push_str(&format!("    default_account: \"{}\"\n", default_id));
            yaml.push_str("    accounts:\n");
            let yaml_accounts = serde_yaml::to_value(serde_json::Value::Object(accounts.clone()))
                .map_err(|e| {
                MicroClawError::Config(format!("Failed to render DISCORD_ACCOUNTS_JSON: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_accounts);
        } else if discord_present {
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
        }
    }

    for (ch, include) in &dynamic_channel_include {
        if !include {
            continue;
        }
        if dynamic_channel_uses_minimal_setup(ch.name) {
            yaml.push_str(&format!("  {}:\n", ch.name));
            yaml.push_str(&format!("    enabled: {}\n", channel_selected(ch.name)));
            continue;
        }
        let bot_count_key = dynamic_bot_count_field_key(ch.name);
        let bot_count = parse_bot_count(&get(&bot_count_key), &bot_count_key)?;
        let mut accounts_map = serde_json::Map::new();
        for slot in 1..=bot_count {
            let id = get(&dynamic_slot_id_field_key(ch.name, slot));
            let enabled =
                parse_boolish(&get(&dynamic_slot_enabled_field_key(ch.name, slot)), true)?;
            let soul_path = normalize_soul_path_input(
                &get(&dynamic_slot_soul_path_field_key(ch.name, slot)),
                &souls_dir,
            );
            let has_any = ch
                .fields
                .iter()
                .any(|f| !effective_dynamic_slot_field_value(ch.name, slot, f, get).is_empty())
                || !soul_path.is_empty();
            if !has_any {
                continue;
            }
            let account_id = account_id_from_value(&id);
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(format!(
                    "{} must use only letters, numbers, '_' or '-'",
                    dynamic_slot_id_field_key(ch.name, slot)
                )));
            }
            let mut account = serde_json::Map::new();
            account.insert("enabled".into(), serde_json::Value::Bool(enabled));
            for f in ch.fields {
                let v = effective_dynamic_slot_field_value(ch.name, slot, f, get);
                if v.trim().is_empty() {
                    continue;
                }
                if dynamic_field_is_bool(ch.name, f.yaml_key) {
                    let parsed = parse_boolish(v.trim(), false).map_err(|_| {
                        MicroClawError::Config(format!(
                            "{} must be true/false (or 1/0)",
                            dynamic_slot_field_key(ch.name, slot, f.yaml_key)
                        ))
                    })?;
                    account.insert(f.yaml_key.to_string(), serde_json::Value::Bool(parsed));
                } else if dynamic_field_is_u64(ch.name, f.yaml_key) {
                    let field_key = dynamic_slot_field_key(ch.name, slot, f.yaml_key);
                    let parsed = parse_u64_field(v.trim(), &field_key)?;
                    account.insert(
                        f.yaml_key.to_string(),
                        serde_json::Value::Number(serde_json::Number::from(parsed)),
                    );
                } else {
                    account.insert(
                        f.yaml_key.to_string(),
                        serde_json::Value::String(v.trim().to_string()),
                    );
                }
            }
            if !soul_path.is_empty() {
                account.insert("soul_path".into(), serde_json::Value::String(soul_path));
            }
            if ch.name == "feishu" {
                let topic_mode = account
                    .get("topic_mode")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if topic_mode {
                    let domain = account
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .unwrap_or("feishu")
                        .to_ascii_lowercase();
                    if domain != "feishu" && domain != "lark" {
                        return Err(MicroClawError::Config(format!(
                            "{} topic_mode is only supported when domain is feishu or lark",
                            dynamic_slot_id_field_key(ch.name, slot)
                        )));
                    }
                }
            }
            let llm_provider = get(&dynamic_slot_llm_provider_key(ch.name, slot));
            if !llm_provider.trim().is_empty() && !llm_provider.trim().eq_ignore_ascii_case("main")
            {
                account.insert(
                    "provider_preset".into(),
                    serde_json::Value::String(llm_provider.trim().to_string()),
                );
            }
            let llm_api_key = get(&dynamic_slot_llm_api_key_key(ch.name, slot));
            if !llm_api_key.trim().is_empty() {
                account.insert(
                    "api_key".into(),
                    serde_json::Value::String(llm_api_key.trim().to_string()),
                );
            }
            let llm_base_url = get(&dynamic_slot_llm_base_url_key(ch.name, slot));
            if !llm_base_url.trim().is_empty() {
                account.insert(
                    "llm_base_url".into(),
                    serde_json::Value::String(llm_base_url.trim().to_string()),
                );
            }
            accounts_map.insert(account_id, serde_json::Value::Object(account));
        }
        let has_accounts = !accounts_map.is_empty();
        yaml.push_str(&format!("  {}:\n", ch.name));
        yaml.push_str(&format!("    enabled: {}\n", channel_selected(ch.name)));
        if has_accounts {
            let default_slot_id = get(&dynamic_slot_id_field_key(ch.name, 1));
            let account_id = account_id_from_value(&default_slot_id);
            let default_id = pick_default_account_id(&account_id, &accounts_map);
            yaml.push_str(&format!("    default_account: \"{}\"\n", default_id));
            yaml.push_str("    accounts:\n");
            let yaml_accounts = serde_yaml::to_value(serde_json::Value::Object(accounts_map))
                .map_err(|e| {
                    MicroClawError::Config(format!("Failed to render {} accounts: {e}", ch.name))
                })?;
            append_yaml_value(&mut yaml, 6, &yaml_accounts);
        }
    }
    if a2a_enabled
        || !a2a_public_base_url.is_empty()
        || !a2a_agent_name.is_empty()
        || !a2a_agent_description.is_empty()
        || !a2a_shared_tokens.is_empty()
        || !a2a_peers.is_empty()
    {
        yaml.push_str("a2a:\n");
        yaml.push_str(&format!("  enabled: {}\n", a2a_enabled));
        if !a2a_public_base_url.is_empty() {
            yaml.push_str(&format!(
                "  public_base_url: {}\n",
                yaml_double_quoted(&a2a_public_base_url)
            ));
        }
        if !a2a_agent_name.is_empty() {
            yaml.push_str(&format!(
                "  agent_name: {}\n",
                yaml_double_quoted(&a2a_agent_name)
            ));
        }
        if !a2a_agent_description.is_empty() {
            yaml.push_str(&format!(
                "  agent_description: {}\n",
                yaml_double_quoted(&a2a_agent_description)
            ));
        }
        if !a2a_shared_tokens.is_empty() {
            yaml.push_str("  shared_tokens:\n");
            for token in &a2a_shared_tokens {
                yaml.push_str(&format!("    - {}\n", yaml_double_quoted(token)));
            }
        }
        if !a2a_peers.is_empty() {
            yaml.push_str("  peers:\n");
            let yaml_peers = serde_yaml::to_value(&a2a_peers)
                .map_err(|e| MicroClawError::Config(format!("Failed to render A2A peers: {e}")))?;
            append_yaml_value(&mut yaml, 4, &yaml_peers);
        }
    }
    yaml.push_str("subagents:\n");
    yaml.push_str(&format!("  max_concurrent: {}\n", subagents_max_concurrent));
    yaml.push_str(&format!(
        "  max_active_per_chat: {}\n",
        subagents_max_active_per_chat
    ));
    yaml.push_str(&format!(
        "  run_timeout_secs: {}\n",
        subagents_run_timeout_secs
    ));
    yaml.push_str(&format!(
        "  announce_to_chat: {}\n",
        subagents_announce_to_chat
    ));
    yaml.push_str(&format!(
        "  max_spawn_depth: {}\n",
        subagents_max_spawn_depth
    ));
    yaml.push_str(&format!(
        "  max_children_per_run: {}\n",
        subagents_max_children_per_run
    ));
    yaml.push_str(&format!(
        "  thread_bound_routing_enabled: {}\n",
        subagents_thread_bound_routing_enabled
    ));
    yaml.push_str(&format!(
        "  announce_relay_interval_secs: {}\n",
        subagents_announce_relay_interval_secs
    ));
    yaml.push_str(&format!(
        "  max_tokens_per_run: {}\n",
        subagents_max_tokens_per_run
    ));
    yaml.push_str(&format!(
        "  orchestrate_max_workers: {}\n",
        subagents_orchestrate_max_workers
    ));
    if subagents_acp_enabled
        || !subagents_acp_command.is_empty()
        || !subagents_acp_args.is_empty()
        || !subagents_acp_env.is_empty()
        || !subagents_acp_auto_approve
        || !subagents_acp_default_target.is_empty()
        || !subagents_acp_targets.is_empty()
    {
        yaml.push_str("  acp:\n");
        yaml.push_str(&format!("    enabled: {}\n", subagents_acp_enabled));
        if !subagents_acp_command.is_empty() {
            yaml.push_str(&format!(
                "    command: {}\n",
                yaml_double_quoted(&subagents_acp_command)
            ));
        }
        if !subagents_acp_args.is_empty() {
            yaml.push_str("    args:\n");
            for arg in &subagents_acp_args {
                yaml.push_str(&format!("      - {}\n", yaml_double_quoted(arg)));
            }
        }
        if !subagents_acp_env.is_empty() {
            yaml.push_str("    env:\n");
            let yaml_env = serde_yaml::to_value(&subagents_acp_env).map_err(|e| {
                MicroClawError::Config(format!("Failed to render ACP env config: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_env);
        }
        yaml.push_str(&format!(
            "    auto_approve: {}\n",
            subagents_acp_auto_approve
        ));
        if !subagents_acp_default_target.is_empty() {
            yaml.push_str(&format!(
                "    default_target: {}\n",
                yaml_double_quoted(&subagents_acp_default_target)
            ));
        }
        if !subagents_acp_targets.is_empty() {
            yaml.push_str("    targets:\n");
            let yaml_targets = serde_yaml::to_value(&subagents_acp_targets).map_err(|e| {
                MicroClawError::Config(format!("Failed to render ACP targets config: {e}"))
            })?;
            append_yaml_value(&mut yaml, 6, &yaml_targets);
        }
    }
    yaml.push('\n');

    yaml.push_str(
        "# LLM provider (anthropic, openai-codex, ollama, openai, openrouter, deepseek, synthetic, chutes, google, etc.)\n",
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
    let llm_user_agent = get("LLM_USER_AGENT");
    if !llm_user_agent.is_empty() {
        yaml.push_str("# LLM HTTP User-Agent (optional)\n");
        yaml.push_str(&format!("llm_user_agent: \"{}\"\n", llm_user_agent));
    }
    if provider_presets.is_empty() {
        yaml.push_str("# Optional reusable provider profiles for per-bot/channel selection\n");
        yaml.push_str("# provider_presets:\n");
        yaml.push_str("#   provider1:\n");
        yaml.push_str("#     provider: \"openai\"\n");
        yaml.push_str("#     api_key: \"sk-...\"\n");
        yaml.push_str("#     llm_base_url: \"https://example.com/v1\"\n");
        yaml.push_str("#     llm_user_agent: \"microclaw/1.0\"\n");
        yaml.push_str("#     default_model: \"gpt-5.2\"\n");
        yaml.push_str("#     show_thinking: false\n");
        yaml.push_str("#   deepseek-hk:\n");
        yaml.push_str("#     provider: \"deepseek\"\n");
        yaml.push_str("#     api_key: \"sk-...\"\n");
    } else {
        yaml.push_str("provider_presets:\n");
        let yaml_presets = serde_yaml::to_value(&provider_presets).map_err(|e| {
            MicroClawError::Config(format!("Failed to render provider_presets: {e}"))
        })?;
        append_yaml_value(&mut yaml, 2, &yaml_presets);
    }
    let show_thinking = values
        .get("SHOW_THINKING")
        .and_then(|v| parse_bool_like(v))
        .unwrap_or(false);
    yaml.push_str("# Show model thinking/reasoning text when available\n");
    yaml.push_str(&format!("show_thinking: {}\n", show_thinking));
    yaml.push_str("# OpenAI-compatible request body overrides (optional)\n");
    yaml.push_str("# Use null to unset a default key for selected provider/model.\n");
    yaml.push_str("# openai_compat_body_overrides: { temperature: 0.2 }\n");
    yaml.push_str("# openai_compat_body_overrides_by_provider:\n");
    yaml.push_str("#   deepseek: { top_p: null, reasoning_effort: \"high\" }\n");
    yaml.push_str("# openai_compat_body_overrides_by_model:\n");
    yaml.push_str("#   gpt-5.2: { response_format: { type: \"json_object\" } }\n");

    yaml.push('\n');
    yaml.push_str(&format!("data_dir: {}\n", yaml_double_quoted(&data_dir)));
    let working_dir = values
        .get("WORKING_DIR")
        .cloned()
        .unwrap_or_else(default_working_dir_for_setup);
    yaml.push_str(&format!(
        "working_dir: {}\n",
        yaml_double_quoted(&working_dir)
    ));
    let override_tz = values.get("OVERRIDE_TIMEZONE").cloned().unwrap_or_default();
    yaml.push_str(
        "# Optional timezone override (IANA), e.g. Asia/Shanghai. Default: system timezone.\n",
    );
    if !override_tz.trim().is_empty() && !override_tz.eq_ignore_ascii_case("auto") {
        yaml.push_str(&format!("override_timezone: \"{}\"\n", override_tz));
    }
    let high_risk_confirm_required = values
        .get("HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED")
        .map(|v| {
            let lower = v.trim().to_ascii_lowercase();
            lower != "false" && lower != "0" && lower != "no"
        })
        .unwrap_or(true);
    yaml.push_str(&format!(
        "high_risk_tool_user_confirmation_required: {}\n",
        high_risk_confirm_required
    ));
    yaml.push_str("# Central tool policy plus optional per-chat/per-principal capability grants\n");
    yaml.push_str("tool_policy:\n");
    yaml.push_str("  mode: \"off\"\n");
    yaml.push_str("  grants_mode: \"off\"\n");
    yaml.push_str("  control_chat_bypass: true\n");
    yaml.push_str("  grants: []\n");
    yaml.push_str("# Central HTTP(S) destination policy for tools and configured endpoints\n");
    yaml.push_str("egress_policy:\n");
    yaml.push_str("  mode: \"off\"\n");
    yaml.push_str("  allow_hosts: []\n");
    yaml.push_str("  deny_hosts: []\n");
    yaml.push_str("  block_private_ips: true\n");
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
    yaml.push_str("  no_network: true\n");
    yaml.push_str("  require_runtime: true\n");
    yaml.push_str("  security_profile: \"hardened\"\n");
    yaml.push_str("  credential_env_allowlist: []\n");

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

    yaml.push_str("\n# Optional SOUL files directory (defaults to <data_dir>/souls)\n");
    yaml.push_str(&format!("souls_dir: {}\n", yaml_double_quoted(&souls_dir)));

    fs::write(path, yaml).map_err(|e| {
        MicroClawError::Config(format!(
            "Failed to write config to {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(backup)
}

pub(crate) fn try_save(
    terminal: &mut DefaultTerminal,
    app: &mut SetupApp,
) -> Result<(), MicroClawError> {
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
    let save_path = crate::config::Config::config_path_for_setup();
    let display_path = save_path.display().to_string();
    let backup = match run_with_spinner(
        terminal,
        app,
        &format!("Saving (3/3): writing {}", display_path),
        move || {
            let p = &save_path;
            save_config_yaml(p, &values)
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    app.backup_path = backup;
    app.completion_summary = checks;
    app.status = format!("Saved {}", display_path);
    app.completed = true;
    Ok(())
}

pub(crate) fn try_save_skip_online(
    terminal: &mut DefaultTerminal,
    app: &mut SetupApp,
) -> Result<(), MicroClawError> {
    app.status = "Saving (1/2): local validation...".into();
    terminal.draw(|f| draw_ui(f, app))?;
    if let Err(e) = app.validate_local() {
        app.status = format!("Cannot save: {e}");
        return Ok(());
    }

    let values = app.to_env_map();
    let save_path = crate::config::Config::config_path_for_setup();
    let display_path = save_path.display().to_string();
    let backup = match run_with_spinner(
        terminal,
        app,
        &format!("Saving (2/2): writing {}", display_path),
        move || {
            let p = &save_path;
            save_config_yaml(p, &values)
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            app.status = format!("Cannot save: {e}");
            return Ok(());
        }
    };

    app.backup_path = backup;
    app.completion_summary = vec!["Online/model validation skipped by user".to_string()];
    app.status = format!("Saved {} (online validation skipped)", display_path);
    app.completed = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

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
        values.insert(telegram_topic_routing_key().into(), "true".into());
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
        assert!(s.contains("    topic_routing:\n"));
        assert!(s.contains("      enabled: true\n"));
        assert!(s.contains("  web:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(s.contains("llm_provider: \"anthropic\""));
        assert!(s.contains("api_key: \"key\""));
        assert!(s.contains("high_risk_tool_user_confirmation_required: true\n"));
        assert!(s.contains("sandbox:\n"));
        assert!(s.contains("  mode: \"all\"\n"));

        // Save again to test backup
        let backup2 = save_config_yaml(&yaml_path, &values).unwrap();
        assert!(backup2.is_some());
        let backup2_path = backup2.unwrap();
        assert!(backup2_path.contains(CONFIG_BACKUP_DIR_NAME));
        assert!(Path::new(&backup2_path).exists());

        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_file(&backup2_path);
        let _ = fs::remove_dir(config_backup_dir_for(&yaml_path));
    }

    #[test]
    fn test_save_config_yaml_respects_high_risk_confirmation_toggle() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_high_risk_confirm_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert(
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED".into(),
            "false".into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("high_risk_tool_user_confirmation_required: false\n"));

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_escapes_windows_directory_paths() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_windows_path_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert("DATA_DIR".into(), r#"C:\Users\alice\.microclaw"#.into());
        values.insert(
            "WORKING_DIR".into(),
            r#"C:\Users\alice\.microclaw\working_dir"#.into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains(r#"data_dir: "C:\\Users\\alice\\.microclaw""#));
        assert!(s.contains(r#"working_dir: "C:\\Users\\alice\\.microclaw\\working_dir""#));

        let cfg: crate::config::Config = serde_yaml::from_str(&s).unwrap();
        assert_eq!(cfg.data_dir, r#"C:\Users\alice\.microclaw"#);
        assert_eq!(cfg.working_dir, r#"C:\Users\alice\.microclaw\working_dir"#);

        let _ = fs::remove_file(&yaml_path);
    }

    #[test]
    fn test_save_config_yaml_keeps_unix_directory_paths_unchanged() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_unix_path_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "web".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());
        values.insert("DATA_DIR".into(), "/home/alice/.microclaw".into());
        values.insert(
            "WORKING_DIR".into(),
            "/home/alice/.microclaw/working_dir".into(),
        );

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains(r#"data_dir: "/home/alice/.microclaw""#));
        assert!(s.contains(r#"working_dir: "/home/alice/.microclaw/working_dir""#));

        let cfg: crate::config::Config = serde_yaml::from_str(&s).unwrap();
        assert_eq!(cfg.data_dir, "/home/alice/.microclaw");
        assert_eq!(cfg.working_dir, "/home/alice/.microclaw/working_dir");

        let _ = fs::remove_file(&yaml_path);
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
    fn test_save_config_yaml_keeps_weixin_minimal_when_selected() {
        let yaml_path = std::env::temp_dir().join(format!(
            "microclaw_setup_weixin_minimal_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let mut values = HashMap::new();
        values.insert("ENABLED_CHANNELS".into(), "weixin".into());
        values.insert("LLM_PROVIDER".into(), "anthropic".into());
        values.insert("LLM_API_KEY".into(), "key".into());

        save_config_yaml(&yaml_path, &values).unwrap();
        let s = fs::read_to_string(&yaml_path).unwrap();
        assert!(s.contains("\nchannels:\n"));
        assert!(s.contains("  weixin:\n"));
        assert!(s.contains("    enabled: true\n"));
        assert!(!s.contains("default_account:"));
        assert!(!s.contains("accounts:"));
        assert!(!s.contains("    base_url:"));
        assert!(!s.contains("    cdn_base_url:"));
        assert!(!s.contains("    webhook_path:"));

        let _ = fs::remove_file(&yaml_path);
    }
}
