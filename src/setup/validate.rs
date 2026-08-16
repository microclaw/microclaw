use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn perform_online_validation(
    telegram_enabled: bool,
    include_telegram_status: bool,
    tg_token: &str,
    env_username: &str,
    provider: &str,
    api_key: &str,
    base_url: &str,
    configured_user_agent: &str,
    model: &str,
    codex_account_id: Option<&str>,
) -> Result<Vec<String>, MicroClawError> {
    let mut checks = Vec::new();

    // --- Telegram validation (optional) ---
    if telegram_enabled {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(llm_user_agent(configured_user_agent))
            .build()?;
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
        if !env_username.is_empty()
            && !actual_username.is_empty()
            && env_username != actual_username
        {
            checks.push(format!(
                "Telegram OK (token user={actual_username}, configured={env_username})"
            ));
        } else {
            checks.push(format!("Telegram OK ({actual_username})"));
        }
    } else {
        push_telegram_disabled_status(&mut checks, include_telegram_status);
    }

    // --- LLM validation: send a minimal "hi" message ---
    checks.push(validate_llm_credentials(
        provider,
        api_key,
        base_url,
        configured_user_agent,
        model,
        codex_account_id,
    )?);

    Ok(checks)
}

/// Send a minimal "hi" message to the configured LLM provider to verify the
/// API key/model work. Returns a human-friendly "LLM OK (...)" string on
/// success, or a `MicroClawError::Config` describing the failure. Shared by the
/// setup wizard and `microclaw doctor`. Synchronous (blocking HTTP), so callers
/// inside an async runtime must run it on a dedicated thread.
pub(crate) fn validate_llm_credentials(
    provider: &str,
    api_key: &str,
    base_url: &str,
    configured_user_agent: &str,
    model: &str,
    codex_account_id: Option<&str>,
) -> Result<String, MicroClawError> {
    const VALIDATION_MAX_OUTPUT_TOKENS: u32 = 64;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(llm_user_agent(configured_user_agent))
        .build()?;

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
            "max_tokens": VALIDATION_MAX_OUTPUT_TOKENS,
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
        Ok(format!("LLM OK (anthropic, model={model})"))
    } else {
        let base = resolve_openai_compat_validation_base(provider, base_url, preset);
        let resp = if is_openai_codex_provider(provider) {
            let body = serde_json::json!({
                "model": model,
                "input": [{"type":"message","role":"user","content":"hi"}],
                "instructions": "You are a helpful assistant.",
                "store": false,
                "stream": true,
            });
            let mut req = client
                .post(format!("{}/responses", base.trim_end_matches('/')))
                .header("content-type", "application/json")
                .body(body.to_string());
            if !api_key.trim().is_empty() {
                req = req.bearer_auth(api_key);
            }
            if let Some(account_id) = codex_account_id {
                if !account_id.trim().is_empty() {
                    req = req.header("ChatGPT-Account-ID", account_id.trim());
                }
            }
            req.send()?
        } else {
            let endpoint = format!("{}/chat/completions", base.trim_end_matches('/'));
            let mut body = serde_json::json!({
                "model": model,
                "max_tokens": VALIDATION_MAX_OUTPUT_TOKENS,
                "messages": [{"role": "user", "content": "hi"}]
            });
            let mut resp = send_openai_validation_chat_request(&client, &endpoint, api_key, &body)?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                if should_retry_with_max_completion_tokens(&text)
                    && switch_to_max_completion_tokens(&mut body)
                {
                    resp = send_openai_validation_chat_request(&client, &endpoint, api_key, &body)?;
                } else {
                    return Err(MicroClawError::Config(format!(
                        "LLM validation failed: {}",
                        extract_openai_error_detail(status, &text)
                    )));
                }
            }
            resp
        };
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            if is_validation_output_capped_error(&text) {
                return Ok(format!(
                    "LLM OK (openai-compatible, model={model}; probe output capped)"
                ));
            }
            let detail = extract_openai_error_detail(status, &text);
            return Err(MicroClawError::Config(format!(
                "LLM validation failed: {detail}"
            )));
        }
        Ok(format!("LLM OK (openai-compatible, model={model})"))
    }
}

pub(crate) fn push_telegram_disabled_status(
    checks: &mut Vec<String>,
    include_telegram_status: bool,
) {
    if include_telegram_status {
        checks.push("Telegram skipped (disabled)".into());
    }
}

pub(crate) fn send_openai_validation_chat_request(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    api_key: &str,
    body: &serde_json::Value,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let mut req = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body.to_string());
    if !api_key.trim().is_empty() {
        req = req.bearer_auth(api_key);
    }
    req.send()
}

pub(crate) fn extract_openai_error_detail(status: reqwest::StatusCode, text: &str) -> String {
    fn extract_message(value: &serde_json::Value) -> Option<String> {
        if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
            return Some(message.to_string());
        }
        if let Some(error) = value.get("error") {
            if let Some(message) = extract_message(error) {
                return Some(message);
            }
        }
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(message) = extract_message(item) {
                    return Some(message);
                }
            }
        }
        None
    }

    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| extract_message(&v))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

pub(crate) fn should_retry_with_max_completion_tokens(error_text: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(error_text) {
        let param_is_max_tokens = value
            .get("error")
            .and_then(|e| e.get("param"))
            .and_then(|p| p.as_str())
            .map(|p| p == "max_tokens")
            .unwrap_or(false);
        if param_is_max_tokens {
            return true;
        }
    }

    let lower = error_text.to_ascii_lowercase();
    lower.contains("max_tokens") && lower.contains("max_completion_tokens")
}

pub(crate) fn is_validation_output_capped_error(error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    lower.contains("max_tokens or model output limit was reached")
        || (lower.contains("max_tokens") && lower.contains("output limit"))
}

pub(crate) fn switch_to_max_completion_tokens(body: &mut serde_json::Value) -> bool {
    if body.get("max_completion_tokens").is_some() {
        return false;
    }
    let Some(max_tokens) = body.get("max_tokens").cloned() else {
        return false;
    };
    if let Some(obj) = body.as_object_mut() {
        obj.remove("max_tokens");
        obj.insert("max_completion_tokens".to_string(), max_tokens);
        return true;
    }
    false
}

pub(crate) fn resolve_openai_compat_validation_base(
    provider: &str,
    base_url: &str,
    preset: Option<&ProviderPreset>,
) -> String {
    let resolved = if base_url.is_empty() {
        preset
            .map(|p| p.default_base_url)
            .filter(|s| !s.is_empty())
            .unwrap_or("https://api.openai.com/v1")
            .trim_end_matches('/')
            .to_string()
    } else {
        base_url.trim_end_matches('/').to_string()
    };

    if is_openai_codex_provider(provider) {
        if let Some(codex_base) = codex_config_default_openai_base_url() {
            return codex_base.trim_end_matches('/').to_string();
        }
        return "https://chatgpt.com/backend-api/codex".to_string();
    }

    resolved
}

pub(crate) fn mask_secret(s: &str) -> String {
    if s.len() <= 6 {
        return "***".into();
    }
    let left = floor_char_boundary(s, 3.min(s.len()));
    let right_start = floor_char_boundary(s, s.len().saturating_sub(2));
    format!("{}***{}", &s[..left], &s[right_start..])
}

pub(crate) fn truncate_single_line(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    for ch in text.chars().take(max_chars - 1) {
        out.push(ch);
    }
    out.push('…');
    out
}

impl SetupApp {
    pub(crate) fn validate_local(&self) -> Result<(), MicroClawError> {
        // A config with no enabled channel can't start, so refuse to save one —
        // this is the source-side fix for "configured a channel but forgot to
        // enable it". (The field defaults to `web`, so a normal setup passes.)
        if self.enabled_channels().is_empty() {
            return Err(MicroClawError::Config(
                "Enable at least one channel: open the 'Enabled channels' field and select one (web, telegram, discord, ...).".into(),
            ));
        }

        for field in &self.fields {
            if self.is_field_required(field) && field.value.trim().is_empty() {
                return Err(MicroClawError::Config(format!("{} is required", field.key)));
            }
        }

        let hooks_allow_raw = self.field_value(web_hooks_allow_request_session_key_key());
        if !hooks_allow_raw.trim().is_empty() {
            let _ = parse_boolish(&hooks_allow_raw, false).map_err(|_| {
                MicroClawError::Config(format!(
                    "{} must be true/false",
                    web_hooks_allow_request_session_key_key()
                ))
            })?;
        }
        let _ = parse_string_list_field(
            &self.field_value(web_hooks_allowed_session_key_prefixes_key()),
        )
        .map_err(|_| {
            MicroClawError::Config(format!(
                "{} must be csv or JSON string array",
                web_hooks_allowed_session_key_prefixes_key()
            ))
        })?;
        let _ = parse_provider_presets_json_value(
            &self.field_value(llm_provider_profiles_key()),
            llm_provider_profiles_key(),
        )?;

        if self.channel_enabled("telegram") {
            let _ = parse_bot_count(
                &self.field_value(telegram_bot_count_key()),
                telegram_bot_count_key(),
            )?;
            let topic_routing_raw = self.field_value(telegram_topic_routing_key());
            if !topic_routing_raw.trim().is_empty() {
                let _ = parse_boolish(&topic_routing_raw, false).map_err(|_| {
                    MicroClawError::Config(format!(
                        "{} must be true/false (or 1/0)",
                        telegram_topic_routing_key()
                    ))
                })?;
            }
            parse_i64_list_field(
                &self.field_value(telegram_allowed_user_ids_key()),
                telegram_allowed_user_ids_key(),
            )?;
            let account_id = account_id_from_value(&self.field_value(&telegram_slot_id_key(1)));
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(format!(
                    "{} must use only letters, numbers, '_' or '-'",
                    telegram_slot_id_key(1)
                )));
            }
            let telegram_slot_accounts = self.telegram_slot_accounts_from_fields()?;
            let telegram_slot_has_account_token = telegram_slot_accounts.values().any(|account| {
                account
                    .get("bot_token")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_some()
            });
            if self.telegram_bot_count() > 1 && telegram_slot_accounts.is_empty() {
                return Err(MicroClawError::Config(
                    "Provide Telegram multi-bot entries via TELEGRAM_BOT#_* fields when TELEGRAM_BOT_COUNT > 1".into(),
                ));
            }
            if self.field_value("TELEGRAM_BOT_TOKEN").is_empty() && !telegram_slot_has_account_token
            {
                return Err(MicroClawError::Config(
                    "TELEGRAM_BOT_TOKEN or TELEGRAM_BOT#_TOKEN is required when telegram is enabled".into(),
                ));
            }
            let slot_has_username = (1..=self.telegram_bot_count()).any(|slot| {
                !self
                    .field_value(&telegram_slot_username_key(slot))
                    .trim()
                    .is_empty()
            });
            if self.field_value("BOT_USERNAME").is_empty() && !slot_has_username {
                return Err(MicroClawError::Config(
                    "TELEGRAM_BOT#_USERNAME is required when telegram is enabled".into(),
                ));
            }
            let username = self.field_value("BOT_USERNAME");
            if username.starts_with('@') {
                return Err(MicroClawError::Config(
                    "BOT_USERNAME should not include '@'".into(),
                ));
            }
            for slot in 1..=self.telegram_bot_count() {
                let username = self.field_value(&telegram_slot_username_key(slot));
                if username.starts_with('@') {
                    return Err(MicroClawError::Config(format!(
                        "{} should not include '@'",
                        telegram_slot_username_key(slot)
                    )));
                }
            }
        }

        if self.channel_enabled("discord") {
            let account_id = account_id_from_value(&self.field_value("DISCORD_ACCOUNT_ID"));
            if !is_valid_account_id(&account_id) {
                return Err(MicroClawError::Config(
                    "DISCORD_ACCOUNT_ID must use only letters, numbers, '_' or '-'".into(),
                ));
            }
            let discord_accounts = parse_accounts_json_value(
                &self.field_value("DISCORD_ACCOUNTS_JSON"),
                "DISCORD_ACCOUNTS_JSON",
            )?;
            let discord_has_account_token = discord_accounts
                .as_ref()
                .map(|accounts| {
                    accounts.values().any(|account| {
                        account
                            .get("bot_token")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                            .is_some()
                    })
                })
                .unwrap_or(false);
            if self.field_value("DISCORD_BOT_TOKEN").is_empty() && !discord_has_account_token {
                return Err(MicroClawError::Config(
                    "DISCORD_BOT_TOKEN or DISCORD_ACCOUNTS_JSON(bot_token) is required when discord is enabled".into(),
                ));
            }
        }

        for ch in DYNAMIC_CHANNELS {
            if self.channel_enabled(ch.name) {
                if dynamic_channel_uses_minimal_setup(ch.name) {
                    continue;
                }
                let bot_count_key = dynamic_bot_count_field_key(ch.name);
                let bot_count = parse_bot_count(&self.field_value(&bot_count_key), &bot_count_key)?;
                let mut seen_any = false;
                for slot in 1..=bot_count {
                    let id_key = dynamic_slot_id_field_key(ch.name, slot);
                    let id_raw = self.field_value(&id_key);
                    let soul_path = self.normalize_soul_path_value(
                        &self.field_value(&dynamic_slot_soul_path_field_key(ch.name, slot)),
                    );
                    let has_any = ch.fields.iter().any(|f| {
                        !effective_dynamic_slot_field_value(ch.name, slot, f, |key| {
                            self.field_value(key)
                        })
                        .is_empty()
                    }) || !soul_path.is_empty();
                    if !has_any {
                        continue;
                    }
                    seen_any = true;
                    let account_id = account_id_from_value(&id_raw);
                    if !is_valid_account_id(&account_id) {
                        return Err(MicroClawError::Config(format!(
                            "{} must use only letters, numbers, '_' or '-'",
                            id_key
                        )));
                    }
                    let enabled_key = dynamic_slot_enabled_field_key(ch.name, slot);
                    let _ = parse_boolish(&self.field_value(&enabled_key), true).map_err(|_| {
                        MicroClawError::Config(format!(
                            "{} must be true/false (or 1/0)",
                            enabled_key
                        ))
                    })?;
                    if ch.name == "feishu" {
                        let mut topic_mode = false;
                        for yaml_key in ["topic_mode", "show_progress"] {
                            let field_key = dynamic_slot_field_key(ch.name, slot, yaml_key);
                            let field_raw = self.field_value(&field_key);
                            let parsed = if field_raw.trim().is_empty() {
                                false
                            } else {
                                parse_boolish(&field_raw, false).map_err(|_| {
                                    MicroClawError::Config(format!(
                                        "{} must be true/false (or 1/0)",
                                        field_key
                                    ))
                                })?
                            };
                            if yaml_key == "topic_mode" {
                                topic_mode = parsed;
                            }
                        }
                        if topic_mode {
                            let domain_key = dynamic_slot_field_key(ch.name, slot, "domain");
                            let domain = self.field_value(&domain_key).trim().to_ascii_lowercase();
                            let domain = if domain.is_empty() {
                                "feishu"
                            } else {
                                domain.as_str()
                            };
                            if domain != "feishu" && domain != "lark" {
                                return Err(MicroClawError::Config(format!(
                                    "{} topic_mode is only supported when domain is feishu or lark",
                                    id_key
                                )));
                            }
                        }
                    }
                    for f in ch.fields {
                        if !f.required {
                            continue;
                        }
                        let key = dynamic_slot_field_key(ch.name, slot, f.yaml_key);
                        if effective_dynamic_slot_field_value(ch.name, slot, f, |field_key| {
                            self.field_value(field_key)
                        })
                        .is_empty()
                        {
                            return Err(MicroClawError::Config(format!(
                                "{} is required when {} bot slot #{} is configured",
                                key, ch.name, slot
                            )));
                        }
                    }
                }
                if !seen_any {
                    return Err(MicroClawError::Config(format!(
                        "Provide at least one {} bot slot (1..{}) with required fields",
                        ch.name, bot_count
                    )));
                }
            }
        }

        let provider = self.field_value("LLM_PROVIDER");
        if provider.is_empty() {
            return Err(MicroClawError::Config("LLM_PROVIDER is required".into()));
        }
        if is_openai_codex_provider(&provider) {
            if !self.field_value("LLM_API_KEY").trim().is_empty() {
                return Err(MicroClawError::Config(
                    "openai-codex ignores LLM_API_KEY here. Configure ~/.codex/auth.json or run `codex login`.".into(),
                ));
            }
            if !self.field_value("LLM_BASE_URL").trim().is_empty() {
                return Err(MicroClawError::Config(
                    "openai-codex ignores LLM_BASE_URL here. Configure ~/.codex/config.toml instead.".into(),
                ));
            }
        } else if provider.eq_ignore_ascii_case("qwen-portal")
            && self.field_value("LLM_API_KEY").trim().is_empty()
            && !qwen_oauth_file_has_access_token()?
        {
            return Err(MicroClawError::Config(
                "qwen-portal requires LLM_API_KEY, or ~/.qwen/oauth_creds.json (access_token), or QWEN_PORTAL_ACCESS_TOKEN.".into(),
            ));
        }

        let override_timezone = self.field_value("OVERRIDE_TIMEZONE");
        let tz = override_timezone.trim();
        if !tz.is_empty() && !tz.eq_ignore_ascii_case("auto") {
            tz.parse::<chrono_tz::Tz>()
                .map_err(|_| MicroClawError::Config(format!("Invalid OVERRIDE_TIMEZONE: {tz}")))?;
        }

        let data_dir = self.field_value("DATA_DIR");
        let dir = if data_dir.is_empty() {
            default_data_dir_for_setup()
        } else {
            data_dir
        };
        fs::create_dir_all(&dir)?;
        let probe = Path::new(&dir).join(".setup_probe");
        fs::write(&probe, "ok")?;
        let _ = fs::remove_file(probe);

        let working_dir = self.field_value("WORKING_DIR");
        let workdir = if working_dir.is_empty() {
            default_working_dir_for_setup()
        } else {
            working_dir
        };
        fs::create_dir_all(&workdir)?;

        let sandbox_enabled = self.field_value("SANDBOX_ENABLED");
        if !sandbox_enabled.is_empty() {
            let lower = sandbox_enabled.to_ascii_lowercase();
            let valid = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");
            if !valid {
                return Err(MicroClawError::Config(
                    "SANDBOX_ENABLED must be true/false (or 1/0)".into(),
                ));
            }
        }
        let high_risk_confirm = self.field_value("HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED");
        if !high_risk_confirm.is_empty() {
            let lower = high_risk_confirm.to_ascii_lowercase();
            let valid = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");
            if !valid {
                return Err(MicroClawError::Config(
                    "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED must be true/false (or 1/0)".into(),
                ));
            }
        }
        let show_thinking = self.field_value("SHOW_THINKING");
        if !show_thinking.is_empty() && parse_bool_like(&show_thinking).is_none() {
            return Err(MicroClawError::Config(
                "SHOW_THINKING must be true/false (or 1/0)".into(),
            ));
        }

        let memory_token_budget_raw = self.field_value("MEMORY_TOKEN_BUDGET");
        if !memory_token_budget_raw.is_empty() {
            let memory_token_budget = memory_token_budget_raw.parse::<usize>().map_err(|_| {
                MicroClawError::Config("MEMORY_TOKEN_BUDGET must be a positive integer".into())
            })?;
            if memory_token_budget == 0 {
                return Err(MicroClawError::Config(
                    "MEMORY_TOKEN_BUDGET must be greater than 0".into(),
                ));
            }
        }

        for key in [
            subagents_max_concurrent_key(),
            subagents_max_active_per_chat_key(),
            subagents_run_timeout_secs_key(),
            subagents_max_spawn_depth_key(),
            subagents_max_children_per_run_key(),
            subagents_announce_relay_interval_secs_key(),
            subagents_max_tokens_per_run_key(),
            subagents_orchestrate_max_workers_key(),
        ] {
            let raw = self.field_value(key);
            if raw.is_empty() {
                continue;
            }
            let value = raw
                .parse::<u64>()
                .map_err(|_| MicroClawError::Config(format!("{key} must be a positive integer")))?;
            if value == 0 {
                return Err(MicroClawError::Config(format!(
                    "{key} must be greater than 0"
                )));
            }
        }

        for key in [
            subagents_announce_to_chat_key(),
            subagents_thread_bound_routing_enabled_key(),
            subagents_acp_enabled_key(),
            subagents_acp_auto_approve_key(),
        ] {
            let raw = self.field_value(key);
            if raw.is_empty() {
                continue;
            }
            let lower = raw.to_ascii_lowercase();
            let valid = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");
            if !valid {
                return Err(MicroClawError::Config(format!(
                    "{key} must be true/false (or 1/0)"
                )));
            }
        }

        let acp_args_raw = self.field_value(subagents_acp_args_key());
        if !acp_args_raw.is_empty() {
            parse_string_list_field(&acp_args_raw)?;
        }
        let acp_env_raw = self.field_value(subagents_acp_env_json_key());
        if !acp_env_raw.trim().is_empty() {
            serde_json::from_str::<HashMap<String, String>>(acp_env_raw.trim()).map_err(|e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    subagents_acp_env_json_key()
                ))
            })?;
        }
        let acp_targets_raw = self.field_value(subagents_acp_targets_json_key());
        if !acp_targets_raw.trim().is_empty() {
            serde_json::from_str::<HashMap<String, crate::config::SubagentAcpTargetConfig>>(
                acp_targets_raw.trim(),
            )
            .map_err(|e| {
                MicroClawError::Config(format!(
                    "{} must be valid JSON object: {e}",
                    subagents_acp_targets_json_key()
                ))
            })?;
        }

        let embedding_dim_raw = self.field_value("EMBEDDING_DIM");
        if !embedding_dim_raw.is_empty() {
            let embedding_dim = embedding_dim_raw.parse::<usize>().map_err(|_| {
                MicroClawError::Config("EMBEDDING_DIM must be a positive integer".into())
            })?;
            if embedding_dim == 0 {
                return Err(MicroClawError::Config(
                    "EMBEDDING_DIM must be greater than 0".into(),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn validate_online(&self) -> Result<Vec<String>, MicroClawError> {
        let tg_enabled = self.channel_enabled("telegram");
        let tg_token = if !self.field_value("TELEGRAM_BOT_TOKEN").is_empty() {
            self.field_value("TELEGRAM_BOT_TOKEN")
        } else if !self.field_value(&telegram_slot_token_key(1)).is_empty() {
            self.field_value(&telegram_slot_token_key(1))
        } else {
            self.telegram_slot_accounts_from_fields()?
                .into_values()
                .find_map(|account| {
                    account
                        .get("bot_token")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default()
        };
        let env_username = if !self.field_value("BOT_USERNAME").is_empty() {
            self.field_value("BOT_USERNAME")
        } else if !self.field_value(&telegram_slot_username_key(1)).is_empty() {
            self.field_value(&telegram_slot_username_key(1))
        } else {
            self.telegram_slot_accounts_from_fields()?
                .into_values()
                .find_map(|account| {
                    account
                        .get("bot_username")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default()
        }
        .trim_start_matches('@')
        .to_string();
        let provider = self.field_value("LLM_PROVIDER").to_lowercase();
        let (api_key, codex_account_id) = if is_openai_codex_provider(&provider) {
            let auth = resolve_openai_codex_auth("")?;
            (auth.bearer_token, auth.account_id)
        } else if provider.eq_ignore_ascii_case("qwen-portal")
            && self.field_value("LLM_API_KEY").trim().is_empty()
        {
            let auth = resolve_qwen_portal_auth("")?;
            (auth.bearer_token, None)
        } else {
            (self.field_value("LLM_API_KEY"), None)
        };
        let base_url = self.field_value("LLM_BASE_URL");
        let user_agent = self.field_value("LLM_USER_AGENT");
        let model = self.field_value("LLM_MODEL");
        std::thread::spawn(move || {
            perform_online_validation(
                tg_enabled,
                true,
                &tg_token,
                &env_username,
                &provider,
                &api_key,
                &base_url,
                &user_agent,
                &model,
                codex_account_id.as_deref(),
            )
        })
        .join()
        .map_err(|_| MicroClawError::Config("Validation thread panicked".into()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

    #[test]
    fn test_mask_secret() {
        assert_eq!(mask_secret("abcdefghi"), "abc***hi");
        assert_eq!(mask_secret("abc"), "***");
    }

    #[test]
    fn test_extract_openai_error_detail_handles_array_wrapped_messages() {
        let detail = extract_openai_error_detail(
            reqwest::StatusCode::BAD_REQUEST,
            r#"[{"error":{"message":"Request contains an invalid argument."}}]"#,
        );
        assert_eq!(detail, "Request contains an invalid argument.");
    }

    #[test]
    fn test_push_telegram_disabled_status_included_when_requested() {
        let mut checks = Vec::new();
        push_telegram_disabled_status(&mut checks, true);
        assert_eq!(checks, vec!["Telegram skipped (disabled)".to_string()]);
    }

    #[test]
    fn test_push_telegram_disabled_status_omitted_when_not_requested() {
        let mut checks = Vec::new();
        push_telegram_disabled_status(&mut checks, false);
        assert!(checks.is_empty());
    }

    #[test]
    fn test_resolve_openai_compat_validation_base_codex() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let temp = std::env::temp_dir().join(format!(
            "microclaw-setup-codex-base-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&temp);
        std::env::set_var("CODEX_HOME", &temp);

        let base = resolve_openai_compat_validation_base("openai-codex", "", None);
        assert_eq!(base, "https://chatgpt.com/backend-api/codex");
        let legacy = resolve_openai_compat_validation_base(
            "openai-codex",
            "https://chatgpt.com/backend-api",
            None,
        );
        assert_eq!(legacy, "https://chatgpt.com/backend-api/codex");

        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        let _ = fs::remove_dir(temp);
    }

    #[test]
    fn test_resolve_openai_compat_validation_base_openai() {
        let base = resolve_openai_compat_validation_base("openai", "https://api.openai.com", None);
        assert_eq!(base, "https://api.openai.com");
    }

    #[test]
    fn test_should_retry_with_max_completion_tokens() {
        let err = r#"{"error":{"message":"Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.","param":"max_tokens"}}"#;
        assert!(should_retry_with_max_completion_tokens(err));
        assert!(!should_retry_with_max_completion_tokens(
            r#"{"error":{"message":"bad request","param":"messages"}}"#
        ));
    }

    #[test]
    fn test_switch_to_max_completion_tokens() {
        let mut body = serde_json::json!({"model":"gpt-5.2","max_tokens":1});
        assert!(switch_to_max_completion_tokens(&mut body));
        assert_eq!(body.get("max_tokens"), None);
        assert_eq!(body["max_completion_tokens"], 1);
        assert!(!switch_to_max_completion_tokens(&mut body));
    }

    #[test]
    fn test_is_validation_output_capped_error() {
        assert!(is_validation_output_capped_error(
            "Could not finish the message because max_tokens or model output limit was reached"
        ));
        assert!(!is_validation_output_capped_error("invalid api key"));
    }
}
