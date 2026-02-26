use super::*;
use microclaw_tools::runtime::{tool_execution_policy, tool_risk};

fn merge_yaml_value(
    target: &mut serde_yaml::Value,
    incoming: &serde_yaml::Value,
    parent_key: Option<&str>,
) {
    if parent_key.is_some_and(is_sensitive_config_key)
        && incoming
            .as_str()
            .map(|s| s.trim() == "***")
            .unwrap_or(false)
    {
        // Frontend redacts secrets in /api/config as "***"; keep existing value when unchanged.
        return;
    }

    match incoming {
        serde_yaml::Value::Mapping(incoming_map) => {
            if !target.is_mapping() {
                *target = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
            }
            let Some(target_map) = target.as_mapping_mut() else {
                return;
            };
            for (k, v) in incoming_map {
                let key_name = k.as_str();
                let entry = target_map
                    .entry(k.clone())
                    .or_insert(serde_yaml::Value::Null);
                merge_yaml_value(entry, v, key_name);
            }
        }
        _ => {
            *target = incoming.clone();
        }
    }
}

pub(super) async fn api_get_config(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let path = config_path_for_save()?;
    Ok(Json(json!({
        "ok": true,
        "path": path,
        "config": redact_config(&state.app_state.config),
        "requires_restart": true
    })))
}

pub(super) async fn api_config_self_check(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let mut warnings = Vec::<ConfigWarning>::new();
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    let since_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let (task_runs_24h, task_success_24h) = call_blocking(state.app_state.db.clone(), {
        let since = since_24h.clone();
        move |db| db.get_task_run_summary_since(Some(&since))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let reflector_observability = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_memory_observability_summary(None)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sandbox_runtime_available = docker_runtime_available();
    let sandbox_mode = match state.app_state.config.sandbox.mode {
        crate::config::SandboxMode::All => "all",
        crate::config::SandboxMode::Off => "off",
    };
    let execution_policy_items = [
        "bash",
        "read_file",
        "write_file",
        "edit_file",
        "glob",
        "grep",
    ]
    .iter()
    .map(|tool| {
        json!({
            "tool": tool,
            "risk": tool_risk(tool).as_str(),
            "policy": tool_execution_policy(tool).as_str()
        })
    })
    .collect::<Vec<_>>();
    let mount_allowlist_path = state
        .app_state
        .config
        .sandbox
        .mount_allowlist_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .or_else(default_mount_allowlist_path);
    let mount_allowlist_status = mount_allowlist_path.as_ref().map(|p| {
        let has_entries = std::fs::read_to_string(p)
            .ok()
            .map(|s| {
                s.lines()
                    .map(str::trim)
                    .any(|line| !line.is_empty() && !line.starts_with('#'))
            })
            .unwrap_or(false);
        json!({
            "path": p,
            "exists": p.exists(),
            "has_entries": has_entries
        })
    });

    if state.legacy_auth_token.is_some() {
        warnings.push(ConfigWarning {
            code: "legacy_auth_token_enabled",
            severity: "medium",
            message: "Legacy auth token is enabled. Prefer session cookie + scoped API keys."
                .to_string(),
        });
    }
    if !has_password {
        warnings.push(ConfigWarning {
            code: "auth_password_not_configured",
            severity: if state.legacy_auth_token.is_none() {
                "high"
            } else {
                "medium"
            },
            message: "Operator password is not configured.".to_string(),
        });
    }
    if !matches!(
        state.app_state.config.web_host.as_str(),
        "127.0.0.1" | "localhost" | "::1"
    ) {
        warnings.push(ConfigWarning {
            code: "web_host_not_loopback",
            severity: "medium",
            message: format!(
                "Web server host is '{}', verify network exposure and upstream protections.",
                state.app_state.config.web_host
            ),
        });
    }
    if matches!(
        state.app_state.config.sandbox.mode,
        crate::config::SandboxMode::Off
    ) {
        warnings.push(ConfigWarning {
            code: "sandbox_disabled",
            severity: "medium",
            message: "Sandbox is disabled; bash tool executes on host by default.".to_string(),
        });
    } else if !sandbox_runtime_available {
        warnings.push(ConfigWarning {
            code: "sandbox_runtime_unavailable",
            severity: if state.app_state.config.sandbox.require_runtime {
                "high"
            } else {
                "medium"
            },
            message:
                "Sandbox is enabled but docker runtime is unavailable; execution may fall back to host."
                    .to_string(),
        });
    }
    if mount_allowlist_status
        .as_ref()
        .and_then(|m| m.get("exists"))
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        warnings.push(ConfigWarning {
            code: "sandbox_mount_allowlist_missing",
            severity: "medium",
            message: "Sandbox mount allowlist file is missing; define explicit allowed roots."
                .to_string(),
        });
    }
    if state.app_state.config.web_max_requests_per_window > 200 {
        warnings.push(ConfigWarning {
            code: "web_rate_limit_too_high",
            severity: "medium",
            message: format!(
                "web_max_requests_per_window is {}, which is higher than typical safe defaults.",
                state.app_state.config.web_max_requests_per_window
            ),
        });
    }
    if state.app_state.config.web_max_inflight_per_session > 10 {
        warnings.push(ConfigWarning {
            code: "web_inflight_limit_too_high",
            severity: "medium",
            message: format!(
                "web_max_inflight_per_session is {}, which may amplify overload impact.",
                state.app_state.config.web_max_inflight_per_session
            ),
        });
    }
    if state.app_state.config.web_rate_window_seconds <= 2
        && state.app_state.config.web_max_requests_per_window >= 20
    {
        warnings.push(ConfigWarning {
            code: "web_rate_window_too_small_for_limit",
            severity: "medium",
            message: format!(
                "web_rate_window_seconds={} with web_max_requests_per_window={} can allow burst spikes.",
                state.app_state.config.web_rate_window_seconds,
                state.app_state.config.web_max_requests_per_window
            ),
        });
    }
    if state.app_state.config.web_session_idle_ttl_seconds < 30 {
        warnings.push(ConfigWarning {
            code: "web_session_idle_ttl_too_low",
            severity: "medium",
            message: format!(
                "web_session_idle_ttl_seconds={} may cause frequent session lock churn.",
                state.app_state.config.web_session_idle_ttl_seconds
            ),
        });
    }
    if state.app_state.config.max_session_messages <= state.app_state.config.compact_keep_recent {
        warnings.push(ConfigWarning {
            code: "compaction_threshold_not_effective",
            severity: "medium",
            message: format!(
                "max_session_messages={} and compact_keep_recent={} make compaction ineffective.",
                state.app_state.config.max_session_messages,
                state.app_state.config.compact_keep_recent
            ),
        });
    }
    if state.app_state.config.memory_token_budget < 400 {
        warnings.push(ConfigWarning {
            code: "memory_token_budget_low",
            severity: "medium",
            message: format!(
                "memory_token_budget={} may reduce memory recall quality for long tasks.",
                state.app_state.config.memory_token_budget
            ),
        });
    }
    if !state.app_state.config.reflector_enabled {
        warnings.push(ConfigWarning {
            code: "reflector_disabled",
            severity: "medium",
            message:
                "Memory reflector is disabled; durable facts may not be extracted automatically."
                    .to_string(),
        });
    } else if state.app_state.config.reflector_interval_mins < 5 {
        warnings.push(ConfigWarning {
            code: "reflector_interval_too_low",
            severity: "medium",
            message: format!(
                "reflector_interval_mins={} may cause unnecessary LLM cost and churn.",
                state.app_state.config.reflector_interval_mins
            ),
        });
    } else if state.app_state.config.reflector_interval_mins > 240 {
        warnings.push(ConfigWarning {
            code: "reflector_interval_too_high",
            severity: "medium",
            message: format!(
                "reflector_interval_mins={} may delay memory freshness significantly.",
                state.app_state.config.reflector_interval_mins
            ),
        });
    }
    let task_failed_24h = (task_runs_24h - task_success_24h).max(0);
    if task_runs_24h >= 5 && task_failed_24h * 2 >= task_runs_24h {
        warnings.push(ConfigWarning {
            code: "scheduler_failure_rate_high",
            severity: "high",
            message: format!(
                "Scheduler failure rate is high in last 24h ({task_failed_24h}/{task_runs_24h} failed)."
            ),
        });
    }
    if state.app_state.config.reflector_enabled && reflector_observability.reflector_runs_24h == 0 {
        warnings.push(ConfigWarning {
            code: "reflector_no_recent_runs",
            severity: "medium",
            message: "Reflector is enabled but recorded 0 runs in the last 24h.".to_string(),
        });
    }

    if let Some(hooks) = state
        .app_state
        .config
        .channels
        .get("hooks")
        .and_then(|v| v.as_mapping())
    {
        let enabled = hooks
            .get(serde_yaml::Value::String("enabled".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if enabled {
            let max_input_bytes = hooks
                .get(serde_yaml::Value::String("max_input_bytes".to_string()))
                .and_then(|v| v.as_u64())
                .unwrap_or(128 * 1024);
            let max_output_bytes = hooks
                .get(serde_yaml::Value::String("max_output_bytes".to_string()))
                .and_then(|v| v.as_u64())
                .unwrap_or(64 * 1024);
            if max_input_bytes > 2 * 1024 * 1024 {
                warnings.push(ConfigWarning {
                    code: "hooks_max_input_bytes_too_high",
                    severity: "medium",
                    message: format!(
                        "hooks.max_input_bytes={} may increase memory pressure.",
                        max_input_bytes
                    ),
                });
            }
            if max_output_bytes > 1024 * 1024 {
                warnings.push(ConfigWarning {
                    code: "hooks_max_output_bytes_too_high",
                    severity: "medium",
                    message: format!(
                        "hooks.max_output_bytes={} may increase output handling risk.",
                        max_output_bytes
                    ),
                });
            }
        }
    }

    if let Some(obs) = state
        .app_state
        .config
        .channels
        .get("observability")
        .and_then(|v| v.as_mapping())
    {
        let otlp_enabled = obs
            .get(serde_yaml::Value::String("otlp_enabled".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if otlp_enabled {
            let endpoint = obs
                .get(serde_yaml::Value::String("otlp_endpoint".to_string()))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("");
            if endpoint.is_empty() {
                warnings.push(ConfigWarning {
                    code: "otlp_enabled_without_endpoint",
                    severity: "high",
                    message: "OTLP export is enabled but otlp_endpoint is missing.".to_string(),
                });
            }
            let queue_capacity = obs
                .get(serde_yaml::Value::String("otlp_queue_capacity".to_string()))
                .and_then(|v| v.as_u64())
                .unwrap_or(256);
            if queue_capacity < 16 {
                warnings.push(ConfigWarning {
                    code: "otlp_queue_capacity_low",
                    severity: "medium",
                    message: format!(
                        "otlp_queue_capacity={} may drop snapshots during burst traffic.",
                        queue_capacity
                    ),
                });
            }
            let retry_attempts = obs
                .get(serde_yaml::Value::String(
                    "otlp_retry_max_attempts".to_string(),
                ))
                .and_then(|v| v.as_u64())
                .unwrap_or(3);
            if retry_attempts <= 1 {
                warnings.push(ConfigWarning {
                    code: "otlp_retry_attempts_too_low",
                    severity: "medium",
                    message:
                        "otlp_retry_max_attempts <= 1 may drop data during short network blips."
                            .to_string(),
                });
            }
        }
    }

    let risk_level = if warnings.iter().any(|w| w.severity == "high") {
        "high"
    } else if warnings.iter().any(|w| w.severity == "medium") {
        "medium"
    } else {
        "none"
    };
    Ok(Json(json!({
        "ok": true,
        "security_posture": {
            "sandbox_mode": sandbox_mode,
            "sandbox_runtime_available": sandbox_runtime_available,
            "sandbox_backend": format!("{:?}", state.app_state.config.sandbox.backend).to_lowercase(),
            "sandbox_require_runtime": state.app_state.config.sandbox.require_runtime,
            "execution_policies": execution_policy_items,
            "mount_allowlist": mount_allowlist_status
        },
        "risk_level": risk_level,
        "warning_count": warnings.len(),
        "warnings": warnings
    })))
}

fn docker_runtime_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn default_mount_allowlist_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))?;
    Some(home.join(".microclaw/sandbox-mount-allowlist.txt"))
}

pub(super) async fn api_update_config(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Admin).await?;

    let mut cfg = state.app_state.config.clone();

    if let Some(v) = body.llm_provider {
        cfg.llm_provider = v;
    }
    if let Some(v) = body.api_key {
        cfg.api_key = v;
    }
    if let Some(v) = body.model {
        cfg.model = v;
    }
    if let Some(v) = body.llm_base_url {
        cfg.llm_base_url = v;
    }
    if let Some(v) = body.max_tokens {
        cfg.max_tokens = v;
    }
    if let Some(v) = body.max_tool_iterations {
        cfg.max_tool_iterations = v;
    }
    if let Some(v) = body.openai_compat_body_overrides {
        cfg.openai_compat_body_overrides = v;
    }
    if let Some(v) = body.openai_compat_body_overrides_by_provider {
        cfg.openai_compat_body_overrides_by_provider = v;
    }
    if let Some(v) = body.openai_compat_body_overrides_by_model {
        cfg.openai_compat_body_overrides_by_model = v;
    }
    if let Some(v) = body.max_document_size_mb {
        cfg.max_document_size_mb = v;
    }
    if let Some(v) = body.memory_token_budget {
        cfg.memory_token_budget = v;
    }
    if let Some(v) = body.embedding_provider {
        cfg.embedding_provider = v;
    }
    if let Some(v) = body.embedding_api_key {
        cfg.embedding_api_key = v;
    }
    if let Some(v) = body.embedding_base_url {
        cfg.embedding_base_url = v;
    }
    if let Some(v) = body.embedding_model {
        cfg.embedding_model = v;
    }
    if let Some(v) = body.embedding_dim {
        cfg.embedding_dim = v;
    }
    if let Some(v) = body.working_dir_isolation {
        cfg.working_dir_isolation = v;
    }
    if let Some(v) = body.high_risk_tool_user_confirmation_required {
        cfg.high_risk_tool_user_confirmation_required = v;
    }
    if let Some(v) = body.telegram_bot_token {
        cfg.telegram_bot_token = v;
    }
    if let Some(v) = body.bot_username {
        cfg.bot_username = v;
    }
    if let Some(v) = body.discord_bot_token {
        cfg.discord_bot_token = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = body.discord_allowed_channels {
        cfg.discord_allowed_channels = v;
    }
    let mut set_channel_bot_username = |channel: &str, value: Option<&str>| {
        if let Some(v) = value.map(str::trim) {
            if v.is_empty() {
                return;
            }
            let entry = cfg
                .channels
                .entry(channel.to_string())
                .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
            if let Some(map) = entry.as_mapping_mut() {
                map.insert(
                    serde_yaml::Value::String("bot_username".to_string()),
                    serde_yaml::Value::String(v.to_string()),
                );
            }
        }
    };
    set_channel_bot_username("telegram", body.telegram_bot_username.as_deref());
    set_channel_bot_username("discord", body.discord_bot_username.as_deref());
    set_channel_bot_username("slack", body.slack_bot_username.as_deref());
    set_channel_bot_username("feishu", body.feishu_bot_username.as_deref());
    set_channel_bot_username("web", body.web_bot_username.as_deref());

    if let Some(channel_configs) = body.channel_configs {
        for (channel_name, fields) in channel_configs {
            let entry = cfg
                .channels
                .entry(channel_name)
                .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
            if let Some(map) = entry.as_mapping_mut() {
                for (field_key, json_val) in fields {
                    if let Some(s) = json_val.as_str() {
                        if s.trim().is_empty() {
                            continue;
                        }
                    }
                    let yaml_val = json_to_yaml_value(&json_val);
                    let key = serde_yaml::Value::String(field_key.clone());
                    let target = map.entry(key).or_insert(serde_yaml::Value::Null);
                    merge_yaml_value(target, &yaml_val, Some(&field_key));
                }
            }
        }
    }

    if let Some(v) = body.reflector_enabled {
        cfg.reflector_enabled = v;
    }
    if let Some(v) = body.reflector_interval_mins {
        cfg.reflector_interval_mins = v;
    }

    if let Some(v) = body.show_thinking {
        cfg.show_thinking = v;
    }
    if let Some(v) = body.web_enabled {
        cfg.web_enabled = v;
    }
    if let Some(v) = body.web_host {
        cfg.web_host = v;
    }
    if let Some(v) = body.web_port {
        cfg.web_port = v;
    }
    if let Some(v) = body.web_auth_token {
        cfg.web_auth_token = v;
    }
    if let Some(v) = body.web_max_inflight_per_session {
        cfg.web_max_inflight_per_session = v;
    }
    if let Some(v) = body.web_max_requests_per_window {
        cfg.web_max_requests_per_window = v;
    }
    if let Some(v) = body.web_rate_window_seconds {
        cfg.web_rate_window_seconds = v;
    }
    if let Some(v) = body.web_run_history_limit {
        cfg.web_run_history_limit = v;
    }
    if let Some(v) = body.web_session_idle_ttl_seconds {
        cfg.web_session_idle_ttl_seconds = v;
    }

    if let Err(e) = cfg.post_deserialize() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    let path = config_path_for_save()?;
    cfg.save_yaml(&path.to_string_lossy())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    audit_log(
        &state,
        "operator",
        &identity.actor,
        "config.update",
        Some(&path.to_string_lossy()),
        "ok",
        None,
    )
    .await;

    Ok(Json(json!({
        "ok": true,
        "path": path,
        "requires_restart": true
    })))
}
