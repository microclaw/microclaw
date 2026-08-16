use super::*;

#[derive(Debug, Serialize)]
pub(crate) struct SessionItem {
    pub(crate) session_key: String,
    pub(crate) label: String,
    pub(crate) chat_id: i64,
    pub(crate) chat_type: String,
    pub(crate) last_message_time: String,
    pub(crate) last_message_preview: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HistoryItem {
    pub(crate) id: String,
    pub(crate) sender_name: String,
    pub(crate) content: String,
    pub(crate) is_from_bot: bool,
    pub(crate) timestamp: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryQuery {
    pub(crate) session_key: Option<String>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SendRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) sender_name: Option<String>,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookAgentRequest {
    #[serde(default, alias = "session_key")]
    pub(crate) session_key: Option<String>,
    #[serde(default, alias = "sender_name")]
    pub(crate) sender_name: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookWakeRequest {
    #[serde(default, alias = "session_key")]
    pub(crate) session_key: Option<String>,
    #[serde(default, alias = "sender_name")]
    pub(crate) sender_name: Option<String>,
    pub(crate) text: String,
    #[serde(default)]
    pub(crate) mode: Option<String>, // now | next-heartbeat
}

#[derive(Debug, Deserialize)]
pub(crate) struct StreamQuery {
    pub(crate) run_id: String,
    pub(crate) last_event_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResetRequest {
    pub(crate) session_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RunStatusQuery {
    pub(crate) run_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UsageQuery {
    pub(crate) session_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningFeedbackRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) run_id: String,
    pub(crate) verdict: String,
    pub(crate) evidence: Option<String>,
    pub(crate) confidence: Option<f64>,
    pub(crate) scope: Option<String>,
    pub(crate) feedback_id: Option<String>,
    pub(crate) valid_until: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningExperienceQuery {
    pub(crate) session_key: Option<String>,
    pub(crate) query: String,
    pub(crate) environment: Option<String>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningRunDetailQuery {
    pub(crate) session_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningRecoveryRequest {
    pub(crate) skill_name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningCandidateRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) claim_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningShadowObservationRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) candidate_id: String,
    pub(crate) pair_key: String,
    pub(crate) arm: String,
    pub(crate) run_id: String,
    pub(crate) verdict: String,
    #[serde(default)]
    pub(crate) cost_usd: f64,
    #[serde(default)]
    pub(crate) duration_ms: i64,
    pub(crate) evidence: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningCandidateActionRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) candidate_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningTrackCandidateActionRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) candidate_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningArchiveRequest {
    pub(crate) session_key: Option<String>,
    pub(crate) entity_type: String,
    pub(crate) entity_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LearningRollbackRequest {
    pub(crate) skill_name: String,
    pub(crate) target_version: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MemoryObservabilityQuery {
    pub(crate) session_key: Option<String>,
    pub(crate) scope: Option<String>, // chat | global
    pub(crate) hours: Option<u64>,
    pub(crate) limit: Option<usize>,
    pub(crate) offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateConfigRequest {
    pub(crate) llm_provider: Option<String>,
    pub(crate) api_key: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) llm_base_url: Option<Option<String>>,
    pub(crate) llm_user_agent: Option<Option<String>>,
    pub(crate) provider_presets: Option<HashMap<String, crate::config::LlmProviderProfile>>,
    pub(crate) max_tokens: Option<u32>,
    pub(crate) max_tool_iterations: Option<usize>,
    pub(crate) openai_compat_body_overrides: Option<HashMap<String, serde_json::Value>>,
    pub(crate) openai_compat_body_overrides_by_provider:
        Option<HashMap<String, HashMap<String, serde_json::Value>>>,
    pub(crate) openai_compat_body_overrides_by_model:
        Option<HashMap<String, HashMap<String, serde_json::Value>>>,
    pub(crate) max_document_size_mb: Option<u64>,
    pub(crate) memory_token_budget: Option<usize>,
    pub(crate) embedding_provider: Option<Option<String>>,
    pub(crate) embedding_api_key: Option<Option<String>>,
    pub(crate) embedding_base_url: Option<Option<String>>,
    pub(crate) embedding_model: Option<Option<String>>,
    pub(crate) embedding_dim: Option<Option<usize>>,
    pub(crate) a2a_enabled: Option<bool>,
    pub(crate) a2a_public_base_url: Option<Option<String>>,
    pub(crate) a2a_agent_name: Option<Option<String>>,
    pub(crate) a2a_agent_description: Option<Option<String>>,
    pub(crate) a2a_shared_tokens: Option<Vec<String>>,
    pub(crate) a2a_peers: Option<HashMap<String, crate::config::A2APeerConfig>>,
    pub(crate) souls_dir: Option<Option<String>>,
    pub(crate) working_dir_isolation: Option<WorkingDirIsolation>,
    pub(crate) high_risk_tool_user_confirmation_required: Option<bool>,

    pub(crate) telegram_bot_token: Option<String>,
    pub(crate) bot_username: Option<String>,
    pub(crate) telegram_bot_username: Option<String>,
    pub(crate) discord_bot_token: Option<String>,
    pub(crate) discord_allowed_channels: Option<Vec<u64>>,
    pub(crate) discord_bot_username: Option<String>,
    pub(crate) slack_bot_username: Option<String>,
    pub(crate) feishu_bot_username: Option<String>,
    pub(crate) web_bot_username: Option<String>,

    /// Generic per-channel config updates. Keys are channel names (e.g. "slack", "feishu").
    /// Values are objects with channel-specific fields. Non-empty string values are merged
    /// into `cfg.channels[name]`; this avoids adding per-channel fields here.
    #[serde(default)]
    pub(crate) channel_configs: Option<HashMap<String, HashMap<String, serde_json::Value>>>,

    pub(crate) reflector_enabled: Option<bool>,
    pub(crate) reflector_interval_mins: Option<u64>,

    // Governance surface (web panel Governance tab).
    pub(crate) tool_policy: Option<crate::tool_guardrails::ToolPolicyConfig>,
    pub(crate) egress_policy: Option<crate::config::EgressPolicyConfig>,
    pub(crate) sandbox_credential_env_allowlist: Option<Vec<String>>,
    pub(crate) token_budget: Option<crate::config::TokenBudgetConfig>,
    pub(crate) heartbeat: Option<crate::config::HeartbeatConfig>,
    pub(crate) alerts: Option<crate::config::AlertsConfig>,
    pub(crate) trust_report: Option<crate::config::TrustReportConfig>,

    pub(crate) show_thinking: Option<bool>,
    pub(crate) web_enabled: Option<bool>,
    pub(crate) web_host: Option<String>,
    pub(crate) web_port: Option<u16>,
    pub(crate) web_max_inflight_per_session: Option<usize>,
    pub(crate) web_max_requests_per_window: Option<usize>,
    pub(crate) web_rate_window_seconds: Option<u64>,
    pub(crate) web_run_history_limit: Option<usize>,
    pub(crate) web_session_idle_ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginRequest {
    pub(crate) password: String,
    pub(crate) label: Option<String>,
    pub(crate) remember_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SetPasswordRequest {
    pub(crate) password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateApiKeyRequest {
    pub(crate) label: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) expires_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RotateApiKeyRequest {
    pub(crate) label: Option<String>,
    pub(crate) scopes: Option<Vec<String>>,
    pub(crate) expires_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ForkSessionRequest {
    pub(crate) source_session_key: String,
    pub(crate) target_session_key: Option<String>,
    pub(crate) fork_point: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MetricsHistoryQuery {
    pub(crate) minutes: Option<i64>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SessionTreeQuery {
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuditQuery {
    pub(crate) kind: Option<String>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigWarning {
    pub(crate) code: &'static str,
    pub(crate) severity: &'static str,
    pub(crate) message: String,
}
