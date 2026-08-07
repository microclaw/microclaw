use rusqlite::OptionalExtension;
use rusqlite::{params, Connection, Transaction};
use std::path::Path;
#[cfg(feature = "sqlite-vec")]
use std::sync::Once;
use std::sync::{Mutex, MutexGuard};

use microclaw_core::error::MicroClawError;

pub struct Database {
    conn: Mutex<Connection>,
}

#[cfg(feature = "sqlite-vec")]
static SQLITE_VEC_AUTOEXT_INIT: Once = Once::new();

#[cfg(feature = "sqlite-vec")]
type SqliteAutoExtensionFn = unsafe extern "C" fn(
    *mut rusqlite::ffi::sqlite3,
    *mut *mut i8,
    *const rusqlite::ffi::sqlite3_api_routines,
) -> i32;

pub async fn call_blocking<T, F>(db: std::sync::Arc<Database>, f: F) -> Result<T, MicroClawError>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T, MicroClawError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || f(db.as_ref()))
        .await
        .map_err(|e| MicroClawError::ToolExecution(format!("DB task join error: {e}")))?
}

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub chat_id: i64,
    pub sender_name: String,
    pub content: String,
    pub is_from_bot: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct ChatSummary {
    pub chat_id: i64,
    pub chat_title: Option<String>,
    pub session_label: Option<String>,
    pub chat_type: String,
    pub last_message_time: String,
    pub last_message_preview: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SessionSettings {
    pub label: Option<String>,
    pub thinking_level: Option<String>,
    pub verbose_level: Option<String>,
    pub reasoning_level: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TaskRunLog {
    pub id: i64,
    pub task_id: i64,
    pub chat_id: i64,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: i64,
    pub success: bool,
    pub result_summary: Option<String>,
}

/// A row returned from the tool result cache lookup.
#[derive(Debug, Clone)]
pub struct CachedToolResult {
    pub tool_name: String,
    pub content: String,
    pub is_error: bool,
    pub metadata_json: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// Metadata for a stored tool-result artifact.
#[derive(Debug, Clone)]
pub struct ToolArtifactMeta {
    pub artifact_id: String,
    pub chat_id: i64,
    pub tool_name: String,
    pub total_chars: i64,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct LlmUsageSummary {
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub last_request_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LlmModelUsageSummary {
    pub model: String,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
}

#[derive(Debug, Clone)]
pub struct Memory {
    pub id: i64,
    pub chat_id: Option<i64>,
    pub content: String,
    pub category: String,
    pub created_at: String,
    pub updated_at: String,
    pub embedding_model: Option<String>,
    pub confidence: f64,
    pub source: String,
    pub last_seen_at: String,
    pub is_archived: bool,
    pub archived_at: Option<String>,
    /// Optional RFC3339 timestamp at which this memory expires. NULL means
    /// the memory is durable; expired rows are filtered from retrieval and
    /// pruned by the reflector.
    pub expires_at: Option<String>,
}

/// A single triple in the temporal knowledge graph.
#[derive(Debug, Clone)]
pub struct KgTriple {
    pub id: i64,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub chat_id: Option<i64>,
    pub valid_from: String,
    pub valid_to: Option<String>,
    pub confidence: f64,
    pub source: String,
    pub source_memory_id: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct MemoryObservabilitySummary {
    pub total: i64,
    pub active: i64,
    pub archived: i64,
    pub low_confidence: i64,
    pub avg_confidence: f64,
    pub reflector_runs_24h: i64,
    pub reflector_inserted_24h: i64,
    pub reflector_updated_24h: i64,
    pub reflector_skipped_24h: i64,
    pub injection_events_24h: i64,
    pub injection_selected_24h: i64,
    pub injection_candidates_24h: i64,
}

#[derive(Debug, Clone)]
pub struct MemoryReflectorRun {
    pub id: i64,
    pub chat_id: i64,
    pub started_at: String,
    pub finished_at: String,
    pub extracted_count: i64,
    pub inserted_count: i64,
    pub updated_count: i64,
    pub skipped_count: i64,
    pub dedup_method: String,
    pub parse_ok: bool,
    pub error_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryInjectionLog {
    pub id: i64,
    pub chat_id: i64,
    pub created_at: String,
    pub retrieval_method: String,
    pub candidate_count: i64,
    pub selected_count: i64,
    pub omitted_count: i64,
    pub tokens_est: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GoalStateRecord {
    pub goal_id: String,
    pub chat_id: i64,
    pub objective: String,
    pub status: String,
    pub constraints_json: Option<String>,
    pub progress_json: Option<String>,
    pub budget_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExperienceRunRecord {
    pub run_id: String,
    pub goal_id: Option<String>,
    pub chat_id: i64,
    pub channel: String,
    pub run_kind: String,
    pub objective: String,
    pub environment_fingerprint: Option<String>,
    pub status: String,
    pub result_summary: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub llm_requests: i64,
    pub tool_calls: i64,
    pub tool_errors: i64,
    pub estimated_cost_usd: Option<f64>,
    pub task_signature: TaskSignatureV1,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TaskSignatureV1 {
    pub version: i64,
    pub task_type: String,
    pub task_family: String,
    pub capability_tags: Vec<String>,
    pub signature_hash: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifierResultRecord {
    pub id: i64,
    pub run_id: String,
    pub verifier_type: String,
    pub verifier_name: String,
    pub verdict: String,
    pub confidence: f64,
    pub evidence: Option<String>,
    pub scope: Option<String>,
    pub verified_at: String,
    pub valid_until: Option<String>,
}

/// Stable ingestion contract for every piece of outcome evidence.
///
/// Keep this versioned and append-only: producers may evolve independently,
/// while persisted envelopes remain replayable and auditable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutcomeEnvelopeV1 {
    pub envelope_id: String,
    pub run_id: String,
    pub source_kind: String,
    pub source_name: String,
    pub verdict: String,
    pub confidence: f64,
    pub evidence: Option<String>,
    pub scope: Option<String>,
    pub valid_until: Option<String>,
    #[serde(default)]
    pub payload: serde_json::Value,
    pub feedback: Option<ExperienceFeedbackInput>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExperienceFeedbackInput {
    pub feedback_id: String,
    pub actor: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExperienceFeedbackRecord {
    pub feedback_id: String,
    pub run_id: String,
    pub actor: String,
    pub verdict: String,
    pub confidence: f64,
    pub evidence: Option<String>,
    pub scope: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExperienceRetrievalRecord {
    pub querying_run_id: String,
    pub source_run_id: String,
    pub rank: i64,
    pub selection_reason: String,
    pub relevance_score: f64,
    pub injected_at: String,
    pub source_objective: String,
    pub source_result_summary: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillActivationRecord {
    pub skill_name: String,
    pub skill_version: Option<i64>,
    pub activated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OutcomeEnvelopeRecord {
    pub envelope_id: String,
    pub schema_version: i64,
    pub run_id: String,
    pub source_kind: String,
    pub source_name: String,
    pub verdict: String,
    pub confidence: f64,
    pub evidence: Option<String>,
    pub scope: Option<String>,
    pub valid_until: Option<String>,
    pub payload: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExperienceRunDetail {
    pub run: ExperienceRunRecord,
    pub outcomes: Vec<OutcomeEnvelopeRecord>,
    pub feedback: Vec<ExperienceFeedbackRecord>,
    pub retrieved_experiences: Vec<ExperienceRetrievalRecord>,
    pub rejected_experiences: Vec<ExperienceRejectionRecord>,
    pub activated_skills: Vec<SkillActivationRecord>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExperienceRejectionRecord {
    pub source_run_id: String,
    pub rejection_reason: String,
    pub relevance_score: f64,
    pub rejected_at: String,
    pub source_objective: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillLifecycleRecord {
    pub skill_name: String,
    pub state: String,
    pub active_version: i64,
    pub previous_trusted_version: Option<i64>,
    pub source: String,
    pub created_at: String,
    pub updated_at: String,
    pub state_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillLearningSummary {
    pub skill_name: String,
    pub state: String,
    pub active_version: i64,
    pub total_outcomes: i64,
    pub passed_outcomes: i64,
    pub failed_outcomes: i64,
    pub success_rate: f64,
    pub utility_lower_bound: f64,
    pub last_outcome_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillTaskUtilitySummary {
    pub skill_name: String,
    pub skill_version: i64,
    pub task_type: String,
    pub task_family: String,
    pub total_outcomes: i64,
    pub passed_outcomes: i64,
    pub failed_outcomes: i64,
    pub success_rate: f64,
    pub utility_lower_bound: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillFailurePattern {
    pub pattern_id: String,
    pub skill_name: String,
    pub skill_version: i64,
    pub task_type: String,
    pub task_family: String,
    pub environment_fingerprint: Option<String>,
    pub tool_name: Option<String>,
    pub error_category: String,
    pub failure_count: i64,
    pub recovery_successes: i64,
    pub state: String,
    pub cooldown_until: Option<String>,
    pub last_evidence: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExperienceComparison {
    pub comparison_id: String,
    pub chat_id: i64,
    pub skill_name: String,
    pub skill_version: i64,
    pub task_type: String,
    pub task_family: String,
    pub environment_fingerprint: Option<String>,
    pub success_run_id: String,
    pub failure_run_id: String,
    pub minimal_difference: String,
    pub counterexample: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningClaim {
    pub claim_id: String,
    pub comparison_id: String,
    pub skill_name: String,
    pub base_version: i64,
    pub claim_version: i64,
    pub statement: String,
    pub applicability: serde_json::Value,
    pub confidence: f64,
    pub evidence: serde_json::Value,
    pub counterexamples: serde_json::Value,
    pub status: String,
    pub supersedes_claim_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillCandidate {
    pub candidate_id: String,
    pub claim_id: String,
    pub skill_name: String,
    pub base_version: i64,
    pub candidate_version: i64,
    pub content: String,
    pub content_hash: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShadowEvaluation {
    pub evaluation_id: String,
    pub candidate_id: String,
    pub sample_count: i64,
    pub baseline_passed: i64,
    pub candidate_passed: i64,
    pub baseline_utility_lower_bound: f64,
    pub candidate_utility_lower_bound: f64,
    pub baseline_cost_usd: f64,
    pub candidate_cost_usd: f64,
    pub baseline_duration_ms: i64,
    pub candidate_duration_ms: i64,
    pub regression_count: i64,
    pub verdict: String,
    pub reason: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningJournalEvent {
    pub id: i64,
    pub event_type: String,
    pub entity_type: String,
    pub entity_id: String,
    pub summary: String,
    pub evidence: serde_json::Value,
    pub undo_action: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SkillGovernancePolicy {
    pub candidate_failures_to_degrade: i64,
    pub trial_min_outcomes: i64,
    pub trial_promote_rate: f64,
    pub trial_degrade_rate: f64,
    pub trusted_min_outcomes: i64,
    pub trusted_degrade_rate: f64,
    pub utility_confidence_z: f64,
    pub trial_promote_utility_lower_bound: f64,
    pub failure_pattern_min_failures: i64,
    pub failure_pattern_cooldown_hours: i64,
    pub failure_pattern_recovery_successes: i64,
    pub shadow_min_samples: i64,
    pub shadow_promote_utility_margin: f64,
    pub shadow_max_cost_ratio: f64,
    pub shadow_max_regressions: i64,
}

impl Default for SkillGovernancePolicy {
    fn default() -> Self {
        Self {
            candidate_failures_to_degrade: 2,
            trial_min_outcomes: 3,
            trial_promote_rate: 0.8,
            trial_degrade_rate: 0.5,
            trusted_min_outcomes: 5,
            trusted_degrade_rate: 0.6,
            utility_confidence_z: 1.96,
            trial_promote_utility_lower_bound: 0.4,
            failure_pattern_min_failures: 2,
            failure_pattern_cooldown_hours: 24,
            failure_pattern_recovery_successes: 2,
            shadow_min_samples: 3,
            shadow_promote_utility_margin: 0.05,
            shadow_max_cost_ratio: 1.2,
            shadow_max_regressions: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillApplicability {
    pub environment_fingerprint: Option<String>,
    pub task_type: Option<String>,
    pub task_family: Option<String>,
    pub matching_outcomes: i64,
    pub passed_outcomes: i64,
    pub failed_outcomes: i64,
    pub success_rate: Option<f64>,
    pub utility_lower_bound: Option<f64>,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedExperienceMatch {
    pub run_id: String,
    pub objective: String,
    pub environment_fingerprint: Option<String>,
    pub verdict: String,
    pub verifier_type: String,
    pub confidence: f64,
    pub result_summary: Option<String>,
    pub started_at: String,
    pub duration_ms: Option<i64>,
    pub total_tokens: i64,
    pub tool_calls: i64,
    pub tool_errors: i64,
    pub estimated_cost_usd: Option<f64>,
    pub relevance_score: f64,
    pub utility_lower_bound: f64,
    pub task_signature: TaskSignatureV1,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ExperienceSummary {
    pub total_runs: i64,
    pub completed_runs: i64,
    pub failed_runs: i64,
    pub verified_runs: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub tool_calls: i64,
    pub tool_errors: i64,
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone)]
pub struct AuthApiKeyRecord {
    pub id: i64,
    pub label: String,
    pub prefix: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub rotated_from_key_id: Option<i64>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MetricsHistoryPoint {
    pub timestamp_ms: i64,
    pub llm_completions: i64,
    pub llm_input_tokens: i64,
    pub llm_output_tokens: i64,
    pub http_requests: i64,
    pub tool_executions: i64,
    pub mcp_calls: i64,
    pub mcp_rate_limited_rejections: i64,
    pub mcp_bulkhead_rejections: i64,
    pub mcp_circuit_open_rejections: i64,
    pub active_sessions: i64,
}

#[derive(Debug, Clone)]
pub struct AuditLogRecord {
    pub id: i64,
    pub kind: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub status: String,
    pub detail: Option<String>,
    pub created_at: String,
}

pub type SessionMetaRow = (String, String, Option<String>, Option<i64>);
pub type SessionTreeRow = (i64, Option<String>, Option<i64>, String);

const SCHEMA_VERSION_CURRENT: i64 = 43;

pub fn wilson_lower_bound(passed: i64, total: i64, z: f64) -> f64 {
    if total <= 0 || passed < 0 || passed > total || !z.is_finite() || z < 0.0 {
        return 0.0;
    }
    let n = total as f64;
    let p = passed as f64 / n;
    let z2 = z * z;
    ((p + z2 / (2.0 * n) - z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt()) / (1.0 + z2 / n))
        .clamp(0.0, 1.0)
}

pub fn derive_task_signature(objective: &str, run_kind: &str) -> TaskSignatureV1 {
    let normalized = objective.to_lowercase();
    let contains_any = |terms: &[&str]| terms.iter().any(|term| normalized.contains(term));
    let (task_type, task_family) =
        if contains_any(&["debug", "bug", "fix", "报错", "修复", "故障", "失败原因"]) {
            ("software_development", "debugging")
        } else if contains_any(&["test", "verify", "验证", "测试", "coverage", "clippy"]) {
            ("software_development", "testing")
        } else if contains_any(&[
            "implement",
            "code",
            "refactor",
            "代码",
            "实现",
            "开发",
            "重构",
        ]) {
            ("software_development", "code_change")
        } else if contains_any(&["deploy", "release", "ci", "部署", "发布", "上线"]) {
            ("operations", "deployment")
        } else if contains_any(&[
            "search", "research", "look up", "调研", "搜索", "查找", "资料",
        ]) {
            ("information_retrieval", "research")
        } else if contains_any(&["analy", "metric", "sql", "dataset", "分析", "指标", "数据"])
        {
            ("data_analysis", "analysis")
        } else if contains_any(&["document", "report", "pdf", "slide", "文档", "报告", "演示"])
        {
            ("content_creation", "document_creation")
        } else if contains_any(&["email", "message", "notify", "邮件", "消息", "通知"]) {
            ("communication", "messaging")
        } else if contains_any(&["schedule", "remind", "calendar", "定时", "提醒", "日历"])
            || run_kind == "scheduled"
        {
            ("operations", "scheduling")
        } else if contains_any(&["memory", "remember", "记忆", "记住", "忘记"]) {
            ("agent_learning", "memory_management")
        } else if contains_any(&["skill", "技能", "学习"]) {
            ("agent_learning", "skill_management")
        } else if contains_any(&["plan", "roadmap", "规划", "计划", "路线"]) {
            ("reasoning", "planning")
        } else {
            ("general", "general_assistance")
        };

    let mut tags = Vec::new();
    for (tag, terms) in [
        ("browser", &["browser", "chrome", "网页", "浏览器"][..]),
        ("filesystem", &["file", "directory", "文件", "目录"][..]),
        (
            "shell",
            &["shell", "command", "terminal", "命令", "终端"][..],
        ),
        ("web", &["web", "http", "url", "网站", "网络"][..]),
        ("coding", &["code", "rust", "python", "代码", "编程"][..]),
        (
            "verification",
            &["test", "verify", "check", "测试", "验证"][..],
        ),
        ("data", &["data", "sql", "metric", "数据", "指标"][..]),
        ("messaging", &["email", "message", "邮件", "消息"][..]),
        ("scheduling", &["schedule", "calendar", "定时", "日历"][..]),
    ] {
        if contains_any(terms) {
            tags.push(tag.to_string());
        }
    }
    tags.push(task_type.to_string());
    tags.sort();
    tags.dedup();
    let canonical = format!("v1|{task_type}|{task_family}|{}", tags.join(","));
    use sha2::Digest;
    let signature_hash = to_hex(&sha2::Sha256::digest(canonical.as_bytes()));
    TaskSignatureV1 {
        version: 1,
        task_type: task_type.into(),
        task_family: task_family.into(),
        capability_tags: tags,
        signature_hash,
    }
}

/// Genesis link for the tamper-evident audit hash chain — the `prev_hash` of the
/// first sealed entry.
const AUDIT_GENESIS_HASH: &str = "GENESIS";

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScheduledTask {
    pub id: i64,
    pub chat_id: i64,
    pub prompt: String,
    pub schedule_type: String,  // "cron" or "once"
    pub schedule_value: String, // cron expression or ISO timestamp
    pub timezone: String,       // IANA timezone; empty means "use app default"
    pub next_run: String,       // ISO timestamp
    pub last_run: Option<String>,
    pub status: String, // "active", "paused", "completed", "cancelled"
    pub created_at: String,
    /// Optional completion contract: JSON array of exit criteria, verified
    /// after each run (see src/completion_contract.rs).
    pub exit_criteria: Option<String>,
    /// Number of times this task has run (success or failure).
    pub run_count: i64,
    /// Retire as `completed` after this many runs. NULL = unlimited.
    pub max_runs: Option<i64>,
    /// Retire as `completed` once the next firing would pass this instant.
    pub not_after: Option<String>,
}

/// A durable, user-directed background learning programme.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningTrack {
    pub track_id: String,
    pub chat_id: i64,
    pub name: String,
    pub objective: String,
    pub directions: serde_json::Value,
    pub allowed_sources: serde_json::Value,
    pub schedule: String,
    pub timezone: String,
    pub token_budget: i64,
    pub max_sources: i64,
    pub promotion_mode: String,
    pub status: String,
    pub next_run: String,
    pub last_run: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningEpoch {
    pub epoch_id: String,
    pub track_id: String,
    pub experience_run_id: Option<String>,
    pub status: String,
    pub report: Option<String>,
    pub candidate_id: Option<String>,
    pub error: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

/// An inert skill proposal produced by a learning epoch. It is never part of
/// prompt discovery until an operator explicitly promotes it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningTrackCandidate {
    pub candidate_id: String,
    pub epoch_id: String,
    pub skill_name: String,
    pub description: String,
    pub instructions: String,
    pub sources: serde_json::Value,
    pub tests: serde_json::Value,
    pub risk: String,
    pub content_hash: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningCandidateEvaluation {
    pub evaluation_id: String,
    pub candidate_id: String,
    pub status: String,
    pub sample_count: i64,
    pub baseline_passed: i64,
    pub candidate_passed: i64,
    pub regression_count: i64,
    pub baseline_tokens: i64,
    pub candidate_tokens: i64,
    pub baseline_duration_ms: i64,
    pub candidate_duration_ms: i64,
    pub reason: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LearningCandidateTrial {
    pub trial_id: String,
    pub evaluation_id: String,
    pub test_name: String,
    pub baseline_passed: bool,
    pub candidate_passed: bool,
    pub baseline_tokens: i64,
    pub candidate_tokens: i64,
    pub baseline_duration_ms: i64,
    pub candidate_duration_ms: i64,
    pub evidence: serde_json::Value,
    pub created_at: String,
}

fn map_learning_track(row: &rusqlite::Row<'_>) -> rusqlite::Result<LearningTrack> {
    let directions: String = row.get(4)?;
    let allowed_sources: String = row.get(5)?;
    Ok(LearningTrack {
        track_id: row.get(0)?,
        chat_id: row.get(1)?,
        name: row.get(2)?,
        objective: row.get(3)?,
        directions: serde_json::from_str(&directions).unwrap_or_default(),
        allowed_sources: serde_json::from_str(&allowed_sources).unwrap_or_default(),
        schedule: row.get(6)?,
        timezone: row.get(7)?,
        token_budget: row.get(8)?,
        max_sources: row.get(9)?,
        promotion_mode: row.get(10)?,
        status: row.get(11)?,
        next_run: row.get(12)?,
        last_run: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

/// An interactive turn that was in flight when the previous process died.
#[derive(Debug, Clone)]
pub struct InterruptedTurn {
    pub chat_id: i64,
    pub channel: String,
    pub chat_type: String,
    pub started_at: String,
    /// Rolling "step N: tool, tool" snapshot from the agent loop, if the run
    /// got far enough to execute tools.
    pub progress_text: Option<String>,
    /// Durable agent-loop phase at the last checkpoint.
    pub phase: String,
    /// Zero-based loop iteration captured with `session_json`.
    pub iteration: i64,
    /// Last session state known to be safe for another LLM call.
    pub session_json: Option<String>,
    /// Whether startup recovery may continue automatically from this row.
    pub resumable: bool,
    /// Pending or executing tool summary when the process stopped.
    pub tool_summary: Option<String>,
    pub last_checkpoint_at: Option<String>,
    pub run_id: Option<String>,
}

fn map_interrupted_turn(row: &rusqlite::Row<'_>) -> rusqlite::Result<InterruptedTurn> {
    Ok(InterruptedTurn {
        chat_id: row.get(0)?,
        channel: row.get(1)?,
        chat_type: row.get(2)?,
        started_at: row.get(3)?,
        progress_text: row.get(4)?,
        phase: row.get(5)?,
        iteration: row.get(6)?,
        session_json: row.get(7)?,
        resumable: row.get::<_, i64>(8)? != 0,
        tool_summary: row.get(9)?,
        last_checkpoint_at: row.get(10)?,
        run_id: row.get(11)?,
    })
}

/// A final reply queued for redelivery after a failed channel send.
#[derive(Debug, Clone)]
pub struct OutboxMessageRecord {
    pub id: i64,
    pub delivery_id: String,
    pub chat_id: i64,
    pub channel: String,
    pub payload_text: String,
    pub full_payload_text: String,
    pub chunk_index: i64,
    pub total_chunks: i64,
    pub idempotency_key: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundDeliveryHealth {
    pub total_deliveries: i64,
    pub delivered_deliveries: i64,
    pub pending_chunks: i64,
    pub sending_chunks: i64,
    pub retry_chunks: i64,
    pub failed_chunks: i64,
    pub oldest_unfinished_at: Option<String>,
}

fn refresh_delivery_status(
    tx: &Transaction<'_>,
    chunk_id: i64,
    now: &str,
) -> Result<(), MicroClawError> {
    let delivery_id: String = tx.query_row(
        "SELECT delivery_id FROM outbound_delivery_chunks WHERE id=?1",
        params![chunk_id],
        |row| row.get(0),
    )?;
    let (total, delivered, failed): (i64, i64, i64) = tx.query_row(
        "SELECT COUNT(*),
                SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
         FROM outbound_delivery_chunks WHERE delivery_id=?1",
        params![delivery_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let status = if failed > 0 {
        "failed"
    } else if total > 0 && delivered == total {
        "delivered"
    } else if delivered > 0 {
        "partial"
    } else {
        "pending"
    };
    tx.execute(
        "UPDATE outbound_deliveries SET status=?2, updated_at=?3 WHERE delivery_id=?1",
        params![delivery_id, status, now],
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ScheduledTaskDlqEntry {
    pub id: i64,
    pub task_id: i64,
    pub chat_id: i64,
    pub failed_at: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: i64,
    pub error_summary: Option<String>,
    pub replayed_at: Option<String>,
    pub replay_note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubagentRunRecord {
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub depth: i64,
    pub chat_id: i64,
    pub caller_channel: String,
    pub task: String,
    pub context: String,
    pub status: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub cancel_requested: bool,
    pub error_text: Option<String>,
    pub result_text: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub provider: String,
    pub model: String,
    pub token_budget: i64,
    pub artifact_json: Option<String>,
    pub label: Option<String>,
    pub progress_text: Option<String>,
    pub last_progress_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubagentAnnounceRecord {
    pub id: i64,
    pub run_id: String,
    pub chat_id: i64,
    pub caller_channel: String,
    pub payload_text: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
}

pub struct CreateSubagentRunParams<'a> {
    pub run_id: &'a str,
    pub parent_run_id: Option<&'a str>,
    pub depth: i64,
    pub token_budget: i64,
    pub chat_id: i64,
    pub caller_channel: &'a str,
    pub task: &'a str,
    pub context: &'a str,
    pub provider: &'a str,
    pub model: &'a str,
    pub label: Option<&'a str>,
}

pub struct FinishSubagentRunParams<'a> {
    pub run_id: &'a str,
    pub status: &'a str,
    pub error_text: Option<&'a str>,
    pub result_text: Option<&'a str>,
    pub artifact_json: Option<&'a str>,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

#[derive(Debug, Clone)]
pub struct SubagentObservabilitySnapshot {
    pub active_runs: i64,
    pub queued_runs: i64,
    pub running_runs: i64,
    pub pending_announces: i64,
    pub retry_announces: i64,
    pub failed_announces: i64,
    pub completed_24h: i64,
    pub failed_24h: i64,
    pub budget_exceeded_24h: i64,
    pub avg_duration_ms_24h: i64,
    pub recent_runs: Vec<SubagentRunRecord>,
}

#[derive(Debug, Clone)]
pub struct SubagentEventRecord {
    pub id: i64,
    pub run_id: String,
    pub event_type: String,
    pub detail: Option<String>,
    pub created_at: String,
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, MicroClawError> {
    // Validate table name to prevent SQL injection via PRAGMA
    if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(MicroClawError::Config(format!(
            "invalid table name: {}",
            table
        )));
    }
    // PRAGMA does not support parameter binding, so format! is required here.
    // The table name validation above ensures only safe identifiers reach this point.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in rows {
        if col? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_memory_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "memories", "embedding_model")? {
        conn.execute("ALTER TABLE memories ADD COLUMN embedding_model TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "chat_channel")? {
        conn.execute("ALTER TABLE memories ADD COLUMN chat_channel TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "external_chat_id")? {
        conn.execute("ALTER TABLE memories ADD COLUMN external_chat_id TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "confidence")? {
        conn.execute("ALTER TABLE memories ADD COLUMN confidence REAL", [])?;
    }
    if !table_has_column(conn, "memories", "source")? {
        conn.execute("ALTER TABLE memories ADD COLUMN source TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "last_seen_at")? {
        conn.execute("ALTER TABLE memories ADD COLUMN last_seen_at TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "is_archived")? {
        conn.execute("ALTER TABLE memories ADD COLUMN is_archived INTEGER", [])?;
    }
    if !table_has_column(conn, "memories", "archived_at")? {
        conn.execute("ALTER TABLE memories ADD COLUMN archived_at TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "expires_at")? {
        conn.execute("ALTER TABLE memories ADD COLUMN expires_at TEXT", [])?;
    }
    conn.execute(
        "UPDATE memories
         SET confidence = COALESCE(confidence, 0.70),
             source = COALESCE(NULLIF(source, ''), 'legacy'),
             last_seen_at = COALESCE(last_seen_at, updated_at, created_at),
             is_archived = COALESCE(is_archived, 0)
         WHERE confidence IS NULL
            OR source IS NULL OR trim(source) = ''
            OR last_seen_at IS NULL
            OR is_archived IS NULL",
        [],
    )?;
    let chats_has_channel = table_has_column(conn, "chats", "channel")?;
    let chats_has_external = table_has_column(conn, "chats", "external_chat_id")?;
    if chats_has_channel && chats_has_external {
        conn.execute(
            "UPDATE memories
             SET chat_channel = (
                     SELECT c.channel FROM chats c WHERE c.chat_id = memories.chat_id
                 ),
                 external_chat_id = (
                     SELECT c.external_chat_id FROM chats c WHERE c.chat_id = memories.chat_id
                 )
             WHERE chat_id IS NOT NULL
               AND (
                   chat_channel IS NULL
                   OR trim(chat_channel) = ''
                   OR external_chat_id IS NULL
                   OR trim(external_chat_id) = ''
               )",
            [],
        )?;
    }
    Ok(())
}

fn infer_channel_from_chat_type(chat_type: &str) -> &'static str {
    if chat_type.starts_with("telegram_")
        || matches!(chat_type, "private" | "group" | "supergroup" | "channel")
    {
        "telegram"
    } else if chat_type == "discord" {
        "discord"
    } else if chat_type == "web" {
        "web"
    } else {
        "unknown"
    }
}

fn ensure_chat_identity_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "chats", "channel")? {
        conn.execute("ALTER TABLE chats ADD COLUMN channel TEXT", [])?;
    }
    if !table_has_column(conn, "chats", "external_chat_id")? {
        conn.execute("ALTER TABLE chats ADD COLUMN external_chat_id TEXT", [])?;
    }

    conn.execute(
        "UPDATE chats
         SET channel = CASE
             WHEN chat_type LIKE 'telegram_%' THEN 'telegram'
             WHEN chat_type IN ('private', 'group', 'supergroup', 'channel') THEN 'telegram'
             WHEN chat_type = 'discord' THEN 'discord'
             WHEN chat_type = 'web' THEN 'web'
             ELSE COALESCE(channel, 'unknown')
         END
         WHERE channel IS NULL OR trim(channel) = ''",
        [],
    )?;
    conn.execute(
        "UPDATE chats
         SET external_chat_id = CAST(chat_id AS TEXT)
         WHERE external_chat_id IS NULL OR trim(external_chat_id) = ''",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chats_channel_external
         ON chats(channel, external_chat_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chats_channel_title
         ON chats(channel, chat_title)",
        [],
    )?;
    Ok(())
}

fn ensure_sessions_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "sessions", "parent_session_key")? {
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN parent_session_key TEXT",
            [],
        )?;
    }
    if !table_has_column(conn, "sessions", "fork_point")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN fork_point INTEGER", [])?;
    }
    if !table_has_column(conn, "sessions", "label")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN label TEXT", [])?;
    }
    if !table_has_column(conn, "sessions", "thinking_level")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN thinking_level TEXT", [])?;
    }
    if !table_has_column(conn, "sessions", "verbose_level")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN verbose_level TEXT", [])?;
    }
    if !table_has_column(conn, "sessions", "reasoning_level")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN reasoning_level TEXT", [])?;
    }
    if table_has_column(conn, "sessions", "parent_session_key")? {
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_parent_session_key
             ON sessions(parent_session_key)",
            [],
        )?;
    }
    Ok(())
}

fn ensure_scheduled_tasks_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "scheduled_tasks", "exit_criteria")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN exit_criteria TEXT",
            [],
        )?;
    }
    if !table_has_column(conn, "scheduled_tasks", "run_count")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN run_count INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !table_has_column(conn, "scheduled_tasks", "max_runs")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN max_runs INTEGER",
            [],
        )?;
    }
    if !table_has_column(conn, "scheduled_tasks", "not_after")? {
        conn.execute("ALTER TABLE scheduled_tasks ADD COLUMN not_after TEXT", [])?;
    }
    if !table_has_column(conn, "scheduled_tasks", "timezone")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN timezone TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

fn get_schema_version(conn: &Connection) -> Result<i64, MicroClawError> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )?;
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM db_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0))
}

fn set_schema_version(conn: &Connection, version: i64) -> Result<(), MicroClawError> {
    conn.execute(
        "INSERT INTO db_meta(key, value) VALUES('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![version.to_string()],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            note TEXT
        )",
        [],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO schema_migrations(version, applied_at, note)
         VALUES(?1, ?2, ?3)",
        params![version, chrono::Utc::now().to_rfc3339(), "applied"],
    )?;
    Ok(())
}

fn apply_schema_migrations(conn: &Connection) -> Result<(), MicroClawError> {
    let mut version = get_schema_version(conn)?;
    if version < 1 {
        set_schema_version(conn, 1)?;
        version = 1;
    }
    if version < 2 {
        ensure_chat_identity_schema(conn)?;
        ensure_memory_schema(conn)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_active_updated ON memories(is_archived, updated_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_confidence ON memories(confidence)",
            [],
        )?;
        set_schema_version(conn, 2)?;
        version = 2;
    }
    if version < 3 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_reflector_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                extracted_count INTEGER NOT NULL DEFAULT 0,
                inserted_count INTEGER NOT NULL DEFAULT 0,
                updated_count INTEGER NOT NULL DEFAULT 0,
                skipped_count INTEGER NOT NULL DEFAULT 0,
                dedup_method TEXT NOT NULL,
                parse_ok INTEGER NOT NULL DEFAULT 1,
                error_text TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_memory_reflector_runs_chat_started
                ON memory_reflector_runs(chat_id, started_at);
            CREATE TABLE IF NOT EXISTS memory_injection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                retrieval_method TEXT NOT NULL,
                candidate_count INTEGER NOT NULL DEFAULT 0,
                selected_count INTEGER NOT NULL DEFAULT 0,
                omitted_count INTEGER NOT NULL DEFAULT 0,
                tokens_est INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_memory_injection_logs_chat_created
                ON memory_injection_logs(chat_id, created_at);",
        )?;
        set_schema_version(conn, 3)?;
        version = 3;
    }
    if version < 4 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_supersede_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_memory_id INTEGER NOT NULL,
                to_memory_id INTEGER NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_memory_supersede_from
                ON memory_supersede_edges(from_memory_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_memory_supersede_to
                ON memory_supersede_edges(to_memory_id, created_at);",
        )?;
        set_schema_version(conn, 4)?;
        version = 4;
    }
    if version < 5 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS auth_passwords (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                session_id TEXT PRIMARY KEY,
                label TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                last_used_at TEXT,
                expires_at TEXT,
                rotated_from_key_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS api_key_scopes (
                api_key_id INTEGER NOT NULL,
                scope TEXT NOT NULL,
                PRIMARY KEY (api_key_id, scope)
            );
            CREATE INDEX IF NOT EXISTS idx_api_key_scopes_scope ON api_key_scopes(scope);",
        )?;
        set_schema_version(conn, 5)?;
        version = 5;
    }
    if version < 6 {
        ensure_sessions_schema(conn)?;
        set_schema_version(conn, 6)?;
        version = 6;
    }
    if version < 7 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metrics_history (
                timestamp_ms INTEGER PRIMARY KEY,
                llm_completions INTEGER NOT NULL DEFAULT 0,
                llm_input_tokens INTEGER NOT NULL DEFAULT 0,
                llm_output_tokens INTEGER NOT NULL DEFAULT 0,
                http_requests INTEGER NOT NULL DEFAULT 0,
                tool_executions INTEGER NOT NULL DEFAULT 0,
                mcp_calls INTEGER NOT NULL DEFAULT 0,
                mcp_rate_limited_rejections INTEGER NOT NULL DEFAULT 0,
                mcp_bulkhead_rejections INTEGER NOT NULL DEFAULT 0,
                mcp_circuit_open_rejections INTEGER NOT NULL DEFAULT 0,
                active_sessions INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp_ms);",
        )?;
        set_schema_version(conn, 7)?;
        version = 7;
    }
    if version < 8 {
        if !table_has_column(conn, "api_keys", "expires_at")? {
            conn.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT", [])?;
        }
        if !table_has_column(conn, "api_keys", "rotated_from_key_id")? {
            conn.execute(
                "ALTER TABLE api_keys ADD COLUMN rotated_from_key_id INTEGER",
                [],
            )?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_logs_kind_created
                ON audit_logs(kind, created_at DESC);",
        )?;
        set_schema_version(conn, 8)?;
        version = 8;
    }
    if version < 9 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scheduled_task_dlq (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                failed_at TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                error_summary TEXT,
                replayed_at TEXT,
                replay_note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scheduled_task_dlq_task_failed
                ON scheduled_task_dlq(task_id, failed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scheduled_task_dlq_chat_failed
                ON scheduled_task_dlq(chat_id, failed_at DESC);",
        )?;
        set_schema_version(conn, 9)?;
        version = 9;
    }
    if version < 10 {
        if !table_has_column(conn, "metrics_history", "mcp_rate_limited_rejections")? {
            conn.execute(
                "ALTER TABLE metrics_history ADD COLUMN mcp_rate_limited_rejections INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "metrics_history", "mcp_bulkhead_rejections")? {
            conn.execute(
                "ALTER TABLE metrics_history ADD COLUMN mcp_bulkhead_rejections INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "metrics_history", "mcp_circuit_open_rejections")? {
            conn.execute(
                "ALTER TABLE metrics_history ADD COLUMN mcp_circuit_open_rejections INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        set_schema_version(conn, 10)?;
        version = 10;
    }
    if version < 11 {
        if !table_has_column(conn, "sessions", "skill_envs_json")? {
            conn.execute("ALTER TABLE sessions ADD COLUMN skill_envs_json TEXT", [])?;
        }
        set_schema_version(conn, 11)?;
        version = 11;
    }
    if version < 12 {
        ensure_scheduled_tasks_schema(conn)?;
        set_schema_version(conn, 12)?;
        version = 12;
    }
    if version < 13 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_runs (
                run_id TEXT PRIMARY KEY,
                parent_run_id TEXT,
                depth INTEGER NOT NULL DEFAULT 1,
                chat_id INTEGER NOT NULL,
                caller_channel TEXT NOT NULL,
                task TEXT NOT NULL,
                context TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                error_text TEXT,
                result_text TEXT,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                provider TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_subagent_runs_chat_created
                ON subagent_runs(chat_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_subagent_runs_chat_status
                ON subagent_runs(chat_id, status);
            CREATE INDEX IF NOT EXISTS idx_subagent_runs_parent_status
                ON subagent_runs(parent_run_id, status);",
        )?;
        set_schema_version(conn, 13)?;
        version = 13;
    }
    if version < 14 {
        if !table_has_column(conn, "subagent_runs", "parent_run_id")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN parent_run_id TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "subagent_runs", "depth")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN depth INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_subagent_runs_parent_status
             ON subagent_runs(parent_run_id, status)",
            [],
        )?;
        set_schema_version(conn, 14)?;
        version = 14;
    }
    if version < 15 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_announces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL UNIQUE,
                chat_id INTEGER NOT NULL,
                caller_channel TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subagent_announces_status_next
                ON subagent_announces(status, next_attempt_at);",
        )?;
        set_schema_version(conn, 15)?;
        version = 15;
    }
    if version < 16 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subagent_events_run_created
                ON subagent_events(run_id, created_at ASC);",
        )?;
        set_schema_version(conn, 16)?;
        version = 16;
    }
    if version < 17 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_focus_bindings (
                chat_id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;
        set_schema_version(conn, 17)?;
        version = 17;
    }
    if version < 18 {
        if !table_has_column(conn, "subagent_runs", "token_budget")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN token_budget INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "subagent_runs", "artifact_json")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN artifact_json TEXT",
                [],
            )?;
        }
        set_schema_version(conn, 18)?;
        version = 18;
    }
    if version < 19 {
        ensure_sessions_schema(conn)?;
        set_schema_version(conn, 19)?;
        version = 19;
    }
    if version < 20 {
        // Temporal knowledge graph: add valid_from/valid_to to memories + knowledge_graph table
        if !table_has_column(conn, "memories", "valid_from")? {
            conn.execute("ALTER TABLE memories ADD COLUMN valid_from TEXT", [])?;
        }
        if !table_has_column(conn, "memories", "valid_to")? {
            conn.execute("ALTER TABLE memories ADD COLUMN valid_to TEXT", [])?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS knowledge_graph (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object TEXT NOT NULL,
                chat_id INTEGER,
                valid_from TEXT NOT NULL,
                valid_to TEXT,
                confidence REAL NOT NULL DEFAULT 0.70,
                source TEXT NOT NULL DEFAULT 'reflector',
                source_memory_id INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kg_subject ON knowledge_graph(subject);
            CREATE INDEX IF NOT EXISTS idx_kg_object ON knowledge_graph(object);
            CREATE INDEX IF NOT EXISTS idx_kg_predicate ON knowledge_graph(predicate);
            CREATE INDEX IF NOT EXISTS idx_kg_chat ON knowledge_graph(chat_id);
            CREATE INDEX IF NOT EXISTS idx_kg_valid_range ON knowledge_graph(valid_from, valid_to);",
        )?;
        set_schema_version(conn, 20)?;
        version = 20;
    }
    if version < 21 {
        // Session search: FTS5 virtual table over messages, with triggers to
        // keep it in sync on INSERT/UPDATE/DELETE. The table is created as
        // contentless (`content=''`) to avoid duplicating text on disk; we
        // manually keep it in sync via triggers rather than rely on the
        // external-content mode so that deletions of individual messages are
        // still cleanly reflected.
        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                content,
                sender_name,
                chat_id UNINDEXED,
                message_id UNINDEXED,
                timestamp UNINDEXED,
                is_from_bot UNINDEXED,
                tokenize = 'unicode61 remove_diacritics 2'
            );",
        )?;
        // Backfill existing messages into the FTS index. rowid pattern uses
        // a composite of chat_id and message_id to stay unique.
        conn.execute_batch(
            "INSERT INTO messages_fts(content, sender_name, chat_id, message_id, timestamp, is_from_bot)
             SELECT content, sender_name, chat_id, id, timestamp, is_from_bot FROM messages;",
        )?;
        conn.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(content, sender_name, chat_id, message_id, timestamp, is_from_bot)
                VALUES (new.content, new.sender_name, new.chat_id, new.id, new.timestamp, new.is_from_bot);
            END;
            CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages BEGIN
                DELETE FROM messages_fts WHERE chat_id = old.chat_id AND message_id = old.id;
            END;
            CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE ON messages BEGIN
                DELETE FROM messages_fts WHERE chat_id = old.chat_id AND message_id = old.id;
                INSERT INTO messages_fts(content, sender_name, chat_id, message_id, timestamp, is_from_bot)
                VALUES (new.content, new.sender_name, new.chat_id, new.id, new.timestamp, new.is_from_bot);
            END;",
        )?;
        set_schema_version(conn, 21)?;
        version = 21;
    }
    if version < 22 {
        // Tool result cache — keyed by SHA-256 of (tool_name + normalized
        // input JSON). Tools opt in by name; rows are purged lazily via TTL.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tool_result_cache (
                cache_key TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL,
                result_content TEXT NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tool_result_cache_tool_expires
                ON tool_result_cache(tool_name, expires_at);
            CREATE INDEX IF NOT EXISTS idx_tool_result_cache_expires
                ON tool_result_cache(expires_at);",
        )?;
        set_schema_version(conn, 22)?;
        version = 22;
    }
    if version < 23 {
        // Tool result artifacts — full content stash for results that exceed
        // the in-context truncation threshold. The agent reads slices via
        // the `fetch_artifact` tool. Rows expire after a TTL to bound
        // storage growth.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tool_result_artifacts (
                artifact_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                content TEXT NOT NULL,
                total_chars INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tool_result_artifacts_chat
                ON tool_result_artifacts(chat_id, expires_at);
            CREATE INDEX IF NOT EXISTS idx_tool_result_artifacts_expires
                ON tool_result_artifacts(expires_at);",
        )?;
        set_schema_version(conn, 23)?;
        version = 23;
    }
    if version < 24 {
        // Memory TTL: per-row expiration for time-bounded facts (NULL = never).
        // Distinct from `valid_to` (knowledge-graph temporal validity) and
        // `is_archived` (manual demotion).
        if !table_has_column(conn, "memories", "expires_at")? {
            conn.execute("ALTER TABLE memories ADD COLUMN expires_at TEXT", [])?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_expires ON memories(expires_at)
             WHERE expires_at IS NOT NULL",
            [],
        )?;
        set_schema_version(conn, 24)?;
        version = 24;
    }
    if version < 25 {
        // Skill activation log — drives the auto-archive of agent-created
        // skills that haven't been used in N days, and surfaces usage
        // counts in the insights tool.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_activation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                chat_id INTEGER,
                activated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_skill_activation_name_time
                ON skill_activation_logs(skill_name, activated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_skill_activation_time
                ON skill_activation_logs(activated_at);",
        )?;
        set_schema_version(conn, 25)?;
        version = 25;
    }
    if version < 26 {
        // Named, progress-reporting sub-agent runs: a human-friendly `label`
        // for "what am I working on", plus the latest progress snapshot pushed
        // by the `report_progress` tool during a long run.
        if !table_has_column(conn, "subagent_runs", "label")? {
            conn.execute("ALTER TABLE subagent_runs ADD COLUMN label TEXT", [])?;
        }
        if !table_has_column(conn, "subagent_runs", "progress_text")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN progress_text TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "subagent_runs", "last_progress_at")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN last_progress_at TEXT",
                [],
            )?;
        }
        set_schema_version(conn, 26)?;
        version = 26;
    }
    if version < 27 {
        // Tamper-evident audit log: each new entry is sealed into a SHA-256 hash
        // chain (`entry_hash` over the entry's fields plus the previous entry's
        // `entry_hash`). Existing pre-migration rows stay unsealed (NULL) and are
        // simply not part of the verifiable chain.
        if !table_has_column(conn, "audit_logs", "prev_hash")? {
            conn.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT", [])?;
        }
        if !table_has_column(conn, "audit_logs", "entry_hash")? {
            conn.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT", [])?;
        }
        set_schema_version(conn, 27)?;
        version = 27;
    }
    if version < 28 {
        // Interrupted-turn recovery: one row per interactive turn in flight.
        // Inserted when the agent loop starts a user-facing turn, deleted when
        // the turn finishes (any outcome). Rows found at startup mean the
        // process died mid-reply — those chats get an "I was interrupted"
        // notice and the rows are cleared.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS active_turns (
                chat_id INTEGER PRIMARY KEY,
                channel TEXT NOT NULL,
                started_at TEXT NOT NULL
            );",
        )?;
        set_schema_version(conn, 28)?;
        version = 28;
    }
    if version < 29 {
        // Delivery outbox: final agent replies that failed to send are queued
        // here and retried with backoff by a supervised background loop, so a
        // transient channel outage can't silently drop a finished answer.
        // Also: `active_turns.progress_text` — a rolling "step N: tool, tool"
        // snapshot so the interrupted-turn notice can say how far the run got.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_outbox_status_next
                ON outbox_messages(status, next_attempt_at);",
        )?;
        if !table_has_column(conn, "active_turns", "progress_text")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN progress_text TEXT", [])?;
        }
        set_schema_version(conn, 29)?;
        version = 29;
    }
    if version < 30 {
        // Durable chunk delivery ledger. The parent row represents one
        // user-visible message; child rows are independently retryable chunks
        // with stable idempotency keys. Legacy whole-message outbox rows are
        // migrated as single-chunk deliveries.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbound_deliveries (
                delivery_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                full_payload_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                stored_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbound_delivery_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                payload_text TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(delivery_id, chunk_index),
                UNIQUE(idempotency_key),
                FOREIGN KEY(delivery_id) REFERENCES outbound_deliveries(delivery_id)
            );
            CREATE INDEX IF NOT EXISTS idx_delivery_chunks_status_next
                ON outbound_delivery_chunks(status, next_attempt_at);
            INSERT OR IGNORE INTO outbound_deliveries(
                delivery_id, chat_id, channel, full_payload_text, status,
                stored_at, created_at, updated_at
            )
            SELECT 'legacy-' || id, chat_id, channel, payload_text,
                   CASE WHEN status = 'delivered' THEN 'delivered'
                        WHEN status = 'failed' THEN 'failed' ELSE 'pending' END,
                   CASE WHEN status = 'delivered' THEN updated_at ELSE NULL END,
                   created_at, updated_at
            FROM outbox_messages;
            INSERT OR IGNORE INTO outbound_delivery_chunks(
                delivery_id, chunk_index, total_chunks, payload_text,
                idempotency_key, status, attempts, next_attempt_at,
                last_error, created_at, updated_at
            )
            SELECT 'legacy-' || id, 0, 1, payload_text, 'legacy-' || id,
                   status, attempts, next_attempt_at, last_error,
                   created_at, updated_at
            FROM outbox_messages;",
        )?;
        set_schema_version(conn, 30)?;
        version = 30;
    }
    if version < 31 {
        // Durable interactive-run checkpoints. The session snapshot is only
        // marked resumable at boundaries where no tool side effect is in an
        // unknown state. During tool execution the row remains inspectable,
        // but startup recovery stops with evidence instead of replaying it.
        if !table_has_column(conn, "active_turns", "chat_type")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN chat_type TEXT NOT NULL DEFAULT 'private'",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "phase")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN phase TEXT NOT NULL DEFAULT 'starting'",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "iteration")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN iteration INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "session_json")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN session_json TEXT", [])?;
        }
        if !table_has_column(conn, "active_turns", "resumable")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN resumable INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "tool_summary")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN tool_summary TEXT", [])?;
        }
        if !table_has_column(conn, "active_turns", "last_checkpoint_at")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN last_checkpoint_at TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "run_id")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN run_id TEXT", [])?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_active_turns_checkpoint
             ON active_turns(resumable, last_checkpoint_at)",
            [],
        )?;
        set_schema_version(conn, 31)?;
        version = 31;
    }
    if version < 32 {
        // Long-horizon learning substrate. Facts remain in `memories`; these
        // tables track goals, task experience, verification evidence, and the
        // governed lifecycle of procedural skills.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS goal_states (
                goal_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                objective TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                constraints_json TEXT,
                progress_json TEXT,
                budget_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_goal_states_chat_status
                ON goal_states(chat_id, status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS experience_runs (
                run_id TEXT PRIMARY KEY,
                goal_id TEXT,
                chat_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                run_kind TEXT NOT NULL,
                objective TEXT NOT NULL,
                environment_fingerprint TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                result_summary TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_ms INTEGER,
                FOREIGN KEY(goal_id) REFERENCES goal_states(goal_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_runs_chat_started
                ON experience_runs(chat_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_experience_runs_goal_started
                ON experience_runs(goal_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_experience_runs_status
                ON experience_runs(status, started_at DESC);

            CREATE TABLE IF NOT EXISTS verifier_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                verifier_type TEXT NOT NULL,
                verifier_name TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                scope TEXT,
                verified_at TEXT NOT NULL,
                valid_until TEXT,
                UNIQUE(run_id, verifier_type, verifier_name),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_verifier_results_run
                ON verifier_results(run_id, verified_at DESC);

            CREATE TABLE IF NOT EXISTS skill_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(skill_name, version)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_versions_name_version
                ON skill_versions(skill_name, version DESC);

            CREATE TABLE IF NOT EXISTS skill_lifecycle (
                skill_name TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                active_version INTEGER NOT NULL,
                previous_trusted_version INTEGER,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                state_reason TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_skill_lifecycle_state
                ON skill_lifecycle(state, updated_at DESC);

            CREATE TABLE IF NOT EXISTS skill_lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                version INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_skill_lifecycle_events_name
                ON skill_lifecycle_events(skill_name, created_at DESC);

            CREATE TABLE IF NOT EXISTS skill_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                skill_version INTEGER NOT NULL,
                run_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                verifier_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, run_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_outcomes_name_created
                ON skill_outcomes(skill_name, created_at DESC);",
        )?;
        if !table_has_column(conn, "skill_activation_logs", "experience_run_id")? {
            conn.execute(
                "ALTER TABLE skill_activation_logs ADD COLUMN experience_run_id TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "skill_activation_logs", "skill_version")? {
            conn.execute(
                "ALTER TABLE skill_activation_logs ADD COLUMN skill_version INTEGER",
                [],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_skill_activation_experience
             ON skill_activation_logs(experience_run_id)",
            [],
        )?;
        set_schema_version(conn, 32)?;
        version = 32;
    }
    if version < 33 {
        for (column, definition) in [
            ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
            ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
            ("llm_requests", "INTEGER NOT NULL DEFAULT 0"),
            ("tool_calls", "INTEGER NOT NULL DEFAULT 0"),
            ("tool_errors", "INTEGER NOT NULL DEFAULT 0"),
            ("estimated_cost_usd", "REAL"),
        ] {
            if !table_has_column(conn, "experience_runs", column)? {
                conn.execute(
                    &format!("ALTER TABLE experience_runs ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        set_schema_version(conn, 33)?;
        version = 33;
    }
    if version < 34 {
        if !table_has_column(conn, "skill_outcomes", "verifier_name")? {
            conn.execute(
                "ALTER TABLE skill_outcomes ADD COLUMN verifier_name TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "skill_outcomes", "valid_until")? {
            conn.execute("ALTER TABLE skill_outcomes ADD COLUMN valid_until TEXT", [])?;
        }
        set_schema_version(conn, 34)?;
        version = 34;
    }
    if version < 35 {
        if !table_has_column(conn, "skill_outcomes", "attribution_confidence")? {
            conn.execute(
                "ALTER TABLE skill_outcomes
                 ADD COLUMN attribution_confidence REAL NOT NULL DEFAULT 1.0",
                [],
            )?;
        }
        set_schema_version(conn, 35)?;
        version = 35;
    }
    if version < 36 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_governance_policy (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                candidate_failures_to_degrade INTEGER NOT NULL,
                trial_min_outcomes INTEGER NOT NULL,
                trial_promote_rate REAL NOT NULL,
                trial_degrade_rate REAL NOT NULL,
                trusted_min_outcomes INTEGER NOT NULL,
                trusted_degrade_rate REAL NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;
        let policy = SkillGovernancePolicy::default();
        conn.execute(
            "INSERT OR IGNORE INTO skill_governance_policy(
                singleton_id, candidate_failures_to_degrade, trial_min_outcomes,
                trial_promote_rate, trial_degrade_rate, trusted_min_outcomes,
                trusted_degrade_rate, updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                policy.candidate_failures_to_degrade,
                policy.trial_min_outcomes,
                policy.trial_promote_rate,
                policy.trial_degrade_rate,
                policy.trusted_min_outcomes,
                policy.trusted_degrade_rate,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        set_schema_version(conn, 36)?;
        version = 36;
    }
    if version < 37 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outcome_envelopes (
                envelope_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                run_id TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                source_name TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                scope TEXT,
                valid_until TEXT,
                payload_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_outcome_envelopes_run_created
                ON outcome_envelopes(run_id, created_at ASC);

            CREATE TABLE IF NOT EXISTS experience_feedback (
                feedback_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                scope TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                valid_until TEXT,
                PRIMARY KEY(run_id, actor, feedback_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_feedback_run_updated
                ON experience_feedback(run_id, updated_at DESC);

            CREATE TABLE IF NOT EXISTS experience_retrieval_logs (
                querying_run_id TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                rank INTEGER NOT NULL,
                selection_reason TEXT NOT NULL,
                relevance_score REAL NOT NULL,
                injected_at TEXT NOT NULL,
                PRIMARY KEY(querying_run_id, source_run_id),
                FOREIGN KEY(querying_run_id) REFERENCES experience_runs(run_id),
                FOREIGN KEY(source_run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_retrieval_query_rank
                ON experience_retrieval_logs(querying_run_id, rank ASC);

            INSERT OR IGNORE INTO outcome_envelopes(
                envelope_id, schema_version, run_id, source_kind, source_name,
                verdict, confidence, evidence, scope, valid_until, payload_json,
                created_at
            )
            SELECT 'legacy-verifier:' || id, 1, run_id, verifier_type,
                   verifier_name, verdict, confidence, evidence, scope,
                   valid_until, '{}', verified_at
            FROM verifier_results;

            INSERT OR IGNORE INTO experience_feedback(
                feedback_id, run_id, actor, verdict, confidence, evidence,
                scope, created_at, updated_at, valid_until
            )
            SELECT verifier_name, run_id, 'legacy', verdict, confidence,
                   evidence, scope, verified_at, verified_at, valid_until
            FROM verifier_results
            WHERE verifier_type='human';",
        )?;
        set_schema_version(conn, 37)?;
        version = 37;
    }
    if version < 38 {
        for (column, definition) in [
            ("task_signature_version", "INTEGER NOT NULL DEFAULT 1"),
            ("task_type", "TEXT NOT NULL DEFAULT 'general'"),
            ("task_family", "TEXT NOT NULL DEFAULT 'general_assistance'"),
            ("capability_tags_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("task_signature_hash", "TEXT NOT NULL DEFAULT ''"),
        ] {
            if !table_has_column(conn, "experience_runs", column)? {
                conn.execute(
                    &format!("ALTER TABLE experience_runs ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        if !table_has_column(conn, "skill_governance_policy", "utility_confidence_z")? {
            conn.execute(
                "ALTER TABLE skill_governance_policy
                 ADD COLUMN utility_confidence_z REAL NOT NULL DEFAULT 1.96",
                [],
            )?;
        }
        if !table_has_column(
            conn,
            "skill_governance_policy",
            "trial_promote_utility_lower_bound",
        )? {
            conn.execute(
                "ALTER TABLE skill_governance_policy
                 ADD COLUMN trial_promote_utility_lower_bound REAL NOT NULL DEFAULT 0.4",
                [],
            )?;
        }
        let mut stmt = conn.prepare(
            "SELECT run_id, objective, run_kind FROM experience_runs
             WHERE task_signature_hash=''",
        )?;
        let existing = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for (run_id, objective, run_kind) in existing {
            let signature = derive_task_signature(&objective, &run_kind);
            conn.execute(
                "UPDATE experience_runs SET task_signature_version=?2,
                    task_type=?3, task_family=?4, capability_tags_json=?5,
                    task_signature_hash=?6 WHERE run_id=?1",
                params![
                    run_id,
                    signature.version,
                    signature.task_type,
                    signature.task_family,
                    serde_json::to_string(&signature.capability_tags)
                        .unwrap_or_else(|_| "[]".into()),
                    signature.signature_hash
                ],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_experience_runs_task_signature
             ON experience_runs(task_type, task_family, started_at DESC)",
            [],
        )?;
        set_schema_version(conn, 38)?;
        version = 38;
    }
    if version < 39 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_failure_patterns (
                pattern_id TEXT PRIMARY KEY,
                skill_name TEXT NOT NULL,
                skill_version INTEGER NOT NULL,
                task_type TEXT NOT NULL,
                task_family TEXT NOT NULL,
                environment_fingerprint TEXT,
                tool_name TEXT,
                error_category TEXT NOT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0,
                recovery_successes INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'observed',
                cooldown_until TEXT,
                last_evidence TEXT,
                first_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, skill_version, task_family,
                       environment_fingerprint, tool_name, error_category)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_failure_patterns_lookup
                ON skill_failure_patterns(
                    skill_name, skill_version, task_family, state, updated_at DESC
                );
            CREATE TABLE IF NOT EXISTS skill_failure_pattern_evidence (
                pattern_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(pattern_id, run_id),
                FOREIGN KEY(pattern_id) REFERENCES skill_failure_patterns(pattern_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS experience_retrieval_rejections (
                querying_run_id TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                rejection_reason TEXT NOT NULL,
                relevance_score REAL NOT NULL,
                rejected_at TEXT NOT NULL,
                PRIMARY KEY(querying_run_id, source_run_id),
                FOREIGN KEY(querying_run_id) REFERENCES experience_runs(run_id),
                FOREIGN KEY(source_run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_rejection_query
                ON experience_retrieval_rejections(querying_run_id, rejected_at ASC);",
        )?;
        for (column, definition) in [
            ("failure_pattern_min_failures", "INTEGER NOT NULL DEFAULT 2"),
            (
                "failure_pattern_cooldown_hours",
                "INTEGER NOT NULL DEFAULT 24",
            ),
            (
                "failure_pattern_recovery_successes",
                "INTEGER NOT NULL DEFAULT 2",
            ),
        ] {
            if !table_has_column(conn, "skill_governance_policy", column)? {
                conn.execute(
                    &format!(
                        "ALTER TABLE skill_governance_policy ADD COLUMN {column} {definition}"
                    ),
                    [],
                )?;
            }
        }
        let policy = SkillGovernancePolicy::default();
        let historical = {
            let mut stmt = conn.prepare(
                "SELECT o.skill_name, o.skill_version, o.run_id,
                        r.task_type, r.task_family, r.environment_fingerprint,
                        json_extract(e.payload_json, '$.tool_name'),
                        COALESCE(e.evidence, o.evidence)
                 FROM skill_outcomes o
                 JOIN experience_runs r ON r.run_id=o.run_id
                 LEFT JOIN outcome_envelopes e ON e.run_id=o.run_id
                    AND e.verdict='failed' AND e.scope='tool_result'
                 WHERE o.verdict='failed'
                   AND o.attribution_confidence >= 0.999
                   AND o.verifier_type IN (
                     'deterministic','environmental','human','rule_based'
                   )
                   AND (o.valid_until IS NULL OR o.valid_until>?1)
                 ORDER BY o.created_at ASC",
            )?;
            let rows = stmt
                .query_map(params![chrono::Utc::now().to_rfc3339()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let now = chrono::Utc::now();
        let cooldown_until =
            (now + chrono::Duration::hours(policy.failure_pattern_cooldown_hours)).to_rfc3339();
        for (
            skill_name,
            skill_version,
            run_id,
            task_type,
            task_family,
            environment,
            tool_name,
            evidence,
        ) in historical
        {
            let category = classify_failure_category(evidence.as_deref());
            let canonical = format!(
                "{skill_name}\n{skill_version}\n{task_family}\n{}\n{}\n{category}",
                environment.as_deref().unwrap_or(""),
                tool_name.as_deref().unwrap_or("")
            );
            use sha2::{Digest, Sha256};
            let pattern_id = to_hex(&Sha256::digest(canonical.as_bytes()));
            conn.execute(
                "INSERT INTO skill_failure_patterns(
                    pattern_id, skill_name, skill_version, task_type, task_family,
                    environment_fingerprint, tool_name, error_category,
                    failure_count, recovery_successes, state, cooldown_until,
                    last_evidence, first_seen_at, updated_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,0,'observed',NULL,?9,?10,?10)
                 ON CONFLICT(pattern_id) DO UPDATE SET
                    last_evidence=excluded.last_evidence,
                    updated_at=excluded.updated_at",
                params![
                    pattern_id,
                    skill_name,
                    skill_version,
                    task_type,
                    task_family,
                    environment,
                    tool_name,
                    category,
                    evidence,
                    now.to_rfc3339()
                ],
            )?;
            if conn.execute(
                "INSERT OR IGNORE INTO skill_failure_pattern_evidence(
                    pattern_id, run_id, verdict, created_at
                 ) VALUES (?1,?2,'failed',?3)",
                params![pattern_id, run_id, now.to_rfc3339()],
            )? > 0
            {
                conn.execute(
                    "UPDATE skill_failure_patterns
                     SET failure_count=failure_count+1,
                         state=CASE WHEN failure_count+1>=?2
                                    THEN 'active' ELSE 'observed' END,
                         cooldown_until=CASE WHEN failure_count+1>=?2
                                    THEN ?3 ELSE NULL END,
                         updated_at=?4 WHERE pattern_id=?1",
                    params![
                        pattern_id,
                        policy.failure_pattern_min_failures,
                        cooldown_until,
                        now.to_rfc3339()
                    ],
                )?;
            }
        }
        conn.execute(
            "UPDATE skill_lifecycle
             SET previous_trusted_version=CASE WHEN state='trusted'
                    THEN active_version ELSE previous_trusted_version END,
                 state='degraded',
                 state_reason='historical active failure pattern backfilled',
                 updated_at=?1
             WHERE state NOT IN ('degraded','archived') AND EXISTS(
               SELECT 1 FROM skill_failure_patterns p
               WHERE p.skill_name=skill_lifecycle.skill_name
                 AND p.skill_version=skill_lifecycle.active_version
                 AND p.state='active'
             )",
            params![now.to_rfc3339()],
        )?;
        set_schema_version(conn, 39)?;
        version = 39;
    }
    if version < 40 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS experience_comparisons (
                comparison_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                skill_name TEXT NOT NULL,
                skill_version INTEGER NOT NULL,
                task_type TEXT NOT NULL,
                task_family TEXT NOT NULL,
                environment_fingerprint TEXT,
                success_run_id TEXT NOT NULL,
                failure_run_id TEXT NOT NULL,
                minimal_difference TEXT NOT NULL,
                counterexample TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(chat_id, skill_name, skill_version, task_family,
                       environment_fingerprint, success_run_id, failure_run_id),
                FOREIGN KEY(success_run_id) REFERENCES experience_runs(run_id),
                FOREIGN KEY(failure_run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_comparisons_skill
                ON experience_comparisons(skill_name, skill_version, created_at DESC);

            CREATE TABLE IF NOT EXISTS learning_claims (
                claim_id TEXT PRIMARY KEY,
                comparison_id TEXT NOT NULL,
                skill_name TEXT NOT NULL,
                base_version INTEGER NOT NULL,
                claim_version INTEGER NOT NULL,
                statement TEXT NOT NULL,
                applicability_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                counterexamples_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'candidate',
                supersedes_claim_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, claim_version),
                FOREIGN KEY(comparison_id) REFERENCES experience_comparisons(comparison_id),
                FOREIGN KEY(supersedes_claim_id) REFERENCES learning_claims(claim_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_claims_skill_status
                ON learning_claims(skill_name, status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS skill_candidates (
                candidate_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                skill_name TEXT NOT NULL,
                base_version INTEGER NOT NULL,
                candidate_version INTEGER NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'candidate',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, candidate_version),
                FOREIGN KEY(claim_id) REFERENCES learning_claims(claim_id)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_candidates_status
                ON skill_candidates(status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS shadow_observations (
                candidate_id TEXT NOT NULL,
                pair_key TEXT NOT NULL,
                arm TEXT NOT NULL,
                run_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                cost_usd REAL NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                evidence TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY(candidate_id, pair_key, arm),
                FOREIGN KEY(candidate_id) REFERENCES skill_candidates(candidate_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_shadow_observations_candidate
                ON shadow_observations(candidate_id, pair_key, arm);

            CREATE TABLE IF NOT EXISTS shadow_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE,
                sample_count INTEGER NOT NULL,
                baseline_passed INTEGER NOT NULL,
                candidate_passed INTEGER NOT NULL,
                baseline_utility_lower_bound REAL NOT NULL,
                candidate_utility_lower_bound REAL NOT NULL,
                baseline_cost_usd REAL NOT NULL,
                candidate_cost_usd REAL NOT NULL,
                baseline_duration_ms INTEGER NOT NULL,
                candidate_duration_ms INTEGER NOT NULL,
                regression_count INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(candidate_id) REFERENCES skill_candidates(candidate_id)
            );

            CREATE TABLE IF NOT EXISTS learning_journal_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                undo_action TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_learning_journal_created
                ON learning_journal_events(created_at DESC);",
        )?;
        for (column, definition) in [
            ("shadow_min_samples", "INTEGER NOT NULL DEFAULT 3"),
            (
                "shadow_promote_utility_margin",
                "REAL NOT NULL DEFAULT 0.05",
            ),
            ("shadow_max_cost_ratio", "REAL NOT NULL DEFAULT 1.2"),
            ("shadow_max_regressions", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !table_has_column(conn, "skill_governance_policy", column)? {
                conn.execute(
                    &format!(
                        "ALTER TABLE skill_governance_policy ADD COLUMN {column} {definition}"
                    ),
                    [],
                )?;
            }
        }
        let tx = conn.unchecked_transaction()?;
        let run_ids = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT run_id FROM skill_outcomes
                 WHERE attribution_confidence>=0.999
                   AND verifier_type IN (
                     'deterministic','environmental','human','rule_based'
                   )
                 ORDER BY created_at ASC",
            )?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for run_id in run_ids {
            refresh_comparative_reflections_for_run(&tx, &run_id)?;
        }
        tx.commit()?;
        set_schema_version(conn, 40)?;
        version = 40;
    }
    if version < 41 {
        // Repair databases whose recorded schema version advanced despite an
        // incomplete historical scheduled_tasks migration or restore.
        ensure_scheduled_tasks_schema(conn)?;
        set_schema_version(conn, 41)?;
        version = 41;
    }
    if version < 42 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS learning_tracks (
                track_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                objective TEXT NOT NULL,
                directions_json TEXT NOT NULL DEFAULT '[]',
                allowed_sources_json TEXT NOT NULL DEFAULT '[]',
                schedule TEXT NOT NULL,
                timezone TEXT NOT NULL,
                token_budget INTEGER NOT NULL DEFAULT 80000,
                max_sources INTEGER NOT NULL DEFAULT 20,
                promotion_mode TEXT NOT NULL DEFAULT 'propose',
                status TEXT NOT NULL DEFAULT 'active',
                next_run TEXT NOT NULL,
                last_run TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(chat_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_tracks_due
                ON learning_tracks(status, next_run);

            CREATE TABLE IF NOT EXISTS learning_epochs (
                epoch_id TEXT PRIMARY KEY,
                track_id TEXT NOT NULL,
                experience_run_id TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                report TEXT,
                candidate_id TEXT,
                error TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(track_id) REFERENCES learning_tracks(track_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_epochs_track
                ON learning_epochs(track_id, started_at DESC);

            CREATE TABLE IF NOT EXISTS learning_track_candidates (
                candidate_id TEXT PRIMARY KEY,
                epoch_id TEXT NOT NULL UNIQUE,
                skill_name TEXT NOT NULL,
                description TEXT NOT NULL,
                instructions TEXT NOT NULL,
                sources_json TEXT NOT NULL DEFAULT '[]',
                tests_json TEXT NOT NULL DEFAULT '[]',
                risk TEXT NOT NULL DEFAULT 'low',
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(epoch_id) REFERENCES learning_epochs(epoch_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_track_candidates_status
                ON learning_track_candidates(status, updated_at DESC);",
        )?;
        set_schema_version(conn, 42)?;
        version = 42;
    }
    if version < 43 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS learning_candidate_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'running',
                sample_count INTEGER NOT NULL DEFAULT 0,
                baseline_passed INTEGER NOT NULL DEFAULT 0,
                candidate_passed INTEGER NOT NULL DEFAULT 0,
                regression_count INTEGER NOT NULL DEFAULT 0,
                baseline_tokens INTEGER NOT NULL DEFAULT 0,
                candidate_tokens INTEGER NOT NULL DEFAULT 0,
                baseline_duration_ms INTEGER NOT NULL DEFAULT 0,
                candidate_duration_ms INTEGER NOT NULL DEFAULT 0,
                reason TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(candidate_id) REFERENCES learning_track_candidates(candidate_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_candidate_evaluations_status
                ON learning_candidate_evaluations(status, started_at DESC);

            CREATE TABLE IF NOT EXISTS learning_candidate_trials (
                trial_id TEXT PRIMARY KEY,
                evaluation_id TEXT NOT NULL,
                test_name TEXT NOT NULL,
                baseline_passed INTEGER NOT NULL,
                candidate_passed INTEGER NOT NULL,
                baseline_tokens INTEGER NOT NULL DEFAULT 0,
                candidate_tokens INTEGER NOT NULL DEFAULT 0,
                baseline_duration_ms INTEGER NOT NULL DEFAULT 0,
                candidate_duration_ms INTEGER NOT NULL DEFAULT 0,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(evaluation_id) REFERENCES learning_candidate_evaluations(evaluation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_candidate_trials_evaluation
                ON learning_candidate_trials(evaluation_id, created_at);",
        )?;
        set_schema_version(conn, 43)?;
        version = 43;
    }
    if version != SCHEMA_VERSION_CURRENT {
        set_schema_version(conn, SCHEMA_VERSION_CURRENT)?;
    }
    Ok(())
}

/// Lowercase hex of a byte slice (avoids pulling in the `hex` crate).
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compute the sealing hash for an audit entry: SHA-256 over the previous
/// entry's hash followed by this entry's content fields, each `\x1f`-terminated
/// so field boundaries can't be ambiguous. The chain link in `prev_hash` makes
/// deletion or reordering detectable; covering every field makes in-place edits
/// detectable.
#[allow(clippy::too_many_arguments)]
fn audit_entry_hash(
    prev_hash: &str,
    kind: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    status: &str,
    detail: Option<&str>,
    created_at: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for field in [
        prev_hash,
        kind,
        actor,
        action,
        target.unwrap_or(""),
        status,
        detail.unwrap_or(""),
        created_at,
    ] {
        h.update(field.as_bytes());
        h.update([0x1f]);
    }
    to_hex(&h.finalize())
}

/// A sealed audit row as read for chain verification: id + content fields +
/// `prev_hash` + `entry_hash`.
type AuditChainRow = (
    i64,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
);

/// Result of verifying the audit hash chain.
#[derive(Debug, Clone)]
pub struct AuditChainStatus {
    /// Number of sealed (hash-bearing) entries inspected.
    pub sealed_entries: usize,
    /// Whether the chain is fully intact.
    pub intact: bool,
    /// The `id` of the first entry where verification failed, if any.
    pub broken_at: Option<i64>,
    /// Human-readable reason for the break, if any.
    pub reason: Option<String>,
}

fn verifier_priority(verifier_type: &str) -> i64 {
    match verifier_type {
        "deterministic" => 60,
        "environmental" => 50,
        "human" => 40,
        "rule_based" => 30,
        "model_based" => 20,
        "runtime" => 10,
        _ => 0,
    }
}

type VerifierCandidate = (String, String, String, f64, Option<String>, Option<String>);

fn verifier_can_govern_skill(verifier_type: &str) -> bool {
    matches!(
        verifier_type,
        "deterministic" | "environmental" | "human" | "rule_based"
    )
}

fn validate_outcome_envelope(envelope: &OutcomeEnvelopeV1) -> Result<(), MicroClawError> {
    if envelope.envelope_id.trim().is_empty()
        || envelope.envelope_id.len() > 256
        || envelope.run_id.trim().is_empty()
        || envelope.run_id.len() > 128
        || !matches!(envelope.verdict.as_str(), "passed" | "failed")
        || envelope.source_name.trim().is_empty()
        || envelope.source_name.len() > 256
        || !envelope.confidence.is_finite()
        || !(0.0..=1.0).contains(&envelope.confidence)
        || envelope
            .evidence
            .as_ref()
            .is_some_and(|value| value.len() > 64 * 1024)
        || envelope
            .scope
            .as_ref()
            .is_some_and(|value| value.len() > 512)
        || serde_json::to_vec(&envelope.payload)
            .map(|value| value.len() > 64 * 1024)
            .unwrap_or(true)
    {
        return Err(MicroClawError::ToolExecution(
            "invalid outcome envelope fields".into(),
        ));
    }
    if !matches!(
        envelope.source_kind.as_str(),
        "deterministic" | "environmental" | "human" | "rule_based" | "model_based" | "runtime"
    ) {
        return Err(MicroClawError::ToolExecution(format!(
            "unsupported outcome source kind: {}",
            envelope.source_kind
        )));
    }
    if let Some(valid_until) = &envelope.valid_until {
        chrono::DateTime::parse_from_rfc3339(valid_until).map_err(|_| {
            MicroClawError::ToolExecution("outcome valid_until must be an RFC3339 timestamp".into())
        })?;
    }
    if let Some(feedback) = &envelope.feedback {
        if envelope.source_kind != "human"
            || feedback.feedback_id.trim().is_empty()
            || feedback.feedback_id.len() > 256
            || feedback.actor.trim().is_empty()
            || feedback.actor.len() > 256
        {
            return Err(MicroClawError::ToolExecution(
                "invalid experience feedback identity".into(),
            ));
        }
    }
    Ok(())
}

fn validate_skill_governance_policy(policy: &SkillGovernancePolicy) -> Result<(), MicroClawError> {
    if policy.candidate_failures_to_degrade < 1
        || policy.trial_min_outcomes < 2
        || policy.trusted_min_outcomes < policy.trial_min_outcomes
        || !(0.0..=1.0).contains(&policy.trial_promote_rate)
        || !(0.0..=1.0).contains(&policy.trial_degrade_rate)
        || !(0.0..=1.0).contains(&policy.trusted_degrade_rate)
        || !(0.0..=1.0).contains(&policy.trial_promote_utility_lower_bound)
        || !policy.utility_confidence_z.is_finite()
        || !(0.0..=5.0).contains(&policy.utility_confidence_z)
        || policy.failure_pattern_min_failures < 1
        || policy.failure_pattern_cooldown_hours < 1
        || policy.failure_pattern_recovery_successes < 1
        || policy.shadow_min_samples < 1
        || !policy.shadow_promote_utility_margin.is_finite()
        || !(0.0..=1.0).contains(&policy.shadow_promote_utility_margin)
        || !policy.shadow_max_cost_ratio.is_finite()
        || policy.shadow_max_cost_ratio < 1.0
        || policy.shadow_max_regressions < 0
        || policy.trial_degrade_rate >= policy.trial_promote_rate
    {
        return Err(MicroClawError::ToolExecution(
            "invalid skill governance policy: counts, rates, confidence, or utility lower bound"
                .into(),
        ));
    }
    Ok(())
}

fn sync_skill_outcomes_for_run(tx: &Transaction<'_>, run_id: &str) -> Result<(), MicroClawError> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut verifier_stmt = tx.prepare(
        "SELECT verifier_type, verifier_name, verdict, confidence, evidence, valid_until
         FROM verifier_results
         WHERE run_id=?1 AND (valid_until IS NULL OR valid_until > ?2)",
    )?;
    let verifier_rows = verifier_stmt.query_map(params![run_id, now], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, f64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;
    let mut strongest: Vec<VerifierCandidate> = Vec::new();
    let mut strongest_priority = -1;
    for row in verifier_rows {
        let candidate = row?;
        let candidate_priority = verifier_priority(&candidate.0);
        if candidate_priority > strongest_priority {
            strongest.clear();
            strongest.push(candidate);
            strongest_priority = candidate_priority;
        } else if candidate_priority == strongest_priority {
            strongest.push(candidate);
        }
    }
    drop(verifier_stmt);
    if strongest.is_empty() {
        tx.execute(
            "DELETE FROM skill_outcomes WHERE run_id=?1",
            params![run_id],
        )?;
        return Ok(());
    }
    let verifier_type = strongest[0].0.clone();
    let (verifier_name, verdict, confidence, evidence) = if verifier_type == "human"
        && strongest.len() > 1
    {
        let passed_weight: f64 = strongest
            .iter()
            .filter(|result| result.2 == "passed")
            .map(|result| result.3)
            .sum();
        let failed_weight: f64 = strongest
            .iter()
            .filter(|result| result.2 == "failed")
            .map(|result| result.3)
            .sum();
        let total_weight = passed_weight + failed_weight;
        let verdict = if passed_weight > failed_weight {
            "passed"
        } else {
            "failed"
        };
        let confidence = if total_weight > 0.0 {
            passed_weight.max(failed_weight) / total_weight
        } else {
            0.0
        };
        (
            "human_consensus".to_string(),
            verdict.to_string(),
            confidence,
            Some(format!(
                "{} active human feedback item(s): passed_weight={passed_weight:.3}, failed_weight={failed_weight:.3}",
                strongest.len()
            )),
        )
    } else {
        // Independent deterministic/environmental/rule checks are
        // conjunctive: one failure is enough to reject the outcome.
        let selected = strongest
            .iter()
            .filter(|result| result.2 == "failed")
            .max_by(|left, right| left.3.total_cmp(&right.3))
            .or_else(|| {
                strongest
                    .iter()
                    .max_by(|left, right| left.3.total_cmp(&right.3))
            })
            .expect("strongest verifier group is non-empty");
        (
            selected.1.clone(),
            selected.2.clone(),
            selected.3,
            selected.4.clone(),
        )
    };
    let valid_until = strongest.iter().filter_map(|result| result.5.clone()).min();

    let mut activation_stmt = tx.prepare(
        "SELECT DISTINCT skill_name, COALESCE(skill_version, 0)
         FROM skill_activation_logs
         WHERE experience_run_id=?1",
    )?;
    let activation_rows = activation_stmt.query_map(params![run_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let activations = activation_rows.collect::<Result<Vec<_>, _>>()?;
    drop(activation_stmt);
    let attribution_confidence = if activations.is_empty() {
        0.0
    } else {
        1.0 / activations.len() as f64
    };
    for (skill_name, mut skill_version) in activations {
        if skill_version == 0 {
            skill_version = tx
                .query_row(
                    "SELECT active_version FROM skill_lifecycle WHERE skill_name=?1",
                    params![skill_name],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
        }
        if skill_version == 0 {
            continue;
        }
        tx.execute(
            "INSERT INTO skill_outcomes(
                skill_name, skill_version, run_id, verdict, verifier_type,
                verifier_name, confidence, evidence, valid_until,
                attribution_confidence, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
             ON CONFLICT(skill_name, run_id) DO UPDATE SET
                skill_version=excluded.skill_version,
                verdict=excluded.verdict,
                verifier_type=excluded.verifier_type,
                verifier_name=excluded.verifier_name,
                confidence=excluded.confidence,
                evidence=excluded.evidence,
                valid_until=excluded.valid_until,
                attribution_confidence=excluded.attribution_confidence,
                updated_at=excluded.updated_at",
            params![
                skill_name,
                skill_version,
                run_id,
                verdict,
                verifier_type,
                verifier_name,
                confidence,
                evidence,
                valid_until,
                attribution_confidence,
                now
            ],
        )?;
        // Runtime completion and model self-evaluation remain observable but
        // cannot promote, degrade, or contraindicate reusable behavior.
        if verifier_can_govern_skill(&verifier_type) && attribution_confidence >= 0.999 {
            evaluate_skill_lifecycle(tx, &skill_name, skill_version)?;
        }
    }
    Ok(())
}

fn classify_failure_category(evidence: Option<&str>) -> &'static str {
    let value = evidence.unwrap_or("").to_ascii_lowercase();
    if value.contains("timeout") || value.contains("timed out") {
        "timeout"
    } else if value.contains("permission")
        || value.contains("denied")
        || value.contains("forbidden")
    {
        "permission"
    } else if value.contains("not found") || value.contains("missing") {
        "dependency"
    } else if value.contains("network") || value.contains("connect") || value.contains("dns") {
        "network"
    } else if value.contains("invalid") || value.contains("parse") || value.contains("syntax") {
        "invalid_input"
    } else if value.contains("cancel") {
        "cancelled"
    } else {
        "execution"
    }
}

fn sync_skill_failure_patterns_for_run(
    tx: &Transaction<'_>,
    run_id: &str,
) -> Result<(), MicroClawError> {
    // Re-project this run idempotently. This is also required when human
    // feedback changes or verifier evidence expires.
    let prior_patterns = {
        let mut stmt =
            tx.prepare("SELECT pattern_id FROM skill_failure_pattern_evidence WHERE run_id=?1")?;
        let rows = stmt
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    tx.execute(
        "DELETE FROM skill_failure_pattern_evidence WHERE run_id=?1",
        params![run_id],
    )?;
    for pattern_id in prior_patterns {
        let (failures, recoveries): (i64, i64) = tx.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN verdict='failed' THEN 1 ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN verdict='passed' THEN 1 ELSE 0 END),0)
             FROM skill_failure_pattern_evidence WHERE pattern_id=?1",
            params![pattern_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if failures == 0 {
            tx.execute(
                "DELETE FROM skill_failure_patterns WHERE pattern_id=?1",
                params![pattern_id],
            )?;
        } else {
            tx.execute(
                "UPDATE skill_failure_patterns
                 SET failure_count=?2, recovery_successes=?3,
                     state=CASE WHEN ?2 < (
                       SELECT failure_pattern_min_failures
                       FROM skill_governance_policy WHERE singleton_id=1
                     ) THEN 'observed' ELSE state END,
                     cooldown_until=CASE WHEN ?2 < (
                       SELECT failure_pattern_min_failures
                       FROM skill_governance_policy WHERE singleton_id=1
                     ) THEN NULL ELSE cooldown_until END,
                     updated_at=?4
                 WHERE pattern_id=?1",
                params![
                    pattern_id,
                    failures,
                    recoveries,
                    chrono::Utc::now().to_rfc3339()
                ],
            )?;
        }
    }
    let context: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT task_type, task_family, environment_fingerprint
             FROM experience_runs WHERE run_id=?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((task_type, task_family, environment)) = context else {
        return Ok(());
    };
    let policy: (i64, i64, i64) = tx.query_row(
        "SELECT failure_pattern_min_failures, failure_pattern_cooldown_hours,
                failure_pattern_recovery_successes
         FROM skill_governance_policy WHERE singleton_id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let skills = {
        let mut stmt = tx.prepare(
            "SELECT skill_name, skill_version, verdict, evidence
             FROM skill_outcomes
             WHERE run_id=?1 AND attribution_confidence >= 0.999
               AND verifier_type IN ('deterministic','environmental','human','rule_based')",
        )?;
        let rows = stmt
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let failed_tools = {
        let mut stmt = tx.prepare(
            "SELECT json_extract(payload_json, '$.tool_name'), evidence
             FROM outcome_envelopes
             WHERE run_id=?1 AND verdict='failed' AND scope='tool_result'",
        )?;
        let rows = stmt
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let now = chrono::Utc::now();
    for (skill_name, skill_version, verdict, skill_evidence) in skills {
        if verdict == "failed" {
            let evidence_items = if failed_tools.is_empty() {
                vec![(None, skill_evidence.clone())]
            } else {
                failed_tools.clone()
            };
            for (tool_name, evidence) in evidence_items {
                let category = classify_failure_category(evidence.as_deref());
                let canonical = format!(
                    "{skill_name}\n{skill_version}\n{task_family}\n{}\n{}\n{category}",
                    environment.as_deref().unwrap_or(""),
                    tool_name.as_deref().unwrap_or("")
                );
                use sha2::{Digest, Sha256};
                let pattern_id = to_hex(&Sha256::digest(canonical.as_bytes()));
                let cooldown_until = (now + chrono::Duration::hours(policy.1)).to_rfc3339();
                tx.execute(
                    "INSERT INTO skill_failure_patterns(
                        pattern_id, skill_name, skill_version, task_type, task_family,
                        environment_fingerprint, tool_name, error_category,
                        failure_count, recovery_successes, state, cooldown_until,
                        last_evidence, first_seen_at, updated_at
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,0,'observed',NULL,?9,?10,?10)
                     ON CONFLICT(pattern_id) DO UPDATE SET
                        last_evidence=excluded.last_evidence,
                        updated_at=excluded.updated_at",
                    params![
                        pattern_id,
                        skill_name,
                        skill_version,
                        task_type,
                        task_family,
                        environment,
                        tool_name,
                        category,
                        evidence,
                        now.to_rfc3339()
                    ],
                )?;
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO skill_failure_pattern_evidence(
                        pattern_id, run_id, verdict, created_at
                     ) VALUES (?1,?2,'failed',?3)",
                    params![pattern_id, run_id, now.to_rfc3339()],
                )?;
                if inserted > 0 {
                    tx.execute(
                        "UPDATE skill_failure_patterns
                         SET failure_count=failure_count+1,
                             recovery_successes=0,
                             state=CASE WHEN failure_count+1 >= ?2
                                        THEN 'active' ELSE 'observed' END,
                             cooldown_until=CASE WHEN failure_count+1 >= ?2
                                        THEN ?3 ELSE cooldown_until END,
                             updated_at=?4 WHERE pattern_id=?1",
                        params![pattern_id, policy.0, cooldown_until, now.to_rfc3339()],
                    )?;
                    if policy.0 <= {
                        tx.query_row(
                            "SELECT failure_count FROM skill_failure_patterns
                             WHERE pattern_id=?1",
                            params![pattern_id],
                            |row| row.get::<_, i64>(0),
                        )?
                    } {
                        let current: Option<(String, Option<i64>)> = tx
                            .query_row(
                                "SELECT state, previous_trusted_version FROM skill_lifecycle
                                 WHERE skill_name=?1 AND active_version=?2",
                                params![skill_name, skill_version],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            )
                            .optional()?;
                        if current
                            .as_ref()
                            .is_some_and(|(state, _)| state != "degraded" && state != "archived")
                        {
                            let (from_state, previous_trusted) =
                                current.unwrap_or_else(|| (String::new(), None));
                            let reason = format!(
                                "active failure pattern: task_family={task_family}, error_category={category}"
                            );
                            if from_state == "trusted" && previous_trusted.is_some() {
                                let restored = previous_trusted.unwrap_or_default();
                                let rollback_reason = format!(
                                    "automatic rollback from v{skill_version} to v{restored}: {reason}"
                                );
                                tx.execute(
                                    "UPDATE skill_lifecycle SET state='trusted',
                                     active_version=?2, previous_trusted_version=NULL,
                                     state_reason=?3, updated_at=?4 WHERE skill_name=?1",
                                    params![
                                        skill_name,
                                        restored,
                                        rollback_reason,
                                        now.to_rfc3339()
                                    ],
                                )?;
                                tx.execute(
                                    "UPDATE skill_candidates
                                     SET status='rolled_back', updated_at=?3
                                     WHERE skill_name=?1 AND candidate_version=?2
                                       AND status='promoted'",
                                    params![skill_name, skill_version, now.to_rfc3339()],
                                )?;
                                tx.execute(
                                    "INSERT INTO skill_lifecycle_events(
                                        skill_name, from_state, to_state, version,
                                        reason, created_at
                                     ) VALUES (?1,'trusted','trusted',?2,?3,?4)",
                                    params![
                                        skill_name,
                                        restored,
                                        rollback_reason,
                                        now.to_rfc3339()
                                    ],
                                )?;
                                tx.execute(
                                    "INSERT INTO learning_journal_events(
                                        event_type, entity_type, entity_id, summary,
                                        evidence_json, created_at
                                     ) VALUES ('automatic_rollback','skill',?1,?2,?3,?4)",
                                    params![
                                        skill_name,
                                        rollback_reason,
                                        serde_json::json!({
                                            "failed_version": skill_version,
                                            "restored_version": restored,
                                            "trigger": reason
                                        })
                                        .to_string(),
                                        now.to_rfc3339()
                                    ],
                                )?;
                            } else {
                                tx.execute(
                                    "UPDATE skill_lifecycle SET state='degraded',
                                     previous_trusted_version=CASE WHEN state='trusted'
                                        THEN active_version ELSE previous_trusted_version END,
                                     state_reason=?3, updated_at=?4
                                     WHERE skill_name=?1 AND active_version=?2",
                                    params![skill_name, skill_version, reason, now.to_rfc3339()],
                                )?;
                                tx.execute(
                                    "INSERT INTO skill_lifecycle_events(
                                        skill_name, from_state, to_state, version,
                                        reason, created_at
                                     ) VALUES (?1,?2,'degraded',?3,?4,?5)",
                                    params![
                                        skill_name,
                                        from_state,
                                        skill_version,
                                        reason,
                                        now.to_rfc3339()
                                    ],
                                )?;
                            }
                        }
                    }
                }
            }
        } else if verdict == "passed" {
            let patterns = {
                let mut stmt = tx.prepare(
                    "SELECT pattern_id FROM skill_failure_patterns
                     WHERE skill_name=?1 AND skill_version=?2 AND task_family=?3
                       AND (environment_fingerprint IS NULL OR environment_fingerprint=?4)
                       AND state IN ('active','cooldown','trial')",
                )?;
                let rows = stmt
                    .query_map(
                        params![skill_name, skill_version, task_family, environment],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            for pattern_id in patterns {
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO skill_failure_pattern_evidence(
                        pattern_id, run_id, verdict, created_at
                     ) VALUES (?1,?2,'passed',?3)",
                    params![pattern_id, run_id, now.to_rfc3339()],
                )?;
                if inserted > 0 {
                    tx.execute(
                        "UPDATE skill_failure_patterns
                         SET recovery_successes=recovery_successes+1,
                             state=CASE
                               WHEN recovery_successes+1 >= ?2 THEN 'resolved'
                               WHEN cooldown_until <= ?3 THEN 'trial'
                               ELSE 'cooldown' END,
                             updated_at=?3 WHERE pattern_id=?1",
                        params![pattern_id, policy.2, now.to_rfc3339()],
                    )?;
                }
            }
            let unresolved: i64 = tx.query_row(
                "SELECT COUNT(*) FROM skill_failure_patterns
                 WHERE skill_name=?1 AND skill_version=?2
                   AND state IN ('active','cooldown','trial')",
                params![skill_name, skill_version],
                |row| row.get(0),
            )?;
            if unresolved == 0 {
                let changed = tx.execute(
                    "UPDATE skill_lifecycle SET state='trial',
                     state_reason='failure patterns resolved; recovery trial started',
                     updated_at=?3
                     WHERE skill_name=?1 AND active_version=?2 AND state='degraded'",
                    params![skill_name, skill_version, now.to_rfc3339()],
                )?;
                if changed > 0 {
                    tx.execute(
                        "INSERT INTO skill_lifecycle_events(
                            skill_name, from_state, to_state, version, reason, created_at
                         ) VALUES (?1,'degraded','trial',?2,
                            'failure patterns resolved; recovery trial started',?3)",
                        params![skill_name, skill_version, now.to_rfc3339()],
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn map_shadow_evaluation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShadowEvaluation> {
    Ok(ShadowEvaluation {
        evaluation_id: row.get(0)?,
        candidate_id: row.get(1)?,
        sample_count: row.get(2)?,
        baseline_passed: row.get(3)?,
        candidate_passed: row.get(4)?,
        baseline_utility_lower_bound: row.get(5)?,
        candidate_utility_lower_bound: row.get(6)?,
        baseline_cost_usd: row.get(7)?,
        candidate_cost_usd: row.get(8)?,
        baseline_duration_ms: row.get(9)?,
        candidate_duration_ms: row.get(10)?,
        regression_count: row.get(11)?,
        verdict: row.get(12)?,
        reason: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn recompute_shadow_evaluation(
    tx: &Transaction<'_>,
    candidate_id: &str,
) -> Result<ShadowEvaluation, MicroClawError> {
    let (
        samples,
        baseline_passed,
        candidate_passed,
        baseline_cost,
        candidate_cost,
        baseline_duration,
        candidate_duration,
        regressions,
    ): (i64, i64, i64, f64, f64, i64, i64, i64) = tx.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(CASE WHEN b.verdict='passed' THEN 1 ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN c.verdict='passed' THEN 1 ELSE 0 END),0),
                COALESCE(SUM(b.cost_usd),0), COALESCE(SUM(c.cost_usd),0),
                COALESCE(SUM(b.duration_ms),0), COALESCE(SUM(c.duration_ms),0),
                COALESCE(SUM(CASE WHEN b.verdict='passed'
                                      AND c.verdict='failed' THEN 1 ELSE 0 END),0)
         FROM shadow_observations b
         JOIN shadow_observations c
           ON c.candidate_id=b.candidate_id AND c.pair_key=b.pair_key
          AND c.arm='candidate'
         WHERE b.candidate_id=?1 AND b.arm='baseline'",
        params![candidate_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    let policy = tx.query_row(
        "SELECT shadow_min_samples, shadow_promote_utility_margin,
                shadow_max_cost_ratio, shadow_max_regressions,
                utility_confidence_z
         FROM skill_governance_policy WHERE singleton_id=1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, f64>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, f64>(4)?,
            ))
        },
    )?;
    let baseline_utility = wilson_lower_bound(baseline_passed, samples, policy.4);
    let candidate_utility = wilson_lower_bound(candidate_passed, samples, policy.4);
    let cost_ratio = if baseline_cost <= f64::EPSILON {
        if candidate_cost <= f64::EPSILON {
            1.0
        } else {
            f64::INFINITY
        }
    } else {
        candidate_cost / baseline_cost
    };
    let (verdict, reason) = if samples < policy.0 {
        (
            "pending",
            format!("need {} paired samples; have {samples}", policy.0),
        )
    } else if regressions > policy.3 {
        (
            "failed",
            format!("regressions {regressions} exceed {}", policy.3),
        )
    } else if candidate_utility + f64::EPSILON < baseline_utility + policy.1 {
        (
            "failed",
            format!(
                "candidate utility floor {candidate_utility:.3} does not exceed baseline {baseline_utility:.3} by {:.3}",
                policy.1
            ),
        )
    } else if cost_ratio > policy.2 {
        (
            "failed",
            format!(
                "candidate cost ratio {cost_ratio:.3} exceeds {:.3}",
                policy.2
            ),
        )
    } else {
        (
            "passed",
            format!(
                "paired shadow gate passed: utility {:.3}→{:.3}, cost ratio {:.3}, regressions {regressions}",
                baseline_utility, candidate_utility, cost_ratio
            ),
        )
    };
    use sha2::{Digest, Sha256};
    let evaluation_id = to_hex(&Sha256::digest(candidate_id.as_bytes()));
    let previous: Option<String> = tx
        .query_row(
            "SELECT verdict FROM shadow_evaluations WHERE candidate_id=?1",
            params![candidate_id],
            |row| row.get(0),
        )
        .optional()?;
    let now = chrono::Utc::now().to_rfc3339();
    tx.execute(
        "INSERT INTO shadow_evaluations(
            evaluation_id, candidate_id, sample_count, baseline_passed,
            candidate_passed, baseline_utility_lower_bound,
            candidate_utility_lower_bound, baseline_cost_usd,
            candidate_cost_usd, baseline_duration_ms, candidate_duration_ms,
            regression_count, verdict, reason, updated_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
         ON CONFLICT(candidate_id) DO UPDATE SET
            sample_count=excluded.sample_count,
            baseline_passed=excluded.baseline_passed,
            candidate_passed=excluded.candidate_passed,
            baseline_utility_lower_bound=excluded.baseline_utility_lower_bound,
            candidate_utility_lower_bound=excluded.candidate_utility_lower_bound,
            baseline_cost_usd=excluded.baseline_cost_usd,
            candidate_cost_usd=excluded.candidate_cost_usd,
            baseline_duration_ms=excluded.baseline_duration_ms,
            candidate_duration_ms=excluded.candidate_duration_ms,
            regression_count=excluded.regression_count,
            verdict=excluded.verdict, reason=excluded.reason,
            updated_at=excluded.updated_at",
        params![
            evaluation_id,
            candidate_id,
            samples,
            baseline_passed,
            candidate_passed,
            baseline_utility,
            candidate_utility,
            baseline_cost,
            candidate_cost,
            baseline_duration,
            candidate_duration,
            regressions,
            verdict,
            reason,
            now
        ],
    )?;
    tx.execute(
        "UPDATE skill_candidates SET status=?2, updated_at=?3
         WHERE candidate_id=?1 AND status<>'promoted'",
        params![
            candidate_id,
            match verdict {
                "passed" => "shadow_passed",
                "failed" => "shadow_failed",
                _ => "shadow",
            },
            now
        ],
    )?;
    if previous.as_deref() != Some(verdict) {
        tx.execute(
            "INSERT INTO learning_journal_events(
                event_type, entity_type, entity_id, summary, evidence_json,
                undo_action, created_at
             ) VALUES ('shadow_evaluated','skill_candidate',?1,?2,?3,
                       CASE WHEN ?4='passed' THEN 'archive_candidate'
                            ELSE NULL END,?5)",
            params![
                candidate_id,
                reason,
                serde_json::json!({
                    "sample_count": samples,
                    "baseline_utility_lower_bound": baseline_utility,
                    "candidate_utility_lower_bound": candidate_utility,
                    "cost_ratio": cost_ratio,
                    "regression_count": regressions
                })
                .to_string(),
                verdict,
                now
            ],
        )?;
    }
    tx.query_row(
        "SELECT evaluation_id, candidate_id, sample_count,
                baseline_passed, candidate_passed,
                baseline_utility_lower_bound, candidate_utility_lower_bound,
                baseline_cost_usd, candidate_cost_usd,
                baseline_duration_ms, candidate_duration_ms,
                regression_count, verdict, reason, updated_at
         FROM shadow_evaluations WHERE candidate_id=?1",
        params![candidate_id],
        map_shadow_evaluation,
    )
    .map_err(Into::into)
}

type ComparativeCurrentRun = (
    String,
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
    Option<f64>,
);

type ComparativePeerRun = (
    String,
    Option<String>,
    i64,
    i64,
    i64,
    Option<f64>,
    Option<String>,
);

fn refresh_comparative_reflections_for_run(
    tx: &Transaction<'_>,
    run_id: &str,
) -> Result<(), MicroClawError> {
    let current: Option<ComparativeCurrentRun> = tx
        .query_row(
            "SELECT o.skill_name, o.skill_version, r.chat_id, o.verdict, r.task_type,
                    r.task_family, r.environment_fingerprint, r.result_summary,
                    r.duration_ms, r.tool_calls, r.tool_errors,
                    r.estimated_cost_usd
             FROM skill_outcomes o
             JOIN experience_runs r ON r.run_id=o.run_id
             WHERE o.run_id=?1 AND o.attribution_confidence>=0.999
               AND o.verifier_type IN (
                 'deterministic','environmental','human','rule_based'
               )
             LIMIT 1",
            params![run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get::<_, Option<i64>>(8)?.unwrap_or_default(),
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        skill_name,
        skill_version,
        chat_id,
        verdict,
        task_type,
        task_family,
        environment,
        result_summary,
        duration_ms,
        tool_calls,
        tool_errors,
        cost,
    )) = current
    else {
        return Ok(());
    };
    let opposite = if verdict == "passed" {
        "failed"
    } else if verdict == "failed" {
        "passed"
    } else {
        return Ok(());
    };
    let peer: Option<ComparativePeerRun> = tx
        .query_row(
            "SELECT o.run_id, r.result_summary, COALESCE(r.duration_ms,0),
                    r.tool_calls, r.tool_errors, r.estimated_cost_usd, o.evidence
             FROM skill_outcomes o
             JOIN experience_runs r ON r.run_id=o.run_id
             WHERE o.skill_name=?1 AND o.skill_version=?2 AND o.verdict=?3
               AND r.task_family=?4
               AND (r.environment_fingerprint IS ?5 OR r.environment_fingerprint=?5)
               AND o.attribution_confidence>=0.999
               AND o.verifier_type IN (
                 'deterministic','environmental','human','rule_based'
               )
               AND o.run_id<>?6
               AND r.chat_id=?7
             ORDER BY o.updated_at DESC LIMIT 1",
            params![
                skill_name,
                skill_version,
                opposite,
                task_family,
                environment,
                run_id,
                chat_id
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((
        peer_run_id,
        peer_summary,
        peer_duration,
        peer_tool_calls,
        peer_tool_errors,
        peer_cost,
        peer_evidence,
    )) = peer
    else {
        return Ok(());
    };
    let (success_run_id, failure_run_id, success_profile, failure_profile, counterexample) =
        if verdict == "passed" {
            (
                run_id.to_string(),
                peer_run_id,
                (
                    duration_ms,
                    tool_calls,
                    tool_errors,
                    cost.unwrap_or_default(),
                ),
                (
                    peer_duration,
                    peer_tool_calls,
                    peer_tool_errors,
                    peer_cost.unwrap_or_default(),
                ),
                peer_evidence.or(peer_summary).unwrap_or_default(),
            )
        } else {
            (
                peer_run_id,
                run_id.to_string(),
                (
                    peer_duration,
                    peer_tool_calls,
                    peer_tool_errors,
                    peer_cost.unwrap_or_default(),
                ),
                (
                    duration_ms,
                    tool_calls,
                    tool_errors,
                    cost.unwrap_or_default(),
                ),
                result_summary.unwrap_or_default(),
            )
        };
    use sha2::{Digest, Sha256};
    let canonical = format!(
        "{chat_id}\n{skill_name}\n{skill_version}\n{task_family}\n{}\n{success_run_id}\n{failure_run_id}",
        environment.as_deref().unwrap_or("")
    );
    let comparison_id = to_hex(&Sha256::digest(canonical.as_bytes()));
    let minimal_difference = format!(
        "success vs failure: tool_errors {}→{}, tool_calls {}→{}, duration_ms {}→{}, cost_usd {:.6}→{:.6}",
        failure_profile.2,
        success_profile.2,
        failure_profile.1,
        success_profile.1,
        failure_profile.0,
        success_profile.0,
        failure_profile.3,
        success_profile.3
    );
    let now = chrono::Utc::now().to_rfc3339();
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO experience_comparisons(
            comparison_id, chat_id, skill_name, skill_version, task_type, task_family,
            environment_fingerprint, success_run_id, failure_run_id,
            minimal_difference, counterexample, created_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            comparison_id,
            chat_id,
            skill_name,
            skill_version,
            task_type,
            task_family,
            environment,
            success_run_id,
            failure_run_id,
            minimal_difference,
            counterexample,
            now
        ],
    )?;
    if inserted == 0 {
        return Ok(());
    }
    let claim_version: i64 = tx.query_row(
        "SELECT COALESCE(MAX(claim_version),0)+1 FROM learning_claims
         WHERE skill_name=?1",
        params![skill_name],
        |row| row.get(0),
    )?;
    let supersedes: Option<String> = tx
        .query_row(
            "SELECT c.claim_id FROM learning_claims c
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             WHERE c.skill_name=?1 AND x.chat_id=?2
             ORDER BY c.claim_version DESC LIMIT 1",
            params![skill_name, chat_id],
            |row| row.get(0),
        )
        .optional()?;
    let claim_id = uuid::Uuid::new_v4().to_string();
    let statement = format!(
        "For task_family={task_family}, prefer the successful execution profile ({minimal_difference}); treat the linked failing run as a counterexample."
    );
    let applicability = serde_json::json!({
        "task_type": task_type,
        "task_family": task_family,
        "environment_fingerprint": environment,
        "skill_version": skill_version
    });
    let evidence = serde_json::json!({
        "success_run_id": success_run_id,
        "failure_run_id": failure_run_id,
        "minimal_difference": minimal_difference
    });
    tx.execute(
        "INSERT INTO learning_claims(
            claim_id, comparison_id, skill_name, base_version, claim_version,
            statement, applicability_json, confidence, evidence_json,
            counterexamples_json, status, supersedes_claim_id,
            created_at, updated_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,0.6,?8,?9,'candidate',?10,?11,?11)",
        params![
            claim_id,
            comparison_id,
            skill_name,
            skill_version,
            claim_version,
            statement,
            applicability.to_string(),
            evidence.to_string(),
            serde_json::json!([counterexample]).to_string(),
            supersedes,
            now
        ],
    )?;
    tx.execute(
        "INSERT INTO learning_journal_events(
            event_type, entity_type, entity_id, summary, evidence_json,
            undo_action, created_at
         ) VALUES ('claim_distilled','learning_claim',?1,?2,?3,
                   'archive_claim',?4)",
        params![claim_id, statement, evidence.to_string(), now],
    )?;
    Ok(())
}

fn refresh_expired_skill_outcomes(tx: &Transaction<'_>) -> Result<(), MicroClawError> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = tx.prepare(
        "SELECT DISTINCT run_id, skill_name, skill_version FROM skill_outcomes
         WHERE valid_until IS NOT NULL AND valid_until <= ?1",
    )?;
    let expired = stmt
        .query_map(params![now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    for (run_id, _, _) in &expired {
        sync_skill_outcomes_for_run(tx, run_id)?;
        sync_skill_failure_patterns_for_run(tx, run_id)?;
    }
    let mut affected = expired
        .into_iter()
        .map(|(_, skill_name, version)| (skill_name, version))
        .collect::<Vec<_>>();
    affected.sort();
    affected.dedup();
    for (skill_name, version) in affected {
        recompute_skill_lifecycle(tx, &skill_name, version, "verifier evidence expired")?;
    }
    Ok(())
}

fn erase_chat_learning(tx: &Transaction<'_>, chat_id: i64) -> Result<usize, MicroClawError> {
    let mut stmt = tx.prepare(
        "SELECT DISTINCT o.skill_name, o.skill_version
         FROM skill_outcomes o
         JOIN experience_runs r ON r.run_id=o.run_id
         WHERE r.chat_id=?1",
    )?;
    let affected_skills = stmt
        .query_map(params![chat_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let mut affected = 0usize;
    let promoted_from_chat = {
        let mut stmt = tx.prepare(
            "SELECT DISTINCT k.skill_name, k.candidate_version, k.base_version
             FROM skill_candidates k
             JOIN learning_claims c ON c.claim_id=k.claim_id
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             JOIN experience_runs s ON s.run_id=x.success_run_id
             JOIN experience_runs f ON f.run_id=x.failure_run_id
             WHERE k.status='promoted' AND (s.chat_id=?1 OR f.chat_id=?1)",
        )?;
        let rows = stmt
            .query_map(params![chat_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (skill_name, candidate_version, base_version) in promoted_from_chat {
        tx.execute(
            "UPDATE skill_lifecycle SET state='trusted', active_version=?2,
             previous_trusted_version=NULL,
             state_reason='comparative evidence erased; restored base version',
             updated_at=?3 WHERE skill_name=?1 AND active_version=?4",
            params![
                skill_name,
                base_version,
                chrono::Utc::now().to_rfc3339(),
                candidate_version
            ],
        )?;
        tx.execute(
            "DELETE FROM skill_versions WHERE skill_name=?1 AND version=?2
             AND source='comparative-reflection'",
            params![skill_name, candidate_version],
        )?;
    }
    affected += tx.execute(
        "DELETE FROM learning_journal_events WHERE
           (entity_type='learning_claim' AND entity_id IN (
             SELECT c.claim_id FROM learning_claims c
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             JOIN experience_runs s ON s.run_id=x.success_run_id
             JOIN experience_runs f ON f.run_id=x.failure_run_id
             WHERE s.chat_id=?1 OR f.chat_id=?1
           )) OR
           (entity_type='skill_candidate' AND entity_id IN (
             SELECT k.candidate_id FROM skill_candidates k
             JOIN learning_claims c ON c.claim_id=k.claim_id
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             JOIN experience_runs s ON s.run_id=x.success_run_id
             JOIN experience_runs f ON f.run_id=x.failure_run_id
             WHERE s.chat_id=?1 OR f.chat_id=?1
           ))",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM learning_journal_events
         WHERE entity_type='skill' AND entity_id IN (
           SELECT DISTINCT o.skill_name FROM skill_outcomes o
           JOIN experience_runs r ON r.run_id=o.run_id WHERE r.chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM shadow_observations WHERE
           run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)
           OR candidate_id IN (
             SELECT k.candidate_id FROM skill_candidates k
             JOIN learning_claims c ON c.claim_id=k.claim_id
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             JOIN experience_runs s ON s.run_id=x.success_run_id
             JOIN experience_runs f ON f.run_id=x.failure_run_id
             WHERE s.chat_id=?1 OR f.chat_id=?1
           )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM shadow_evaluations WHERE candidate_id IN (
           SELECT k.candidate_id FROM skill_candidates k
           JOIN learning_claims c ON c.claim_id=k.claim_id
           JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
           JOIN experience_runs s ON s.run_id=x.success_run_id
           JOIN experience_runs f ON f.run_id=x.failure_run_id
           WHERE s.chat_id=?1 OR f.chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM skill_candidates WHERE claim_id IN (
           SELECT c.claim_id FROM learning_claims c
           JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
           JOIN experience_runs s ON s.run_id=x.success_run_id
           JOIN experience_runs f ON f.run_id=x.failure_run_id
           WHERE s.chat_id=?1 OR f.chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM learning_claims WHERE comparison_id IN (
           SELECT x.comparison_id FROM experience_comparisons x
           JOIN experience_runs s ON s.run_id=x.success_run_id
           JOIN experience_runs f ON f.run_id=x.failure_run_id
           WHERE s.chat_id=?1 OR f.chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM experience_comparisons WHERE
           success_run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)
           OR failure_run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM skill_failure_pattern_evidence
         WHERE run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM skill_outcomes
         WHERE run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM verifier_results
         WHERE run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM experience_feedback
         WHERE run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM outcome_envelopes
         WHERE run_id IN (SELECT run_id FROM experience_runs WHERE chat_id=?1)",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM experience_retrieval_logs
         WHERE querying_run_id IN (
             SELECT run_id FROM experience_runs WHERE chat_id=?1
         ) OR source_run_id IN (
             SELECT run_id FROM experience_runs WHERE chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM experience_retrieval_rejections
         WHERE querying_run_id IN (
             SELECT run_id FROM experience_runs WHERE chat_id=?1
         ) OR source_run_id IN (
             SELECT run_id FROM experience_runs WHERE chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM skill_activation_logs
         WHERE chat_id=?1 OR experience_run_id IN (
             SELECT run_id FROM experience_runs WHERE chat_id=?1
         )",
        params![chat_id],
    )?;
    affected += tx.execute(
        "DELETE FROM experience_runs WHERE chat_id=?1",
        params![chat_id],
    )?;
    affected += tx.execute("DELETE FROM goal_states WHERE chat_id=?1", params![chat_id])?;
    for (skill_name, version) in affected_skills {
        tx.execute(
            "DELETE FROM skill_failure_pattern_evidence
             WHERE pattern_id IN (
               SELECT pattern_id FROM skill_failure_patterns
               WHERE skill_name=?1 AND skill_version=?2
             )",
            params![skill_name, version],
        )?;
        tx.execute(
            "DELETE FROM skill_failure_patterns
             WHERE skill_name=?1 AND skill_version=?2",
            params![skill_name, version],
        )?;
        let remaining = {
            let mut stmt = tx.prepare(
                "SELECT run_id FROM skill_outcomes
                 WHERE skill_name=?1 AND skill_version=?2 ORDER BY created_at ASC",
            )?;
            let rows = stmt
                .query_map(params![skill_name, version], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for run_id in remaining {
            sync_skill_failure_patterns_for_run(tx, &run_id)?;
        }
        recompute_skill_lifecycle(tx, &skill_name, version, "chat learning evidence erased")?;
    }
    Ok(affected)
}

fn evaluate_skill_lifecycle(
    tx: &Transaction<'_>,
    skill_name: &str,
    version: i64,
) -> Result<bool, MicroClawError> {
    let current: Option<String> = tx
        .query_row(
            "SELECT state FROM skill_lifecycle
             WHERE skill_name=?1 AND active_version=?2",
            params![skill_name, version],
            |row| row.get(0),
        )
        .optional()?;
    let Some(current) = current else {
        return Ok(false);
    };
    if current == "archived" || current == "degraded" {
        return Ok(false);
    }
    let (total, passed, failed): (i64, i64, i64) = tx.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(CASE WHEN verdict='passed' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN verdict='failed' THEN 1 ELSE 0 END), 0)
         FROM skill_outcomes
         WHERE skill_name=?1 AND skill_version=?2
           AND verifier_type IN ('deterministic','environmental','human','rule_based')
           AND attribution_confidence >= 0.999
           AND (valid_until IS NULL OR valid_until > ?3)",
        params![skill_name, version, chrono::Utc::now().to_rfc3339()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let success_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    let policy = tx.query_row(
        "SELECT candidate_failures_to_degrade, trial_min_outcomes,
                trial_promote_rate, trial_degrade_rate, trusted_min_outcomes,
                trusted_degrade_rate, utility_confidence_z,
                trial_promote_utility_lower_bound,
                failure_pattern_min_failures, failure_pattern_cooldown_hours,
                failure_pattern_recovery_successes, shadow_min_samples,
                shadow_promote_utility_margin, shadow_max_cost_ratio,
                shadow_max_regressions
         FROM skill_governance_policy WHERE singleton_id=1",
        [],
        |row| {
            Ok(SkillGovernancePolicy {
                candidate_failures_to_degrade: row.get(0)?,
                trial_min_outcomes: row.get(1)?,
                trial_promote_rate: row.get(2)?,
                trial_degrade_rate: row.get(3)?,
                trusted_min_outcomes: row.get(4)?,
                trusted_degrade_rate: row.get(5)?,
                utility_confidence_z: row.get(6)?,
                trial_promote_utility_lower_bound: row.get(7)?,
                failure_pattern_min_failures: row.get(8)?,
                failure_pattern_cooldown_hours: row.get(9)?,
                failure_pattern_recovery_successes: row.get(10)?,
                shadow_min_samples: row.get(11)?,
                shadow_promote_utility_margin: row.get(12)?,
                shadow_max_cost_ratio: row.get(13)?,
                shadow_max_regressions: row.get(14)?,
            })
        },
    )?;
    let utility_lower_bound = wilson_lower_bound(passed, total, policy.utility_confidence_z);
    let transition = match current.as_str() {
        "candidate" if failed >= policy.candidate_failures_to_degrade => {
            Some(("degraded", "candidate exceeded verified failure threshold"))
        }
        "candidate" if passed >= 1 => Some(("trial", "first verified success")),
        "trial"
            if total >= policy.trial_min_outcomes
                && success_rate >= policy.trial_promote_rate
                && utility_lower_bound >= policy.trial_promote_utility_lower_bound =>
        {
            Some((
                "trusted",
                "trial passed raw-rate and risk-adjusted utility thresholds",
            ))
        }
        "trial"
            if total >= policy.trial_min_outcomes && success_rate < policy.trial_degrade_rate =>
        {
            Some(("degraded", "trial failed quality threshold"))
        }
        "trusted"
            if total >= policy.trusted_min_outcomes
                && success_rate < policy.trusted_degrade_rate =>
        {
            Some((
                "degraded",
                "trusted skill regressed below quality threshold",
            ))
        }
        _ => None,
    };
    let Some((next, reason)) = transition else {
        return Ok(false);
    };
    let now = chrono::Utc::now().to_rfc3339();
    if current == "trusted" && next == "degraded" {
        let rollback_version: Option<i64> = tx
            .query_row(
                "SELECT previous_trusted_version FROM skill_lifecycle
                 WHERE skill_name=?1 AND active_version=?2",
                params![skill_name, version],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if let Some(rollback_version) = rollback_version {
            let exists: i64 = tx.query_row(
                "SELECT COUNT(*) FROM skill_versions
                 WHERE skill_name=?1 AND version=?2",
                params![skill_name, rollback_version],
                |row| row.get(0),
            )?;
            if exists > 0 {
                let rollback_reason =
                    format!("automatic rollback from v{version} to v{rollback_version}: {reason}");
                tx.execute(
                    "UPDATE skill_lifecycle SET state='trusted', active_version=?2,
                     previous_trusted_version=NULL, updated_at=?3, state_reason=?4
                     WHERE skill_name=?1",
                    params![skill_name, rollback_version, now, rollback_reason],
                )?;
                tx.execute(
                    "INSERT INTO skill_lifecycle_events(
                        skill_name, from_state, to_state, version, reason, created_at
                     ) VALUES (?1,'trusted','trusted',?2,?3,?4)",
                    params![skill_name, rollback_version, rollback_reason, now],
                )?;
                tx.execute(
                    "UPDATE skill_candidates SET status='rolled_back', updated_at=?3
                     WHERE skill_name=?1 AND candidate_version=?2
                       AND status='promoted'",
                    params![skill_name, version, now],
                )?;
                tx.execute(
                    "INSERT INTO learning_journal_events(
                        event_type, entity_type, entity_id, summary,
                        evidence_json, undo_action, created_at
                     ) VALUES ('automatic_rollback','skill',?1,?2,?3,NULL,?4)",
                    params![
                        skill_name,
                        rollback_reason,
                        serde_json::json!({
                            "failed_version": version,
                            "restored_version": rollback_version,
                            "trigger": reason
                        })
                        .to_string(),
                        now
                    ],
                )?;
                return Ok(true);
            }
        }
    }
    let previous_trusted = (current == "trusted").then_some(version);
    tx.execute(
        "UPDATE skill_lifecycle
         SET state=?2,
             previous_trusted_version=COALESCE(?3, previous_trusted_version),
             updated_at=?4, state_reason=?5
         WHERE skill_name=?1",
        params![skill_name, next, previous_trusted, now, reason],
    )?;
    tx.execute(
        "INSERT INTO skill_lifecycle_events(
            skill_name, from_state, to_state, version, reason, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![skill_name, current, next, version, reason, now],
    )?;
    Ok(true)
}

fn recompute_skill_lifecycle(
    tx: &Transaction<'_>,
    skill_name: &str,
    version: i64,
    reason: &str,
) -> Result<(), MicroClawError> {
    let current: Option<(String, String)> = tx
        .query_row(
            "SELECT state, source FROM skill_lifecycle
             WHERE skill_name=?1 AND active_version=?2",
            params![skill_name, version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((from_state, source)) = current else {
        return Ok(());
    };
    if from_state == "archived" {
        return Ok(());
    }
    let baseline = if source == "agent-created" {
        "candidate"
    } else {
        "trusted"
    };
    let now = chrono::Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE skill_lifecycle
         SET state=?2, updated_at=?3, state_reason=?4
         WHERE skill_name=?1",
        params![skill_name, baseline, now, reason],
    )?;
    if from_state != baseline {
        tx.execute(
            "INSERT INTO skill_lifecycle_events(
                skill_name, from_state, to_state, version, reason, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![skill_name, from_state, baseline, version, reason, now],
        )?;
    }
    // At most candidate -> trial -> trusted/degraded. Bound the loop so a
    // malformed future policy cannot create a transition cycle.
    for _ in 0..3 {
        if !evaluate_skill_lifecycle(tx, skill_name, version)? {
            break;
        }
    }
    Ok(())
}

impl Database {
    fn lock_conn(&self) -> MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn new(data_dir: &str) -> Result<Self, MicroClawError> {
        let db_path = Path::new(data_dir).join("microclaw.db");
        std::fs::create_dir_all(data_dir)?;

        #[cfg(feature = "sqlite-vec")]
        SQLITE_VEC_AUTOEXT_INIT.call_once(|| unsafe {
            let init_fn_ptr = sqlite_vec::sqlite3_vec_init as *const ();
            let init_fn: SqliteAutoExtensionFn = std::mem::transmute(init_fn_ptr);
            rusqlite::ffi::sqlite3_auto_extension(Some(init_fn));
        });

        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL,
                channel TEXT,
                external_chat_id TEXT
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT NOT NULL,
                chat_id INTEGER NOT NULL,
                sender_name TEXT NOT NULL,
                content TEXT NOT NULL,
                is_from_bot INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (id, chat_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_chat_timestamp
                ON messages(chat_id, timestamp);

            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                prompt TEXT NOT NULL,
                schedule_type TEXT NOT NULL DEFAULT 'cron',
                schedule_value TEXT NOT NULL,
                timezone TEXT NOT NULL DEFAULT '',
                next_run TEXT NOT NULL,
                last_run TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                exit_criteria TEXT,
                run_count INTEGER NOT NULL DEFAULT 0,
                max_runs INTEGER,
                not_after TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_status_next
                ON scheduled_tasks(status, next_run);

            CREATE TABLE IF NOT EXISTS task_run_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                success INTEGER NOT NULL DEFAULT 1,
                result_summary TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_task_run_logs_task_id
                ON task_run_logs(task_id);

            CREATE TABLE IF NOT EXISTS scheduled_task_dlq (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                failed_at TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                error_summary TEXT,
                replayed_at TEXT,
                replay_note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scheduled_task_dlq_task_failed
                ON scheduled_task_dlq(task_id, failed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scheduled_task_dlq_chat_failed
                ON scheduled_task_dlq(chat_id, failed_at DESC);

            CREATE TABLE IF NOT EXISTS sessions (
                chat_id INTEGER PRIMARY KEY,
                messages_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                label TEXT,
                thinking_level TEXT,
                verbose_level TEXT,
                reasoning_level TEXT,
                skill_envs_json TEXT,
                parent_session_key TEXT,
                fork_point INTEGER
            );

            CREATE TABLE IF NOT EXISTS llm_usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                caller_channel TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                total_tokens INTEGER NOT NULL,
                request_kind TEXT NOT NULL DEFAULT 'agent_loop',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_llm_usage_chat_created
                ON llm_usage_logs(chat_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_llm_usage_created
                ON llm_usage_logs(created_at);

            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                embedding_model TEXT,
                confidence REAL NOT NULL DEFAULT 0.70,
                source TEXT NOT NULL DEFAULT 'legacy',
                last_seen_at TEXT NOT NULL,
                is_archived INTEGER NOT NULL DEFAULT 0,
                archived_at TEXT,
                chat_channel TEXT,
                external_chat_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_memories_chat ON memories(chat_id);

            CREATE TABLE IF NOT EXISTS memory_reflector_state (
                chat_id INTEGER PRIMARY KEY,
                last_reflected_ts TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS memory_reflector_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                extracted_count INTEGER NOT NULL DEFAULT 0,
                inserted_count INTEGER NOT NULL DEFAULT 0,
                updated_count INTEGER NOT NULL DEFAULT 0,
                skipped_count INTEGER NOT NULL DEFAULT 0,
                dedup_method TEXT NOT NULL,
                parse_ok INTEGER NOT NULL DEFAULT 1,
                error_text TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_memory_reflector_runs_chat_started
                ON memory_reflector_runs(chat_id, started_at);

            CREATE TABLE IF NOT EXISTS memory_injection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                retrieval_method TEXT NOT NULL,
                candidate_count INTEGER NOT NULL DEFAULT 0,
                selected_count INTEGER NOT NULL DEFAULT 0,
                omitted_count INTEGER NOT NULL DEFAULT 0,
                tokens_est INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_memory_injection_logs_chat_created
                ON memory_injection_logs(chat_id, created_at);

            CREATE TABLE IF NOT EXISTS auth_passwords (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                session_id TEXT PRIMARY KEY,
                label TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                last_used_at TEXT,
                expires_at TEXT,
                rotated_from_key_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS api_key_scopes (
                api_key_id INTEGER NOT NULL,
                scope TEXT NOT NULL,
                PRIMARY KEY (api_key_id, scope)
            );
            CREATE INDEX IF NOT EXISTS idx_api_key_scopes_scope ON api_key_scopes(scope);

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_logs_kind_created
                ON audit_logs(kind, created_at DESC);

            CREATE TABLE IF NOT EXISTS metrics_history (
                timestamp_ms INTEGER PRIMARY KEY,
                llm_completions INTEGER NOT NULL DEFAULT 0,
                llm_input_tokens INTEGER NOT NULL DEFAULT 0,
                llm_output_tokens INTEGER NOT NULL DEFAULT 0,
                http_requests INTEGER NOT NULL DEFAULT 0,
                tool_executions INTEGER NOT NULL DEFAULT 0,
                mcp_calls INTEGER NOT NULL DEFAULT 0,
                mcp_rate_limited_rejections INTEGER NOT NULL DEFAULT 0,
                mcp_bulkhead_rejections INTEGER NOT NULL DEFAULT 0,
                mcp_circuit_open_rejections INTEGER NOT NULL DEFAULT 0,
                active_sessions INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp_ms);
            ",
        )?;

        ensure_chat_identity_schema(&conn)?;
        ensure_memory_schema(&conn)?;
        ensure_sessions_schema(&conn)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_active_updated ON memories(is_archived, updated_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_confidence ON memories(confidence)",
            [],
        )?;
        // Composite index for archive_excess_memories: covers capacity enforcement queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_chat_active_confidence ON memories(chat_id, is_archived, confidence, last_seen_at)",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )?;
        apply_schema_migrations(&conn)?;

        Ok(Database {
            conn: Mutex::new(conn),
        })
    }

    pub fn upsert_chat(
        &self,
        chat_id: i64,
        chat_title: Option<&str>,
        chat_type: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO chats (chat_id, chat_title, chat_type, last_message_time, channel, external_chat_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
                chat_title = COALESCE(?2, chat_title),
                chat_type = ?3,
                last_message_time = ?4,
                channel = COALESCE(channel, ?5),
                external_chat_id = COALESCE(external_chat_id, ?6)",
            params![
                chat_id,
                chat_title,
                chat_type,
                now,
                infer_channel_from_chat_type(chat_type),
                chat_id.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn resolve_or_create_chat_id(
        &self,
        channel: &str,
        external_chat_id: &str,
        chat_title: Option<&str>,
        chat_type: &str,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();

        if let Some(chat_id) = conn
            .query_row(
                "SELECT chat_id FROM chats WHERE channel = ?1 AND external_chat_id = ?2 LIMIT 1",
                params![channel, external_chat_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            conn.execute(
                "UPDATE chats
                 SET chat_title = COALESCE(?2, chat_title),
                     chat_type = ?3,
                     last_message_time = ?4
                 WHERE chat_id = ?1",
                params![chat_id, chat_title, chat_type, now],
            )?;
            return Ok(chat_id);
        }

        let preferred_chat_id = external_chat_id.parse::<i64>().ok();
        if let Some(cid) = preferred_chat_id {
            let occupied = conn
                .query_row(
                    "SELECT 1 FROM chats WHERE chat_id = ?1 LIMIT 1",
                    params![cid],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !occupied {
                conn.execute(
                    "INSERT INTO chats(chat_id, chat_title, chat_type, last_message_time, channel, external_chat_id)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![cid, chat_title, chat_type, now, channel, external_chat_id],
                )?;
                return Ok(cid);
            }
        }

        conn.execute(
            "INSERT INTO chats(chat_title, chat_type, last_message_time, channel, external_chat_id)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![chat_title, chat_type, now, channel, external_chat_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn store_message(&self, msg: &StoredMessage) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT OR REPLACE INTO messages (id, chat_id, sender_name, content, is_from_bot, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg.id,
                msg.chat_id,
                msg.sender_name,
                msg.content,
                msg.is_from_bot as i32,
                msg.timestamp,
            ],
        )?;
        Ok(())
    }

    pub fn store_message_if_new(&self, msg: &StoredMessage) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let affected = conn.execute(
            "INSERT OR IGNORE INTO messages (id, chat_id, sender_name, content, is_from_bot, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg.id,
                msg.chat_id,
                msg.sender_name,
                msg.content,
                msg.is_from_bot as i32,
                msg.timestamp,
            ],
        )?;
        Ok(affected > 0)
    }

    pub fn message_exists(&self, chat_id: i64, message_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let exists = conn
            .query_row(
                "SELECT 1 FROM messages WHERE chat_id = ?1 AND id = ?2 LIMIT 1",
                params![chat_id, message_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn get_recent_messages(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
             FROM messages
             WHERE chat_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let messages = stmt
            .query_map(params![chat_id, limit as i64], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    sender_name: row.get(2)?,
                    content: row.get(3)?,
                    is_from_bot: row.get::<_, i32>(4)? != 0,
                    timestamp: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Reverse so oldest first
        let mut messages = messages;
        messages.reverse();
        Ok(messages)
    }

    pub fn get_all_messages(&self, chat_id: i64) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
             FROM messages
             WHERE chat_id = ?1
             ORDER BY timestamp ASC",
        )?;
        let messages = stmt
            .query_map(params![chat_id], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    sender_name: row.get(2)?,
                    content: row.get(3)?,
                    is_from_bot: row.get::<_, i32>(4)? != 0,
                    timestamp: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    pub fn get_chats_by_type(
        &self,
        chat_type: &str,
        limit: usize,
    ) -> Result<Vec<ChatSummary>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT
                c.chat_id,
                c.chat_title,
                s.label,
                c.chat_type,
                c.last_message_time,
                (
                    SELECT m.content
                    FROM messages m
                    WHERE m.chat_id = c.chat_id
                    ORDER BY m.timestamp DESC
                    LIMIT 1
                ) AS last_message_preview
             FROM chats c
             LEFT JOIN sessions s ON s.chat_id = c.chat_id
             WHERE c.chat_type = ?1
             ORDER BY c.last_message_time DESC
             LIMIT ?2",
        )?;
        let chats = stmt
            .query_map(params![chat_type, limit as i64], |row| {
                Ok(ChatSummary {
                    chat_id: row.get(0)?,
                    chat_title: row.get(1)?,
                    session_label: row.get(2)?,
                    chat_type: row.get(3)?,
                    last_message_time: row.get(4)?,
                    last_message_preview: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(chats)
    }

    pub fn get_recent_chats(&self, limit: usize) -> Result<Vec<ChatSummary>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT
                c.chat_id,
                c.chat_title,
                s.label,
                c.chat_type,
                c.last_message_time,
                (
                    SELECT m.content
                    FROM messages m
                    WHERE m.chat_id = c.chat_id
                    ORDER BY m.timestamp DESC
                    LIMIT 1
                ) AS last_message_preview
             FROM chats c
             LEFT JOIN sessions s ON s.chat_id = c.chat_id
             ORDER BY c.last_message_time DESC
             LIMIT ?1",
        )?;
        let chats = stmt
            .query_map(params![limit as i64], |row| {
                Ok(ChatSummary {
                    chat_id: row.get(0)?,
                    chat_title: row.get(1)?,
                    session_label: row.get(2)?,
                    chat_type: row.get(3)?,
                    last_message_time: row.get(4)?,
                    last_message_preview: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(chats)
    }

    pub fn get_chat_type(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT chat_type FROM chats WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_chat_id_by_channel_and_title(
        &self,
        channel: &str,
        chat_title: &str,
    ) -> Result<Option<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT chat_id
             FROM chats
             WHERE channel = ?1 AND chat_title = ?2
             ORDER BY last_message_time DESC
             LIMIT 1",
            params![channel, chat_title],
            |row| row.get::<_, i64>(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_chat_channel(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT channel FROM chats WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, Option<String>>(0),
        );
        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_chat_external_id(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT external_chat_id FROM chats WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, Option<String>>(0),
        );
        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get messages since the bot's last response in this chat.
    /// Falls back to `fallback_limit` most recent messages if bot never responded.
    pub fn get_messages_since_last_bot_response(
        &self,
        chat_id: i64,
        max: usize,
        fallback: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();

        // Find timestamp of last bot message
        let last_bot_ts: Option<String> = conn
            .query_row(
                "SELECT timestamp FROM messages
                 WHERE chat_id = ?1 AND is_from_bot = 1
                 ORDER BY timestamp DESC LIMIT 1",
                params![chat_id],
                |row| row.get(0),
            )
            .ok();

        let mut messages = if let Some(ts) = last_bot_ts {
            let mut stmt = conn.prepare(
                "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
                 FROM messages
                 WHERE chat_id = ?1 AND timestamp >= ?2
                 ORDER BY timestamp DESC
                 LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(params![chat_id, ts, max as i64], |row| {
                    Ok(StoredMessage {
                        id: row.get(0)?,
                        chat_id: row.get(1)?,
                        sender_name: row.get(2)?,
                        content: row.get(3)?,
                        is_from_bot: row.get::<_, i32>(4)? != 0,
                        timestamp: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
                 FROM messages
                 WHERE chat_id = ?1
                 ORDER BY timestamp DESC
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(params![chat_id, fallback as i64], |row| {
                    Ok(StoredMessage {
                        id: row.get(0)?,
                        chat_id: row.get(1)?,
                        sender_name: row.get(2)?,
                        content: row.get(3)?,
                        is_from_bot: row.get::<_, i32>(4)? != 0,
                        timestamp: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        messages.reverse();
        Ok(messages)
    }

    // --- Scheduled tasks ---

    pub fn create_scheduled_task(
        &self,
        chat_id: i64,
        prompt: &str,
        schedule_type: &str,
        schedule_value: &str,
        next_run: &str,
    ) -> Result<i64, MicroClawError> {
        self.create_scheduled_task_with_timezone(
            chat_id,
            prompt,
            schedule_type,
            schedule_value,
            "",
            next_run,
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub fn create_learning_track(
        &self,
        chat_id: i64,
        name: &str,
        objective: &str,
        directions: &serde_json::Value,
        allowed_sources: &serde_json::Value,
        schedule: &str,
        timezone: &str,
        token_budget: i64,
        max_sources: i64,
        promotion_mode: &str,
        next_run: &str,
    ) -> Result<String, MicroClawError> {
        if name.trim().is_empty()
            || name.len() > 96
            || objective.trim().is_empty()
            || objective.len() > 8_000
            || schedule.trim().is_empty()
            || !matches!(promotion_mode, "propose" | "manual")
            || !(1_000..=2_000_000).contains(&token_budget)
            || !(1..=100).contains(&max_sources)
        {
            return Err(MicroClawError::ToolExecution(
                "invalid learning track configuration".into(),
            ));
        }
        let track_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO learning_tracks(
                track_id, chat_id, name, objective, directions_json,
                allowed_sources_json, schedule, timezone, token_budget,
                max_sources, promotion_mode, status, next_run, created_at,
                updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'active',?12,?13,?13)",
            params![
                track_id,
                chat_id,
                name.trim(),
                objective.trim(),
                directions.to_string(),
                allowed_sources.to_string(),
                schedule,
                timezone,
                token_budget,
                max_sources,
                promotion_mode,
                next_run,
                now
            ],
        )?;
        Ok(track_id)
    }

    pub fn list_learning_tracks(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<LearningTrack>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT track_id, chat_id, name, objective, directions_json,
                    allowed_sources_json, schedule, timezone, token_budget,
                    max_sources, promotion_mode, status, next_run, last_run,
                    created_at, updated_at
             FROM learning_tracks
             WHERE (?1 IS NULL OR chat_id=?1)
             ORDER BY updated_at DESC",
        )?;
        let rows = stmt
            .query_map(params![chat_id], map_learning_track)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn learning_track_belongs_to_chat(
        &self,
        track_id: &str,
        chat_id: i64,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM learning_tracks WHERE track_id=?1 AND chat_id=?2",
            params![track_id, chat_id],
            |row| row.get(0),
        )?;
        Ok(count == 1)
    }

    pub fn update_learning_track_status(
        &self,
        track_id: &str,
        status: &str,
        next_run: Option<&str>,
    ) -> Result<bool, MicroClawError> {
        if !matches!(status, "active" | "paused" | "archived") {
            return Err(MicroClawError::ToolExecution(
                "invalid learning track status".into(),
            ));
        }
        let conn = self.lock_conn();
        let changed = conn.execute(
            "UPDATE learning_tracks SET status=?2,
                 next_run=COALESCE(?3,next_run), updated_at=?4
             WHERE track_id=?1",
            params![track_id, status, next_run, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(changed == 1)
    }

    /// Atomically moves due tracks into the future before returning them.
    /// This provides at-most-once claiming per process tick; crashed epochs
    /// remain visible and the next scheduled epoch can proceed normally.
    pub fn claim_due_learning_tracks(
        &self,
        now: &str,
        next_runs: &[(String, String)],
    ) -> Result<Vec<LearningTrack>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let mut claimed = Vec::new();
        for (track_id, next_run) in next_runs {
            let changed = tx.execute(
                "UPDATE learning_tracks SET next_run=?3, last_run=?2,
                     updated_at=?2
                 WHERE track_id=?1 AND status='active' AND next_run<=?2",
                params![track_id, now, next_run],
            )?;
            if changed == 1 {
                claimed.push(tx.query_row(
                    "SELECT track_id, chat_id, name, objective, directions_json,
                            allowed_sources_json, schedule, timezone, token_budget,
                            max_sources, promotion_mode, status, next_run, last_run,
                            created_at, updated_at
                     FROM learning_tracks WHERE track_id=?1",
                    params![track_id],
                    map_learning_track,
                )?);
            }
        }
        tx.commit()?;
        Ok(claimed)
    }

    pub fn start_learning_epoch(
        &self,
        track_id: &str,
        experience_run_id: &str,
    ) -> Result<String, MicroClawError> {
        let epoch_id = uuid::Uuid::new_v4().to_string();
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO learning_epochs(
                epoch_id, track_id, experience_run_id, status, started_at
             ) VALUES (?1,?2,?3,'running',?4)",
            params![
                epoch_id,
                track_id,
                experience_run_id,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(epoch_id)
    }

    pub fn finish_learning_epoch(
        &self,
        epoch_id: &str,
        status: &str,
        report: Option<&str>,
        candidate_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), MicroClawError> {
        if !matches!(status, "completed" | "failed" | "no_candidate") {
            return Err(MicroClawError::ToolExecution(
                "invalid learning epoch status".into(),
            ));
        }
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE learning_epochs SET status=?2, report=?3,
                 candidate_id=?4, error=?5, finished_at=?6
             WHERE epoch_id=?1",
            params![
                epoch_id,
                status,
                report,
                candidate_id,
                error,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    pub fn create_learning_track_candidate(
        &self,
        epoch_id: &str,
        skill_name: &str,
        description: &str,
        instructions: &str,
        sources: &serde_json::Value,
        tests: &serde_json::Value,
        risk: &str,
    ) -> Result<String, MicroClawError> {
        if skill_name.trim().is_empty()
            || description.trim().is_empty()
            || instructions.trim().is_empty()
            || !matches!(risk, "low" | "medium" | "high")
        {
            return Err(MicroClawError::ToolExecution(
                "invalid learning candidate".into(),
            ));
        }
        use sha2::{Digest, Sha256};
        let content_hash = to_hex(&Sha256::digest(instructions.as_bytes()));
        let candidate_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO learning_track_candidates(
                candidate_id, epoch_id, skill_name, description, instructions,
                sources_json, tests_json, risk, content_hash, status,
                created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',?10,?10)",
            params![
                candidate_id,
                epoch_id,
                skill_name,
                description,
                instructions,
                sources.to_string(),
                tests.to_string(),
                risk,
                content_hash,
                now
            ],
        )?;
        Ok(candidate_id)
    }

    pub fn list_learning_epochs(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<LearningEpoch>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT e.epoch_id, e.track_id, e.experience_run_id, e.status,
                    e.report, e.candidate_id, e.error, e.started_at, e.finished_at
             FROM learning_epochs e
             JOIN learning_tracks t ON t.track_id=e.track_id
             WHERE t.chat_id=?1 ORDER BY e.started_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 200) as i64], |row| {
                Ok(LearningEpoch {
                    epoch_id: row.get(0)?,
                    track_id: row.get(1)?,
                    experience_run_id: row.get(2)?,
                    status: row.get(3)?,
                    report: row.get(4)?,
                    candidate_id: row.get(5)?,
                    error: row.get(6)?,
                    started_at: row.get(7)?,
                    finished_at: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_learning_track_candidates(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<LearningTrackCandidate>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT c.candidate_id, c.epoch_id, c.skill_name, c.description,
                    c.instructions, c.sources_json, c.tests_json, c.risk,
                    c.content_hash, c.status, c.created_at, c.updated_at
             FROM learning_track_candidates c
             JOIN learning_epochs e ON e.epoch_id=c.epoch_id
             JOIN learning_tracks t ON t.track_id=e.track_id
             WHERE t.chat_id=?1 ORDER BY c.updated_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 200) as i64], |row| {
                let sources: String = row.get(5)?;
                let tests: String = row.get(6)?;
                Ok(LearningTrackCandidate {
                    candidate_id: row.get(0)?,
                    epoch_id: row.get(1)?,
                    skill_name: row.get(2)?,
                    description: row.get(3)?,
                    instructions: row.get(4)?,
                    sources: serde_json::from_str(&sources).unwrap_or_default(),
                    tests: serde_json::from_str(&tests).unwrap_or_default(),
                    risk: row.get(7)?,
                    content_hash: row.get(8)?,
                    status: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_learning_track_candidate(
        &self,
        candidate_id: &str,
        chat_id: i64,
    ) -> Result<Option<LearningTrackCandidate>, MicroClawError> {
        Ok(self
            .list_learning_track_candidates(chat_id, 200)?
            .into_iter()
            .find(|candidate| candidate.candidate_id == candidate_id))
    }

    pub fn update_learning_track_candidate_status(
        &self,
        candidate_id: &str,
        status: &str,
    ) -> Result<bool, MicroClawError> {
        if !matches!(
            status,
            "pending"
                | "evaluating"
                | "evaluation_passed"
                | "evaluation_failed"
                | "promoted"
                | "rejected"
        ) {
            return Err(MicroClawError::ToolExecution(
                "invalid learning candidate status".into(),
            ));
        }
        let conn = self.lock_conn();
        let changed = conn.execute(
            "UPDATE learning_track_candidates SET status=?2, updated_at=?3
             WHERE candidate_id=?1",
            params![candidate_id, status, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(changed == 1)
    }

    pub fn start_learning_candidate_evaluation(
        &self,
        candidate_id: &str,
    ) -> Result<String, MicroClawError> {
        let evaluation_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE learning_track_candidates SET status='evaluating', updated_at=?2
             WHERE candidate_id=?1 AND status IN ('pending','evaluation_failed')",
            params![candidate_id, now],
        )?;
        if changed != 1 {
            return Err(MicroClawError::ToolExecution(
                "learning candidate is not eligible for evaluation".into(),
            ));
        }
        tx.execute(
            "DELETE FROM learning_candidate_trials WHERE evaluation_id IN
             (SELECT evaluation_id FROM learning_candidate_evaluations WHERE candidate_id=?1)",
            params![candidate_id],
        )?;
        tx.execute(
            "DELETE FROM learning_candidate_evaluations WHERE candidate_id=?1",
            params![candidate_id],
        )?;
        tx.execute(
            "INSERT INTO learning_candidate_evaluations(
                evaluation_id,candidate_id,status,started_at
             ) VALUES (?1,?2,'running',?3)",
            params![evaluation_id, candidate_id, now],
        )?;
        tx.commit()?;
        Ok(evaluation_id)
    }

    #[expect(clippy::too_many_arguments)]
    pub fn record_learning_candidate_trial(
        &self,
        evaluation_id: &str,
        test_name: &str,
        baseline_passed: bool,
        candidate_passed: bool,
        baseline_tokens: i64,
        candidate_tokens: i64,
        baseline_duration_ms: i64,
        candidate_duration_ms: i64,
        evidence: &serde_json::Value,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO learning_candidate_trials(
                trial_id,evaluation_id,test_name,baseline_passed,candidate_passed,
                baseline_tokens,candidate_tokens,baseline_duration_ms,
                candidate_duration_ms,evidence_json,created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                uuid::Uuid::new_v4().to_string(),
                evaluation_id,
                test_name,
                baseline_passed as i64,
                candidate_passed as i64,
                baseline_tokens.max(0),
                candidate_tokens.max(0),
                baseline_duration_ms.max(0),
                candidate_duration_ms.max(0),
                evidence.to_string(),
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn finish_learning_candidate_evaluation(
        &self,
        evaluation_id: &str,
        passed: bool,
        reason: &str,
    ) -> Result<LearningCandidateEvaluation, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let totals: (i64, i64, i64, i64, i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(baseline_passed),0),
                    COALESCE(SUM(candidate_passed),0),
                    COALESCE(SUM(CASE WHEN baseline_passed=1 AND candidate_passed=0 THEN 1 ELSE 0 END),0),
                    COALESCE(SUM(baseline_tokens),0), COALESCE(SUM(candidate_tokens),0)
             FROM learning_candidate_trials WHERE evaluation_id=?1",
            params![evaluation_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        )?;
        let durations: (i64, i64) = tx.query_row(
            "SELECT COALESCE(SUM(baseline_duration_ms),0),COALESCE(SUM(candidate_duration_ms),0)
             FROM learning_candidate_trials WHERE evaluation_id=?1",
            params![evaluation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let status = if passed { "passed" } else { "failed" };
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE learning_candidate_evaluations SET status=?2,sample_count=?3,
                baseline_passed=?4,candidate_passed=?5,regression_count=?6,
                baseline_tokens=?7,candidate_tokens=?8,baseline_duration_ms=?9,
                candidate_duration_ms=?10,reason=?11,finished_at=?12
             WHERE evaluation_id=?1 AND status='running'",
            params![
                evaluation_id,
                status,
                totals.0,
                totals.1,
                totals.2,
                totals.3,
                totals.4,
                totals.5,
                durations.0,
                durations.1,
                reason,
                now
            ],
        )?;
        tx.execute(
            "UPDATE learning_track_candidates SET status=?2,updated_at=?3
             WHERE candidate_id=(SELECT candidate_id FROM learning_candidate_evaluations WHERE evaluation_id=?1)",
            params![evaluation_id, if passed { "evaluation_passed" } else { "evaluation_failed" }, now],
        )?;
        tx.commit()?;
        drop(conn);
        self.get_learning_candidate_evaluation_by_id(evaluation_id)?
            .ok_or_else(|| MicroClawError::ToolExecution("evaluation disappeared".into()))
    }

    fn get_learning_candidate_evaluation_by_id(
        &self,
        evaluation_id: &str,
    ) -> Result<Option<LearningCandidateEvaluation>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT evaluation_id,candidate_id,status,sample_count,baseline_passed,
                    candidate_passed,regression_count,baseline_tokens,candidate_tokens,
                    baseline_duration_ms,candidate_duration_ms,reason,started_at,finished_at
             FROM learning_candidate_evaluations WHERE evaluation_id=?1",
            params![evaluation_id],
            |row| {
                Ok(LearningCandidateEvaluation {
                    evaluation_id: row.get(0)?,
                    candidate_id: row.get(1)?,
                    status: row.get(2)?,
                    sample_count: row.get(3)?,
                    baseline_passed: row.get(4)?,
                    candidate_passed: row.get(5)?,
                    regression_count: row.get(6)?,
                    baseline_tokens: row.get(7)?,
                    candidate_tokens: row.get(8)?,
                    baseline_duration_ms: row.get(9)?,
                    candidate_duration_ms: row.get(10)?,
                    reason: row.get(11)?,
                    started_at: row.get(12)?,
                    finished_at: row.get(13)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_learning_candidate_evaluations(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<LearningCandidateEvaluation>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT v.evaluation_id,v.candidate_id,v.status,v.sample_count,
                    v.baseline_passed,v.candidate_passed,v.regression_count,
                    v.baseline_tokens,v.candidate_tokens,v.baseline_duration_ms,
                    v.candidate_duration_ms,v.reason,v.started_at,v.finished_at
             FROM learning_candidate_evaluations v
             JOIN learning_track_candidates c ON c.candidate_id=v.candidate_id
             JOIN learning_epochs e ON e.epoch_id=c.epoch_id
             JOIN learning_tracks t ON t.track_id=e.track_id
             WHERE t.chat_id=?1 ORDER BY v.started_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 200) as i64], |row| {
                Ok(LearningCandidateEvaluation {
                    evaluation_id: row.get(0)?,
                    candidate_id: row.get(1)?,
                    status: row.get(2)?,
                    sample_count: row.get(3)?,
                    baseline_passed: row.get(4)?,
                    candidate_passed: row.get(5)?,
                    regression_count: row.get(6)?,
                    baseline_tokens: row.get(7)?,
                    candidate_tokens: row.get(8)?,
                    baseline_duration_ms: row.get(9)?,
                    candidate_duration_ms: row.get(10)?,
                    reason: row.get(11)?,
                    started_at: row.get(12)?,
                    finished_at: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_learning_candidate_trials(
        &self,
        evaluation_id: &str,
    ) -> Result<Vec<LearningCandidateTrial>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT trial_id,evaluation_id,test_name,baseline_passed,candidate_passed,
                    baseline_tokens,candidate_tokens,baseline_duration_ms,
                    candidate_duration_ms,evidence_json,created_at
             FROM learning_candidate_trials WHERE evaluation_id=?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map(params![evaluation_id], |row| {
                let evidence: String = row.get(9)?;
                Ok(LearningCandidateTrial {
                    trial_id: row.get(0)?,
                    evaluation_id: row.get(1)?,
                    test_name: row.get(2)?,
                    baseline_passed: row.get::<_, i64>(3)? != 0,
                    candidate_passed: row.get::<_, i64>(4)? != 0,
                    baseline_tokens: row.get(5)?,
                    candidate_tokens: row.get(6)?,
                    baseline_duration_ms: row.get(7)?,
                    candidate_duration_ms: row.get(8)?,
                    evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                    created_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn create_scheduled_task_with_timezone(
        &self,
        chat_id: i64,
        prompt: &str,
        schedule_type: &str,
        schedule_value: &str,
        timezone: &str,
        next_run: &str,
    ) -> Result<i64, MicroClawError> {
        self.create_scheduled_task_full(
            chat_id,
            prompt,
            schedule_type,
            schedule_value,
            timezone,
            next_run,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_scheduled_task_full(
        &self,
        chat_id: i64,
        prompt: &str,
        schedule_type: &str,
        schedule_value: &str,
        timezone: &str,
        next_run: &str,
        exit_criteria: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        self.create_scheduled_task_lifecycle(
            chat_id,
            prompt,
            schedule_type,
            schedule_value,
            timezone,
            next_run,
            exit_criteria,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_scheduled_task_lifecycle(
        &self,
        chat_id: i64,
        prompt: &str,
        schedule_type: &str,
        schedule_value: &str,
        timezone: &str,
        next_run: &str,
        exit_criteria: Option<&str>,
        max_runs: Option<i64>,
        not_after: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO scheduled_tasks (chat_id, prompt, schedule_type, schedule_value, timezone, next_run, status, created_at, exit_criteria, max_runs, not_after)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?8, ?9, ?10)",
            params![
                chat_id,
                prompt,
                schedule_type,
                schedule_value,
                timezone,
                next_run,
                now,
                exit_criteria,
                max_runs,
                not_after
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_due_tasks(&self, now: &str) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, timezone, next_run, last_run, status, created_at, exit_criteria, run_count, max_runs, not_after
             FROM scheduled_tasks
             WHERE status = 'active' AND next_run <= ?1",
        )?;
        let tasks = stmt
            .query_map(params![now], |row| {
                Ok(ScheduledTask {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    prompt: row.get(2)?,
                    schedule_type: row.get(3)?,
                    schedule_value: row.get(4)?,
                    timezone: row.get(5)?,
                    next_run: row.get(6)?,
                    last_run: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    exit_criteria: row.get(10)?,
                    run_count: row.get(11)?,
                    max_runs: row.get(12)?,
                    not_after: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tasks)
    }

    pub fn claim_due_tasks(
        &self,
        now: &str,
        limit: usize,
    ) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;

        let mut stmt = tx.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, timezone, next_run, last_run, status, created_at, exit_criteria, run_count, max_runs, not_after
             FROM scheduled_tasks
             WHERE status = 'active' AND next_run <= ?1
             ORDER BY next_run ASC, id ASC
             LIMIT ?2",
        )?;
        let candidates = stmt
            .query_map(params![now, limit as i64], |row| {
                Ok(ScheduledTask {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    prompt: row.get(2)?,
                    schedule_type: row.get(3)?,
                    schedule_value: row.get(4)?,
                    timezone: row.get(5)?,
                    next_run: row.get(6)?,
                    last_run: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    exit_criteria: row.get(10)?,
                    run_count: row.get(11)?,
                    max_runs: row.get(12)?,
                    not_after: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let mut claimed = Vec::new();
        for task in candidates {
            let rows = tx.execute(
                "UPDATE scheduled_tasks
                 SET status = 'running'
                 WHERE id = ?1 AND status = 'active' AND next_run <= ?2",
                params![task.id, now],
            )?;
            if rows > 0 {
                let mut claimed_task = task;
                claimed_task.status = "running".to_string();
                claimed.push(claimed_task);
            }
        }

        tx.commit()?;
        Ok(claimed)
    }

    pub fn get_tasks_for_chat(&self, chat_id: i64) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, timezone, next_run, last_run, status, created_at, exit_criteria, run_count, max_runs, not_after
             FROM scheduled_tasks
             WHERE chat_id = ?1 AND status IN ('active', 'paused')
             ORDER BY id",
        )?;
        let tasks = stmt
            .query_map(params![chat_id], |row| {
                Ok(ScheduledTask {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    prompt: row.get(2)?,
                    schedule_type: row.get(3)?,
                    schedule_value: row.get(4)?,
                    timezone: row.get(5)?,
                    next_run: row.get(6)?,
                    last_run: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    exit_criteria: row.get(10)?,
                    run_count: row.get(11)?,
                    max_runs: row.get(12)?,
                    not_after: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tasks)
    }

    /// List scheduled tasks across all chats for management views.
    /// `status` filters to one status; `None` returns every task. Newest first.
    pub fn list_scheduled_tasks(
        &self,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, timezone, next_run, last_run, status, created_at, exit_criteria, run_count, max_runs, not_after
             FROM scheduled_tasks
             WHERE (?1 IS NULL OR status = ?1)
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let tasks = stmt
            .query_map(params![status, limit as i64], |row| {
                Ok(ScheduledTask {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    prompt: row.get(2)?,
                    schedule_type: row.get(3)?,
                    schedule_value: row.get(4)?,
                    timezone: row.get(5)?,
                    next_run: row.get(6)?,
                    last_run: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    exit_criteria: row.get(10)?,
                    run_count: row.get(11)?,
                    max_runs: row.get(12)?,
                    not_after: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tasks)
    }

    pub fn get_task_by_id(&self, task_id: i64) -> Result<Option<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, timezone, next_run, last_run, status, created_at, exit_criteria, run_count, max_runs, not_after
             FROM scheduled_tasks
             WHERE id = ?1",
            params![task_id],
            |row| {
                Ok(ScheduledTask {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    prompt: row.get(2)?,
                    schedule_type: row.get(3)?,
                    schedule_value: row.get(4)?,
                    timezone: row.get(5)?,
                    next_run: row.get(6)?,
                    last_run: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    exit_criteria: row.get(10)?,
                    run_count: row.get(11)?,
                    max_runs: row.get(12)?,
                    not_after: row.get(13)?,
                })
            },
        );
        match result {
            Ok(task) => Ok(Some(task)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Fetch one scheduled task by id regardless of status (management/
    /// detail views and tests need retired tasks too).
    pub fn get_scheduled_task(
        &self,
        task_id: i64,
    ) -> Result<Option<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, timezone, next_run, last_run, status, created_at, exit_criteria, run_count, max_runs, not_after
             FROM scheduled_tasks WHERE id = ?1",
        )?;
        let task = stmt
            .query_map(params![task_id], |row| {
                Ok(ScheduledTask {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    prompt: row.get(2)?,
                    schedule_type: row.get(3)?,
                    schedule_value: row.get(4)?,
                    timezone: row.get(5)?,
                    next_run: row.get(6)?,
                    last_run: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    exit_criteria: row.get(10)?,
                    run_count: row.get(11)?,
                    max_runs: row.get(12)?,
                    not_after: row.get(13)?,
                })
            })?
            .next()
            .transpose()?;
        Ok(task)
    }

    pub fn update_task_status(&self, task_id: i64, status: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE scheduled_tasks SET status = ?1 WHERE id = ?2",
            params![status, task_id],
        )?;
        Ok(rows > 0)
    }

    pub fn requeue_scheduled_task(
        &self,
        task_id: i64,
        next_run: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE scheduled_tasks
             SET status = 'active', next_run = ?1
             WHERE id = ?2",
            params![next_run, task_id],
        )?;
        Ok(rows > 0)
    }

    pub fn update_task_after_run(
        &self,
        task_id: i64,
        last_run: &str,
        next_run: Option<&str>,
        success: bool,
    ) -> Result<(), MicroClawError> {
        self.update_task_after_run_lifecycle(task_id, last_run, next_run, success, false)
    }

    /// `lifecycle_finished` marks a RECURRING task that just retired on
    /// purpose (max_runs reached / not_after passed): it becomes `completed`
    /// regardless of this run's outcome, so DLQ auto-replay never resurrects
    /// a task whose lifecycle has ended. `run_count` increments on every run.
    pub fn update_task_after_run_lifecycle(
        &self,
        task_id: i64,
        last_run: &str,
        next_run: Option<&str>,
        success: bool,
        lifecycle_finished: bool,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        match next_run {
            Some(next) => {
                // Recurring task: reschedule and stay active regardless of this
                // run's outcome (a transient failure retries on the next tick).
                conn.execute(
                    "UPDATE scheduled_tasks
                     SET last_run = ?1, next_run = ?2, status = 'active',
                         run_count = run_count + 1
                     WHERE id = ?3",
                    params![last_run, next, task_id],
                )?;
            }
            None => {
                // One-shot task: reflect the actual outcome. A failed one-shot
                // becomes 'failed' (and is recorded in the DLQ) rather than
                // masquerading as 'completed'. A lifecycle retirement is always
                // 'completed' — the task did all the running it was asked to.
                let status = if lifecycle_finished || success {
                    "completed"
                } else {
                    "failed"
                };
                conn.execute(
                    "UPDATE scheduled_tasks
                     SET last_run = ?1, status = ?2, run_count = run_count + 1
                     WHERE id = ?3",
                    params![last_run, status, task_id],
                )?;
            }
        }
        Ok(())
    }

    pub fn recover_running_tasks(&self) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE scheduled_tasks
             SET status = 'active'
             WHERE status = 'running'",
            [],
        )?;
        Ok(rows)
    }

    // --- Task run logs ---

    #[allow(clippy::too_many_arguments)]
    pub fn log_task_run(
        &self,
        task_id: i64,
        chat_id: i64,
        started_at: &str,
        finished_at: &str,
        duration_ms: i64,
        success: bool,
        result_summary: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO task_run_logs (task_id, chat_id, started_at, finished_at, duration_ms, success, result_summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                task_id,
                chat_id,
                started_at,
                finished_at,
                duration_ms,
                success as i32,
                result_summary,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_task_run_logs(
        &self,
        task_id: i64,
        limit: usize,
    ) -> Result<Vec<TaskRunLog>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, task_id, chat_id, started_at, finished_at, duration_ms, success, result_summary
             FROM task_run_logs
             WHERE task_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let logs = stmt
            .query_map(params![task_id, limit as i64], |row| {
                Ok(TaskRunLog {
                    id: row.get(0)?,
                    task_id: row.get(1)?,
                    chat_id: row.get(2)?,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get(5)?,
                    success: row.get::<_, i32>(6)? != 0,
                    result_summary: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(logs)
    }

    pub fn get_task_run_summary_since(
        &self,
        since: Option<&str>,
    ) -> Result<(i64, i64), MicroClawError> {
        let conn = self.lock_conn();
        if let Some(since) = since {
            let (total, success): (i64, i64) = conn.query_row(
                "SELECT
                    COUNT(*) AS total_runs,
                    COALESCE(SUM(CASE WHEN success != 0 THEN 1 ELSE 0 END), 0) AS success_runs
                 FROM task_run_logs
                 WHERE started_at >= ?1",
                params![since],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            Ok((total, success))
        } else {
            let (total, success): (i64, i64) = conn.query_row(
                "SELECT
                    COUNT(*) AS total_runs,
                    COALESCE(SUM(CASE WHEN success != 0 THEN 1 ELSE 0 END), 0) AS success_runs
                 FROM task_run_logs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            Ok((total, success))
        }
    }
    pub fn insert_scheduled_task_dlq(
        &self,
        task_id: i64,
        chat_id: i64,
        started_at: &str,
        finished_at: &str,
        duration_ms: i64,
        error_summary: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let failed_at = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO scheduled_task_dlq (
                task_id, chat_id, failed_at, started_at, finished_at, duration_ms, error_summary
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                task_id,
                chat_id,
                failed_at,
                started_at,
                finished_at,
                duration_ms,
                error_summary
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_scheduled_task_dlq(
        &self,
        chat_id: Option<i64>,
        task_id: Option<i64>,
        include_replayed: bool,
        limit: usize,
    ) -> Result<Vec<ScheduledTaskDlqEntry>, MicroClawError> {
        let conn = self.lock_conn();
        let replay_filter = if include_replayed {
            ""
        } else {
            " AND replayed_at IS NULL"
        };
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(ScheduledTaskDlqEntry {
                id: row.get(0)?,
                task_id: row.get(1)?,
                chat_id: row.get(2)?,
                failed_at: row.get(3)?,
                started_at: row.get(4)?,
                finished_at: row.get(5)?,
                duration_ms: row.get(6)?,
                error_summary: row.get(7)?,
                replayed_at: row.get(8)?,
                replay_note: row.get(9)?,
            })
        };
        let query = match (chat_id, task_id) {
            (Some(_), Some(_)) => format!(
                "SELECT id, task_id, chat_id, failed_at, started_at, finished_at, duration_ms,
                        error_summary, replayed_at, replay_note
                 FROM scheduled_task_dlq
                 WHERE chat_id = ?1 AND task_id = ?2{replay_filter}
                 ORDER BY failed_at DESC LIMIT ?3"
            ),
            (Some(_), None) => format!(
                "SELECT id, task_id, chat_id, failed_at, started_at, finished_at, duration_ms,
                        error_summary, replayed_at, replay_note
                 FROM scheduled_task_dlq
                 WHERE chat_id = ?1{replay_filter}
                 ORDER BY failed_at DESC LIMIT ?2"
            ),
            (None, Some(_)) => format!(
                "SELECT id, task_id, chat_id, failed_at, started_at, finished_at, duration_ms,
                        error_summary, replayed_at, replay_note
                 FROM scheduled_task_dlq
                 WHERE task_id = ?1{replay_filter}
                 ORDER BY failed_at DESC LIMIT ?2"
            ),
            (None, None) => format!(
                "SELECT id, task_id, chat_id, failed_at, started_at, finished_at, duration_ms,
                        error_summary, replayed_at, replay_note
                 FROM scheduled_task_dlq
                 WHERE 1=1{replay_filter}
                 ORDER BY failed_at DESC LIMIT ?1"
            ),
        };
        let mut stmt = conn.prepare(&query)?;
        match (chat_id, task_id) {
            (Some(c), Some(t)) => stmt
                .query_map(params![c, t, limit as i64], mapper)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into),
            (Some(c), None) => stmt
                .query_map(params![c, limit as i64], mapper)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into),
            (None, Some(t)) => stmt
                .query_map(params![t, limit as i64], mapper)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into),
            (None, None) => stmt
                .query_map(params![limit as i64], mapper)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into),
        }
    }

    pub fn mark_scheduled_task_dlq_replayed(
        &self,
        dlq_id: i64,
        note: Option<&str>,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let replayed_at = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE scheduled_task_dlq
             SET replayed_at = ?1, replay_note = ?2
             WHERE id = ?3",
            params![replayed_at, note, dlq_id],
        )?;
        Ok(rows > 0)
    }
    #[allow(dead_code)]
    pub fn delete_task(&self, task_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "DELETE FROM scheduled_tasks WHERE id = ?1",
            params![task_id],
        )?;
        Ok(rows > 0)
    }

    // --- Sessions ---

    pub fn save_session(&self, chat_id: i64, messages_json: &str) -> Result<(), MicroClawError> {
        self.save_session_with_meta(chat_id, messages_json, None, None, None)
    }

    pub fn save_session_with_meta(
        &self,
        chat_id: i64,
        messages_json: &str,
        parent_session_key: Option<&str>,
        fork_point: Option<i64>,
        skill_envs_json: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (chat_id, messages_json, updated_at, parent_session_key, fork_point, skill_envs_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
                messages_json = ?2,
                updated_at = ?3,
                parent_session_key = COALESCE(?4, parent_session_key),
                fork_point = COALESCE(?5, fork_point),
                skill_envs_json = COALESCE(?6, skill_envs_json)",
            params![chat_id, messages_json, now, parent_session_key, fork_point, skill_envs_json],
        )?;
        Ok(())
    }

    pub fn save_session_skill_envs(
        &self,
        chat_id: i64,
        skill_envs_json: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE sessions SET skill_envs_json = ?2 WHERE chat_id = ?1",
            params![chat_id, skill_envs_json],
        )?;
        Ok(())
    }

    pub fn load_session(&self, chat_id: i64) -> Result<Option<(String, String)>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT messages_json, updated_at FROM sessions WHERE chat_id = ?1",
            params![chat_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        );
        match result {
            Ok(pair) => Ok(Some(pair)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn load_session_skill_envs(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT skill_envs_json FROM sessions WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, Option<String>>(0),
        );
        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Look up a cached tool result by key; returns `None` if missing or
    /// past its TTL. Passing `now` as an RFC3339 string lets callers
    /// control "now" deterministically in tests.
    pub fn get_cached_tool_result(
        &self,
        cache_key: &str,
        now: &str,
    ) -> Result<Option<CachedToolResult>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT tool_name, result_content, is_error, metadata_json, created_at, expires_at
                 FROM tool_result_cache
                 WHERE cache_key = ?1 AND expires_at > ?2",
                params![cache_key, now],
                |r| {
                    Ok(CachedToolResult {
                        tool_name: r.get(0)?,
                        content: r.get(1)?,
                        is_error: r.get::<_, i64>(2)? != 0,
                        metadata_json: r.get::<_, Option<String>>(3)?,
                        created_at: r.get(4)?,
                        expires_at: r.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Insert or replace a cached tool result. Only non-error results
    /// should be cached in practice; the `is_error` flag is exposed so
    /// callers can choose a policy.
    pub fn put_cached_tool_result(
        &self,
        cache_key: &str,
        tool_name: &str,
        content: &str,
        is_error: bool,
        metadata_json: Option<&str>,
        expires_at: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO tool_result_cache
                (cache_key, tool_name, result_content, is_error, metadata_json, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(cache_key) DO UPDATE SET
                tool_name = excluded.tool_name,
                result_content = excluded.result_content,
                is_error = excluded.is_error,
                metadata_json = excluded.metadata_json,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at",
            params![cache_key, tool_name, content, is_error as i64, metadata_json, now, expires_at],
        )?;
        Ok(())
    }

    /// Delete all expired cache rows. Returns number of rows deleted.
    pub fn prune_tool_result_cache(&self, now: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM tool_result_cache WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
    }

    /// Persist a tool-result artifact (full content) so the agent can fetch
    /// slices later via `fetch_artifact`. The caller is responsible for
    /// generating a unique `artifact_id`.
    pub fn save_tool_artifact(
        &self,
        artifact_id: &str,
        chat_id: i64,
        tool_name: &str,
        content: &str,
        expires_at: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let total_chars = content.chars().count() as i64;
        conn.execute(
            "INSERT INTO tool_result_artifacts
                (artifact_id, chat_id, tool_name, content, total_chars, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                artifact_id,
                chat_id,
                tool_name,
                content,
                total_chars,
                now,
                expires_at
            ],
        )?;
        Ok(())
    }

    /// Fetch a character-range slice of a stored artifact. Returns
    /// `(meta, slice, returned_chars)` if the artifact exists and is not
    /// expired. `offset` and `length` are interpreted as Unicode code
    /// points to keep the cap predictable across multi-byte content.
    pub fn get_tool_artifact_slice(
        &self,
        artifact_id: &str,
        offset: usize,
        length: usize,
        now: &str,
    ) -> Result<Option<(ToolArtifactMeta, String)>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT artifact_id, chat_id, tool_name, content, total_chars, created_at, expires_at
                 FROM tool_result_artifacts
                 WHERE artifact_id = ?1 AND expires_at > ?2",
                params![artifact_id, now],
                |r| {
                    let content: String = r.get(3)?;
                    Ok((
                        ToolArtifactMeta {
                            artifact_id: r.get(0)?,
                            chat_id: r.get(1)?,
                            tool_name: r.get(2)?,
                            total_chars: r.get(4)?,
                            created_at: r.get(5)?,
                            expires_at: r.get(6)?,
                        },
                        content,
                    ))
                },
            )
            .optional()?;
        let Some((meta, content)) = row else {
            return Ok(None);
        };
        let slice: String = content.chars().skip(offset).take(length).collect();
        Ok(Some((meta, slice)))
    }

    /// Delete expired artifact rows. Returns number of rows deleted.
    pub fn prune_tool_artifacts(&self, now: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM tool_result_artifacts WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
    }

    // Kept as scalar fields so callers do not need to construct a persistence
    // DTO merely to synchronize an active plan.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_goal_state(
        &self,
        goal_id: &str,
        chat_id: i64,
        objective: &str,
        status: &str,
        constraints_json: Option<&str>,
        progress_json: Option<&str>,
        budget_json: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let completed_at = matches!(status, "completed" | "failed" | "cancelled").then_some(&now);
        conn.execute(
            "INSERT INTO goal_states(
                goal_id, chat_id, objective, status, constraints_json,
                progress_json, budget_json, created_at, updated_at, completed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
             ON CONFLICT(goal_id) DO UPDATE SET
                objective=excluded.objective,
                status=excluded.status,
                constraints_json=COALESCE(excluded.constraints_json, goal_states.constraints_json),
                progress_json=COALESCE(excluded.progress_json, goal_states.progress_json),
                budget_json=COALESCE(excluded.budget_json, goal_states.budget_json),
                updated_at=excluded.updated_at,
                completed_at=excluded.completed_at",
            params![
                goal_id,
                chat_id,
                objective,
                status,
                constraints_json,
                progress_json,
                budget_json,
                now,
                completed_at
            ],
        )?;
        Ok(())
    }

    pub fn get_active_goal_state(
        &self,
        chat_id: i64,
    ) -> Result<Option<GoalStateRecord>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT goal_id, chat_id, objective, status, constraints_json,
                    progress_json, budget_json, created_at, updated_at, completed_at
             FROM goal_states
             WHERE chat_id=?1 AND status='active'
             ORDER BY updated_at DESC LIMIT 1",
            params![chat_id],
            |row| {
                Ok(GoalStateRecord {
                    goal_id: row.get(0)?,
                    chat_id: row.get(1)?,
                    objective: row.get(2)?,
                    status: row.get(3)?,
                    constraints_json: row.get(4)?,
                    progress_json: row.get(5)?,
                    budget_json: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    completed_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    // Experience identity and execution context are deliberately explicit at
    // the write boundary; grouping them would obscure required audit fields.
    #[allow(clippy::too_many_arguments)]
    pub fn start_experience_run(
        &self,
        run_id: &str,
        goal_id: Option<&str>,
        chat_id: i64,
        channel: &str,
        run_kind: &str,
        objective: &str,
        environment_fingerprint: Option<&str>,
    ) -> Result<(), MicroClawError> {
        if run_id.trim().is_empty()
            || run_id.len() > 128
            || channel.trim().is_empty()
            || channel.len() > 128
            || !matches!(run_kind, "interactive" | "scheduled" | "recovery")
            || objective.len() > 16 * 1024
            || environment_fingerprint.is_some_and(|value| value.len() > 2048)
        {
            return Err(MicroClawError::ToolExecution(
                "invalid experience run identity or context".into(),
            ));
        }
        let conn = self.lock_conn();
        let signature = derive_task_signature(objective, run_kind);
        let capability_tags_json = serde_json::to_string(&signature.capability_tags)
            .map_err(|error| MicroClawError::ToolExecution(error.to_string()))?;
        conn.execute(
            "INSERT INTO experience_runs(
                run_id, goal_id, chat_id, channel, run_kind, objective,
                environment_fingerprint, status, started_at,
                task_signature_version, task_type, task_family,
                capability_tags_json, task_signature_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'running', ?8,
                       ?9, ?10, ?11, ?12, ?13)",
            params![
                run_id,
                goal_id,
                chat_id,
                channel,
                run_kind,
                objective,
                environment_fingerprint,
                chrono::Utc::now().to_rfc3339(),
                signature.version,
                signature.task_type,
                signature.task_family,
                capability_tags_json,
                signature.signature_hash
            ],
        )?;
        Ok(())
    }

    pub fn finish_experience_run(
        &self,
        run_id: &str,
        status: &str,
        result_summary: Option<&str>,
        duration_ms: i64,
    ) -> Result<(), MicroClawError> {
        if !matches!(status, "completed" | "failed" | "cancelled")
            || duration_ms < 0
            || result_summary.is_some_and(|summary| summary.len() > 16 * 1024)
        {
            return Err(MicroClawError::ToolExecution(
                "invalid experience completion fields".into(),
            ));
        }
        let conn = self.lock_conn();
        let changed = conn.execute(
            "UPDATE experience_runs
             SET status=?2, result_summary=?3, finished_at=?4, duration_ms=?5
             WHERE run_id=?1",
            params![
                run_id,
                status,
                result_summary,
                chrono::Utc::now().to_rfc3339(),
                duration_ms
            ],
        )?;
        if changed == 0 {
            return Err(MicroClawError::ToolExecution(format!(
                "experience run not found: {run_id}"
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_experience_metrics(
        &self,
        run_id: &str,
        input_tokens: i64,
        output_tokens: i64,
        llm_requests: i64,
        tool_calls: i64,
        tool_errors: i64,
        estimated_cost_usd: Option<f64>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let changed = conn.execute(
            "UPDATE experience_runs
             SET input_tokens=?2, output_tokens=?3, llm_requests=?4,
                 tool_calls=?5, tool_errors=?6, estimated_cost_usd=?7
             WHERE run_id=?1",
            params![
                run_id,
                input_tokens.max(0),
                output_tokens.max(0),
                llm_requests.max(0),
                tool_calls.max(0),
                tool_errors.max(0),
                estimated_cost_usd.filter(|cost| cost.is_finite() && *cost >= 0.0)
            ],
        )?;
        if changed == 0 {
            return Err(MicroClawError::ToolExecution(format!(
                "experience run not found: {run_id}"
            )));
        }
        Ok(())
    }

    /// Retire experience rows left running by a previous process. The
    /// restart signal is retained for observability but intentionally uses a
    /// non-governing verifier type because a process crash is not evidence
    /// that an activated skill was incorrect.
    pub fn recover_running_experience_runs(&self) -> Result<usize, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("SELECT run_id FROM experience_runs WHERE status='running'")?;
        let run_ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        if run_ids.is_empty() {
            tx.commit()?;
            return Ok(0);
        }
        let now = chrono::Utc::now().to_rfc3339();
        for run_id in &run_ids {
            tx.execute(
                "UPDATE experience_runs
                 SET status='failed', result_summary='interrupted by process restart',
                     finished_at=?2
                 WHERE run_id=?1 AND status='running'",
                params![run_id, now],
            )?;
        }
        tx.commit()?;
        drop(conn);
        for run_id in &run_ids {
            self.ingest_outcome_envelope(&OutcomeEnvelopeV1 {
                envelope_id: format!("process-restart:{run_id}"),
                run_id: run_id.clone(),
                source_kind: "runtime".into(),
                source_name: "process_restart".into(),
                verdict: "failed".into(),
                confidence: 1.0,
                evidence: Some("run was still active when the process restarted".into()),
                scope: Some("runtime".into()),
                valid_until: None,
                payload: serde_json::json!({"interrupted": true}),
                feedback: None,
            })?;
        }
        Ok(run_ids.len())
    }

    pub fn latest_experience_run_id(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT run_id FROM experience_runs
             WHERE chat_id=?1 ORDER BY started_at DESC LIMIT 1",
            params![chat_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn experience_run_belongs_to_chat(
        &self,
        run_id: &str,
        chat_id: i64,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM experience_runs WHERE run_id=?1 AND chat_id=?2",
            params![run_id, chat_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn get_recent_experience_runs(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ExperienceRunRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let limit = limit.clamp(1, 200) as i64;
        let sql = if chat_id.is_some() {
            "SELECT run_id, goal_id, chat_id, channel, run_kind, objective,
                    environment_fingerprint, status, result_summary, started_at,
                    finished_at, duration_ms, input_tokens, output_tokens,
                    llm_requests, tool_calls, tool_errors, estimated_cost_usd,
                    task_signature_version, task_type, task_family,
                    capability_tags_json, task_signature_hash
             FROM experience_runs WHERE chat_id=?1
             ORDER BY started_at DESC LIMIT ?2"
        } else {
            "SELECT run_id, goal_id, chat_id, channel, run_kind, objective,
                    environment_fingerprint, status, result_summary, started_at,
                    finished_at, duration_ms, input_tokens, output_tokens,
                    llm_requests, tool_calls, tool_errors, estimated_cost_usd,
                    task_signature_version, task_type, task_family,
                    capability_tags_json, task_signature_hash
             FROM experience_runs
             ORDER BY started_at DESC LIMIT ?2"
        };
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(ExperienceRunRecord {
                run_id: row.get(0)?,
                goal_id: row.get(1)?,
                chat_id: row.get(2)?,
                channel: row.get(3)?,
                run_kind: row.get(4)?,
                objective: row.get(5)?,
                environment_fingerprint: row.get(6)?,
                status: row.get(7)?,
                result_summary: row.get(8)?,
                started_at: row.get(9)?,
                finished_at: row.get(10)?,
                duration_ms: row.get(11)?,
                input_tokens: row.get(12)?,
                output_tokens: row.get(13)?,
                llm_requests: row.get(14)?,
                tool_calls: row.get(15)?,
                tool_errors: row.get(16)?,
                estimated_cost_usd: row.get(17)?,
                task_signature: TaskSignatureV1 {
                    version: row.get(18)?,
                    task_type: row.get(19)?,
                    task_family: row.get(20)?,
                    capability_tags: serde_json::from_str::<Vec<String>>(
                        &row.get::<_, String>(21)?,
                    )
                    .unwrap_or_default(),
                    signature_hash: row.get(22)?,
                },
            })
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = if let Some(chat_id) = chat_id {
            stmt.query_map(params![chat_id, limit], map_row)?
        } else {
            stmt.query_map(params![Option::<i64>::None, limit], map_row)?
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Persist the exact verified experiences injected into one agent run.
    /// Re-recording the same query run replaces its selection atomically.
    pub fn record_experience_retrievals(
        &self,
        querying_run_id: &str,
        selections: &[(String, String, f64)],
    ) -> Result<(), MicroClawError> {
        if querying_run_id.trim().is_empty()
            || selections.len() > 20
            || selections.iter().any(|(run_id, reason, score)| {
                run_id.trim().is_empty()
                    || reason.trim().is_empty()
                    || reason.len() > 1024
                    || !score.is_finite()
            })
        {
            return Err(MicroClawError::ToolExecution(
                "invalid experience retrieval log".into(),
            ));
        }
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let querying_chat: Option<i64> = tx
            .query_row(
                "SELECT chat_id FROM experience_runs WHERE run_id=?1",
                params![querying_run_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(querying_chat) = querying_chat else {
            return Err(MicroClawError::ToolExecution(format!(
                "experience run not found: {querying_run_id}"
            )));
        };
        tx.execute(
            "DELETE FROM experience_retrieval_logs WHERE querying_run_id=?1",
            params![querying_run_id],
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        for (index, (source_run_id, reason, score)) in selections.iter().enumerate() {
            let source_chat: Option<i64> = tx
                .query_row(
                    "SELECT chat_id FROM experience_runs WHERE run_id=?1",
                    params![source_run_id],
                    |row| row.get(0),
                )
                .optional()?;
            if source_chat != Some(querying_chat) || source_run_id == querying_run_id {
                return Err(MicroClawError::ToolExecution(
                    "retrieved experience must be a different run in the same chat".into(),
                ));
            }
            tx.execute(
                "INSERT INTO experience_retrieval_logs(
                    querying_run_id, source_run_id, rank, selection_reason,
                    relevance_score, injected_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    querying_run_id,
                    source_run_id,
                    index as i64 + 1,
                    reason,
                    score,
                    now
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record_experience_rejections(
        &self,
        querying_run_id: &str,
        rejections: &[(String, String, f64)],
    ) -> Result<(), MicroClawError> {
        if rejections.len() > 50
            || rejections.iter().any(|(run_id, reason, score)| {
                run_id.trim().is_empty()
                    || reason.trim().is_empty()
                    || reason.len() > 1024
                    || !score.is_finite()
            })
        {
            return Err(MicroClawError::ToolExecution(
                "invalid experience rejection log".into(),
            ));
        }
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM experience_retrieval_rejections WHERE querying_run_id=?1",
            params![querying_run_id],
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        for (source_run_id, reason, score) in rejections {
            tx.execute(
                "INSERT INTO experience_retrieval_rejections(
                    querying_run_id, source_run_id, rejection_reason,
                    relevance_score, rejected_at
                 ) SELECT ?1,?2,?3,?4,?5
                   WHERE EXISTS(
                     SELECT 1 FROM experience_runs q JOIN experience_runs s
                     ON q.chat_id=s.chat_id
                     WHERE q.run_id=?1 AND s.run_id=?2 AND q.run_id<>s.run_id
                   )",
                params![querying_run_id, source_run_id, reason, score, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_experience_run_detail(
        &self,
        run_id: &str,
    ) -> Result<Option<ExperienceRunDetail>, MicroClawError> {
        let conn = self.lock_conn();
        let run = conn
            .query_row(
                "SELECT run_id, goal_id, chat_id, channel, run_kind, objective,
                        environment_fingerprint, status, result_summary, started_at,
                        finished_at, duration_ms, input_tokens, output_tokens,
                        llm_requests, tool_calls, tool_errors, estimated_cost_usd
                        , task_signature_version, task_type, task_family,
                        capability_tags_json, task_signature_hash
                 FROM experience_runs WHERE run_id=?1",
                params![run_id],
                |row| {
                    Ok(ExperienceRunRecord {
                        run_id: row.get(0)?,
                        goal_id: row.get(1)?,
                        chat_id: row.get(2)?,
                        channel: row.get(3)?,
                        run_kind: row.get(4)?,
                        objective: row.get(5)?,
                        environment_fingerprint: row.get(6)?,
                        status: row.get(7)?,
                        result_summary: row.get(8)?,
                        started_at: row.get(9)?,
                        finished_at: row.get(10)?,
                        duration_ms: row.get(11)?,
                        input_tokens: row.get(12)?,
                        output_tokens: row.get(13)?,
                        llm_requests: row.get(14)?,
                        tool_calls: row.get(15)?,
                        tool_errors: row.get(16)?,
                        estimated_cost_usd: row.get(17)?,
                        task_signature: TaskSignatureV1 {
                            version: row.get(18)?,
                            task_type: row.get(19)?,
                            task_family: row.get(20)?,
                            capability_tags: serde_json::from_str::<Vec<String>>(
                                &row.get::<_, String>(21)?,
                            )
                            .unwrap_or_default(),
                            signature_hash: row.get(22)?,
                        },
                    })
                },
            )
            .optional()?;
        let Some(run) = run else {
            return Ok(None);
        };

        let mut outcome_stmt = conn.prepare(
            "SELECT envelope_id, schema_version, run_id, source_kind, source_name,
                    verdict, confidence, evidence, scope, valid_until,
                    payload_json, created_at
             FROM outcome_envelopes WHERE run_id=?1 ORDER BY created_at ASC",
        )?;
        let outcomes = outcome_stmt
            .query_map(params![run_id], |row| {
                let payload_json: String = row.get(10)?;
                Ok(OutcomeEnvelopeRecord {
                    envelope_id: row.get(0)?,
                    schema_version: row.get(1)?,
                    run_id: row.get(2)?,
                    source_kind: row.get(3)?,
                    source_name: row.get(4)?,
                    verdict: row.get(5)?,
                    confidence: row.get(6)?,
                    evidence: row.get(7)?,
                    scope: row.get(8)?,
                    valid_until: row.get(9)?,
                    payload: serde_json::from_str(&payload_json).unwrap_or(serde_json::Value::Null),
                    created_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut feedback_stmt = conn.prepare(
            "SELECT feedback_id, run_id, actor, verdict, confidence, evidence,
                    scope, created_at, updated_at, valid_until
             FROM experience_feedback WHERE run_id=?1 ORDER BY updated_at ASC",
        )?;
        let feedback = feedback_stmt
            .query_map(params![run_id], |row| {
                Ok(ExperienceFeedbackRecord {
                    feedback_id: row.get(0)?,
                    run_id: row.get(1)?,
                    actor: row.get(2)?,
                    verdict: row.get(3)?,
                    confidence: row.get(4)?,
                    evidence: row.get(5)?,
                    scope: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    valid_until: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut retrieval_stmt = conn.prepare(
            "SELECT l.querying_run_id, l.source_run_id, l.rank,
                    l.selection_reason, l.relevance_score, l.injected_at,
                    r.objective, r.result_summary
             FROM experience_retrieval_logs l
             JOIN experience_runs r ON r.run_id=l.source_run_id
             WHERE l.querying_run_id=?1 ORDER BY l.rank ASC",
        )?;
        let retrieved_experiences = retrieval_stmt
            .query_map(params![run_id], |row| {
                Ok(ExperienceRetrievalRecord {
                    querying_run_id: row.get(0)?,
                    source_run_id: row.get(1)?,
                    rank: row.get(2)?,
                    selection_reason: row.get(3)?,
                    relevance_score: row.get(4)?,
                    injected_at: row.get(5)?,
                    source_objective: row.get(6)?,
                    source_result_summary: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut rejection_stmt = conn.prepare(
            "SELECT x.source_run_id, x.rejection_reason, x.relevance_score,
                    x.rejected_at, r.objective
             FROM experience_retrieval_rejections x
             JOIN experience_runs r ON r.run_id=x.source_run_id
             WHERE x.querying_run_id=?1 ORDER BY x.rejected_at ASC",
        )?;
        let rejected_experiences = rejection_stmt
            .query_map(params![run_id], |row| {
                Ok(ExperienceRejectionRecord {
                    source_run_id: row.get(0)?,
                    rejection_reason: row.get(1)?,
                    relevance_score: row.get(2)?,
                    rejected_at: row.get(3)?,
                    source_objective: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut skill_stmt = conn.prepare(
            "SELECT skill_name, skill_version, activated_at
             FROM skill_activation_logs
             WHERE experience_run_id=?1 ORDER BY activated_at ASC",
        )?;
        let activated_skills = skill_stmt
            .query_map(params![run_id], |row| {
                Ok(SkillActivationRecord {
                    skill_name: row.get(0)?,
                    skill_version: row.get(1)?,
                    activated_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(ExperienceRunDetail {
            run,
            outcomes,
            feedback,
            retrieved_experiences,
            rejected_experiences,
            activated_skills,
        }))
    }

    pub fn get_experience_summary(
        &self,
        chat_id: Option<i64>,
    ) -> Result<ExperienceSummary, MicroClawError> {
        let conn = self.lock_conn();
        let sql = if chat_id.is_some() {
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status IN ('failed','cancelled') THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN EXISTS(
                        SELECT 1 FROM verifier_results v WHERE v.run_id=experience_runs.run_id
                    ) THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(tool_calls), 0),
                    COALESCE(SUM(tool_errors), 0),
                    COALESCE(SUM(estimated_cost_usd), 0.0)
             FROM experience_runs WHERE chat_id=?1"
        } else {
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status IN ('failed','cancelled') THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN EXISTS(
                        SELECT 1 FROM verifier_results v WHERE v.run_id=experience_runs.run_id
                    ) THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(tool_calls), 0),
                    COALESCE(SUM(tool_errors), 0),
                    COALESCE(SUM(estimated_cost_usd), 0.0)
             FROM experience_runs"
        };
        let map = |row: &rusqlite::Row<'_>| {
            Ok(ExperienceSummary {
                total_runs: row.get(0)?,
                completed_runs: row.get(1)?,
                failed_runs: row.get(2)?,
                verified_runs: row.get(3)?,
                input_tokens: row.get(4)?,
                output_tokens: row.get(5)?,
                tool_calls: row.get(6)?,
                tool_errors: row.get(7)?,
                estimated_cost_usd: row.get(8)?,
            })
        };
        if let Some(chat_id) = chat_id {
            conn.query_row(sql, params![chat_id], map)
        } else {
            conn.query_row(sql, [], map)
        }
        .map_err(Into::into)
    }

    pub fn search_verified_experiences(
        &self,
        chat_id: i64,
        query: &str,
        environment_fingerprint: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VerifiedExperienceMatch>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT run_id, objective, environment_fingerprint, result_summary,
                    started_at, duration_ms, input_tokens + output_tokens,
                    tool_calls, tool_errors, estimated_cost_usd,
                    task_signature_version, task_type, task_family,
                    capability_tags_json, task_signature_hash
             FROM experience_runs
             WHERE chat_id=?1 AND status IN ('completed','failed','cancelled')
             ORDER BY started_at DESC LIMIT 200",
        )?;
        let candidates = stmt
            .query_map(params![chat_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<f64>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let query_lower = query.trim().to_lowercase();
        let query_signature = derive_task_signature(query, "interactive");
        let query_terms = query_lower
            .split(|ch: char| !ch.is_alphanumeric())
            .filter(|term| term.chars().count() >= 2)
            .collect::<Vec<_>>();
        let now = chrono::Utc::now().to_rfc3339();
        let mut matches = Vec::new();
        for (
            run_id,
            objective,
            environment,
            result_summary,
            started_at,
            duration_ms,
            total_tokens,
            tool_calls,
            tool_errors,
            estimated_cost_usd,
            signature_version,
            task_type,
            task_family,
            capability_tags_json,
            signature_hash,
        ) in candidates
        {
            let searchable = format!(
                "{} {}",
                objective.to_lowercase(),
                result_summary.as_deref().unwrap_or("").to_lowercase()
            );
            let lexical = if query_lower.is_empty() {
                0.25
            } else if searchable.contains(&query_lower) {
                1.0
            } else if query_terms.is_empty() {
                0.0
            } else {
                query_terms
                    .iter()
                    .filter(|term| searchable.contains(**term))
                    .count() as f64
                    / query_terms.len() as f64
            };
            if lexical == 0.0 {
                continue;
            }

            let mut verifier_stmt = conn.prepare(
                "SELECT verifier_type, verdict, confidence
                 FROM verifier_results
                 WHERE run_id=?1
                   AND verifier_type IN ('deterministic','environmental','human','rule_based')
                   AND (valid_until IS NULL OR valid_until > ?2)",
            )?;
            let verifier_rows = verifier_stmt
                .query_map(params![run_id, now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if verifier_rows.is_empty() {
                continue;
            }
            let max_priority = verifier_rows
                .iter()
                .map(|result| verifier_priority(&result.0))
                .max()
                .unwrap_or(0);
            let strongest = verifier_rows
                .iter()
                .filter(|result| verifier_priority(&result.0) == max_priority)
                .collect::<Vec<_>>();
            let verifier_type = strongest[0].0.clone();
            let (verdict, confidence) = if verifier_type == "human" {
                let passed: f64 = strongest
                    .iter()
                    .filter(|result| result.1 == "passed")
                    .map(|result| result.2)
                    .sum();
                let failed: f64 = strongest
                    .iter()
                    .filter(|result| result.1 == "failed")
                    .map(|result| result.2)
                    .sum();
                let total = passed + failed;
                (
                    if passed > failed { "passed" } else { "failed" }.to_string(),
                    if total > 0.0 {
                        passed.max(failed) / total
                    } else {
                        0.0
                    },
                )
            } else {
                let selected = strongest
                    .iter()
                    .filter(|result| result.1 == "failed")
                    .max_by(|left, right| left.2.total_cmp(&right.2))
                    .or_else(|| {
                        strongest
                            .iter()
                            .max_by(|left, right| left.2.total_cmp(&right.2))
                    })
                    .expect("strongest verifier group is non-empty");
                (selected.1.clone(), selected.2)
            };
            let environment_bonus = match (environment_fingerprint, environment.as_deref()) {
                (Some(expected), Some(actual)) if expected == actual => 0.25,
                _ => 0.0,
            };
            let capability_tags =
                serde_json::from_str::<Vec<String>>(&capability_tags_json).unwrap_or_default();
            let task_bonus = if task_family == query_signature.task_family {
                0.3
            } else if task_type == query_signature.task_type {
                0.15
            } else {
                0.0
            };
            let shared_tags = capability_tags
                .iter()
                .filter(|tag| query_signature.capability_tags.contains(tag))
                .count();
            let tag_bonus = if capability_tags.is_empty()
                && query_signature.capability_tags.is_empty()
            {
                0.0
            } else {
                0.2 * shared_tags as f64
                    / capability_tags
                        .len()
                        .max(query_signature.capability_tags.len()) as f64
            };
            let rejection_reason = if verdict == "failed" {
                Some(format!(
                    "not injected: prior run has verified failure ({verifier_type})"
                ))
            } else {
                conn.query_row(
                    "SELECT 'not injected: skill ' || p.skill_name ||
                            ' is contraindicated for ' || p.task_family ||
                            ' (' || p.error_category || ', failures=' ||
                            p.failure_count || ')'
                     FROM skill_failure_patterns p
                     JOIN skill_activation_logs a
                       ON a.skill_name=p.skill_name
                      AND COALESCE(a.skill_version, p.skill_version)=p.skill_version
                     WHERE a.experience_run_id=?1
                       AND p.task_family=?2
                       AND (p.environment_fingerprint IS NULL
                            OR p.environment_fingerprint=?3)
                       AND p.state IN ('active','cooldown')
                     ORDER BY p.failure_count DESC LIMIT 1",
                    params![run_id, query_signature.task_family, environment_fingerprint],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            };
            matches.push(VerifiedExperienceMatch {
                run_id,
                objective,
                environment_fingerprint: environment,
                verdict,
                verifier_type,
                confidence,
                result_summary,
                started_at,
                duration_ms,
                total_tokens,
                tool_calls,
                tool_errors,
                estimated_cost_usd,
                relevance_score: lexical + environment_bonus + task_bonus + tag_bonus,
                utility_lower_bound: 0.0,
                task_signature: TaskSignatureV1 {
                    version: signature_version,
                    task_type,
                    task_family,
                    capability_tags,
                    signature_hash,
                },
                rejection_reason,
            });
        }
        let mut utility_samples = std::collections::HashMap::<String, (i64, i64)>::new();
        for item in &matches {
            let entry = utility_samples
                .entry(item.task_signature.task_family.clone())
                .or_default();
            entry.1 += 1;
            if item.verdict == "passed" {
                entry.0 += 1;
            }
        }
        for item in &mut matches {
            let (passed, total) = utility_samples
                .get(&item.task_signature.task_family)
                .copied()
                .unwrap_or_default();
            item.utility_lower_bound = wilson_lower_bound(passed, total, 1.96);
            item.relevance_score += 0.25 * item.utility_lower_bound;
        }
        matches.sort_by(|left, right| {
            right
                .relevance_score
                .total_cmp(&left.relevance_score)
                .then_with(|| right.started_at.cmp(&left.started_at))
        });
        matches.truncate(limit.clamp(1, 20));
        Ok(matches)
    }

    #[expect(clippy::too_many_arguments)]
    pub fn record_verifier_result(
        &self,
        run_id: &str,
        verifier_type: &str,
        verifier_name: &str,
        verdict: &str,
        confidence: f64,
        evidence: Option<&str>,
        scope: Option<&str>,
        valid_until: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let feedback = (verifier_type == "human").then(|| ExperienceFeedbackInput {
            feedback_id: verifier_name.to_string(),
            actor: "verifier".into(),
        });
        self.ingest_outcome_envelope(&OutcomeEnvelopeV1 {
            envelope_id: uuid::Uuid::new_v4().to_string(),
            run_id: run_id.to_string(),
            source_kind: verifier_type.to_string(),
            source_name: verifier_name.to_string(),
            verdict: verdict.to_string(),
            confidence,
            evidence: evidence.map(str::to_string),
            scope: scope.map(str::to_string),
            valid_until: valid_until.map(str::to_string),
            payload: serde_json::Value::Object(serde_json::Map::new()),
            feedback,
        })
    }

    /// Ingest one versioned outcome envelope and atomically update its
    /// normalized projections. All outcome producers use this boundary.
    pub fn ingest_outcome_envelope(
        &self,
        envelope: &OutcomeEnvelopeV1,
    ) -> Result<(), MicroClawError> {
        validate_outcome_envelope(envelope)?;
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let run_exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM experience_runs WHERE run_id=?1",
            params![envelope.run_id],
            |row| row.get(0),
        )?;
        if run_exists == 0 {
            return Err(MicroClawError::ToolExecution(format!(
                "experience run not found: {}",
                envelope.run_id
            )));
        }
        let now = chrono::Utc::now().to_rfc3339();
        let payload_json = serde_json::to_string(&envelope.payload).map_err(|error| {
            MicroClawError::ToolExecution(format!("invalid outcome payload: {error}"))
        })?;
        tx.execute(
            "INSERT INTO outcome_envelopes(
                envelope_id, schema_version, run_id, source_kind, source_name,
                verdict, confidence, evidence, scope, valid_until, payload_json,
                created_at
             ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(envelope_id) DO UPDATE SET
                verdict=excluded.verdict,
                confidence=excluded.confidence,
                evidence=excluded.evidence,
                scope=excluded.scope,
                valid_until=excluded.valid_until,
                payload_json=excluded.payload_json,
                created_at=excluded.created_at",
            params![
                envelope.envelope_id,
                envelope.run_id,
                envelope.source_kind,
                envelope.source_name,
                envelope.verdict,
                envelope.confidence.clamp(0.0, 1.0),
                envelope.evidence,
                envelope.scope,
                envelope.valid_until,
                payload_json,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO verifier_results(
                run_id, verifier_type, verifier_name, verdict, confidence,
                evidence, scope, verified_at, valid_until
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(run_id, verifier_type, verifier_name) DO UPDATE SET
                verdict=excluded.verdict,
                confidence=excluded.confidence,
                evidence=excluded.evidence,
                scope=excluded.scope,
                verified_at=excluded.verified_at,
                valid_until=excluded.valid_until",
            params![
                envelope.run_id,
                envelope.source_kind,
                envelope.source_name,
                envelope.verdict,
                envelope.confidence.clamp(0.0, 1.0),
                envelope.evidence,
                envelope.scope,
                now,
                envelope.valid_until
            ],
        )?;
        if let Some(feedback) = &envelope.feedback {
            tx.execute(
                "INSERT INTO experience_feedback(
                    feedback_id, run_id, actor, verdict, confidence, evidence,
                    scope, created_at, updated_at, valid_until
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
                 ON CONFLICT(run_id, actor, feedback_id) DO UPDATE SET
                    verdict=excluded.verdict,
                    confidence=excluded.confidence,
                    evidence=excluded.evidence,
                    scope=excluded.scope,
                    updated_at=excluded.updated_at,
                    valid_until=excluded.valid_until",
                params![
                    feedback.feedback_id,
                    envelope.run_id,
                    feedback.actor,
                    envelope.verdict,
                    envelope.confidence.clamp(0.0, 1.0),
                    envelope.evidence,
                    envelope.scope,
                    now,
                    envelope.valid_until
                ],
            )?;
        }
        sync_skill_outcomes_for_run(&tx, &envelope.run_id)?;
        sync_skill_failure_patterns_for_run(&tx, &envelope.run_id)?;
        refresh_comparative_reflections_for_run(&tx, &envelope.run_id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_verifier_results(
        &self,
        run_id: &str,
    ) -> Result<Vec<VerifierResultRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, run_id, verifier_type, verifier_name, verdict,
                    confidence, evidence, scope, verified_at, valid_until
             FROM verifier_results WHERE run_id=?1
             ORDER BY verified_at ASC",
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok(VerifierResultRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                verifier_type: row.get(2)?,
                verifier_name: row.get(3)?,
                verdict: row.get(4)?,
                confidence: row.get(5)?,
                evidence: row.get(6)?,
                scope: row.get(7)?,
                verified_at: row.get(8)?,
                valid_until: row.get(9)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn register_skill_version(
        &self,
        skill_name: &str,
        version: i64,
        content: &str,
        source: &str,
    ) -> Result<(), MicroClawError> {
        if skill_name.trim().is_empty() || version <= 0 {
            return Err(MicroClawError::ToolExecution(
                "skill name must be non-empty and version must be positive".into(),
            ));
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = to_hex(&hasher.finalize());
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        let existing_hash: Option<String> = tx
            .query_row(
                "SELECT content_hash FROM skill_versions
                 WHERE skill_name=?1 AND version=?2",
                params![skill_name, version],
                |row| row.get(0),
            )
            .optional()?;
        if existing_hash
            .as_deref()
            .is_some_and(|existing| existing != hash)
        {
            return Err(MicroClawError::ToolExecution(format!(
                "skill version {skill_name}@{version} is immutable and already has different content"
            )));
        }
        tx.execute(
            "INSERT INTO skill_versions(
                skill_name, version, content, content_hash, source, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(skill_name, version) DO NOTHING",
            params![skill_name, version, content, hash, source, now],
        )?;
        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT state, active_version FROM skill_lifecycle WHERE skill_name=?1",
                params![skill_name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match existing {
            None => {
                let initial = if source == "agent-created" {
                    "candidate"
                } else {
                    "trusted"
                };
                tx.execute(
                    "INSERT INTO skill_lifecycle(
                        skill_name, state, active_version, source,
                        created_at, updated_at, state_reason
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 'version registered')",
                    params![skill_name, initial, version, source, now],
                )?;
                tx.execute(
                    "INSERT INTO skill_lifecycle_events(
                        skill_name, from_state, to_state, version, reason, created_at
                     ) VALUES (?1, NULL, ?2, ?3, 'version registered', ?4)",
                    params![skill_name, initial, version, now],
                )?;
            }
            Some((state, active_version)) => {
                // Re-discovery of an identical current/older version must not
                // implicitly change the active version or lifecycle. Version
                // rollback is an explicit, audited operation.
                if version <= active_version {
                    tx.commit()?;
                    return Ok(());
                }
                let next_state = if source == "agent-created" && version > active_version {
                    "candidate"
                } else {
                    state.as_str()
                };
                let previous_trusted =
                    (state == "trusted" && version > active_version).then_some(active_version);
                tx.execute(
                    "UPDATE skill_lifecycle
                     SET state=?2, active_version=?3,
                         previous_trusted_version=COALESCE(?4, previous_trusted_version),
                         source=?5, updated_at=?6, state_reason='new version registered'
                     WHERE skill_name=?1",
                    params![
                        skill_name,
                        next_state,
                        version,
                        previous_trusted,
                        source,
                        now
                    ],
                )?;
                if next_state != state {
                    tx.execute(
                        "INSERT INTO skill_lifecycle_events(
                            skill_name, from_state, to_state, version, reason, created_at
                         ) VALUES (?1, ?2, ?3, ?4, 'new version registered', ?5)",
                        params![skill_name, state, next_state, version, now],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_skill_lifecycle(
        &self,
        skill_name: &str,
    ) -> Result<Option<SkillLifecycleRecord>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT skill_name, state, active_version, previous_trusted_version,
                    source, created_at, updated_at, state_reason
             FROM skill_lifecycle WHERE skill_name=?1",
            params![skill_name],
            |row| {
                Ok(SkillLifecycleRecord {
                    skill_name: row.get(0)?,
                    state: row.get(1)?,
                    active_version: row.get(2)?,
                    previous_trusted_version: row.get(3)?,
                    source: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                    state_reason: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_skill_version_content(
        &self,
        skill_name: &str,
        version: i64,
    ) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT content FROM skill_versions WHERE skill_name=?1 AND version=?2",
            params![skill_name, version],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    /// Evaluate a skill against verified outcomes from the current run's
    /// environment. Two or more matching outcomes with a pass rate below 50%
    /// form a learned contraindication until a new version is registered.
    pub fn evaluate_skill_applicability(
        &self,
        skill_name: &str,
        chat_id: i64,
    ) -> Result<SkillApplicability, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        refresh_expired_skill_outcomes(&tx)?;
        let utility_confidence_z: f64 = tx.query_row(
            "SELECT utility_confidence_z FROM skill_governance_policy WHERE singleton_id=1",
            [],
            |row| row.get(0),
        )?;
        let context: Option<(Option<String>, String, String)> = tx
            .query_row(
                "SELECT environment_fingerprint, task_type, task_family
                 FROM experience_runs
                 WHERE chat_id=?1 AND status='running'
                 ORDER BY started_at DESC LIMIT 1",
                params![chat_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((environment, task_type, task_family)) = context else {
            tx.commit()?;
            return Ok(SkillApplicability {
                environment_fingerprint: None,
                task_type: None,
                task_family: None,
                matching_outcomes: 0,
                passed_outcomes: 0,
                failed_outcomes: 0,
                success_rate: None,
                utility_lower_bound: None,
                allowed: true,
                reason: "no comparable verified task history".into(),
            });
        };
        let (total, passed, failed): (i64, i64, i64) = tx.query_row(
            "SELECT COUNT(o.id),
                    COALESCE(SUM(CASE WHEN o.verdict='passed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN o.verdict='failed' THEN 1 ELSE 0 END), 0)
             FROM skill_outcomes o
             JOIN skill_lifecycle l
               ON l.skill_name=o.skill_name AND l.active_version=o.skill_version
             JOIN experience_runs r ON r.run_id=o.run_id
             WHERE o.skill_name=?1
               AND (?2 IS NULL OR r.environment_fingerprint=?2)
               AND r.task_family=?3
               AND o.verifier_type IN ('deterministic','environmental','human','rule_based')
               AND o.attribution_confidence >= 0.999
               AND (o.valid_until IS NULL OR o.valid_until > ?4)",
            params![
                skill_name,
                environment,
                task_family,
                chrono::Utc::now().to_rfc3339()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let success_rate = (total > 0).then_some(passed as f64 / total as f64);
        let utility_lower_bound =
            (total > 0).then_some(wilson_lower_bound(passed, total, utility_confidence_z));
        let active_pattern: Option<(String, Option<String>, i64, Option<String>)> = tx
            .query_row(
                "SELECT error_category, tool_name, failure_count, cooldown_until
                 FROM skill_failure_patterns p
                 JOIN skill_lifecycle l ON l.skill_name=p.skill_name
                    AND l.active_version=p.skill_version
                 WHERE p.skill_name=?1 AND p.task_family=?2
                   AND (p.environment_fingerprint IS NULL
                        OR p.environment_fingerprint=?3)
                   AND p.state IN ('active','cooldown')
                 ORDER BY p.failure_count DESC, p.updated_at DESC LIMIT 1",
                params![skill_name, task_family, environment],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let allowed = active_pattern.is_none() && (total < 2 || success_rate.unwrap_or(0.0) >= 0.5);
        let result = SkillApplicability {
            environment_fingerprint: environment,
            task_type: Some(task_type),
            task_family: Some(task_family),
            matching_outcomes: total,
            passed_outcomes: passed,
            failed_outcomes: failed,
            success_rate,
            utility_lower_bound,
            allowed,
            reason: if let Some((category, tool, count, cooldown)) = active_pattern {
                format!(
                    "learned contraindication: {count} {category} failure(s), tool={}, cooldown_until={}",
                    tool.as_deref().unwrap_or("any"),
                    cooldown.as_deref().unwrap_or("unknown")
                )
            } else if allowed {
                "no learned contraindication for this task family and environment".into()
            } else {
                "verified outcomes show repeated failure for this task family and environment"
                    .into()
            },
        };
        tx.commit()?;
        Ok(result)
    }

    pub fn transition_skill_state(
        &self,
        skill_name: &str,
        to_state: &str,
        reason: &str,
    ) -> Result<bool, MicroClawError> {
        if !matches!(
            to_state,
            "candidate" | "trial" | "trusted" | "degraded" | "archived"
        ) {
            return Err(MicroClawError::ToolExecution(format!(
                "invalid skill lifecycle state: {to_state}"
            )));
        }
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let current: Option<(String, i64)> = tx
            .query_row(
                "SELECT state, active_version FROM skill_lifecycle WHERE skill_name=?1",
                params![skill_name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((from_state, version)) = current else {
            return Ok(false);
        };
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE skill_lifecycle
             SET state=?2, updated_at=?3, state_reason=?4 WHERE skill_name=?1",
            params![skill_name, to_state, now, reason],
        )?;
        if from_state != to_state {
            tx.execute(
                "INSERT INTO skill_lifecycle_events(
                    skill_name, from_state, to_state, version, reason, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![skill_name, from_state, to_state, version, reason, now],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn rollback_skill(
        &self,
        skill_name: &str,
        target_version: Option<i64>,
        reason: &str,
    ) -> Result<Option<(i64, String)>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let current: Option<(String, i64, Option<i64>)> = tx
            .query_row(
                "SELECT state, active_version, previous_trusted_version
                 FROM skill_lifecycle WHERE skill_name=?1",
                params![skill_name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((from_state, active_version, previous_trusted)) = current else {
            return Ok(None);
        };
        let target = target_version.or(previous_trusted);
        let Some(target) = target else {
            return Ok(None);
        };
        let content: Option<String> = tx
            .query_row(
                "SELECT content FROM skill_versions WHERE skill_name=?1 AND version=?2",
                params![skill_name, target],
                |row| row.get(0),
            )
            .optional()?;
        let Some(content) = content else {
            return Ok(None);
        };
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE skill_lifecycle
             SET state='trusted', active_version=?2,
                 previous_trusted_version=?3, updated_at=?4, state_reason=?5
             WHERE skill_name=?1",
            params![skill_name, target, active_version, now, reason],
        )?;
        tx.execute(
            "INSERT INTO skill_lifecycle_events(
                skill_name, from_state, to_state, version, reason, created_at
             ) VALUES (?1, ?2, 'trusted', ?3, ?4, ?5)",
            params![skill_name, from_state, target, reason, now],
        )?;
        tx.execute(
            "UPDATE skill_candidates SET status='rolled_back', updated_at=?3
             WHERE skill_name=?1 AND candidate_version=?2 AND status='promoted'",
            params![skill_name, active_version, now],
        )?;
        tx.execute(
            "INSERT INTO learning_journal_events(
                event_type, entity_type, entity_id, summary, evidence_json,
                undo_action, created_at
             ) VALUES ('operator_rollback','skill',?1,?2,?3,NULL,?4)",
            params![
                skill_name,
                format!("rolled back {skill_name} from v{active_version} to v{target}: {reason}"),
                serde_json::json!({
                    "from_version": active_version,
                    "to_version": target,
                    "reason": reason
                })
                .to_string(),
                now
            ],
        )?;
        tx.commit()?;
        Ok(Some((target, content)))
    }

    pub fn get_skill_learning_summaries(
        &self,
    ) -> Result<Vec<SkillLearningSummary>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        refresh_expired_skill_outcomes(&tx)?;
        let utility_confidence_z: f64 = tx.query_row(
            "SELECT utility_confidence_z FROM skill_governance_policy WHERE singleton_id=1",
            [],
            |row| row.get(0),
        )?;
        let mut stmt = tx.prepare(
            "SELECT l.skill_name, l.state, l.active_version,
                    COUNT(o.id),
                    COALESCE(SUM(CASE WHEN o.verdict='passed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN o.verdict='failed' THEN 1 ELSE 0 END), 0),
                    MAX(o.updated_at)
             FROM skill_lifecycle l
             LEFT JOIN skill_outcomes o
              ON o.skill_name=l.skill_name AND o.skill_version=l.active_version
              AND o.verifier_type IN ('deterministic','environmental','human','rule_based')
              AND o.attribution_confidence >= 0.999
              AND (o.valid_until IS NULL OR o.valid_until >
                   strftime('%Y-%m-%dT%H:%M:%f+00:00','now'))
             GROUP BY l.skill_name, l.state, l.active_version
             ORDER BY l.updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let total: i64 = row.get(3)?;
            let passed: i64 = row.get(4)?;
            let failed: i64 = row.get(5)?;
            Ok(SkillLearningSummary {
                skill_name: row.get(0)?,
                state: row.get(1)?,
                active_version: row.get(2)?,
                total_outcomes: total,
                passed_outcomes: passed,
                failed_outcomes: failed,
                success_rate: if total == 0 {
                    0.0
                } else {
                    passed as f64 / total as f64
                },
                utility_lower_bound: wilson_lower_bound(passed, total, utility_confidence_z),
                last_outcome_at: row.get(6)?,
            })
        })?;
        let summaries = rows.collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        tx.commit()?;
        Ok(summaries)
    }

    pub fn get_skill_task_utility_summaries(
        &self,
        skill_name: Option<&str>,
    ) -> Result<Vec<SkillTaskUtilitySummary>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        refresh_expired_skill_outcomes(&tx)?;
        let z: f64 = tx.query_row(
            "SELECT utility_confidence_z FROM skill_governance_policy WHERE singleton_id=1",
            [],
            |row| row.get(0),
        )?;
        let mut stmt = tx.prepare(
            "SELECT o.skill_name, o.skill_version, r.task_type, r.task_family,
                    COUNT(o.id),
                    COALESCE(SUM(CASE WHEN o.verdict='passed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN o.verdict='failed' THEN 1 ELSE 0 END), 0)
             FROM skill_outcomes o
             JOIN experience_runs r ON r.run_id=o.run_id
             JOIN skill_lifecycle l
               ON l.skill_name=o.skill_name AND l.active_version=o.skill_version
             WHERE (?1 IS NULL OR o.skill_name=?1)
               AND o.verifier_type IN ('deterministic','environmental','human','rule_based')
               AND o.attribution_confidence >= 0.999
               AND (o.valid_until IS NULL OR o.valid_until >
                    strftime('%Y-%m-%dT%H:%M:%f+00:00','now'))
             GROUP BY o.skill_name, o.skill_version, r.task_type, r.task_family
             ORDER BY o.skill_name, COUNT(o.id) DESC, r.task_family",
        )?;
        let rows = stmt
            .query_map(params![skill_name], |row| {
                let total: i64 = row.get(4)?;
                let passed: i64 = row.get(5)?;
                Ok(SkillTaskUtilitySummary {
                    skill_name: row.get(0)?,
                    skill_version: row.get(1)?,
                    task_type: row.get(2)?,
                    task_family: row.get(3)?,
                    total_outcomes: total,
                    passed_outcomes: passed,
                    failed_outcomes: row.get(6)?,
                    success_rate: if total == 0 {
                        0.0
                    } else {
                        passed as f64 / total as f64
                    },
                    utility_lower_bound: wilson_lower_bound(passed, total, z),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        tx.commit()?;
        Ok(rows)
    }

    pub fn get_skill_failure_patterns(
        &self,
        skill_name: Option<&str>,
    ) -> Result<Vec<SkillFailurePattern>, MicroClawError> {
        let conn = self.lock_conn();
        let sql = "SELECT pattern_id, skill_name, skill_version, task_type,
                          task_family, environment_fingerprint, tool_name,
                          error_category, failure_count, recovery_successes,
                          state, cooldown_until, last_evidence, updated_at
                   FROM skill_failure_patterns
                   WHERE (?1 IS NULL OR skill_name=?1)
                   ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'cooldown' THEN 1
                                      WHEN 'trial' THEN 2 ELSE 3 END,
                            failure_count DESC, updated_at DESC";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params![skill_name], |row| {
                Ok(SkillFailurePattern {
                    pattern_id: row.get(0)?,
                    skill_name: row.get(1)?,
                    skill_version: row.get(2)?,
                    task_type: row.get(3)?,
                    task_family: row.get(4)?,
                    environment_fingerprint: row.get(5)?,
                    tool_name: row.get(6)?,
                    error_category: row.get(7)?,
                    failure_count: row.get(8)?,
                    recovery_successes: row.get(9)?,
                    state: row.get(10)?,
                    cooldown_until: row.get(11)?,
                    last_evidence: row.get(12)?,
                    updated_at: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn begin_skill_recovery_trial(&self, skill_name: &str) -> Result<bool, MicroClawError> {
        if skill_name.trim().is_empty() || skill_name.len() > 256 {
            return Err(MicroClawError::ToolExecution(
                "invalid skill name for recovery trial".into(),
            ));
        }
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        let changed = tx.execute(
            "UPDATE skill_failure_patterns SET state='trial', updated_at=?2
             WHERE skill_name=?1 AND state IN ('active','cooldown')
               AND cooldown_until IS NOT NULL AND cooldown_until<=?2",
            params![skill_name, now],
        )?;
        if changed > 0 {
            let lifecycle: Option<(String, i64)> = tx
                .query_row(
                    "SELECT state, active_version FROM skill_lifecycle WHERE skill_name=?1",
                    params![skill_name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((state, version)) = lifecycle {
                if state == "degraded" {
                    tx.execute(
                        "UPDATE skill_lifecycle SET state='trial',
                         state_reason='cooldown elapsed; recovery trial explicitly started',
                         updated_at=?2 WHERE skill_name=?1",
                        params![skill_name, now],
                    )?;
                    tx.execute(
                        "INSERT INTO skill_lifecycle_events(
                            skill_name, from_state, to_state, version, reason, created_at
                         ) VALUES (?1,'degraded','trial',?2,
                           'cooldown elapsed; recovery trial explicitly started',?3)",
                        params![skill_name, version, now],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    pub fn get_experience_comparisons(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ExperienceComparison>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT comparison_id, chat_id, skill_name, skill_version, task_type,
                    task_family, environment_fingerprint, success_run_id,
                    failure_run_id, minimal_difference, counterexample, created_at
             FROM experience_comparisons
             WHERE (?1 IS NULL OR chat_id=?1)
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 200) as i64], |row| {
                Ok(ExperienceComparison {
                    comparison_id: row.get(0)?,
                    chat_id: row.get(1)?,
                    skill_name: row.get(2)?,
                    skill_version: row.get(3)?,
                    task_type: row.get(4)?,
                    task_family: row.get(5)?,
                    environment_fingerprint: row.get(6)?,
                    success_run_id: row.get(7)?,
                    failure_run_id: row.get(8)?,
                    minimal_difference: row.get(9)?,
                    counterexample: row.get(10)?,
                    created_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_learning_claims(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<LearningClaim>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT c.claim_id, c.comparison_id, c.skill_name, c.base_version,
                    c.claim_version, c.statement, c.applicability_json, c.confidence,
                    c.evidence_json, c.counterexamples_json, c.status,
                    c.supersedes_claim_id, c.created_at, c.updated_at
             FROM learning_claims c
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             WHERE (?1 IS NULL OR x.chat_id=?1)
             ORDER BY c.updated_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 200) as i64], |row| {
                let applicability: String = row.get(6)?;
                let evidence: String = row.get(8)?;
                let counterexamples: String = row.get(9)?;
                Ok(LearningClaim {
                    claim_id: row.get(0)?,
                    comparison_id: row.get(1)?,
                    skill_name: row.get(2)?,
                    base_version: row.get(3)?,
                    claim_version: row.get(4)?,
                    statement: row.get(5)?,
                    applicability: serde_json::from_str(&applicability)
                        .unwrap_or(serde_json::Value::Null),
                    confidence: row.get(7)?,
                    evidence: serde_json::from_str(&evidence).unwrap_or(serde_json::Value::Null),
                    counterexamples: serde_json::from_str(&counterexamples)
                        .unwrap_or(serde_json::Value::Null),
                    status: row.get(10)?,
                    supersedes_claim_id: row.get(11)?,
                    created_at: row.get(12)?,
                    updated_at: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_skill_candidates(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<SkillCandidate>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT k.candidate_id, k.claim_id, k.skill_name, k.base_version,
                    k.candidate_version, k.content, k.content_hash, k.status,
                    k.created_at, k.updated_at
             FROM skill_candidates k
             JOIN learning_claims c ON c.claim_id=k.claim_id
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             WHERE (?1 IS NULL OR x.chat_id=?1)
             ORDER BY k.updated_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 200) as i64], |row| {
                Ok(SkillCandidate {
                    candidate_id: row.get(0)?,
                    claim_id: row.get(1)?,
                    skill_name: row.get(2)?,
                    base_version: row.get(3)?,
                    candidate_version: row.get(4)?,
                    content: row.get(5)?,
                    content_hash: row.get(6)?,
                    status: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn create_skill_candidate_from_claim(
        &self,
        claim_id: &str,
        chat_id: i64,
    ) -> Result<SkillCandidate, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let claim: Option<(String, i64, String, String)> = tx
            .query_row(
                "SELECT c.skill_name, c.base_version, c.statement, c.status
                 FROM learning_claims c
                 JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
                 WHERE c.claim_id=?1 AND x.chat_id=?2",
                params![claim_id, chat_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((skill_name, base_version, statement, claim_status)) = claim else {
            return Err(MicroClawError::ToolExecution(
                "learning claim not found".into(),
            ));
        };
        if claim_status == "archived" {
            return Err(MicroClawError::ToolExecution(
                "archived claim cannot create a candidate".into(),
            ));
        }
        if let Some(existing) = tx
            .query_row(
                "SELECT candidate_id FROM skill_candidates WHERE claim_id=?1",
                params![claim_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            drop(tx);
            drop(conn);
            return self
                .get_skill_candidates(Some(chat_id), 200)?
                .into_iter()
                .find(|candidate| candidate.candidate_id == existing)
                .ok_or_else(|| {
                    MicroClawError::ToolExecution("candidate projection missing".into())
                });
        }
        let base_content: String = tx.query_row(
            "SELECT content FROM skill_versions
             WHERE skill_name=?1 AND version=?2",
            params![skill_name, base_version],
            |row| row.get(0),
        )?;
        let candidate_version: i64 = tx.query_row(
            "SELECT MAX(version)+1 FROM (
               SELECT version FROM skill_versions WHERE skill_name=?1
               UNION ALL
               SELECT candidate_version AS version FROM skill_candidates
               WHERE skill_name=?1
             )",
            params![skill_name],
            |row| row.get::<_, Option<i64>>(0).map(|value| value.unwrap_or(1)),
        )?;
        let content = format!(
            "{base_content}\n\n## Learned guardrail (candidate v{candidate_version})\n\n- {statement}\n"
        );
        use sha2::{Digest, Sha256};
        let content_hash = to_hex(&Sha256::digest(content.as_bytes()));
        let candidate_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO skill_candidates(
                candidate_id, claim_id, skill_name, base_version,
                candidate_version, content, content_hash, status,
                created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,'candidate',?8,?8)",
            params![
                candidate_id,
                claim_id,
                skill_name,
                base_version,
                candidate_version,
                content,
                content_hash,
                now
            ],
        )?;
        tx.execute(
            "UPDATE learning_claims SET status='trial', updated_at=?2
             WHERE claim_id=?1",
            params![claim_id, now],
        )?;
        tx.execute(
            "INSERT INTO learning_journal_events(
                event_type, entity_type, entity_id, summary, evidence_json,
                undo_action, created_at
             ) VALUES ('candidate_created','skill_candidate',?1,?2,?3,
                       'archive_candidate',?4)",
            params![
                candidate_id,
                format!("{skill_name} candidate v{candidate_version} created from claim"),
                serde_json::json!({
                    "claim_id": claim_id,
                    "base_version": base_version,
                    "content_hash": content_hash
                })
                .to_string(),
                now
            ],
        )?;
        tx.commit()?;
        drop(conn);
        self.get_skill_candidates(Some(chat_id), 200)?
            .into_iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
            .ok_or_else(|| MicroClawError::ToolExecution("candidate projection missing".into()))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn record_shadow_observation(
        &self,
        candidate_id: &str,
        chat_id: i64,
        pair_key: &str,
        arm: &str,
        run_id: &str,
        verdict: &str,
        cost_usd: f64,
        duration_ms: i64,
        evidence: Option<&str>,
    ) -> Result<ShadowEvaluation, MicroClawError> {
        if !matches!(arm, "baseline" | "candidate")
            || !matches!(verdict, "passed" | "failed")
            || pair_key.trim().is_empty()
            || pair_key.len() > 128
            || !cost_usd.is_finite()
            || cost_usd < 0.0
            || duration_ms < 0
        {
            return Err(MicroClawError::ToolExecution(
                "invalid shadow observation".into(),
            ));
        }
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM skill_candidates c
             JOIN learning_claims l ON l.claim_id=c.claim_id
             JOIN experience_comparisons x ON x.comparison_id=l.comparison_id
             JOIN experience_runs r ON r.run_id=?2
             JOIN verifier_results v ON v.run_id=r.run_id
             WHERE c.candidate_id=?1
               AND c.status NOT IN ('archived','promoted')
               AND x.chat_id=?5
               AND r.task_family=json_extract(l.applicability_json,'$.task_family')
               AND (
                 json_extract(l.applicability_json,'$.environment_fingerprint') IS NULL
                 OR r.environment_fingerprint=
                    json_extract(l.applicability_json,'$.environment_fingerprint')
               )
               AND v.verdict=?3
               AND v.verifier_type IN (
                 'deterministic','environmental','human','rule_based'
               )
               AND (v.valid_until IS NULL OR v.valid_until>?4)",
            params![
                candidate_id,
                run_id,
                verdict,
                chrono::Utc::now().to_rfc3339(),
                chat_id
            ],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(MicroClawError::ToolExecution(
                "candidate or strongly verified comparable run not eligible for shadow evaluation"
                    .into(),
            ));
        }
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO shadow_observations(
                candidate_id, pair_key, arm, run_id, verdict, cost_usd,
                duration_ms, evidence, created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(candidate_id,pair_key,arm) DO UPDATE SET
                run_id=excluded.run_id, verdict=excluded.verdict,
                cost_usd=excluded.cost_usd, duration_ms=excluded.duration_ms,
                evidence=excluded.evidence, created_at=excluded.created_at",
            params![
                candidate_id,
                pair_key,
                arm,
                run_id,
                verdict,
                cost_usd,
                duration_ms,
                evidence,
                now
            ],
        )?;
        let evaluation = recompute_shadow_evaluation(&tx, candidate_id)?;
        tx.commit()?;
        Ok(evaluation)
    }

    pub fn get_shadow_evaluations(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<ShadowEvaluation>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT e.evaluation_id, e.candidate_id, e.sample_count,
                    e.baseline_passed, e.candidate_passed,
                    e.baseline_utility_lower_bound, e.candidate_utility_lower_bound,
                    e.baseline_cost_usd, e.candidate_cost_usd,
                    e.baseline_duration_ms, e.candidate_duration_ms,
                    e.regression_count, e.verdict, e.reason, e.updated_at
             FROM shadow_evaluations e
             JOIN skill_candidates k ON k.candidate_id=e.candidate_id
             JOIN learning_claims c ON c.claim_id=k.claim_id
             JOIN experience_comparisons x ON x.comparison_id=c.comparison_id
             WHERE (?1 IS NULL OR x.chat_id=?1)
             ORDER BY e.updated_at DESC",
        )?;
        let rows = stmt
            .query_map(params![chat_id], map_shadow_evaluation)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn promote_shadow_candidate(
        &self,
        candidate_id: &str,
        chat_id: i64,
    ) -> Result<(String, i64), MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let candidate: Option<(String, i64, i64, String, String, String)> = tx
            .query_row(
                "SELECT c.skill_name, c.base_version, c.candidate_version,
                        c.content, c.content_hash, e.verdict
                 FROM skill_candidates c
                 JOIN shadow_evaluations e ON e.candidate_id=c.candidate_id
                 JOIN learning_claims l ON l.claim_id=c.claim_id
                 JOIN experience_comparisons x ON x.comparison_id=l.comparison_id
                 WHERE c.candidate_id=?1 AND c.status='shadow_passed'
                   AND x.chat_id=?2",
                params![candidate_id, chat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((skill_name, base_version, candidate_version, content, hash, verdict)) = candidate
        else {
            return Err(MicroClawError::ToolExecution(
                "candidate has not passed shadow evaluation".into(),
            ));
        };
        if verdict != "passed" {
            return Err(MicroClawError::ToolExecution(
                "shadow evaluation gate did not pass".into(),
            ));
        }
        let lifecycle: Option<(String, i64)> = tx
            .query_row(
                "SELECT state, active_version FROM skill_lifecycle WHERE skill_name=?1",
                params![skill_name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if lifecycle.as_ref().map(|item| item.1) != Some(base_version) {
            return Err(MicroClawError::ToolExecution(
                "candidate base version is no longer active; regenerate and re-evaluate".into(),
            ));
        }
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO skill_versions(
                skill_name, version, content, content_hash, source, created_at
             ) VALUES (?1,?2,?3,?4,'comparative-reflection',?5)",
            params![skill_name, candidate_version, content, hash, now],
        )?;
        tx.execute(
            "UPDATE skill_lifecycle SET state='trusted', active_version=?2,
                 previous_trusted_version=?3, source='comparative-reflection',
                 state_reason='shadow evaluation passed', updated_at=?4
             WHERE skill_name=?1",
            params![skill_name, candidate_version, base_version, now],
        )?;
        tx.execute(
            "UPDATE skill_candidates SET status='promoted', updated_at=?2
             WHERE candidate_id=?1",
            params![candidate_id, now],
        )?;
        tx.execute(
            "UPDATE learning_claims SET status='trusted', updated_at=?2
             WHERE claim_id=(SELECT claim_id FROM skill_candidates
                              WHERE candidate_id=?1)",
            params![candidate_id, now],
        )?;
        tx.execute(
            "INSERT INTO skill_lifecycle_events(
                skill_name, from_state, to_state, version, reason, created_at
             ) VALUES (?1,?2,'trusted',?3,'shadow evaluation passed',?4)",
            params![
                skill_name,
                lifecycle
                    .map(|item| item.0)
                    .unwrap_or_else(|| "candidate".into()),
                candidate_version,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO learning_journal_events(
                event_type, entity_type, entity_id, summary, evidence_json,
                undo_action, created_at
             ) VALUES ('candidate_promoted','skill_candidate',?1,?2,?3,
                       'rollback_skill',?4)",
            params![
                candidate_id,
                format!("{skill_name} promoted from v{base_version} to v{candidate_version}"),
                serde_json::json!({
                    "skill_name": skill_name,
                    "from_version": base_version,
                    "to_version": candidate_version
                })
                .to_string(),
                now
            ],
        )?;
        tx.commit()?;
        Ok((skill_name, candidate_version))
    }

    pub fn archive_learning_entity(
        &self,
        entity_type: &str,
        entity_id: &str,
        chat_id: i64,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = match entity_type {
            "learning_claim" => conn.execute(
                "UPDATE learning_claims SET status='archived', updated_at=?2
                 WHERE claim_id=?1 AND status NOT IN ('trusted','archived')
                   AND comparison_id IN (
                     SELECT comparison_id FROM experience_comparisons
                     WHERE chat_id=?3
                   )",
                params![entity_id, now, chat_id],
            )?,
            "skill_candidate" => conn.execute(
                "UPDATE skill_candidates SET status='archived', updated_at=?2
                 WHERE candidate_id=?1 AND status NOT IN ('promoted','archived')
                   AND claim_id IN (
                     SELECT c.claim_id FROM learning_claims c
                     JOIN experience_comparisons x
                       ON x.comparison_id=c.comparison_id
                     WHERE x.chat_id=?3
                   )",
                params![entity_id, now, chat_id],
            )?,
            _ => {
                return Err(MicroClawError::ToolExecution(
                    "unsupported learning entity type".into(),
                ));
            }
        };
        if changed > 0 {
            conn.execute(
                "INSERT INTO learning_journal_events(
                    event_type, entity_type, entity_id, summary,
                    evidence_json, created_at
                 ) VALUES ('entity_archived',?1,?2,?3,?4,?5)",
                params![
                    entity_type,
                    entity_id,
                    format!("archived {entity_type} {entity_id}"),
                    serde_json::json!({"chat_id": chat_id}).to_string(),
                    now
                ],
            )?;
        }
        Ok(changed > 0)
    }

    pub fn get_learning_journal(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<LearningJournalEvent>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, event_type, entity_type, entity_id, summary,
                    evidence_json, undo_action, created_at
             FROM learning_journal_events j
             WHERE ?1 IS NULL OR EXISTS(
               SELECT 1 FROM experience_comparisons x
               LEFT JOIN learning_claims c ON c.comparison_id=x.comparison_id
               LEFT JOIN skill_candidates k ON k.claim_id=c.claim_id
               WHERE x.chat_id=?1 AND (
                 (j.entity_type='learning_claim' AND j.entity_id=c.claim_id)
                 OR (j.entity_type='skill_candidate' AND j.entity_id=k.candidate_id)
                 OR (j.entity_type='skill' AND j.entity_id=x.skill_name)
               )
             )
             ORDER BY j.created_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit.clamp(1, 500) as i64], |row| {
                let evidence: String = row.get(5)?;
                Ok(LearningJournalEvent {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    entity_type: row.get(2)?,
                    entity_id: row.get(3)?,
                    summary: row.get(4)?,
                    evidence: serde_json::from_str(&evidence).unwrap_or(serde_json::Value::Null),
                    undo_action: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_skill_governance_policy(&self) -> Result<SkillGovernancePolicy, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT candidate_failures_to_degrade, trial_min_outcomes,
                trial_promote_rate, trial_degrade_rate, trusted_min_outcomes,
                    trusted_degrade_rate, utility_confidence_z,
                    trial_promote_utility_lower_bound,
                    failure_pattern_min_failures, failure_pattern_cooldown_hours,
                    failure_pattern_recovery_successes, shadow_min_samples,
                    shadow_promote_utility_margin, shadow_max_cost_ratio,
                    shadow_max_regressions
             FROM skill_governance_policy WHERE singleton_id=1",
            [],
            |row| {
                Ok(SkillGovernancePolicy {
                    candidate_failures_to_degrade: row.get(0)?,
                    trial_min_outcomes: row.get(1)?,
                    trial_promote_rate: row.get(2)?,
                    trial_degrade_rate: row.get(3)?,
                    trusted_min_outcomes: row.get(4)?,
                    trusted_degrade_rate: row.get(5)?,
                    utility_confidence_z: row.get(6)?,
                    trial_promote_utility_lower_bound: row.get(7)?,
                    failure_pattern_min_failures: row.get(8)?,
                    failure_pattern_cooldown_hours: row.get(9)?,
                    failure_pattern_recovery_successes: row.get(10)?,
                    shadow_min_samples: row.get(11)?,
                    shadow_promote_utility_margin: row.get(12)?,
                    shadow_max_cost_ratio: row.get(13)?,
                    shadow_max_regressions: row.get(14)?,
                })
            },
        )
        .map_err(Into::into)
    }

    pub fn update_skill_governance_policy(
        &self,
        policy: &SkillGovernancePolicy,
    ) -> Result<(), MicroClawError> {
        validate_skill_governance_policy(policy)?;
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE skill_governance_policy
             SET candidate_failures_to_degrade=?1, trial_min_outcomes=?2,
                 trial_promote_rate=?3, trial_degrade_rate=?4,
                 trusted_min_outcomes=?5, trusted_degrade_rate=?6,
                 utility_confidence_z=?7,
                 trial_promote_utility_lower_bound=?8,
                 failure_pattern_min_failures=?9,
                 failure_pattern_cooldown_hours=?10,
                 failure_pattern_recovery_successes=?11,
                 shadow_min_samples=?12,
                 shadow_promote_utility_margin=?13,
                 shadow_max_cost_ratio=?14,
                 shadow_max_regressions=?15,
                 updated_at=?16
             WHERE singleton_id=1",
            params![
                policy.candidate_failures_to_degrade,
                policy.trial_min_outcomes,
                policy.trial_promote_rate,
                policy.trial_degrade_rate,
                policy.trusted_min_outcomes,
                policy.trusted_degrade_rate,
                policy.utility_confidence_z,
                policy.trial_promote_utility_lower_bound,
                policy.failure_pattern_min_failures,
                policy.failure_pattern_cooldown_hours,
                policy.failure_pattern_recovery_successes,
                policy.shadow_min_samples,
                policy.shadow_promote_utility_margin,
                policy.shadow_max_cost_ratio,
                policy.shadow_max_regressions,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        let now = chrono::Utc::now();
        let cooldown_until =
            (now + chrono::Duration::hours(policy.failure_pattern_cooldown_hours)).to_rfc3339();
        tx.execute(
            "UPDATE skill_failure_patterns
             SET state=CASE
                   WHEN failure_count < ?1 THEN 'observed'
                   WHEN state='observed' THEN 'active'
                   ELSE state END,
                 cooldown_until=CASE
                   WHEN failure_count < ?1 THEN NULL
                   WHEN state='observed' THEN ?2
                   ELSE cooldown_until END,
                 updated_at=?3",
            params![
                policy.failure_pattern_min_failures,
                cooldown_until,
                now.to_rfc3339()
            ],
        )?;
        let mut stmt = tx.prepare(
            "SELECT skill_name, active_version FROM skill_lifecycle
             WHERE state IN ('candidate','trial','trusted')",
        )?;
        let active = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for (skill_name, version) in active {
            evaluate_skill_lifecycle(&tx, &skill_name, version)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Append a row to the skill activation log. `chat_id` may be 0 for
    /// channel-less invocations (e.g. tests).
    pub fn log_skill_activation(
        &self,
        skill_name: &str,
        chat_id: i64,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let experience_run_id: Option<String> = conn
            .query_row(
                "SELECT run_id FROM experience_runs
                 WHERE chat_id=?1 AND status='running'
                 ORDER BY started_at DESC LIMIT 1",
                params![chat_id],
                |row| row.get(0),
            )
            .optional()?;
        let skill_version: Option<i64> = conn
            .query_row(
                "SELECT active_version FROM skill_lifecycle WHERE skill_name=?1",
                params![skill_name],
                |row| row.get(0),
            )
            .optional()?;
        conn.execute(
            "INSERT INTO skill_activation_logs(
                skill_name, chat_id, activated_at, experience_run_id, skill_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![skill_name, chat_id, now, experience_run_id, skill_version],
        )?;
        Ok(())
    }

    /// Most-recent activation timestamp for a skill, or `None` if never
    /// activated. Used by the auto-archive job.
    pub fn last_skill_activation_at(
        &self,
        skill_name: &str,
    ) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT activated_at FROM skill_activation_logs
             WHERE skill_name = ?1
             ORDER BY activated_at DESC
             LIMIT 1",
            params![skill_name],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(ts) => Ok(Some(ts)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Activation counts for every skill seen in the last `since` window.
    /// Returns `(skill_name, count)` rows ordered by count descending.
    /// Used by the insights surface and operator dashboards.
    pub fn skill_activation_counts_since(
        &self,
        since: &str,
    ) -> Result<Vec<(String, i64)>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT skill_name, COUNT(*) AS n
             FROM skill_activation_logs
             WHERE activated_at >= ?1
             GROUP BY skill_name
             ORDER BY n DESC, skill_name ASC",
        )?;
        let rows = stmt
            .query_map(params![since], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Overwrite the session label for a chat. No-op if the chat has no
    /// session row yet. Used by the title generator background task.
    pub fn set_session_label(&self, chat_id: i64, label: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE sessions SET label = ?1 WHERE chat_id = ?2",
            params![label, chat_id],
        )?;
        Ok(())
    }

    /// Return the current session label + message count for a chat. Used
    /// to decide whether the title generator should run.
    pub fn get_session_label_and_length(
        &self,
        chat_id: i64,
    ) -> Result<Option<(Option<String>, usize)>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn
            .query_row(
                "SELECT label, messages_json FROM sessions WHERE chat_id = ?1",
                params![chat_id],
                |row| {
                    let label: Option<String> = row.get(0)?;
                    let json: String = row.get(1)?;
                    Ok((label, json))
                },
            )
            .optional()?;
        let Some((label, json)) = result else {
            return Ok(None);
        };
        let count = serde_json::from_str::<Vec<serde_json::Value>>(&json)
            .map(|v| v.len())
            .unwrap_or(0);
        Ok(Some((label, count)))
    }

    pub fn save_session_settings(
        &self,
        chat_id: i64,
        settings: &SessionSettings,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (
                chat_id,
                messages_json,
                updated_at,
                label,
                thinking_level,
                verbose_level,
                reasoning_level
             )
             VALUES (?1, '[]', ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
                updated_at = excluded.updated_at,
                label = COALESCE(excluded.label, sessions.label),
                thinking_level = COALESCE(excluded.thinking_level, sessions.thinking_level),
                verbose_level = COALESCE(excluded.verbose_level, sessions.verbose_level),
                reasoning_level = COALESCE(excluded.reasoning_level, sessions.reasoning_level)",
            params![
                chat_id,
                now,
                settings.label,
                settings.thinking_level,
                settings.verbose_level,
                settings.reasoning_level
            ],
        )?;
        Ok(())
    }

    pub fn load_session_settings(
        &self,
        chat_id: i64,
    ) -> Result<Option<SessionSettings>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT label, thinking_level, verbose_level, reasoning_level
             FROM sessions
             WHERE chat_id = ?1",
            params![chat_id],
            |row| {
                Ok(SessionSettings {
                    label: row.get::<_, Option<String>>(0)?,
                    thinking_level: row.get::<_, Option<String>>(1)?,
                    verbose_level: row.get::<_, Option<String>>(2)?,
                    reasoning_level: row.get::<_, Option<String>>(3)?,
                })
            },
        );
        match result {
            Ok(settings) => Ok(Some(settings)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn load_session_meta(
        &self,
        chat_id: i64,
    ) -> Result<Option<SessionMetaRow>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT messages_json, updated_at, parent_session_key, fork_point
             FROM sessions WHERE chat_id = ?1",
            params![chat_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_session_meta(&self, limit: usize) -> Result<Vec<SessionTreeRow>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT chat_id, parent_session_key, fork_point, updated_at
             FROM sessions
             ORDER BY updated_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_session(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        Ok(rows > 0)
    }

    /// Clear all resettable chat state without deleting chat metadata or memories.
    /// This removes resumable session state, historical messages, and scheduled task state.
    pub fn clear_chat_context(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;
        affected += tx.execute(
            "DELETE FROM task_run_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM scheduled_task_dlq WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM scheduled_tasks WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    /// Clear conversational context for a chat while preserving scheduled task state.
    /// This removes resumable session state and historical messages only.
    pub fn clear_chat_conversation(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;
        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    /// Clear memory state for a chat without deleting chat/session/message history.
    /// This removes structured memories and reflector bookkeeping for the chat.
    pub fn clear_chat_memory(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;
        affected += erase_chat_learning(&tx, chat_id)?;
        affected += tx.execute(
            "DELETE FROM memory_reflector_state WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_reflector_runs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_injection_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_supersede_edges
             WHERE from_memory_id IN (SELECT id FROM memories WHERE chat_id = ?1)
                OR to_memory_id IN (SELECT id FROM memories WHERE chat_id = ?1)",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM memories WHERE chat_id = ?1", params![chat_id])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    pub fn delete_chat_data(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;

        affected += erase_chat_learning(&tx, chat_id)?;
        affected += tx.execute(
            "DELETE FROM llm_usage_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute(
            "DELETE FROM scheduled_tasks WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_reflector_state WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_reflector_runs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_injection_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_supersede_edges
             WHERE from_memory_id IN (SELECT id FROM memories WHERE chat_id = ?1)
                OR to_memory_id IN (SELECT id FROM memories WHERE chat_id = ?1)",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM memories WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM chats WHERE chat_id = ?1", params![chat_id])?;

        tx.commit()?;
        Ok(affected > 0)
    }

    // --- Auth: password/session/api-key ---

    pub fn upsert_auth_password_hash(&self, password_hash: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO auth_passwords(id, password_hash, created_at, updated_at)
             VALUES(1, ?1, ?2, ?2)
             ON CONFLICT(id) DO UPDATE SET
                password_hash = excluded.password_hash,
                updated_at = excluded.updated_at",
            params![password_hash, now],
        )?;
        Ok(())
    }

    pub fn get_auth_password_hash(&self) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let value = conn
            .query_row(
                "SELECT password_hash FROM auth_passwords WHERE id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn clear_auth_password_hash(&self) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute("DELETE FROM auth_passwords WHERE id = 1", [])?;
        Ok(rows > 0)
    }

    pub fn create_auth_session(
        &self,
        session_id: &str,
        label: Option<&str>,
        expires_at: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO auth_sessions(session_id, label, created_at, expires_at, last_seen_at, revoked_at)
             VALUES(?1, ?2, ?3, ?4, ?3, NULL)",
            params![session_id, label, now, expires_at],
        )?;
        Ok(())
    }

    pub fn validate_auth_session(&self, session_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let valid = conn
            .query_row(
                "SELECT 1
                 FROM auth_sessions
                 WHERE session_id = ?1
                   AND revoked_at IS NULL
                   AND expires_at > ?2
                 LIMIT 1",
                params![session_id, now],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if valid {
            let _ = conn.execute(
                "UPDATE auth_sessions SET last_seen_at = ?2 WHERE session_id = ?1",
                params![session_id, now],
            );
        }
        Ok(valid)
    }

    pub fn revoke_auth_session(&self, session_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE session_id = ?1",
            params![session_id, now],
        )?;
        Ok(rows > 0)
    }

    pub fn revoke_all_auth_sessions(&self) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?1)
             WHERE revoked_at IS NULL",
            params![now],
        )?;
        Ok(rows)
    }

    pub fn create_api_key(
        &self,
        label: &str,
        key_hash: &str,
        prefix: &str,
        scopes: &[String],
        expires_at: Option<&str>,
        rotated_from_key_id: Option<i64>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO api_keys(label, key_hash, prefix, created_at, expires_at, rotated_from_key_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![label, key_hash, prefix, now, expires_at, rotated_from_key_id],
        )?;
        let key_id = tx.last_insert_rowid();
        for scope in scopes {
            tx.execute(
                "INSERT OR IGNORE INTO api_key_scopes(api_key_id, scope) VALUES(?1, ?2)",
                params![key_id, scope],
            )?;
        }
        tx.commit()?;
        Ok(key_id)
    }

    pub fn list_api_keys(&self) -> Result<Vec<AuthApiKeyRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, label, prefix, created_at, revoked_at, expires_at, last_used_at, rotated_from_key_id
             FROM api_keys
             ORDER BY id DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let mut scopes_stmt = conn.prepare(
                "SELECT scope FROM api_key_scopes WHERE api_key_id = ?1 ORDER BY scope ASC",
            )?;
            let scopes = scopes_stmt
                .query_map(params![id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            out.push(AuthApiKeyRecord {
                id,
                label: row.get(1)?,
                prefix: row.get(2)?,
                created_at: row.get(3)?,
                revoked_at: row.get(4)?,
                expires_at: row.get(5)?,
                last_used_at: row.get(6)?,
                rotated_from_key_id: row.get(7)?,
                scopes,
            });
        }
        Ok(out)
    }

    pub fn rotate_api_key_revoke_old(&self, old_key_id: i64) -> Result<bool, MicroClawError> {
        self.revoke_api_key(old_key_id)
    }

    pub fn revoke_api_key(&self, key_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE api_keys
             SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE id = ?1",
            params![key_id, now],
        )?;
        Ok(rows > 0)
    }

    pub fn validate_api_key_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<(i64, Vec<String>)>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id FROM api_keys
                 WHERE key_hash = ?1
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?2)
                 LIMIT 1",
                params![key_hash, chrono::Utc::now().to_rfc3339()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        let Some(key_id) = row else {
            return Ok(None);
        };
        let now = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE api_keys SET last_used_at = ?2 WHERE id = ?1",
            params![key_id, now],
        );
        let mut stmt = conn
            .prepare("SELECT scope FROM api_key_scopes WHERE api_key_id = ?1 ORDER BY scope ASC")?;
        let scopes = stmt
            .query_map(params![key_id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some((key_id, scopes)))
    }

    pub fn log_audit_event(
        &self,
        kind: &str,
        actor: &str,
        action: &str,
        target: Option<&str>,
        status: &str,
        detail: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        // Seal the entry into the hash chain. Reading the latest sealed hash and
        // inserting happen under the same connection lock, so concurrent callers
        // can't race the chain.
        let prev_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM audit_logs
                 WHERE entry_hash IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| AUDIT_GENESIS_HASH.to_string());
        let entry_hash = audit_entry_hash(
            &prev_hash, kind, actor, action, target, status, detail, &now,
        );
        conn.execute(
            "INSERT INTO audit_logs(kind, actor, action, target, status, detail, created_at, prev_hash, entry_hash)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![kind, actor, action, target, status, detail, now, prev_hash, entry_hash],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Verify the tamper-evident audit hash chain. Walks all sealed entries in
    /// `id` order, checking that each links to the previous (`prev_hash`) and
    /// that its `entry_hash` still matches its content. Returns the first break,
    /// if any. Unsealed legacy rows (NULL `entry_hash`) are ignored.
    pub fn verify_audit_chain(&self) -> Result<AuditChainStatus, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, kind, actor, action, target, status, detail, created_at, prev_hash, entry_hash
             FROM audit_logs
             WHERE entry_hash IS NOT NULL
             ORDER BY id ASC",
        )?;
        // Collect first so the statement borrow is released before we iterate.
        let rows: Vec<AuditChainRow> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut expected_prev = AUDIT_GENESIS_HASH.to_string();
        let mut sealed = 0usize;
        for (id, kind, actor, action, target, status, detail, created_at, prev_hash, entry_hash) in
            &rows
        {
            sealed += 1;
            let prev = prev_hash.as_deref().unwrap_or("");
            if prev != expected_prev {
                return Ok(AuditChainStatus {
                    sealed_entries: sealed,
                    intact: false,
                    broken_at: Some(*id),
                    reason: Some(
                        "prev_hash does not link to the previous entry (an entry was deleted, inserted, or reordered)".to_string(),
                    ),
                });
            }
            let recomputed = audit_entry_hash(
                prev,
                kind,
                actor,
                action,
                target.as_deref(),
                status,
                detail.as_deref(),
                created_at,
            );
            if &recomputed != entry_hash {
                return Ok(AuditChainStatus {
                    sealed_entries: sealed,
                    intact: false,
                    broken_at: Some(*id),
                    reason: Some(
                        "entry_hash does not match content (an entry was modified)".to_string(),
                    ),
                });
            }
            expected_prev = entry_hash.clone();
        }

        Ok(AuditChainStatus {
            sealed_entries: sealed,
            intact: true,
            broken_at: None,
            reason: None,
        })
    }

    pub fn list_audit_logs(
        &self,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditLogRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut rows = Vec::new();
        if let Some(k) = kind {
            let mut stmt = conn.prepare(
                "SELECT id, kind, actor, action, target, status, detail, created_at
                 FROM audit_logs
                 WHERE kind = ?1
                 ORDER BY id DESC
                 LIMIT ?2",
            )?;
            let iter = stmt.query_map(params![k, limit as i64], |row| {
                Ok(AuditLogRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    status: row.get(5)?,
                    detail: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?;
            for item in iter {
                rows.push(item?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, kind, actor, action, target, status, detail, created_at
                 FROM audit_logs
                 ORDER BY id DESC
                 LIMIT ?1",
            )?;
            let iter = stmt.query_map(params![limit as i64], |row| {
                Ok(AuditLogRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    status: row.get(5)?,
                    detail: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?;
            for item in iter {
                rows.push(item?);
            }
        }
        Ok(rows)
    }

    // --- Metrics history ---

    pub fn upsert_metrics_history(
        &self,
        point: &MetricsHistoryPoint,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO metrics_history(
                timestamp_ms, llm_completions, llm_input_tokens, llm_output_tokens,
                http_requests, tool_executions, mcp_calls,
                mcp_rate_limited_rejections, mcp_bulkhead_rejections, mcp_circuit_open_rejections,
                active_sessions
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(timestamp_ms) DO UPDATE SET
                llm_completions = excluded.llm_completions,
                llm_input_tokens = excluded.llm_input_tokens,
                llm_output_tokens = excluded.llm_output_tokens,
                http_requests = excluded.http_requests,
                tool_executions = excluded.tool_executions,
                mcp_calls = excluded.mcp_calls,
                mcp_rate_limited_rejections = excluded.mcp_rate_limited_rejections,
                mcp_bulkhead_rejections = excluded.mcp_bulkhead_rejections,
                mcp_circuit_open_rejections = excluded.mcp_circuit_open_rejections,
                active_sessions = excluded.active_sessions",
            params![
                point.timestamp_ms,
                point.llm_completions,
                point.llm_input_tokens,
                point.llm_output_tokens,
                point.http_requests,
                point.tool_executions,
                point.mcp_calls,
                point.mcp_rate_limited_rejections,
                point.mcp_bulkhead_rejections,
                point.mcp_circuit_open_rejections,
                point.active_sessions
            ],
        )?;
        Ok(())
    }

    pub fn get_metrics_history(
        &self,
        since_ts_ms: i64,
        limit: usize,
    ) -> Result<Vec<MetricsHistoryPoint>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT
                timestamp_ms, llm_completions, llm_input_tokens, llm_output_tokens,
                http_requests, tool_executions, mcp_calls,
                mcp_rate_limited_rejections, mcp_bulkhead_rejections, mcp_circuit_open_rejections,
                active_sessions
             FROM metrics_history
             WHERE timestamp_ms >= ?1
             ORDER BY timestamp_ms ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![since_ts_ms, limit as i64], |row| {
                Ok(MetricsHistoryPoint {
                    timestamp_ms: row.get(0)?,
                    llm_completions: row.get(1)?,
                    llm_input_tokens: row.get(2)?,
                    llm_output_tokens: row.get(3)?,
                    http_requests: row.get(4)?,
                    tool_executions: row.get(5)?,
                    mcp_calls: row.get(6)?,
                    mcp_rate_limited_rejections: row.get(7)?,
                    mcp_bulkhead_rejections: row.get(8)?,
                    mcp_circuit_open_rejections: row.get(9)?,
                    active_sessions: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn cleanup_metrics_history_before(
        &self,
        before_ts_ms: i64,
    ) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM metrics_history WHERE timestamp_ms < ?1",
            params![before_ts_ms],
        )?;
        Ok(n)
    }

    pub fn get_new_user_messages_since(
        &self,
        chat_id: i64,
        since: &str,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
             FROM messages
             WHERE chat_id = ?1 AND timestamp > ?2 AND is_from_bot = 0
             ORDER BY timestamp ASC",
        )?;
        let messages = stmt
            .query_map(params![chat_id, since], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    sender_name: row.get(2)?,
                    content: row.get(3)?,
                    is_from_bot: row.get::<_, i32>(4)? != 0,
                    timestamp: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    pub fn get_messages_since(
        &self,
        chat_id: i64,
        since: &str,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
             FROM messages
             WHERE chat_id = ?1 AND timestamp > ?2
             ORDER BY timestamp ASC
             LIMIT ?3",
        )?;
        let messages = stmt
            .query_map(params![chat_id, since, limit as i64], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    sender_name: row.get(2)?,
                    content: row.get(3)?,
                    is_from_bot: row.get::<_, i32>(4)? != 0,
                    timestamp: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    /// Full-text search over stored messages using the SQLite FTS5 index.
    ///
    /// `query` must be a valid FTS5 match expression (simple words are OK,
    /// e.g. `"rust async"`). Returns ranked matches newest-first for
    /// equally-ranked rows. When `chat_id` is `Some`, the search is scoped to
    /// that chat; otherwise it spans all chats. When `since` is `Some`, only
    /// messages with timestamp >= that value are returned. Results are
    /// truncated to `limit` rows.
    pub fn search_messages_fts(
        &self,
        query: &str,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, 200) as i64;
        let conn = self.lock_conn();

        let mut sql = String::from(
            "SELECT m.id, m.chat_id, m.sender_name, m.content, m.is_from_bot, m.timestamp
             FROM messages_fts f
             JOIN messages m ON m.id = f.message_id AND m.chat_id = f.chat_id
             WHERE f.content MATCH ?1",
        );
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(query.to_string())];
        if let Some(cid) = chat_id {
            sql.push_str(" AND m.chat_id = ?");
            sql.push_str(&(binds.len() + 1).to_string());
            binds.push(Box::new(cid));
        }
        if let Some(ts) = since {
            sql.push_str(" AND m.timestamp >= ?");
            sql.push_str(&(binds.len() + 1).to_string());
            binds.push(Box::new(ts.to_string()));
        }
        sql.push_str(" ORDER BY bm25(messages_fts), m.timestamp DESC LIMIT ?");
        sql.push_str(&(binds.len() + 1).to_string());
        binds.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql)?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let messages = stmt
            .query_map(
                rusqlite::params_from_iter(bind_refs.iter().copied()),
                |row| {
                    Ok(StoredMessage {
                        id: row.get(0)?,
                        chat_id: row.get(1)?,
                        sender_name: row.get(2)?,
                        content: row.get(3)?,
                        is_from_bot: row.get::<_, i32>(4)? != 0,
                        timestamp: row.get(5)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    pub fn get_reflector_cursor(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT last_reflected_ts FROM memory_reflector_state WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(ts) => Ok(Some(ts)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_reflector_cursor(
        &self,
        chat_id: i64,
        last_reflected_ts: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memory_reflector_state (chat_id, last_reflected_ts, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(chat_id) DO UPDATE SET
                last_reflected_ts = excluded.last_reflected_ts,
                updated_at = excluded.updated_at",
            params![chat_id, last_reflected_ts, now],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_llm_usage(
        &self,
        chat_id: i64,
        caller_channel: &str,
        provider: &str,
        model: &str,
        input_tokens: i64,
        output_tokens: i64,
        request_kind: &str,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let total_tokens = input_tokens.saturating_add(output_tokens);
        conn.execute(
            "INSERT INTO llm_usage_logs
                (chat_id, caller_channel, provider, model, input_tokens, output_tokens, total_tokens, request_kind, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                chat_id,
                caller_channel,
                provider,
                model,
                input_tokens,
                output_tokens,
                total_tokens,
                request_kind,
                now,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_llm_usage_summary(
        &self,
        chat_id: Option<i64>,
    ) -> Result<LlmUsageSummary, MicroClawError> {
        self.get_llm_usage_summary_since(chat_id, None)
    }

    pub fn get_llm_usage_summary_since(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
    ) -> Result<LlmUsageSummary, MicroClawError> {
        let conn = self.lock_conn();
        let (requests, input_tokens, output_tokens, total_tokens, last_request_at) =
            match (chat_id, since) {
                (Some(id), Some(since_ts)) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs
                 WHERE chat_id = ?1 AND created_at >= ?2",
                    params![id, since_ts],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
                (Some(id), None) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs
                 WHERE chat_id = ?1",
                    params![id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
                (None, Some(since_ts)) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs
                 WHERE created_at >= ?1",
                    params![since_ts],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
                (None, None) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
            };

        Ok(LlmUsageSummary {
            requests,
            input_tokens,
            output_tokens,
            total_tokens,
            last_request_at,
        })
    }

    pub fn get_llm_usage_by_model(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<LlmModelUsageSummary>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT
                model,
                COUNT(*) AS requests,
                COALESCE(SUM(input_tokens), 0) AS input_tokens,
                COALESCE(SUM(output_tokens), 0) AS output_tokens,
                COALESCE(SUM(total_tokens), 0) AS total_tokens
             FROM llm_usage_logs",
        );

        let mut has_where = false;
        if chat_id.is_some() {
            query.push_str(" WHERE chat_id = ?1");
            has_where = true;
        }
        if since.is_some() {
            if has_where {
                if chat_id.is_some() {
                    query.push_str(" AND created_at >= ?2");
                } else {
                    query.push_str(" AND created_at >= ?1");
                }
            } else {
                query.push_str(" WHERE created_at >= ?1");
            }
        }
        query.push_str(" GROUP BY model ORDER BY total_tokens DESC");
        if limit.is_some() {
            match (chat_id.is_some(), since.is_some()) {
                (true, true) => query.push_str(" LIMIT ?3"),
                (true, false) | (false, true) => query.push_str(" LIMIT ?2"),
                (false, false) => query.push_str(" LIMIT ?1"),
            }
        }

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(LlmModelUsageSummary {
                model: row.get(0)?,
                requests: row.get(1)?,
                input_tokens: row.get(2)?,
                output_tokens: row.get(3)?,
                total_tokens: row.get(4)?,
            })
        };

        let rows = match (chat_id, since, limit) {
            (Some(id), Some(since_ts), Some(limit_n)) => {
                stmt.query_map(params![id, since_ts, limit_n as i64], mapper)?
            }
            (Some(id), Some(since_ts), None) => stmt.query_map(params![id, since_ts], mapper)?,
            (Some(id), None, Some(limit_n)) => {
                stmt.query_map(params![id, limit_n as i64], mapper)?
            }
            (Some(id), None, None) => stmt.query_map(params![id], mapper)?,
            (None, Some(since_ts), Some(limit_n)) => {
                stmt.query_map(params![since_ts, limit_n as i64], mapper)?
            }
            (None, Some(since_ts), None) => stmt.query_map(params![since_ts], mapper)?,
            (None, None, Some(limit_n)) => stmt.query_map(params![limit_n as i64], mapper)?,
            (None, None, None) => stmt.query_map([], mapper)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // --- Memories ---

    pub fn insert_memory(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
    ) -> Result<i64, MicroClawError> {
        self.insert_memory_with_metadata(chat_id, content, category, "tool", 0.80)
    }

    pub fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let (chat_channel, external_chat_id) = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT channel, external_chat_id FROM chats WHERE chat_id = ?1",
                params![cid],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?
            .unwrap_or((None, None))
        } else {
            (None, None)
        };
        conn.execute(
            "INSERT INTO memories (
                chat_id, content, category, created_at, updated_at, embedding_model,
                confidence, source, last_seen_at, is_archived, archived_at,
                chat_channel, external_chat_id
            ) VALUES (?1, ?2, ?3, ?4, ?4, NULL, ?5, ?6, ?4, 0, NULL, ?7, ?8)",
            params![
                chat_id,
                content,
                category,
                now,
                confidence.clamp(0.0, 1.0),
                source,
                chat_channel,
                external_chat_id
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories
             WHERE (chat_id = ?1 OR chat_id IS NULL)
               AND is_archived = 0
               AND confidence >= 0.45
               AND (expires_at IS NULL OR expires_at > ?3)
             ORDER BY updated_at DESC
             LIMIT ?2",
        )?;
        let memories = stmt
            .query_map(params![chat_id, limit as i64, now], |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                    expires_at: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
    }

    pub fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories
             WHERE (chat_id = ?1 OR (?1 IS NULL AND chat_id IS NULL))",
        )?;
        let memories = stmt
            .query_map(params![chat_id], |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                    expires_at: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
    }

    /// Total number of stored messages in a chat (both sides). Used as a cheap
    /// proxy for how well the bot "knows" this person.
    pub fn count_messages_for_chat(&self, chat_id: i64) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    pub fn get_active_chat_ids_since(&self, since: &str) -> Result<Vec<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT chat_id FROM messages WHERE timestamp > ?1 AND is_from_bot = 0",
        )?;
        let ids = stmt
            .query_map(params![since], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Chats whose most recent message is older than `cutoff` (i.e. idle since
    /// then). Only chats that have ever had a message are returned.
    pub fn list_idle_chats(&self, cutoff: &str, limit: usize) -> Result<Vec<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT chat_id FROM messages
             GROUP BY chat_id
             HAVING MAX(timestamp) < ?1
             LIMIT ?2",
        )?;
        let ids = stmt
            .query_map(params![cutoff, limit.max(1) as i64], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Keyword search in memories visible to chat_id (own + global).
    pub fn search_memories(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.search_memories_with_options(chat_id, query, limit, false, true)
    }

    pub fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let pattern = format!("%{}%", query.to_lowercase());
        let now = chrono::Utc::now().to_rfc3339();
        let mut sql = String::from(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories
             WHERE (chat_id = ?1 OR chat_id IS NULL)
               AND LOWER(content) LIKE ?2
               AND (expires_at IS NULL OR expires_at > ?4)",
        );
        if !include_archived {
            sql.push_str(" AND is_archived = 0");
        }
        if !broad_recall {
            sql.push_str(" AND confidence >= 0.45");
        }
        sql.push_str(" ORDER BY confidence DESC, updated_at DESC LIMIT ?3");
        let mut stmt = conn.prepare(&sql)?;
        let memories = stmt
            .query_map(params![chat_id, pattern, limit as i64, now], |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                    expires_at: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
    }

    /// Delete a memory row by id. Returns true if a row was deleted.
    pub fn delete_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute("DELETE FROM memories WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    /// Set or clear the `expires_at` of a memory. Pass `None` to clear.
    pub fn set_memory_expires_at(
        &self,
        id: i64,
        expires_at: Option<&str>,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
            params![expires_at, id],
        )?;
        Ok(rows > 0)
    }

    /// Hard-delete memories whose `expires_at` is at or before `now`.
    /// Returns the number of rows deleted. Called from the reflector on its
    /// scheduled tick.
    pub fn prune_expired_memories(&self, now: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
    }

    /// Update content and category of an existing memory. Returns true if found.
    pub fn update_memory_content(
        &self,
        id: i64,
        content: &str,
        category: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET content = ?1,
                 category = ?2,
                 updated_at = ?3,
                 embedding_model = NULL,
                 last_seen_at = ?3,
                 is_archived = 0,
                 archived_at = NULL
             WHERE id = ?4",
            params![content, category, now, id],
        )?;
        Ok(rows > 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET content = ?1,
                 category = ?2,
                 updated_at = ?3,
                 embedding_model = NULL,
                 confidence = ?4,
                 source = ?5,
                 last_seen_at = ?3,
                 is_archived = 0,
                 archived_at = NULL
             WHERE id = ?6",
            params![
                content,
                category,
                now,
                confidence.clamp(0.0, 1.0),
                source,
                id
            ],
        )?;
        Ok(rows > 0)
    }

    pub fn update_memory_embedding_model(
        &self,
        id: i64,
        model: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE memories SET embedding_model = ?1 WHERE id = ?2",
            params![model, id],
        )?;
        Ok(rows > 0)
    }

    pub fn get_memories_without_embedding(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model
             , confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories
             WHERE embedding_model IS NULL
               AND is_archived = 0",
        );
        if chat_id.is_some() {
            query.push_str(" AND chat_id = ?1");
        }
        query.push_str(" ORDER BY updated_at DESC LIMIT ");
        query.push_str(&limit.to_string());

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(Memory {
                id: row.get(0)?,
                chat_id: row.get(1)?,
                content: row.get(2)?,
                category: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                embedding_model: row.get(6)?,
                confidence: row.get(7)?,
                source: row.get(8)?,
                last_seen_at: row.get(9)?,
                is_archived: row.get::<_, i64>(10)? != 0,
                archived_at: row.get(11)?,
                expires_at: row.get(12)?,
            })
        };

        let rows = if let Some(cid) = chat_id {
            stmt.query_map(params![cid], mapper)?
        } else {
            stmt.query_map([], mapper)?
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    #[cfg(feature = "sqlite-vec")]
    pub fn prepare_vector_index(&self, dimension: usize) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let dimension = dimension.max(1);
        conn.execute(
            "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )?;

        let current_dim: Option<String> = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'embedding_dim'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = current_dim {
            if existing != dimension.to_string() {
                conn.execute("DROP TABLE IF EXISTS memories_vec", [])?;
                conn.execute("UPDATE memories SET embedding_model = NULL", [])?;
            }
        }

        conn.execute(
            &format!(
                "CREATE VIRTUAL TABLE IF NOT EXISTS memories_vec USING vec0(
                    embedding float[{dimension}] distance_metric=cosine
                )"
            ),
            [],
        )?;
        conn.execute(
            "INSERT INTO db_meta(key, value) VALUES('embedding_dim', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![dimension.to_string()],
        )?;
        Ok(())
    }

    #[cfg(feature = "sqlite-vec")]
    pub fn upsert_memory_vec(
        &self,
        memory_id: i64,
        embedding: &[f32],
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let vector_json = serde_json::to_string(embedding)?;
        conn.execute(
            "INSERT OR REPLACE INTO memories_vec(rowid, embedding) VALUES(?1, vec_f32(?2))",
            params![memory_id, vector_json],
        )?;
        Ok(())
    }

    pub fn get_all_active_memories(&self) -> Result<Vec<(i64, String)>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt =
            conn.prepare("SELECT id, content FROM memories WHERE is_archived = 0 ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    #[cfg(feature = "sqlite-vec")]
    pub fn knn_memories(
        &self,
        chat_id: i64,
        query_vec: &[f32],
        k: usize,
    ) -> Result<Vec<(i64, f32)>, MicroClawError> {
        let conn = self.lock_conn();
        let vector_json = serde_json::to_string(query_vec)?;
        let mut stmt = conn.prepare(
            "SELECT m.id, v.distance
             FROM (
                SELECT rowid, distance
                FROM memories_vec
                WHERE embedding MATCH vec_f32(?1) AND k = ?2
             ) v
             JOIN memories m ON m.id = v.rowid
             WHERE (m.chat_id = ?3 OR m.chat_id IS NULL)
             ORDER BY v.distance ASC",
        )?;
        let rows = stmt.query_map(params![vector_json, k as i64, chat_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f32>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get a single memory by id.
    pub fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories WHERE id = ?1",
            params![id],
            |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                    expires_at: row.get(12)?,
                })
            },
        );
        match result {
            Ok(m) => Ok(Some(m)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = if let Some(floor) = confidence_floor {
            conn.execute(
                "UPDATE memories
                 SET last_seen_at = ?1,
                     confidence = MAX(confidence, ?2)
                 WHERE id = ?3",
                params![now, floor.clamp(0.0, 1.0), id],
            )?
        } else {
            conn.execute(
                "UPDATE memories SET last_seen_at = ?1 WHERE id = ?2",
                params![now, id],
            )?
        };
        Ok(rows > 0)
    }

    pub fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET is_archived = 1, archived_at = ?1, updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
        Ok(rows > 0)
    }

    pub fn archive_stale_memories(&self, stale_days: i64) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(stale_days.max(1))).to_rfc3339();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET is_archived = 1, archived_at = ?1, updated_at = ?1
             WHERE is_archived = 0
               AND confidence < 0.35
               AND COALESCE(last_seen_at, updated_at, created_at) < ?2",
            params![now, cutoff],
        )?;
        Ok(rows)
    }

    /// Archive the lowest-confidence, least-recently-seen memories for a chat
    /// (or global if `chat_id` is None) when the count exceeds `max_entries`.
    /// Returns the number of memories archived.
    pub fn archive_excess_memories(
        &self,
        chat_id: Option<i64>,
        max_entries: usize,
    ) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let count: usize = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE is_archived = 0 AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE is_archived = 0 AND chat_id IS NULL",
                [],
                |row| row.get(0),
            )?
        };
        if count <= max_entries {
            return Ok(0);
        }
        let excess = count - max_entries;
        let now = chrono::Utc::now().to_rfc3339();
        let rows = if let Some(cid) = chat_id {
            conn.execute(
                "UPDATE memories SET is_archived = 1, archived_at = ?1, updated_at = ?1
                 WHERE is_archived = 0 AND chat_id = ?2
                   AND id IN (
                     SELECT id FROM memories
                     WHERE is_archived = 0 AND chat_id = ?2
                     ORDER BY confidence ASC, COALESCE(last_seen_at, updated_at, created_at) ASC
                     LIMIT ?3
                   )",
                params![now, cid, excess],
            )?
        } else {
            conn.execute(
                "UPDATE memories SET is_archived = 1, archived_at = ?1, updated_at = ?1
                 WHERE is_archived = 0 AND chat_id IS NULL
                   AND id IN (
                     SELECT id FROM memories
                     WHERE is_archived = 0 AND chat_id IS NULL
                     ORDER BY confidence ASC, COALESCE(last_seen_at, updated_at, created_at) ASC
                     LIMIT ?2
                   )",
                params![now, excess],
            )?
        };
        Ok(rows)
    }

    pub fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let (chat_id, chat_channel, external_chat_id): (
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT chat_id, chat_channel, external_chat_id FROM memories WHERE id = ?1",
            params![from_memory_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO memories (
                chat_id, content, category, created_at, updated_at, embedding_model,
                confidence, source, last_seen_at, is_archived, archived_at, chat_channel, external_chat_id
            ) VALUES (?1, ?2, ?3, ?4, ?4, NULL, ?5, ?6, ?4, 0, NULL, ?7, ?8)",
            params![
                chat_id,
                new_content,
                category,
                now,
                confidence.clamp(0.0, 1.0),
                source,
                chat_channel,
                external_chat_id
            ],
        )?;
        let to_memory_id = tx.last_insert_rowid();

        tx.execute(
            "UPDATE memories
             SET is_archived = 1, archived_at = ?1, updated_at = ?1
             WHERE id = ?2",
            params![now, from_memory_id],
        )?;
        tx.execute(
            "INSERT INTO memory_supersede_edges(from_memory_id, to_memory_id, reason, created_at)
             VALUES(?1, ?2, ?3, ?4)",
            params![from_memory_id, to_memory_id, reason, now],
        )?;
        tx.commit()?;
        Ok(to_memory_id)
    }

    // ── Knowledge Graph operations ──

    /// Insert a new knowledge graph triple.
    #[allow(clippy::too_many_arguments)]
    pub fn kg_insert_triple(
        &self,
        subject: &str,
        predicate: &str,
        object: &str,
        chat_id: Option<i64>,
        valid_from: &str,
        confidence: f64,
        source: &str,
        source_memory_id: Option<i64>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO knowledge_graph (subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9)",
            params![
                subject,
                predicate,
                object,
                chat_id,
                valid_from,
                confidence.clamp(0.0, 1.0),
                source,
                source_memory_id,
                now
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Invalidate a triple by setting its valid_to timestamp.
    pub fn kg_invalidate_triple(&self, id: i64, valid_to: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE knowledge_graph SET valid_to = ?1 WHERE id = ?2 AND valid_to IS NULL",
            params![valid_to, id],
        )?;
        Ok(rows > 0)
    }

    /// Query triples by subject, optionally filtered by a point-in-time (as_of).
    pub fn kg_query_subject(
        &self,
        subject: &str,
        chat_id: Option<i64>,
        as_of: Option<&str>,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        let conn = self.lock_conn();
        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<KgTriple> {
            Ok(KgTriple {
                id: row.get(0)?,
                subject: row.get(1)?,
                predicate: row.get(2)?,
                object: row.get(3)?,
                chat_id: row.get(4)?,
                valid_from: row.get(5)?,
                valid_to: row.get(6)?,
                confidence: row.get(7)?,
                source: row.get(8)?,
                source_memory_id: row.get(9)?,
                created_at: row.get(10)?,
            })
        };
        if let Some(ts) = as_of {
            let mut stmt = conn.prepare(
                "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
                 FROM knowledge_graph
                 WHERE LOWER(subject) = LOWER(?1)
                   AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
                   AND valid_from <= ?3
                   AND (valid_to IS NULL OR valid_to > ?3)
                 ORDER BY valid_from DESC",
            )?;
            let rows = stmt
                .query_map(params![subject, chat_id, ts], map_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
                 FROM knowledge_graph
                 WHERE LOWER(subject) = LOWER(?1)
                   AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
                   AND valid_to IS NULL
                 ORDER BY valid_from DESC",
            )?;
            let rows = stmt
                .query_map(params![subject, chat_id], map_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    /// Query triples by object (reverse lookup).
    pub fn kg_query_object(
        &self,
        object: &str,
        chat_id: Option<i64>,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
             FROM knowledge_graph
             WHERE LOWER(object) = LOWER(?1)
               AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
               AND valid_to IS NULL
             ORDER BY valid_from DESC",
        )?;
        let rows = stmt
            .query_map(params![object, chat_id], |row| {
                Ok(KgTriple {
                    id: row.get(0)?,
                    subject: row.get(1)?,
                    predicate: row.get(2)?,
                    object: row.get(3)?,
                    chat_id: row.get(4)?,
                    valid_from: row.get(5)?,
                    valid_to: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    source_memory_id: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Distinct active entities (subjects and objects) for a chat, used to find
    /// which graph nodes a query mentions so retrieval can be seeded from them.
    pub fn kg_distinct_entities(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<String>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT entity FROM (
                 SELECT subject AS entity FROM knowledge_graph
                 WHERE (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL) AND valid_to IS NULL
                 UNION
                 SELECT object AS entity FROM knowledge_graph
                 WHERE (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL) AND valid_to IS NULL
             )
             ORDER BY LENGTH(entity) DESC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Bounded breadth-first expansion of the knowledge graph from `seed`
    /// entities, returning the active triples reachable within `max_hops`. This
    /// is the graph-augmented retrieval primitive: seed from entities a query
    /// mentions, then pull in directly-connected facts (and their neighbours)
    /// so multi-hop context surfaces without the agent having to query the graph
    /// by hand. Bounded by `total_limit` triples and a per-hop frontier cap, so
    /// it stays cheap even on large graphs.
    pub fn kg_neighborhood(
        &self,
        chat_id: Option<i64>,
        seeds: &[String],
        max_hops: usize,
        total_limit: usize,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        if seeds.is_empty() || total_limit == 0 || max_hops == 0 {
            return Ok(Vec::new());
        }
        const FRONTIER_CAP: usize = 32;
        const PER_NODE_LIMIT: i64 = 8;
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
             FROM knowledge_graph
             WHERE (LOWER(subject) = LOWER(?1) OR LOWER(object) = LOWER(?1))
               AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
               AND valid_to IS NULL
             ORDER BY confidence DESC
             LIMIT ?3",
        )?;
        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<KgTriple> {
            Ok(KgTriple {
                id: row.get(0)?,
                subject: row.get(1)?,
                predicate: row.get(2)?,
                object: row.get(3)?,
                chat_id: row.get(4)?,
                valid_from: row.get(5)?,
                valid_to: row.get(6)?,
                confidence: row.get(7)?,
                source: row.get(8)?,
                source_memory_id: row.get(9)?,
                created_at: row.get(10)?,
            })
        };

        let mut visited_entities: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut seen_triples: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut frontier: Vec<String> = Vec::new();
        for s in seeds {
            let lc = s.to_lowercase();
            if visited_entities.insert(lc) {
                frontier.push(s.clone());
            }
        }
        let mut out: Vec<KgTriple> = Vec::new();

        for _hop in 0..max_hops {
            if out.len() >= total_limit || frontier.is_empty() {
                break;
            }
            frontier.truncate(FRONTIER_CAP);
            let mut next: Vec<String> = Vec::new();
            for entity in &frontier {
                let rows = stmt
                    .query_map(params![entity, chat_id, PER_NODE_LIMIT], map_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                for t in rows {
                    if !seen_triples.insert(t.id) {
                        continue;
                    }
                    for endpoint in [&t.subject, &t.object] {
                        let lc = endpoint.to_lowercase();
                        if visited_entities.insert(lc) {
                            next.push(endpoint.clone());
                        }
                    }
                    out.push(t);
                    if out.len() >= total_limit {
                        break;
                    }
                }
                if out.len() >= total_limit {
                    break;
                }
            }
            frontier = next;
        }

        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(total_limit);
        Ok(out)
    }

    /// Get a timeline of all triples for a subject, including invalidated ones.
    pub fn kg_timeline(
        &self,
        subject: &str,
        chat_id: Option<i64>,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
             FROM knowledge_graph
             WHERE LOWER(subject) = LOWER(?1)
               AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
             ORDER BY valid_from ASC",
        )?;
        let rows = stmt
            .query_map(params![subject, chat_id], |row| {
                Ok(KgTriple {
                    id: row.get(0)?,
                    subject: row.get(1)?,
                    predicate: row.get(2)?,
                    object: row.get(3)?,
                    chat_id: row.get(4)?,
                    valid_from: row.get(5)?,
                    valid_to: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    source_memory_id: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get knowledge graph stats (total triples, active, invalidated).
    pub fn kg_stats(&self, chat_id: Option<i64>) -> Result<(usize, usize, usize), MicroClawError> {
        let conn = self.lock_conn();
        let total: usize = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_graph WHERE (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL)",
            params![chat_id],
            |row| row.get(0),
        )?;
        let active: usize = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_graph WHERE valid_to IS NULL AND (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL)",
            params![chat_id],
            |row| row.get(0),
        )?;
        Ok((total, active, total.saturating_sub(active)))
    }

    /// Delete oldest invalidated triples when count exceeds max_triples for a chat.
    /// If still over limit after pruning invalidated, also deletes oldest active triples by confidence.
    pub fn kg_prune_excess(
        &self,
        chat_id: i64,
        max_triples: usize,
    ) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let count: usize = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_graph WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get(0),
        )?;
        if count <= max_triples {
            return Ok(0);
        }
        let excess = count - max_triples;
        // First: delete invalidated triples (oldest first)
        let deleted_invalidated = conn.execute(
            "DELETE FROM knowledge_graph WHERE id IN (
                SELECT id FROM knowledge_graph
                WHERE chat_id = ?1 AND valid_to IS NOT NULL
                ORDER BY created_at ASC
                LIMIT ?2
            )",
            params![chat_id, excess],
        )?;
        let remaining_excess = excess.saturating_sub(deleted_invalidated);
        if remaining_excess == 0 {
            return Ok(deleted_invalidated);
        }
        // Still over: delete lowest-confidence active triples
        let deleted_active = conn.execute(
            "DELETE FROM knowledge_graph WHERE id IN (
                SELECT id FROM knowledge_graph
                WHERE chat_id = ?1 AND valid_to IS NULL
                ORDER BY confidence ASC, created_at ASC
                LIMIT ?2
            )",
            params![chat_id, remaining_excess],
        )?;
        Ok(deleted_invalidated + deleted_active)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_reflector_run(
        &self,
        chat_id: i64,
        started_at: &str,
        finished_at: &str,
        extracted_count: usize,
        inserted_count: usize,
        updated_count: usize,
        skipped_count: usize,
        dedup_method: &str,
        parse_ok: bool,
        error_text: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO memory_reflector_runs (
                chat_id, started_at, finished_at, extracted_count, inserted_count, updated_count, skipped_count, dedup_method, parse_ok, error_text
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                chat_id,
                started_at,
                finished_at,
                extracted_count as i64,
                inserted_count as i64,
                updated_count as i64,
                skipped_count as i64,
                dedup_method,
                if parse_ok { 1 } else { 0 },
                error_text
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn log_memory_injection(
        &self,
        chat_id: i64,
        retrieval_method: &str,
        candidate_count: usize,
        selected_count: usize,
        omitted_count: usize,
        tokens_est: usize,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memory_injection_logs (
                chat_id, created_at, retrieval_method, candidate_count, selected_count, omitted_count, tokens_est
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                chat_id,
                now,
                retrieval_method,
                candidate_count as i64,
                selected_count as i64,
                omitted_count as i64,
                tokens_est as i64
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_memory_observability_summary(
        &self,
        chat_id: Option<i64>,
    ) -> Result<MemoryObservabilitySummary, MicroClawError> {
        let conn = self.lock_conn();
        let since_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

        let (total, active, archived, low_confidence, avg_confidence) = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN is_archived = 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN is_archived != 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN confidence < 0.45 THEN 1 ELSE 0 END), 0),
                    COALESCE(AVG(confidence), 0.0)
                 FROM memories
                 WHERE chat_id = ?1 OR chat_id IS NULL",
                params![cid],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, f64>(4)?,
                    ))
                },
            )?
        } else {
            conn.query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN is_archived = 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN is_archived != 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN confidence < 0.45 THEN 1 ELSE 0 END), 0),
                    COALESCE(AVG(confidence), 0.0)
                 FROM memories",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, f64>(4)?,
                    ))
                },
            )?
        };

        let (
            reflector_runs_24h,
            reflector_inserted_24h,
            reflector_updated_24h,
            reflector_skipped_24h,
        ) = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT
                        COUNT(*),
                        COALESCE(SUM(inserted_count), 0),
                        COALESCE(SUM(updated_count), 0),
                        COALESCE(SUM(skipped_count), 0)
                     FROM memory_reflector_runs
                     WHERE chat_id = ?1 AND unixepoch(started_at) >= unixepoch(?2)",
                params![cid, &since_24h],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
        } else {
            conn.query_row(
                "SELECT
                        COUNT(*),
                        COALESCE(SUM(inserted_count), 0),
                        COALESCE(SUM(updated_count), 0),
                        COALESCE(SUM(skipped_count), 0)
                     FROM memory_reflector_runs
                     WHERE unixepoch(started_at) >= unixepoch(?1)",
                params![&since_24h],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
        };

        let (injection_events_24h, injection_selected_24h, injection_candidates_24h) =
            if let Some(cid) = chat_id {
                conn.query_row(
                    "SELECT
                        COUNT(*),
                        COALESCE(SUM(selected_count), 0),
                        COALESCE(SUM(candidate_count), 0)
                     FROM memory_injection_logs
                     WHERE chat_id = ?1 AND unixepoch(created_at) >= unixepoch(?2)",
                    params![cid, &since_24h],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?
            } else {
                conn.query_row(
                    "SELECT
                        COUNT(*),
                        COALESCE(SUM(selected_count), 0),
                        COALESCE(SUM(candidate_count), 0)
                     FROM memory_injection_logs
                     WHERE unixepoch(created_at) >= unixepoch(?1)",
                    params![&since_24h],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?
            };

        Ok(MemoryObservabilitySummary {
            total,
            active,
            archived,
            low_confidence,
            avg_confidence,
            reflector_runs_24h,
            reflector_inserted_24h,
            reflector_updated_24h,
            reflector_skipped_24h,
            injection_events_24h,
            injection_selected_24h,
            injection_candidates_24h,
        })
    }

    pub fn get_memory_reflector_runs(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MemoryReflectorRun>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT id, chat_id, started_at, finished_at, extracted_count, inserted_count, updated_count, skipped_count, dedup_method, parse_ok, error_text
             FROM memory_reflector_runs",
        );
        let mut where_parts: Vec<&str> = Vec::new();
        if chat_id.is_some() {
            where_parts.push("chat_id = ?1");
        }
        if since.is_some() {
            where_parts.push(if chat_id.is_some() {
                "unixepoch(started_at) >= unixepoch(?2)"
            } else {
                "unixepoch(started_at) >= unixepoch(?1)"
            });
        }
        if !where_parts.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_parts.join(" AND "));
        }
        query.push_str(" ORDER BY unixepoch(started_at) ASC LIMIT ");
        query.push_str(&limit.max(1).to_string());
        query.push_str(" OFFSET ");
        query.push_str(&offset.to_string());

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(MemoryReflectorRun {
                id: row.get(0)?,
                chat_id: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                extracted_count: row.get(4)?,
                inserted_count: row.get(5)?,
                updated_count: row.get(6)?,
                skipped_count: row.get(7)?,
                dedup_method: row.get(8)?,
                parse_ok: row.get::<_, i64>(9)? != 0,
                error_text: row.get(10)?,
            })
        };
        let rows = match (chat_id, since) {
            (Some(cid), Some(ts)) => stmt.query_map(params![cid, ts], mapper)?,
            (Some(cid), None) => stmt.query_map(params![cid], mapper)?,
            (None, Some(ts)) => stmt.query_map(params![ts], mapper)?,
            (None, None) => stmt.query_map([], mapper)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_memory_injection_logs(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MemoryInjectionLog>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT id, chat_id, created_at, retrieval_method, candidate_count, selected_count, omitted_count, tokens_est
             FROM memory_injection_logs",
        );
        let mut where_parts: Vec<&str> = Vec::new();
        if chat_id.is_some() {
            where_parts.push("chat_id = ?1");
        }
        if since.is_some() {
            where_parts.push(if chat_id.is_some() {
                "unixepoch(created_at) >= unixepoch(?2)"
            } else {
                "unixepoch(created_at) >= unixepoch(?1)"
            });
        }
        if !where_parts.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_parts.join(" AND "));
        }
        query.push_str(" ORDER BY unixepoch(created_at) ASC LIMIT ");
        query.push_str(&limit.max(1).to_string());
        query.push_str(" OFFSET ");
        query.push_str(&offset.to_string());

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(MemoryInjectionLog {
                id: row.get(0)?,
                chat_id: row.get(1)?,
                created_at: row.get(2)?,
                retrieval_method: row.get(3)?,
                candidate_count: row.get(4)?,
                selected_count: row.get(5)?,
                omitted_count: row.get(6)?,
                tokens_est: row.get(7)?,
            })
        };
        let rows = match (chat_id, since) {
            (Some(cid), Some(ts)) => stmt.query_map(params![cid, ts], mapper)?,
            (Some(cid), None) => stmt.query_map(params![cid], mapper)?,
            (None, Some(ts)) => stmt.query_map(params![ts], mapper)?,
            (None, None) => stmt.query_map([], mapper)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn create_subagent_run(
        &self,
        params: CreateSubagentRunParams<'_>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO subagent_runs(
                run_id, parent_run_id, depth, token_budget, chat_id, caller_channel, task, context, status, created_at, provider, model, label
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'accepted', ?9, ?10, ?11, ?12)",
            params![
                params.run_id,
                params.parent_run_id,
                params.depth,
                params.token_budget,
                params.chat_id,
                params.caller_channel,
                params.task,
                params.context,
                now,
                params.provider,
                params.model,
                params.label
            ],
        )?;
        Ok(())
    }

    /// Record a progress snapshot for a running sub-agent: update the latest
    /// progress text/time on the run and append a `progress` event to its
    /// timeline. Returns the previous `last_progress_at` (for throttling).
    pub fn record_subagent_progress(
        &self,
        run_id: &str,
        progress_text: &str,
    ) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let prev: Option<String> = conn
            .query_row(
                "SELECT last_progress_at FROM subagent_runs WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        conn.execute(
            "UPDATE subagent_runs SET progress_text = ?2, last_progress_at = ?3 WHERE run_id = ?1",
            params![run_id, progress_text, now],
        )?;
        conn.execute(
            "INSERT INTO subagent_events(run_id, event_type, detail, created_at)
             VALUES (?1, 'progress', ?2, ?3)",
            params![run_id, progress_text, now],
        )?;
        Ok(prev)
    }

    pub fn mark_subagent_queued(&self, run_id: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE subagent_runs
             SET status = 'queued'
             WHERE run_id = ?1 AND status = 'accepted'",
            params![run_id],
        )?;
        Ok(())
    }

    pub fn mark_subagent_running(&self, run_id: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE subagent_runs
             SET status = 'running', started_at = COALESCE(started_at, ?2)
             WHERE run_id = ?1",
            params![run_id, now],
        )?;
        Ok(())
    }

    pub fn mark_subagent_finished(
        &self,
        params: FinishSubagentRunParams<'_>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE subagent_runs
             SET status = ?2,
                 finished_at = ?3,
                 error_text = ?4,
                 result_text = ?5,
                 artifact_json = ?6,
                 input_tokens = ?7,
                 output_tokens = ?8,
                 total_tokens = (?7 + ?8)
             WHERE run_id = ?1",
            params![
                params.run_id,
                params.status,
                now,
                params.error_text,
                params.result_text,
                params.artifact_json,
                params.input_tokens,
                params.output_tokens
            ],
        )?;
        Ok(())
    }

    /// Startup crash recovery: sub-agent runs execute in-process, so any run
    /// still marked in-flight when a new process boots was killed mid-run.
    /// Retire them as `interrupted` so lists and gates stop counting them,
    /// and return how many rows were fixed.
    pub fn recover_orphaned_subagent_runs(&self) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let affected = conn.execute(
            "UPDATE subagent_runs
             SET status = 'interrupted',
                 finished_at = ?1,
                 error_text = COALESCE(error_text, 'process restarted while this run was in flight')
             WHERE status IN ('accepted', 'queued', 'running')",
            params![now],
        )?;
        Ok(affected)
    }

    /// Record that an interactive turn is in flight for `chat_id`. One row per
    /// chat: a re-entrant start (queued follow-up in the same chat) just
    /// refreshes the timestamp.
    pub fn mark_turn_active(&self, chat_id: i64, channel: &str) -> Result<(), MicroClawError> {
        self.mark_turn_active_with_context(chat_id, channel, "private", None)
    }

    /// Record an interactive run together with the routing context needed to
    /// resume it after process restart.
    pub fn mark_turn_active_with_context(
        &self,
        chat_id: i64,
        channel: &str,
        chat_type: &str,
        run_id: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO active_turns (
                chat_id, channel, chat_type, started_at, progress_text,
                phase, iteration, session_json, resumable, tool_summary,
                last_checkpoint_at, run_id
             )
             VALUES (?1, ?2, ?3, ?4, NULL, 'starting', 0, NULL, 0, NULL, ?4, ?5)
             ON CONFLICT(chat_id) DO UPDATE SET
                channel = ?2,
                chat_type = ?3,
                started_at = ?4,
                progress_text = NULL,
                phase = 'starting',
                iteration = 0,
                session_json = NULL,
                resumable = 0,
                tool_summary = NULL,
                last_checkpoint_at = ?4,
                run_id = ?5",
            params![chat_id, channel, chat_type, now, run_id],
        )?;
        Ok(())
    }

    /// Attach a new process-local run id to an interrupted turn without
    /// overwriting its last safe checkpoint. If recovery crashes before the
    /// next checkpoint, the following startup can resume from the same state.
    pub fn mark_turn_recovery_started(
        &self,
        chat_id: i64,
        run_id: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE active_turns
             SET phase = 'resuming', run_id = ?2
             WHERE chat_id = ?1",
            params![chat_id, run_id],
        )?;
        Ok(())
    }

    /// Update the rolling progress snapshot for an in-flight interactive turn.
    /// No-op for chats without an active turn (e.g. scheduler-driven runs).
    pub fn update_turn_progress(&self, chat_id: i64, progress: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE active_turns SET progress_text = ?2 WHERE chat_id = ?1",
            params![chat_id, progress],
        )?;
        Ok(())
    }

    /// Persist a durable agent-loop boundary.
    ///
    /// `session_json` must end at a provider-neutral message boundary. Callers
    /// set `resumable=false` while a side-effecting tool may be in flight, so
    /// startup recovery can never blindly replay an operation with uncertain
    /// outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_active_turn(
        &self,
        chat_id: i64,
        phase: &str,
        iteration: i64,
        session_json: Option<&str>,
        resumable: bool,
        progress_text: Option<&str>,
        tool_summary: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE active_turns
             SET phase = ?2,
                 iteration = ?3,
                 session_json = COALESCE(?4, session_json),
                 resumable = ?5,
                 progress_text = COALESCE(?6, progress_text),
                 tool_summary = ?7,
                 last_checkpoint_at = ?8
             WHERE chat_id = ?1",
            params![
                chat_id,
                phase,
                iteration,
                session_json,
                i64::from(resumable),
                progress_text,
                tool_summary,
                now
            ],
        )?;
        Ok(())
    }

    /// Inspect in-flight interactive runs without mutating recovery state.
    pub fn list_active_turns(&self) -> Result<Vec<InterruptedTurn>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT chat_id, channel, chat_type, started_at, progress_text,
                    phase, iteration, session_json, resumable, tool_summary,
                    last_checkpoint_at, run_id
             FROM active_turns ORDER BY started_at",
        )?;
        let rows = stmt
            .query_map([], map_interrupted_turn)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The interactive turn for `chat_id` finished (any outcome).
    pub fn clear_turn_active(&self, chat_id: i64) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "DELETE FROM active_turns WHERE chat_id = ?1",
            params![chat_id],
        )?;
        Ok(())
    }

    /// Startup crash recovery: return-and-clear every turn that was in flight
    /// when the previous process died. The table is emptied in the same
    /// transaction so a second caller can never double-notify.
    pub fn take_interrupted_turns(&self) -> Result<Vec<InterruptedTurn>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let rows: Vec<InterruptedTurn> = {
            let mut stmt = tx.prepare(
                "SELECT chat_id, channel, chat_type, started_at, progress_text,
                        phase, iteration, session_json, resumable, tool_summary,
                        last_checkpoint_at, run_id
                 FROM active_turns ORDER BY started_at",
            )?;
            let collected = stmt
                .query_map([], map_interrupted_turn)?
                .collect::<Result<Vec<InterruptedTurn>, _>>()?;
            collected
        };
        tx.execute("DELETE FROM active_turns", [])?;
        tx.commit()?;
        Ok(rows)
    }

    /// Queue a final reply whose direct channel delivery failed. The outbox
    /// flush loop retries it with backoff until delivered or terminally
    /// failed.
    pub fn enqueue_outbox_message(
        &self,
        chat_id: i64,
        channel: &str,
        payload_text: &str,
    ) -> Result<i64, MicroClawError> {
        let delivery_id = format!("delivery-{}", uuid::Uuid::new_v4());
        let ids = self.create_outbound_delivery(
            &delivery_id,
            chat_id,
            channel,
            payload_text,
            &[payload_text.to_string()],
        )?;
        Ok(ids[0])
    }

    /// Persist a complete outbound message and its independently retryable
    /// chunks before the first network call.
    pub fn create_outbound_delivery(
        &self,
        delivery_id: &str,
        chat_id: i64,
        channel: &str,
        full_payload_text: &str,
        chunks: &[String],
    ) -> Result<Vec<i64>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO outbound_deliveries(
                delivery_id, chat_id, channel, full_payload_text, status,
                created_at, updated_at
             ) VALUES(?1, ?2, ?3, ?4, 'pending', ?5, ?5)",
            params![delivery_id, chat_id, channel, full_payload_text, now],
        )?;
        let total = chunks.len().max(1) as i64;
        let mut ids = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let idempotency_key = format!("{delivery_id}:{}", index + 1);
            tx.execute(
                "INSERT INTO outbound_delivery_chunks(
                    delivery_id, chunk_index, total_chunks, payload_text,
                    idempotency_key, status, attempts, next_attempt_at,
                    created_at, updated_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
                params![
                    delivery_id,
                    index as i64,
                    total,
                    chunk,
                    idempotency_key,
                    now
                ],
            )?;
            ids.push(tx.last_insert_rowid());
        }
        tx.commit()?;
        Ok(ids)
    }

    pub fn list_due_outbox_messages(
        &self,
        now_iso: &str,
        limit: usize,
    ) -> Result<Vec<OutboxMessageRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.delivery_id, d.chat_id, d.channel,
                    c.payload_text, d.full_payload_text, c.chunk_index,
                    c.total_chunks, c.idempotency_key, c.status, c.attempts,
                    c.next_attempt_at, c.last_error
             FROM outbound_delivery_chunks c
             JOIN outbound_deliveries d ON d.delivery_id = c.delivery_id
             WHERE c.status IN ('pending', 'retry')
               AND (c.next_attempt_at IS NULL OR unixepoch(c.next_attempt_at) <= unixepoch(?1))
             ORDER BY c.id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_iso, limit.max(1) as i64], |row| {
            Ok(OutboxMessageRecord {
                id: row.get(0)?,
                delivery_id: row.get(1)?,
                chat_id: row.get(2)?,
                channel: row.get(3)?,
                payload_text: row.get(4)?,
                full_payload_text: row.get(5)?,
                chunk_index: row.get(6)?,
                total_chunks: row.get(7)?,
                idempotency_key: row.get(8)?,
                status: row.get(9)?,
                attempts: row.get(10)?,
                next_attempt_at: row.get(11)?,
                last_error: row.get(12)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_outbox_delivered(&self, id: i64) -> Result<(), MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE outbound_delivery_chunks
             SET status='delivered', updated_at=?2 WHERE id=?1",
            params![id, now],
        )?;
        refresh_delivery_status(&tx, id, &now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_outbox_sending(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = conn.execute(
            "UPDATE outbound_delivery_chunks
             SET status='sending', updated_at=?2
             WHERE id=?1 AND status IN ('pending', 'retry')",
            params![id, now],
        )?;
        Ok(changed == 1)
    }

    pub fn mark_outbox_retry(
        &self,
        id: i64,
        attempts: i64,
        next_attempt_at: Option<&str>,
        last_error: &str,
        terminal_fail: bool,
    ) -> Result<(), MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        let status = if terminal_fail { "failed" } else { "retry" };
        tx.execute(
            "UPDATE outbound_delivery_chunks
             SET status=?2, attempts=?3, next_attempt_at=?4, last_error=?5, updated_at=?6
             WHERE id=?1",
            params![id, status, attempts, next_attempt_at, last_error, now],
        )?;
        refresh_delivery_status(&tx, id, &now)?;
        tx.commit()?;
        Ok(())
    }

    /// Reset chunks left in `sending` by an unclean shutdown. Stable channel
    /// idempotency keys make replay safe on supporting transports (Weixin).
    pub fn recover_sending_outbox_messages(&self) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = conn.execute(
            "UPDATE outbound_delivery_chunks
             SET status='retry', next_attempt_at=?1,
                 last_error='recovered after interrupted delivery', updated_at=?1
             WHERE status='sending'",
            params![now],
        )?;
        Ok(changed)
    }

    pub fn outbound_delivery_is_complete(&self, delivery_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbound_delivery_chunks
             WHERE delivery_id=?1 AND status != 'delivered'",
            params![delivery_id],
            |row| row.get(0),
        )?;
        Ok(remaining == 0)
    }

    /// Store the full logical message once, after every external chunk is
    /// delivered. Returns true only for the caller that performed the insert.
    pub fn finalize_outbound_delivery(
        &self,
        delivery_id: &str,
        sender_name: &str,
    ) -> Result<bool, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let delivery = tx.query_row(
            "SELECT chat_id, full_payload_text, stored_at
             FROM outbound_deliveries WHERE delivery_id=?1",
            params![delivery_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        if delivery.2.is_some() {
            return Ok(false);
        }
        let remaining: i64 = tx.query_row(
            "SELECT COUNT(*) FROM outbound_delivery_chunks
             WHERE delivery_id=?1 AND status != 'delivered'",
            params![delivery_id],
            |row| row.get(0),
        )?;
        if remaining != 0 {
            return Ok(false);
        }
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO messages(id, chat_id, sender_name, content, is_from_bot, timestamp)
             VALUES(?1, ?2, ?3, ?4, 1, ?5)",
            params![
                uuid::Uuid::new_v4().to_string(),
                delivery.0,
                sender_name,
                delivery.1,
                now
            ],
        )?;
        tx.execute(
            "UPDATE outbound_deliveries
             SET status='delivered', stored_at=?2, updated_at=?2
             WHERE delivery_id=?1 AND stored_at IS NULL",
            params![delivery_id, now],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Pending + retry outbox depth (governance/observability).
    pub fn count_outbox_pending(&self) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbound_delivery_chunks
             WHERE status IN ('pending', 'retry', 'sending')",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Exact depth of the scheduled-task dead-letter queue (unlike
    /// `list_scheduled_task_dlq`, this is not clamped by a LIMIT).
    pub fn count_scheduled_task_dlq(
        &self,
        include_replayed: bool,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let replay_filter = if include_replayed {
            ""
        } else {
            " WHERE replayed_at IS NULL"
        };
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM scheduled_task_dlq{replay_filter}"),
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Completion-contract verdict tallies (verified, failed) recorded at
    /// or after `since` (RFC 3339). Verdicts are the `contract` events
    /// written when a sub-agent run's exit criteria are checked.
    pub fn contract_verdict_counts_since(
        &self,
        since: &str,
    ) -> Result<(i64, i64), MicroClawError> {
        let conn = self.lock_conn();
        let counts = conn.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN detail LIKE 'verified%' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN detail LIKE 'failed%' THEN 1 ELSE 0 END), 0)
             FROM subagent_events
             WHERE event_type = 'contract' AND created_at >= ?1",
            [since],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok(counts)
    }

    /// Read-only delivery health snapshot for diagnostics and monitoring.
    pub fn outbound_delivery_health(&self) -> Result<OutboundDeliveryHealth, MicroClawError> {
        let conn = self.lock_conn();
        let (total_deliveries, delivered_deliveries): (i64, i64) = conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END), 0)
             FROM outbound_deliveries",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (pending_chunks, sending_chunks, retry_chunks, failed_chunks, oldest_unfinished_at) =
            conn.query_row(
                "SELECT
                    COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='sending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='retry' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0),
                    MIN(CASE WHEN status != 'delivered' THEN created_at END)
                 FROM outbound_delivery_chunks",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
        Ok(OutboundDeliveryHealth {
            total_deliveries,
            delivered_deliveries,
            pending_chunks,
            sending_chunks,
            retry_chunks,
            failed_chunks,
            oldest_unfinished_at,
        })
    }

    pub fn request_subagent_cancel(
        &self,
        run_id: &str,
        chat_id: i64,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let affected = conn.execute(
            "UPDATE subagent_runs
             SET cancel_requested = 1
             WHERE run_id = ?1 AND chat_id = ?2
               AND status IN ('accepted', 'queued', 'running')",
            params![run_id, chat_id],
        )?;
        Ok(affected > 0)
    }

    pub fn list_subagent_runs(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<SubagentRunRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT run_id, parent_run_id, depth, token_budget, chat_id, caller_channel, task, context, status, created_at,
                    started_at, finished_at, cancel_requested, error_text, result_text,
                    input_tokens, output_tokens, total_tokens, provider, model, artifact_json,
                    label, progress_text, last_progress_at
             FROM subagent_runs
             WHERE chat_id = ?1
             ORDER BY created_at DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![chat_id, limit.max(1) as i64], |row| {
            Ok(SubagentRunRecord {
                run_id: row.get(0)?,
                parent_run_id: row.get(1)?,
                depth: row.get(2)?,
                token_budget: row.get(3)?,
                chat_id: row.get(4)?,
                caller_channel: row.get(5)?,
                task: row.get(6)?,
                context: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                started_at: row.get(10)?,
                finished_at: row.get(11)?,
                cancel_requested: row.get::<_, i64>(12)? != 0,
                error_text: row.get(13)?,
                result_text: row.get(14)?,
                input_tokens: row.get(15)?,
                output_tokens: row.get(16)?,
                total_tokens: row.get(17)?,
                provider: row.get(18)?,
                model: row.get(19)?,
                artifact_json: row.get(20)?,
                label: row.get(21)?,
                progress_text: row.get(22)?,
                last_progress_at: row.get(23)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Average wall-clock duration (seconds) of recently-completed sub-agent runs
    /// in a chat, for rough ETA hints. `None` when there's no completed history.
    pub fn avg_completed_subagent_duration_secs(
        &self,
        chat_id: i64,
    ) -> Result<Option<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let avg: Option<f64> = conn.query_row(
            "SELECT AVG((julianday(finished_at) - julianday(started_at)) * 86400.0)
             FROM subagent_runs
             WHERE chat_id = ?1 AND status = 'completed'
               AND started_at IS NOT NULL AND finished_at IS NOT NULL",
            params![chat_id],
            |row| row.get(0),
        )?;
        Ok(avg.map(|v| v.round() as i64).filter(|v| *v > 0))
    }

    /// All currently-active sub-agent runs across chats (accepted/queued/running),
    /// oldest first. Used by the proactive task-standup loop.
    pub fn list_active_subagent_runs(&self) -> Result<Vec<SubagentRunRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT run_id, parent_run_id, depth, token_budget, chat_id, caller_channel, task, context, status, created_at,
                    started_at, finished_at, cancel_requested, error_text, result_text,
                    input_tokens, output_tokens, total_tokens, provider, model, artifact_json,
                    label, progress_text, last_progress_at
             FROM subagent_runs
             WHERE status IN ('accepted', 'queued', 'running')
             ORDER BY chat_id ASC, created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SubagentRunRecord {
                run_id: row.get(0)?,
                parent_run_id: row.get(1)?,
                depth: row.get(2)?,
                token_budget: row.get(3)?,
                chat_id: row.get(4)?,
                caller_channel: row.get(5)?,
                task: row.get(6)?,
                context: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                started_at: row.get(10)?,
                finished_at: row.get(11)?,
                cancel_requested: row.get::<_, i64>(12)? != 0,
                error_text: row.get(13)?,
                result_text: row.get(14)?,
                input_tokens: row.get(15)?,
                output_tokens: row.get(16)?,
                total_tokens: row.get(17)?,
                provider: row.get(18)?,
                model: row.get(19)?,
                artifact_json: row.get(20)?,
                label: row.get(21)?,
                progress_text: row.get(22)?,
                last_progress_at: row.get(23)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_subagent_run(
        &self,
        run_id: &str,
        chat_id: i64,
    ) -> Result<Option<SubagentRunRecord>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT run_id, parent_run_id, depth, token_budget, chat_id, caller_channel, task, context, status, created_at,
                    started_at, finished_at, cancel_requested, error_text, result_text,
                    input_tokens, output_tokens, total_tokens, provider, model, artifact_json,
                    label, progress_text, last_progress_at
             FROM subagent_runs
             WHERE run_id = ?1 AND chat_id = ?2",
            params![run_id, chat_id],
            |row| {
                Ok(SubagentRunRecord {
                    run_id: row.get(0)?,
                    parent_run_id: row.get(1)?,
                    depth: row.get(2)?,
                    token_budget: row.get(3)?,
                    chat_id: row.get(4)?,
                    caller_channel: row.get(5)?,
                    task: row.get(6)?,
                    context: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    started_at: row.get(10)?,
                    finished_at: row.get(11)?,
                    cancel_requested: row.get::<_, i64>(12)? != 0,
                    error_text: row.get(13)?,
                    result_text: row.get(14)?,
                    input_tokens: row.get(15)?,
                    output_tokens: row.get(16)?,
                    total_tokens: row.get(17)?,
                    provider: row.get(18)?,
                    model: row.get(19)?,
                    artifact_json: row.get(20)?,
                label: row.get(21)?,
                progress_text: row.get(22)?,
                last_progress_at: row.get(23)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// All child runs of a parent run, oldest first.
    pub fn list_subagent_children(
        &self,
        parent_run_id: &str,
    ) -> Result<Vec<SubagentRunRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT run_id, parent_run_id, depth, token_budget, chat_id, caller_channel, task, context, status, created_at,
                    started_at, finished_at, cancel_requested, error_text, result_text,
                    input_tokens, output_tokens, total_tokens, provider, model, artifact_json,
                    label, progress_text, last_progress_at
             FROM subagent_runs
             WHERE parent_run_id = ?1
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![parent_run_id], |row| {
            Ok(SubagentRunRecord {
                run_id: row.get(0)?,
                parent_run_id: row.get(1)?,
                depth: row.get(2)?,
                token_budget: row.get(3)?,
                chat_id: row.get(4)?,
                caller_channel: row.get(5)?,
                task: row.get(6)?,
                context: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                started_at: row.get(10)?,
                finished_at: row.get(11)?,
                cancel_requested: row.get::<_, i64>(12)? != 0,
                error_text: row.get(13)?,
                result_text: row.get(14)?,
                input_tokens: row.get(15)?,
                output_tokens: row.get(16)?,
                total_tokens: row.get(17)?,
                provider: row.get(18)?,
                model: row.get(19)?,
                artifact_json: row.get(20)?,
                label: row.get(21)?,
                progress_text: row.get(22)?,
                last_progress_at: row.get(23)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Resolve a sub-agent reference that is either an exact run_id or a
    /// human-friendly label, scoped to a chat. Exact run_id wins; otherwise the
    /// most recent run with that label is returned, preferring active ones.
    pub fn resolve_subagent_run_id(
        &self,
        chat_id: i64,
        run_id_or_label: &str,
    ) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let exact: Option<String> = conn
            .query_row(
                "SELECT run_id FROM subagent_runs WHERE run_id = ?1 AND chat_id = ?2",
                params![run_id_or_label, chat_id],
                |row| row.get(0),
            )
            .optional()?;
        if exact.is_some() {
            return Ok(exact);
        }
        let by_label: Option<String> = conn
            .query_row(
                "SELECT run_id FROM subagent_runs
                 WHERE chat_id = ?1 AND label = ?2
                 ORDER BY (status IN ('accepted','queued','running')) DESC, created_at DESC
                 LIMIT 1",
                params![chat_id, run_id_or_label],
                |row| row.get(0),
            )
            .optional()?;
        Ok(by_label)
    }

    pub fn is_subagent_cancel_requested(&self, run_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let requested = conn
            .query_row(
                "SELECT cancel_requested FROM subagent_runs WHERE run_id = ?1",
                params![run_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(requested != 0)
    }

    pub fn count_active_subagent_runs_for_chat(&self, chat_id: i64) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT COUNT(*)
             FROM subagent_runs
             WHERE chat_id = ?1
               AND status IN ('accepted', 'queued', 'running')",
            params![chat_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    pub fn count_active_subagent_children(
        &self,
        parent_run_id: &str,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT COUNT(*)
             FROM subagent_runs
             WHERE parent_run_id = ?1
               AND status IN ('accepted', 'queued', 'running')",
            params![parent_run_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    pub fn enqueue_subagent_announce(
        &self,
        run_id: &str,
        chat_id: i64,
        caller_channel: &str,
        payload_text: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO subagent_announces(
                run_id, chat_id, caller_channel, payload_text, status, attempts, next_attempt_at, created_at, updated_at
            ) VALUES(?1, ?2, ?3, ?4, 'pending', 0, ?5, ?6, ?6)
            ON CONFLICT(run_id) DO NOTHING",
            params![run_id, chat_id, caller_channel, payload_text, now, now],
        )?;
        Ok(())
    }

    pub fn list_due_subagent_announces(
        &self,
        now_iso: &str,
        limit: usize,
    ) -> Result<Vec<SubagentAnnounceRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, run_id, chat_id, caller_channel, payload_text, status, attempts, next_attempt_at, last_error
             FROM subagent_announces
             WHERE status IN ('pending', 'retry')
               AND (next_attempt_at IS NULL OR unixepoch(next_attempt_at) <= unixepoch(?1))
             ORDER BY id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_iso, limit.max(1) as i64], |row| {
            Ok(SubagentAnnounceRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                chat_id: row.get(2)?,
                caller_channel: row.get(3)?,
                payload_text: row.get(4)?,
                status: row.get(5)?,
                attempts: row.get(6)?,
                next_attempt_at: row.get(7)?,
                last_error: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_subagent_announce_sent(&self, id: i64) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE subagent_announces
             SET status='sent', updated_at=?2
             WHERE id=?1",
            params![id, now],
        )?;
        Ok(())
    }

    pub fn mark_subagent_announce_retry(
        &self,
        id: i64,
        attempts: i64,
        next_attempt_at: Option<&str>,
        last_error: &str,
        terminal_fail: bool,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let status = if terminal_fail { "failed" } else { "retry" };
        conn.execute(
            "UPDATE subagent_announces
             SET status=?2, attempts=?3, next_attempt_at=?4, last_error=?5, updated_at=?6
             WHERE id=?1",
            params![id, status, attempts, next_attempt_at, last_error, now],
        )?;
        Ok(())
    }

    pub fn append_subagent_event(
        &self,
        run_id: &str,
        event_type: &str,
        detail: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO subagent_events(run_id, event_type, detail, created_at)
             VALUES(?1, ?2, ?3, ?4)",
            params![run_id, event_type, detail, now],
        )?;
        Ok(())
    }

    pub fn list_subagent_events(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<SubagentEventRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, run_id, event_type, detail, created_at
             FROM subagent_events
             WHERE run_id = ?1
             ORDER BY created_at DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![run_id, limit.max(1) as i64], |row| {
            Ok(SubagentEventRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                event_type: row.get(2)?,
                detail: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn set_subagent_focus(&self, chat_id: i64, run_id: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO subagent_focus_bindings(chat_id, run_id, updated_at)
             VALUES(?1, ?2, ?3)
             ON CONFLICT(chat_id) DO UPDATE SET
                run_id = excluded.run_id,
                updated_at = excluded.updated_at",
            params![chat_id, run_id, now],
        )?;
        Ok(())
    }

    pub fn clear_subagent_focus(&self, chat_id: i64) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "DELETE FROM subagent_focus_bindings WHERE chat_id = ?1",
            params![chat_id],
        )?;
        Ok(())
    }

    pub fn get_subagent_focus(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT run_id FROM subagent_focus_bindings WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_subagent_observability_snapshot(
        &self,
        chat_id: Option<i64>,
        recent_limit: usize,
    ) -> Result<SubagentObservabilitySnapshot, MicroClawError> {
        let conn = self.lock_conn();
        let since = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let active_filter = if chat_id.is_some() {
            " AND chat_id = ?1"
        } else {
            ""
        };

        let active_runs: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status IN ('accepted','queued','running') AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status IN ('accepted','queued','running')",
                [],
                |row| row.get(0),
            )?
        };
        let queued_runs: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs WHERE status = 'queued' AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs WHERE status = 'queued'",
                [],
                |row| row.get(0),
            )?
        };
        let running_runs: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs WHERE status = 'running' AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs WHERE status = 'running'",
                [],
                |row| row.get(0),
            )?
        };

        let pending_announces: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_announces WHERE status = 'pending' AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_announces WHERE status = 'pending'",
                [],
                |row| row.get(0),
            )?
        };
        let retry_announces: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_announces WHERE status = 'retry' AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_announces WHERE status = 'retry'",
                [],
                |row| row.get(0),
            )?
        };
        let failed_announces: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_announces WHERE status = 'failed' AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_announces WHERE status = 'failed'",
                [],
                |row| row.get(0),
            )?
        };

        let completed_24h: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status = 'completed' AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)
                   AND chat_id = ?2",
                params![since, cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status = 'completed' AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)",
                params![since],
                |row| row.get(0),
            )?
        };
        let failed_24h: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status IN ('failed','timed_out','cancelled') AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)
                   AND chat_id = ?2",
                params![since, cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status IN ('failed','timed_out','cancelled') AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)",
                params![since],
                |row| row.get(0),
            )?
        };
        let budget_exceeded_24h: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status = 'budget_exceeded' AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)
                   AND chat_id = ?2",
                params![since, cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM subagent_runs
                 WHERE status = 'budget_exceeded' AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)",
                params![since],
                |row| row.get(0),
            )?
        };

        let avg_duration_ms_24h: i64 = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COALESCE(AVG((julianday(finished_at) - julianday(started_at)) * 86400000.0), 0)
                 FROM subagent_runs
                 WHERE started_at IS NOT NULL AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)
                   AND chat_id = ?2",
                params![since, cid],
                |row| row.get::<_, f64>(0).map(|v| v as i64),
            )?
        } else {
            conn.query_row(
                "SELECT COALESCE(AVG((julianday(finished_at) - julianday(started_at)) * 86400000.0), 0)
                 FROM subagent_runs
                 WHERE started_at IS NOT NULL AND finished_at IS NOT NULL
                   AND unixepoch(finished_at) >= unixepoch(?1)",
                params![since],
                |row| row.get::<_, f64>(0).map(|v| v as i64),
            )?
        };

        let mut stmt = conn.prepare(&format!(
            "SELECT run_id, parent_run_id, depth, token_budget, chat_id, caller_channel, task, context, status, created_at,
                    started_at, finished_at, cancel_requested, error_text, result_text,
                    input_tokens, output_tokens, total_tokens, provider, model, artifact_json,
                    label, progress_text, last_progress_at
             FROM subagent_runs
             WHERE 1=1 {active_filter}
             ORDER BY created_at DESC
             LIMIT ?{}",
            if chat_id.is_some() { 2 } else { 1 }
        ))?;
        let recent_runs = if let Some(cid) = chat_id {
            let rows = stmt.query_map(params![cid, recent_limit.max(1) as i64], |row| {
                Ok(SubagentRunRecord {
                    run_id: row.get(0)?,
                    parent_run_id: row.get(1)?,
                    depth: row.get(2)?,
                    token_budget: row.get(3)?,
                    chat_id: row.get(4)?,
                    caller_channel: row.get(5)?,
                    task: row.get(6)?,
                    context: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    started_at: row.get(10)?,
                    finished_at: row.get(11)?,
                    cancel_requested: row.get::<_, i64>(12)? != 0,
                    error_text: row.get(13)?,
                    result_text: row.get(14)?,
                    input_tokens: row.get(15)?,
                    output_tokens: row.get(16)?,
                    total_tokens: row.get(17)?,
                    provider: row.get(18)?,
                    model: row.get(19)?,
                    artifact_json: row.get(20)?,
                    label: row.get(21)?,
                    progress_text: row.get(22)?,
                    last_progress_at: row.get(23)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        } else {
            let rows = stmt.query_map(params![recent_limit.max(1) as i64], |row| {
                Ok(SubagentRunRecord {
                    run_id: row.get(0)?,
                    parent_run_id: row.get(1)?,
                    depth: row.get(2)?,
                    token_budget: row.get(3)?,
                    chat_id: row.get(4)?,
                    caller_channel: row.get(5)?,
                    task: row.get(6)?,
                    context: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    started_at: row.get(10)?,
                    finished_at: row.get(11)?,
                    cancel_requested: row.get::<_, i64>(12)? != 0,
                    error_text: row.get(13)?,
                    result_text: row.get(14)?,
                    input_tokens: row.get(15)?,
                    output_tokens: row.get(16)?,
                    total_tokens: row.get(17)?,
                    provider: row.get(18)?,
                    model: row.get(19)?,
                    artifact_json: row.get(20)?,
                    label: row.get(21)?,
                    progress_text: row.get(22)?,
                    last_progress_at: row.get(23)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        Ok(SubagentObservabilitySnapshot {
            active_runs,
            queued_runs,
            running_runs,
            pending_announces,
            retry_announces,
            failed_announces,
            completed_24h,
            failed_24h,
            budget_exceeded_24h,
            avg_duration_ms_24h,
            recent_runs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> (Database, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("microclaw_test_{}", uuid::Uuid::new_v4()));
        let db = Database::new(dir.to_str().unwrap()).unwrap();
        (db, dir)
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_chain_intact_after_appends() {
        let (db, dir) = test_db();
        db.log_audit_event("auth", "alice", "login", None, "ok", None)
            .unwrap();
        db.log_audit_event(
            "tool",
            "bot",
            "web_fetch",
            Some("https://x"),
            "ok",
            Some("200"),
        )
        .unwrap();
        db.log_audit_event("auth", "alice", "logout", None, "ok", None)
            .unwrap();
        let status = db.verify_audit_chain().unwrap();
        assert!(status.intact, "reason: {:?}", status.reason);
        assert_eq!(status.sealed_entries, 3);
        assert_eq!(status.broken_at, None);
        cleanup(&dir);
    }

    #[test]
    fn audit_chain_detects_modification() {
        let (db, dir) = test_db();
        db.log_audit_event("auth", "alice", "login", None, "ok", None)
            .unwrap();
        let id = db
            .log_audit_event("tool", "bot", "web_fetch", Some("https://x"), "ok", None)
            .unwrap();
        db.log_audit_event("auth", "alice", "logout", None, "ok", None)
            .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute(
                "UPDATE audit_logs SET status='tampered' WHERE id=?1",
                params![id],
            )
            .unwrap();
        }
        let status = db.verify_audit_chain().unwrap();
        assert!(!status.intact);
        assert_eq!(status.broken_at, Some(id));
        assert!(status.reason.unwrap().contains("modified"));
        cleanup(&dir);
    }

    #[test]
    fn audit_chain_detects_deletion() {
        let (db, dir) = test_db();
        db.log_audit_event("auth", "alice", "login", None, "ok", None)
            .unwrap();
        let id = db
            .log_audit_event("tool", "bot", "web_fetch", Some("https://x"), "ok", None)
            .unwrap();
        db.log_audit_event("auth", "alice", "logout", None, "ok", None)
            .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute("DELETE FROM audit_logs WHERE id=?1", params![id])
                .unwrap();
        }
        let status = db.verify_audit_chain().unwrap();
        assert!(!status.intact);
        assert!(status.broken_at.is_some());
        assert!(status.reason.unwrap().contains("deleted"));
        cleanup(&dir);
    }

    #[test]
    fn test_new_database_creates_tables() {
        let (db, dir) = test_db();
        // Verify we can do basic operations without errors
        let msgs = db.get_recent_messages(1, 10).unwrap();
        assert!(msgs.is_empty());
        let tasks = db.get_due_tasks("2099-01-01T00:00:00Z").unwrap();
        assert!(tasks.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_schema_version_is_tracked() {
        let (db, dir) = test_db();
        let conn = db.lock_conn();
        let version: String = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION_CURRENT.to_string());
        drop(conn);
        cleanup(&dir);
    }

    #[test]
    fn test_legacy_schema_is_upgraded_to_current_version() {
        let dir =
            std::env::temp_dir().join(format!("microclaw_legacy_upgrade_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
             );
             CREATE TABLE messages (
                id TEXT NOT NULL,
                chat_id INTEGER NOT NULL,
                sender_name TEXT NOT NULL,
                content TEXT NOT NULL,
                is_from_bot INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (id, chat_id)
             );
             CREATE TABLE scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                prompt TEXT NOT NULL,
                schedule_type TEXT NOT NULL DEFAULT 'cron',
                schedule_value TEXT NOT NULL,
                next_run TEXT NOT NULL,
                last_run TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
             );
             CREATE TABLE sessions (
                chat_id INTEGER PRIMARY KEY,
                messages_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
             );
             CREATE TABLE memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
             );",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        let version: String = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION_CURRENT.to_string());

        let has_confidence = table_has_column(&conn, "memories", "confidence").unwrap();
        let has_source = table_has_column(&conn, "memories", "source").unwrap();
        let has_last_seen = table_has_column(&conn, "memories", "last_seen_at").unwrap();
        let has_archived = table_has_column(&conn, "memories", "is_archived").unwrap();
        assert!(has_confidence && has_source && has_last_seen && has_archived);
        assert!(table_has_column(&conn, "sessions", "parent_session_key").unwrap());
        assert!(table_has_column(&conn, "sessions", "fork_point").unwrap());
        assert!(table_has_column(&conn, "sessions", "label").unwrap());
        assert!(table_has_column(&conn, "sessions", "thinking_level").unwrap());
        assert!(table_has_column(&conn, "sessions", "verbose_level").unwrap());
        assert!(table_has_column(&conn, "sessions", "reasoning_level").unwrap());
        assert!(table_has_column(&conn, "scheduled_tasks", "timezone").unwrap());

        let session_parent_index_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_sessions_parent_session_key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(session_parent_index_exists, 1);

        let supersede_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_supersede_edges'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(supersede_table_exists, 1);
        let dlq_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scheduled_task_dlq'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dlq_table_exists, 1);
        drop(conn);
        cleanup(&dir);
    }

    #[test]
    fn test_migration_matrix_upgrades_multiple_legacy_versions() {
        fn seed_legacy_db(dir: &std::path::Path, version: i64) {
            let db_path = dir.join("microclaw.db");
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE chats (
                    chat_id INTEGER PRIMARY KEY,
                    chat_title TEXT,
                    chat_type TEXT NOT NULL DEFAULT 'private',
                    last_message_time TEXT NOT NULL
                 );
                 CREATE TABLE messages (
                    id TEXT NOT NULL,
                    chat_id INTEGER NOT NULL,
                    sender_name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    is_from_bot INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (id, chat_id)
                 );
                 CREATE TABLE scheduled_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL,
                    prompt TEXT NOT NULL,
                    schedule_type TEXT NOT NULL DEFAULT 'cron',
                    schedule_value TEXT NOT NULL,
                    next_run TEXT NOT NULL,
                    last_run TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL
                 );
                 CREATE TABLE sessions (
                    chat_id INTEGER PRIMARY KEY,
                    messages_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 );
                 CREATE TABLE memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO db_meta(key, value) VALUES('schema_version', ?1)",
                params![version.to_string()],
            )
            .unwrap();

            if version >= 5 {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS api_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        label TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        prefix TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        revoked_at TEXT,
                        last_used_at TEXT
                    );",
                )
                .unwrap();
            }
            if version >= 7 {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS metrics_history (
                        timestamp_ms INTEGER PRIMARY KEY,
                        llm_completions INTEGER NOT NULL DEFAULT 0,
                        llm_input_tokens INTEGER NOT NULL DEFAULT 0,
                        llm_output_tokens INTEGER NOT NULL DEFAULT 0,
                        http_requests INTEGER NOT NULL DEFAULT 0,
                        tool_executions INTEGER NOT NULL DEFAULT 0,
                        mcp_calls INTEGER NOT NULL DEFAULT 0,
                        active_sessions INTEGER NOT NULL DEFAULT 0
                    );",
                )
                .unwrap();
            }
            if version >= 8 {
                conn.execute_batch(
                    "ALTER TABLE api_keys ADD COLUMN expires_at TEXT;
                     ALTER TABLE api_keys ADD COLUMN rotated_from_key_id INTEGER;",
                )
                .unwrap();
            }
            drop(conn);
        }

        for version in [1_i64, 5_i64, 7_i64, 8_i64] {
            let dir = std::env::temp_dir().join(format!(
                "microclaw_migration_matrix_{}_{}",
                version,
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            seed_legacy_db(&dir, version);

            let db = Database::new(dir.to_str().unwrap()).unwrap();
            let conn = db.lock_conn();
            let actual: String = conn
                .query_row(
                    "SELECT value FROM db_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                actual,
                SCHEMA_VERSION_CURRENT.to_string(),
                "legacy schema_version {} should migrate to current",
                version
            );
            assert!(table_has_column(&conn, "sessions", "parent_session_key").unwrap());
            assert!(table_has_column(&conn, "sessions", "fork_point").unwrap());
            assert!(table_has_column(&conn, "sessions", "label").unwrap());
            assert!(table_has_column(&conn, "sessions", "thinking_level").unwrap());
            assert!(table_has_column(&conn, "sessions", "verbose_level").unwrap());
            assert!(table_has_column(&conn, "sessions", "reasoning_level").unwrap());
            assert!(table_has_column(&conn, "scheduled_tasks", "timezone").unwrap());
            assert!(table_has_column(&conn, "api_keys", "expires_at").unwrap());
            assert!(table_has_column(&conn, "api_keys", "rotated_from_key_id").unwrap());
            assert!(
                table_has_column(&conn, "metrics_history", "mcp_rate_limited_rejections").unwrap()
            );
            assert!(table_has_column(&conn, "metrics_history", "mcp_bulkhead_rejections").unwrap());
            assert!(
                table_has_column(&conn, "metrics_history", "mcp_circuit_open_rejections").unwrap()
            );
            drop(conn);
            cleanup(&dir);
        }
    }

    #[test]
    fn test_current_version_repairs_incomplete_scheduled_tasks_schema() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_incomplete_scheduled_tasks_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                prompt TEXT NOT NULL,
                schedule_type TEXT NOT NULL DEFAULT 'cron',
                schedule_value TEXT NOT NULL,
                next_run TEXT NOT NULL,
                last_run TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
             );
             CREATE TABLE db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO db_meta(key, value) VALUES('schema_version', '40');",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        for column in [
            "exit_criteria",
            "run_count",
            "max_runs",
            "not_after",
            "timezone",
        ] {
            assert!(
                table_has_column(&conn, "scheduled_tasks", column).unwrap(),
                "missing repaired scheduled_tasks.{column}"
            );
        }
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION_CURRENT);
        drop(conn);

        // Exercise the exact query shape that failed in production.
        assert!(db.get_tasks_for_chat(1).unwrap().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_upsert_chat_insert_and_update() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("Test Chat"), "group").unwrap();
        // Update title
        db.upsert_chat(100, Some("New Title"), "group").unwrap();
        // Insert without title
        db.upsert_chat(200, None, "private").unwrap();
        cleanup(&dir);
    }

    #[test]
    fn test_metrics_history_roundtrip_with_mcp_rejection_fields() {
        let (db, dir) = test_db();
        let point = MetricsHistoryPoint {
            timestamp_ms: 1_700_000_000_000,
            llm_completions: 10,
            llm_input_tokens: 1000,
            llm_output_tokens: 500,
            http_requests: 20,
            tool_executions: 8,
            mcp_calls: 3,
            mcp_rate_limited_rejections: 2,
            mcp_bulkhead_rejections: 1,
            mcp_circuit_open_rejections: 4,
            active_sessions: 6,
        };
        db.upsert_metrics_history(&point).unwrap();
        let rows = db.get_metrics_history(point.timestamp_ms, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let got = &rows[0];
        assert_eq!(got.mcp_rate_limited_rejections, 2);
        assert_eq!(got.mcp_bulkhead_rejections, 1);
        assert_eq!(got.mcp_circuit_open_rejections, 4);
        cleanup(&dir);
    }

    #[test]
    fn test_store_and_retrieve_message() {
        let (db, dir) = test_db();
        let msg = StoredMessage {
            id: "msg1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:00Z".into(),
        };
        db.store_message(&msg).unwrap();

        let messages = db.get_recent_messages(100, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "msg1");
        assert_eq!(messages[0].sender_name, "alice");
        assert_eq!(messages[0].content, "hello");
        assert!(!messages[0].is_from_bot);
        cleanup(&dir);
    }

    #[test]
    fn test_search_messages_fts_basic() {
        let (db, dir) = test_db();
        let now = chrono::Utc::now();
        let messages = [
            ("chat-1", 101, "alice", "Rust async futures are awesome"),
            ("chat-2", 101, "bot", "I agree, tokio makes them easy"),
            (
                "chat-3",
                101,
                "alice",
                "Let's talk about JavaScript promises instead",
            ),
            ("chat-4", 202, "bob", "Discussing Rust borrow checker"),
        ];
        for (i, (id, chat, sender, content)) in messages.iter().enumerate() {
            let msg = StoredMessage {
                id: (*id).into(),
                chat_id: *chat,
                sender_name: (*sender).into(),
                content: (*content).into(),
                is_from_bot: *sender == "bot",
                timestamp: (now + chrono::Duration::seconds(i as i64)).to_rfc3339(),
            };
            db.store_message(&msg).unwrap();
        }

        let rust_hits = db.search_messages_fts("rust", None, None, 10).unwrap();
        assert!(rust_hits.len() >= 2, "expected at least 2 rust matches");
        assert!(rust_hits
            .iter()
            .all(|m| m.content.to_lowercase().contains("rust")));

        let scoped = db.search_messages_fts("rust", Some(101), None, 10).unwrap();
        assert!(scoped.iter().all(|m| m.chat_id == 101));

        let empty = db.search_messages_fts("", None, None, 10).unwrap();
        assert!(empty.is_empty());

        let no_match = db
            .search_messages_fts("nothingmatchesthis", None, None, 10)
            .unwrap();
        assert!(no_match.is_empty());

        // Delete and confirm the FTS row is also removed via trigger.
        {
            let conn = db.lock_conn();
            conn.execute(
                "DELETE FROM messages WHERE id = ?1 AND chat_id = ?2",
                params!["chat-1", 101i64],
            )
            .unwrap();
        }
        let after_delete = db.search_messages_fts("awesome", None, None, 10).unwrap();
        assert!(after_delete.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_store_message_upsert() {
        let (db, dir) = test_db();
        let msg = StoredMessage {
            id: "msg1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "original".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:00Z".into(),
        };
        db.store_message(&msg).unwrap();

        // Store same id again with different content (INSERT OR REPLACE)
        let msg2 = StoredMessage {
            id: "msg1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "updated".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        };
        db.store_message(&msg2).unwrap();

        let messages = db.get_recent_messages(100, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "updated");
        cleanup(&dir);
    }

    #[test]
    fn test_message_exists() {
        let (db, dir) = test_db();
        assert!(!db.message_exists(100, "msg1").unwrap());

        db.store_message(&StoredMessage {
            id: "msg1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:00Z".into(),
        })
        .unwrap();

        assert!(db.message_exists(100, "msg1").unwrap());
        assert!(!db.message_exists(100, "msg2").unwrap());
        assert!(!db.message_exists(200, "msg1").unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_store_message_if_new() {
        let (db, dir) = test_db();
        let msg = StoredMessage {
            id: "msg-new".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:00Z".into(),
        };
        assert!(db.store_message_if_new(&msg).unwrap());
        assert!(!db.store_message_if_new(&msg).unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_get_recent_messages_ordering_and_limit() {
        let (db, dir) = test_db();
        for i in 0..5 {
            let msg = StoredMessage {
                id: format!("msg{i}"),
                chat_id: 100,
                sender_name: "alice".into(),
                content: format!("message {i}"),
                is_from_bot: false,
                timestamp: format!("2024-01-01T00:00:0{i}Z"),
            };
            db.store_message(&msg).unwrap();
        }

        // Limit to 3 - should get the 3 most recent, but reversed to oldest-first
        let messages = db.get_recent_messages(100, 3).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, "message 2"); // oldest of the 3 most recent
        assert_eq!(messages[1].content, "message 3");
        assert_eq!(messages[2].content, "message 4"); // most recent

        // Different chat_id should be empty
        let messages = db.get_recent_messages(200, 10).unwrap();
        assert!(messages.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_get_messages_since_last_bot_response_with_bot_msg() {
        let (db, dir) = test_db();

        // User message 1
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();

        // Bot response
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 100,
            sender_name: "bot".into(),
            content: "hello!".into(),
            is_from_bot: true,
            timestamp: "2024-01-01T00:00:02Z".into(),
        })
        .unwrap();

        // User message 2 (after bot response)
        db.store_message(&StoredMessage {
            id: "m3".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "how are you?".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:03Z".into(),
        })
        .unwrap();

        // User message 3
        db.store_message(&StoredMessage {
            id: "m4".into(),
            chat_id: 100,
            sender_name: "bob".into(),
            content: "me too".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:04Z".into(),
        })
        .unwrap();

        let messages = db
            .get_messages_since_last_bot_response(100, 50, 10)
            .unwrap();
        // Should include the bot message and everything after it
        assert!(messages.len() >= 2);
        // First should be the bot msg or after it
        assert_eq!(messages[0].id, "m2"); // the bot message (timestamp >= bot's timestamp)
        assert_eq!(messages[1].id, "m3");
        assert_eq!(messages[2].id, "m4");
        cleanup(&dir);
    }

    #[test]
    fn test_get_messages_since_last_bot_response_no_bot_msg() {
        let (db, dir) = test_db();

        for i in 0..5 {
            db.store_message(&StoredMessage {
                id: format!("m{i}"),
                chat_id: 100,
                sender_name: "alice".into(),
                content: format!("msg {i}"),
                is_from_bot: false,
                timestamp: format!("2024-01-01T00:00:0{i}Z"),
            })
            .unwrap();
        }

        // Fallback to last 3
        let messages = db.get_messages_since_last_bot_response(100, 50, 3).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, "msg 2");
        assert_eq!(messages[2].content, "msg 4");
        cleanup(&dir);
    }

    #[test]
    fn test_create_and_get_scheduled_task() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(
                100,
                "say hello",
                "cron",
                "0 */5 * * * *",
                "2024-06-01T00:05:00Z",
            )
            .unwrap();
        assert!(id > 0);

        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].prompt, "say hello");
        assert_eq!(tasks[0].schedule_type, "cron");
        assert_eq!(tasks[0].status, "active");
        cleanup(&dir);
    }

    #[test]
    fn test_get_due_tasks() {
        let (db, dir) = test_db();
        db.create_scheduled_task(100, "task1", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();
        db.create_scheduled_task(
            100,
            "task2",
            "once",
            "2099-12-31T00:00:00Z",
            "2099-12-31T00:00:00Z",
        )
        .unwrap();

        // Only task1 is due
        let due = db.get_due_tasks("2024-06-01T00:00:00Z").unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].prompt, "task1");

        // Both are due in the far future
        let due = db.get_due_tasks("2100-01-01T00:00:00Z").unwrap();
        assert_eq!(due.len(), 2);
        cleanup(&dir);
    }

    #[test]
    fn test_claim_due_tasks_is_single_consumer() {
        let (db, dir) = test_db();
        db.create_scheduled_task(100, "task1", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        let first = db.claim_due_tasks("2024-06-01T00:00:00Z", 50).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].status, "running");

        // A second claim in the same due window should not see the same task again.
        let second = db.claim_due_tasks("2024-06-01T00:00:00Z", 50).unwrap();
        assert!(second.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_get_tasks_for_chat_filters_status() {
        let (db, dir) = test_db();
        let id1 = db
            .create_scheduled_task(
                100,
                "active task",
                "cron",
                "0 * * * * *",
                "2024-01-01T00:00:00Z",
            )
            .unwrap();
        let id2 = db
            .create_scheduled_task(
                100,
                "to cancel",
                "once",
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:00Z",
            )
            .unwrap();
        db.update_task_status(id2, "cancelled").unwrap();

        // Only active/paused tasks should be returned
        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, id1);

        // Pause the active one
        db.update_task_status(id1, "paused").unwrap();
        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].status, "paused");
        cleanup(&dir);
    }

    #[test]
    fn test_update_task_status() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        assert!(db.update_task_status(id, "paused").unwrap());
        assert!(db.update_task_status(id, "active").unwrap());
        assert!(db.update_task_status(id, "cancelled").unwrap());

        // Non-existent task
        assert!(!db.update_task_status(9999, "paused").unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_requeue_scheduled_task() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();
        db.update_task_status(id, "paused").unwrap();

        assert!(db
            .requeue_scheduled_task(id, "2099-01-01T00:00:00Z")
            .unwrap());
        let task = db.get_task_by_id(id).unwrap().unwrap();
        assert_eq!(task.status, "active");
        assert_eq!(task.next_run, "2099-01-01T00:00:00Z");

        assert!(!db
            .requeue_scheduled_task(9999, "2099-01-01T00:00:00Z")
            .unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_update_task_after_run_cron() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        db.update_task_after_run(
            id,
            "2024-01-01T00:01:00Z",
            Some("2024-01-01T00:02:00Z"),
            true,
        )
        .unwrap();

        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert_eq!(tasks[0].last_run.as_deref(), Some("2024-01-01T00:01:00Z"));
        assert_eq!(tasks[0].next_run, "2024-01-01T00:02:00Z");
        assert_eq!(tasks[0].status, "active");
        cleanup(&dir);
    }

    #[test]
    fn test_recover_running_tasks() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(
            db.claim_due_tasks("2024-01-01T00:00:00Z", 10)
                .unwrap()
                .len(),
            1
        );

        let recovered = db.recover_running_tasks().unwrap();
        assert_eq!(recovered, 1);
        let task = db.get_task_by_id(id).unwrap().unwrap();
        assert_eq!(task.status, "active");
        cleanup(&dir);
    }

    #[test]
    fn test_update_task_after_run_one_shot() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(
                100,
                "test",
                "once",
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:00Z",
            )
            .unwrap();

        // One-shot success: no next_run, should mark as completed
        db.update_task_after_run(id, "2024-01-01T00:00:00Z", None, true)
            .unwrap();

        // Should not appear in active/paused list
        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert!(tasks.is_empty());
        assert_eq!(db.get_task_by_id(id).unwrap().unwrap().status, "completed");
        cleanup(&dir);
    }

    #[test]
    fn test_update_task_after_run_one_shot_failure_marked_failed() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(
                100,
                "test",
                "once",
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:00Z",
            )
            .unwrap();

        // A failed one-shot must be recorded as 'failed', not 'completed'.
        db.update_task_after_run(id, "2024-01-01T00:00:00Z", None, false)
            .unwrap();

        assert_eq!(db.get_task_by_id(id).unwrap().unwrap().status, "failed");
        cleanup(&dir);
    }

    #[test]
    fn test_delete_task() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        assert!(db.delete_task(id).unwrap());
        assert!(!db.delete_task(id).unwrap()); // already deleted

        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert!(tasks.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_get_all_messages() {
        let (db, dir) = test_db();
        for i in 0..5 {
            db.store_message(&StoredMessage {
                id: format!("msg{i}"),
                chat_id: 100,
                sender_name: "alice".into(),
                content: format!("message {i}"),
                is_from_bot: false,
                timestamp: format!("2024-01-01T00:00:0{i}Z"),
            })
            .unwrap();
        }

        let messages = db.get_all_messages(100).unwrap();
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0].content, "message 0");
        assert_eq!(messages[4].content, "message 4");

        // Different chat should be empty
        assert!(db.get_all_messages(200).unwrap().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_log_task_run() {
        let (db, dir) = test_db();
        let task_id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        let log_id = db
            .log_task_run(
                task_id,
                100,
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:05Z",
                5000,
                true,
                Some("Success"),
            )
            .unwrap();
        assert!(log_id > 0);

        let logs = db.get_task_run_logs(task_id, 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].task_id, task_id);
        assert_eq!(logs[0].duration_ms, 5000);
        assert!(logs[0].success);
        assert_eq!(logs[0].result_summary.as_deref(), Some("Success"));
        cleanup(&dir);
    }

    #[test]
    fn test_get_task_run_logs_ordering_and_limit() {
        let (db, dir) = test_db();
        let task_id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        for i in 0..5 {
            db.log_task_run(
                task_id,
                100,
                &format!("2024-01-01T00:0{i}:00Z"),
                &format!("2024-01-01T00:0{i}:05Z"),
                5000,
                true,
                Some(&format!("Run {i}")),
            )
            .unwrap();
        }

        // Limit to 3, most recent first
        let logs = db.get_task_run_logs(task_id, 3).unwrap();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].result_summary.as_deref(), Some("Run 4")); // most recent
        assert_eq!(logs[2].result_summary.as_deref(), Some("Run 2"));
        cleanup(&dir);
    }

    #[test]
    fn test_get_task_run_summary_since() {
        let (db, dir) = test_db();
        let task_id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();
        db.log_task_run(
            task_id,
            100,
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:05Z",
            5000,
            true,
            Some("ok"),
        )
        .unwrap();
        db.log_task_run(
            task_id,
            100,
            "2024-01-01T00:10:00Z",
            "2024-01-01T00:10:05Z",
            5000,
            false,
            Some("fail"),
        )
        .unwrap();

        let (total_all, success_all) = db.get_task_run_summary_since(None).unwrap();
        assert_eq!(total_all, 2);
        assert_eq!(success_all, 1);

        let (total_since, success_since) = db
            .get_task_run_summary_since(Some("2024-01-01T00:05:00Z"))
            .unwrap();
        assert_eq!(total_since, 1);
        assert_eq!(success_since, 0);
        cleanup(&dir);
    }

    #[test]
    fn test_count_scheduled_task_dlq_is_not_limit_clamped() {
        let (db, dir) = test_db();
        let task_id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(db.count_scheduled_task_dlq(false).unwrap(), 0);
        for i in 0..3 {
            db.insert_scheduled_task_dlq(
                task_id,
                100,
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:05Z",
                5000 + i,
                Some("Error: timeout"),
            )
            .unwrap();
        }
        assert_eq!(db.count_scheduled_task_dlq(false).unwrap(), 3);
        assert_eq!(db.count_scheduled_task_dlq(true).unwrap(), 3);
        cleanup(&dir);
    }

    #[test]
    fn test_contract_verdict_counts_since_aggregates_verdicts() {
        let (db, dir) = test_db();
        db.append_subagent_event("run-1", "contract", Some("verified 2/2"))
            .unwrap();
        db.append_subagent_event("run-2", "contract", Some("failed 1/3"))
            .unwrap();
        db.append_subagent_event("run-2", "contract", Some("verified 3/3"))
            .unwrap();
        // Non-contract events must not count.
        db.append_subagent_event("run-3", "submit_result", None).unwrap();

        let (verified, failed) = db
            .contract_verdict_counts_since("2000-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(verified, 2);
        assert_eq!(failed, 1);

        let (verified, failed) = db
            .contract_verdict_counts_since("2999-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(verified, 0);
        assert_eq!(failed, 0);
        cleanup(&dir);
    }

    #[test]
    fn test_scheduled_task_dlq_insert_list_and_mark_replayed() {
        let (db, dir) = test_db();
        let task_id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        let dlq_id = db
            .insert_scheduled_task_dlq(
                task_id,
                100,
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:05Z",
                5000,
                Some("Error: timeout"),
            )
            .unwrap();
        assert!(dlq_id > 0);

        let pending = db
            .list_scheduled_task_dlq(Some(100), Some(task_id), false, 10)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task_id, task_id);
        assert_eq!(pending[0].replayed_at, None);

        assert!(db
            .mark_scheduled_task_dlq_replayed(dlq_id, Some("queued replay"))
            .unwrap());

        let pending_after = db
            .list_scheduled_task_dlq(Some(100), Some(task_id), false, 10)
            .unwrap();
        assert!(pending_after.is_empty());

        let all = db
            .list_scheduled_task_dlq(Some(100), Some(task_id), true, 10)
            .unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].replayed_at.is_some());
        assert_eq!(all[0].replay_note.as_deref(), Some("queued replay"));
        cleanup(&dir);
    }

    #[test]
    fn test_save_and_load_session() {
        let (db, dir) = test_db();
        let json = r#"[{"role":"user","content":"hello"}]"#;
        db.save_session(100, json).unwrap();

        let result = db.load_session(100).unwrap();
        assert!(result.is_some());
        let (loaded_json, updated_at) = result.unwrap();
        assert_eq!(loaded_json, json);
        assert!(!updated_at.is_empty());

        // Upsert: save again with different data
        let json2 = r#"[{"role":"user","content":"hello"},{"role":"assistant","content":"hi"}]"#;
        db.save_session(100, json2).unwrap();
        let (loaded_json2, _) = db.load_session(100).unwrap().unwrap();
        assert_eq!(loaded_json2, json2);

        cleanup(&dir);
    }

    #[test]
    fn test_save_and_load_session_settings() {
        let (db, dir) = test_db();
        let settings = SessionSettings {
            label: Some("Ops".into()),
            thinking_level: Some("high".into()),
            verbose_level: Some("full".into()),
            reasoning_level: Some("stream".into()),
        };
        db.save_session_settings(100, &settings).unwrap();

        let loaded = db.load_session_settings(100).unwrap().unwrap();
        assert_eq!(loaded.label.as_deref(), Some("Ops"));
        assert_eq!(loaded.thinking_level.as_deref(), Some("high"));
        assert_eq!(loaded.verbose_level.as_deref(), Some("full"));
        assert_eq!(loaded.reasoning_level.as_deref(), Some("stream"));

        cleanup(&dir);
    }

    #[test]
    fn test_load_session_nonexistent() {
        let (db, dir) = test_db();
        let result = db.load_session(999).unwrap();
        assert!(result.is_none());
        cleanup(&dir);
    }

    #[test]
    fn test_delete_session() {
        let (db, dir) = test_db();
        db.save_session(100, "[]").unwrap();
        assert!(db.delete_session(100).unwrap());
        assert!(db.load_session(100).unwrap().is_none());
        // Delete again returns false
        assert!(!db.delete_session(100).unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_clear_chat_context_removes_session_messages_and_scheduled_tasks() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("chat-100"), "private").unwrap();
        db.save_session(100, r#"[{"role":"user","content":"hi"}]"#)
            .unwrap();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        db.insert_memory(Some(100), "User likes Rust", "PROFILE")
            .unwrap();
        let task_id = db
            .create_scheduled_task(
                100,
                "daily summary",
                "cron",
                "0 0 8 * * *",
                "2099-01-01T08:00:00Z",
            )
            .unwrap();
        db.log_task_run(
            task_id,
            100,
            "2024-01-01T08:00:00Z",
            "2024-01-01T08:00:01Z",
            1000,
            true,
            Some("ok"),
        )
        .unwrap();
        db.insert_scheduled_task_dlq(
            task_id,
            100,
            "2024-01-01T09:00:00Z",
            "2024-01-01T09:00:01Z",
            1000,
            Some("failure"),
        )
        .unwrap();

        assert!(db.clear_chat_context(100).unwrap());
        assert!(db.load_session(100).unwrap().is_none());
        assert!(db.get_recent_messages(100, 10).unwrap().is_empty());
        assert!(db.get_tasks_for_chat(100).unwrap().is_empty());
        assert!(db.get_task_run_logs(task_id, 10).unwrap().is_empty());
        assert!(db
            .list_scheduled_task_dlq(Some(100), Some(task_id), true, 10)
            .unwrap()
            .is_empty());
        assert!(!db.search_memories(100, "Rust", 10).unwrap().is_empty());
        assert!(db.get_chat_type(100).unwrap().is_some());

        cleanup(&dir);
    }

    #[test]
    fn test_clear_chat_conversation_keeps_scheduled_tasks() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("chat-100"), "private").unwrap();
        db.save_session(100, r#"[{"role":"user","content":"hi"}]"#)
            .unwrap();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        db.insert_memory(Some(100), "User likes Rust", "PROFILE")
            .unwrap();
        let task_id = db
            .create_scheduled_task(
                100,
                "daily summary",
                "cron",
                "0 0 8 * * *",
                "2099-01-01T08:00:00Z",
            )
            .unwrap();
        db.log_task_run(
            task_id,
            100,
            "2024-01-01T08:00:00Z",
            "2024-01-01T08:00:01Z",
            1000,
            true,
            Some("ok"),
        )
        .unwrap();
        db.insert_scheduled_task_dlq(
            task_id,
            100,
            "2024-01-01T09:00:00Z",
            "2024-01-01T09:00:01Z",
            1000,
            Some("failure"),
        )
        .unwrap();

        assert!(db.clear_chat_conversation(100).unwrap());
        assert!(db.load_session(100).unwrap().is_none());
        assert!(db.get_recent_messages(100, 10).unwrap().is_empty());
        assert_eq!(db.get_tasks_for_chat(100).unwrap().len(), 1);
        assert_eq!(db.get_task_run_logs(task_id, 10).unwrap().len(), 1);
        assert_eq!(
            db.list_scheduled_task_dlq(Some(100), Some(task_id), true, 10)
                .unwrap()
                .len(),
            1
        );
        assert!(!db.search_memories(100, "Rust", 10).unwrap().is_empty());
        assert!(db.get_chat_type(100).unwrap().is_some());

        cleanup(&dir);
    }

    #[test]
    fn test_clear_chat_memory_removes_memories_but_keeps_conversation() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("chat-100"), "private").unwrap();
        db.save_session(100, r#"[{"role":"user","content":"hi"}]"#)
            .unwrap();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        db.insert_memory(Some(100), "User likes Rust", "PROFILE")
            .unwrap();

        assert!(db.clear_chat_memory(100).unwrap());
        assert!(db.search_memories(100, "Rust", 10).unwrap().is_empty());
        assert!(db.load_session(100).unwrap().is_some());
        assert!(!db.get_recent_messages(100, 10).unwrap().is_empty());
        assert!(db.get_chat_type(100).unwrap().is_some());

        cleanup(&dir);
    }

    #[test]
    fn test_get_new_user_messages_since() {
        let (db, dir) = test_db();

        // Messages before the cutoff
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "old msg".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();

        // Bot message at the cutoff
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 100,
            sender_name: "bot".into(),
            content: "response".into(),
            is_from_bot: true,
            timestamp: "2024-01-01T00:00:02Z".into(),
        })
        .unwrap();

        // User messages after cutoff
        db.store_message(&StoredMessage {
            id: "m3".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "new msg 1".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:03Z".into(),
        })
        .unwrap();

        db.store_message(&StoredMessage {
            id: "m4".into(),
            chat_id: 100,
            sender_name: "bob".into(),
            content: "new msg 2".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:04Z".into(),
        })
        .unwrap();

        // Bot message after cutoff (should be excluded - only non-bot)
        db.store_message(&StoredMessage {
            id: "m5".into(),
            chat_id: 100,
            sender_name: "bot".into(),
            content: "bot again".into(),
            is_from_bot: true,
            timestamp: "2024-01-01T00:00:05Z".into(),
        })
        .unwrap();

        let msgs = db
            .get_new_user_messages_since(100, "2024-01-01T00:00:02Z")
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "new msg 1");
        assert_eq!(msgs[1].content, "new msg 2");

        cleanup(&dir);
    }

    #[test]
    fn test_get_messages_since_includes_user_and_bot() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "old".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 100,
            sender_name: "bot".into(),
            content: "bot".into(),
            is_from_bot: true,
            timestamp: "2024-01-01T00:00:02Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m3".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "new".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:03Z".into(),
        })
        .unwrap();

        let msgs = db
            .get_messages_since(100, "2024-01-01T00:00:01Z", 10)
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].id, "m2");
        assert_eq!(msgs[1].id, "m3");

        cleanup(&dir);
    }

    #[test]
    fn test_reflector_cursor_roundtrip() {
        let (db, dir) = test_db();
        assert!(db.get_reflector_cursor(100).unwrap().is_none());

        db.set_reflector_cursor(100, "2024-01-01T00:00:03Z")
            .unwrap();
        assert_eq!(
            db.get_reflector_cursor(100).unwrap().as_deref(),
            Some("2024-01-01T00:00:03Z")
        );

        db.set_reflector_cursor(100, "2024-01-01T00:00:05Z")
            .unwrap();
        assert_eq!(
            db.get_reflector_cursor(100).unwrap().as_deref(),
            Some("2024-01-01T00:00:05Z")
        );

        cleanup(&dir);
    }

    #[test]
    fn test_resolve_or_create_chat_id_channel_scoped() {
        let (db, dir) = test_db();

        let tg = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        let tg_again = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        assert_eq!(tg, tg_again);

        let discord = db
            .resolve_or_create_chat_id("discord", "12345", Some("discord-12345"), "discord")
            .unwrap();
        assert_ne!(tg, discord);
        assert_eq!(
            db.get_chat_external_id(discord).unwrap().as_deref(),
            Some("12345")
        );

        cleanup(&dir);
    }

    #[test]
    fn test_upsert_chat_preserves_existing_channel_identity() {
        let (db, dir) = test_db();

        let scoped_chat_id = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();

        db.upsert_chat(scoped_chat_id, Some("Updated title"), "telegram_private")
            .unwrap();

        assert_eq!(
            db.get_chat_channel(scoped_chat_id).unwrap().as_deref(),
            Some("telegram.btcpos")
        );
        assert_eq!(
            db.get_chat_external_id(scoped_chat_id).unwrap().as_deref(),
            Some("12345")
        );

        let scoped_again = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        assert_eq!(scoped_chat_id, scoped_again);

        cleanup(&dir);
    }

    #[test]
    fn test_resolve_or_create_chat_id_scopes_same_external_id_by_channel() {
        let (db, dir) = test_db();

        let default_tg = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        let scoped_tg = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();

        assert_ne!(default_tg, scoped_tg);

        let default_tg_again = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        let scoped_tg_again = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();

        assert_eq!(default_tg, default_tg_again);
        assert_eq!(scoped_tg, scoped_tg_again);

        cleanup(&dir);
    }

    #[test]
    fn test_get_chat_id_by_channel_and_title_finds_non_recent_chat() {
        let (db, dir) = test_db();

        for i in 0..5000 {
            db.resolve_or_create_chat_id(
                "web",
                &format!("ext-{i}"),
                Some(&format!("title-{i}")),
                "web",
            )
            .unwrap();
        }
        let target = db
            .resolve_or_create_chat_id("web", "legacy-ext", Some("legacy-session"), "web")
            .unwrap();
        for i in 5000..9300 {
            db.resolve_or_create_chat_id(
                "web",
                &format!("ext-{i}"),
                Some(&format!("title-{i}")),
                "web",
            )
            .unwrap();
        }

        let found = db
            .get_chat_id_by_channel_and_title("web", "legacy-session")
            .unwrap();
        assert_eq!(found, Some(target));

        cleanup(&dir);
    }

    #[test]
    fn test_migration_backfills_chat_identity_columns() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_migration_chat_identity_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
            );
            INSERT INTO chats(chat_id, chat_title, chat_type, last_message_time)
            VALUES (100, 'legacy tg', 'telegram_private', '2026-01-01T00:00:00Z');",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        let (channel, external): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT channel, external_chat_id FROM chats WHERE chat_id = 100",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(channel.as_deref(), Some("telegram"));
        assert_eq!(external.as_deref(), Some("100"));
        drop(conn);

        cleanup(&dir);
    }

    #[test]
    fn test_migration_backfills_memory_identity_columns() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_migration_memory_identity_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
            );
            INSERT INTO chats(chat_id, chat_title, chat_type, last_message_time)
            VALUES (200, 'legacy discord', 'discord', '2026-01-01T00:00:00Z');

            CREATE TABLE memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                embedding_model TEXT
            );
            INSERT INTO memories(chat_id, content, category, created_at, updated_at, embedding_model)
            VALUES (200, 'legacy memory', 'KNOWLEDGE', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', NULL);",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        let (chat_channel, external): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT chat_channel, external_chat_id FROM memories WHERE chat_id = 200",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(chat_channel.as_deref(), Some("discord"));
        assert_eq!(external.as_deref(), Some("200"));
        drop(conn);

        cleanup(&dir);
    }

    #[test]
    fn test_kg_neighborhood_bounded_multihop_expansion() {
        let (db, dir) = test_db();
        let chat = Some(7i64);
        let vf = "2026-01-01T00:00:00Z";
        // Alice -works_at-> Acme -located_in-> Berlin ; plus a noise edge.
        db.kg_insert_triple("Alice", "works_at", "Acme", chat, vf, 0.9, "test", None)
            .unwrap();
        db.kg_insert_triple("Acme", "located_in", "Berlin", chat, vf, 0.8, "test", None)
            .unwrap();
        db.kg_insert_triple(
            "Berlin",
            "capital_of",
            "Germany",
            chat,
            vf,
            0.7,
            "test",
            None,
        )
        .unwrap();
        db.kg_insert_triple("Zoe", "likes", "Tea", chat, vf, 0.6, "test", None)
            .unwrap();

        // Distinct entities should include all nodes, longest-first.
        let ents = db.kg_distinct_entities(chat, 100).unwrap();
        assert!(ents.iter().any(|e| e == "Acme"));
        assert!(ents.iter().any(|e| e == "Germany"));

        // 1 hop from Alice reaches the works_at edge but not located_in.
        let one = db
            .kg_neighborhood(chat, &["Alice".to_string()], 1, 10)
            .unwrap();
        assert!(one.iter().any(|t| t.predicate == "works_at"));
        assert!(!one.iter().any(|t| t.predicate == "located_in"));

        // 2 hops from Alice pulls in Acme's edges (multi-hop), but never Zoe's.
        let two = db
            .kg_neighborhood(chat, &["Alice".to_string()], 2, 10)
            .unwrap();
        assert!(two.iter().any(|t| t.predicate == "located_in"));
        assert!(!two.iter().any(|t| t.subject == "Zoe"));

        // total_limit is respected.
        let capped = db
            .kg_neighborhood(chat, &["Alice".to_string()], 3, 1)
            .unwrap();
        assert_eq!(capped.len(), 1);

        // Empty seeds → empty result, no panic.
        assert!(db.kg_neighborhood(chat, &[], 2, 10).unwrap().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_log_llm_usage_and_summary() {
        let (db, dir) = test_db();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-test",
            10,
            5,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-test",
            20,
            8,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(200, "discord", "openai", "gpt-test", 30, 7, "agent_loop")
            .unwrap();

        let chat_100 = db.get_llm_usage_summary(Some(100)).unwrap();
        assert_eq!(chat_100.requests, 2);
        assert_eq!(chat_100.input_tokens, 30);
        assert_eq!(chat_100.output_tokens, 13);
        assert_eq!(chat_100.total_tokens, 43);
        assert!(chat_100.last_request_at.is_some());

        let all = db.get_llm_usage_summary(None).unwrap();
        assert_eq!(all.requests, 3);
        assert_eq!(all.input_tokens, 60);
        assert_eq!(all.output_tokens, 20);
        assert_eq!(all.total_tokens, 80);
        assert!(all.last_request_at.is_some());

        cleanup(&dir);
    }

    #[test]
    fn test_delete_chat_data_cleans_llm_usage() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("chat-100"), "private").unwrap();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-test",
            11,
            9,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(
            200,
            "telegram",
            "anthropic",
            "claude-test",
            3,
            4,
            "agent_loop",
        )
        .unwrap();

        assert!(db.delete_chat_data(100).unwrap());

        let chat_100 = db.get_llm_usage_summary(Some(100)).unwrap();
        assert_eq!(chat_100.requests, 0);
        let chat_200 = db.get_llm_usage_summary(Some(200)).unwrap();
        assert_eq!(chat_200.requests, 1);

        cleanup(&dir);
    }

    #[test]
    fn test_get_llm_usage_summary_since_and_by_model() {
        let (db, dir) = test_db();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-a",
            10,
            5,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-a",
            20,
            10,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(100, "telegram", "anthropic", "claude-b", 3, 7, "agent_loop")
            .unwrap();

        let all = db.get_llm_usage_summary_since(Some(100), None).unwrap();
        assert_eq!(all.requests, 3);
        assert_eq!(all.input_tokens, 33);
        assert_eq!(all.output_tokens, 22);

        let future = db
            .get_llm_usage_summary_since(Some(100), Some("2100-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(future.requests, 0);

        let by_model = db
            .get_llm_usage_by_model(Some(100), None, Some(10))
            .unwrap();
        assert_eq!(by_model.len(), 2);
        assert_eq!(by_model[0].model, "claude-a");
        assert_eq!(by_model[0].requests, 2);
        assert_eq!(by_model[0].total_tokens, 45);
        assert_eq!(by_model[1].model, "claude-b");
        assert_eq!(by_model[1].requests, 1);
        assert_eq!(by_model[1].total_tokens, 10);

        cleanup(&dir);
    }

    #[test]
    fn test_insert_and_get_memories_for_context() {
        let (db, dir) = test_db();
        db.insert_memory(Some(100), "User is a Rust developer", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "User lives in Tokyo", "PROFILE")
            .unwrap();
        db.insert_memory(None, "Global fact", "KNOWLEDGE").unwrap();
        db.insert_memory(Some(200), "Other chat memory", "EVENT")
            .unwrap();

        // chat 100 should see its own + global, not chat 200
        let mems = db.get_memories_for_context(100, 10).unwrap();
        assert_eq!(mems.len(), 3);
        let contents: Vec<&str> = mems.iter().map(|m| m.content.as_str()).collect();
        assert!(contents.contains(&"User is a Rust developer"));
        assert!(contents.contains(&"User lives in Tokyo"));
        assert!(contents.contains(&"Global fact"));
        assert!(!contents.contains(&"Other chat memory"));

        cleanup(&dir);
    }

    #[test]
    fn test_get_memories_for_context_limit() {
        let (db, dir) = test_db();
        for i in 0..5 {
            db.insert_memory(Some(100), &format!("memory {i}"), "KNOWLEDGE")
                .unwrap();
        }
        let mems = db.get_memories_for_context(100, 3).unwrap();
        assert_eq!(mems.len(), 3);
        cleanup(&dir);
    }

    #[test]
    fn test_get_all_memories_for_chat() {
        let (db, dir) = test_db();
        db.insert_memory(Some(100), "chat 100 mem", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "chat 100 mem 2", "EVENT")
            .unwrap();
        db.insert_memory(Some(200), "chat 200 mem", "PROFILE")
            .unwrap();
        db.insert_memory(None, "global mem", "KNOWLEDGE").unwrap();

        let mems = db.get_all_memories_for_chat(Some(100)).unwrap();
        assert_eq!(mems.len(), 2);

        let global = db.get_all_memories_for_chat(None).unwrap();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].content, "global mem");

        cleanup(&dir);
    }

    #[test]
    fn test_get_active_chat_ids_since() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-06-01T00:00:01Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 200,
            sender_name: "bob".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2024-06-01T00:00:02Z".into(),
        })
        .unwrap();
        // Bot message should not count
        db.store_message(&StoredMessage {
            id: "m3".into(),
            chat_id: 300,
            sender_name: "bot".into(),
            content: "bot msg".into(),
            is_from_bot: true,
            timestamp: "2024-06-01T00:00:03Z".into(),
        })
        .unwrap();

        let ids = db
            .get_active_chat_ids_since("2024-06-01T00:00:00Z")
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&100));
        assert!(ids.contains(&200));
        assert!(!ids.contains(&300));

        // Before any messages
        let ids_empty = db
            .get_active_chat_ids_since("2025-01-01T00:00:00Z")
            .unwrap();
        assert!(ids_empty.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_search_memories() {
        let (db, dir) = test_db();
        db.insert_memory(Some(100), "User is a Rust developer", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "User loves coffee", "PROFILE")
            .unwrap();
        db.insert_memory(None, "Rust is fast and safe", "KNOWLEDGE")
            .unwrap();

        let results = db.search_memories(100, "rust", 10).unwrap();
        assert_eq!(results.len(), 2); // own + global both match "rust"

        let results = db.search_memories(100, "coffee", 10).unwrap();
        assert_eq!(results.len(), 1);

        let results = db.search_memories(100, "nonexistent_xyz", 10).unwrap();
        assert!(results.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_archive_memory_hides_from_search_and_context() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "User prefers concise summaries", "PROFILE")
            .unwrap();
        assert!(db.archive_memory(id).unwrap());

        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert!(mem.is_archived);
        assert!(mem.archived_at.is_some());

        let search = db.search_memories(100, "concise", 10).unwrap();
        assert!(search.is_empty());
        let context = db.get_memories_for_context(100, 10).unwrap();
        assert!(context.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_memory_observability_summary_rollup() {
        let (db, dir) = test_db();
        let started_at_dt = chrono::Utc::now() - chrono::Duration::minutes(1);
        let started_at = started_at_dt.to_rfc3339();
        let finished_at = (started_at_dt + chrono::Duration::seconds(1)).to_rfc3339();
        db.insert_memory_with_metadata(Some(100), "prod db on 5433", "KNOWLEDGE", "explicit", 0.95)
            .unwrap();
        let stale_id = db
            .insert_memory_with_metadata(Some(100), "temporary thought", "EVENT", "reflector", 0.20)
            .unwrap();
        db.archive_memory(stale_id).unwrap();
        db.log_reflector_run(
            100,
            &started_at,
            &finished_at,
            3,
            1,
            1,
            1,
            "jaccard",
            true,
            None,
        )
        .unwrap();
        db.log_memory_injection(100, "keyword", 5, 2, 3, 80)
            .unwrap();

        let summary = db.get_memory_observability_summary(Some(100)).unwrap();
        assert!(summary.total >= 2);
        assert!(summary.active >= 1);
        assert!(summary.archived >= 1);
        assert!(summary.reflector_runs_24h >= 1);
        assert!(summary.injection_events_24h >= 1);
        assert!(summary.injection_candidates_24h >= summary.injection_selected_24h);

        cleanup(&dir);
    }

    #[test]
    fn test_supersede_memory_creates_edge_and_archives_old() {
        let (db, dir) = test_db();
        let old_id = db
            .insert_memory_with_metadata(
                Some(100),
                "prod db port is 5433",
                "KNOWLEDGE",
                "explicit",
                0.95,
            )
            .unwrap();
        let new_id = db
            .supersede_memory(
                old_id,
                "prod db port is 6432",
                "KNOWLEDGE",
                "explicit_conflict",
                0.96,
                Some("port_update"),
            )
            .unwrap();
        assert!(new_id > old_id);
        let old = db.get_memory_by_id(old_id).unwrap().unwrap();
        let newm = db.get_memory_by_id(new_id).unwrap().unwrap();
        assert!(old.is_archived);
        assert_eq!(newm.content, "prod db port is 6432");

        let conn = db.lock_conn();
        let edge_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_supersede_edges WHERE from_memory_id = ?1 AND to_memory_id = ?2",
                params![old_id, new_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(edge_count, 1);
        drop(conn);
        cleanup(&dir);
    }

    #[test]
    fn test_delete_memory() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "to be deleted", "EVENT")
            .unwrap();

        assert!(db.delete_memory(id).unwrap());
        assert!(!db.delete_memory(id).unwrap()); // already gone
        assert!(db.get_memory_by_id(id).unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn test_update_memory_content() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "User lives in Tokyo", "PROFILE")
            .unwrap();

        assert!(db
            .update_memory_content(id, "User lives in Osaka", "PROFILE")
            .unwrap());

        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert_eq!(mem.content, "User lives in Osaka");
        assert_eq!(mem.category, "PROFILE");

        // Non-existent id
        assert!(!db.update_memory_content(9999, "x", "PROFILE").unwrap());

        cleanup(&dir);
    }

    #[test]
    fn test_get_memory_by_id() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "test memory", "KNOWLEDGE")
            .unwrap();

        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert_eq!(mem.id, id);
        assert_eq!(mem.content, "test memory");
        assert_eq!(mem.category, "KNOWLEDGE");

        assert!(db.get_memory_by_id(9999).unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn test_update_memory_embedding_model_and_query_missing() {
        let (db, dir) = test_db();
        let id1 = db
            .insert_memory(Some(100), "memory one", "KNOWLEDGE")
            .unwrap();
        let id2 = db
            .insert_memory(Some(100), "memory two", "KNOWLEDGE")
            .unwrap();

        let missing_before = db.get_memories_without_embedding(Some(100), 10).unwrap();
        assert_eq!(missing_before.len(), 2);

        assert!(db
            .update_memory_embedding_model(id1, "text-embedding-3-small")
            .unwrap());

        let mem1 = db.get_memory_by_id(id1).unwrap().unwrap();
        assert_eq!(
            mem1.embedding_model.as_deref(),
            Some("text-embedding-3-small")
        );
        let mem2 = db.get_memory_by_id(id2).unwrap().unwrap();
        assert!(mem2.embedding_model.is_none());

        let missing_after = db.get_memories_without_embedding(Some(100), 10).unwrap();
        assert_eq!(missing_after.len(), 1);
        assert_eq!(missing_after[0].id, id2);

        cleanup(&dir);
    }

    #[test]
    fn test_api_key_expiry_and_rotation_and_audit_logs() {
        let (db, dir) = test_db();
        let scopes = vec![
            "operator.read".to_string(),
            "operator.approvals".to_string(),
        ];
        let key_id = db
            .create_api_key(
                "k1",
                "hash-k1",
                "prefix-k1",
                &scopes,
                Some(&(chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
                None,
            )
            .unwrap();
        let valid = db.validate_api_key_hash("hash-k1").unwrap();
        assert!(valid.is_some());

        let expired_id = db
            .create_api_key(
                "k2",
                "hash-k2",
                "prefix-k2",
                &scopes,
                Some(&(chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()),
                Some(key_id),
            )
            .unwrap();
        let expired = db.validate_api_key_hash("hash-k2").unwrap();
        assert!(expired.is_none());
        assert!(db.rotate_api_key_revoke_old(key_id).unwrap());

        let keys = db.list_api_keys().unwrap();
        let rotated = keys.iter().find(|k| k.id == expired_id).unwrap();
        assert_eq!(rotated.rotated_from_key_id, Some(key_id));

        db.log_audit_event(
            "operator",
            "tester",
            "auth.api_key.rotate",
            Some("k1"),
            "ok",
            None,
        )
        .unwrap();
        let logs = db.list_audit_logs(Some("operator"), 20).unwrap();
        assert!(!logs.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_skill_activation_log_and_query() {
        let (db, dir) = test_db();
        // No activations yet → None
        assert!(db.last_skill_activation_at("alpha").unwrap().is_none());

        db.log_skill_activation("alpha", 7).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        db.log_skill_activation("alpha", 7).unwrap();
        db.log_skill_activation("beta", 8).unwrap();

        let last_alpha = db.last_skill_activation_at("alpha").unwrap().unwrap();
        let last_beta = db.last_skill_activation_at("beta").unwrap().unwrap();
        assert!(last_alpha >= last_beta || last_alpha <= last_beta);

        let counts = db
            .skill_activation_counts_since("1970-01-01T00:00:00Z")
            .unwrap();
        let alpha = counts.iter().find(|(n, _)| n == "alpha").unwrap();
        let beta = counts.iter().find(|(n, _)| n == "beta").unwrap();
        assert_eq!(alpha.1, 2);
        assert_eq!(beta.1, 1);
        // Counts ordered by n DESC then name — alpha first.
        assert_eq!(counts[0].0, "alpha");

        // Cutoff in the future → no rows.
        let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let none = db.skill_activation_counts_since(&future).unwrap();
        assert!(none.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_memory_ttl_filters_and_prunes() {
        let (db, dir) = test_db();
        let durable = db
            .insert_memory(Some(7), "durable fact", "KNOWLEDGE")
            .unwrap();
        let expiring = db
            .insert_memory(Some(7), "transient fact", "KNOWLEDGE")
            .unwrap();
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

        // Future expiry — still surfaced in retrieval.
        db.set_memory_expires_at(durable, Some(&future)).unwrap();
        // Past expiry — gets filtered from retrieval right away.
        db.set_memory_expires_at(expiring, Some(&past)).unwrap();

        let ctx = db.get_memories_for_context(7, 50).unwrap();
        let ids: Vec<i64> = ctx.iter().map(|m| m.id).collect();
        assert!(ids.contains(&durable), "durable memory should be visible");
        assert!(
            !ids.contains(&expiring),
            "expired memory must not appear in context retrieval"
        );

        // Search also filters.
        let hits = db.search_memories(7, "fact", 50).unwrap();
        assert!(hits.iter().all(|m| m.id != expiring));

        // Prune deletes the row.
        let now = chrono::Utc::now().to_rfc3339();
        let pruned = db.prune_expired_memories(&now).unwrap();
        assert_eq!(pruned, 1);
        assert!(db.get_memory_by_id(expiring).unwrap().is_none());
        assert!(db.get_memory_by_id(durable).unwrap().is_some());
        cleanup(&dir);
    }

    #[test]
    fn test_tool_artifact_save_and_slice() {
        let (db, dir) = test_db();
        let now = chrono::Utc::now();
        let expires = (now + chrono::Duration::hours(1)).to_rfc3339();
        let body: String = "0123456789".repeat(20); // 200 chars
        db.save_tool_artifact("art_x", 42, "bash", &body, &expires)
            .unwrap();

        // First slice from offset 0
        let (meta, slice) = db
            .get_tool_artifact_slice("art_x", 0, 50, &now.to_rfc3339())
            .unwrap()
            .expect("artifact present");
        assert_eq!(meta.chat_id, 42);
        assert_eq!(meta.tool_name, "bash");
        assert_eq!(meta.total_chars, 200);
        assert_eq!(slice.chars().count(), 50);
        assert!(body.starts_with(&slice));

        // Slice past the end clamps to remaining
        let (_, tail) = db
            .get_tool_artifact_slice("art_x", 190, 50, &now.to_rfc3339())
            .unwrap()
            .unwrap();
        assert_eq!(tail.chars().count(), 10);

        // Expired artifact returns None
        let future = (now + chrono::Duration::hours(2)).to_rfc3339();
        let missing = db.get_tool_artifact_slice("art_x", 0, 10, &future).unwrap();
        assert!(missing.is_none());

        // Prune removes expired rows
        let pruned = db.prune_tool_artifacts(&future).unwrap();
        assert_eq!(pruned, 1);
        cleanup(&dir);
    }

    #[cfg(feature = "sqlite-vec")]
    #[test]
    fn test_sqlite_vec_prepare_and_knn() {
        let (db, dir) = test_db();
        db.prepare_vector_index(3).unwrap();
        let id1 = db
            .insert_memory(Some(100), "vector one", "KNOWLEDGE")
            .unwrap();
        let id2 = db
            .insert_memory(Some(100), "vector two", "KNOWLEDGE")
            .unwrap();
        db.upsert_memory_vec(id1, &[1.0, 0.0, 0.0]).unwrap();
        db.upsert_memory_vec(id2, &[0.0, 1.0, 0.0]).unwrap();

        let nearest = db.knn_memories(100, &[0.95, 0.05, 0.0], 1).unwrap();
        assert_eq!(nearest.len(), 1);
        assert_eq!(nearest[0].0, id1);
        assert!(nearest[0].1 >= 0.0);

        cleanup(&dir);
    }

    #[test]
    fn test_list_idle_chats() {
        let (db, dir) = test_db();
        // Chat 1: last message long ago (idle). Chat 2: recent (active).
        db.store_message(&StoredMessage {
            id: "old".into(),
            chat_id: 1,
            sender_name: "u".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2020-01-01T00:00:00Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "new".into(),
            chat_id: 2,
            sender_name: "u".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2099-01-01T00:00:00Z".into(),
        })
        .unwrap();
        let idle = db.list_idle_chats("2030-01-01T00:00:00Z", 50).unwrap();
        assert!(idle.contains(&1));
        assert!(!idle.contains(&2));

        // Familiarity proxy: message counts per chat.
        assert_eq!(db.count_messages_for_chat(1).unwrap(), 1);
        assert_eq!(db.count_messages_for_chat(2).unwrap(), 1);
        assert_eq!(db.count_messages_for_chat(999).unwrap(), 0);
        cleanup(&dir);
    }

    #[test]
    fn test_active_turns_mark_clear_and_take() {
        let (db, dir) = test_db();

        // Nothing tracked → nothing to recover.
        assert!(db.take_interrupted_turns().unwrap().is_empty());

        db.mark_turn_active(10, "telegram").unwrap();
        db.mark_turn_active(20, "discord").unwrap();
        // Re-entrant mark for the same chat refreshes rather than duplicates.
        db.mark_turn_active(10, "telegram").unwrap();
        // Progress snapshots attach to the in-flight turn; unknown chat = no-op.
        db.update_turn_progress(10, "step 3: web_search, read_file")
            .unwrap();
        db.update_turn_progress(999, "ignored").unwrap();
        // A turn that finished cleanly leaves no residue.
        db.clear_turn_active(20).unwrap();

        let orphans = db.take_interrupted_turns().unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].chat_id, 10);
        assert_eq!(orphans[0].channel, "telegram");
        assert!(!orphans[0].started_at.is_empty());
        assert_eq!(
            orphans[0].progress_text.as_deref(),
            Some("step 3: web_search, read_file")
        );

        // take is destructive: a second sweep can never double-notify.
        assert!(db.take_interrupted_turns().unwrap().is_empty());
        // Clearing an unknown chat is a no-op, not an error.
        db.clear_turn_active(999).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn test_active_turn_checkpoint_survives_recovery_restart_boundary() {
        let (db, dir) = test_db();
        let session = r#"[{"role":"user","content":"finish the task"}]"#;

        db.mark_turn_active_with_context(42, "slack", "group", Some("run-original"))
            .unwrap();
        db.checkpoint_active_turn(
            42,
            "ready_for_llm",
            3,
            Some(session),
            true,
            Some("step 3 complete"),
            None,
        )
        .unwrap();
        let checkpoint_at = db.list_active_turns().unwrap()[0]
            .last_checkpoint_at
            .clone();

        // A recovery claim updates only process-local metadata. Simulating a
        // second crash here must leave the safe session checkpoint available.
        db.mark_turn_recovery_started(42, "run-recovery").unwrap();
        let turns = db.list_active_turns().unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].chat_type, "group");
        assert_eq!(turns[0].phase, "resuming");
        assert_eq!(turns[0].iteration, 3);
        assert_eq!(turns[0].session_json.as_deref(), Some(session));
        assert!(turns[0].resumable);
        assert_eq!(turns[0].run_id.as_deref(), Some("run-recovery"));
        assert_eq!(turns[0].last_checkpoint_at, checkpoint_at);

        // Once a tool starts, retain the prior evidence but mark the boundary
        // non-resumable so startup cannot replay an uncertain side effect.
        db.checkpoint_active_turn(
            42,
            "executing_tools",
            4,
            None,
            false,
            None,
            Some("send_message(medium)"),
        )
        .unwrap();
        let turn = db.list_active_turns().unwrap().pop().unwrap();
        assert!(!turn.resumable);
        assert_eq!(turn.session_json.as_deref(), Some(session));
        assert_eq!(turn.tool_summary.as_deref(), Some("send_message(medium)"));

        db.clear_turn_active(42).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn test_outbox_lifecycle() {
        let (db, dir) = test_db();
        assert_eq!(db.count_outbox_pending().unwrap(), 0);

        let id = db
            .enqueue_outbox_message(42, "telegram", "the answer is 42")
            .unwrap();
        assert_eq!(db.count_outbox_pending().unwrap(), 1);

        // Due immediately (next_attempt_at = enqueue time).
        let due = db
            .list_due_outbox_messages("2999-01-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].chat_id, 42);
        assert_eq!(due[0].payload_text, "the answer is 42");
        assert_eq!(due[0].status, "pending");

        // Retry with a future next attempt → not due before that instant.
        db.mark_outbox_retry(id, 1, Some("2999-06-01T00:00:00Z"), "network down", false)
            .unwrap();
        assert!(db
            .list_due_outbox_messages("2999-01-01T00:00:00Z", 10)
            .unwrap()
            .is_empty());
        let due = db
            .list_due_outbox_messages("2999-07-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 1);
        assert_eq!(due[0].last_error.as_deref(), Some("network down"));

        // Delivered → gone from the queue and the pending count.
        db.mark_outbox_delivered(id).unwrap();
        assert!(db
            .list_due_outbox_messages("2999-07-01T00:00:00Z", 10)
            .unwrap()
            .is_empty());
        assert_eq!(db.count_outbox_pending().unwrap(), 0);

        // Terminal failure also leaves the queue.
        let id2 = db.enqueue_outbox_message(43, "slack", "bye").unwrap();
        db.mark_outbox_retry(id2, 8, None, "gave up", true).unwrap();
        assert!(db
            .list_due_outbox_messages("2999-07-01T00:00:00Z", 10)
            .unwrap()
            .is_empty());
        assert_eq!(db.count_outbox_pending().unwrap(), 0);
        cleanup(&dir);
    }

    #[test]
    fn test_chunked_delivery_resumes_and_stores_logical_message_once() {
        let (db, dir) = test_db();
        let ids = db
            .create_outbound_delivery(
                "delivery-test",
                77,
                "weixin",
                "first second third",
                &["first".into(), "second".into(), "third".into()],
            )
            .unwrap();
        assert_eq!(ids.len(), 3);
        let health = db.outbound_delivery_health().unwrap();
        assert_eq!(health.total_deliveries, 1);
        assert_eq!(health.pending_chunks, 3);

        assert!(db.mark_outbox_sending(ids[0]).unwrap());
        db.mark_outbox_delivered(ids[0]).unwrap();
        assert!(db.mark_outbox_sending(ids[1]).unwrap());
        assert_eq!(db.recover_sending_outbox_messages().unwrap(), 1);

        let due = db
            .list_due_outbox_messages("2999-01-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].chunk_index, 1);
        assert_eq!(due[0].idempotency_key, "delivery-test:2");
        assert_eq!(due[1].chunk_index, 2);

        for row in due {
            assert!(db.mark_outbox_sending(row.id).unwrap());
            db.mark_outbox_delivered(row.id).unwrap();
        }
        assert!(db.outbound_delivery_is_complete("delivery-test").unwrap());
        assert!(db
            .finalize_outbound_delivery("delivery-test", "bot")
            .unwrap());
        assert!(!db
            .finalize_outbound_delivery("delivery-test", "bot")
            .unwrap());

        let messages = db.get_all_messages(77).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "first second third");
        let health = db.outbound_delivery_health().unwrap();
        assert_eq!(health.delivered_deliveries, 1);
        assert_eq!(
            health.pending_chunks + health.sending_chunks + health.retry_chunks,
            0
        );
        assert_eq!(health.failed_chunks, 0);
        cleanup(&dir);
    }

    #[test]
    fn test_recover_orphaned_subagent_runs() {
        let (db, dir) = test_db();
        for (run_id, status) in [
            ("orph-accepted", None),
            ("orph-running", Some("running")),
            ("done-ok", Some("done")),
        ] {
            db.create_subagent_run(CreateSubagentRunParams {
                run_id,
                parent_run_id: None,
                depth: 1,
                token_budget: 0,
                chat_id: 7,
                caller_channel: "telegram",
                task: "t",
                context: "",
                provider: "anthropic",
                model: "claude-test",
                label: None,
            })
            .unwrap();
            match status {
                Some("running") => db.mark_subagent_running(run_id).unwrap(),
                Some(s) => db
                    .mark_subagent_finished(FinishSubagentRunParams {
                        run_id,
                        status: s,
                        error_text: None,
                        result_text: Some("ok"),
                        artifact_json: None,
                        input_tokens: 0,
                        output_tokens: 0,
                    })
                    .unwrap(),
                None => {}
            }
        }

        let fixed = db.recover_orphaned_subagent_runs().unwrap();
        assert_eq!(fixed, 2, "accepted + running rows must be retired");

        for run_id in ["orph-accepted", "orph-running"] {
            let run = db.get_subagent_run(run_id, 7).unwrap().unwrap();
            assert_eq!(run.status, "interrupted");
            assert!(run.finished_at.is_some());
            assert!(run.error_text.as_deref().unwrap().contains("restarted"));
        }
        // Finished runs are untouched, and nothing counts as active anymore.
        let done = db.get_subagent_run("done-ok", 7).unwrap().unwrap();
        assert_eq!(done.status, "done");
        assert!(done.error_text.is_none());
        assert!(db.list_active_subagent_runs().unwrap().is_empty());
        // Idempotent: a second recovery pass finds nothing.
        assert_eq!(db.recover_orphaned_subagent_runs().unwrap(), 0);
        cleanup(&dir);
    }

    #[test]
    fn test_subagent_run_label_and_progress() {
        let (db, dir) = test_db();
        db.create_subagent_run(CreateSubagentRunParams {
            run_id: "subrun-1",
            parent_run_id: None,
            depth: 1,
            token_budget: 0,
            chat_id: 42,
            caller_channel: "telegram",
            task: "research competitor pricing",
            context: "",
            provider: "anthropic",
            model: "claude-test",
            label: Some("competitor research"),
        })
        .unwrap();

        // Label round-trips through both get and list.
        let run = db.get_subagent_run("subrun-1", 42).unwrap().unwrap();
        assert_eq!(run.label.as_deref(), Some("competitor research"));
        assert!(run.progress_text.is_none());
        assert!(run.last_progress_at.is_none());
        let listed = db.list_subagent_runs(42, 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label.as_deref(), Some("competitor research"));

        // Active-runs query (used by the standup loop) sees the fresh run.
        let active = db.list_active_subagent_runs().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].run_id, "subrun-1");
        assert_eq!(active[0].chat_id, 42);

        // Resolve by exact run_id, by label, and a miss.
        assert_eq!(
            db.resolve_subagent_run_id(42, "subrun-1")
                .unwrap()
                .as_deref(),
            Some("subrun-1")
        );
        assert_eq!(
            db.resolve_subagent_run_id(42, "competitor research")
                .unwrap()
                .as_deref(),
            Some("subrun-1")
        );
        assert!(db.resolve_subagent_run_id(42, "nope").unwrap().is_none());
        // Wrong chat → no match.
        assert!(db
            .resolve_subagent_run_id(99, "competitor research")
            .unwrap()
            .is_none());

        // Children listing for fan-in: a child of subrun-1.
        db.create_subagent_run(CreateSubagentRunParams {
            run_id: "subrun-1a",
            parent_run_id: Some("subrun-1"),
            depth: 2,
            token_budget: 0,
            chat_id: 42,
            caller_channel: "telegram",
            task: "child task",
            context: "",
            provider: "anthropic",
            model: "claude-test",
            label: Some("child"),
        })
        .unwrap();
        let kids = db.list_subagent_children("subrun-1").unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].run_id, "subrun-1a");
        assert!(db.list_subagent_children("subrun-1a").unwrap().is_empty());

        // First progress: no previous timestamp.
        let prev = db
            .record_subagent_progress("subrun-1", "checked 3/5 sources")
            .unwrap();
        assert!(prev.is_none());
        let run = db.get_subagent_run("subrun-1", 42).unwrap().unwrap();
        assert_eq!(run.progress_text.as_deref(), Some("checked 3/5 sources"));
        assert!(run.last_progress_at.is_some());

        // Second progress: returns the prior timestamp (used for throttling) and
        // appends a second event to the run timeline.
        let prev2 = db
            .record_subagent_progress("subrun-1", "checked 5/5 sources")
            .unwrap();
        assert!(prev2.is_some());
        let events = db.list_subagent_events("subrun-1", 50).unwrap();
        let progress_events = events.iter().filter(|e| e.event_type == "progress").count();
        assert_eq!(progress_events, 2);

        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_promotes_verified_skill_and_preserves_evidence() {
        let (db, dir) = test_db();
        db.upsert_goal_state(
            "goal-1",
            42,
            "finish the release",
            "active",
            Some(r#"{"must_pass_tests":true}"#),
            None,
            Some(r#"{"tool_calls":20}"#),
        )
        .unwrap();
        assert_eq!(
            db.get_active_goal_state(42).unwrap().unwrap().objective,
            "finish the release"
        );

        db.register_skill_version(
            "release-check",
            1,
            "---\nname: release-check\n---\nRun tests.",
            "agent-created",
        )
        .unwrap();
        assert_eq!(
            db.get_skill_lifecycle("release-check")
                .unwrap()
                .unwrap()
                .state,
            "candidate"
        );
        db.start_experience_run(
            "self-reported",
            Some("goal-1"),
            42,
            "web",
            "interactive",
            "ship it",
            Some("repo=test"),
        )
        .unwrap();
        db.log_skill_activation("release-check", 42).unwrap();
        db.record_verifier_result(
            "self-reported",
            "runtime",
            "agent_loop_completion",
            "passed",
            0.55,
            Some("model returned normally"),
            Some("turn"),
            None,
        )
        .unwrap();
        assert_eq!(
            db.get_skill_lifecycle("release-check")
                .unwrap()
                .unwrap()
                .state,
            "candidate",
            "runtime self-report must not advance governed behavior"
        );
        db.finish_experience_run("self-reported", "completed", None, 10)
            .unwrap();
        db.update_experience_metrics("self-reported", 120, 30, 2, 4, 1, Some(0.0125))
            .unwrap();
        let measured = db
            .get_recent_experience_runs(Some(42), 1)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(measured.input_tokens, 120);
        assert_eq!(measured.output_tokens, 30);
        assert_eq!(measured.llm_requests, 2);
        assert_eq!(measured.tool_calls, 4);
        assert_eq!(measured.tool_errors, 1);
        assert_eq!(measured.estimated_cost_usd, Some(0.0125));

        for index in 1..=3 {
            let run_id = format!("run-{index}");
            db.start_experience_run(
                &run_id,
                Some("goal-1"),
                42,
                "web",
                "interactive",
                "ship it",
                Some("repo=test"),
            )
            .unwrap();
            db.log_skill_activation("release-check", 42).unwrap();
            db.finish_experience_run(&run_id, "completed", Some("done"), 10)
                .unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "tests",
                "passed",
                1.0,
                Some("cargo test passed"),
                Some("repository"),
                None,
            )
            .unwrap();
        }

        let lifecycle = db.get_skill_lifecycle("release-check").unwrap().unwrap();
        assert_eq!(lifecycle.state, "trusted");
        let summaries = db.get_skill_learning_summaries().unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.skill_name == "release-check")
            .unwrap();
        assert_eq!(summary.total_outcomes, 3);
        assert_eq!(summary.passed_outcomes, 3);
        assert_eq!(summary.success_rate, 1.0);
        assert_eq!(
            db.get_verifier_results("run-1").unwrap()[0]
                .evidence
                .as_deref(),
            Some("cargo test passed")
        );
        assert!(db.clear_chat_memory(42).unwrap());
        assert!(db
            .get_recent_experience_runs(Some(42), 10)
            .unwrap()
            .is_empty());
        assert!(db.get_active_goal_state(42).unwrap().is_none());
        assert_eq!(
            db.get_skill_lifecycle("release-check")
                .unwrap()
                .unwrap()
                .state,
            "candidate",
            "erasing chat learning must recompute derived skill trust"
        );
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_degrades_and_rolls_back_skill_version() {
        let (db, dir) = test_db();
        db.register_skill_version("browser-flow", 1, "safe v1", "agent-created")
            .unwrap();
        // Promote v1 to trusted.
        for index in 1..=3 {
            let run_id = format!("good-{index}");
            db.start_experience_run(&run_id, None, 7, "web", "interactive", "browse", None)
                .unwrap();
            db.log_skill_activation("browser-flow", 7).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "browser_assertion",
                "passed",
                1.0,
                None,
                None,
                None,
            )
            .unwrap();
        }
        assert_eq!(
            db.get_skill_lifecycle("browser-flow")
                .unwrap()
                .unwrap()
                .state,
            "trusted"
        );

        db.register_skill_version("browser-flow", 2, "risky v2", "agent-created")
            .unwrap();
        db.register_skill_version("browser-flow", 1, "safe v1", "agent-created")
            .unwrap();
        assert_eq!(
            db.get_skill_lifecycle("browser-flow")
                .unwrap()
                .unwrap()
                .active_version,
            2,
            "re-registering an older version must not perform an implicit rollback"
        );
        assert!(
            db.register_skill_version("browser-flow", 1, "mutated v1", "agent-created")
                .is_err(),
            "recorded versions must be immutable"
        );
        assert_eq!(
            db.get_skill_lifecycle("browser-flow")
                .unwrap()
                .unwrap()
                .state,
            "candidate"
        );
        for index in 1..=2 {
            let run_id = format!("bad-{index}");
            db.start_experience_run(&run_id, None, 7, "web", "interactive", "browse", None)
                .unwrap();
            db.log_skill_activation("browser-flow", 7).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "browser_assertion",
                "failed",
                1.0,
                Some("wrong page"),
                None,
                None,
            )
            .unwrap();
        }
        assert_eq!(
            db.get_skill_lifecycle("browser-flow")
                .unwrap()
                .unwrap()
                .state,
            "degraded"
        );
        let (version, content) = db
            .rollback_skill("browser-flow", None, "operator rollback")
            .unwrap()
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(content, "safe v1");
        assert_eq!(
            db.get_skill_lifecycle("browser-flow")
                .unwrap()
                .unwrap()
                .state,
            "trusted"
        );
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_blocks_repeated_failures_in_matching_environment() {
        let (db, dir) = test_db();
        db.register_skill_version("deploy", 1, "deploy safely", "built-in")
            .unwrap();
        for index in 1..=2 {
            let run_id = format!("linux-failure-{index}");
            db.start_experience_run(
                &run_id,
                None,
                9,
                "web",
                "interactive",
                "deploy",
                Some("os=linux;provider=acme"),
            )
            .unwrap();
            db.log_skill_activation("deploy", 9).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "deployment_health",
                "failed",
                1.0,
                Some("health check failed"),
                None,
                None,
            )
            .unwrap();
            db.finish_experience_run(&run_id, "completed", None, 10)
                .unwrap();
        }
        db.start_experience_run(
            "linux-current",
            None,
            9,
            "web",
            "interactive",
            "deploy",
            Some("os=linux;provider=acme"),
        )
        .unwrap();
        let applicability = db.evaluate_skill_applicability("deploy", 9).unwrap();
        assert!(!applicability.allowed);
        assert_eq!(applicability.matching_outcomes, 2);
        assert_eq!(applicability.failed_outcomes, 2);
        assert_eq!(applicability.task_family.as_deref(), Some("deployment"));
        db.finish_experience_run("linux-current", "completed", None, 1)
            .unwrap();
        db.start_experience_run(
            "linux-debug-current",
            None,
            9,
            "web",
            "interactive",
            "debug parser failure",
            Some("os=linux;provider=acme"),
        )
        .unwrap();
        let different_family = db.evaluate_skill_applicability("deploy", 9).unwrap();
        assert!(different_family.allowed);
        assert_eq!(different_family.matching_outcomes, 0);
        assert_eq!(different_family.task_family.as_deref(), Some("debugging"));

        db.transition_skill_state("deploy", "archived", "operator archive")
            .unwrap();
        assert_eq!(
            db.get_skill_lifecycle("deploy").unwrap().unwrap().state,
            "archived"
        );
        cleanup(&dir);
    }

    #[test]
    fn learning_failure_patterns_block_retrieval_and_recover_after_cooldown() {
        let (db, dir) = test_db();
        db.register_skill_version("deploy-safe", 1, "deploy", "built-in")
            .unwrap();
        for index in 1..=2 {
            let run_id = format!("deploy-timeout-{index}");
            db.start_experience_run(
                &run_id,
                None,
                91,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("deploy-safe", 91).unwrap();
            db.ingest_outcome_envelope(&OutcomeEnvelopeV1 {
                envelope_id: format!("tool:{index}"),
                run_id: run_id.clone(),
                source_kind: "runtime".into(),
                source_name: "tool_result:bash".into(),
                verdict: "failed".into(),
                confidence: 1.0,
                evidence: Some("command timed out".into()),
                scope: Some("tool_result".into()),
                valid_until: None,
                payload: serde_json::json!({"tool_name": "bash"}),
                feedback: None,
            })
            .unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "health",
                "failed",
                1.0,
                Some("deployment health failed"),
                None,
                None,
            )
            .unwrap();
            db.finish_experience_run(&run_id, "failed", Some("timeout"), 10)
                .unwrap();
        }

        let patterns = db.get_skill_failure_patterns(Some("deploy-safe")).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].task_family, "deployment");
        assert_eq!(patterns[0].tool_name.as_deref(), Some("bash"));
        assert_eq!(patterns[0].error_category, "timeout");
        assert_eq!(patterns[0].failure_count, 2);
        assert_eq!(patterns[0].state, "active");
        assert_eq!(
            db.get_skill_lifecycle("deploy-safe")
                .unwrap()
                .unwrap()
                .state,
            "degraded"
        );

        let matches = db
            .search_verified_experiences(91, "deploy service", Some("os=linux"), 10)
            .unwrap();
        assert!(matches.iter().all(|item| item.rejection_reason.is_some()));

        db.start_experience_run(
            "querying-run",
            None,
            91,
            "web",
            "interactive",
            "deploy service",
            Some("os=linux"),
        )
        .unwrap();
        let rejected = matches
            .iter()
            .map(|item| {
                (
                    item.run_id.clone(),
                    item.rejection_reason.clone().unwrap(),
                    item.relevance_score,
                )
            })
            .collect::<Vec<_>>();
        db.record_experience_rejections("querying-run", &rejected)
            .unwrap();
        let detail = db
            .get_experience_run_detail("querying-run")
            .unwrap()
            .unwrap();
        assert_eq!(detail.rejected_experiences.len(), 2);
        assert!(detail.retrieved_experiences.is_empty());
        db.finish_experience_run("querying-run", "completed", None, 1)
            .unwrap();

        {
            let conn = db.lock_conn();
            conn.execute(
                "UPDATE skill_failure_patterns
                 SET cooldown_until='2000-01-01T00:00:00+00:00'
                 WHERE skill_name='deploy-safe'",
                [],
            )
            .unwrap();
        }
        assert!(db.begin_skill_recovery_trial("deploy-safe").unwrap());
        assert_eq!(
            db.get_skill_lifecycle("deploy-safe")
                .unwrap()
                .unwrap()
                .state,
            "trial"
        );
        for index in 1..=2 {
            let run_id = format!("deploy-recovery-{index}");
            db.start_experience_run(
                &run_id,
                None,
                91,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("deploy-safe", 91).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "health",
                "passed",
                1.0,
                Some("healthy"),
                None,
                None,
            )
            .unwrap();
        }
        let pattern = db
            .get_skill_failure_patterns(Some("deploy-safe"))
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(pattern.state, "resolved");
        assert_eq!(pattern.recovery_successes, 2);
        assert_eq!(
            db.get_skill_lifecycle("deploy-safe")
                .unwrap()
                .unwrap()
                .state,
            "trial"
        );
        cleanup(&dir);
    }

    #[test]
    fn comparative_reflection_shadow_promotion_and_automatic_rollback() {
        let (db, dir) = test_db();
        db.register_skill_version("reflective-deploy", 1, "deploy safely", "built-in")
            .unwrap();
        for (run_id, verdict, summary, errors) in [
            ("reflection-failure", "failed", "health timeout", 1),
            ("reflection-success", "passed", "healthy deployment", 0),
        ] {
            db.start_experience_run(
                run_id,
                None,
                92,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("reflective-deploy", 92).unwrap();
            db.update_experience_metrics(run_id, 10, 5, 1, 2, errors, Some(1.0))
                .unwrap();
            db.finish_experience_run(run_id, "completed", Some(summary), 100)
                .unwrap();
            db.record_verifier_result(
                run_id,
                "deterministic",
                "health",
                verdict,
                1.0,
                Some(summary),
                None,
                None,
            )
            .unwrap();
        }

        let comparisons = db.get_experience_comparisons(Some(92), 10).unwrap();
        assert_eq!(comparisons.len(), 1);
        assert_eq!(comparisons[0].task_family, "deployment");
        assert_eq!(comparisons[0].success_run_id, "reflection-success");
        assert_eq!(comparisons[0].failure_run_id, "reflection-failure");
        assert!(comparisons[0].minimal_difference.contains("tool_errors"));

        let claims = db.get_learning_claims(Some(92), 10).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].status, "candidate");
        assert_eq!(claims[0].evidence["success_run_id"], "reflection-success");
        assert!(claims[0].counterexamples.is_array());

        let candidate = db
            .create_skill_candidate_from_claim(&claims[0].claim_id, 92)
            .unwrap();
        assert_eq!(candidate.base_version, 1);
        assert_eq!(candidate.candidate_version, 2);
        assert!(candidate.content.contains("Learned guardrail"));
        assert_eq!(
            db.get_skill_lifecycle("reflective-deploy")
                .unwrap()
                .unwrap()
                .active_version,
            1,
            "candidate creation and shadow evaluation must not activate it"
        );

        let mut evaluation = None;
        for index in 0..3 {
            let pair = format!("pair-{index}");
            db.record_shadow_observation(
                &candidate.candidate_id,
                92,
                &pair,
                "baseline",
                "reflection-success",
                "passed",
                1.0,
                100,
                Some("baseline passed"),
            )
            .unwrap();
            evaluation = Some(
                db.record_shadow_observation(
                    &candidate.candidate_id,
                    92,
                    &pair,
                    "candidate",
                    "reflection-failure",
                    "failed",
                    0.8,
                    80,
                    Some("candidate regressed"),
                )
                .unwrap(),
            );
        }
        assert_eq!(evaluation.as_ref().unwrap().verdict, "failed");
        assert_eq!(evaluation.as_ref().unwrap().regression_count, 3);

        for index in 0..3 {
            let pair = format!("pair-{index}");
            db.record_shadow_observation(
                &candidate.candidate_id,
                92,
                &pair,
                "baseline",
                "reflection-failure",
                "failed",
                1.0,
                100,
                Some("baseline failed"),
            )
            .unwrap();
            evaluation = Some(
                db.record_shadow_observation(
                    &candidate.candidate_id,
                    92,
                    &pair,
                    "candidate",
                    "reflection-success",
                    "passed",
                    0.8,
                    80,
                    Some("candidate passed"),
                )
                .unwrap(),
            );
        }
        let evaluation = evaluation.unwrap();
        assert_eq!(evaluation.sample_count, 3);
        assert_eq!(evaluation.verdict, "passed");
        assert!(evaluation.candidate_utility_lower_bound > 0.4);
        assert_eq!(
            db.get_skill_lifecycle("reflective-deploy")
                .unwrap()
                .unwrap()
                .active_version,
            1,
            "shadow pass still requires an explicit governed promotion"
        );

        let promoted = db
            .promote_shadow_candidate(&candidate.candidate_id, 92)
            .unwrap();
        assert_eq!(promoted, ("reflective-deploy".to_string(), 2));
        assert_eq!(
            db.get_skill_lifecycle("reflective-deploy")
                .unwrap()
                .unwrap()
                .active_version,
            2
        );

        for index in 0..2 {
            let run_id = format!("promoted-regression-{index}");
            db.start_experience_run(
                &run_id,
                None,
                92,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("reflective-deploy", 92).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "health",
                "failed",
                1.0,
                Some("new regression"),
                None,
                None,
            )
            .unwrap();
        }
        let lifecycle = db
            .get_skill_lifecycle("reflective-deploy")
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.active_version, 1);
        assert_eq!(lifecycle.state, "trusted");
        assert!(lifecycle
            .state_reason
            .as_deref()
            .unwrap_or_default()
            .contains("automatic rollback"));
        let journal = db.get_learning_journal(Some(92), 50).unwrap();
        assert!(journal
            .iter()
            .any(|event| event.event_type == "claim_distilled"));
        assert!(journal
            .iter()
            .any(|event| event.event_type == "candidate_promoted"));
        assert!(journal
            .iter()
            .any(|event| event.event_type == "automatic_rollback"));
        assert!(db.clear_chat_memory(92).unwrap());
        assert!(db
            .get_experience_comparisons(Some(92), 10)
            .unwrap()
            .is_empty());
        assert!(db.get_learning_claims(Some(92), 10).unwrap().is_empty());
        assert!(db.get_skill_candidates(Some(92), 10).unwrap().is_empty());
        assert!(db.get_shadow_evaluations(Some(92)).unwrap().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn comparative_reflection_never_pairs_or_exposes_across_chats() {
        let (db, dir) = test_db();
        db.register_skill_version("scoped-reflection", 1, "base", "built-in")
            .unwrap();
        for (run_id, chat_id, verdict) in [
            ("scoped-failure", 201, "failed"),
            ("scoped-success", 202, "passed"),
        ] {
            db.start_experience_run(
                run_id,
                None,
                chat_id,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("scoped-reflection", chat_id)
                .unwrap();
            db.record_verifier_result(
                run_id,
                "deterministic",
                "health",
                verdict,
                1.0,
                Some(verdict),
                None,
                None,
            )
            .unwrap();
        }
        assert!(db
            .get_experience_comparisons(Some(201), 10)
            .unwrap()
            .is_empty());
        assert!(db
            .get_experience_comparisons(Some(202), 10)
            .unwrap()
            .is_empty());
        assert!(db.get_learning_claims(Some(201), 10).unwrap().is_empty());
        assert!(db.get_learning_claims(Some(202), 10).unwrap().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_recovers_interrupted_runs_without_penalizing_skill() {
        let (db, dir) = test_db();
        db.register_skill_version("restart-safe", 1, "instructions", "agent-created")
            .unwrap();
        db.start_experience_run(
            "interrupted-run",
            None,
            11,
            "web",
            "interactive",
            "long task",
            Some("channel=web"),
        )
        .unwrap();
        db.log_skill_activation("restart-safe", 11).unwrap();

        assert_eq!(db.recover_running_experience_runs().unwrap(), 1);
        assert_eq!(db.recover_running_experience_runs().unwrap(), 0);
        let run = db
            .get_recent_experience_runs(Some(11), 1)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(run.status, "failed");
        assert_eq!(
            db.get_skill_lifecycle("restart-safe")
                .unwrap()
                .unwrap()
                .state,
            "candidate",
            "process interruption must remain observable without governing the skill"
        );
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_aggregates_human_feedback_and_ignores_expired_evidence() {
        let (db, dir) = test_db();
        db.register_skill_version("reviewed", 1, "instructions", "agent-created")
            .unwrap();
        db.start_experience_run(
            "human-run",
            None,
            12,
            "web",
            "interactive",
            "review",
            Some("channel=web"),
        )
        .unwrap();
        db.log_skill_activation("reviewed", 12).unwrap();
        db.record_verifier_result(
            "human-run",
            "human",
            "user_feedback:alice",
            "passed",
            0.9,
            Some("confirmed"),
            None,
            None,
        )
        .unwrap();
        db.record_verifier_result(
            "human-run",
            "human",
            "user_feedback:bob",
            "failed",
            0.2,
            Some("minor concern"),
            None,
            None,
        )
        .unwrap();
        db.finish_experience_run("human-run", "completed", Some("review completed"), 25)
            .unwrap();
        assert_eq!(
            db.get_skill_lifecycle("reviewed").unwrap().unwrap().state,
            "trial"
        );
        let summary = db
            .get_skill_learning_summaries()
            .unwrap()
            .into_iter()
            .find(|summary| summary.skill_name == "reviewed")
            .unwrap();
        assert_eq!(summary.total_outcomes, 1);
        assert_eq!(summary.passed_outcomes, 1);
        let recalled = db
            .search_verified_experiences(12, "review", Some("channel=web"), 5)
            .unwrap();
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].run_id, "human-run");
        assert_eq!(recalled[0].verdict, "passed");
        assert!(recalled[0].relevance_score > 1.0);
        assert_eq!(recalled[0].task_signature.task_type, "general");
        assert!(recalled[0].utility_lower_bound > 0.0);

        db.start_experience_run(
            "expired-run",
            None,
            12,
            "web",
            "interactive",
            "review",
            Some("channel=web"),
        )
        .unwrap();
        db.log_skill_activation("reviewed", 12).unwrap();
        db.record_verifier_result(
            "expired-run",
            "human",
            "user_feedback:old",
            "failed",
            1.0,
            Some("stale"),
            None,
            Some("2000-01-01T00:00:00+00:00"),
        )
        .unwrap();
        let summary = db
            .get_skill_learning_summaries()
            .unwrap()
            .into_iter()
            .find(|summary| summary.skill_name == "reviewed")
            .unwrap();
        assert_eq!(summary.total_outcomes, 1);
        assert_eq!(summary.failed_outcomes, 0);
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_does_not_assign_shared_success_to_multiple_skills() {
        let (db, dir) = test_db();
        for skill in ["planner", "executor"] {
            db.register_skill_version(skill, 1, "instructions", "agent-created")
                .unwrap();
        }
        db.start_experience_run(
            "shared-run",
            None,
            13,
            "web",
            "interactive",
            "combined task",
            Some("channel=web"),
        )
        .unwrap();
        db.log_skill_activation("planner", 13).unwrap();
        db.log_skill_activation("executor", 13).unwrap();
        db.record_verifier_result(
            "shared-run",
            "deterministic",
            "tests",
            "passed",
            1.0,
            Some("all tests passed"),
            None,
            None,
        )
        .unwrap();
        for skill in ["planner", "executor"] {
            assert_eq!(
                db.get_skill_lifecycle(skill).unwrap().unwrap().state,
                "candidate",
                "ambiguous shared credit must not promote either skill"
            );
        }
        assert!(db
            .get_skill_learning_summaries()
            .unwrap()
            .iter()
            .all(|summary| summary.skill_name != "planner" || summary.total_outcomes == 0));
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_governance_policy_is_validated_and_persisted() {
        let (db, dir) = test_db();
        db.start_experience_run(
            "unique-run",
            None,
            15,
            "web",
            "interactive",
            "uniqueness",
            None,
        )
        .unwrap();
        assert!(db
            .start_experience_run(
                "unique-run",
                None,
                15,
                "web",
                "interactive",
                "replacement attempt",
                None,
            )
            .is_err());
        assert!(db
            .record_verifier_result(
                "missing-run",
                "human",
                "review",
                "passed",
                1.0,
                None,
                None,
                None,
            )
            .is_err());
        assert!(db
            .finish_experience_run("missing-run", "completed", None, 0)
            .is_err());
        let defaults = db.get_skill_governance_policy().unwrap();
        assert_eq!(defaults.trial_min_outcomes, 3);
        assert_eq!(defaults.utility_confidence_z, 1.96);
        assert_eq!(defaults.trial_promote_utility_lower_bound, 0.4);
        assert_eq!(defaults.failure_pattern_min_failures, 2);
        assert_eq!(defaults.failure_pattern_cooldown_hours, 24);
        assert_eq!(defaults.failure_pattern_recovery_successes, 2);
        assert_eq!(defaults.shadow_min_samples, 3);
        assert_eq!(defaults.shadow_promote_utility_margin, 0.05);
        assert_eq!(defaults.shadow_max_cost_ratio, 1.2);
        assert_eq!(defaults.shadow_max_regressions, 0);

        let mut invalid = defaults.clone();
        invalid.trial_degrade_rate = invalid.trial_promote_rate;
        assert!(db.update_skill_governance_policy(&invalid).is_err());
        let mut invalid_confidence = defaults.clone();
        invalid_confidence.utility_confidence_z = -1.0;
        assert!(db
            .update_skill_governance_policy(&invalid_confidence)
            .is_err());
        let mut invalid_cooldown = defaults.clone();
        invalid_cooldown.failure_pattern_cooldown_hours = 0;
        assert!(db
            .update_skill_governance_policy(&invalid_cooldown)
            .is_err());
        let mut invalid_shadow_cost = defaults.clone();
        invalid_shadow_cost.shadow_max_cost_ratio = 0.9;
        assert!(db
            .update_skill_governance_policy(&invalid_shadow_cost)
            .is_err());

        let mut updated = defaults;
        updated.candidate_failures_to_degrade = 3;
        updated.trial_min_outcomes = 4;
        updated.trusted_min_outcomes = 6;
        updated.utility_confidence_z = 1.645;
        updated.trial_promote_utility_lower_bound = 0.3;
        updated.failure_pattern_min_failures = 3;
        updated.failure_pattern_cooldown_hours = 12;
        updated.failure_pattern_recovery_successes = 1;
        updated.shadow_min_samples = 4;
        updated.shadow_promote_utility_margin = 0.1;
        updated.shadow_max_cost_ratio = 1.5;
        updated.shadow_max_regressions = 1;
        db.update_skill_governance_policy(&updated).unwrap();
        let saved = db.get_skill_governance_policy().unwrap();
        assert_eq!(saved.candidate_failures_to_degrade, 3);
        assert_eq!(saved.utility_confidence_z, 1.645);
        assert_eq!(saved.trial_promote_utility_lower_bound, 0.3);
        assert_eq!(saved.failure_pattern_min_failures, 3);
        assert_eq!(saved.failure_pattern_cooldown_hours, 12);
        assert_eq!(saved.failure_pattern_recovery_successes, 1);
        assert_eq!(saved.shadow_min_samples, 4);
        assert_eq!(saved.shadow_promote_utility_margin, 0.1);
        assert_eq!(saved.shadow_max_cost_ratio, 1.5);
        assert_eq!(saved.shadow_max_regressions, 1);
        cleanup(&dir);
    }

    #[test]
    fn learning_substrate_expired_strong_evidence_falls_back_to_active_evidence() {
        let (db, dir) = test_db();
        db.register_skill_version("expiry", 1, "instructions", "agent-created")
            .unwrap();
        db.start_experience_run(
            "expiry-run",
            None,
            14,
            "web",
            "interactive",
            "expiry check",
            Some("channel=web"),
        )
        .unwrap();
        db.log_skill_activation("expiry", 14).unwrap();
        db.record_verifier_result(
            "expiry-run",
            "human",
            "user_feedback:reviewer",
            "failed",
            0.8,
            None,
            None,
            None,
        )
        .unwrap();
        db.record_verifier_result(
            "expiry-run",
            "deterministic",
            "temporary-check",
            "passed",
            1.0,
            None,
            None,
            Some("2099-01-01T00:00:00+00:00"),
        )
        .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute(
                "UPDATE verifier_results SET valid_until='2000-01-01T00:00:00+00:00'
                 WHERE run_id='expiry-run' AND verifier_name='temporary-check'",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE skill_outcomes SET valid_until='2000-01-01T00:00:00+00:00'
                 WHERE run_id='expiry-run'",
                [],
            )
            .unwrap();
        }
        let summary = db
            .get_skill_learning_summaries()
            .unwrap()
            .into_iter()
            .find(|summary| summary.skill_name == "expiry")
            .unwrap();
        assert_eq!(summary.total_outcomes, 1);
        assert_eq!(summary.failed_outcomes, 1);
        cleanup(&dir);
    }

    #[test]
    fn outcome_envelope_projects_feedback_and_retrieval_audit_detail() {
        let (db, dir) = test_db();
        db.start_experience_run(
            "source-run",
            None,
            21,
            "web",
            "interactive",
            "deploy service",
            Some("channel=web"),
        )
        .unwrap();
        db.finish_experience_run("source-run", "completed", Some("deployed"), 20)
            .unwrap();
        db.record_verifier_result(
            "source-run",
            "deterministic",
            "deployment_check",
            "passed",
            1.0,
            Some("health check passed"),
            Some("deployment"),
            None,
        )
        .unwrap();
        db.start_experience_run(
            "query-run",
            None,
            21,
            "web",
            "interactive",
            "deploy another service",
            Some("channel=web"),
        )
        .unwrap();
        db.record_experience_retrievals(
            "query-run",
            &[(
                "source-run".into(),
                "strong_verified; environment_match=true".into(),
                1.25,
            )],
        )
        .unwrap();
        db.ingest_outcome_envelope(&OutcomeEnvelopeV1 {
            envelope_id: "feedback-envelope".into(),
            run_id: "query-run".into(),
            source_kind: "human".into(),
            source_name: "user_feedback:tester:accept".into(),
            verdict: "passed".into(),
            confidence: 0.9,
            evidence: Some("confirmed by operator".into()),
            scope: Some("turn".into()),
            valid_until: None,
            payload: serde_json::json!({"origin": "test"}),
            feedback: Some(ExperienceFeedbackInput {
                feedback_id: "accept".into(),
                actor: "tester".into(),
            }),
        })
        .unwrap();

        let detail = db.get_experience_run_detail("query-run").unwrap().unwrap();
        assert_eq!(detail.outcomes.len(), 1);
        assert_eq!(detail.outcomes[0].schema_version, 1);
        assert_eq!(detail.outcomes[0].payload["origin"], "test");
        assert_eq!(detail.feedback.len(), 1);
        assert_eq!(detail.feedback[0].feedback_id, "accept");
        assert_eq!(detail.retrieved_experiences.len(), 1);
        assert_eq!(detail.retrieved_experiences[0].source_run_id, "source-run");

        assert!(db
            .record_experience_retrievals(
                "query-run",
                &[("missing-run".into(), "invalid".into(), 1.0)]
            )
            .is_err());
        cleanup(&dir);
    }

    #[test]
    fn migration_37_backfills_existing_verifiers_and_human_feedback() {
        let (db, dir) = test_db();
        db.start_experience_run(
            "pre-v37-run",
            None,
            22,
            "web",
            "interactive",
            "legacy outcome",
            None,
        )
        .unwrap();
        db.record_verifier_result(
            "pre-v37-run",
            "human",
            "user_feedback:legacy-review",
            "passed",
            0.8,
            Some("approved before migration"),
            Some("turn"),
            None,
        )
        .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute_batch(
                "DROP TABLE experience_retrieval_logs;
                 DROP TABLE experience_feedback;
                 DROP TABLE outcome_envelopes;",
            )
            .unwrap();
            set_schema_version(&conn, 36).unwrap();
            apply_schema_migrations(&conn).unwrap();
        }

        let detail = db
            .get_experience_run_detail("pre-v37-run")
            .unwrap()
            .unwrap();
        assert_eq!(detail.outcomes.len(), 1);
        assert_eq!(detail.outcomes[0].source_kind, "human");
        assert_eq!(detail.feedback.len(), 1);
        assert_eq!(detail.feedback[0].actor, "legacy");
        let version = {
            let conn = db.lock_conn();
            get_schema_version(&conn).unwrap()
        };
        assert_eq!(version, SCHEMA_VERSION_CURRENT);
        cleanup(&dir);
    }

    #[test]
    fn migration_39_creates_failure_patterns_and_rejection_audit() {
        let (db, dir) = test_db();
        db.register_skill_version("legacy-failure", 1, "deploy", "built-in")
            .unwrap();
        for index in 0..2 {
            let run_id = format!("legacy-failure-{index}");
            db.start_experience_run(
                &run_id,
                None,
                81,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("legacy-failure", 81).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "health",
                "failed",
                1.0,
                Some("network connect failed"),
                None,
                None,
            )
            .unwrap();
        }
        {
            let conn = db.lock_conn();
            conn.execute_batch(
                "DROP TABLE skill_failure_pattern_evidence;
                 DROP TABLE skill_failure_patterns;
                 DROP TABLE experience_retrieval_rejections;",
            )
            .unwrap();
            set_schema_version(&conn, 38).unwrap();
            apply_schema_migrations(&conn).unwrap();
            let patterns: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='table' AND name='skill_failure_patterns'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let rejections: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='table' AND name='experience_retrieval_rejections'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(patterns, 1);
            assert_eq!(rejections, 1);
            assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION_CURRENT);
        }
        let backfilled = db
            .get_skill_failure_patterns(Some("legacy-failure"))
            .unwrap();
        assert_eq!(backfilled.len(), 1);
        assert_eq!(backfilled[0].failure_count, 2);
        assert_eq!(backfilled[0].error_category, "network");
        assert_eq!(backfilled[0].state, "active");
        cleanup(&dir);
    }

    #[test]
    fn migration_40_creates_comparative_reflection_and_shadow_schema() {
        let (db, dir) = test_db();
        db.register_skill_version("legacy-reflection", 1, "deploy", "built-in")
            .unwrap();
        for (run_id, verdict) in [("legacy-p2-fail", "failed"), ("legacy-p2-pass", "passed")] {
            db.start_experience_run(
                run_id,
                None,
                82,
                "web",
                "interactive",
                "deploy service",
                Some("os=linux"),
            )
            .unwrap();
            db.log_skill_activation("legacy-reflection", 82).unwrap();
            db.record_verifier_result(
                run_id,
                "deterministic",
                "health",
                verdict,
                1.0,
                Some(verdict),
                None,
                None,
            )
            .unwrap();
        }
        {
            let conn = db.lock_conn();
            conn.execute_batch(
                "DROP TABLE shadow_observations;
                 DROP TABLE shadow_evaluations;
                 DROP TABLE skill_candidates;
                 DROP TABLE learning_journal_events;
                 DROP TABLE learning_claims;
                 DROP TABLE experience_comparisons;",
            )
            .unwrap();
            set_schema_version(&conn, 39).unwrap();
            apply_schema_migrations(&conn).unwrap();
        }
        let conn = db.lock_conn();
        for table in [
            "experience_comparisons",
            "learning_claims",
            "skill_candidates",
            "shadow_observations",
            "shadow_evaluations",
            "learning_journal_events",
        ] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "missing migration table {table}");
        }
        assert!(table_has_column(&conn, "skill_governance_policy", "shadow_min_samples").unwrap());
        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION_CURRENT);
        drop(conn);
        assert_eq!(
            db.get_experience_comparisons(Some(82), 10).unwrap().len(),
            1
        );
        assert_eq!(db.get_learning_claims(Some(82), 10).unwrap().len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn task_signature_v1_is_deterministic_and_multilingual() {
        let first = derive_task_signature("Fix Rust parser bug and run tests", "interactive");
        let repeated = derive_task_signature("Fix Rust parser bug and run tests", "interactive");
        assert_eq!(first, repeated);
        assert_eq!(first.task_type, "software_development");
        assert_eq!(first.task_family, "debugging");
        assert!(first.capability_tags.contains(&"coding".to_string()));
        assert!(first.capability_tags.contains(&"verification".to_string()));

        let chinese = derive_task_signature("调研长周期智能体的最新资料", "interactive");
        assert_eq!(chinese.task_type, "information_retrieval");
        assert_eq!(chinese.task_family, "research");
        assert_ne!(first.signature_hash, chinese.signature_hash);
    }

    #[test]
    fn wilson_utility_lower_bound_is_conservative_and_monotonic() {
        let three_of_three = wilson_lower_bound(3, 3, 1.96);
        let four_of_four = wilson_lower_bound(4, 4, 1.96);
        assert!(three_of_three > 0.4 && three_of_three < 0.5);
        assert!(four_of_four > 0.5);
        assert!(four_of_four > three_of_three);
        assert_eq!(wilson_lower_bound(0, 0, 1.96), 0.0);
    }

    #[test]
    fn utility_lower_bound_gates_promotion_and_summaries_are_task_stratified() {
        let (db, dir) = test_db();
        db.register_skill_version("bounded", 1, "instructions", "agent-created")
            .unwrap();
        let mut policy = db.get_skill_governance_policy().unwrap();
        policy.trial_promote_rate = 0.6;
        policy.trial_promote_utility_lower_bound = 0.5;
        db.update_skill_governance_policy(&policy).unwrap();

        for index in 0..3 {
            let run_id = format!("bounded-pass-{index}");
            db.start_experience_run(
                &run_id,
                None,
                61,
                "web",
                "interactive",
                "deploy service safely",
                Some("env=prod"),
            )
            .unwrap();
            db.log_skill_activation("bounded", 61).unwrap();
            db.record_verifier_result(
                &run_id,
                "deterministic",
                "check",
                "passed",
                1.0,
                None,
                None,
                None,
            )
            .unwrap();
            db.finish_experience_run(&run_id, "completed", None, 1)
                .unwrap();
        }
        assert_eq!(
            db.get_skill_lifecycle("bounded").unwrap().unwrap().state,
            "trial",
            "three perfect samples remain too uncertain at z=1.96"
        );

        db.start_experience_run(
            "bounded-pass-3",
            None,
            61,
            "web",
            "interactive",
            "deploy service safely",
            Some("env=prod"),
        )
        .unwrap();
        db.log_skill_activation("bounded", 61).unwrap();
        db.record_verifier_result(
            "bounded-pass-3",
            "deterministic",
            "check",
            "passed",
            1.0,
            None,
            None,
            None,
        )
        .unwrap();
        db.finish_experience_run("bounded-pass-3", "completed", None, 1)
            .unwrap();
        assert_eq!(
            db.get_skill_lifecycle("bounded").unwrap().unwrap().state,
            "trusted"
        );

        let summaries = db
            .get_skill_task_utility_summaries(Some("bounded"))
            .unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].task_family, "deployment");
        assert_eq!(summaries[0].total_outcomes, 4);
        assert!(summaries[0].utility_lower_bound > 0.5);
        cleanup(&dir);
    }

    #[test]
    fn migration_38_backfills_task_signatures() {
        let (db, dir) = test_db();
        db.start_experience_run(
            "pre-v38-run",
            None,
            62,
            "web",
            "interactive",
            "debug Rust build failure",
            None,
        )
        .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute(
                "UPDATE experience_runs SET task_type='general',
                    task_family='general_assistance', capability_tags_json='[]',
                    task_signature_hash='' WHERE run_id='pre-v38-run'",
                [],
            )
            .unwrap();
            set_schema_version(&conn, 37).unwrap();
            apply_schema_migrations(&conn).unwrap();
        }
        let run = db
            .get_experience_run_detail("pre-v38-run")
            .unwrap()
            .unwrap()
            .run;
        assert_eq!(run.task_signature.task_family, "debugging");
        assert!(!run.task_signature.signature_hash.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn learning_tracks_are_scoped_claimed_and_candidate_gated() {
        let (db, dir) = test_db();
        let track_id = db
            .create_learning_track(
                77,
                "rust-reliability",
                "Learn repeatable Rust runtime reliability procedures",
                &serde_json::json!(["recovery", "verification"]),
                &serde_json::json!(["doc.rust-lang.org"]),
                "0 0 3 * * *",
                "UTC",
                80_000,
                10,
                "propose",
                "2026-01-01T00:00:00Z",
            )
            .unwrap();
        assert!(db.learning_track_belongs_to_chat(&track_id, 77).unwrap());
        assert!(!db.learning_track_belongs_to_chat(&track_id, 78).unwrap());
        let claimed = db
            .claim_due_learning_tracks(
                "2026-01-02T00:00:00Z",
                &[(track_id.clone(), "2026-01-03T00:00:00Z".into())],
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(db
            .claim_due_learning_tracks(
                "2026-01-02T00:00:00Z",
                &[(track_id.clone(), "2026-01-03T00:00:00Z".into())],
            )
            .unwrap()
            .is_empty());

        let epoch_id = db.start_learning_epoch(&track_id, "experience-77").unwrap();
        let candidate_id = db
            .create_learning_track_candidate(
                &epoch_id,
                "rust-recovery",
                "Use when diagnosing recoverable Rust runtime failures",
                "# Procedure\n\n1. Reproduce.\n2. Verify.",
                &serde_json::json!([{"url": "https://doc.rust-lang.org"}]),
                &serde_json::json!([{"name": "replay", "expected": "passes"}]),
                "low",
            )
            .unwrap();
        db.finish_learning_epoch(
            &epoch_id,
            "completed",
            Some("source-backed report"),
            Some(&candidate_id),
            None,
        )
        .unwrap();
        let candidates = db.list_learning_track_candidates(77, 10).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].status, "pending");

        let evaluation_id = db
            .start_learning_candidate_evaluation(&candidate_id)
            .unwrap();
        for index in 0..3 {
            db.record_learning_candidate_trial(
                &evaluation_id,
                &format!("scenario-{index}"),
                index == 0,
                true,
                100,
                90,
                10,
                9,
                &serde_json::json!({"judge_reason": "candidate meets criterion"}),
            )
            .unwrap();
        }
        let evaluation = db
            .finish_learning_candidate_evaluation(
                &evaluation_id,
                true,
                "candidate improves baseline without regressions",
            )
            .unwrap();
        assert_eq!(evaluation.status, "passed");
        assert_eq!(evaluation.sample_count, 3);
        assert_eq!(evaluation.baseline_passed, 1);
        assert_eq!(evaluation.candidate_passed, 3);
        assert_eq!(evaluation.regression_count, 0);
        assert_eq!(
            db.list_learning_candidate_trials(&evaluation_id)
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            db.list_learning_track_candidates(77, 10).unwrap()[0].status,
            "evaluation_passed"
        );
        assert!(db
            .update_learning_track_candidate_status(&candidate_id, "promoted")
            .unwrap());
        cleanup(&dir);
    }
}
