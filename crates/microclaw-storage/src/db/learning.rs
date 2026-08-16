use super::*;

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

pub(crate) fn map_learning_track(row: &rusqlite::Row<'_>) -> rusqlite::Result<LearningTrack> {
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

pub(crate) fn verifier_priority(verifier_type: &str) -> i64 {
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

pub(crate) type VerifierCandidate = (String, String, String, f64, Option<String>, Option<String>);

pub(crate) fn verifier_can_govern_skill(verifier_type: &str) -> bool {
    matches!(
        verifier_type,
        "deterministic" | "environmental" | "human" | "rule_based"
    )
}

pub(crate) fn validate_outcome_envelope(
    envelope: &OutcomeEnvelopeV1,
) -> Result<(), MicroClawError> {
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

pub(crate) fn validate_skill_governance_policy(
    policy: &SkillGovernancePolicy,
) -> Result<(), MicroClawError> {
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

pub(crate) fn sync_skill_outcomes_for_run(
    tx: &Transaction<'_>,
    run_id: &str,
) -> Result<(), MicroClawError> {
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

pub(crate) fn classify_failure_category(evidence: Option<&str>) -> &'static str {
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

pub(crate) fn sync_skill_failure_patterns_for_run(
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

pub(crate) fn map_shadow_evaluation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShadowEvaluation> {
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

pub(crate) fn recompute_shadow_evaluation(
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

pub(crate) type ComparativeCurrentRun = (
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

pub(crate) type ComparativePeerRun = (
    String,
    Option<String>,
    i64,
    i64,
    i64,
    Option<f64>,
    Option<String>,
);

pub(crate) fn refresh_comparative_reflections_for_run(
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

pub(crate) fn refresh_expired_skill_outcomes(tx: &Transaction<'_>) -> Result<(), MicroClawError> {
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

pub(crate) fn erase_chat_learning(
    tx: &Transaction<'_>,
    chat_id: i64,
) -> Result<usize, MicroClawError> {
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

pub(crate) fn evaluate_skill_lifecycle(
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

pub(crate) fn recompute_skill_lifecycle(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::*;

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
