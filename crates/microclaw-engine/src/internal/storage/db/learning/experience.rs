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

impl Database {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::storage::db::test_support::*;

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
}
