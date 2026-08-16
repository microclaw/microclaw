use super::*;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillActivationRecord {
    pub skill_name: String,
    pub skill_version: Option<i64>,
    pub activated_at: String,
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
}
