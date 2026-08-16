use super::*;

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
}

#[cfg(test)]
mod tests {
    use crate::db::test_support::*;

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
