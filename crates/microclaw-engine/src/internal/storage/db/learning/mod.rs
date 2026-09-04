use super::*;

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

pub mod experience;
pub mod skills;
pub mod tracks;

pub use self::experience::*;
pub use self::skills::*;
pub use self::tracks::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::storage::db::test_support::*;

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
    fn wilson_utility_lower_bound_is_conservative_and_monotonic() {
        let three_of_three = wilson_lower_bound(3, 3, 1.96);
        let four_of_four = wilson_lower_bound(4, 4, 1.96);
        assert!(three_of_three > 0.4 && three_of_three < 0.5);
        assert!(four_of_four > 0.5);
        assert!(four_of_four > three_of_three);
        assert_eq!(wilson_lower_bound(0, 0, 1.96), 0.0);
    }
}
