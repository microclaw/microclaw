use super::*;

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

impl Database {
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
    use crate::db::test_support::*;

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
        db.append_subagent_event("run-3", "submit_result", None)
            .unwrap();

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
}
