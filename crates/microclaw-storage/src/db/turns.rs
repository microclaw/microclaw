use super::*;

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

pub(crate) fn map_interrupted_turn(row: &rusqlite::Row<'_>) -> rusqlite::Result<InterruptedTurn> {
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

impl Database {
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
}

#[cfg(test)]
mod tests {
    use crate::db::test_support::*;

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
}
