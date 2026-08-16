use super::*;

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

impl Database {
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

    /// Exact depth of the scheduled-task dead-letter queue (unlike
    /// `list_scheduled_task_dlq`, this is not clamped by a LIMIT).
    pub fn count_scheduled_task_dlq(&self, include_replayed: bool) -> Result<i64, MicroClawError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::*;

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
}
