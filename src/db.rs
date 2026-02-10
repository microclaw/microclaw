use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

use crate::error::MicroClawError;

pub struct Database {
    conn: Mutex<Connection>,
}

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
    pub chat_type: String,
    pub last_message_time: String,
    pub last_message_preview: Option<String>,
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

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScheduledTask {
    pub id: i64,
    pub chat_id: i64,
    pub prompt: String,
    pub schedule_type: String,  // "cron" or "once"
    pub schedule_value: String, // cron expression or ISO timestamp
    pub next_run: String,       // ISO timestamp
    pub last_run: Option<String>,
    pub status: String, // "active", "paused", "completed", "cancelled"
    pub created_at: String,
}

impl Database {
    pub fn new(data_dir: &str) -> Result<Self, MicroClawError> {
        let db_path = Path::new(data_dir).join("microclaw.db");
        std::fs::create_dir_all(data_dir)?;

        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
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
                next_run TEXT NOT NULL,
                last_run TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
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

            CREATE TABLE IF NOT EXISTS sessions (
                chat_id INTEGER PRIMARY KEY,
                messages_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;

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
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO chats (chat_id, chat_title, chat_type, last_message_time)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chat_id) DO UPDATE SET
                chat_title = COALESCE(?2, chat_title),
                last_message_time = ?4",
            params![chat_id, chat_title, chat_type, now],
        )?;
        Ok(())
    }

    pub fn store_message(&self, msg: &StoredMessage) -> Result<(), MicroClawError> {
        let conn = self.conn.lock().unwrap();
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

    pub fn get_recent_messages(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT
                c.chat_id,
                c.chat_title,
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
             WHERE c.chat_type = ?1
             ORDER BY c.last_message_time DESC
             LIMIT ?2",
        )?;
        let chats = stmt
            .query_map(params![chat_type, limit as i64], |row| {
                Ok(ChatSummary {
                    chat_id: row.get(0)?,
                    chat_title: row.get(1)?,
                    chat_type: row.get(2)?,
                    last_message_time: row.get(3)?,
                    last_message_preview: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(chats)
    }

    pub fn get_chat_type(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
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

    /// Get messages since the bot's last response in this chat.
    /// Falls back to `fallback_limit` most recent messages if bot never responded.
    pub fn get_messages_since_last_bot_response(
        &self,
        chat_id: i64,
        max: usize,
        fallback: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.conn.lock().unwrap();

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
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO scheduled_tasks (chat_id, prompt, schedule_type, schedule_value, next_run, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)",
            params![chat_id, prompt, schedule_type, schedule_value, next_run, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_due_tasks(&self, now: &str) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, next_run, last_run, status, created_at
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
                    next_run: row.get(5)?,
                    last_run: row.get(6)?,
                    status: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tasks)
    }

    pub fn get_tasks_for_chat(&self, chat_id: i64) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, next_run, last_run, status, created_at
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
                    next_run: row.get(5)?,
                    last_run: row.get(6)?,
                    status: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tasks)
    }

    pub fn get_task_by_id(&self, task_id: i64) -> Result<Option<ScheduledTask>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT id, chat_id, prompt, schedule_type, schedule_value, next_run, last_run, status, created_at
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
                    next_run: row.get(5)?,
                    last_run: row.get(6)?,
                    status: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        );
        match result {
            Ok(task) => Ok(Some(task)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn update_task_status(&self, task_id: i64, status: &str) -> Result<bool, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE scheduled_tasks SET status = ?1 WHERE id = ?2",
            params![status, task_id],
        )?;
        Ok(rows > 0)
    }

    pub fn update_task_after_run(
        &self,
        task_id: i64,
        last_run: &str,
        next_run: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.conn.lock().unwrap();
        match next_run {
            Some(next) => {
                conn.execute(
                    "UPDATE scheduled_tasks SET last_run = ?1, next_run = ?2 WHERE id = ?3",
                    params![last_run, next, task_id],
                )?;
            }
            None => {
                // One-shot task, mark completed
                conn.execute(
                    "UPDATE scheduled_tasks SET last_run = ?1, status = 'completed' WHERE id = ?2",
                    params![last_run, task_id],
                )?;
            }
        }
        Ok(())
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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

    #[allow(dead_code)]
    pub fn delete_task(&self, task_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM scheduled_tasks WHERE id = ?1",
            params![task_id],
        )?;
        Ok(rows > 0)
    }

    // --- Sessions ---

    pub fn save_session(&self, chat_id: i64, messages_json: &str) -> Result<(), MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (chat_id, messages_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(chat_id) DO UPDATE SET
                messages_json = ?2,
                updated_at = ?3",
            params![chat_id, messages_json, now],
        )?;
        Ok(())
    }

    pub fn load_session(&self, chat_id: i64) -> Result<Option<(String, String)>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
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

    pub fn delete_session(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        Ok(rows > 0)
    }

    pub fn delete_chat_data(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;

        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM scheduled_tasks WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM chats WHERE chat_id = ?1", params![chat_id])?;

        tx.commit()?;
        Ok(affected > 0)
    }

    pub fn get_new_user_messages_since(
        &self,
        chat_id: i64,
        since: &str,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.conn.lock().unwrap();
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
    fn test_update_task_after_run_cron() {
        let (db, dir) = test_db();
        let id = db
            .create_scheduled_task(100, "test", "cron", "0 * * * * *", "2024-01-01T00:00:00Z")
            .unwrap();

        db.update_task_after_run(id, "2024-01-01T00:01:00Z", Some("2024-01-01T00:02:00Z"))
            .unwrap();

        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert_eq!(tasks[0].last_run.as_deref(), Some("2024-01-01T00:01:00Z"));
        assert_eq!(tasks[0].next_run, "2024-01-01T00:02:00Z");
        assert_eq!(tasks[0].status, "active");
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

        // One-shot: no next_run, should mark as completed
        db.update_task_after_run(id, "2024-01-01T00:00:00Z", None)
            .unwrap();

        // Should not appear in active/paused list
        let tasks = db.get_tasks_for_chat(100).unwrap();
        assert!(tasks.is_empty());
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
}
