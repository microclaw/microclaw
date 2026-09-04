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

impl Database {
    pub(crate) fn lock_conn(&self) -> MutexGuard<'_, Connection> {
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
}

pub mod audit;
pub mod auth;
pub mod chats;
pub mod learning;
pub mod memory;
pub mod meta;
pub mod outbox;
pub mod schema;
pub mod sessions;
pub mod subagents;
pub mod tasks;
#[cfg(test)]
pub(crate) mod test_support;
pub mod tool_cache;
pub mod turns;
pub mod usage;

pub use self::audit::*;
pub use self::auth::*;
pub use self::chats::*;
pub use self::learning::*;
pub use self::memory::*;
pub use self::meta::*;
pub use self::outbox::*;
pub(crate) use self::schema::*;
pub use self::sessions::*;
pub use self::subagents::*;
pub use self::tasks::*;
pub use self::tool_cache::*;
pub use self::turns::*;
pub use self::usage::*;
