use rusqlite::OptionalExtension;
use rusqlite::{params, Connection};
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
pub struct LlmUsageSummary {
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub last_request_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LlmModelUsageSummary {
    pub model: String,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
}

#[derive(Debug, Clone)]
pub struct Memory {
    pub id: i64,
    pub chat_id: Option<i64>,
    pub content: String,
    pub category: String,
    pub created_at: String,
    pub updated_at: String,
    pub embedding_model: Option<String>,
    pub confidence: f64,
    pub source: String,
    pub last_seen_at: String,
    pub is_archived: bool,
    pub archived_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryObservabilitySummary {
    pub total: i64,
    pub active: i64,
    pub archived: i64,
    pub low_confidence: i64,
    pub avg_confidence: f64,
    pub reflector_runs_24h: i64,
    pub reflector_inserted_24h: i64,
    pub reflector_updated_24h: i64,
    pub reflector_skipped_24h: i64,
    pub injection_events_24h: i64,
    pub injection_selected_24h: i64,
    pub injection_candidates_24h: i64,
}

#[derive(Debug, Clone)]
pub struct MemoryReflectorRun {
    pub id: i64,
    pub chat_id: i64,
    pub started_at: String,
    pub finished_at: String,
    pub extracted_count: i64,
    pub inserted_count: i64,
    pub updated_count: i64,
    pub skipped_count: i64,
    pub dedup_method: String,
    pub parse_ok: bool,
    pub error_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryInjectionLog {
    pub id: i64,
    pub chat_id: i64,
    pub created_at: String,
    pub retrieval_method: String,
    pub candidate_count: i64,
    pub selected_count: i64,
    pub omitted_count: i64,
    pub tokens_est: i64,
}

#[derive(Debug, Clone)]
pub struct AuthApiKeyRecord {
    pub id: i64,
    pub label: String,
    pub prefix: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub rotated_from_key_id: Option<i64>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MetricsHistoryPoint {
    pub timestamp_ms: i64,
    pub llm_completions: i64,
    pub llm_input_tokens: i64,
    pub llm_output_tokens: i64,
    pub http_requests: i64,
    pub tool_executions: i64,
    pub mcp_calls: i64,
    pub mcp_rate_limited_rejections: i64,
    pub mcp_bulkhead_rejections: i64,
    pub mcp_circuit_open_rejections: i64,
    pub active_sessions: i64,
}

#[derive(Debug, Clone)]
pub struct AuditLogRecord {
    pub id: i64,
    pub kind: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub status: String,
    pub detail: Option<String>,
    pub created_at: String,
}

pub type SessionMetaRow = (String, String, Option<String>, Option<i64>);
pub type SessionTreeRow = (i64, Option<String>, Option<i64>, String);

const SCHEMA_VERSION_CURRENT: i64 = 10;

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

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, MicroClawError> {
    // Validate table name to prevent SQL injection via PRAGMA
    if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(MicroClawError::Config(format!(
            "invalid table name: {}",
            table
        )));
    }
    // PRAGMA does not support parameter binding, so format! is required here.
    // The table name validation above ensures only safe identifiers reach this point.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in rows {
        if col? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_memory_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "memories", "embedding_model")? {
        conn.execute("ALTER TABLE memories ADD COLUMN embedding_model TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "chat_channel")? {
        conn.execute("ALTER TABLE memories ADD COLUMN chat_channel TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "external_chat_id")? {
        conn.execute("ALTER TABLE memories ADD COLUMN external_chat_id TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "confidence")? {
        conn.execute("ALTER TABLE memories ADD COLUMN confidence REAL", [])?;
    }
    if !table_has_column(conn, "memories", "source")? {
        conn.execute("ALTER TABLE memories ADD COLUMN source TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "last_seen_at")? {
        conn.execute("ALTER TABLE memories ADD COLUMN last_seen_at TEXT", [])?;
    }
    if !table_has_column(conn, "memories", "is_archived")? {
        conn.execute("ALTER TABLE memories ADD COLUMN is_archived INTEGER", [])?;
    }
    if !table_has_column(conn, "memories", "archived_at")? {
        conn.execute("ALTER TABLE memories ADD COLUMN archived_at TEXT", [])?;
    }
    conn.execute(
        "UPDATE memories
         SET confidence = COALESCE(confidence, 0.70),
             source = COALESCE(NULLIF(source, ''), 'legacy'),
             last_seen_at = COALESCE(last_seen_at, updated_at, created_at),
             is_archived = COALESCE(is_archived, 0)
         WHERE confidence IS NULL
            OR source IS NULL OR trim(source) = ''
            OR last_seen_at IS NULL
            OR is_archived IS NULL",
        [],
    )?;
    let chats_has_channel = table_has_column(conn, "chats", "channel")?;
    let chats_has_external = table_has_column(conn, "chats", "external_chat_id")?;
    if chats_has_channel && chats_has_external {
        conn.execute(
            "UPDATE memories
             SET chat_channel = (
                     SELECT c.channel FROM chats c WHERE c.chat_id = memories.chat_id
                 ),
                 external_chat_id = (
                     SELECT c.external_chat_id FROM chats c WHERE c.chat_id = memories.chat_id
                 )
             WHERE chat_id IS NOT NULL
               AND (
                   chat_channel IS NULL
                   OR trim(chat_channel) = ''
                   OR external_chat_id IS NULL
                   OR trim(external_chat_id) = ''
               )",
            [],
        )?;
    }
    Ok(())
}

fn infer_channel_from_chat_type(chat_type: &str) -> &'static str {
    if chat_type.starts_with("telegram_")
        || matches!(chat_type, "private" | "group" | "supergroup" | "channel")
    {
        "telegram"
    } else if chat_type == "discord" {
        "discord"
    } else if chat_type == "web" {
        "web"
    } else {
        "unknown"
    }
}

fn ensure_chat_identity_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "chats", "channel")? {
        conn.execute("ALTER TABLE chats ADD COLUMN channel TEXT", [])?;
    }
    if !table_has_column(conn, "chats", "external_chat_id")? {
        conn.execute("ALTER TABLE chats ADD COLUMN external_chat_id TEXT", [])?;
    }

    conn.execute(
        "UPDATE chats
         SET channel = CASE
             WHEN chat_type LIKE 'telegram_%' THEN 'telegram'
             WHEN chat_type IN ('private', 'group', 'supergroup', 'channel') THEN 'telegram'
             WHEN chat_type = 'discord' THEN 'discord'
             WHEN chat_type = 'web' THEN 'web'
             ELSE COALESCE(channel, 'unknown')
         END
         WHERE channel IS NULL OR trim(channel) = ''",
        [],
    )?;
    conn.execute(
        "UPDATE chats
         SET external_chat_id = CAST(chat_id AS TEXT)
         WHERE external_chat_id IS NULL OR trim(external_chat_id) = ''",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chats_channel_external
         ON chats(channel, external_chat_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chats_channel_title
         ON chats(channel, chat_title)",
        [],
    )?;
    Ok(())
}

fn ensure_sessions_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "sessions", "parent_session_key")? {
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN parent_session_key TEXT",
            [],
        )?;
    }
    if !table_has_column(conn, "sessions", "fork_point")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN fork_point INTEGER", [])?;
    }
    if table_has_column(conn, "sessions", "parent_session_key")? {
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_parent_session_key
             ON sessions(parent_session_key)",
            [],
        )?;
    }
    Ok(())
}

fn get_schema_version(conn: &Connection) -> Result<i64, MicroClawError> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )?;
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM db_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0))
}

fn set_schema_version(conn: &Connection, version: i64) -> Result<(), MicroClawError> {
    conn.execute(
        "INSERT INTO db_meta(key, value) VALUES('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![version.to_string()],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            note TEXT
        )",
        [],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO schema_migrations(version, applied_at, note)
         VALUES(?1, ?2, ?3)",
        params![version, chrono::Utc::now().to_rfc3339(), "applied"],
    )?;
    Ok(())
}

fn apply_schema_migrations(conn: &Connection) -> Result<(), MicroClawError> {
    let mut version = get_schema_version(conn)?;
    if version < 1 {
        set_schema_version(conn, 1)?;
        version = 1;
    }
    if version < 2 {
        ensure_chat_identity_schema(conn)?;
        ensure_memory_schema(conn)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_active_updated ON memories(is_archived, updated_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_confidence ON memories(confidence)",
            [],
        )?;
        set_schema_version(conn, 2)?;
        version = 2;
    }
    if version < 3 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_reflector_runs (
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
                ON memory_injection_logs(chat_id, created_at);",
        )?;
        set_schema_version(conn, 3)?;
        version = 3;
    }
    if version < 4 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_supersede_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_memory_id INTEGER NOT NULL,
                to_memory_id INTEGER NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_memory_supersede_from
                ON memory_supersede_edges(from_memory_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_memory_supersede_to
                ON memory_supersede_edges(to_memory_id, created_at);",
        )?;
        set_schema_version(conn, 4)?;
        version = 4;
    }
    if version < 5 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS auth_passwords (
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
            CREATE INDEX IF NOT EXISTS idx_api_key_scopes_scope ON api_key_scopes(scope);",
        )?;
        set_schema_version(conn, 5)?;
        version = 5;
    }
    if version < 6 {
        ensure_sessions_schema(conn)?;
        set_schema_version(conn, 6)?;
        version = 6;
    }
    if version < 7 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metrics_history (
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
            CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp_ms);",
        )?;
        set_schema_version(conn, 7)?;
        version = 7;
    }
    if version < 8 {
        if !table_has_column(conn, "api_keys", "expires_at")? {
            conn.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT", [])?;
        }
        if !table_has_column(conn, "api_keys", "rotated_from_key_id")? {
            conn.execute(
                "ALTER TABLE api_keys ADD COLUMN rotated_from_key_id INTEGER",
                [],
            )?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_logs (
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
                ON audit_logs(kind, created_at DESC);",
        )?;
        set_schema_version(conn, 8)?;
        version = 8;
    }
    if version < 9 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scheduled_task_dlq (
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
                ON scheduled_task_dlq(chat_id, failed_at DESC);",
        )?;
        set_schema_version(conn, 9)?;
        version = 9;
    }
    if version < 10 {
        if !table_has_column(conn, "metrics_history", "mcp_rate_limited_rejections")? {
            conn.execute(
                "ALTER TABLE metrics_history ADD COLUMN mcp_rate_limited_rejections INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "metrics_history", "mcp_bulkhead_rejections")? {
            conn.execute(
                "ALTER TABLE metrics_history ADD COLUMN mcp_bulkhead_rejections INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "metrics_history", "mcp_circuit_open_rejections")? {
            conn.execute(
                "ALTER TABLE metrics_history ADD COLUMN mcp_circuit_open_rejections INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        set_schema_version(conn, 10)?;
        version = 10;
    }
    if version != SCHEMA_VERSION_CURRENT {
        set_schema_version(conn, SCHEMA_VERSION_CURRENT)?;
    }
    Ok(())
}

impl Database {
    fn lock_conn(&self) -> MutexGuard<'_, Connection> {
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
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

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
        conn.execute(
            "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )?;
        apply_schema_migrations(&conn)?;

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
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO chats (chat_id, chat_title, chat_type, last_message_time, channel, external_chat_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
                chat_title = COALESCE(?2, chat_title),
                chat_type = ?3,
                last_message_time = ?4,
                channel = COALESCE(?5, channel),
                external_chat_id = COALESCE(external_chat_id, ?6)",
            params![
                chat_id,
                chat_title,
                chat_type,
                now,
                infer_channel_from_chat_type(chat_type),
                chat_id.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn resolve_or_create_chat_id(
        &self,
        channel: &str,
        external_chat_id: &str,
        chat_title: Option<&str>,
        chat_type: &str,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();

        if let Some(chat_id) = conn
            .query_row(
                "SELECT chat_id FROM chats WHERE channel = ?1 AND external_chat_id = ?2 LIMIT 1",
                params![channel, external_chat_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            conn.execute(
                "UPDATE chats
                 SET chat_title = COALESCE(?2, chat_title),
                     chat_type = ?3,
                     last_message_time = ?4
                 WHERE chat_id = ?1",
                params![chat_id, chat_title, chat_type, now],
            )?;
            return Ok(chat_id);
        }

        let preferred_chat_id = external_chat_id.parse::<i64>().ok();
        if let Some(cid) = preferred_chat_id {
            let occupied = conn
                .query_row(
                    "SELECT 1 FROM chats WHERE chat_id = ?1 LIMIT 1",
                    params![cid],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !occupied {
                conn.execute(
                    "INSERT INTO chats(chat_id, chat_title, chat_type, last_message_time, channel, external_chat_id)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![cid, chat_title, chat_type, now, channel, external_chat_id],
                )?;
                return Ok(cid);
            }
        }

        conn.execute(
            "INSERT INTO chats(chat_title, chat_type, last_message_time, channel, external_chat_id)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![chat_title, chat_type, now, channel, external_chat_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn store_message(&self, msg: &StoredMessage) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
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
        let conn = self.lock_conn();
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
        let conn = self.lock_conn();
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
        let conn = self.lock_conn();
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

    pub fn get_recent_chats(&self, limit: usize) -> Result<Vec<ChatSummary>, MicroClawError> {
        let conn = self.lock_conn();
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
             ORDER BY c.last_message_time DESC
             LIMIT ?1",
        )?;
        let chats = stmt
            .query_map(params![limit as i64], |row| {
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
        let conn = self.lock_conn();
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

    pub fn get_chat_id_by_channel_and_title(
        &self,
        channel: &str,
        chat_title: &str,
    ) -> Result<Option<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT chat_id
             FROM chats
             WHERE channel = ?1 AND chat_title = ?2
             ORDER BY last_message_time DESC
             LIMIT 1",
            params![channel, chat_title],
            |row| row.get::<_, i64>(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_chat_channel(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT channel FROM chats WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, Option<String>>(0),
        );
        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_chat_external_id(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT external_chat_id FROM chats WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, Option<String>>(0),
        );
        match result {
            Ok(v) => Ok(v),
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
        let conn = self.lock_conn();

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
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO scheduled_tasks (chat_id, prompt, schedule_type, schedule_value, next_run, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)",
            params![chat_id, prompt, schedule_type, schedule_value, next_run, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_due_tasks(&self, now: &str) -> Result<Vec<ScheduledTask>, MicroClawError> {
        let conn = self.lock_conn();
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
        let conn = self.lock_conn();
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
        let conn = self.lock_conn();
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
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
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

    pub fn save_session(&self, chat_id: i64, messages_json: &str) -> Result<(), MicroClawError> {
        self.save_session_with_meta(chat_id, messages_json, None, None)
    }

    pub fn save_session_with_meta(
        &self,
        chat_id: i64,
        messages_json: &str,
        parent_session_key: Option<&str>,
        fork_point: Option<i64>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (chat_id, messages_json, updated_at, parent_session_key, fork_point)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(chat_id) DO UPDATE SET
                messages_json = ?2,
                updated_at = ?3,
                parent_session_key = COALESCE(?4, parent_session_key),
                fork_point = COALESCE(?5, fork_point)",
            params![chat_id, messages_json, now, parent_session_key, fork_point],
        )?;
        Ok(())
    }

    pub fn load_session(&self, chat_id: i64) -> Result<Option<(String, String)>, MicroClawError> {
        let conn = self.lock_conn();
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

    pub fn load_session_meta(
        &self,
        chat_id: i64,
    ) -> Result<Option<SessionMetaRow>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT messages_json, updated_at, parent_session_key, fork_point
             FROM sessions WHERE chat_id = ?1",
            params![chat_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_session_meta(&self, limit: usize) -> Result<Vec<SessionTreeRow>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT chat_id, parent_session_key, fork_point, updated_at
             FROM sessions
             ORDER BY updated_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_session(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        Ok(rows > 0)
    }

    /// Clear conversational context for a chat without deleting chat metadata or memories.
    /// This removes resumable session state and historical messages used to rebuild context.
    pub fn clear_chat_context(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;
        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    pub fn delete_chat_data(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;

        affected += tx.execute(
            "DELETE FROM llm_usage_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute(
            "DELETE FROM scheduled_tasks WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_reflector_state WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_reflector_runs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_injection_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM memory_supersede_edges
             WHERE from_memory_id IN (SELECT id FROM memories WHERE chat_id = ?1)
                OR to_memory_id IN (SELECT id FROM memories WHERE chat_id = ?1)",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM memories WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM chats WHERE chat_id = ?1", params![chat_id])?;

        tx.commit()?;
        Ok(affected > 0)
    }

    // --- Auth: password/session/api-key ---

    pub fn upsert_auth_password_hash(&self, password_hash: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO auth_passwords(id, password_hash, created_at, updated_at)
             VALUES(1, ?1, ?2, ?2)
             ON CONFLICT(id) DO UPDATE SET
                password_hash = excluded.password_hash,
                updated_at = excluded.updated_at",
            params![password_hash, now],
        )?;
        Ok(())
    }

    pub fn get_auth_password_hash(&self) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let value = conn
            .query_row(
                "SELECT password_hash FROM auth_passwords WHERE id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn clear_auth_password_hash(&self) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute("DELETE FROM auth_passwords WHERE id = 1", [])?;
        Ok(rows > 0)
    }

    pub fn create_auth_session(
        &self,
        session_id: &str,
        label: Option<&str>,
        expires_at: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO auth_sessions(session_id, label, created_at, expires_at, last_seen_at, revoked_at)
             VALUES(?1, ?2, ?3, ?4, ?3, NULL)",
            params![session_id, label, now, expires_at],
        )?;
        Ok(())
    }

    pub fn validate_auth_session(&self, session_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let valid = conn
            .query_row(
                "SELECT 1
                 FROM auth_sessions
                 WHERE session_id = ?1
                   AND revoked_at IS NULL
                   AND expires_at > ?2
                 LIMIT 1",
                params![session_id, now],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if valid {
            let _ = conn.execute(
                "UPDATE auth_sessions SET last_seen_at = ?2 WHERE session_id = ?1",
                params![session_id, now],
            );
        }
        Ok(valid)
    }

    pub fn revoke_auth_session(&self, session_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE session_id = ?1",
            params![session_id, now],
        )?;
        Ok(rows > 0)
    }

    pub fn revoke_all_auth_sessions(&self) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?1)
             WHERE revoked_at IS NULL",
            params![now],
        )?;
        Ok(rows)
    }

    pub fn create_api_key(
        &self,
        label: &str,
        key_hash: &str,
        prefix: &str,
        scopes: &[String],
        expires_at: Option<&str>,
        rotated_from_key_id: Option<i64>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO api_keys(label, key_hash, prefix, created_at, expires_at, rotated_from_key_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![label, key_hash, prefix, now, expires_at, rotated_from_key_id],
        )?;
        let key_id = tx.last_insert_rowid();
        for scope in scopes {
            tx.execute(
                "INSERT OR IGNORE INTO api_key_scopes(api_key_id, scope) VALUES(?1, ?2)",
                params![key_id, scope],
            )?;
        }
        tx.commit()?;
        Ok(key_id)
    }

    pub fn list_api_keys(&self) -> Result<Vec<AuthApiKeyRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, label, prefix, created_at, revoked_at, expires_at, last_used_at, rotated_from_key_id
             FROM api_keys
             ORDER BY id DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let mut scopes_stmt = conn.prepare(
                "SELECT scope FROM api_key_scopes WHERE api_key_id = ?1 ORDER BY scope ASC",
            )?;
            let scopes = scopes_stmt
                .query_map(params![id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            out.push(AuthApiKeyRecord {
                id,
                label: row.get(1)?,
                prefix: row.get(2)?,
                created_at: row.get(3)?,
                revoked_at: row.get(4)?,
                expires_at: row.get(5)?,
                last_used_at: row.get(6)?,
                rotated_from_key_id: row.get(7)?,
                scopes,
            });
        }
        Ok(out)
    }

    pub fn rotate_api_key_revoke_old(&self, old_key_id: i64) -> Result<bool, MicroClawError> {
        self.revoke_api_key(old_key_id)
    }

    pub fn revoke_api_key(&self, key_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE api_keys
             SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE id = ?1",
            params![key_id, now],
        )?;
        Ok(rows > 0)
    }

    pub fn validate_api_key_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<(i64, Vec<String>)>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id FROM api_keys
                 WHERE key_hash = ?1
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?2)
                 LIMIT 1",
                params![key_hash, chrono::Utc::now().to_rfc3339()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        let Some(key_id) = row else {
            return Ok(None);
        };
        let now = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE api_keys SET last_used_at = ?2 WHERE id = ?1",
            params![key_id, now],
        );
        let mut stmt = conn
            .prepare("SELECT scope FROM api_key_scopes WHERE api_key_id = ?1 ORDER BY scope ASC")?;
        let scopes = stmt
            .query_map(params![key_id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some((key_id, scopes)))
    }

    pub fn log_audit_event(
        &self,
        kind: &str,
        actor: &str,
        action: &str,
        target: Option<&str>,
        status: &str,
        detail: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO audit_logs(kind, actor, action, target, status, detail, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![kind, actor, action, target, status, detail, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_audit_logs(
        &self,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditLogRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut rows = Vec::new();
        if let Some(k) = kind {
            let mut stmt = conn.prepare(
                "SELECT id, kind, actor, action, target, status, detail, created_at
                 FROM audit_logs
                 WHERE kind = ?1
                 ORDER BY id DESC
                 LIMIT ?2",
            )?;
            let iter = stmt.query_map(params![k, limit as i64], |row| {
                Ok(AuditLogRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    status: row.get(5)?,
                    detail: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?;
            for item in iter {
                rows.push(item?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, kind, actor, action, target, status, detail, created_at
                 FROM audit_logs
                 ORDER BY id DESC
                 LIMIT ?1",
            )?;
            let iter = stmt.query_map(params![limit as i64], |row| {
                Ok(AuditLogRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    status: row.get(5)?,
                    detail: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?;
            for item in iter {
                rows.push(item?);
            }
        }
        Ok(rows)
    }

    // --- Metrics history ---

    pub fn upsert_metrics_history(
        &self,
        point: &MetricsHistoryPoint,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO metrics_history(
                timestamp_ms, llm_completions, llm_input_tokens, llm_output_tokens,
                http_requests, tool_executions, mcp_calls,
                mcp_rate_limited_rejections, mcp_bulkhead_rejections, mcp_circuit_open_rejections,
                active_sessions
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(timestamp_ms) DO UPDATE SET
                llm_completions = excluded.llm_completions,
                llm_input_tokens = excluded.llm_input_tokens,
                llm_output_tokens = excluded.llm_output_tokens,
                http_requests = excluded.http_requests,
                tool_executions = excluded.tool_executions,
                mcp_calls = excluded.mcp_calls,
                mcp_rate_limited_rejections = excluded.mcp_rate_limited_rejections,
                mcp_bulkhead_rejections = excluded.mcp_bulkhead_rejections,
                mcp_circuit_open_rejections = excluded.mcp_circuit_open_rejections,
                active_sessions = excluded.active_sessions",
            params![
                point.timestamp_ms,
                point.llm_completions,
                point.llm_input_tokens,
                point.llm_output_tokens,
                point.http_requests,
                point.tool_executions,
                point.mcp_calls,
                point.mcp_rate_limited_rejections,
                point.mcp_bulkhead_rejections,
                point.mcp_circuit_open_rejections,
                point.active_sessions
            ],
        )?;
        Ok(())
    }

    pub fn get_metrics_history(
        &self,
        since_ts_ms: i64,
        limit: usize,
    ) -> Result<Vec<MetricsHistoryPoint>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT
                timestamp_ms, llm_completions, llm_input_tokens, llm_output_tokens,
                http_requests, tool_executions, mcp_calls,
                mcp_rate_limited_rejections, mcp_bulkhead_rejections, mcp_circuit_open_rejections,
                active_sessions
             FROM metrics_history
             WHERE timestamp_ms >= ?1
             ORDER BY timestamp_ms ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![since_ts_ms, limit as i64], |row| {
                Ok(MetricsHistoryPoint {
                    timestamp_ms: row.get(0)?,
                    llm_completions: row.get(1)?,
                    llm_input_tokens: row.get(2)?,
                    llm_output_tokens: row.get(3)?,
                    http_requests: row.get(4)?,
                    tool_executions: row.get(5)?,
                    mcp_calls: row.get(6)?,
                    mcp_rate_limited_rejections: row.get(7)?,
                    mcp_bulkhead_rejections: row.get(8)?,
                    mcp_circuit_open_rejections: row.get(9)?,
                    active_sessions: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn cleanup_metrics_history_before(
        &self,
        before_ts_ms: i64,
    ) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM metrics_history WHERE timestamp_ms < ?1",
            params![before_ts_ms],
        )?;
        Ok(n)
    }

    pub fn get_new_user_messages_since(
        &self,
        chat_id: i64,
        since: &str,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();
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

    pub fn get_messages_since(
        &self,
        chat_id: i64,
        since: &str,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, sender_name, content, is_from_bot, timestamp
             FROM messages
             WHERE chat_id = ?1 AND timestamp > ?2
             ORDER BY timestamp ASC
             LIMIT ?3",
        )?;
        let messages = stmt
            .query_map(params![chat_id, since, limit as i64], |row| {
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

    pub fn get_reflector_cursor(&self, chat_id: i64) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT last_reflected_ts FROM memory_reflector_state WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(ts) => Ok(Some(ts)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_reflector_cursor(
        &self,
        chat_id: i64,
        last_reflected_ts: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memory_reflector_state (chat_id, last_reflected_ts, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(chat_id) DO UPDATE SET
                last_reflected_ts = excluded.last_reflected_ts,
                updated_at = excluded.updated_at",
            params![chat_id, last_reflected_ts, now],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_llm_usage(
        &self,
        chat_id: i64,
        caller_channel: &str,
        provider: &str,
        model: &str,
        input_tokens: i64,
        output_tokens: i64,
        request_kind: &str,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let total_tokens = input_tokens.saturating_add(output_tokens);
        conn.execute(
            "INSERT INTO llm_usage_logs
                (chat_id, caller_channel, provider, model, input_tokens, output_tokens, total_tokens, request_kind, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                chat_id,
                caller_channel,
                provider,
                model,
                input_tokens,
                output_tokens,
                total_tokens,
                request_kind,
                now,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_llm_usage_summary(
        &self,
        chat_id: Option<i64>,
    ) -> Result<LlmUsageSummary, MicroClawError> {
        self.get_llm_usage_summary_since(chat_id, None)
    }

    pub fn get_llm_usage_summary_since(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
    ) -> Result<LlmUsageSummary, MicroClawError> {
        let conn = self.lock_conn();
        let (requests, input_tokens, output_tokens, total_tokens, last_request_at) =
            match (chat_id, since) {
                (Some(id), Some(since_ts)) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs
                 WHERE chat_id = ?1 AND created_at >= ?2",
                    params![id, since_ts],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
                (Some(id), None) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs
                 WHERE chat_id = ?1",
                    params![id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
                (None, Some(since_ts)) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs
                 WHERE created_at >= ?1",
                    params![since_ts],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
                (None, None) => conn.query_row(
                    "SELECT
                    COUNT(*),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(total_tokens), 0),
                    MAX(created_at)
                 FROM llm_usage_logs",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?,
            };

        Ok(LlmUsageSummary {
            requests,
            input_tokens,
            output_tokens,
            total_tokens,
            last_request_at,
        })
    }

    pub fn get_llm_usage_by_model(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<LlmModelUsageSummary>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT
                model,
                COUNT(*) AS requests,
                COALESCE(SUM(input_tokens), 0) AS input_tokens,
                COALESCE(SUM(output_tokens), 0) AS output_tokens,
                COALESCE(SUM(total_tokens), 0) AS total_tokens
             FROM llm_usage_logs",
        );

        let mut has_where = false;
        if chat_id.is_some() {
            query.push_str(" WHERE chat_id = ?1");
            has_where = true;
        }
        if since.is_some() {
            if has_where {
                if chat_id.is_some() {
                    query.push_str(" AND created_at >= ?2");
                } else {
                    query.push_str(" AND created_at >= ?1");
                }
            } else {
                query.push_str(" WHERE created_at >= ?1");
            }
        }
        query.push_str(" GROUP BY model ORDER BY total_tokens DESC");
        if limit.is_some() {
            match (chat_id.is_some(), since.is_some()) {
                (true, true) => query.push_str(" LIMIT ?3"),
                (true, false) | (false, true) => query.push_str(" LIMIT ?2"),
                (false, false) => query.push_str(" LIMIT ?1"),
            }
        }

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(LlmModelUsageSummary {
                model: row.get(0)?,
                requests: row.get(1)?,
                input_tokens: row.get(2)?,
                output_tokens: row.get(3)?,
                total_tokens: row.get(4)?,
            })
        };

        let rows = match (chat_id, since, limit) {
            (Some(id), Some(since_ts), Some(limit_n)) => {
                stmt.query_map(params![id, since_ts, limit_n as i64], mapper)?
            }
            (Some(id), Some(since_ts), None) => stmt.query_map(params![id, since_ts], mapper)?,
            (Some(id), None, Some(limit_n)) => {
                stmt.query_map(params![id, limit_n as i64], mapper)?
            }
            (Some(id), None, None) => stmt.query_map(params![id], mapper)?,
            (None, Some(since_ts), Some(limit_n)) => {
                stmt.query_map(params![since_ts, limit_n as i64], mapper)?
            }
            (None, Some(since_ts), None) => stmt.query_map(params![since_ts], mapper)?,
            (None, None, Some(limit_n)) => stmt.query_map(params![limit_n as i64], mapper)?,
            (None, None, None) => stmt.query_map([], mapper)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // --- Memories ---

    pub fn insert_memory(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
    ) -> Result<i64, MicroClawError> {
        self.insert_memory_with_metadata(chat_id, content, category, "tool", 0.80)
    }

    pub fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let (chat_channel, external_chat_id) = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT channel, external_chat_id FROM chats WHERE chat_id = ?1",
                params![cid],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?
            .unwrap_or((None, None))
        } else {
            (None, None)
        };
        conn.execute(
            "INSERT INTO memories (
                chat_id, content, category, created_at, updated_at, embedding_model,
                confidence, source, last_seen_at, is_archived, archived_at,
                chat_channel, external_chat_id
            ) VALUES (?1, ?2, ?3, ?4, ?4, NULL, ?5, ?6, ?4, 0, NULL, ?7, ?8)",
            params![
                chat_id,
                content,
                category,
                now,
                confidence.clamp(0.0, 1.0),
                source,
                chat_channel,
                external_chat_id
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at
             FROM memories
             WHERE (chat_id = ?1 OR chat_id IS NULL)
               AND is_archived = 0
               AND confidence >= 0.45
             ORDER BY updated_at DESC
             LIMIT ?2",
        )?;
        let memories = stmt
            .query_map(params![chat_id, limit as i64], |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
    }

    pub fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at
             FROM memories
             WHERE (chat_id = ?1 OR (?1 IS NULL AND chat_id IS NULL))",
        )?;
        let memories = stmt
            .query_map(params![chat_id], |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
    }

    pub fn get_active_chat_ids_since(&self, since: &str) -> Result<Vec<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT chat_id FROM messages WHERE timestamp > ?1 AND is_from_bot = 0",
        )?;
        let ids = stmt
            .query_map(params![since], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Keyword search in memories visible to chat_id (own + global).
    pub fn search_memories(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.search_memories_with_options(chat_id, query, limit, false, true)
    }

    pub fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let pattern = format!("%{}%", query.to_lowercase());
        let mut sql = String::from(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at
             FROM memories
             WHERE (chat_id = ?1 OR chat_id IS NULL)
               AND LOWER(content) LIKE ?2",
        );
        if !include_archived {
            sql.push_str(" AND is_archived = 0");
        }
        if !broad_recall {
            sql.push_str(" AND confidence >= 0.45");
        }
        sql.push_str(" ORDER BY confidence DESC, updated_at DESC LIMIT ?3");
        let mut stmt = conn.prepare(&sql)?;
        let memories = stmt
            .query_map(params![chat_id, pattern, limit as i64], |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
    }

    /// Delete a memory row by id. Returns true if a row was deleted.
    pub fn delete_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute("DELETE FROM memories WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    /// Update content and category of an existing memory. Returns true if found.
    pub fn update_memory_content(
        &self,
        id: i64,
        content: &str,
        category: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET content = ?1,
                 category = ?2,
                 updated_at = ?3,
                 embedding_model = NULL,
                 last_seen_at = ?3,
                 is_archived = 0,
                 archived_at = NULL
             WHERE id = ?4",
            params![content, category, now, id],
        )?;
        Ok(rows > 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET content = ?1,
                 category = ?2,
                 updated_at = ?3,
                 embedding_model = NULL,
                 confidence = ?4,
                 source = ?5,
                 last_seen_at = ?3,
                 is_archived = 0,
                 archived_at = NULL
             WHERE id = ?6",
            params![
                content,
                category,
                now,
                confidence.clamp(0.0, 1.0),
                source,
                id
            ],
        )?;
        Ok(rows > 0)
    }

    pub fn update_memory_embedding_model(
        &self,
        id: i64,
        model: &str,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE memories SET embedding_model = ?1 WHERE id = ?2",
            params![model, id],
        )?;
        Ok(rows > 0)
    }

    pub fn get_memories_without_embedding(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model
             , confidence, source, last_seen_at, is_archived, archived_at
             FROM memories
             WHERE embedding_model IS NULL
               AND is_archived = 0",
        );
        if chat_id.is_some() {
            query.push_str(" AND chat_id = ?1");
        }
        query.push_str(" ORDER BY updated_at DESC LIMIT ");
        query.push_str(&limit.to_string());

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(Memory {
                id: row.get(0)?,
                chat_id: row.get(1)?,
                content: row.get(2)?,
                category: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                embedding_model: row.get(6)?,
                confidence: row.get(7)?,
                source: row.get(8)?,
                last_seen_at: row.get(9)?,
                is_archived: row.get::<_, i64>(10)? != 0,
                archived_at: row.get(11)?,
            })
        };

        let rows = if let Some(cid) = chat_id {
            stmt.query_map(params![cid], mapper)?
        } else {
            stmt.query_map([], mapper)?
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    #[cfg(feature = "sqlite-vec")]
    pub fn prepare_vector_index(&self, dimension: usize) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let dimension = dimension.max(1);
        conn.execute(
            "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )?;

        let current_dim: Option<String> = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'embedding_dim'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = current_dim {
            if existing != dimension.to_string() {
                conn.execute("DROP TABLE IF EXISTS memories_vec", [])?;
                conn.execute("UPDATE memories SET embedding_model = NULL", [])?;
            }
        }

        conn.execute(
            &format!(
                "CREATE VIRTUAL TABLE IF NOT EXISTS memories_vec USING vec0(
                    embedding float[{dimension}] distance_metric=cosine
                )"
            ),
            [],
        )?;
        conn.execute(
            "INSERT INTO db_meta(key, value) VALUES('embedding_dim', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![dimension.to_string()],
        )?;
        Ok(())
    }

    #[cfg(feature = "sqlite-vec")]
    pub fn upsert_memory_vec(
        &self,
        memory_id: i64,
        embedding: &[f32],
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let vector_json = serde_json::to_string(embedding)?;
        conn.execute(
            "INSERT OR REPLACE INTO memories_vec(rowid, embedding) VALUES(?1, vec_f32(?2))",
            params![memory_id, vector_json],
        )?;
        Ok(())
    }

    pub fn get_all_active_memories(&self) -> Result<Vec<(i64, String)>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt =
            conn.prepare("SELECT id, content FROM memories WHERE is_archived = 0 ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    #[cfg(feature = "sqlite-vec")]
    pub fn knn_memories(
        &self,
        chat_id: i64,
        query_vec: &[f32],
        k: usize,
    ) -> Result<Vec<(i64, f32)>, MicroClawError> {
        let conn = self.lock_conn();
        let vector_json = serde_json::to_string(query_vec)?;
        let mut stmt = conn.prepare(
            "SELECT m.id, v.distance
             FROM (
                SELECT rowid, distance
                FROM memories_vec
                WHERE embedding MATCH vec_f32(?1) AND k = ?2
             ) v
             JOIN memories m ON m.id = v.rowid
             WHERE (m.chat_id = ?3 OR m.chat_id IS NULL)
             ORDER BY v.distance ASC",
        )?;
        let rows = stmt.query_map(params![vector_json, k as i64, chat_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f32>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get a single memory by id.
    pub fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at
             FROM memories WHERE id = ?1",
            params![id],
            |row| {
                Ok(Memory {
                    id: row.get(0)?,
                    chat_id: row.get(1)?,
                    content: row.get(2)?,
                    category: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    embedding_model: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_archived: row.get::<_, i64>(10)? != 0,
                    archived_at: row.get(11)?,
                })
            },
        );
        match result {
            Ok(m) => Ok(Some(m)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = if let Some(floor) = confidence_floor {
            conn.execute(
                "UPDATE memories
                 SET last_seen_at = ?1,
                     confidence = MAX(confidence, ?2)
                 WHERE id = ?3",
                params![now, floor.clamp(0.0, 1.0), id],
            )?
        } else {
            conn.execute(
                "UPDATE memories SET last_seen_at = ?1 WHERE id = ?2",
                params![now, id],
            )?
        };
        Ok(rows > 0)
    }

    pub fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET is_archived = 1, archived_at = ?1, updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
        Ok(rows > 0)
    }

    pub fn archive_stale_memories(&self, stale_days: i64) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(stale_days.max(1))).to_rfc3339();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE memories
             SET is_archived = 1, archived_at = ?1, updated_at = ?1
             WHERE is_archived = 0
               AND confidence < 0.35
               AND COALESCE(last_seen_at, updated_at, created_at) < ?2",
            params![now, cutoff],
        )?;
        Ok(rows)
    }

    pub fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let (chat_id, chat_channel, external_chat_id): (
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT chat_id, chat_channel, external_chat_id FROM memories WHERE id = ?1",
            params![from_memory_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO memories (
                chat_id, content, category, created_at, updated_at, embedding_model,
                confidence, source, last_seen_at, is_archived, archived_at, chat_channel, external_chat_id
            ) VALUES (?1, ?2, ?3, ?4, ?4, NULL, ?5, ?6, ?4, 0, NULL, ?7, ?8)",
            params![
                chat_id,
                new_content,
                category,
                now,
                confidence.clamp(0.0, 1.0),
                source,
                chat_channel,
                external_chat_id
            ],
        )?;
        let to_memory_id = tx.last_insert_rowid();

        tx.execute(
            "UPDATE memories
             SET is_archived = 1, archived_at = ?1, updated_at = ?1
             WHERE id = ?2",
            params![now, from_memory_id],
        )?;
        tx.execute(
            "INSERT INTO memory_supersede_edges(from_memory_id, to_memory_id, reason, created_at)
             VALUES(?1, ?2, ?3, ?4)",
            params![from_memory_id, to_memory_id, reason, now],
        )?;
        tx.commit()?;
        Ok(to_memory_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_reflector_run(
        &self,
        chat_id: i64,
        started_at: &str,
        finished_at: &str,
        extracted_count: usize,
        inserted_count: usize,
        updated_count: usize,
        skipped_count: usize,
        dedup_method: &str,
        parse_ok: bool,
        error_text: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO memory_reflector_runs (
                chat_id, started_at, finished_at, extracted_count, inserted_count, updated_count, skipped_count, dedup_method, parse_ok, error_text
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                chat_id,
                started_at,
                finished_at,
                extracted_count as i64,
                inserted_count as i64,
                updated_count as i64,
                skipped_count as i64,
                dedup_method,
                if parse_ok { 1 } else { 0 },
                error_text
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn log_memory_injection(
        &self,
        chat_id: i64,
        retrieval_method: &str,
        candidate_count: usize,
        selected_count: usize,
        omitted_count: usize,
        tokens_est: usize,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memory_injection_logs (
                chat_id, created_at, retrieval_method, candidate_count, selected_count, omitted_count, tokens_est
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                chat_id,
                now,
                retrieval_method,
                candidate_count as i64,
                selected_count as i64,
                omitted_count as i64,
                tokens_est as i64
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_memory_observability_summary(
        &self,
        chat_id: Option<i64>,
    ) -> Result<MemoryObservabilitySummary, MicroClawError> {
        let conn = self.lock_conn();
        let since_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

        let (total, active, archived, low_confidence, avg_confidence) = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN is_archived = 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN is_archived != 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN confidence < 0.45 THEN 1 ELSE 0 END), 0),
                    COALESCE(AVG(confidence), 0.0)
                 FROM memories
                 WHERE chat_id = ?1 OR chat_id IS NULL",
                params![cid],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, f64>(4)?,
                    ))
                },
            )?
        } else {
            conn.query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN is_archived = 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN is_archived != 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN confidence < 0.45 THEN 1 ELSE 0 END), 0),
                    COALESCE(AVG(confidence), 0.0)
                 FROM memories",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, f64>(4)?,
                    ))
                },
            )?
        };

        let (
            reflector_runs_24h,
            reflector_inserted_24h,
            reflector_updated_24h,
            reflector_skipped_24h,
        ) = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT
                        COUNT(*),
                        COALESCE(SUM(inserted_count), 0),
                        COALESCE(SUM(updated_count), 0),
                        COALESCE(SUM(skipped_count), 0)
                     FROM memory_reflector_runs
                     WHERE chat_id = ?1 AND unixepoch(started_at) >= unixepoch(?2)",
                params![cid, &since_24h],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
        } else {
            conn.query_row(
                "SELECT
                        COUNT(*),
                        COALESCE(SUM(inserted_count), 0),
                        COALESCE(SUM(updated_count), 0),
                        COALESCE(SUM(skipped_count), 0)
                     FROM memory_reflector_runs
                     WHERE unixepoch(started_at) >= unixepoch(?1)",
                params![&since_24h],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
        };

        let (injection_events_24h, injection_selected_24h, injection_candidates_24h) =
            if let Some(cid) = chat_id {
                conn.query_row(
                    "SELECT
                        COUNT(*),
                        COALESCE(SUM(selected_count), 0),
                        COALESCE(SUM(candidate_count), 0)
                     FROM memory_injection_logs
                     WHERE chat_id = ?1 AND unixepoch(created_at) >= unixepoch(?2)",
                    params![cid, &since_24h],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?
            } else {
                conn.query_row(
                    "SELECT
                        COUNT(*),
                        COALESCE(SUM(selected_count), 0),
                        COALESCE(SUM(candidate_count), 0)
                     FROM memory_injection_logs
                     WHERE unixepoch(created_at) >= unixepoch(?1)",
                    params![&since_24h],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?
            };

        Ok(MemoryObservabilitySummary {
            total,
            active,
            archived,
            low_confidence,
            avg_confidence,
            reflector_runs_24h,
            reflector_inserted_24h,
            reflector_updated_24h,
            reflector_skipped_24h,
            injection_events_24h,
            injection_selected_24h,
            injection_candidates_24h,
        })
    }

    pub fn get_memory_reflector_runs(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MemoryReflectorRun>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT id, chat_id, started_at, finished_at, extracted_count, inserted_count, updated_count, skipped_count, dedup_method, parse_ok, error_text
             FROM memory_reflector_runs",
        );
        let mut where_parts: Vec<&str> = Vec::new();
        if chat_id.is_some() {
            where_parts.push("chat_id = ?1");
        }
        if since.is_some() {
            where_parts.push(if chat_id.is_some() {
                "unixepoch(started_at) >= unixepoch(?2)"
            } else {
                "unixepoch(started_at) >= unixepoch(?1)"
            });
        }
        if !where_parts.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_parts.join(" AND "));
        }
        query.push_str(" ORDER BY unixepoch(started_at) ASC LIMIT ");
        query.push_str(&limit.max(1).to_string());
        query.push_str(" OFFSET ");
        query.push_str(&offset.to_string());

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(MemoryReflectorRun {
                id: row.get(0)?,
                chat_id: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                extracted_count: row.get(4)?,
                inserted_count: row.get(5)?,
                updated_count: row.get(6)?,
                skipped_count: row.get(7)?,
                dedup_method: row.get(8)?,
                parse_ok: row.get::<_, i64>(9)? != 0,
                error_text: row.get(10)?,
            })
        };
        let rows = match (chat_id, since) {
            (Some(cid), Some(ts)) => stmt.query_map(params![cid, ts], mapper)?,
            (Some(cid), None) => stmt.query_map(params![cid], mapper)?,
            (None, Some(ts)) => stmt.query_map(params![ts], mapper)?,
            (None, None) => stmt.query_map([], mapper)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_memory_injection_logs(
        &self,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MemoryInjectionLog>, MicroClawError> {
        let conn = self.lock_conn();
        let mut query = String::from(
            "SELECT id, chat_id, created_at, retrieval_method, candidate_count, selected_count, omitted_count, tokens_est
             FROM memory_injection_logs",
        );
        let mut where_parts: Vec<&str> = Vec::new();
        if chat_id.is_some() {
            where_parts.push("chat_id = ?1");
        }
        if since.is_some() {
            where_parts.push(if chat_id.is_some() {
                "unixepoch(created_at) >= unixepoch(?2)"
            } else {
                "unixepoch(created_at) >= unixepoch(?1)"
            });
        }
        if !where_parts.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_parts.join(" AND "));
        }
        query.push_str(" ORDER BY unixepoch(created_at) ASC LIMIT ");
        query.push_str(&limit.max(1).to_string());
        query.push_str(" OFFSET ");
        query.push_str(&offset.to_string());

        let mut stmt = conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(MemoryInjectionLog {
                id: row.get(0)?,
                chat_id: row.get(1)?,
                created_at: row.get(2)?,
                retrieval_method: row.get(3)?,
                candidate_count: row.get(4)?,
                selected_count: row.get(5)?,
                omitted_count: row.get(6)?,
                tokens_est: row.get(7)?,
            })
        };
        let rows = match (chat_id, since) {
            (Some(cid), Some(ts)) => stmt.query_map(params![cid, ts], mapper)?,
            (Some(cid), None) => stmt.query_map(params![cid], mapper)?,
            (None, Some(ts)) => stmt.query_map(params![ts], mapper)?,
            (None, None) => stmt.query_map([], mapper)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
    fn test_schema_version_is_tracked() {
        let (db, dir) = test_db();
        let conn = db.lock_conn();
        let version: String = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION_CURRENT.to_string());
        drop(conn);
        cleanup(&dir);
    }

    #[test]
    fn test_legacy_schema_is_upgraded_to_current_version() {
        let dir =
            std::env::temp_dir().join(format!("microclaw_legacy_upgrade_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
             );
             CREATE TABLE messages (
                id TEXT NOT NULL,
                chat_id INTEGER NOT NULL,
                sender_name TEXT NOT NULL,
                content TEXT NOT NULL,
                is_from_bot INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (id, chat_id)
             );
             CREATE TABLE scheduled_tasks (
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
             CREATE TABLE sessions (
                chat_id INTEGER PRIMARY KEY,
                messages_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
             );
             CREATE TABLE memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
             );",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        let version: String = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION_CURRENT.to_string());

        let has_confidence = table_has_column(&conn, "memories", "confidence").unwrap();
        let has_source = table_has_column(&conn, "memories", "source").unwrap();
        let has_last_seen = table_has_column(&conn, "memories", "last_seen_at").unwrap();
        let has_archived = table_has_column(&conn, "memories", "is_archived").unwrap();
        assert!(has_confidence && has_source && has_last_seen && has_archived);
        assert!(table_has_column(&conn, "sessions", "parent_session_key").unwrap());
        assert!(table_has_column(&conn, "sessions", "fork_point").unwrap());

        let session_parent_index_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_sessions_parent_session_key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(session_parent_index_exists, 1);

        let supersede_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_supersede_edges'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(supersede_table_exists, 1);
        let dlq_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scheduled_task_dlq'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dlq_table_exists, 1);
        drop(conn);
        cleanup(&dir);
    }

    #[test]
    fn test_migration_matrix_upgrades_multiple_legacy_versions() {
        fn seed_legacy_db(dir: &std::path::Path, version: i64) {
            let db_path = dir.join("microclaw.db");
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE chats (
                    chat_id INTEGER PRIMARY KEY,
                    chat_title TEXT,
                    chat_type TEXT NOT NULL DEFAULT 'private',
                    last_message_time TEXT NOT NULL
                 );
                 CREATE TABLE messages (
                    id TEXT NOT NULL,
                    chat_id INTEGER NOT NULL,
                    sender_name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    is_from_bot INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (id, chat_id)
                 );
                 CREATE TABLE scheduled_tasks (
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
                 CREATE TABLE sessions (
                    chat_id INTEGER PRIMARY KEY,
                    messages_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 );
                 CREATE TABLE memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO db_meta(key, value) VALUES('schema_version', ?1)",
                params![version.to_string()],
            )
            .unwrap();

            if version >= 5 {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS api_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        label TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        prefix TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        revoked_at TEXT,
                        last_used_at TEXT
                    );",
                )
                .unwrap();
            }
            if version >= 7 {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS metrics_history (
                        timestamp_ms INTEGER PRIMARY KEY,
                        llm_completions INTEGER NOT NULL DEFAULT 0,
                        llm_input_tokens INTEGER NOT NULL DEFAULT 0,
                        llm_output_tokens INTEGER NOT NULL DEFAULT 0,
                        http_requests INTEGER NOT NULL DEFAULT 0,
                        tool_executions INTEGER NOT NULL DEFAULT 0,
                        mcp_calls INTEGER NOT NULL DEFAULT 0,
                        active_sessions INTEGER NOT NULL DEFAULT 0
                    );",
                )
                .unwrap();
            }
            drop(conn);
        }

        for version in [1_i64, 5_i64, 7_i64, 8_i64] {
            let dir = std::env::temp_dir().join(format!(
                "microclaw_migration_matrix_{}_{}",
                version,
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            seed_legacy_db(&dir, version);

            let db = Database::new(dir.to_str().unwrap()).unwrap();
            let conn = db.lock_conn();
            let actual: String = conn
                .query_row(
                    "SELECT value FROM db_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                actual,
                SCHEMA_VERSION_CURRENT.to_string(),
                "legacy schema_version {} should migrate to current",
                version
            );
            assert!(table_has_column(&conn, "sessions", "parent_session_key").unwrap());
            assert!(table_has_column(&conn, "sessions", "fork_point").unwrap());
            assert!(table_has_column(&conn, "api_keys", "expires_at").unwrap());
            assert!(table_has_column(&conn, "api_keys", "rotated_from_key_id").unwrap());
            assert!(
                table_has_column(&conn, "metrics_history", "mcp_rate_limited_rejections").unwrap()
            );
            assert!(table_has_column(&conn, "metrics_history", "mcp_bulkhead_rejections").unwrap());
            assert!(
                table_has_column(&conn, "metrics_history", "mcp_circuit_open_rejections").unwrap()
            );
            drop(conn);
            cleanup(&dir);
        }
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
    fn test_metrics_history_roundtrip_with_mcp_rejection_fields() {
        let (db, dir) = test_db();
        let point = MetricsHistoryPoint {
            timestamp_ms: 1_700_000_000_000,
            llm_completions: 10,
            llm_input_tokens: 1000,
            llm_output_tokens: 500,
            http_requests: 20,
            tool_executions: 8,
            mcp_calls: 3,
            mcp_rate_limited_rejections: 2,
            mcp_bulkhead_rejections: 1,
            mcp_circuit_open_rejections: 4,
            active_sessions: 6,
        };
        db.upsert_metrics_history(&point).unwrap();
        let rows = db.get_metrics_history(point.timestamp_ms, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let got = &rows[0];
        assert_eq!(got.mcp_rate_limited_rejections, 2);
        assert_eq!(got.mcp_bulkhead_rejections, 1);
        assert_eq!(got.mcp_circuit_open_rejections, 4);
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
    fn test_clear_chat_context_removes_session_and_messages_only() {
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

        assert!(db.clear_chat_context(100).unwrap());
        assert!(db.load_session(100).unwrap().is_none());
        assert!(db.get_recent_messages(100, 10).unwrap().is_empty());
        assert!(!db.search_memories(100, "Rust", 10).unwrap().is_empty());
        assert!(db.get_chat_type(100).unwrap().is_some());

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

    #[test]
    fn test_get_messages_since_includes_user_and_bot() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "old".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 100,
            sender_name: "bot".into(),
            content: "bot".into(),
            is_from_bot: true,
            timestamp: "2024-01-01T00:00:02Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m3".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "new".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:03Z".into(),
        })
        .unwrap();

        let msgs = db
            .get_messages_since(100, "2024-01-01T00:00:01Z", 10)
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].id, "m2");
        assert_eq!(msgs[1].id, "m3");

        cleanup(&dir);
    }

    #[test]
    fn test_reflector_cursor_roundtrip() {
        let (db, dir) = test_db();
        assert!(db.get_reflector_cursor(100).unwrap().is_none());

        db.set_reflector_cursor(100, "2024-01-01T00:00:03Z")
            .unwrap();
        assert_eq!(
            db.get_reflector_cursor(100).unwrap().as_deref(),
            Some("2024-01-01T00:00:03Z")
        );

        db.set_reflector_cursor(100, "2024-01-01T00:00:05Z")
            .unwrap();
        assert_eq!(
            db.get_reflector_cursor(100).unwrap().as_deref(),
            Some("2024-01-01T00:00:05Z")
        );

        cleanup(&dir);
    }

    #[test]
    fn test_resolve_or_create_chat_id_channel_scoped() {
        let (db, dir) = test_db();

        let tg = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        let tg_again = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        assert_eq!(tg, tg_again);

        let discord = db
            .resolve_or_create_chat_id("discord", "12345", Some("discord-12345"), "discord")
            .unwrap();
        assert_ne!(tg, discord);
        assert_eq!(
            db.get_chat_external_id(discord).unwrap().as_deref(),
            Some("12345")
        );

        cleanup(&dir);
    }

    #[test]
    fn test_get_chat_id_by_channel_and_title_finds_non_recent_chat() {
        let (db, dir) = test_db();

        for i in 0..5000 {
            db.resolve_or_create_chat_id(
                "web",
                &format!("ext-{i}"),
                Some(&format!("title-{i}")),
                "web",
            )
            .unwrap();
        }
        let target = db
            .resolve_or_create_chat_id("web", "legacy-ext", Some("legacy-session"), "web")
            .unwrap();
        for i in 5000..9300 {
            db.resolve_or_create_chat_id(
                "web",
                &format!("ext-{i}"),
                Some(&format!("title-{i}")),
                "web",
            )
            .unwrap();
        }

        let found = db
            .get_chat_id_by_channel_and_title("web", "legacy-session")
            .unwrap();
        assert_eq!(found, Some(target));

        cleanup(&dir);
    }

    #[test]
    fn test_migration_backfills_chat_identity_columns() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_migration_chat_identity_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
            );
            INSERT INTO chats(chat_id, chat_title, chat_type, last_message_time)
            VALUES (100, 'legacy tg', 'telegram_private', '2026-01-01T00:00:00Z');",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        let (channel, external): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT channel, external_chat_id FROM chats WHERE chat_id = 100",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(channel.as_deref(), Some("telegram"));
        assert_eq!(external.as_deref(), Some("100"));
        drop(conn);

        cleanup(&dir);
    }

    #[test]
    fn test_migration_backfills_memory_identity_columns() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_migration_memory_identity_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chats (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT,
                chat_type TEXT NOT NULL DEFAULT 'private',
                last_message_time TEXT NOT NULL
            );
            INSERT INTO chats(chat_id, chat_title, chat_type, last_message_time)
            VALUES (200, 'legacy discord', 'discord', '2026-01-01T00:00:00Z');

            CREATE TABLE memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                embedding_model TEXT
            );
            INSERT INTO memories(chat_id, content, category, created_at, updated_at, embedding_model)
            VALUES (200, 'legacy memory', 'KNOWLEDGE', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', NULL);",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        let (chat_channel, external): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT chat_channel, external_chat_id FROM memories WHERE chat_id = 200",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(chat_channel.as_deref(), Some("discord"));
        assert_eq!(external.as_deref(), Some("200"));
        drop(conn);

        cleanup(&dir);
    }

    #[test]
    fn test_log_llm_usage_and_summary() {
        let (db, dir) = test_db();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-test",
            10,
            5,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-test",
            20,
            8,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(200, "discord", "openai", "gpt-test", 30, 7, "agent_loop")
            .unwrap();

        let chat_100 = db.get_llm_usage_summary(Some(100)).unwrap();
        assert_eq!(chat_100.requests, 2);
        assert_eq!(chat_100.input_tokens, 30);
        assert_eq!(chat_100.output_tokens, 13);
        assert_eq!(chat_100.total_tokens, 43);
        assert!(chat_100.last_request_at.is_some());

        let all = db.get_llm_usage_summary(None).unwrap();
        assert_eq!(all.requests, 3);
        assert_eq!(all.input_tokens, 60);
        assert_eq!(all.output_tokens, 20);
        assert_eq!(all.total_tokens, 80);
        assert!(all.last_request_at.is_some());

        cleanup(&dir);
    }

    #[test]
    fn test_delete_chat_data_cleans_llm_usage() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("chat-100"), "private").unwrap();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-test",
            11,
            9,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(
            200,
            "telegram",
            "anthropic",
            "claude-test",
            3,
            4,
            "agent_loop",
        )
        .unwrap();

        assert!(db.delete_chat_data(100).unwrap());

        let chat_100 = db.get_llm_usage_summary(Some(100)).unwrap();
        assert_eq!(chat_100.requests, 0);
        let chat_200 = db.get_llm_usage_summary(Some(200)).unwrap();
        assert_eq!(chat_200.requests, 1);

        cleanup(&dir);
    }

    #[test]
    fn test_get_llm_usage_summary_since_and_by_model() {
        let (db, dir) = test_db();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-a",
            10,
            5,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(
            100,
            "telegram",
            "anthropic",
            "claude-a",
            20,
            10,
            "agent_loop",
        )
        .unwrap();
        db.log_llm_usage(100, "telegram", "anthropic", "claude-b", 3, 7, "agent_loop")
            .unwrap();

        let all = db.get_llm_usage_summary_since(Some(100), None).unwrap();
        assert_eq!(all.requests, 3);
        assert_eq!(all.input_tokens, 33);
        assert_eq!(all.output_tokens, 22);

        let future = db
            .get_llm_usage_summary_since(Some(100), Some("2100-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(future.requests, 0);

        let by_model = db
            .get_llm_usage_by_model(Some(100), None, Some(10))
            .unwrap();
        assert_eq!(by_model.len(), 2);
        assert_eq!(by_model[0].model, "claude-a");
        assert_eq!(by_model[0].requests, 2);
        assert_eq!(by_model[0].total_tokens, 45);
        assert_eq!(by_model[1].model, "claude-b");
        assert_eq!(by_model[1].requests, 1);
        assert_eq!(by_model[1].total_tokens, 10);

        cleanup(&dir);
    }

    #[test]
    fn test_insert_and_get_memories_for_context() {
        let (db, dir) = test_db();
        db.insert_memory(Some(100), "User is a Rust developer", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "User lives in Tokyo", "PROFILE")
            .unwrap();
        db.insert_memory(None, "Global fact", "KNOWLEDGE").unwrap();
        db.insert_memory(Some(200), "Other chat memory", "EVENT")
            .unwrap();

        // chat 100 should see its own + global, not chat 200
        let mems = db.get_memories_for_context(100, 10).unwrap();
        assert_eq!(mems.len(), 3);
        let contents: Vec<&str> = mems.iter().map(|m| m.content.as_str()).collect();
        assert!(contents.contains(&"User is a Rust developer"));
        assert!(contents.contains(&"User lives in Tokyo"));
        assert!(contents.contains(&"Global fact"));
        assert!(!contents.contains(&"Other chat memory"));

        cleanup(&dir);
    }

    #[test]
    fn test_get_memories_for_context_limit() {
        let (db, dir) = test_db();
        for i in 0..5 {
            db.insert_memory(Some(100), &format!("memory {i}"), "KNOWLEDGE")
                .unwrap();
        }
        let mems = db.get_memories_for_context(100, 3).unwrap();
        assert_eq!(mems.len(), 3);
        cleanup(&dir);
    }

    #[test]
    fn test_get_all_memories_for_chat() {
        let (db, dir) = test_db();
        db.insert_memory(Some(100), "chat 100 mem", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "chat 100 mem 2", "EVENT")
            .unwrap();
        db.insert_memory(Some(200), "chat 200 mem", "PROFILE")
            .unwrap();
        db.insert_memory(None, "global mem", "KNOWLEDGE").unwrap();

        let mems = db.get_all_memories_for_chat(Some(100)).unwrap();
        assert_eq!(mems.len(), 2);

        let global = db.get_all_memories_for_chat(None).unwrap();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].content, "global mem");

        cleanup(&dir);
    }

    #[test]
    fn test_get_active_chat_ids_since() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-06-01T00:00:01Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 200,
            sender_name: "bob".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2024-06-01T00:00:02Z".into(),
        })
        .unwrap();
        // Bot message should not count
        db.store_message(&StoredMessage {
            id: "m3".into(),
            chat_id: 300,
            sender_name: "bot".into(),
            content: "bot msg".into(),
            is_from_bot: true,
            timestamp: "2024-06-01T00:00:03Z".into(),
        })
        .unwrap();

        let ids = db
            .get_active_chat_ids_since("2024-06-01T00:00:00Z")
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&100));
        assert!(ids.contains(&200));
        assert!(!ids.contains(&300));

        // Before any messages
        let ids_empty = db
            .get_active_chat_ids_since("2025-01-01T00:00:00Z")
            .unwrap();
        assert!(ids_empty.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_search_memories() {
        let (db, dir) = test_db();
        db.insert_memory(Some(100), "User is a Rust developer", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "User loves coffee", "PROFILE")
            .unwrap();
        db.insert_memory(None, "Rust is fast and safe", "KNOWLEDGE")
            .unwrap();

        let results = db.search_memories(100, "rust", 10).unwrap();
        assert_eq!(results.len(), 2); // own + global both match "rust"

        let results = db.search_memories(100, "coffee", 10).unwrap();
        assert_eq!(results.len(), 1);

        let results = db.search_memories(100, "nonexistent_xyz", 10).unwrap();
        assert!(results.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_archive_memory_hides_from_search_and_context() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "User prefers concise summaries", "PROFILE")
            .unwrap();
        assert!(db.archive_memory(id).unwrap());

        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert!(mem.is_archived);
        assert!(mem.archived_at.is_some());

        let search = db.search_memories(100, "concise", 10).unwrap();
        assert!(search.is_empty());
        let context = db.get_memories_for_context(100, 10).unwrap();
        assert!(context.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn test_memory_observability_summary_rollup() {
        let (db, dir) = test_db();
        let started_at_dt = chrono::Utc::now() - chrono::Duration::minutes(1);
        let started_at = started_at_dt.to_rfc3339();
        let finished_at = (started_at_dt + chrono::Duration::seconds(1)).to_rfc3339();
        db.insert_memory_with_metadata(Some(100), "prod db on 5433", "KNOWLEDGE", "explicit", 0.95)
            .unwrap();
        let stale_id = db
            .insert_memory_with_metadata(Some(100), "temporary thought", "EVENT", "reflector", 0.20)
            .unwrap();
        db.archive_memory(stale_id).unwrap();
        db.log_reflector_run(
            100,
            &started_at,
            &finished_at,
            3,
            1,
            1,
            1,
            "jaccard",
            true,
            None,
        )
        .unwrap();
        db.log_memory_injection(100, "keyword", 5, 2, 3, 80)
            .unwrap();

        let summary = db.get_memory_observability_summary(Some(100)).unwrap();
        assert!(summary.total >= 2);
        assert!(summary.active >= 1);
        assert!(summary.archived >= 1);
        assert!(summary.reflector_runs_24h >= 1);
        assert!(summary.injection_events_24h >= 1);
        assert!(summary.injection_candidates_24h >= summary.injection_selected_24h);

        cleanup(&dir);
    }

    #[test]
    fn test_supersede_memory_creates_edge_and_archives_old() {
        let (db, dir) = test_db();
        let old_id = db
            .insert_memory_with_metadata(
                Some(100),
                "prod db port is 5433",
                "KNOWLEDGE",
                "explicit",
                0.95,
            )
            .unwrap();
        let new_id = db
            .supersede_memory(
                old_id,
                "prod db port is 6432",
                "KNOWLEDGE",
                "explicit_conflict",
                0.96,
                Some("port_update"),
            )
            .unwrap();
        assert!(new_id > old_id);
        let old = db.get_memory_by_id(old_id).unwrap().unwrap();
        let newm = db.get_memory_by_id(new_id).unwrap().unwrap();
        assert!(old.is_archived);
        assert_eq!(newm.content, "prod db port is 6432");

        let conn = db.lock_conn();
        let edge_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_supersede_edges WHERE from_memory_id = ?1 AND to_memory_id = ?2",
                params![old_id, new_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(edge_count, 1);
        drop(conn);
        cleanup(&dir);
    }

    #[test]
    fn test_delete_memory() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "to be deleted", "EVENT")
            .unwrap();

        assert!(db.delete_memory(id).unwrap());
        assert!(!db.delete_memory(id).unwrap()); // already gone
        assert!(db.get_memory_by_id(id).unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn test_update_memory_content() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "User lives in Tokyo", "PROFILE")
            .unwrap();

        assert!(db
            .update_memory_content(id, "User lives in Osaka", "PROFILE")
            .unwrap());

        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert_eq!(mem.content, "User lives in Osaka");
        assert_eq!(mem.category, "PROFILE");

        // Non-existent id
        assert!(!db.update_memory_content(9999, "x", "PROFILE").unwrap());

        cleanup(&dir);
    }

    #[test]
    fn test_get_memory_by_id() {
        let (db, dir) = test_db();
        let id = db
            .insert_memory(Some(100), "test memory", "KNOWLEDGE")
            .unwrap();

        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert_eq!(mem.id, id);
        assert_eq!(mem.content, "test memory");
        assert_eq!(mem.category, "KNOWLEDGE");

        assert!(db.get_memory_by_id(9999).unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn test_update_memory_embedding_model_and_query_missing() {
        let (db, dir) = test_db();
        let id1 = db
            .insert_memory(Some(100), "memory one", "KNOWLEDGE")
            .unwrap();
        let id2 = db
            .insert_memory(Some(100), "memory two", "KNOWLEDGE")
            .unwrap();

        let missing_before = db.get_memories_without_embedding(Some(100), 10).unwrap();
        assert_eq!(missing_before.len(), 2);

        assert!(db
            .update_memory_embedding_model(id1, "text-embedding-3-small")
            .unwrap());

        let mem1 = db.get_memory_by_id(id1).unwrap().unwrap();
        assert_eq!(
            mem1.embedding_model.as_deref(),
            Some("text-embedding-3-small")
        );
        let mem2 = db.get_memory_by_id(id2).unwrap().unwrap();
        assert!(mem2.embedding_model.is_none());

        let missing_after = db.get_memories_without_embedding(Some(100), 10).unwrap();
        assert_eq!(missing_after.len(), 1);
        assert_eq!(missing_after[0].id, id2);

        cleanup(&dir);
    }

    #[test]
    fn test_api_key_expiry_and_rotation_and_audit_logs() {
        let (db, dir) = test_db();
        let scopes = vec![
            "operator.read".to_string(),
            "operator.approvals".to_string(),
        ];
        let key_id = db
            .create_api_key(
                "k1",
                "hash-k1",
                "prefix-k1",
                &scopes,
                Some(&(chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
                None,
            )
            .unwrap();
        let valid = db.validate_api_key_hash("hash-k1").unwrap();
        assert!(valid.is_some());

        let expired_id = db
            .create_api_key(
                "k2",
                "hash-k2",
                "prefix-k2",
                &scopes,
                Some(&(chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()),
                Some(key_id),
            )
            .unwrap();
        let expired = db.validate_api_key_hash("hash-k2").unwrap();
        assert!(expired.is_none());
        assert!(db.rotate_api_key_revoke_old(key_id).unwrap());

        let keys = db.list_api_keys().unwrap();
        let rotated = keys.iter().find(|k| k.id == expired_id).unwrap();
        assert_eq!(rotated.rotated_from_key_id, Some(key_id));

        db.log_audit_event(
            "operator",
            "tester",
            "auth.api_key.rotate",
            Some("k1"),
            "ok",
            None,
        )
        .unwrap();
        let logs = db.list_audit_logs(Some("operator"), 20).unwrap();
        assert!(!logs.is_empty());

        cleanup(&dir);
    }

    #[cfg(feature = "sqlite-vec")]
    #[test]
    fn test_sqlite_vec_prepare_and_knn() {
        let (db, dir) = test_db();
        db.prepare_vector_index(3).unwrap();
        let id1 = db
            .insert_memory(Some(100), "vector one", "KNOWLEDGE")
            .unwrap();
        let id2 = db
            .insert_memory(Some(100), "vector two", "KNOWLEDGE")
            .unwrap();
        db.upsert_memory_vec(id1, &[1.0, 0.0, 0.0]).unwrap();
        db.upsert_memory_vec(id2, &[0.0, 1.0, 0.0]).unwrap();

        let nearest = db.knn_memories(100, &[0.95, 0.05, 0.0], 1).unwrap();
        assert_eq!(nearest.len(), 1);
        assert_eq!(nearest[0].0, id1);
        assert!(nearest[0].1 >= 0.0);

        cleanup(&dir);
    }
}
