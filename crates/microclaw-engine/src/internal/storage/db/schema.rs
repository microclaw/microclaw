//! Schema bootstrap and versioned migrations.
//!
//! The `if version < N` blocks in `apply_schema_migrations` are FROZEN TEXT:
//! never reformat, reorder, or "clean up" historical migrations. The upgrade
//! path from every deployed version must replay byte-identically. New schema
//! changes append a new version block and bump `SCHEMA_VERSION_CURRENT`.

use super::*;

pub(crate) const SCHEMA_VERSION_CURRENT: i64 = 43;

pub(crate) fn table_has_column(
    conn: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, MicroClawError> {
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

pub(crate) fn ensure_memory_schema(conn: &Connection) -> Result<(), MicroClawError> {
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
    if !table_has_column(conn, "memories", "expires_at")? {
        conn.execute("ALTER TABLE memories ADD COLUMN expires_at TEXT", [])?;
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

pub(crate) fn infer_channel_from_chat_type(chat_type: &str) -> &'static str {
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

pub(crate) fn ensure_chat_identity_schema(conn: &Connection) -> Result<(), MicroClawError> {
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

pub(crate) fn ensure_sessions_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "sessions", "parent_session_key")? {
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN parent_session_key TEXT",
            [],
        )?;
    }
    if !table_has_column(conn, "sessions", "fork_point")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN fork_point INTEGER", [])?;
    }
    if !table_has_column(conn, "sessions", "label")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN label TEXT", [])?;
    }
    if !table_has_column(conn, "sessions", "thinking_level")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN thinking_level TEXT", [])?;
    }
    if !table_has_column(conn, "sessions", "verbose_level")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN verbose_level TEXT", [])?;
    }
    if !table_has_column(conn, "sessions", "reasoning_level")? {
        conn.execute("ALTER TABLE sessions ADD COLUMN reasoning_level TEXT", [])?;
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

pub(crate) fn ensure_scheduled_tasks_schema(conn: &Connection) -> Result<(), MicroClawError> {
    if !table_has_column(conn, "scheduled_tasks", "exit_criteria")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN exit_criteria TEXT",
            [],
        )?;
    }
    if !table_has_column(conn, "scheduled_tasks", "run_count")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN run_count INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !table_has_column(conn, "scheduled_tasks", "max_runs")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN max_runs INTEGER",
            [],
        )?;
    }
    if !table_has_column(conn, "scheduled_tasks", "not_after")? {
        conn.execute("ALTER TABLE scheduled_tasks ADD COLUMN not_after TEXT", [])?;
    }
    if !table_has_column(conn, "scheduled_tasks", "timezone")? {
        conn.execute(
            "ALTER TABLE scheduled_tasks ADD COLUMN timezone TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

pub(crate) fn get_schema_version(conn: &Connection) -> Result<i64, MicroClawError> {
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

pub(crate) fn set_schema_version(conn: &Connection, version: i64) -> Result<(), MicroClawError> {
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

pub(crate) fn apply_schema_migrations(conn: &Connection) -> Result<(), MicroClawError> {
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
    if version < 11 {
        if !table_has_column(conn, "sessions", "skill_envs_json")? {
            conn.execute("ALTER TABLE sessions ADD COLUMN skill_envs_json TEXT", [])?;
        }
        set_schema_version(conn, 11)?;
        version = 11;
    }
    if version < 12 {
        ensure_scheduled_tasks_schema(conn)?;
        set_schema_version(conn, 12)?;
        version = 12;
    }
    if version < 13 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_runs (
                run_id TEXT PRIMARY KEY,
                parent_run_id TEXT,
                depth INTEGER NOT NULL DEFAULT 1,
                chat_id INTEGER NOT NULL,
                caller_channel TEXT NOT NULL,
                task TEXT NOT NULL,
                context TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                error_text TEXT,
                result_text TEXT,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                provider TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_subagent_runs_chat_created
                ON subagent_runs(chat_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_subagent_runs_chat_status
                ON subagent_runs(chat_id, status);
            CREATE INDEX IF NOT EXISTS idx_subagent_runs_parent_status
                ON subagent_runs(parent_run_id, status);",
        )?;
        set_schema_version(conn, 13)?;
        version = 13;
    }
    if version < 14 {
        if !table_has_column(conn, "subagent_runs", "parent_run_id")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN parent_run_id TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "subagent_runs", "depth")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN depth INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_subagent_runs_parent_status
             ON subagent_runs(parent_run_id, status)",
            [],
        )?;
        set_schema_version(conn, 14)?;
        version = 14;
    }
    if version < 15 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_announces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL UNIQUE,
                chat_id INTEGER NOT NULL,
                caller_channel TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subagent_announces_status_next
                ON subagent_announces(status, next_attempt_at);",
        )?;
        set_schema_version(conn, 15)?;
        version = 15;
    }
    if version < 16 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subagent_events_run_created
                ON subagent_events(run_id, created_at ASC);",
        )?;
        set_schema_version(conn, 16)?;
        version = 16;
    }
    if version < 17 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subagent_focus_bindings (
                chat_id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;
        set_schema_version(conn, 17)?;
        version = 17;
    }
    if version < 18 {
        if !table_has_column(conn, "subagent_runs", "token_budget")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN token_budget INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "subagent_runs", "artifact_json")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN artifact_json TEXT",
                [],
            )?;
        }
        set_schema_version(conn, 18)?;
        version = 18;
    }
    if version < 19 {
        ensure_sessions_schema(conn)?;
        set_schema_version(conn, 19)?;
        version = 19;
    }
    if version < 20 {
        // Temporal knowledge graph: add valid_from/valid_to to memories + knowledge_graph table
        if !table_has_column(conn, "memories", "valid_from")? {
            conn.execute("ALTER TABLE memories ADD COLUMN valid_from TEXT", [])?;
        }
        if !table_has_column(conn, "memories", "valid_to")? {
            conn.execute("ALTER TABLE memories ADD COLUMN valid_to TEXT", [])?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS knowledge_graph (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object TEXT NOT NULL,
                chat_id INTEGER,
                valid_from TEXT NOT NULL,
                valid_to TEXT,
                confidence REAL NOT NULL DEFAULT 0.70,
                source TEXT NOT NULL DEFAULT 'reflector',
                source_memory_id INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kg_subject ON knowledge_graph(subject);
            CREATE INDEX IF NOT EXISTS idx_kg_object ON knowledge_graph(object);
            CREATE INDEX IF NOT EXISTS idx_kg_predicate ON knowledge_graph(predicate);
            CREATE INDEX IF NOT EXISTS idx_kg_chat ON knowledge_graph(chat_id);
            CREATE INDEX IF NOT EXISTS idx_kg_valid_range ON knowledge_graph(valid_from, valid_to);",
        )?;
        set_schema_version(conn, 20)?;
        version = 20;
    }
    if version < 21 {
        // Session search: FTS5 virtual table over messages, with triggers to
        // keep it in sync on INSERT/UPDATE/DELETE. The table is created as
        // contentless (`content=''`) to avoid duplicating text on disk; we
        // manually keep it in sync via triggers rather than rely on the
        // external-content mode so that deletions of individual messages are
        // still cleanly reflected.
        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                content,
                sender_name,
                chat_id UNINDEXED,
                message_id UNINDEXED,
                timestamp UNINDEXED,
                is_from_bot UNINDEXED,
                tokenize = 'unicode61 remove_diacritics 2'
            );",
        )?;
        // Backfill existing messages into the FTS index. rowid pattern uses
        // a composite of chat_id and message_id to stay unique.
        conn.execute_batch(
            "INSERT INTO messages_fts(content, sender_name, chat_id, message_id, timestamp, is_from_bot)
             SELECT content, sender_name, chat_id, id, timestamp, is_from_bot FROM messages;",
        )?;
        conn.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(content, sender_name, chat_id, message_id, timestamp, is_from_bot)
                VALUES (new.content, new.sender_name, new.chat_id, new.id, new.timestamp, new.is_from_bot);
            END;
            CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages BEGIN
                DELETE FROM messages_fts WHERE chat_id = old.chat_id AND message_id = old.id;
            END;
            CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE ON messages BEGIN
                DELETE FROM messages_fts WHERE chat_id = old.chat_id AND message_id = old.id;
                INSERT INTO messages_fts(content, sender_name, chat_id, message_id, timestamp, is_from_bot)
                VALUES (new.content, new.sender_name, new.chat_id, new.id, new.timestamp, new.is_from_bot);
            END;",
        )?;
        set_schema_version(conn, 21)?;
        version = 21;
    }
    if version < 22 {
        // Tool result cache — keyed by SHA-256 of (tool_name + normalized
        // input JSON). Tools opt in by name; rows are purged lazily via TTL.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tool_result_cache (
                cache_key TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL,
                result_content TEXT NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tool_result_cache_tool_expires
                ON tool_result_cache(tool_name, expires_at);
            CREATE INDEX IF NOT EXISTS idx_tool_result_cache_expires
                ON tool_result_cache(expires_at);",
        )?;
        set_schema_version(conn, 22)?;
        version = 22;
    }
    if version < 23 {
        // Tool result artifacts — full content stash for results that exceed
        // the in-context truncation threshold. The agent reads slices via
        // the `fetch_artifact` tool. Rows expire after a TTL to bound
        // storage growth.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tool_result_artifacts (
                artifact_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                content TEXT NOT NULL,
                total_chars INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tool_result_artifacts_chat
                ON tool_result_artifacts(chat_id, expires_at);
            CREATE INDEX IF NOT EXISTS idx_tool_result_artifacts_expires
                ON tool_result_artifacts(expires_at);",
        )?;
        set_schema_version(conn, 23)?;
        version = 23;
    }
    if version < 24 {
        // Memory TTL: per-row expiration for time-bounded facts (NULL = never).
        // Distinct from `valid_to` (knowledge-graph temporal validity) and
        // `is_archived` (manual demotion).
        if !table_has_column(conn, "memories", "expires_at")? {
            conn.execute("ALTER TABLE memories ADD COLUMN expires_at TEXT", [])?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_expires ON memories(expires_at)
             WHERE expires_at IS NOT NULL",
            [],
        )?;
        set_schema_version(conn, 24)?;
        version = 24;
    }
    if version < 25 {
        // Skill activation log — drives the auto-archive of agent-created
        // skills that haven't been used in N days, and surfaces usage
        // counts in the insights tool.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_activation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                chat_id INTEGER,
                activated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_skill_activation_name_time
                ON skill_activation_logs(skill_name, activated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_skill_activation_time
                ON skill_activation_logs(activated_at);",
        )?;
        set_schema_version(conn, 25)?;
        version = 25;
    }
    if version < 26 {
        // Named, progress-reporting sub-agent runs: a human-friendly `label`
        // for "what am I working on", plus the latest progress snapshot pushed
        // by the `report_progress` tool during a long run.
        if !table_has_column(conn, "subagent_runs", "label")? {
            conn.execute("ALTER TABLE subagent_runs ADD COLUMN label TEXT", [])?;
        }
        if !table_has_column(conn, "subagent_runs", "progress_text")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN progress_text TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "subagent_runs", "last_progress_at")? {
            conn.execute(
                "ALTER TABLE subagent_runs ADD COLUMN last_progress_at TEXT",
                [],
            )?;
        }
        set_schema_version(conn, 26)?;
        version = 26;
    }
    if version < 27 {
        // Tamper-evident audit log: each new entry is sealed into a SHA-256 hash
        // chain (`entry_hash` over the entry's fields plus the previous entry's
        // `entry_hash`). Existing pre-migration rows stay unsealed (NULL) and are
        // simply not part of the verifiable chain.
        if !table_has_column(conn, "audit_logs", "prev_hash")? {
            conn.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT", [])?;
        }
        if !table_has_column(conn, "audit_logs", "entry_hash")? {
            conn.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT", [])?;
        }
        set_schema_version(conn, 27)?;
        version = 27;
    }
    if version < 28 {
        // Interrupted-turn recovery: one row per interactive turn in flight.
        // Inserted when the agent loop starts a user-facing turn, deleted when
        // the turn finishes (any outcome). Rows found at startup mean the
        // process died mid-reply — those chats get an "I was interrupted"
        // notice and the rows are cleared.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS active_turns (
                chat_id INTEGER PRIMARY KEY,
                channel TEXT NOT NULL,
                started_at TEXT NOT NULL
            );",
        )?;
        set_schema_version(conn, 28)?;
        version = 28;
    }
    if version < 29 {
        // Delivery outbox: final agent replies that failed to send are queued
        // here and retried with backoff by a supervised background loop, so a
        // transient channel outage can't silently drop a finished answer.
        // Also: `active_turns.progress_text` — a rolling "step N: tool, tool"
        // snapshot so the interrupted-turn notice can say how far the run got.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_outbox_status_next
                ON outbox_messages(status, next_attempt_at);",
        )?;
        if !table_has_column(conn, "active_turns", "progress_text")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN progress_text TEXT", [])?;
        }
        set_schema_version(conn, 29)?;
        version = 29;
    }
    if version < 30 {
        // Durable chunk delivery ledger. The parent row represents one
        // user-visible message; child rows are independently retryable chunks
        // with stable idempotency keys. Legacy whole-message outbox rows are
        // migrated as single-chunk deliveries.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbound_deliveries (
                delivery_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                full_payload_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                stored_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbound_delivery_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                payload_text TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(delivery_id, chunk_index),
                UNIQUE(idempotency_key),
                FOREIGN KEY(delivery_id) REFERENCES outbound_deliveries(delivery_id)
            );
            CREATE INDEX IF NOT EXISTS idx_delivery_chunks_status_next
                ON outbound_delivery_chunks(status, next_attempt_at);
            INSERT OR IGNORE INTO outbound_deliveries(
                delivery_id, chat_id, channel, full_payload_text, status,
                stored_at, created_at, updated_at
            )
            SELECT 'legacy-' || id, chat_id, channel, payload_text,
                   CASE WHEN status = 'delivered' THEN 'delivered'
                        WHEN status = 'failed' THEN 'failed' ELSE 'pending' END,
                   CASE WHEN status = 'delivered' THEN updated_at ELSE NULL END,
                   created_at, updated_at
            FROM outbox_messages;
            INSERT OR IGNORE INTO outbound_delivery_chunks(
                delivery_id, chunk_index, total_chunks, payload_text,
                idempotency_key, status, attempts, next_attempt_at,
                last_error, created_at, updated_at
            )
            SELECT 'legacy-' || id, 0, 1, payload_text, 'legacy-' || id,
                   status, attempts, next_attempt_at, last_error,
                   created_at, updated_at
            FROM outbox_messages;",
        )?;
        set_schema_version(conn, 30)?;
        version = 30;
    }
    if version < 31 {
        // Durable interactive-run checkpoints. The session snapshot is only
        // marked resumable at boundaries where no tool side effect is in an
        // unknown state. During tool execution the row remains inspectable,
        // but startup recovery stops with evidence instead of replaying it.
        if !table_has_column(conn, "active_turns", "chat_type")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN chat_type TEXT NOT NULL DEFAULT 'private'",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "phase")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN phase TEXT NOT NULL DEFAULT 'starting'",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "iteration")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN iteration INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "session_json")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN session_json TEXT", [])?;
        }
        if !table_has_column(conn, "active_turns", "resumable")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN resumable INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "tool_summary")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN tool_summary TEXT", [])?;
        }
        if !table_has_column(conn, "active_turns", "last_checkpoint_at")? {
            conn.execute(
                "ALTER TABLE active_turns ADD COLUMN last_checkpoint_at TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "active_turns", "run_id")? {
            conn.execute("ALTER TABLE active_turns ADD COLUMN run_id TEXT", [])?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_active_turns_checkpoint
             ON active_turns(resumable, last_checkpoint_at)",
            [],
        )?;
        set_schema_version(conn, 31)?;
        version = 31;
    }
    if version < 32 {
        // Long-horizon learning substrate. Facts remain in `memories`; these
        // tables track goals, task experience, verification evidence, and the
        // governed lifecycle of procedural skills.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS goal_states (
                goal_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                objective TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                constraints_json TEXT,
                progress_json TEXT,
                budget_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_goal_states_chat_status
                ON goal_states(chat_id, status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS experience_runs (
                run_id TEXT PRIMARY KEY,
                goal_id TEXT,
                chat_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                run_kind TEXT NOT NULL,
                objective TEXT NOT NULL,
                environment_fingerprint TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                result_summary TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_ms INTEGER,
                FOREIGN KEY(goal_id) REFERENCES goal_states(goal_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_runs_chat_started
                ON experience_runs(chat_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_experience_runs_goal_started
                ON experience_runs(goal_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_experience_runs_status
                ON experience_runs(status, started_at DESC);

            CREATE TABLE IF NOT EXISTS verifier_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                verifier_type TEXT NOT NULL,
                verifier_name TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                scope TEXT,
                verified_at TEXT NOT NULL,
                valid_until TEXT,
                UNIQUE(run_id, verifier_type, verifier_name),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_verifier_results_run
                ON verifier_results(run_id, verified_at DESC);

            CREATE TABLE IF NOT EXISTS skill_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(skill_name, version)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_versions_name_version
                ON skill_versions(skill_name, version DESC);

            CREATE TABLE IF NOT EXISTS skill_lifecycle (
                skill_name TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                active_version INTEGER NOT NULL,
                previous_trusted_version INTEGER,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                state_reason TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_skill_lifecycle_state
                ON skill_lifecycle(state, updated_at DESC);

            CREATE TABLE IF NOT EXISTS skill_lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                version INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_skill_lifecycle_events_name
                ON skill_lifecycle_events(skill_name, created_at DESC);

            CREATE TABLE IF NOT EXISTS skill_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                skill_version INTEGER NOT NULL,
                run_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                verifier_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, run_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_outcomes_name_created
                ON skill_outcomes(skill_name, created_at DESC);",
        )?;
        if !table_has_column(conn, "skill_activation_logs", "experience_run_id")? {
            conn.execute(
                "ALTER TABLE skill_activation_logs ADD COLUMN experience_run_id TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "skill_activation_logs", "skill_version")? {
            conn.execute(
                "ALTER TABLE skill_activation_logs ADD COLUMN skill_version INTEGER",
                [],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_skill_activation_experience
             ON skill_activation_logs(experience_run_id)",
            [],
        )?;
        set_schema_version(conn, 32)?;
        version = 32;
    }
    if version < 33 {
        for (column, definition) in [
            ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
            ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
            ("llm_requests", "INTEGER NOT NULL DEFAULT 0"),
            ("tool_calls", "INTEGER NOT NULL DEFAULT 0"),
            ("tool_errors", "INTEGER NOT NULL DEFAULT 0"),
            ("estimated_cost_usd", "REAL"),
        ] {
            if !table_has_column(conn, "experience_runs", column)? {
                conn.execute(
                    &format!("ALTER TABLE experience_runs ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        set_schema_version(conn, 33)?;
        version = 33;
    }
    if version < 34 {
        if !table_has_column(conn, "skill_outcomes", "verifier_name")? {
            conn.execute(
                "ALTER TABLE skill_outcomes ADD COLUMN verifier_name TEXT",
                [],
            )?;
        }
        if !table_has_column(conn, "skill_outcomes", "valid_until")? {
            conn.execute("ALTER TABLE skill_outcomes ADD COLUMN valid_until TEXT", [])?;
        }
        set_schema_version(conn, 34)?;
        version = 34;
    }
    if version < 35 {
        if !table_has_column(conn, "skill_outcomes", "attribution_confidence")? {
            conn.execute(
                "ALTER TABLE skill_outcomes
                 ADD COLUMN attribution_confidence REAL NOT NULL DEFAULT 1.0",
                [],
            )?;
        }
        set_schema_version(conn, 35)?;
        version = 35;
    }
    if version < 36 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_governance_policy (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                candidate_failures_to_degrade INTEGER NOT NULL,
                trial_min_outcomes INTEGER NOT NULL,
                trial_promote_rate REAL NOT NULL,
                trial_degrade_rate REAL NOT NULL,
                trusted_min_outcomes INTEGER NOT NULL,
                trusted_degrade_rate REAL NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;
        let policy = SkillGovernancePolicy::default();
        conn.execute(
            "INSERT OR IGNORE INTO skill_governance_policy(
                singleton_id, candidate_failures_to_degrade, trial_min_outcomes,
                trial_promote_rate, trial_degrade_rate, trusted_min_outcomes,
                trusted_degrade_rate, updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                policy.candidate_failures_to_degrade,
                policy.trial_min_outcomes,
                policy.trial_promote_rate,
                policy.trial_degrade_rate,
                policy.trusted_min_outcomes,
                policy.trusted_degrade_rate,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        set_schema_version(conn, 36)?;
        version = 36;
    }
    if version < 37 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outcome_envelopes (
                envelope_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                run_id TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                source_name TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                scope TEXT,
                valid_until TEXT,
                payload_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_outcome_envelopes_run_created
                ON outcome_envelopes(run_id, created_at ASC);

            CREATE TABLE IF NOT EXISTS experience_feedback (
                feedback_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                scope TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                valid_until TEXT,
                PRIMARY KEY(run_id, actor, feedback_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_feedback_run_updated
                ON experience_feedback(run_id, updated_at DESC);

            CREATE TABLE IF NOT EXISTS experience_retrieval_logs (
                querying_run_id TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                rank INTEGER NOT NULL,
                selection_reason TEXT NOT NULL,
                relevance_score REAL NOT NULL,
                injected_at TEXT NOT NULL,
                PRIMARY KEY(querying_run_id, source_run_id),
                FOREIGN KEY(querying_run_id) REFERENCES experience_runs(run_id),
                FOREIGN KEY(source_run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_retrieval_query_rank
                ON experience_retrieval_logs(querying_run_id, rank ASC);

            INSERT OR IGNORE INTO outcome_envelopes(
                envelope_id, schema_version, run_id, source_kind, source_name,
                verdict, confidence, evidence, scope, valid_until, payload_json,
                created_at
            )
            SELECT 'legacy-verifier:' || id, 1, run_id, verifier_type,
                   verifier_name, verdict, confidence, evidence, scope,
                   valid_until, '{}', verified_at
            FROM verifier_results;

            INSERT OR IGNORE INTO experience_feedback(
                feedback_id, run_id, actor, verdict, confidence, evidence,
                scope, created_at, updated_at, valid_until
            )
            SELECT verifier_name, run_id, 'legacy', verdict, confidence,
                   evidence, scope, verified_at, verified_at, valid_until
            FROM verifier_results
            WHERE verifier_type='human';",
        )?;
        set_schema_version(conn, 37)?;
        version = 37;
    }
    if version < 38 {
        for (column, definition) in [
            ("task_signature_version", "INTEGER NOT NULL DEFAULT 1"),
            ("task_type", "TEXT NOT NULL DEFAULT 'general'"),
            ("task_family", "TEXT NOT NULL DEFAULT 'general_assistance'"),
            ("capability_tags_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("task_signature_hash", "TEXT NOT NULL DEFAULT ''"),
        ] {
            if !table_has_column(conn, "experience_runs", column)? {
                conn.execute(
                    &format!("ALTER TABLE experience_runs ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        if !table_has_column(conn, "skill_governance_policy", "utility_confidence_z")? {
            conn.execute(
                "ALTER TABLE skill_governance_policy
                 ADD COLUMN utility_confidence_z REAL NOT NULL DEFAULT 1.96",
                [],
            )?;
        }
        if !table_has_column(
            conn,
            "skill_governance_policy",
            "trial_promote_utility_lower_bound",
        )? {
            conn.execute(
                "ALTER TABLE skill_governance_policy
                 ADD COLUMN trial_promote_utility_lower_bound REAL NOT NULL DEFAULT 0.4",
                [],
            )?;
        }
        let mut stmt = conn.prepare(
            "SELECT run_id, objective, run_kind FROM experience_runs
             WHERE task_signature_hash=''",
        )?;
        let existing = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for (run_id, objective, run_kind) in existing {
            let signature = derive_task_signature(&objective, &run_kind);
            conn.execute(
                "UPDATE experience_runs SET task_signature_version=?2,
                    task_type=?3, task_family=?4, capability_tags_json=?5,
                    task_signature_hash=?6 WHERE run_id=?1",
                params![
                    run_id,
                    signature.version,
                    signature.task_type,
                    signature.task_family,
                    serde_json::to_string(&signature.capability_tags)
                        .unwrap_or_else(|_| "[]".into()),
                    signature.signature_hash
                ],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_experience_runs_task_signature
             ON experience_runs(task_type, task_family, started_at DESC)",
            [],
        )?;
        set_schema_version(conn, 38)?;
        version = 38;
    }
    if version < 39 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_failure_patterns (
                pattern_id TEXT PRIMARY KEY,
                skill_name TEXT NOT NULL,
                skill_version INTEGER NOT NULL,
                task_type TEXT NOT NULL,
                task_family TEXT NOT NULL,
                environment_fingerprint TEXT,
                tool_name TEXT,
                error_category TEXT NOT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0,
                recovery_successes INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'observed',
                cooldown_until TEXT,
                last_evidence TEXT,
                first_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, skill_version, task_family,
                       environment_fingerprint, tool_name, error_category)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_failure_patterns_lookup
                ON skill_failure_patterns(
                    skill_name, skill_version, task_family, state, updated_at DESC
                );
            CREATE TABLE IF NOT EXISTS skill_failure_pattern_evidence (
                pattern_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(pattern_id, run_id),
                FOREIGN KEY(pattern_id) REFERENCES skill_failure_patterns(pattern_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS experience_retrieval_rejections (
                querying_run_id TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                rejection_reason TEXT NOT NULL,
                relevance_score REAL NOT NULL,
                rejected_at TEXT NOT NULL,
                PRIMARY KEY(querying_run_id, source_run_id),
                FOREIGN KEY(querying_run_id) REFERENCES experience_runs(run_id),
                FOREIGN KEY(source_run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_rejection_query
                ON experience_retrieval_rejections(querying_run_id, rejected_at ASC);",
        )?;
        for (column, definition) in [
            ("failure_pattern_min_failures", "INTEGER NOT NULL DEFAULT 2"),
            (
                "failure_pattern_cooldown_hours",
                "INTEGER NOT NULL DEFAULT 24",
            ),
            (
                "failure_pattern_recovery_successes",
                "INTEGER NOT NULL DEFAULT 2",
            ),
        ] {
            if !table_has_column(conn, "skill_governance_policy", column)? {
                conn.execute(
                    &format!(
                        "ALTER TABLE skill_governance_policy ADD COLUMN {column} {definition}"
                    ),
                    [],
                )?;
            }
        }
        let policy = SkillGovernancePolicy::default();
        let historical = {
            let mut stmt = conn.prepare(
                "SELECT o.skill_name, o.skill_version, o.run_id,
                        r.task_type, r.task_family, r.environment_fingerprint,
                        json_extract(e.payload_json, '$.tool_name'),
                        COALESCE(e.evidence, o.evidence)
                 FROM skill_outcomes o
                 JOIN experience_runs r ON r.run_id=o.run_id
                 LEFT JOIN outcome_envelopes e ON e.run_id=o.run_id
                    AND e.verdict='failed' AND e.scope='tool_result'
                 WHERE o.verdict='failed'
                   AND o.attribution_confidence >= 0.999
                   AND o.verifier_type IN (
                     'deterministic','environmental','human','rule_based'
                   )
                   AND (o.valid_until IS NULL OR o.valid_until>?1)
                 ORDER BY o.created_at ASC",
            )?;
            let rows = stmt
                .query_map(params![chrono::Utc::now().to_rfc3339()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let now = chrono::Utc::now();
        let cooldown_until =
            (now + chrono::Duration::hours(policy.failure_pattern_cooldown_hours)).to_rfc3339();
        for (
            skill_name,
            skill_version,
            run_id,
            task_type,
            task_family,
            environment,
            tool_name,
            evidence,
        ) in historical
        {
            let category = classify_failure_category(evidence.as_deref());
            let canonical = format!(
                "{skill_name}\n{skill_version}\n{task_family}\n{}\n{}\n{category}",
                environment.as_deref().unwrap_or(""),
                tool_name.as_deref().unwrap_or("")
            );
            use sha2::{Digest, Sha256};
            let pattern_id = to_hex(&Sha256::digest(canonical.as_bytes()));
            conn.execute(
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
            if conn.execute(
                "INSERT OR IGNORE INTO skill_failure_pattern_evidence(
                    pattern_id, run_id, verdict, created_at
                 ) VALUES (?1,?2,'failed',?3)",
                params![pattern_id, run_id, now.to_rfc3339()],
            )? > 0
            {
                conn.execute(
                    "UPDATE skill_failure_patterns
                     SET failure_count=failure_count+1,
                         state=CASE WHEN failure_count+1>=?2
                                    THEN 'active' ELSE 'observed' END,
                         cooldown_until=CASE WHEN failure_count+1>=?2
                                    THEN ?3 ELSE NULL END,
                         updated_at=?4 WHERE pattern_id=?1",
                    params![
                        pattern_id,
                        policy.failure_pattern_min_failures,
                        cooldown_until,
                        now.to_rfc3339()
                    ],
                )?;
            }
        }
        conn.execute(
            "UPDATE skill_lifecycle
             SET previous_trusted_version=CASE WHEN state='trusted'
                    THEN active_version ELSE previous_trusted_version END,
                 state='degraded',
                 state_reason='historical active failure pattern backfilled',
                 updated_at=?1
             WHERE state NOT IN ('degraded','archived') AND EXISTS(
               SELECT 1 FROM skill_failure_patterns p
               WHERE p.skill_name=skill_lifecycle.skill_name
                 AND p.skill_version=skill_lifecycle.active_version
                 AND p.state='active'
             )",
            params![now.to_rfc3339()],
        )?;
        set_schema_version(conn, 39)?;
        version = 39;
    }
    if version < 40 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS experience_comparisons (
                comparison_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                skill_name TEXT NOT NULL,
                skill_version INTEGER NOT NULL,
                task_type TEXT NOT NULL,
                task_family TEXT NOT NULL,
                environment_fingerprint TEXT,
                success_run_id TEXT NOT NULL,
                failure_run_id TEXT NOT NULL,
                minimal_difference TEXT NOT NULL,
                counterexample TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(chat_id, skill_name, skill_version, task_family,
                       environment_fingerprint, success_run_id, failure_run_id),
                FOREIGN KEY(success_run_id) REFERENCES experience_runs(run_id),
                FOREIGN KEY(failure_run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_comparisons_skill
                ON experience_comparisons(skill_name, skill_version, created_at DESC);

            CREATE TABLE IF NOT EXISTS learning_claims (
                claim_id TEXT PRIMARY KEY,
                comparison_id TEXT NOT NULL,
                skill_name TEXT NOT NULL,
                base_version INTEGER NOT NULL,
                claim_version INTEGER NOT NULL,
                statement TEXT NOT NULL,
                applicability_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                counterexamples_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'candidate',
                supersedes_claim_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, claim_version),
                FOREIGN KEY(comparison_id) REFERENCES experience_comparisons(comparison_id),
                FOREIGN KEY(supersedes_claim_id) REFERENCES learning_claims(claim_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_claims_skill_status
                ON learning_claims(skill_name, status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS skill_candidates (
                candidate_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                skill_name TEXT NOT NULL,
                base_version INTEGER NOT NULL,
                candidate_version INTEGER NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'candidate',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(skill_name, candidate_version),
                FOREIGN KEY(claim_id) REFERENCES learning_claims(claim_id)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_candidates_status
                ON skill_candidates(status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS shadow_observations (
                candidate_id TEXT NOT NULL,
                pair_key TEXT NOT NULL,
                arm TEXT NOT NULL,
                run_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                cost_usd REAL NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                evidence TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY(candidate_id, pair_key, arm),
                FOREIGN KEY(candidate_id) REFERENCES skill_candidates(candidate_id),
                FOREIGN KEY(run_id) REFERENCES experience_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_shadow_observations_candidate
                ON shadow_observations(candidate_id, pair_key, arm);

            CREATE TABLE IF NOT EXISTS shadow_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE,
                sample_count INTEGER NOT NULL,
                baseline_passed INTEGER NOT NULL,
                candidate_passed INTEGER NOT NULL,
                baseline_utility_lower_bound REAL NOT NULL,
                candidate_utility_lower_bound REAL NOT NULL,
                baseline_cost_usd REAL NOT NULL,
                candidate_cost_usd REAL NOT NULL,
                baseline_duration_ms INTEGER NOT NULL,
                candidate_duration_ms INTEGER NOT NULL,
                regression_count INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(candidate_id) REFERENCES skill_candidates(candidate_id)
            );

            CREATE TABLE IF NOT EXISTS learning_journal_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                undo_action TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_learning_journal_created
                ON learning_journal_events(created_at DESC);",
        )?;
        for (column, definition) in [
            ("shadow_min_samples", "INTEGER NOT NULL DEFAULT 3"),
            (
                "shadow_promote_utility_margin",
                "REAL NOT NULL DEFAULT 0.05",
            ),
            ("shadow_max_cost_ratio", "REAL NOT NULL DEFAULT 1.2"),
            ("shadow_max_regressions", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !table_has_column(conn, "skill_governance_policy", column)? {
                conn.execute(
                    &format!(
                        "ALTER TABLE skill_governance_policy ADD COLUMN {column} {definition}"
                    ),
                    [],
                )?;
            }
        }
        let tx = conn.unchecked_transaction()?;
        let run_ids = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT run_id FROM skill_outcomes
                 WHERE attribution_confidence>=0.999
                   AND verifier_type IN (
                     'deterministic','environmental','human','rule_based'
                   )
                 ORDER BY created_at ASC",
            )?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for run_id in run_ids {
            refresh_comparative_reflections_for_run(&tx, &run_id)?;
        }
        tx.commit()?;
        set_schema_version(conn, 40)?;
        version = 40;
    }
    if version < 41 {
        // Repair databases whose recorded schema version advanced despite an
        // incomplete historical scheduled_tasks migration or restore.
        ensure_scheduled_tasks_schema(conn)?;
        set_schema_version(conn, 41)?;
        version = 41;
    }
    if version < 42 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS learning_tracks (
                track_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                objective TEXT NOT NULL,
                directions_json TEXT NOT NULL DEFAULT '[]',
                allowed_sources_json TEXT NOT NULL DEFAULT '[]',
                schedule TEXT NOT NULL,
                timezone TEXT NOT NULL,
                token_budget INTEGER NOT NULL DEFAULT 80000,
                max_sources INTEGER NOT NULL DEFAULT 20,
                promotion_mode TEXT NOT NULL DEFAULT 'propose',
                status TEXT NOT NULL DEFAULT 'active',
                next_run TEXT NOT NULL,
                last_run TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(chat_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_tracks_due
                ON learning_tracks(status, next_run);

            CREATE TABLE IF NOT EXISTS learning_epochs (
                epoch_id TEXT PRIMARY KEY,
                track_id TEXT NOT NULL,
                experience_run_id TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                report TEXT,
                candidate_id TEXT,
                error TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(track_id) REFERENCES learning_tracks(track_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_epochs_track
                ON learning_epochs(track_id, started_at DESC);

            CREATE TABLE IF NOT EXISTS learning_track_candidates (
                candidate_id TEXT PRIMARY KEY,
                epoch_id TEXT NOT NULL UNIQUE,
                skill_name TEXT NOT NULL,
                description TEXT NOT NULL,
                instructions TEXT NOT NULL,
                sources_json TEXT NOT NULL DEFAULT '[]',
                tests_json TEXT NOT NULL DEFAULT '[]',
                risk TEXT NOT NULL DEFAULT 'low',
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(epoch_id) REFERENCES learning_epochs(epoch_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_track_candidates_status
                ON learning_track_candidates(status, updated_at DESC);",
        )?;
        set_schema_version(conn, 42)?;
        version = 42;
    }
    if version < 43 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS learning_candidate_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'running',
                sample_count INTEGER NOT NULL DEFAULT 0,
                baseline_passed INTEGER NOT NULL DEFAULT 0,
                candidate_passed INTEGER NOT NULL DEFAULT 0,
                regression_count INTEGER NOT NULL DEFAULT 0,
                baseline_tokens INTEGER NOT NULL DEFAULT 0,
                candidate_tokens INTEGER NOT NULL DEFAULT 0,
                baseline_duration_ms INTEGER NOT NULL DEFAULT 0,
                candidate_duration_ms INTEGER NOT NULL DEFAULT 0,
                reason TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(candidate_id) REFERENCES learning_track_candidates(candidate_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_candidate_evaluations_status
                ON learning_candidate_evaluations(status, started_at DESC);

            CREATE TABLE IF NOT EXISTS learning_candidate_trials (
                trial_id TEXT PRIMARY KEY,
                evaluation_id TEXT NOT NULL,
                test_name TEXT NOT NULL,
                baseline_passed INTEGER NOT NULL,
                candidate_passed INTEGER NOT NULL,
                baseline_tokens INTEGER NOT NULL DEFAULT 0,
                candidate_tokens INTEGER NOT NULL DEFAULT 0,
                baseline_duration_ms INTEGER NOT NULL DEFAULT 0,
                candidate_duration_ms INTEGER NOT NULL DEFAULT 0,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(evaluation_id) REFERENCES learning_candidate_evaluations(evaluation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_candidate_trials_evaluation
                ON learning_candidate_trials(evaluation_id, created_at);",
        )?;
        set_schema_version(conn, 43)?;
        version = 43;
    }
    if version != SCHEMA_VERSION_CURRENT {
        set_schema_version(conn, SCHEMA_VERSION_CURRENT)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::storage::db::test_support::*;

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
        assert!(table_has_column(&conn, "sessions", "label").unwrap());
        assert!(table_has_column(&conn, "sessions", "thinking_level").unwrap());
        assert!(table_has_column(&conn, "sessions", "verbose_level").unwrap());
        assert!(table_has_column(&conn, "sessions", "reasoning_level").unwrap());
        assert!(table_has_column(&conn, "scheduled_tasks", "timezone").unwrap());

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
            if version >= 8 {
                conn.execute_batch(
                    "ALTER TABLE api_keys ADD COLUMN expires_at TEXT;
                     ALTER TABLE api_keys ADD COLUMN rotated_from_key_id INTEGER;",
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
            assert!(table_has_column(&conn, "sessions", "label").unwrap());
            assert!(table_has_column(&conn, "sessions", "thinking_level").unwrap());
            assert!(table_has_column(&conn, "sessions", "verbose_level").unwrap());
            assert!(table_has_column(&conn, "sessions", "reasoning_level").unwrap());
            assert!(table_has_column(&conn, "scheduled_tasks", "timezone").unwrap());
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
    fn test_current_version_repairs_incomplete_scheduled_tasks_schema() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_incomplete_scheduled_tasks_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("microclaw.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE scheduled_tasks (
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
             CREATE TABLE db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO db_meta(key, value) VALUES('schema_version', '40');",
        )
        .unwrap();
        drop(conn);

        let db = Database::new(dir.to_str().unwrap()).unwrap();
        let conn = db.lock_conn();
        for column in [
            "exit_criteria",
            "run_count",
            "max_runs",
            "not_after",
            "timezone",
        ] {
            assert!(
                table_has_column(&conn, "scheduled_tasks", column).unwrap(),
                "missing repaired scheduled_tasks.{column}"
            );
        }
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION_CURRENT);
        drop(conn);

        // Exercise the exact query shape that failed in production.
        assert!(db.get_tasks_for_chat(1).unwrap().is_empty());
        cleanup(&dir);
    }
}
