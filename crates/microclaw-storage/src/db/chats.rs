use super::*;

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
    pub session_label: Option<String>,
    pub chat_type: String,
    pub last_message_time: String,
    pub last_message_preview: Option<String>,
}

impl Database {
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
                channel = COALESCE(channel, ?5),
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

    pub fn find_chat_id(
        &self,
        channel: &str,
        external_chat_id: &str,
    ) -> Result<Option<i64>, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT chat_id FROM chats WHERE channel = ?1 AND external_chat_id = ?2 LIMIT 1",
            params![channel, external_chat_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(Into::into)
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

    pub fn store_message_if_new(&self, msg: &StoredMessage) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let affected = conn.execute(
            "INSERT OR IGNORE INTO messages (id, chat_id, sender_name, content, is_from_bot, timestamp)
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
        Ok(affected > 0)
    }

    pub fn message_exists(&self, chat_id: i64, message_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let exists = conn
            .query_row(
                "SELECT 1 FROM messages WHERE chat_id = ?1 AND id = ?2 LIMIT 1",
                params![chat_id, message_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
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
                s.label,
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
             LEFT JOIN sessions s ON s.chat_id = c.chat_id
             WHERE c.chat_type = ?1
             ORDER BY c.last_message_time DESC
             LIMIT ?2",
        )?;
        let chats = stmt
            .query_map(params![chat_type, limit as i64], |row| {
                Ok(ChatSummary {
                    chat_id: row.get(0)?,
                    chat_title: row.get(1)?,
                    session_label: row.get(2)?,
                    chat_type: row.get(3)?,
                    last_message_time: row.get(4)?,
                    last_message_preview: row.get(5)?,
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
                s.label,
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
             LEFT JOIN sessions s ON s.chat_id = c.chat_id
             ORDER BY c.last_message_time DESC
             LIMIT ?1",
        )?;
        let chats = stmt
            .query_map(params![limit as i64], |row| {
                Ok(ChatSummary {
                    chat_id: row.get(0)?,
                    chat_title: row.get(1)?,
                    session_label: row.get(2)?,
                    chat_type: row.get(3)?,
                    last_message_time: row.get(4)?,
                    last_message_preview: row.get(5)?,
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

    /// Clear all resettable chat state without deleting chat metadata or memories.
    /// This removes resumable session state, historical messages, and scheduled task state.
    pub fn clear_chat_context(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;
        affected += tx.execute(
            "DELETE FROM task_run_logs WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM scheduled_task_dlq WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute(
            "DELETE FROM scheduled_tasks WHERE chat_id = ?1",
            params![chat_id],
        )?;
        affected += tx.execute("DELETE FROM sessions WHERE chat_id = ?1", params![chat_id])?;
        affected += tx.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    /// Clear conversational context for a chat while preserving scheduled task state.
    /// This removes resumable session state and historical messages only.
    pub fn clear_chat_conversation(&self, chat_id: i64) -> Result<bool, MicroClawError> {
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

        affected += erase_chat_learning(&tx, chat_id)?;
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

    /// Full-text search over stored messages using the SQLite FTS5 index.
    ///
    /// `query` must be a valid FTS5 match expression (simple words are OK,
    /// e.g. `"rust async"`). Returns ranked matches newest-first for
    /// equally-ranked rows. When `chat_id` is `Some`, the search is scoped to
    /// that chat; otherwise it spans all chats. When `since` is `Some`, only
    /// messages with timestamp >= that value are returned. Results are
    /// truncated to `limit` rows.
    pub fn search_messages_fts(
        &self,
        query: &str,
        chat_id: Option<i64>,
        since: Option<&str>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, MicroClawError> {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, 200) as i64;
        let conn = self.lock_conn();

        let mut sql = String::from(
            "SELECT m.id, m.chat_id, m.sender_name, m.content, m.is_from_bot, m.timestamp
             FROM messages_fts f
             JOIN messages m ON m.id = f.message_id AND m.chat_id = f.chat_id
             WHERE f.content MATCH ?1",
        );
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(query.to_string())];
        if let Some(cid) = chat_id {
            sql.push_str(" AND m.chat_id = ?");
            sql.push_str(&(binds.len() + 1).to_string());
            binds.push(Box::new(cid));
        }
        if let Some(ts) = since {
            sql.push_str(" AND m.timestamp >= ?");
            sql.push_str(&(binds.len() + 1).to_string());
            binds.push(Box::new(ts.to_string()));
        }
        sql.push_str(" ORDER BY bm25(messages_fts), m.timestamp DESC LIMIT ?");
        sql.push_str(&(binds.len() + 1).to_string());
        binds.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql)?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let messages = stmt
            .query_map(
                rusqlite::params_from_iter(bind_refs.iter().copied()),
                |row| {
                    Ok(StoredMessage {
                        id: row.get(0)?,
                        chat_id: row.get(1)?,
                        sender_name: row.get(2)?,
                        content: row.get(3)?,
                        is_from_bot: row.get::<_, i32>(4)? != 0,
                        timestamp: row.get(5)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    /// Total number of stored messages in a chat (both sides). Used as a cheap
    /// proxy for how well the bot "knows" this person.
    pub fn count_messages_for_chat(&self, chat_id: i64) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
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

    /// Chats whose most recent message is older than `cutoff` (i.e. idle since
    /// then). Only chats that have ever had a message are returned.
    pub fn list_idle_chats(&self, cutoff: &str, limit: usize) -> Result<Vec<i64>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT chat_id FROM messages
             GROUP BY chat_id
             HAVING MAX(timestamp) < ?1
             LIMIT ?2",
        )?;
        let ids = stmt
            .query_map(params![cutoff, limit.max(1) as i64], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::*;

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
    fn test_search_messages_fts_basic() {
        let (db, dir) = test_db();
        let now = chrono::Utc::now();
        let messages = [
            ("chat-1", 101, "alice", "Rust async futures are awesome"),
            ("chat-2", 101, "bot", "I agree, tokio makes them easy"),
            (
                "chat-3",
                101,
                "alice",
                "Let's talk about JavaScript promises instead",
            ),
            ("chat-4", 202, "bob", "Discussing Rust borrow checker"),
        ];
        for (i, (id, chat, sender, content)) in messages.iter().enumerate() {
            let msg = StoredMessage {
                id: (*id).into(),
                chat_id: *chat,
                sender_name: (*sender).into(),
                content: (*content).into(),
                is_from_bot: *sender == "bot",
                timestamp: (now + chrono::Duration::seconds(i as i64)).to_rfc3339(),
            };
            db.store_message(&msg).unwrap();
        }

        let rust_hits = db.search_messages_fts("rust", None, None, 10).unwrap();
        assert!(rust_hits.len() >= 2, "expected at least 2 rust matches");
        assert!(rust_hits
            .iter()
            .all(|m| m.content.to_lowercase().contains("rust")));

        let scoped = db.search_messages_fts("rust", Some(101), None, 10).unwrap();
        assert!(scoped.iter().all(|m| m.chat_id == 101));

        let empty = db.search_messages_fts("", None, None, 10).unwrap();
        assert!(empty.is_empty());

        let no_match = db
            .search_messages_fts("nothingmatchesthis", None, None, 10)
            .unwrap();
        assert!(no_match.is_empty());

        // Delete and confirm the FTS row is also removed via trigger.
        {
            let conn = db.lock_conn();
            conn.execute(
                "DELETE FROM messages WHERE id = ?1 AND chat_id = ?2",
                params!["chat-1", 101i64],
            )
            .unwrap();
        }
        let after_delete = db.search_messages_fts("awesome", None, None, 10).unwrap();
        assert!(after_delete.is_empty());

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
    fn test_message_exists() {
        let (db, dir) = test_db();
        assert!(!db.message_exists(100, "msg1").unwrap());

        db.store_message(&StoredMessage {
            id: "msg1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:00Z".into(),
        })
        .unwrap();

        assert!(db.message_exists(100, "msg1").unwrap());
        assert!(!db.message_exists(100, "msg2").unwrap());
        assert!(!db.message_exists(200, "msg1").unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_store_message_if_new() {
        let (db, dir) = test_db();
        let msg = StoredMessage {
            id: "msg-new".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:00Z".into(),
        };
        assert!(db.store_message_if_new(&msg).unwrap());
        assert!(!db.store_message_if_new(&msg).unwrap());
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
    fn test_clear_chat_memory_removes_memories_but_keeps_conversation() {
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

        assert!(db.clear_chat_memory(100).unwrap());
        assert!(db.search_memories(100, "Rust", 10).unwrap().is_empty());
        assert!(db.load_session(100).unwrap().is_some());
        assert!(!db.get_recent_messages(100, 10).unwrap().is_empty());
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
        assert_eq!(db.find_chat_id("telegram", "12345").unwrap(), Some(tg));
        assert_eq!(db.find_chat_id("discord", "12345").unwrap(), Some(discord));
        assert_eq!(db.find_chat_id("work", "12345").unwrap(), None);
        assert_eq!(
            db.get_chat_external_id(discord).unwrap().as_deref(),
            Some("12345")
        );

        cleanup(&dir);
    }

    #[test]
    fn test_upsert_chat_preserves_existing_channel_identity() {
        let (db, dir) = test_db();

        let scoped_chat_id = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();

        db.upsert_chat(scoped_chat_id, Some("Updated title"), "telegram_private")
            .unwrap();

        assert_eq!(
            db.get_chat_channel(scoped_chat_id).unwrap().as_deref(),
            Some("telegram.btcpos")
        );
        assert_eq!(
            db.get_chat_external_id(scoped_chat_id).unwrap().as_deref(),
            Some("12345")
        );

        let scoped_again = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        assert_eq!(scoped_chat_id, scoped_again);

        cleanup(&dir);
    }

    #[test]
    fn test_resolve_or_create_chat_id_scopes_same_external_id_by_channel() {
        let (db, dir) = test_db();

        let default_tg = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        let scoped_tg = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();

        assert_ne!(default_tg, scoped_tg);

        let default_tg_again = db
            .resolve_or_create_chat_id(
                "telegram",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();
        let scoped_tg_again = db
            .resolve_or_create_chat_id(
                "telegram.btcpos",
                "12345",
                Some("telegram-12345"),
                "telegram_private",
            )
            .unwrap();

        assert_eq!(default_tg, default_tg_again);
        assert_eq!(scoped_tg, scoped_tg_again);

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
    fn test_list_idle_chats() {
        let (db, dir) = test_db();
        // Chat 1: last message long ago (idle). Chat 2: recent (active).
        db.store_message(&StoredMessage {
            id: "old".into(),
            chat_id: 1,
            sender_name: "u".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2020-01-01T00:00:00Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "new".into(),
            chat_id: 2,
            sender_name: "u".into(),
            content: "hi".into(),
            is_from_bot: false,
            timestamp: "2099-01-01T00:00:00Z".into(),
        })
        .unwrap();
        let idle = db.list_idle_chats("2030-01-01T00:00:00Z", 50).unwrap();
        assert!(idle.contains(&1));
        assert!(!idle.contains(&2));

        // Familiarity proxy: message counts per chat.
        assert_eq!(db.count_messages_for_chat(1).unwrap(), 1);
        assert_eq!(db.count_messages_for_chat(2).unwrap(), 1);
        assert_eq!(db.count_messages_for_chat(999).unwrap(), 0);
        cleanup(&dir);
    }
}
