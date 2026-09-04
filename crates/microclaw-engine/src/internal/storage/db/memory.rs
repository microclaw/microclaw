use super::*;

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
    /// Optional RFC3339 timestamp at which this memory expires. NULL means
    /// the memory is durable; expired rows are filtered from retrieval and
    /// pruned by the reflector.
    pub expires_at: Option<String>,
}

/// A single triple in the temporal knowledge graph.
#[derive(Debug, Clone)]
pub struct KgTriple {
    pub id: i64,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub chat_id: Option<i64>,
    pub valid_from: String,
    pub valid_to: Option<String>,
    pub confidence: f64,
    pub source: String,
    pub source_memory_id: Option<i64>,
    pub created_at: String,
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

impl Database {
    /// Clear memory state for a chat without deleting chat/session/message history.
    /// This removes structured memories and reflector bookkeeping for the chat.
    pub fn clear_chat_memory(&self, chat_id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let mut affected = 0usize;
        affected += erase_chat_learning(&tx, chat_id)?;
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
        tx.commit()?;
        Ok(affected > 0)
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
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories
             WHERE (chat_id = ?1 OR chat_id IS NULL)
               AND is_archived = 0
               AND confidence >= 0.45
               AND (expires_at IS NULL OR expires_at > ?3)
             ORDER BY updated_at DESC
             LIMIT ?2",
        )?;
        let memories = stmt
            .query_map(params![chat_id, limit as i64, now], |row| {
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
                    expires_at: row.get(12)?,
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
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
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
                    expires_at: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(memories)
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
        let now = chrono::Utc::now().to_rfc3339();
        let mut sql = String::from(
            "SELECT id, chat_id, content, category, created_at, updated_at, embedding_model,
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
             FROM memories
             WHERE (chat_id = ?1 OR chat_id IS NULL)
               AND LOWER(content) LIKE ?2
               AND (expires_at IS NULL OR expires_at > ?4)",
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
            .query_map(params![chat_id, pattern, limit as i64, now], |row| {
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
                    expires_at: row.get(12)?,
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

    /// Set or clear the `expires_at` of a memory. Pass `None` to clear.
    pub fn set_memory_expires_at(
        &self,
        id: i64,
        expires_at: Option<&str>,
    ) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
            params![expires_at, id],
        )?;
        Ok(rows > 0)
    }

    /// Hard-delete memories whose `expires_at` is at or before `now`.
    /// Returns the number of rows deleted. Called from the reflector on its
    /// scheduled tick.
    pub fn prune_expired_memories(&self, now: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
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
             , confidence, source, last_seen_at, is_archived, archived_at, expires_at
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
                expires_at: row.get(12)?,
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
                    confidence, source, last_seen_at, is_archived, archived_at, expires_at
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
                    expires_at: row.get(12)?,
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

    /// Archive the lowest-confidence, least-recently-seen memories for a chat
    /// (or global if `chat_id` is None) when the count exceeds `max_entries`.
    /// Returns the number of memories archived.
    pub fn archive_excess_memories(
        &self,
        chat_id: Option<i64>,
        max_entries: usize,
    ) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let count: usize = if let Some(cid) = chat_id {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE is_archived = 0 AND chat_id = ?1",
                params![cid],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE is_archived = 0 AND chat_id IS NULL",
                [],
                |row| row.get(0),
            )?
        };
        if count <= max_entries {
            return Ok(0);
        }
        let excess = count - max_entries;
        let now = chrono::Utc::now().to_rfc3339();
        let rows = if let Some(cid) = chat_id {
            conn.execute(
                "UPDATE memories SET is_archived = 1, archived_at = ?1, updated_at = ?1
                 WHERE is_archived = 0 AND chat_id = ?2
                   AND id IN (
                     SELECT id FROM memories
                     WHERE is_archived = 0 AND chat_id = ?2
                     ORDER BY confidence ASC, COALESCE(last_seen_at, updated_at, created_at) ASC
                     LIMIT ?3
                   )",
                params![now, cid, excess],
            )?
        } else {
            conn.execute(
                "UPDATE memories SET is_archived = 1, archived_at = ?1, updated_at = ?1
                 WHERE is_archived = 0 AND chat_id IS NULL
                   AND id IN (
                     SELECT id FROM memories
                     WHERE is_archived = 0 AND chat_id IS NULL
                     ORDER BY confidence ASC, COALESCE(last_seen_at, updated_at, created_at) ASC
                     LIMIT ?2
                   )",
                params![now, excess],
            )?
        };
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

    // ── Knowledge Graph operations ──

    /// Insert a new knowledge graph triple.
    #[allow(clippy::too_many_arguments)]
    pub fn kg_insert_triple(
        &self,
        subject: &str,
        predicate: &str,
        object: &str,
        chat_id: Option<i64>,
        valid_from: &str,
        confidence: f64,
        source: &str,
        source_memory_id: Option<i64>,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO knowledge_graph (subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9)",
            params![
                subject,
                predicate,
                object,
                chat_id,
                valid_from,
                confidence.clamp(0.0, 1.0),
                source,
                source_memory_id,
                now
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Invalidate a triple by setting its valid_to timestamp.
    pub fn kg_invalidate_triple(&self, id: i64, valid_to: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let rows = conn.execute(
            "UPDATE knowledge_graph SET valid_to = ?1 WHERE id = ?2 AND valid_to IS NULL",
            params![valid_to, id],
        )?;
        Ok(rows > 0)
    }

    /// Query triples by subject, optionally filtered by a point-in-time (as_of).
    pub fn kg_query_subject(
        &self,
        subject: &str,
        chat_id: Option<i64>,
        as_of: Option<&str>,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        let conn = self.lock_conn();
        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<KgTriple> {
            Ok(KgTriple {
                id: row.get(0)?,
                subject: row.get(1)?,
                predicate: row.get(2)?,
                object: row.get(3)?,
                chat_id: row.get(4)?,
                valid_from: row.get(5)?,
                valid_to: row.get(6)?,
                confidence: row.get(7)?,
                source: row.get(8)?,
                source_memory_id: row.get(9)?,
                created_at: row.get(10)?,
            })
        };
        if let Some(ts) = as_of {
            let mut stmt = conn.prepare(
                "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
                 FROM knowledge_graph
                 WHERE LOWER(subject) = LOWER(?1)
                   AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
                   AND valid_from <= ?3
                   AND (valid_to IS NULL OR valid_to > ?3)
                 ORDER BY valid_from DESC",
            )?;
            let rows = stmt
                .query_map(params![subject, chat_id, ts], map_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
                 FROM knowledge_graph
                 WHERE LOWER(subject) = LOWER(?1)
                   AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
                   AND valid_to IS NULL
                 ORDER BY valid_from DESC",
            )?;
            let rows = stmt
                .query_map(params![subject, chat_id], map_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    /// Query triples by object (reverse lookup).
    pub fn kg_query_object(
        &self,
        object: &str,
        chat_id: Option<i64>,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
             FROM knowledge_graph
             WHERE LOWER(object) = LOWER(?1)
               AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
               AND valid_to IS NULL
             ORDER BY valid_from DESC",
        )?;
        let rows = stmt
            .query_map(params![object, chat_id], |row| {
                Ok(KgTriple {
                    id: row.get(0)?,
                    subject: row.get(1)?,
                    predicate: row.get(2)?,
                    object: row.get(3)?,
                    chat_id: row.get(4)?,
                    valid_from: row.get(5)?,
                    valid_to: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    source_memory_id: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Distinct active entities (subjects and objects) for a chat, used to find
    /// which graph nodes a query mentions so retrieval can be seeded from them.
    pub fn kg_distinct_entities(
        &self,
        chat_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<String>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT entity FROM (
                 SELECT subject AS entity FROM knowledge_graph
                 WHERE (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL) AND valid_to IS NULL
                 UNION
                 SELECT object AS entity FROM knowledge_graph
                 WHERE (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL) AND valid_to IS NULL
             )
             ORDER BY LENGTH(entity) DESC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![chat_id, limit as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Bounded breadth-first expansion of the knowledge graph from `seed`
    /// entities, returning the active triples reachable within `max_hops`. This
    /// is the graph-augmented retrieval primitive: seed from entities a query
    /// mentions, then pull in directly-connected facts (and their neighbours)
    /// so multi-hop context surfaces without the agent having to query the graph
    /// by hand. Bounded by `total_limit` triples and a per-hop frontier cap, so
    /// it stays cheap even on large graphs.
    pub fn kg_neighborhood(
        &self,
        chat_id: Option<i64>,
        seeds: &[String],
        max_hops: usize,
        total_limit: usize,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        if seeds.is_empty() || total_limit == 0 || max_hops == 0 {
            return Ok(Vec::new());
        }
        const FRONTIER_CAP: usize = 32;
        const PER_NODE_LIMIT: i64 = 8;
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
             FROM knowledge_graph
             WHERE (LOWER(subject) = LOWER(?1) OR LOWER(object) = LOWER(?1))
               AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
               AND valid_to IS NULL
             ORDER BY confidence DESC
             LIMIT ?3",
        )?;
        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<KgTriple> {
            Ok(KgTriple {
                id: row.get(0)?,
                subject: row.get(1)?,
                predicate: row.get(2)?,
                object: row.get(3)?,
                chat_id: row.get(4)?,
                valid_from: row.get(5)?,
                valid_to: row.get(6)?,
                confidence: row.get(7)?,
                source: row.get(8)?,
                source_memory_id: row.get(9)?,
                created_at: row.get(10)?,
            })
        };

        let mut visited_entities: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut seen_triples: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut frontier: Vec<String> = Vec::new();
        for s in seeds {
            let lc = s.to_lowercase();
            if visited_entities.insert(lc) {
                frontier.push(s.clone());
            }
        }
        let mut out: Vec<KgTriple> = Vec::new();

        for _hop in 0..max_hops {
            if out.len() >= total_limit || frontier.is_empty() {
                break;
            }
            frontier.truncate(FRONTIER_CAP);
            let mut next: Vec<String> = Vec::new();
            for entity in &frontier {
                let rows = stmt
                    .query_map(params![entity, chat_id, PER_NODE_LIMIT], map_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                for t in rows {
                    if !seen_triples.insert(t.id) {
                        continue;
                    }
                    for endpoint in [&t.subject, &t.object] {
                        let lc = endpoint.to_lowercase();
                        if visited_entities.insert(lc) {
                            next.push(endpoint.clone());
                        }
                    }
                    out.push(t);
                    if out.len() >= total_limit {
                        break;
                    }
                }
                if out.len() >= total_limit {
                    break;
                }
            }
            frontier = next;
        }

        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(total_limit);
        Ok(out)
    }

    /// Get a timeline of all triples for a subject, including invalidated ones.
    pub fn kg_timeline(
        &self,
        subject: &str,
        chat_id: Option<i64>,
    ) -> Result<Vec<KgTriple>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, chat_id, valid_from, valid_to, confidence, source, source_memory_id, created_at
             FROM knowledge_graph
             WHERE LOWER(subject) = LOWER(?1)
               AND (?2 IS NULL OR chat_id = ?2 OR chat_id IS NULL)
             ORDER BY valid_from ASC",
        )?;
        let rows = stmt
            .query_map(params![subject, chat_id], |row| {
                Ok(KgTriple {
                    id: row.get(0)?,
                    subject: row.get(1)?,
                    predicate: row.get(2)?,
                    object: row.get(3)?,
                    chat_id: row.get(4)?,
                    valid_from: row.get(5)?,
                    valid_to: row.get(6)?,
                    confidence: row.get(7)?,
                    source: row.get(8)?,
                    source_memory_id: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get knowledge graph stats (total triples, active, invalidated).
    pub fn kg_stats(&self, chat_id: Option<i64>) -> Result<(usize, usize, usize), MicroClawError> {
        let conn = self.lock_conn();
        let total: usize = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_graph WHERE (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL)",
            params![chat_id],
            |row| row.get(0),
        )?;
        let active: usize = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_graph WHERE valid_to IS NULL AND (?1 IS NULL OR chat_id = ?1 OR chat_id IS NULL)",
            params![chat_id],
            |row| row.get(0),
        )?;
        Ok((total, active, total.saturating_sub(active)))
    }

    /// Delete oldest invalidated triples when count exceeds max_triples for a chat.
    /// If still over limit after pruning invalidated, also deletes oldest active triples by confidence.
    pub fn kg_prune_excess(
        &self,
        chat_id: i64,
        max_triples: usize,
    ) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let count: usize = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_graph WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get(0),
        )?;
        if count <= max_triples {
            return Ok(0);
        }
        let excess = count - max_triples;
        // First: delete invalidated triples (oldest first)
        let deleted_invalidated = conn.execute(
            "DELETE FROM knowledge_graph WHERE id IN (
                SELECT id FROM knowledge_graph
                WHERE chat_id = ?1 AND valid_to IS NOT NULL
                ORDER BY created_at ASC
                LIMIT ?2
            )",
            params![chat_id, excess],
        )?;
        let remaining_excess = excess.saturating_sub(deleted_invalidated);
        if remaining_excess == 0 {
            return Ok(deleted_invalidated);
        }
        // Still over: delete lowest-confidence active triples
        let deleted_active = conn.execute(
            "DELETE FROM knowledge_graph WHERE id IN (
                SELECT id FROM knowledge_graph
                WHERE chat_id = ?1 AND valid_to IS NULL
                ORDER BY confidence ASC, created_at ASC
                LIMIT ?2
            )",
            params![chat_id, remaining_excess],
        )?;
        Ok(deleted_invalidated + deleted_active)
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
    use crate::internal::storage::db::test_support::*;

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
    fn test_kg_neighborhood_bounded_multihop_expansion() {
        let (db, dir) = test_db();
        let chat = Some(7i64);
        let vf = "2026-01-01T00:00:00Z";
        // Alice -works_at-> Acme -located_in-> Berlin ; plus a noise edge.
        db.kg_insert_triple("Alice", "works_at", "Acme", chat, vf, 0.9, "test", None)
            .unwrap();
        db.kg_insert_triple("Acme", "located_in", "Berlin", chat, vf, 0.8, "test", None)
            .unwrap();
        db.kg_insert_triple(
            "Berlin",
            "capital_of",
            "Germany",
            chat,
            vf,
            0.7,
            "test",
            None,
        )
        .unwrap();
        db.kg_insert_triple("Zoe", "likes", "Tea", chat, vf, 0.6, "test", None)
            .unwrap();

        // Distinct entities should include all nodes, longest-first.
        let ents = db.kg_distinct_entities(chat, 100).unwrap();
        assert!(ents.iter().any(|e| e == "Acme"));
        assert!(ents.iter().any(|e| e == "Germany"));

        // 1 hop from Alice reaches the works_at edge but not located_in.
        let one = db
            .kg_neighborhood(chat, &["Alice".to_string()], 1, 10)
            .unwrap();
        assert!(one.iter().any(|t| t.predicate == "works_at"));
        assert!(!one.iter().any(|t| t.predicate == "located_in"));

        // 2 hops from Alice pulls in Acme's edges (multi-hop), but never Zoe's.
        let two = db
            .kg_neighborhood(chat, &["Alice".to_string()], 2, 10)
            .unwrap();
        assert!(two.iter().any(|t| t.predicate == "located_in"));
        assert!(!two.iter().any(|t| t.subject == "Zoe"));

        // total_limit is respected.
        let capped = db
            .kg_neighborhood(chat, &["Alice".to_string()], 3, 1)
            .unwrap();
        assert_eq!(capped.len(), 1);

        // Empty seeds → empty result, no panic.
        assert!(db.kg_neighborhood(chat, &[], 2, 10).unwrap().is_empty());
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
    fn test_memory_ttl_filters_and_prunes() {
        let (db, dir) = test_db();
        let durable = db
            .insert_memory(Some(7), "durable fact", "KNOWLEDGE")
            .unwrap();
        let expiring = db
            .insert_memory(Some(7), "transient fact", "KNOWLEDGE")
            .unwrap();
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

        // Future expiry — still surfaced in retrieval.
        db.set_memory_expires_at(durable, Some(&future)).unwrap();
        // Past expiry — gets filtered from retrieval right away.
        db.set_memory_expires_at(expiring, Some(&past)).unwrap();

        let ctx = db.get_memories_for_context(7, 50).unwrap();
        let ids: Vec<i64> = ctx.iter().map(|m| m.id).collect();
        assert!(ids.contains(&durable), "durable memory should be visible");
        assert!(
            !ids.contains(&expiring),
            "expired memory must not appear in context retrieval"
        );

        // Search also filters.
        let hits = db.search_memories(7, "fact", 50).unwrap();
        assert!(hits.iter().all(|m| m.id != expiring));

        // Prune deletes the row.
        let now = chrono::Utc::now().to_rfc3339();
        let pruned = db.prune_expired_memories(&now).unwrap();
        assert_eq!(pruned, 1);
        assert!(db.get_memory_by_id(expiring).unwrap().is_none());
        assert!(db.get_memory_by_id(durable).unwrap().is_some());
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
