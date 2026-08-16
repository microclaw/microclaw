use super::*;

/// A row returned from the tool result cache lookup.
#[derive(Debug, Clone)]
pub struct CachedToolResult {
    pub tool_name: String,
    pub content: String,
    pub is_error: bool,
    pub metadata_json: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// Metadata for a stored tool-result artifact.
#[derive(Debug, Clone)]
pub struct ToolArtifactMeta {
    pub artifact_id: String,
    pub chat_id: i64,
    pub tool_name: String,
    pub total_chars: i64,
    pub created_at: String,
    pub expires_at: String,
}

impl Database {
    /// Look up a cached tool result by key; returns `None` if missing or
    /// past its TTL. Passing `now` as an RFC3339 string lets callers
    /// control "now" deterministically in tests.
    pub fn get_cached_tool_result(
        &self,
        cache_key: &str,
        now: &str,
    ) -> Result<Option<CachedToolResult>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT tool_name, result_content, is_error, metadata_json, created_at, expires_at
                 FROM tool_result_cache
                 WHERE cache_key = ?1 AND expires_at > ?2",
                params![cache_key, now],
                |r| {
                    Ok(CachedToolResult {
                        tool_name: r.get(0)?,
                        content: r.get(1)?,
                        is_error: r.get::<_, i64>(2)? != 0,
                        metadata_json: r.get::<_, Option<String>>(3)?,
                        created_at: r.get(4)?,
                        expires_at: r.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Insert or replace a cached tool result. Only non-error results
    /// should be cached in practice; the `is_error` flag is exposed so
    /// callers can choose a policy.
    pub fn put_cached_tool_result(
        &self,
        cache_key: &str,
        tool_name: &str,
        content: &str,
        is_error: bool,
        metadata_json: Option<&str>,
        expires_at: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO tool_result_cache
                (cache_key, tool_name, result_content, is_error, metadata_json, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(cache_key) DO UPDATE SET
                tool_name = excluded.tool_name,
                result_content = excluded.result_content,
                is_error = excluded.is_error,
                metadata_json = excluded.metadata_json,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at",
            params![cache_key, tool_name, content, is_error as i64, metadata_json, now, expires_at],
        )?;
        Ok(())
    }

    /// Delete all expired cache rows. Returns number of rows deleted.
    pub fn prune_tool_result_cache(&self, now: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM tool_result_cache WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
    }

    /// Persist a tool-result artifact (full content) so the agent can fetch
    /// slices later via `fetch_artifact`. The caller is responsible for
    /// generating a unique `artifact_id`.
    pub fn save_tool_artifact(
        &self,
        artifact_id: &str,
        chat_id: i64,
        tool_name: &str,
        content: &str,
        expires_at: &str,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let total_chars = content.chars().count() as i64;
        conn.execute(
            "INSERT INTO tool_result_artifacts
                (artifact_id, chat_id, tool_name, content, total_chars, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                artifact_id,
                chat_id,
                tool_name,
                content,
                total_chars,
                now,
                expires_at
            ],
        )?;
        Ok(())
    }

    /// Fetch a character-range slice of a stored artifact. Returns
    /// `(meta, slice, returned_chars)` if the artifact exists and is not
    /// expired. `offset` and `length` are interpreted as Unicode code
    /// points to keep the cap predictable across multi-byte content.
    pub fn get_tool_artifact_slice(
        &self,
        artifact_id: &str,
        offset: usize,
        length: usize,
        now: &str,
    ) -> Result<Option<(ToolArtifactMeta, String)>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT artifact_id, chat_id, tool_name, content, total_chars, created_at, expires_at
                 FROM tool_result_artifacts
                 WHERE artifact_id = ?1 AND expires_at > ?2",
                params![artifact_id, now],
                |r| {
                    let content: String = r.get(3)?;
                    Ok((
                        ToolArtifactMeta {
                            artifact_id: r.get(0)?,
                            chat_id: r.get(1)?,
                            tool_name: r.get(2)?,
                            total_chars: r.get(4)?,
                            created_at: r.get(5)?,
                            expires_at: r.get(6)?,
                        },
                        content,
                    ))
                },
            )
            .optional()?;
        let Some((meta, content)) = row else {
            return Ok(None);
        };
        let slice: String = content.chars().skip(offset).take(length).collect();
        Ok(Some((meta, slice)))
    }

    /// Delete expired artifact rows. Returns number of rows deleted.
    pub fn prune_tool_artifacts(&self, now: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute(
            "DELETE FROM tool_result_artifacts WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::test_support::*;

    #[test]
    fn test_tool_artifact_save_and_slice() {
        let (db, dir) = test_db();
        let now = chrono::Utc::now();
        let expires = (now + chrono::Duration::hours(1)).to_rfc3339();
        let body: String = "0123456789".repeat(20); // 200 chars
        db.save_tool_artifact("art_x", 42, "bash", &body, &expires)
            .unwrap();

        // First slice from offset 0
        let (meta, slice) = db
            .get_tool_artifact_slice("art_x", 0, 50, &now.to_rfc3339())
            .unwrap()
            .expect("artifact present");
        assert_eq!(meta.chat_id, 42);
        assert_eq!(meta.tool_name, "bash");
        assert_eq!(meta.total_chars, 200);
        assert_eq!(slice.chars().count(), 50);
        assert!(body.starts_with(&slice));

        // Slice past the end clamps to remaining
        let (_, tail) = db
            .get_tool_artifact_slice("art_x", 190, 50, &now.to_rfc3339())
            .unwrap()
            .unwrap();
        assert_eq!(tail.chars().count(), 10);

        // Expired artifact returns None
        let future = (now + chrono::Duration::hours(2)).to_rfc3339();
        let missing = db.get_tool_artifact_slice("art_x", 0, 10, &future).unwrap();
        assert!(missing.is_none());

        // Prune removes expired rows
        let pruned = db.prune_tool_artifacts(&future).unwrap();
        assert_eq!(pruned, 1);
        cleanup(&dir);
    }
}
