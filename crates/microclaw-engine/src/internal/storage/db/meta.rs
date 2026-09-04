use super::*;

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

impl Database {
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

    /// Read a runtime key from the `db_meta` KV table (also used for
    /// schema_version/embedding_dim). Namespaced keys recommended.
    pub fn get_runtime_meta(&self, key: &str) -> Result<Option<String>, MicroClawError> {
        let conn = self.lock_conn();
        let value = conn
            .query_row("SELECT value FROM db_meta WHERE key = ?1", [key], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        Ok(value)
    }

    /// Upsert a runtime key in the `db_meta` KV table.
    pub fn set_runtime_meta(&self, key: &str, value: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO db_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    /// List runtime keys sharing a prefix (sorted by key).
    pub fn list_runtime_meta_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, MicroClawError> {
        let conn = self.lock_conn();
        let pattern = format!("{}%", prefix.replace('%', "\\%").replace('_', "\\_"));
        let mut stmt = conn
            .prepare("SELECT key, value FROM db_meta WHERE key LIKE ?1 ESCAPE '\\' ORDER BY key")?;
        let rows = stmt
            .query_map([&pattern], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a single runtime key; returns whether a row was removed.
    pub fn delete_runtime_meta(&self, key: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let n = conn.execute("DELETE FROM db_meta WHERE key = ?1", [key])?;
        Ok(n > 0)
    }

    /// Delete every runtime key sharing a prefix; returns removed count.
    pub fn delete_runtime_meta_prefix(&self, prefix: &str) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let pattern = format!("{}%", prefix.replace('%', "\\%").replace('_', "\\_"));
        let n = conn.execute(
            "DELETE FROM db_meta WHERE key LIKE ?1 ESCAPE '\\'",
            [&pattern],
        )?;
        Ok(n)
    }

    /// Completion-contract verdict tallies (verified, failed) recorded at
    /// or after `since` (RFC 3339). Verdicts are the `contract` events
    /// written when a sub-agent run's exit criteria are checked.
    pub fn contract_verdict_counts_since(&self, since: &str) -> Result<(i64, i64), MicroClawError> {
        let conn = self.lock_conn();
        let counts = conn.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN detail LIKE 'verified%' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN detail LIKE 'failed%' THEN 1 ELSE 0 END), 0)
             FROM subagent_events
             WHERE event_type = 'contract' AND created_at >= ?1",
            [since],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::storage::db::test_support::*;

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
}
