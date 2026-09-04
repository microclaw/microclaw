use super::*;

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

impl Database {
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
}

#[cfg(test)]
mod tests {
    use crate::internal::storage::db::test_support::*;

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
}
