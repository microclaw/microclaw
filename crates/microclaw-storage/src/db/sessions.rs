use super::*;

#[derive(Debug, Clone, Default)]
pub struct SessionSettings {
    pub label: Option<String>,
    pub thinking_level: Option<String>,
    pub verbose_level: Option<String>,
    pub reasoning_level: Option<String>,
}

pub type SessionMetaRow = (String, String, Option<String>, Option<i64>);

pub type SessionTreeRow = (i64, Option<String>, Option<i64>, String);

impl Database {
    pub fn save_session(&self, chat_id: i64, messages_json: &str) -> Result<(), MicroClawError> {
        self.save_session_with_meta(chat_id, messages_json, None, None, None)
    }

    pub fn save_session_with_meta(
        &self,
        chat_id: i64,
        messages_json: &str,
        parent_session_key: Option<&str>,
        fork_point: Option<i64>,
        skill_envs_json: Option<&str>,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (chat_id, messages_json, updated_at, parent_session_key, fork_point, skill_envs_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
                messages_json = ?2,
                updated_at = ?3,
                parent_session_key = COALESCE(?4, parent_session_key),
                fork_point = COALESCE(?5, fork_point),
                skill_envs_json = COALESCE(?6, skill_envs_json)",
            params![chat_id, messages_json, now, parent_session_key, fork_point, skill_envs_json],
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

    /// Overwrite the session label for a chat. No-op if the chat has no
    /// session row yet. Used by the title generator background task.
    pub fn set_session_label(&self, chat_id: i64, label: &str) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE sessions SET label = ?1 WHERE chat_id = ?2",
            params![label, chat_id],
        )?;
        Ok(())
    }

    /// Return the current session label + message count for a chat. Used
    /// to decide whether the title generator should run.
    pub fn get_session_label_and_length(
        &self,
        chat_id: i64,
    ) -> Result<Option<(Option<String>, usize)>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn
            .query_row(
                "SELECT label, messages_json FROM sessions WHERE chat_id = ?1",
                params![chat_id],
                |row| {
                    let label: Option<String> = row.get(0)?;
                    let json: String = row.get(1)?;
                    Ok((label, json))
                },
            )
            .optional()?;
        let Some((label, json)) = result else {
            return Ok(None);
        };
        let count = serde_json::from_str::<Vec<serde_json::Value>>(&json)
            .map(|v| v.len())
            .unwrap_or(0);
        Ok(Some((label, count)))
    }

    pub fn save_session_settings(
        &self,
        chat_id: i64,
        settings: &SessionSettings,
    ) -> Result<(), MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (
                chat_id,
                messages_json,
                updated_at,
                label,
                thinking_level,
                verbose_level,
                reasoning_level
             )
             VALUES (?1, '[]', ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
                updated_at = excluded.updated_at,
                label = COALESCE(excluded.label, sessions.label),
                thinking_level = COALESCE(excluded.thinking_level, sessions.thinking_level),
                verbose_level = COALESCE(excluded.verbose_level, sessions.verbose_level),
                reasoning_level = COALESCE(excluded.reasoning_level, sessions.reasoning_level)",
            params![
                chat_id,
                now,
                settings.label,
                settings.thinking_level,
                settings.verbose_level,
                settings.reasoning_level
            ],
        )?;
        Ok(())
    }

    pub fn load_session_settings(
        &self,
        chat_id: i64,
    ) -> Result<Option<SessionSettings>, MicroClawError> {
        let conn = self.lock_conn();
        let result = conn.query_row(
            "SELECT label, thinking_level, verbose_level, reasoning_level
             FROM sessions
             WHERE chat_id = ?1",
            params![chat_id],
            |row| {
                Ok(SessionSettings {
                    label: row.get::<_, Option<String>>(0)?,
                    thinking_level: row.get::<_, Option<String>>(1)?,
                    verbose_level: row.get::<_, Option<String>>(2)?,
                    reasoning_level: row.get::<_, Option<String>>(3)?,
                })
            },
        );
        match result {
            Ok(settings) => Ok(Some(settings)),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::*;

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
    fn test_save_and_load_session_settings() {
        let (db, dir) = test_db();
        let settings = SessionSettings {
            label: Some("Ops".into()),
            thinking_level: Some("high".into()),
            verbose_level: Some("full".into()),
            reasoning_level: Some("stream".into()),
        };
        db.save_session_settings(100, &settings).unwrap();

        let loaded = db.load_session_settings(100).unwrap().unwrap();
        assert_eq!(loaded.label.as_deref(), Some("Ops"));
        assert_eq!(loaded.thinking_level.as_deref(), Some("high"));
        assert_eq!(loaded.verbose_level.as_deref(), Some("full"));
        assert_eq!(loaded.reasoning_level.as_deref(), Some("stream"));

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
}
