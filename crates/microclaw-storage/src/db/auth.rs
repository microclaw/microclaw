use super::*;

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

impl Database {
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
}

#[cfg(test)]
mod tests {
    use crate::db::test_support::*;

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
}
