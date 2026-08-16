use super::*;

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

/// Genesis link for the tamper-evident audit hash chain — the `prev_hash` of the
/// first sealed entry.
pub(crate) const AUDIT_GENESIS_HASH: &str = "GENESIS";

/// Lowercase hex of a byte slice (avoids pulling in the `hex` crate).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compute the sealing hash for an audit entry: SHA-256 over the previous
/// entry's hash followed by this entry's content fields, each `\x1f`-terminated
/// so field boundaries can't be ambiguous. The chain link in `prev_hash` makes
/// deletion or reordering detectable; covering every field makes in-place edits
/// detectable.
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_entry_hash(
    prev_hash: &str,
    kind: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    status: &str,
    detail: Option<&str>,
    created_at: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for field in [
        prev_hash,
        kind,
        actor,
        action,
        target.unwrap_or(""),
        status,
        detail.unwrap_or(""),
        created_at,
    ] {
        h.update(field.as_bytes());
        h.update([0x1f]);
    }
    to_hex(&h.finalize())
}

/// A sealed audit row as read for chain verification: id + content fields +
/// `prev_hash` + `entry_hash`.
pub(crate) type AuditChainRow = (
    i64,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
);

/// Result of verifying the audit hash chain.
#[derive(Debug, Clone)]
pub struct AuditChainStatus {
    /// Number of sealed (hash-bearing) entries inspected.
    pub sealed_entries: usize,
    /// Whether the chain is fully intact.
    pub intact: bool,
    /// The `id` of the first entry where verification failed, if any.
    pub broken_at: Option<i64>,
    /// Human-readable reason for the break, if any.
    pub reason: Option<String>,
}

impl Database {
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
        // Seal the entry into the hash chain. Reading the latest sealed hash and
        // inserting happen under the same connection lock, so concurrent callers
        // can't race the chain.
        let prev_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM audit_logs
                 WHERE entry_hash IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| AUDIT_GENESIS_HASH.to_string());
        let entry_hash = audit_entry_hash(
            &prev_hash, kind, actor, action, target, status, detail, &now,
        );
        conn.execute(
            "INSERT INTO audit_logs(kind, actor, action, target, status, detail, created_at, prev_hash, entry_hash)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![kind, actor, action, target, status, detail, now, prev_hash, entry_hash],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Verify the tamper-evident audit hash chain. Walks all sealed entries in
    /// `id` order, checking that each links to the previous (`prev_hash`) and
    /// that its `entry_hash` still matches its content. Returns the first break,
    /// if any. Unsealed legacy rows (NULL `entry_hash`) are ignored.
    pub fn verify_audit_chain(&self) -> Result<AuditChainStatus, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, kind, actor, action, target, status, detail, created_at, prev_hash, entry_hash
             FROM audit_logs
             WHERE entry_hash IS NOT NULL
             ORDER BY id ASC",
        )?;
        // Collect first so the statement borrow is released before we iterate.
        let rows: Vec<AuditChainRow> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut expected_prev = AUDIT_GENESIS_HASH.to_string();
        let mut sealed = 0usize;
        for (id, kind, actor, action, target, status, detail, created_at, prev_hash, entry_hash) in
            &rows
        {
            sealed += 1;
            let prev = prev_hash.as_deref().unwrap_or("");
            if prev != expected_prev {
                return Ok(AuditChainStatus {
                    sealed_entries: sealed,
                    intact: false,
                    broken_at: Some(*id),
                    reason: Some(
                        "prev_hash does not link to the previous entry (an entry was deleted, inserted, or reordered)".to_string(),
                    ),
                });
            }
            let recomputed = audit_entry_hash(
                prev,
                kind,
                actor,
                action,
                target.as_deref(),
                status,
                detail.as_deref(),
                created_at,
            );
            if &recomputed != entry_hash {
                return Ok(AuditChainStatus {
                    sealed_entries: sealed,
                    intact: false,
                    broken_at: Some(*id),
                    reason: Some(
                        "entry_hash does not match content (an entry was modified)".to_string(),
                    ),
                });
            }
            expected_prev = entry_hash.clone();
        }

        Ok(AuditChainStatus {
            sealed_entries: sealed,
            intact: true,
            broken_at: None,
            reason: None,
        })
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

    /// Count audit-chain events of one kind recorded at or after `since`.
    pub fn count_audit_events_since(&self, kind: &str, since: &str) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE kind = ?1 AND created_at >= ?2",
            [kind, since],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::*;

    #[test]
    fn audit_chain_intact_after_appends() {
        let (db, dir) = test_db();
        db.log_audit_event("auth", "alice", "login", None, "ok", None)
            .unwrap();
        db.log_audit_event(
            "tool",
            "bot",
            "web_fetch",
            Some("https://x"),
            "ok",
            Some("200"),
        )
        .unwrap();
        db.log_audit_event("auth", "alice", "logout", None, "ok", None)
            .unwrap();
        let status = db.verify_audit_chain().unwrap();
        assert!(status.intact, "reason: {:?}", status.reason);
        assert_eq!(status.sealed_entries, 3);
        assert_eq!(status.broken_at, None);
        cleanup(&dir);
    }

    #[test]
    fn audit_chain_detects_modification() {
        let (db, dir) = test_db();
        db.log_audit_event("auth", "alice", "login", None, "ok", None)
            .unwrap();
        let id = db
            .log_audit_event("tool", "bot", "web_fetch", Some("https://x"), "ok", None)
            .unwrap();
        db.log_audit_event("auth", "alice", "logout", None, "ok", None)
            .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute(
                "UPDATE audit_logs SET status='tampered' WHERE id=?1",
                params![id],
            )
            .unwrap();
        }
        let status = db.verify_audit_chain().unwrap();
        assert!(!status.intact);
        assert_eq!(status.broken_at, Some(id));
        assert!(status.reason.unwrap().contains("modified"));
        cleanup(&dir);
    }

    #[test]
    fn audit_chain_detects_deletion() {
        let (db, dir) = test_db();
        db.log_audit_event("auth", "alice", "login", None, "ok", None)
            .unwrap();
        let id = db
            .log_audit_event("tool", "bot", "web_fetch", Some("https://x"), "ok", None)
            .unwrap();
        db.log_audit_event("auth", "alice", "logout", None, "ok", None)
            .unwrap();
        {
            let conn = db.lock_conn();
            conn.execute("DELETE FROM audit_logs WHERE id=?1", params![id])
                .unwrap();
        }
        let status = db.verify_audit_chain().unwrap();
        assert!(!status.intact);
        assert!(status.broken_at.is_some());
        assert!(status.reason.unwrap().contains("deleted"));
        cleanup(&dir);
    }
}
