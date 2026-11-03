use super::*;

/// A Desktop client (or any other device) that paired with this Server and
/// holds a revocable device token. Only the token hash is stored.
#[derive(Debug, Clone)]
pub struct PairedDeviceRecord {
    pub id: i64,
    pub device_id: String,
    pub label: String,
    pub platform: Option<String>,
    pub prefix: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl Database {
    pub fn create_paired_device(
        &self,
        device_id: &str,
        label: &str,
        platform: Option<&str>,
        token_hash: &str,
        prefix: &str,
    ) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO paired_devices(device_id, label, platform, token_hash, prefix, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![device_id, label, platform, token_hash, prefix, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_paired_devices(&self) -> Result<Vec<PairedDeviceRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, device_id, label, platform, prefix, created_at, last_seen_at, revoked_at
             FROM paired_devices
             ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PairedDeviceRecord {
                id: row.get(0)?,
                device_id: row.get(1)?,
                label: row.get(2)?,
                platform: row.get(3)?,
                prefix: row.get(4)?,
                created_at: row.get(5)?,
                last_seen_at: row.get(6)?,
                revoked_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_paired_device_by_device_id(
        &self,
        device_id: &str,
    ) -> Result<Option<PairedDeviceRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id, device_id, label, platform, prefix, created_at, last_seen_at, revoked_at
                 FROM paired_devices WHERE device_id = ?1",
                params![device_id],
                |row| {
                    Ok(PairedDeviceRecord {
                        id: row.get(0)?,
                        device_id: row.get(1)?,
                        label: row.get(2)?,
                        platform: row.get(3)?,
                        prefix: row.get(4)?,
                        created_at: row.get(5)?,
                        last_seen_at: row.get(6)?,
                        revoked_at: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Soft-revoke a device. Returns false when no such row exists.
    pub fn revoke_paired_device(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE paired_devices
             SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE id = ?1",
            params![id, now],
        )?;
        Ok(rows > 0)
    }

    /// Resolve a presented token hash to an active device, bumping
    /// `last_seen_at`. Revoked devices resolve to `None`.
    pub fn validate_paired_device_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PairedDeviceRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id, device_id, label, platform, prefix, created_at, last_seen_at, revoked_at
                 FROM paired_devices
                 WHERE token_hash = ?1 AND revoked_at IS NULL
                 LIMIT 1",
                params![token_hash],
                |row| {
                    Ok(PairedDeviceRecord {
                        id: row.get(0)?,
                        device_id: row.get(1)?,
                        label: row.get(2)?,
                        platform: row.get(3)?,
                        prefix: row.get(4)?,
                        created_at: row.get(5)?,
                        last_seen_at: row.get(6)?,
                        revoked_at: row.get(7)?,
                    })
                },
            )
            .optional()?;
        let Some(mut record) = row else {
            return Ok(None);
        };
        let now = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE paired_devices SET last_seen_at = ?2 WHERE id = ?1",
            params![record.id, now],
        );
        record.last_seen_at = Some(now);
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use crate::internal::storage::db::test_support::*;

    #[test]
    fn paired_device_lifecycle_create_validate_revoke() {
        let (db, dir) = test_db();
        let id = db
            .create_paired_device(
                "dev-1",
                "Everett's MacBook",
                Some("macos"),
                "hash-1",
                "mcd_abc",
            )
            .unwrap();
        assert!(id > 0);

        let active = db.validate_paired_device_token_hash("hash-1").unwrap();
        let active = active.expect("token resolves while active");
        assert_eq!(active.device_id, "dev-1");
        assert_eq!(active.label, "Everett's MacBook");
        assert_eq!(active.platform.as_deref(), Some("macos"));
        assert!(
            active.last_seen_at.is_some(),
            "validation bumps last_seen_at"
        );
        assert!(db
            .validate_paired_device_token_hash("hash-unknown")
            .unwrap()
            .is_none());

        let listed = db.list_paired_devices().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].prefix, "mcd_abc");
        assert!(listed[0].revoked_at.is_none());

        assert!(db.revoke_paired_device(id).unwrap());
        assert!(db
            .validate_paired_device_token_hash("hash-1")
            .unwrap()
            .is_none());
        let listed = db.list_paired_devices().unwrap();
        assert!(listed[0].revoked_at.is_some());
        // Revoking twice keeps the first timestamp and still reports the row.
        let first = listed[0].revoked_at.clone();
        assert!(db.revoke_paired_device(id).unwrap());
        assert_eq!(db.list_paired_devices().unwrap()[0].revoked_at, first);
        assert!(!db.revoke_paired_device(999).unwrap());

        let by_id = db.get_paired_device_by_device_id("dev-1").unwrap().unwrap();
        assert_eq!(by_id.id, id);
        assert!(db.get_paired_device_by_device_id("nope").unwrap().is_none());
        cleanup(&dir);
    }

    #[test]
    fn paired_device_token_hash_and_device_id_are_unique() {
        let (db, dir) = test_db();
        db.create_paired_device("dev-1", "a", None, "hash-1", "p")
            .unwrap();
        assert!(db
            .create_paired_device("dev-2", "b", None, "hash-1", "p")
            .is_err());
        assert!(db
            .create_paired_device("dev-1", "c", None, "hash-2", "p")
            .is_err());
        cleanup(&dir);
    }
}
