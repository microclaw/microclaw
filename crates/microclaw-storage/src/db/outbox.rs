use super::*;

/// A final reply queued for redelivery after a failed channel send.
#[derive(Debug, Clone)]
pub struct OutboxMessageRecord {
    pub id: i64,
    pub delivery_id: String,
    pub chat_id: i64,
    pub channel: String,
    pub payload_text: String,
    pub full_payload_text: String,
    pub chunk_index: i64,
    pub total_chunks: i64,
    pub idempotency_key: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundDeliveryHealth {
    pub total_deliveries: i64,
    pub delivered_deliveries: i64,
    pub pending_chunks: i64,
    pub sending_chunks: i64,
    pub retry_chunks: i64,
    pub failed_chunks: i64,
    pub oldest_unfinished_at: Option<String>,
}

pub(crate) fn refresh_delivery_status(
    tx: &Transaction<'_>,
    chunk_id: i64,
    now: &str,
) -> Result<(), MicroClawError> {
    let delivery_id: String = tx.query_row(
        "SELECT delivery_id FROM outbound_delivery_chunks WHERE id=?1",
        params![chunk_id],
        |row| row.get(0),
    )?;
    let (total, delivered, failed): (i64, i64, i64) = tx.query_row(
        "SELECT COUNT(*),
                SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
         FROM outbound_delivery_chunks WHERE delivery_id=?1",
        params![delivery_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let status = if failed > 0 {
        "failed"
    } else if total > 0 && delivered == total {
        "delivered"
    } else if delivered > 0 {
        "partial"
    } else {
        "pending"
    };
    tx.execute(
        "UPDATE outbound_deliveries SET status=?2, updated_at=?3 WHERE delivery_id=?1",
        params![delivery_id, status, now],
    )?;
    Ok(())
}

impl Database {
    /// Queue a final reply whose direct channel delivery failed. The outbox
    /// flush loop retries it with backoff until delivered or terminally
    /// failed.
    pub fn enqueue_outbox_message(
        &self,
        chat_id: i64,
        channel: &str,
        payload_text: &str,
    ) -> Result<i64, MicroClawError> {
        let delivery_id = format!("delivery-{}", uuid::Uuid::new_v4());
        let ids = self.create_outbound_delivery(
            &delivery_id,
            chat_id,
            channel,
            payload_text,
            &[payload_text.to_string()],
        )?;
        Ok(ids[0])
    }

    /// Persist a complete outbound message and its independently retryable
    /// chunks before the first network call.
    pub fn create_outbound_delivery(
        &self,
        delivery_id: &str,
        chat_id: i64,
        channel: &str,
        full_payload_text: &str,
        chunks: &[String],
    ) -> Result<Vec<i64>, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO outbound_deliveries(
                delivery_id, chat_id, channel, full_payload_text, status,
                created_at, updated_at
             ) VALUES(?1, ?2, ?3, ?4, 'pending', ?5, ?5)",
            params![delivery_id, chat_id, channel, full_payload_text, now],
        )?;
        let total = chunks.len().max(1) as i64;
        let mut ids = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let idempotency_key = format!("{delivery_id}:{}", index + 1);
            tx.execute(
                "INSERT INTO outbound_delivery_chunks(
                    delivery_id, chunk_index, total_chunks, payload_text,
                    idempotency_key, status, attempts, next_attempt_at,
                    created_at, updated_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
                params![
                    delivery_id,
                    index as i64,
                    total,
                    chunk,
                    idempotency_key,
                    now
                ],
            )?;
            ids.push(tx.last_insert_rowid());
        }
        tx.commit()?;
        Ok(ids)
    }

    pub fn list_due_outbox_messages(
        &self,
        now_iso: &str,
        limit: usize,
    ) -> Result<Vec<OutboxMessageRecord>, MicroClawError> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.delivery_id, d.chat_id, d.channel,
                    c.payload_text, d.full_payload_text, c.chunk_index,
                    c.total_chunks, c.idempotency_key, c.status, c.attempts,
                    c.next_attempt_at, c.last_error
             FROM outbound_delivery_chunks c
             JOIN outbound_deliveries d ON d.delivery_id = c.delivery_id
             WHERE c.status IN ('pending', 'retry')
               AND (c.next_attempt_at IS NULL OR unixepoch(c.next_attempt_at) <= unixepoch(?1))
             ORDER BY c.id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_iso, limit.max(1) as i64], |row| {
            Ok(OutboxMessageRecord {
                id: row.get(0)?,
                delivery_id: row.get(1)?,
                chat_id: row.get(2)?,
                channel: row.get(3)?,
                payload_text: row.get(4)?,
                full_payload_text: row.get(5)?,
                chunk_index: row.get(6)?,
                total_chunks: row.get(7)?,
                idempotency_key: row.get(8)?,
                status: row.get(9)?,
                attempts: row.get(10)?,
                next_attempt_at: row.get(11)?,
                last_error: row.get(12)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_outbox_delivered(&self, id: i64) -> Result<(), MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE outbound_delivery_chunks
             SET status='delivered', updated_at=?2 WHERE id=?1",
            params![id, now],
        )?;
        refresh_delivery_status(&tx, id, &now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_outbox_sending(&self, id: i64) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = conn.execute(
            "UPDATE outbound_delivery_chunks
             SET status='sending', updated_at=?2
             WHERE id=?1 AND status IN ('pending', 'retry')",
            params![id, now],
        )?;
        Ok(changed == 1)
    }

    pub fn mark_outbox_retry(
        &self,
        id: i64,
        attempts: i64,
        next_attempt_at: Option<&str>,
        last_error: &str,
        terminal_fail: bool,
    ) -> Result<(), MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        let status = if terminal_fail { "failed" } else { "retry" };
        tx.execute(
            "UPDATE outbound_delivery_chunks
             SET status=?2, attempts=?3, next_attempt_at=?4, last_error=?5, updated_at=?6
             WHERE id=?1",
            params![id, status, attempts, next_attempt_at, last_error, now],
        )?;
        refresh_delivery_status(&tx, id, &now)?;
        tx.commit()?;
        Ok(())
    }

    /// Reset chunks left in `sending` by an unclean shutdown. Stable channel
    /// idempotency keys make replay safe on supporting transports (Weixin).
    pub fn recover_sending_outbox_messages(&self) -> Result<usize, MicroClawError> {
        let conn = self.lock_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = conn.execute(
            "UPDATE outbound_delivery_chunks
             SET status='retry', next_attempt_at=?1,
                 last_error='recovered after interrupted delivery', updated_at=?1
             WHERE status='sending'",
            params![now],
        )?;
        Ok(changed)
    }

    pub fn outbound_delivery_is_complete(&self, delivery_id: &str) -> Result<bool, MicroClawError> {
        let conn = self.lock_conn();
        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbound_delivery_chunks
             WHERE delivery_id=?1 AND status != 'delivered'",
            params![delivery_id],
            |row| row.get(0),
        )?;
        Ok(remaining == 0)
    }

    /// Store the full logical message once, after every external chunk is
    /// delivered. Returns true only for the caller that performed the insert.
    pub fn finalize_outbound_delivery(
        &self,
        delivery_id: &str,
        sender_name: &str,
    ) -> Result<bool, MicroClawError> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        let delivery = tx.query_row(
            "SELECT chat_id, full_payload_text, stored_at
             FROM outbound_deliveries WHERE delivery_id=?1",
            params![delivery_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        if delivery.2.is_some() {
            return Ok(false);
        }
        let remaining: i64 = tx.query_row(
            "SELECT COUNT(*) FROM outbound_delivery_chunks
             WHERE delivery_id=?1 AND status != 'delivered'",
            params![delivery_id],
            |row| row.get(0),
        )?;
        if remaining != 0 {
            return Ok(false);
        }
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO messages(id, chat_id, sender_name, content, is_from_bot, timestamp)
             VALUES(?1, ?2, ?3, ?4, 1, ?5)",
            params![
                uuid::Uuid::new_v4().to_string(),
                delivery.0,
                sender_name,
                delivery.1,
                now
            ],
        )?;
        tx.execute(
            "UPDATE outbound_deliveries
             SET status='delivered', stored_at=?2, updated_at=?2
             WHERE delivery_id=?1 AND stored_at IS NULL",
            params![delivery_id, now],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Pending + retry outbox depth (governance/observability).
    pub fn count_outbox_pending(&self) -> Result<i64, MicroClawError> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbound_delivery_chunks
             WHERE status IN ('pending', 'retry', 'sending')",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Read-only delivery health snapshot for diagnostics and monitoring.
    pub fn outbound_delivery_health(&self) -> Result<OutboundDeliveryHealth, MicroClawError> {
        let conn = self.lock_conn();
        let (total_deliveries, delivered_deliveries): (i64, i64) = conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END), 0)
             FROM outbound_deliveries",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (pending_chunks, sending_chunks, retry_chunks, failed_chunks, oldest_unfinished_at) =
            conn.query_row(
                "SELECT
                    COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='sending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='retry' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0),
                    MIN(CASE WHEN status != 'delivered' THEN created_at END)
                 FROM outbound_delivery_chunks",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
        Ok(OutboundDeliveryHealth {
            total_deliveries,
            delivered_deliveries,
            pending_chunks,
            sending_chunks,
            retry_chunks,
            failed_chunks,
            oldest_unfinished_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::test_support::*;

    #[test]
    fn test_outbox_lifecycle() {
        let (db, dir) = test_db();
        assert_eq!(db.count_outbox_pending().unwrap(), 0);

        let id = db
            .enqueue_outbox_message(42, "telegram", "the answer is 42")
            .unwrap();
        assert_eq!(db.count_outbox_pending().unwrap(), 1);

        // Due immediately (next_attempt_at = enqueue time).
        let due = db
            .list_due_outbox_messages("2999-01-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].chat_id, 42);
        assert_eq!(due[0].payload_text, "the answer is 42");
        assert_eq!(due[0].status, "pending");

        // Retry with a future next attempt → not due before that instant.
        db.mark_outbox_retry(id, 1, Some("2999-06-01T00:00:00Z"), "network down", false)
            .unwrap();
        assert!(db
            .list_due_outbox_messages("2999-01-01T00:00:00Z", 10)
            .unwrap()
            .is_empty());
        let due = db
            .list_due_outbox_messages("2999-07-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 1);
        assert_eq!(due[0].last_error.as_deref(), Some("network down"));

        // Delivered → gone from the queue and the pending count.
        db.mark_outbox_delivered(id).unwrap();
        assert!(db
            .list_due_outbox_messages("2999-07-01T00:00:00Z", 10)
            .unwrap()
            .is_empty());
        assert_eq!(db.count_outbox_pending().unwrap(), 0);

        // Terminal failure also leaves the queue.
        let id2 = db.enqueue_outbox_message(43, "slack", "bye").unwrap();
        db.mark_outbox_retry(id2, 8, None, "gave up", true).unwrap();
        assert!(db
            .list_due_outbox_messages("2999-07-01T00:00:00Z", 10)
            .unwrap()
            .is_empty());
        assert_eq!(db.count_outbox_pending().unwrap(), 0);
        cleanup(&dir);
    }

    #[test]
    fn test_chunked_delivery_resumes_and_stores_logical_message_once() {
        let (db, dir) = test_db();
        let ids = db
            .create_outbound_delivery(
                "delivery-test",
                77,
                "weixin",
                "first second third",
                &["first".into(), "second".into(), "third".into()],
            )
            .unwrap();
        assert_eq!(ids.len(), 3);
        let health = db.outbound_delivery_health().unwrap();
        assert_eq!(health.total_deliveries, 1);
        assert_eq!(health.pending_chunks, 3);

        assert!(db.mark_outbox_sending(ids[0]).unwrap());
        db.mark_outbox_delivered(ids[0]).unwrap();
        assert!(db.mark_outbox_sending(ids[1]).unwrap());
        assert_eq!(db.recover_sending_outbox_messages().unwrap(), 1);

        let due = db
            .list_due_outbox_messages("2999-01-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].chunk_index, 1);
        assert_eq!(due[0].idempotency_key, "delivery-test:2");
        assert_eq!(due[1].chunk_index, 2);

        for row in due {
            assert!(db.mark_outbox_sending(row.id).unwrap());
            db.mark_outbox_delivered(row.id).unwrap();
        }
        assert!(db.outbound_delivery_is_complete("delivery-test").unwrap());
        assert!(db
            .finalize_outbound_delivery("delivery-test", "bot")
            .unwrap());
        assert!(!db
            .finalize_outbound_delivery("delivery-test", "bot")
            .unwrap());

        let messages = db.get_all_messages(77).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "first second third");
        let health = db.outbound_delivery_health().unwrap();
        assert_eq!(health.delivered_deliveries, 1);
        assert_eq!(
            health.pending_chunks + health.sending_chunks + health.retry_chunks,
            0
        );
        assert_eq!(health.failed_chunks, 0);
        cleanup(&dir);
    }
}
