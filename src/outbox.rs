//! Delivery outbox: final replies that failed to send are retried here.
//!
//! Channel adapters deliver the final agent reply themselves (with their own
//! formatting). When that direct send fails — a Telegram outage, a Slack 5xx —
//! the adapter enqueues the plain text into `outbox_messages` instead of
//! dropping it. This supervised loop drains the queue with exponential
//! backoff, delivering through the shared channel-registry funnel (which also
//! stores the message in chat history on success). After `MAX_ATTEMPTS` the
//! row is marked `failed` and kept for post-mortem; it is never silently
//! deleted.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::runtime::AppState;
use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_storage::db::call_blocking;

const FLUSH_INTERVAL_SECS: u64 = 10;
const MAX_ATTEMPTS: i64 = 8;
const MAX_BACKOFF_SECS: i64 = 600;

/// Exponential backoff for the next redelivery attempt, capped so an outage
/// longer than ~10 minutes still gets probed every 10 minutes.
fn backoff_secs(attempts: i64) -> i64 {
    (1_i64 << attempts.clamp(0, 10)).min(MAX_BACKOFF_SECS)
}

/// One drain pass. Returns how many rows were processed (delivered or
/// rescheduled). Extracted from the loop for testability.
pub async fn flush_outbox_once(state: &Arc<AppState>, max_batch: usize) -> usize {
    let now = chrono::Utc::now().to_rfc3339();
    let rows = match call_blocking(state.db.clone(), move |db| {
        db.list_due_outbox_messages(&now, max_batch)
    })
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!("outbox: failed to list due messages: {e}");
            return 0;
        }
    };

    let mut processed = 0usize;
    for row in rows {
        let bot_username = state.config.bot_username_for_channel(&row.channel);
        let delivery = deliver_and_store_bot_message(
            state.channel_registry.as_ref(),
            state.db.clone(),
            &bot_username,
            row.chat_id,
            &row.payload_text,
        )
        .await;
        match delivery {
            Ok(()) => {
                info!(
                    "outbox: redelivered reply to chat {} via {} after {} failed attempt(s)",
                    row.chat_id,
                    row.channel,
                    row.attempts + 1
                );
                let id = row.id;
                let _ = call_blocking(state.db.clone(), move |db| db.mark_outbox_delivered(id))
                    .await;
            }
            Err(err) => {
                let next_attempts = row.attempts + 1;
                let terminal = next_attempts >= MAX_ATTEMPTS;
                let next_at = if terminal {
                    None
                } else {
                    Some(
                        (chrono::Utc::now()
                            + chrono::Duration::seconds(backoff_secs(next_attempts)))
                        .to_rfc3339(),
                    )
                };
                if terminal {
                    warn!(
                        "outbox: giving up on reply to chat {} via {} after {} attempts: {}",
                        row.chat_id, row.channel, next_attempts, err
                    );
                }
                let id = row.id;
                let _ = call_blocking(state.db.clone(), move |db| {
                    db.mark_outbox_retry(id, next_attempts, next_at.as_deref(), &err, terminal)
                })
                .await;
            }
        }
        processed += 1;
    }
    processed
}

/// Spawn the supervised background flush loop.
pub fn spawn_outbox_flush(state: Arc<AppState>) {
    crate::supervision::spawn_supervised("outbox_flush", move || {
        let state = state.clone();
        async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
            loop {
                ticker.tick().await;
                flush_outbox_once(&state, 50).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::backoff_secs;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_secs(0), 1);
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(3), 8);
        assert_eq!(backoff_secs(9), 512);
        assert_eq!(backoff_secs(10), 600);
        assert_eq!(backoff_secs(50), 600);
    }
}
