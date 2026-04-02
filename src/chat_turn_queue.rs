//! Per-chat turn serialization and message coalescing.
//!
//! `ChatTurnQueue` ensures at most one agent run is active per (channel, chat_id)
//! at any time. Messages arriving while a run is active are queued and coalesced
//! after the run completes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Key identifying a specific chat across channels.
type ChatKey = (String, i64);

/// A message that arrived while an agent run was active for the same chat.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub sender_name: String,
    pub content: String,
    pub message_id: String,
    pub timestamp: String,
}

/// Internal per-chat slot tracking the turn lock and pending messages.
struct ChatSlot {
    /// Async mutex held for the duration of an agent run.
    turn_lock: Arc<Mutex<()>>,
    /// Messages queued while a run is active.
    pending_messages: Vec<PendingMessage>,
    /// Last time this slot was actively used.
    last_active: Instant,
}

impl ChatSlot {
    fn new() -> Self {
        Self {
            turn_lock: Arc::new(Mutex::new(())),
            pending_messages: Vec::new(),
            last_active: Instant::now(),
        }
    }
}

/// RAII guard that releases the per-chat turn lock when dropped.
pub struct TurnGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    key: ChatKey,
}

impl Drop for TurnGuard {
    fn drop(&mut self) {
        debug!(
            channel = %self.key.0,
            chat_id = self.key.1,
            "Chat turn released"
        );
    }
}

/// Per-chat turn serialization queue.
///
/// Ensures at most one agent run per (channel, chat_id). Messages arriving
/// during an active run are coalesced into `pending_messages` and can be
/// drained after the run completes.
pub struct ChatTurnQueue {
    slots: Mutex<HashMap<ChatKey, Arc<Mutex<ChatSlot>>>>,
    max_pending: usize,
    enabled: bool,
    idle_ttl: Duration,
}

impl ChatTurnQueue {
    pub fn new(enabled: bool, max_pending: usize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            max_pending,
            enabled,
            idle_ttl: Duration::from_secs(600),
        }
    }

    /// Get or create the slot for a given chat, performing opportunistic
    /// cleanup of idle slots.
    async fn get_slot(&self, key: &ChatKey) -> Arc<Mutex<ChatSlot>> {
        let mut slots = self.slots.lock().await;
        // Opportunistic cleanup: remove idle slots (no pending messages, not locked)
        if slots.len() > 100 {
            let now = Instant::now();
            let ttl = self.idle_ttl;
            slots.retain(|_, slot_arc| {
                // Only remove if we can try-lock it (not actively held)
                if let Ok(slot) = slot_arc.try_lock() {
                    if slot.pending_messages.is_empty() && now.duration_since(slot.last_active) > ttl
                    {
                        return false; // remove
                    }
                }
                true
            });
        }
        slots
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(ChatSlot::new())))
            .clone()
    }

    /// Acquire the turn for a chat. Blocks until the previous run completes.
    /// Returns a [`TurnGuard`] that releases the turn when dropped.
    ///
    /// If `chat_turn_serialization` is disabled, returns immediately without locking.
    pub async fn acquire(
        self: &Arc<Self>,
        channel: &str,
        chat_id: i64,
    ) -> Option<TurnGuard> {
        if !self.enabled {
            return None;
        }
        let key: ChatKey = (channel.to_string(), chat_id);
        let slot_arc = self.get_slot(&key).await;

        let turn_lock = {
            let slot = slot_arc.lock().await;
            slot.turn_lock.clone()
        };

        // Acquire with timeout to prevent deadlock (e.g., recursive same-chat calls).
        let guard = match tokio::time::timeout(Duration::from_secs(60), turn_lock.lock_owned()).await
        {
            Ok(guard) => guard,
            Err(_) => {
                warn!(
                    channel = %key.0,
                    chat_id = key.1,
                    "ChatTurnQueue: timeout waiting for turn lock (60s); proceeding without lock"
                );
                return None;
            }
        };

        {
            let mut slot = slot_arc.lock().await;
            slot.last_active = Instant::now();
        }

        debug!(
            channel,
            chat_id,
            "Chat turn acquired"
        );

        Some(TurnGuard {
            _guard: guard,
            key,
        })
    }

    /// Enqueue a message for a chat that currently has an active run.
    ///
    /// Returns `true` if the chat has an active run (message was queued).
    /// Returns `false` if no run is active (caller should start a new run).
    pub async fn enqueue_if_busy(
        &self,
        channel: &str,
        chat_id: i64,
        msg: PendingMessage,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        let key: ChatKey = (channel.to_string(), chat_id);
        let slot_arc = {
            let slots = self.slots.lock().await;
            match slots.get(&key) {
                Some(arc) => arc.clone(),
                None => return false, // no slot means no active run
            }
        };

        let mut slot = slot_arc.lock().await;
        // Check if turn_lock is currently held (i.e., a run is active)
        if slot.turn_lock.try_lock().is_ok() {
            // Lock was not held -> no active run
            return false;
        }

        // Run is active; queue the message
        if slot.pending_messages.len() >= self.max_pending {
            // Drop oldest to make room
            slot.pending_messages.remove(0);
            warn!(
                channel,
                chat_id,
                max_pending = self.max_pending,
                "ChatTurnQueue: pending messages at capacity; dropped oldest"
            );
        }

        debug!(
            channel,
            chat_id,
            sender = %msg.sender_name,
            pending_count = slot.pending_messages.len() + 1,
            "Message queued while chat turn is active"
        );
        slot.pending_messages.push(msg);
        true
    }

    /// Drain all pending messages accumulated during the current turn.
    /// Returns them in arrival order.
    pub async fn drain_pending(&self, channel: &str, chat_id: i64) -> Vec<PendingMessage> {
        let key: ChatKey = (channel.to_string(), chat_id);
        let slot_arc = {
            let slots = self.slots.lock().await;
            match slots.get(&key) {
                Some(arc) => arc.clone(),
                None => return Vec::new(),
            }
        };

        let mut slot = slot_arc.lock().await;
        std::mem::take(&mut slot.pending_messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_queue(enabled: bool) -> Arc<ChatTurnQueue> {
        Arc::new(ChatTurnQueue::new(enabled, 20))
    }

    fn make_msg(content: &str) -> PendingMessage {
        PendingMessage {
            sender_name: "user".to_string(),
            content: content.to_string(),
            message_id: format!("msg_{content}"),
            timestamp: "2026-04-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn test_acquire_release_basic() {
        let q = make_queue(true);
        let guard = q.acquire("telegram", 1).await;
        assert!(guard.is_some());
        drop(guard);
        // Can acquire again
        let guard2 = q.acquire("telegram", 1).await;
        assert!(guard2.is_some());
    }

    #[tokio::test]
    async fn test_acquire_blocks_concurrent() {
        let q = make_queue(true);
        let counter = Arc::new(AtomicUsize::new(0));

        let guard = q.acquire("tg", 1).await.unwrap();
        let q2 = q.clone();
        let c2 = counter.clone();

        // Spawn a task that tries to acquire the same chat
        let handle = tokio::spawn(async move {
            let _g = q2.acquire("tg", 1).await;
            c2.fetch_add(1, Ordering::SeqCst);
        });

        // Give the spawned task time to attempt acquire
        tokio::time::sleep(Duration::from_millis(50)).await;
        // It should still be blocked
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Release the first guard
        drop(guard);
        // Now the spawned task should complete
        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_enqueue_if_busy_returns_true_when_active() {
        let q = make_queue(true);
        let _guard = q.acquire("tg", 1).await.unwrap();

        let queued = q.enqueue_if_busy("tg", 1, make_msg("hello")).await;
        assert!(queued);

        let queued2 = q.enqueue_if_busy("tg", 1, make_msg("world")).await;
        assert!(queued2);
    }

    #[tokio::test]
    async fn test_enqueue_if_busy_returns_false_when_idle() {
        let q = make_queue(true);
        // No active run
        let queued = q.enqueue_if_busy("tg", 1, make_msg("hello")).await;
        assert!(!queued);
    }

    #[tokio::test]
    async fn test_drain_pending_returns_all() {
        let q = make_queue(true);
        let _guard = q.acquire("tg", 1).await.unwrap();

        q.enqueue_if_busy("tg", 1, make_msg("a")).await;
        q.enqueue_if_busy("tg", 1, make_msg("b")).await;
        q.enqueue_if_busy("tg", 1, make_msg("c")).await;

        let pending = q.drain_pending("tg", 1).await;
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].content, "a");
        assert_eq!(pending[1].content, "b");
        assert_eq!(pending[2].content, "c");
    }

    #[tokio::test]
    async fn test_drain_clears_queue() {
        let q = make_queue(true);
        let _guard = q.acquire("tg", 1).await.unwrap();

        q.enqueue_if_busy("tg", 1, make_msg("a")).await;
        let _ = q.drain_pending("tg", 1).await;

        let pending = q.drain_pending("tg", 1).await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_different_chats_independent() {
        let q = make_queue(true);
        let counter = Arc::new(AtomicUsize::new(0));

        let _guard_chat1 = q.acquire("tg", 1).await.unwrap();
        let q2 = q.clone();
        let c2 = counter.clone();

        // Different chat should not block
        let handle = tokio::spawn(async move {
            let _g = q2.acquire("tg", 2).await;
            c2.fetch_add(1, Ordering::SeqCst);
        });

        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_disabled_queue_passes_through() {
        let q = make_queue(false);
        // acquire returns None when disabled
        let guard = q.acquire("tg", 1).await;
        assert!(guard.is_none());

        // enqueue_if_busy returns false when disabled
        let queued = q.enqueue_if_busy("tg", 1, make_msg("test")).await;
        assert!(!queued);
    }

    #[tokio::test]
    async fn test_max_pending_drops_oldest() {
        let q = Arc::new(ChatTurnQueue::new(true, 3));
        let _guard = q.acquire("tg", 1).await.unwrap();

        q.enqueue_if_busy("tg", 1, make_msg("a")).await;
        q.enqueue_if_busy("tg", 1, make_msg("b")).await;
        q.enqueue_if_busy("tg", 1, make_msg("c")).await;
        // This should drop "a"
        q.enqueue_if_busy("tg", 1, make_msg("d")).await;

        let pending = q.drain_pending("tg", 1).await;
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].content, "b");
        assert_eq!(pending[1].content, "c");
        assert_eq!(pending[2].content, "d");
    }
}
