use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Instant;

use tokio::sync::RwLock;

/// An active chat run registered for abort handling.
#[derive(Clone)]
pub struct ChatAbortControllerEntry {
    /// The Abort signal — set to true when chat.abort is invoked.
    pub aborted: Arc<AtomicBool>,
    /// Accumulated text delta buffer for this run.
    pub buffer: Arc<RwLock<String>>,
    /// The session key this run belongs to.
    pub session_key: String,
    /// When this run was registered (Unix ms). Exposed for testing.
    #[allow(dead_code)]
    pub started_at_ms: i64,
    /// When this run expires and should be auto-cleaned (Unix ms).
    #[allow(dead_code)]
    pub expires_at_ms: i64,
    /// The WebSocket connection that owns this run (for auth).
    #[allow(dead_code)]
    pub owner_conn_id: Option<String>,
}

/// Global registry of active chat abort controllers.
/// Key: run_id (string UUID from stream.rs)
static CHAT_ABORT_CONTROLLERS: LazyLock<RwLock<HashMap<String, ChatAbortControllerEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

impl ChatAbortControllerEntry {
    /// Creates a new abort controller entry with default expiration of 2 minutes.
    pub fn new(session_key: String, owner_conn_id: Option<String>) -> Self {
        let now_ms = Instant::now().elapsed().as_millis() as i64;
        Self {
            aborted: Arc::new(AtomicBool::new(false)),
            buffer: Arc::new(RwLock::new(String::new())),
            session_key,
            started_at_ms: now_ms,
            expires_at_ms: now_ms + 120_000, // default 2min
            owner_conn_id,
        }
    }
}

/// Register a new chat abort controller for a run.
pub async fn register_chat_run(
    run_id: String,
    session_key: String,
    owner_conn_id: Option<String>,
) -> ChatAbortControllerEntry {
    let entry = ChatAbortControllerEntry::new(session_key, owner_conn_id);
    let mut guard = CHAT_ABORT_CONTROLLERS.write().await;
    guard.insert(run_id, entry.clone());
    entry
}

/// Remove a chat abort controller entry.
pub async fn unregister_chat_run(run_id: &str) {
    let mut guard = CHAT_ABORT_CONTROLLERS.write().await;
    guard.remove(run_id);
}

/// Clear all chat abort controller entries (for testing).
#[cfg(test)]
pub async fn clear_all_runs() {
    let mut guard = CHAT_ABORT_CONTROLLERS.write().await;
    guard.clear();
}

/// Get a clone of the controller entry for a run. Exposed for testing.
#[allow(dead_code)]
pub async fn get_chat_run(run_id: &str) -> Option<ChatAbortControllerEntry> {
    let guard = CHAT_ABORT_CONTROLLERS.read().await;
    guard.get(run_id).cloned()
}

/// Check if a run has been aborted.
#[allow(dead_code)]
pub fn is_aborted(entry: &ChatAbortControllerEntry) -> bool {
    entry.aborted.load(Ordering::SeqCst)
}

/// Signal abort for a specific run. Returns (aborted, partial_text).
pub async fn abort_chat_run_by_id(
    run_id: &str,
    session_key: &str,
) -> (bool, Option<String>) {
    let entry = {
        let guard = CHAT_ABORT_CONTROLLERS.read().await;
        guard.get(run_id).cloned()
    };

    let Some(entry) = entry else {
        return (false, None);
    };

    if entry.session_key != session_key {
        return (false, None);
    }

    entry.aborted.store(true, Ordering::SeqCst);

    // Collect buffered text atomically
    let buffer = entry.buffer.read().await;
    let text = buffer.trim();
    let partial_text = if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    };

    (true, partial_text)
}

/// Signal abort for all runs belonging to a session.
/// Returns (aborted, run_ids, partial_texts).
pub async fn abort_chat_runs_for_session_key(
    session_key: &str,
) -> (bool, Vec<String>, Vec<String>) {
    // Collect matching entries under write lock
    let entries_to_abort: Vec<(String, Arc<RwLock<String>>)> = {
        let mut guard = CHAT_ABORT_CONTROLLERS.write().await;
        let collected: Vec<(String, Arc<RwLock<String>>)> = guard
            .iter_mut()
            .filter(|(_, entry)| entry.session_key == session_key)
            .map(|(run_id, entry)| {
                entry.aborted.store(true, Ordering::SeqCst);
                (run_id.clone(), entry.buffer.clone())
            })
            .collect();
        collected
    }; // guard dropped here

    if entries_to_abort.is_empty() {
        return (false, Vec::new(), Vec::new());
    }

    let mut run_ids = Vec::new();
    let mut partials = Vec::new();
    for (run_id, buffer) in entries_to_abort {
        run_ids.push(run_id);
        let text = buffer.read().await.trim().to_string();
        partials.push(text);
    }

    (true, run_ids, partials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_unregister() {
        clear_all_runs().await;
        let run_id = "test-run-1";
        let session_key = "main:web:direct:user1";
        let owner_conn = Some("conn-abc".to_string());

        let entry = register_chat_run(run_id.to_string(), session_key.to_string(), owner_conn.clone()).await;
        assert!(!is_aborted(&entry));
        assert_eq!(entry.session_key, session_key);
        assert_eq!(entry.owner_conn_id, owner_conn);

        unregister_chat_run(run_id).await;
        assert!(get_chat_run(run_id).await.is_none());
    }

    #[tokio::test]
    async fn test_abort_run_by_id_success() {
        clear_all_runs().await;
        let run_id = "test-run-2";
        let session_key = "main:web:direct:user1";

        register_chat_run(run_id.to_string(), session_key.to_string(), None).await;

        let (aborted, partial) = abort_chat_run_by_id(run_id, session_key).await;
        assert!(aborted);
        assert!(partial.is_none()); // no text accumulated yet
    }

    #[tokio::test]
    async fn test_abort_run_by_id_wrong_session() {
        clear_all_runs().await;
        let run_id = "test-run-3";
        let session_key = "main:web:direct:user1";

        register_chat_run(run_id.to_string(), session_key.to_string(), None).await;

        let (aborted, _) = abort_chat_run_by_id(run_id, "wrong:session:key").await;
        assert!(!aborted);
    }

    #[tokio::test]
    async fn test_abort_nonexistent_run() {
        clear_all_runs().await;
        let (aborted, _) = abort_chat_run_by_id("nonexistent", "any").await;
        assert!(!aborted);
    }

    #[tokio::test]
    async fn test_abort_session_key_aborts_all_runs() {
        // Clear any leftover state from previous tests
        clear_all_runs().await;

        let session_key = "main:web:direct:user1";

        register_chat_run("run-a".to_string(), session_key.to_string(), None).await;
        register_chat_run("run-b".to_string(), session_key.to_string(), None).await;
        register_chat_run("run-c".to_string(), "other:session".to_string(), None).await;

        let (aborted, run_ids, _) = abort_chat_runs_for_session_key(session_key).await;
        assert!(aborted);
        assert_eq!(run_ids.len(), 2);
        assert!(run_ids.contains(&"run-a".to_string()));
        assert!(run_ids.contains(&"run-b".to_string()));
        assert!(!run_ids.contains(&"run-c".to_string()));
    }

    #[tokio::test]
    async fn test_unregister_removes_from_map() {
        clear_all_runs().await;
        let run_id = "test-run-5";
        let session_key = "main:web:direct:user1";

        register_chat_run(run_id.to_string(), session_key.to_string(), None).await;
        assert!(get_chat_run(run_id).await.is_some());

        unregister_chat_run(run_id).await;
        assert!(get_chat_run(run_id).await.is_none());
    }
}
