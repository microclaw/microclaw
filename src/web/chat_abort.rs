use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;

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
}

/// Global registry of active chat abort controllers.
/// Key: run_id (string UUID from stream.rs)
static CHAT_ABORT_CONTROLLERS: LazyLock<RwLock<HashMap<String, ChatAbortControllerEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

impl ChatAbortControllerEntry {
    pub fn new(session_key: String) -> Self {
        Self {
            aborted: Arc::new(AtomicBool::new(false)),
            buffer: Arc::new(RwLock::new(String::new())),
            session_key,
        }
    }
}

/// Register a new chat abort controller for a run.
pub async fn register_chat_run(
    run_id: String,
    session_key: String,
) -> ChatAbortControllerEntry {
    let entry = ChatAbortControllerEntry::new(session_key);
    let mut guard = CHAT_ABORT_CONTROLLERS.write().await;
    guard.insert(run_id, entry.clone());
    entry
}

/// Remove a chat abort controller entry.
pub async fn unregister_chat_run(run_id: &str) {
    let mut guard = CHAT_ABORT_CONTROLLERS.write().await;
    guard.remove(run_id);
}

/// Get a clone of the controller entry for a run.
#[cfg(test)]
pub async fn get_chat_run(run_id: &str) -> Option<ChatAbortControllerEntry> {
    let guard = CHAT_ABORT_CONTROLLERS.read().await;
    guard.get(run_id).cloned()
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
        tracing::debug!(
            target: "chat_abort",
            run_id = %run_id,
            session_key = %session_key,
            "abort_chat_run_by_id: run not found"
        );
        return (false, None);
    };

    if entry.session_key != session_key {
        tracing::debug!(
            target: "chat_abort",
            run_id = %run_id,
            session_key = %session_key,
            entry_session_key = %entry.session_key,
            "abort_chat_run_by_id: session_key mismatch"
        );
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

    tracing::debug!(
        target: "chat_abort",
        run_id = %run_id,
        session_key = %session_key,
        has_partial = %partial_text.is_some(),
        "abort_chat_run_by_id: abort signaled"
    );

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
        tracing::debug!(
            target: "chat_abort",
            session_key = %session_key,
            "abort_chat_runs_for_session_key: no runs found for session"
        );
        return (false, Vec::new(), Vec::new());
    }

    let mut run_ids = Vec::new();
    let mut partials = Vec::new();
    for (run_id, buffer) in entries_to_abort {
        run_ids.push(run_id.clone());
        let text = buffer.read().await.trim().to_string();
        partials.push(text);
    }

    tracing::debug!(
        target: "chat_abort",
        session_key = %session_key,
        run_ids = ?run_ids,
        "abort_chat_runs_for_session_key: aborted {} runs",
        run_ids.len()
    );

    (true, run_ids, partials)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use unique run_id / session_key values so they can run in
    // parallel without interfering via the shared global registry.

    #[tokio::test]
    async fn test_register_and_unregister() {
        let run_id = "reg-unreg-1";
        let session_key = "session:reg-unreg";

        let entry = register_chat_run(run_id.to_string(), session_key.to_string()).await;
        assert!(!entry.aborted.load(Ordering::SeqCst));
        assert_eq!(entry.session_key, session_key);

        unregister_chat_run(run_id).await;
        assert!(get_chat_run(run_id).await.is_none());
    }

    #[tokio::test]
    async fn test_abort_run_by_id_success() {
        let run_id = "abort-ok-1";
        let session_key = "session:abort-ok";

        register_chat_run(run_id.to_string(), session_key.to_string()).await;

        let (aborted, partial) = abort_chat_run_by_id(run_id, session_key).await;
        assert!(aborted);
        assert!(partial.is_none()); // no text accumulated yet

        unregister_chat_run(run_id).await;
    }

    #[tokio::test]
    async fn test_abort_run_by_id_wrong_session() {
        let run_id = "abort-wrong-1";
        let session_key = "session:abort-wrong";

        register_chat_run(run_id.to_string(), session_key.to_string()).await;

        let (aborted, _) = abort_chat_run_by_id(run_id, "wrong:session:key").await;
        assert!(!aborted);

        unregister_chat_run(run_id).await;
    }

    #[tokio::test]
    async fn test_abort_nonexistent_run() {
        let (aborted, _) = abort_chat_run_by_id("nonexistent-xyz", "any").await;
        assert!(!aborted);
    }

    #[tokio::test]
    async fn test_abort_session_key_aborts_all_runs() {
        let session_key = "session:batch-abort";

        register_chat_run("batch-a".to_string(), session_key.to_string()).await;
        register_chat_run("batch-b".to_string(), session_key.to_string()).await;
        register_chat_run("batch-c".to_string(), "session:batch-other".to_string()).await;

        let (aborted, run_ids, _) = abort_chat_runs_for_session_key(session_key).await;
        assert!(aborted);
        assert_eq!(run_ids.len(), 2);
        assert!(run_ids.contains(&"batch-a".to_string()));
        assert!(run_ids.contains(&"batch-b".to_string()));
        assert!(!run_ids.contains(&"batch-c".to_string()));

        // clean up
        unregister_chat_run("batch-a").await;
        unregister_chat_run("batch-b").await;
        unregister_chat_run("batch-c").await;
    }

    #[tokio::test]
    async fn test_unregister_removes_from_map() {
        let run_id = "unreg-check-1";
        let session_key = "session:unreg-check";

        register_chat_run(run_id.to_string(), session_key.to_string()).await;
        assert!(get_chat_run(run_id).await.is_some());

        unregister_chat_run(run_id).await;
        assert!(get_chat_run(run_id).await.is_none());
    }
}
