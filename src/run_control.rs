use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use tokio::sync::{Mutex, Notify};

type RunKey = (String, i64);

#[derive(Clone)]
struct ActiveRun {
    run_id: u64,
    source_message_id: Option<String>,
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_RUNS: LazyLock<Mutex<HashMap<RunKey, Vec<ActiveRun>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ABORTED_SOURCE_MESSAGE_IDS: LazyLock<Mutex<HashMap<RunKey, HashSet<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub const STOPPED_TEXT: &str = "Current run aborted.";

pub async fn register_run(
    channel: &str,
    chat_id: i64,
    source_message_id: Option<String>,
) -> (u64, Arc<AtomicBool>, Arc<Notify>) {
    let run_id = NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed);
    let cancelled = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(Notify::new());
    let run = ActiveRun {
        run_id,
        source_message_id,
        cancelled: cancelled.clone(),
        notify: notify.clone(),
    };
    let mut map = ACTIVE_RUNS.lock().await;
    map.entry((channel.to_string(), chat_id))
        .or_default()
        .push(run);
    (run_id, cancelled, notify)
}

pub async fn unregister_run(channel: &str, chat_id: i64, run_id: u64) {
    let mut map = ACTIVE_RUNS.lock().await;
    let key = (channel.to_string(), chat_id);
    if let Some(runs) = map.get_mut(&key) {
        runs.retain(|r| r.run_id != run_id);
        if runs.is_empty() {
            map.remove(&key);
        }
    }
}

pub async fn abort_runs(channel: &str, chat_id: i64) -> usize {
    let key = (channel.to_string(), chat_id);
    let runs = {
        let mut map = ACTIVE_RUNS.lock().await;
        map.remove(&key).unwrap_or_default()
    };
    let aborted_source_ids: Vec<String> = runs
        .iter()
        .filter_map(|r| r.source_message_id.clone())
        .collect();
    let count = runs.len();
    for run in runs {
        run.cancelled.store(true, Ordering::SeqCst);
        run.notify.notify_waiters();
    }
    if !aborted_source_ids.is_empty() {
        let mut guard = ABORTED_SOURCE_MESSAGE_IDS.lock().await;
        let ids = guard.entry(key).or_default();
        for id in aborted_source_ids {
            ids.insert(id);
        }
    }
    count
}

pub fn is_cancelled(flag: &AtomicBool) -> bool {
    flag.load(Ordering::SeqCst)
}

pub async fn is_aborted_source_message(channel: &str, chat_id: i64, message_id: &str) -> bool {
    let key = (channel.to_string(), chat_id);
    let guard = ABORTED_SOURCE_MESSAGE_IDS.lock().await;
    guard
        .get(&key)
        .map(|ids| ids.contains(message_id))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_abort_runs_marks_cancelled() {
        let channel = "test.abort";
        let chat_id = 101;
        let (run_id, cancelled, _notify) =
            register_run(channel, chat_id, Some("u1".to_string())).await;
        assert!(!is_cancelled(&cancelled));

        let aborted = abort_runs(channel, chat_id).await;
        assert_eq!(aborted, 1);
        assert!(is_cancelled(&cancelled));
        assert!(is_aborted_source_message(channel, chat_id, "u1").await);

        unregister_run(channel, chat_id, run_id).await;
    }

    #[tokio::test]
    async fn test_abort_runs_without_active_returns_zero() {
        let aborted = abort_runs("test.none", 999).await;
        assert_eq!(aborted, 0);
    }
}
