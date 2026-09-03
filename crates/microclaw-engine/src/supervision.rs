//! Supervised background loops.
//!
//! A plain `tokio::spawn`ed loop that panics dies silently — the scheduler,
//! reflector, or heartbeat simply stops until the process restarts, with
//! nothing but one log line at panic time. Loops spawned through
//! [`spawn_supervised`] instead restart with capped exponential backoff, and
//! every restart is counted in a process-wide registry that `insights`
//! surfaces — "scheduler restarted 14× today" becomes visible instead of a
//! mystery.

use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::{Mutex, OnceLock};

use futures_util::FutureExt;
use tracing::error;

/// Backoff cap between restarts of a crash-looping task.
const MAX_BACKOFF_MS: u64 = 300_000;

static RESTARTS: OnceLock<Mutex<HashMap<&'static str, u64>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<&'static str, u64>> {
    RESTARTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn record_restart(task_name: &'static str) -> u64 {
    let mut counts = registry().lock().expect("restart registry poisoned");
    let count = counts.entry(task_name).or_insert(0);
    *count += 1;
    *count
}

/// Snapshot of `(task_name, restart_count)` sorted by name. Empty when no
/// supervised task has ever panicked.
pub fn restart_counts() -> Vec<(&'static str, u64)> {
    let counts = registry().lock().expect("restart registry poisoned");
    let mut out: Vec<_> = counts.iter().map(|(k, v)| (*k, *v)).collect();
    out.sort_by_key(|(name, _)| *name);
    out
}

/// Spawn a background loop that survives its own panics. `make` builds a
/// fresh instance of the loop future; on panic the task is rebuilt and
/// restarted after a capped exponential backoff. A future that returns
/// normally ends the supervision (loops that finish on purpose stay
/// finished).
pub fn spawn_supervised<F, Fut>(task_name: &'static str, make: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_supervised_with_backoff(task_name, 1_000, make);
}

fn spawn_supervised_with_backoff<F, Fut>(task_name: &'static str, initial_backoff_ms: u64, make: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff_ms = initial_backoff_ms.max(1);
        loop {
            match AssertUnwindSafe(make()).catch_unwind().await {
                Ok(()) => break,
                Err(payload) => {
                    let restarts = record_restart(task_name);
                    error!(
                        "Background task '{task_name}' panicked (restart #{restarts}); \
                         restarting in {backoff_ms}ms. reason={}",
                        panic_message(&*payload)
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms.saturating_mul(2)).min(MAX_BACKOFF_MS);
                }
            }
        }
    });
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn panicking_task_restarts_and_is_counted() {
        let attempts = Arc::new(AtomicU64::new(0));
        let attempts_in = attempts.clone();
        spawn_supervised_with_backoff("test-crashy-loop", 5, move || {
            let attempts = attempts_in.clone();
            async move {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    panic!("boom {n}");
                }
                // Third attempt completes normally — supervision ends.
            }
        });
        // Two panics with 5ms/10ms backoff: give it ample time.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while attempts.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("supervised task did not restart in time");

        let counts = restart_counts();
        let entry = counts.iter().find(|(name, _)| *name == "test-crashy-loop");
        assert_eq!(entry.map(|(_, c)| *c), Some(2));
    }

    #[tokio::test]
    async fn completing_task_is_not_counted() {
        spawn_supervised_with_backoff("test-clean-loop", 5, || async {});
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(restart_counts()
            .iter()
            .all(|(name, _)| *name != "test-clean-loop"));
    }
}
