use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::future::AbortHandle;

#[derive(Default)]
pub struct InflightRuns {
    next_id: AtomicU64,
    inner: Mutex<HashMap<i64, HashMap<u64, AbortHandle>>>,
}

impl InflightRuns {
    pub fn register(self: &Arc<Self>, chat_id: i64, handle: AbortHandle) -> InflightRunGuard {
        let run_id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut inner = self.inner.lock().expect("inflight runs lock poisoned");
        inner.entry(chat_id).or_default().insert(run_id, handle);
        InflightRunGuard {
            inflight: self.clone(),
            chat_id,
            run_id,
        }
    }

    pub fn abort_chat(&self, chat_id: i64) -> usize {
        let handles = {
            let mut inner = self.inner.lock().expect("inflight runs lock poisoned");
            inner
                .remove(&chat_id)
                .map(|runs| runs.into_values().collect::<Vec<_>>())
                .unwrap_or_default()
        };

        for handle in &handles {
            handle.abort();
        }
        handles.len()
    }

    fn unregister(&self, chat_id: i64, run_id: u64) {
        let mut inner = self.inner.lock().expect("inflight runs lock poisoned");
        if let Some(runs) = inner.get_mut(&chat_id) {
            runs.remove(&run_id);
            if runs.is_empty() {
                inner.remove(&chat_id);
            }
        }
    }
}

pub struct InflightRunGuard {
    inflight: Arc<InflightRuns>,
    chat_id: i64,
    run_id: u64,
}

impl Drop for InflightRunGuard {
    fn drop(&mut self) {
        self.inflight.unregister(self.chat_id, self.run_id);
    }
}
