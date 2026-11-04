//! In-run approval suspension.
//!
//! By default a high-risk tool call that needs a human ends the run with an
//! approval prompt, and the *next* user message ("1"/"2"/"3", "approve", …)
//! resolves it. That suits chat channels, where the reply really is the next
//! message.
//!
//! An embedding caller that can answer while the run is still going (the
//! MicroClaw Code TUI, an SDK host with its own dialog) registers a broker
//! for its `(channel, chat_id)` for the duration of the run. The tool executor
//! then emits `ApprovalRequired` with a fresh `approval_id`, waits here for
//! [`resolve`], and continues the same run: it retries the tool, records a
//! standing grant, or returns a "denied" tool result to the model.
//!
//! Without a registered broker nothing changes: the text path stays.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use tokio::sync::oneshot;

type BrokerKey = (String, i64);

/// A caller's answer to a pending approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    ApproveOnce,
    /// Approve and record a standing per-chat allowance for the tool.
    ApproveAlways,
    Deny,
}

impl ApprovalDecision {
    /// Parse a decision string: the option values of the approval card
    /// (`1`/`2`/`3`) or the words `approve`/`approve_once`, `always`/
    /// `approve_always`, `deny`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "approve" | "approve_once" | "once" | "yes" => Some(Self::ApproveOnce),
            "2" | "always" | "approve_always" | "always_allow" => Some(Self::ApproveAlways),
            "3" | "deny" | "reject" | "no" => Some(Self::Deny),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Slot {
    generation: u64,
    /// Pending approvals in the order they were opened.
    pending: Vec<(String, oneshot::Sender<ApprovalDecision>)>,
}

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static BROKERS: LazyLock<Mutex<HashMap<BrokerKey, Slot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn brokers() -> std::sync::MutexGuard<'static, HashMap<BrokerKey, Slot>> {
    BROKERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Keeps a broker registered; dropping it unregisters the broker and denies
/// anything still pending (the waiting run, if any, is going away too).
#[must_use = "the broker is unregistered when the guard is dropped"]
pub struct BrokerGuard {
    key: BrokerKey,
    generation: u64,
}

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let mut map = brokers();
        if map
            .get(&self.key)
            .is_some_and(|slot| slot.generation == self.generation)
        {
            // Dropping the senders wakes the waiters with a closed channel,
            // which they treat as a denial.
            map.remove(&self.key);
        }
    }
}

/// Register an in-run approval broker for `(channel, chat_id)`. A later
/// registration for the same key replaces the earlier one.
pub fn register(channel: &str, chat_id: i64) -> BrokerGuard {
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    let key = (channel.to_string(), chat_id);
    brokers().insert(
        key.clone(),
        Slot {
            generation,
            pending: Vec::new(),
        },
    );
    BrokerGuard { key, generation }
}

/// Whether a caller is registered to answer approvals in-run.
pub fn is_registered(channel: &str, chat_id: i64) -> bool {
    brokers().contains_key(&(channel.to_string(), chat_id))
}

/// Open a pending approval. Returns `None` when no broker is registered,
/// in which case the caller falls back to the text approval path.
pub fn open(
    channel: &str,
    chat_id: i64,
    approval_id: &str,
) -> Option<oneshot::Receiver<ApprovalDecision>> {
    let mut map = brokers();
    let slot = map.get_mut(&(channel.to_string(), chat_id))?;
    let (tx, rx) = oneshot::channel();
    slot.pending.push((approval_id.to_string(), tx));
    Some(rx)
}

/// Withdraw a pending approval that is no longer awaited.
pub fn close(channel: &str, chat_id: i64, approval_id: &str) {
    if let Some(slot) = brokers().get_mut(&(channel.to_string(), chat_id)) {
        slot.pending.retain(|(id, _)| id != approval_id);
    }
}

/// Resolve a pending approval. An empty `approval_id` resolves the oldest
/// pending one. Returns `false` when nothing matched.
pub fn resolve(channel: &str, chat_id: i64, approval_id: &str, decision: ApprovalDecision) -> bool {
    let sender = {
        let mut map = brokers();
        let Some(slot) = map.get_mut(&(channel.to_string(), chat_id)) else {
            return false;
        };
        let index = if approval_id.trim().is_empty() {
            (!slot.pending.is_empty()).then_some(0)
        } else {
            slot.pending.iter().position(|(id, _)| id == approval_id)
        };
        match index {
            Some(index) => slot.pending.remove(index).1,
            None => return false,
        }
    };
    sender.send(decision).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decisions() {
        assert_eq!(
            ApprovalDecision::parse("1"),
            Some(ApprovalDecision::ApproveOnce)
        );
        assert_eq!(
            ApprovalDecision::parse(" Always "),
            Some(ApprovalDecision::ApproveAlways)
        );
        assert_eq!(ApprovalDecision::parse("3"), Some(ApprovalDecision::Deny));
        assert_eq!(ApprovalDecision::parse("maybe"), None);
    }

    #[tokio::test]
    async fn resolves_by_id_and_oldest() {
        let guard = register("broker-test", 1);
        assert!(is_registered("broker-test", 1));
        let first = open("broker-test", 1, "a").unwrap();
        let second = open("broker-test", 1, "b").unwrap();
        assert!(resolve("broker-test", 1, "b", ApprovalDecision::Deny));
        assert_eq!(second.await.unwrap(), ApprovalDecision::Deny);
        assert!(resolve("broker-test", 1, "", ApprovalDecision::ApproveOnce));
        assert_eq!(first.await.unwrap(), ApprovalDecision::ApproveOnce);
        assert!(!resolve("broker-test", 1, "", ApprovalDecision::Deny));
        drop(guard);
        assert!(!is_registered("broker-test", 1));
        assert!(open("broker-test", 1, "c").is_none());
    }

    #[tokio::test]
    async fn dropping_the_guard_closes_pending_waits() {
        let guard = register("broker-test", 2);
        let pending = open("broker-test", 2, "a").unwrap();
        drop(guard);
        assert!(pending.await.is_err());
    }

    #[test]
    fn a_newer_registration_survives_an_older_guard() {
        let old = register("broker-test", 3);
        let new = register("broker-test", 3);
        drop(old);
        assert!(is_registered("broker-test", 3));
        drop(new);
        assert!(!is_registered("broker-test", 3));
    }
}
