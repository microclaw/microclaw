/// Round-robin API-key pool. Providers read `current()` per request and
/// call `advance()` on auth (401/403) or rate-limit (429) errors so a
/// multi-account setup keeps working when one key is throttled or revoked.
#[derive(Clone)]
pub struct KeyPool {
    keys: std::sync::Arc<Vec<String>>,
    index: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    rotations: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl KeyPool {
    pub fn new(primary: &str, extra: &[String]) -> Self {
        let mut keys: Vec<String> = Vec::with_capacity(1 + extra.len());
        keys.push(primary.to_string());
        for key in extra {
            let key = key.trim();
            if !key.is_empty() && !keys.iter().any(|k| k == key) {
                keys.push(key.to_string());
            }
        }
        KeyPool {
            keys: std::sync::Arc::new(keys),
            index: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rotations: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn current(&self) -> String {
        let idx = self.index.load(std::sync::atomic::Ordering::Relaxed) % self.keys.len();
        self.keys[idx].clone()
    }

    /// Rotate to the next key. Returns `false` (and does nothing) when the
    /// pool has a single key, so callers can skip a pointless retry.
    pub fn advance(&self) -> bool {
        if self.keys.len() <= 1 {
            return false;
        }
        self.index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.rotations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn rotations(&self) -> u64 {
        self.rotations.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Statuses where rotating to another API key can plausibly help: bad or
/// revoked credentials and per-account rate limits.
pub(crate) fn is_key_rotation_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 429)
}

#[cfg(test)]
mod key_pool_tests {
    use super::*;

    #[test]
    fn key_pool_rotates_round_robin_and_dedupes() {
        let pool = KeyPool::new("k1", &["k2".into(), " ".into(), "k1".into(), "k3".into()]);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.current(), "k1");
        assert!(pool.advance());
        assert_eq!(pool.current(), "k2");
        assert!(pool.advance());
        assert_eq!(pool.current(), "k3");
        assert!(pool.advance());
        assert_eq!(pool.current(), "k1");
        assert_eq!(pool.rotations(), 3);
    }

    #[test]
    fn single_key_pool_never_advances() {
        let pool = KeyPool::new("only", &[]);
        assert!(!pool.advance());
        assert_eq!(pool.current(), "only");
        assert_eq!(pool.rotations(), 0);
    }

    #[test]
    fn rotation_statuses() {
        assert!(is_key_rotation_status(401));
        assert!(is_key_rotation_status(403));
        assert!(is_key_rotation_status(429));
        assert!(!is_key_rotation_status(500));
    }
}
