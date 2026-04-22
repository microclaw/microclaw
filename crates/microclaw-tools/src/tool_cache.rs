//! Tool result cache helpers.
//!
//! Cache-key derivation and opt-in tool list. The actual read/write goes
//! through `microclaw_storage::db::Database::{get,put}_cached_tool_result`,
//! which keeps the storage contract in one place.

use std::collections::HashMap;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Tools allowed to participate in caching, with default TTL.
/// Expanding this list is a config decision; read-only network/tool calls
/// are the prime candidates.
pub fn default_ttls() -> HashMap<&'static str, Duration> {
    let mut m = HashMap::new();
    m.insert("web_fetch", Duration::from_secs(15 * 60));
    m.insert("web_search", Duration::from_secs(10 * 60));
    m.insert("osv_check", Duration::from_secs(60 * 60));
    m.insert("describe_image", Duration::from_secs(60 * 60));
    m.insert("session_search", Duration::from_secs(60));
    m
}

/// Normalize a JSON value so structurally-equivalent inputs produce the
/// same cache key. Objects are key-sorted; arrays keep order. Auth
/// context fields are removed so identical requests from different
/// callers collide intentionally (tool cache is per-input, not per-user).
pub fn normalize_input_for_key(input: &serde_json::Value) -> serde_json::Value {
    match input {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map
                .keys()
                .filter(|k| !k.starts_with("__microclaw_"))
                .cloned()
                .collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(v) = map.get(&k) {
                    out.insert(k, normalize_input_for_key(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(normalize_input_for_key).collect())
        }
        other => other.clone(),
    }
}

/// Compute the cache key for (`tool_name`, `input`). Uses SHA-256 hex
/// over a canonical JSON encoding.
pub fn cache_key(tool_name: &str, input: &serde_json::Value) -> String {
    let canonical =
        serde_json::to_string(&normalize_input_for_key(input)).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update(b":");
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_key_order_is_irrelevant() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(cache_key("t", &a), cache_key("t", &b));
    }

    #[test]
    fn auth_context_is_stripped() {
        let with_auth = json!({"q": "x", "__microclaw_auth": {"caller_chat_id": 1}});
        let without = json!({"q": "x"});
        assert_eq!(cache_key("t", &with_auth), cache_key("t", &without));
    }

    #[test]
    fn different_tools_collide_differently() {
        let v = json!({"q": "x"});
        assert_ne!(cache_key("a", &v), cache_key("b", &v));
    }

    #[test]
    fn array_order_matters() {
        let a = json!([1, 2, 3]);
        let b = json!([3, 2, 1]);
        assert_ne!(cache_key("t", &a), cache_key("t", &b));
    }
}
