//! Anthropic prompt-cache breakpoints (system_and_3 strategy).
//!
//! Anthropic accepts up to 4 `cache_control` markers per request. This module
//! places one on the system prompt (stable across the whole session) and one
//! each on the last 3 non-system messages (rolling window of recent turns).
//! On a multi-turn chat that means the second turn re-uses the prefix from
//! the first, the third re-uses the second's prefix, etc., cutting input
//! token cost by ~75%.
//!
//! Implementation note: rather than threading a `cache_control` field through
//! the typed `MessagesRequest`/`Message`/`ContentBlock` shapes (which would
//! pollute the OpenAI-compat path), we serialize the request to a
//! `serde_json::Value` and mutate it just before send. The mutation upgrades
//! `system: "..."` to `system: [{type: "text", text: "...", cache_control}]`
//! and attaches `cache_control` to the LAST content block of each targeted
//! message (Anthropic's documented attachment point).
//!
//! Hermes reference: `agent/prompt_caching.py:apply_anthropic_cache_control`.

use serde_json::{json, Value};

const MAX_BREAKPOINTS: usize = 4;

/// Mutate an Anthropic `/v1/messages` request body in-place to add prompt-cache
/// breakpoints. Safe to call on any request: if the structure isn't what we
/// expect we leave it alone and the API just doesn't cache.
pub fn apply_anthropic_prompt_cache(body: &mut Value, ttl: &str) {
    let marker = build_marker(ttl);

    let mut budget = MAX_BREAKPOINTS;

    if let Some(obj) = body.as_object_mut() {
        if let Some(system) = obj.get_mut("system") {
            if mark_system(system, &marker) {
                budget -= 1;
            }
        }

        if budget == 0 {
            return;
        }

        if let Some(messages) = obj.get_mut("messages").and_then(|v| v.as_array_mut()) {
            // last `budget` non-system messages — in microclaw the messages
            // array never contains a "system" role (system is a top-level
            // field), but we filter defensively for parity with hermes.
            let mut targets: Vec<usize> = messages
                .iter()
                .enumerate()
                .filter(|(_, m)| {
                    m.get("role")
                        .and_then(|r| r.as_str())
                        .map(|r| r != "system")
                        .unwrap_or(true)
                })
                .map(|(i, _)| i)
                .collect();
            let take = budget.min(targets.len());
            let start = targets.len().saturating_sub(take);
            targets.drain(..start);
            for idx in targets {
                mark_message(&mut messages[idx], &marker);
            }
        }
    }
}

fn build_marker(ttl: &str) -> Value {
    if ttl == "1h" {
        json!({"type": "ephemeral", "ttl": "1h"})
    } else {
        json!({"type": "ephemeral"})
    }
}

/// Promote the system prompt to a structured array so cache_control can attach
/// to it. Returns true if a breakpoint was placed.
fn mark_system(system: &mut Value, marker: &Value) -> bool {
    match system {
        Value::String(s) => {
            if s.is_empty() {
                return false;
            }
            *system = json!([{
                "type": "text",
                "text": s.clone(),
                "cache_control": marker,
            }]);
            true
        }
        Value::Array(blocks) => {
            if let Some(last) = blocks.last_mut() {
                attach_marker_to_block(last, marker);
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Attach a cache_control marker to a single message. The marker goes on the
/// LAST content block; if `content` is a plain string we lift it into a single
/// text block first.
fn mark_message(msg: &mut Value, marker: &Value) {
    let Some(obj) = msg.as_object_mut() else {
        return;
    };
    let content = obj.entry("content").or_insert(Value::Null);
    match content {
        Value::String(s) => {
            *content = json!([{
                "type": "text",
                "text": s.clone(),
                "cache_control": marker,
            }]);
        }
        Value::Array(blocks) => {
            if let Some(last) = blocks.last_mut() {
                attach_marker_to_block(last, marker);
            }
        }
        _ => {
            // Null / number / bool — unusual, skip.
        }
    }
}

fn attach_marker_to_block(block: &mut Value, marker: &Value) {
    if let Some(obj) = block.as_object_mut() {
        obj.insert("cache_control".to_string(), marker.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ephemeral() -> Value {
        json!({"type": "ephemeral"})
    }

    #[test]
    fn marks_system_string_as_block_array() {
        let mut body = json!({
            "model": "claude-sonnet-4-5",
            "system": "You are helpful.",
            "messages": [],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        let sys = &body["system"];
        assert!(sys.is_array());
        assert_eq!(sys[0]["text"], "You are helpful.");
        assert_eq!(sys[0]["cache_control"], ephemeral());
    }

    #[test]
    fn empty_system_string_no_marker() {
        let mut body = json!({
            "model": "claude-sonnet-4-5",
            "system": "",
            "messages": [
                {"role": "user", "content": "hi"},
            ],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        // Empty system stays a string, not promoted; the user message still
        // gets a marker.
        assert!(body["system"].is_string());
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"],
            ephemeral()
        );
    }

    #[test]
    fn marks_last_three_non_system_messages() {
        let mut body = json!({
            "system": "S",
            "messages": [
                {"role": "user", "content": "m1"},
                {"role": "assistant", "content": "m2"},
                {"role": "user", "content": "m3"},
                {"role": "assistant", "content": "m4"},
                {"role": "user", "content": "m5"},
            ],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        // m1, m2 unchanged; m3, m4, m5 each carry a marker on their lifted text block.
        assert!(body["messages"][0]["content"].is_string(), "m1 untouched");
        assert!(body["messages"][1]["content"].is_string(), "m2 untouched");
        for i in [2, 3, 4] {
            assert_eq!(
                body["messages"][i]["content"][0]["cache_control"],
                ephemeral(),
                "m{} should be marked",
                i + 1
            );
        }
    }

    #[test]
    fn marks_last_block_when_content_is_array() {
        let mut body = json!({
            "system": "S",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "first"},
                        {"type": "text", "text": "second"},
                    ],
                },
            ],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        let blocks = &body["messages"][0]["content"];
        assert!(blocks[0].get("cache_control").is_none());
        assert_eq!(blocks[1]["cache_control"], ephemeral());
    }

    #[test]
    fn ttl_1h_marker() {
        let mut body = json!({
            "system": "S",
            "messages": [],
        });
        apply_anthropic_prompt_cache(&mut body, "1h");
        assert_eq!(body["system"][0]["cache_control"]["ttl"], "1h");
    }

    #[test]
    fn budget_capped_at_four_total() {
        let mut body = json!({
            "system": "S",
            "messages": [
                {"role": "user", "content": "m1"},
                {"role": "assistant", "content": "m2"},
                {"role": "user", "content": "m3"},
                {"role": "assistant", "content": "m4"},
                {"role": "user", "content": "m5"},
            ],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        // 1 system + 3 messages = 4. The 4th-from-end (m2) must NOT be marked.
        assert!(body["messages"][1]["content"].is_string());
    }

    #[test]
    fn no_messages_just_system() {
        let mut body = json!({
            "system": "S",
            "messages": [],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        assert_eq!(body["system"][0]["cache_control"], ephemeral());
    }

    #[test]
    fn missing_system_field_safe() {
        let mut body = json!({
            "messages": [{"role": "user", "content": "hi"}],
        });
        apply_anthropic_prompt_cache(&mut body, "5m");
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"],
            ephemeral()
        );
    }
}
