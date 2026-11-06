//! Embedder-supplied tool gate: a callback consulted before (and after)
//! every tool call at the registry choke point.
//!
//! Embedders such as MicroClaw Code use it for permission rules
//! (`allow` / `ask` / `deny` per tool, path or command) and for user hooks
//! (`pre_tool_use` / `post_tool_use`). The gate runs after the operator
//! `tool_policy` and egress checks, so it can only tighten them, and before
//! the high-risk approval gate:
//!
//! - [`ToolGateDecision::Allow`]: continue (the normal approval rules still
//!   apply, e.g. `bash` still asks where approvals are required).
//! - [`ToolGateDecision::Approve`]: continue without asking even where the
//!   tool would normally need an approval (an explicit allow rule).
//! - [`ToolGateDecision::Ask`]: the call needs a person's approval, whatever
//!   the tool's risk; it goes through the same in-run approval flow as
//!   high-risk tools.
//! - [`ToolGateDecision::Deny`]: the call is not executed; the reason is
//!   returned to the model.
//!
//! A decision may also replace the tool input (`updated_input`).

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

/// One tool call as seen by the gate.
#[derive(Debug, Clone)]
pub struct ToolGateCall<'a> {
    pub tool: &'a str,
    /// The tool input, without internal `__microclaw_*` keys.
    pub input: &'a Value,
    pub caller_channel: &'a str,
    /// `main` for the main agent, otherwise the principal (`subagent:<id>`).
    pub principal: &'a str,
    pub chat_id: i64,
    /// The person already approved this call (in-run approval retry).
    pub approved: bool,
}

/// What to do with a tool call.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolGateDecision {
    Allow,
    Approve { rule: Option<String> },
    Ask { reason: Option<String> },
    Deny { reason: String },
}

/// A decision plus an optional replacement input.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolGateOutcome {
    pub decision: ToolGateDecision,
    pub updated_input: Option<Value>,
}

impl ToolGateOutcome {
    pub fn allow() -> Self {
        Self {
            decision: ToolGateDecision::Allow,
            updated_input: None,
        }
    }

    pub fn with(decision: ToolGateDecision) -> Self {
        Self {
            decision,
            updated_input: None,
        }
    }
}

/// The tool result as seen by [`ToolGate::after`].
#[derive(Debug, Clone)]
pub struct ToolGateResult<'a> {
    pub content: &'a str,
    pub is_error: bool,
    pub error_type: Option<&'a str>,
}

#[async_trait]
pub trait ToolGate: Send + Sync {
    /// Decide on a call before it runs.
    async fn before(&self, call: &ToolGateCall<'_>) -> ToolGateOutcome;

    /// Observe a finished call. Returned text is appended to the tool result
    /// the model sees (extra context, e.g. from a `post_tool_use` hook).
    async fn after(
        &self,
        _call: &ToolGateCall<'_>,
        _result: &ToolGateResult<'_>,
    ) -> Option<String> {
        None
    }
}

/// Shared, optional gate stored in the configuration (not serialized).
#[derive(Clone, Default)]
pub struct ToolGateHandle(pub Option<Arc<dyn ToolGate>>);

impl ToolGateHandle {
    pub fn new(gate: Arc<dyn ToolGate>) -> Self {
        Self(Some(gate))
    }

    pub fn get(&self) -> Option<&Arc<dyn ToolGate>> {
        self.0.as_ref()
    }
}

impl fmt::Debug for ToolGateHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "ToolGateHandle(Some)"
        } else {
            "ToolGateHandle(None)"
        })
    }
}

/// Copy of `input` without internal `__microclaw_*` keys.
pub fn public_input(input: &Value) -> Value {
    match input {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| !k.starts_with("__microclaw"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Re-attach the internal keys of `original` to a gate-supplied input.
pub fn merge_internal_keys(original: &Value, updated: Value) -> Value {
    match (original, updated) {
        (Value::Object(orig), Value::Object(mut new)) => {
            for (k, v) in orig {
                if k.starts_with("__microclaw") {
                    new.insert(k.clone(), v.clone());
                }
            }
            Value::Object(new)
        }
        (_, updated) => updated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strips_and_restores_internal_keys() {
        let input = json!({"command": "ls", "__microclaw_auth": {"x": 1}});
        assert_eq!(public_input(&input), json!({"command": "ls"}));
        let merged = merge_internal_keys(&input, json!({"command": "ls -la"}));
        assert_eq!(merged["command"], "ls -la");
        assert_eq!(merged["__microclaw_auth"]["x"], 1);
    }
}
