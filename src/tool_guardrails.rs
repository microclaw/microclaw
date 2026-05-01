//! Per-turn tool-call guardrails.
//!
//! Sits alongside the existing `recent_tool_call_keys` circuit breaker (which
//! short-circuits identical-(tool,args) calls after N repeats). This module
//! adds two finer-grained signals from hermes-agent's `tool_guardrails.py`:
//!
//! * **Idempotent no-progress**: if a read-only tool returns the same result
//!   hash N times for the same args, append a guidance suffix to the tool
//!   result asking the model to use what it already has instead of repeating.
//! * **Same-tool failure streak**: if any tool fails N times this turn — with
//!   ANY args — append guidance suggesting a different approach.
//!
//! Both signals only emit warnings (the result still goes back to the model);
//! they never block execution. The existing duplicate-call circuit breaker
//! handles the blocking case for identical (tool, args) repeats.
//!
//! The Controller is reset per turn by the agent loop.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::tools::IDEMPOTENT_TOOLS;

/// Default thresholds (keeping warnings light — these are nudges, not gates).
const NO_PROGRESS_WARN_AFTER: usize = 2;
const SAME_TOOL_FAILURE_WARN_AFTER: usize = 3;

#[derive(Default)]
pub struct GuardrailController {
    /// (tool_name, args_hash) -> (last_result_hash, repeat_count)
    no_progress: HashMap<(String, String), (String, usize)>,
    /// tool_name -> failure_count
    same_tool_failures: HashMap<String, usize>,
}

impl GuardrailController {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset_for_turn(&mut self) {
        self.no_progress.clear();
        self.same_tool_failures.clear();
    }

    /// Record a tool result and return an optional guidance suffix to append
    /// to the tool's result content.
    pub fn after_call(
        &mut self,
        tool_name: &str,
        args_hash: &str,
        result: &str,
        failed: bool,
    ) -> Option<String> {
        if failed {
            // Reset no-progress tracking for this signature; failure isn't
            // "no progress", it's "regression".
            self.no_progress
                .remove(&(tool_name.to_string(), args_hash.to_string()));
            let count = self
                .same_tool_failures
                .entry(tool_name.to_string())
                .or_insert(0);
            *count += 1;
            if *count >= SAME_TOOL_FAILURE_WARN_AFTER {
                return Some(format!(
                    "\n\n[Tool loop warning: `{tool_name}` has failed {count} time(s) this turn. \
                     This looks like a loop — change approach (different tool, different inputs, \
                     or summarize what you know and proceed) before retrying.]"
                ));
            }
            return None;
        }

        // Successful call — reset failure streak for this tool.
        self.same_tool_failures.remove(tool_name);

        if !is_idempotent(tool_name) {
            return None;
        }

        let result_hash = hash_str(result);
        let key = (tool_name.to_string(), args_hash.to_string());
        let entry = self
            .no_progress
            .entry(key)
            .or_insert((result_hash.clone(), 0));
        if entry.0 == result_hash {
            entry.1 += 1;
        } else {
            *entry = (result_hash, 1);
        }
        let count = entry.1;
        if count >= NO_PROGRESS_WARN_AFTER {
            return Some(format!(
                "\n\n[Tool loop warning: `{tool_name}` has returned the same result \
                 {count} time(s) for the same arguments. Use the result you already have \
                 — re-running it won't change the answer.]"
            ));
        }
        None
    }
}

fn is_idempotent(tool_name: &str) -> bool {
    IDEMPOTENT_TOOLS.contains(&tool_name)
}

fn hash_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    // First 16 hex chars are plenty for collision resistance within a turn.
    format!("{:x}", digest)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_no_progress_warns_on_third_identical() {
        let mut c = GuardrailController::new();
        assert!(c
            .after_call("read_file", "h1", "file contents", false)
            .is_none());
        // 2nd call same args same result => count=2 => warn at threshold (2)
        let warn = c.after_call("read_file", "h1", "file contents", false);
        assert!(warn.is_some());
        assert!(warn.unwrap().contains("same result"));
    }

    #[test]
    fn idempotent_changing_result_does_not_warn() {
        let mut c = GuardrailController::new();
        c.after_call("read_file", "h1", "v1", false);
        c.after_call("read_file", "h1", "v2", false);
        let warn = c.after_call("read_file", "h1", "v3", false);
        assert!(warn.is_none());
    }

    #[test]
    fn mutating_tool_no_warning_on_repeat() {
        let mut c = GuardrailController::new();
        c.after_call("write_file", "h1", "ok", false);
        let warn = c.after_call("write_file", "h1", "ok", false);
        assert!(warn.is_none());
    }

    #[test]
    fn same_tool_failure_streak_warns() {
        let mut c = GuardrailController::new();
        c.after_call("bash", "h1", "err1", true);
        c.after_call("bash", "h2", "err2", true);
        // Third failure (any args) => warn
        let warn = c.after_call("bash", "h3", "err3", true);
        assert!(warn.is_some());
        assert!(warn.unwrap().contains("failed 3"));
    }

    #[test]
    fn success_resets_failure_streak() {
        let mut c = GuardrailController::new();
        c.after_call("bash", "h1", "err1", true);
        c.after_call("bash", "h2", "err2", true);
        c.after_call("bash", "h3", "ok", false);
        // After success, streak resets; next two failures should NOT warn.
        let warn = c.after_call("bash", "h4", "err4", true);
        assert!(warn.is_none());
        let warn = c.after_call("bash", "h5", "err5", true);
        assert!(warn.is_none());
    }

    #[test]
    fn failure_does_not_increment_no_progress() {
        let mut c = GuardrailController::new();
        c.after_call("read_file", "h1", "ok", false);
        c.after_call("read_file", "h1", "err", true);
        let warn = c.after_call("read_file", "h1", "ok", false);
        // Failure cleared the no-progress counter, so we're at count=1 again.
        assert!(warn.is_none());
    }

    #[test]
    fn reset_for_turn_clears_state() {
        let mut c = GuardrailController::new();
        c.after_call("read_file", "h1", "v1", false);
        c.after_call("read_file", "h1", "v1", false);
        c.reset_for_turn();
        let warn = c.after_call("read_file", "h1", "v1", false);
        assert!(warn.is_none());
    }
}
