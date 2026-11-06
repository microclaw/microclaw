//! The Code tool gate: permission rules and hooks applied at the engine choke point.
//!
//! [`CodeToolGate`] implements the engine's [`ToolGate`]; install it with the
//! SDK builder's `tool_gate(Arc::new(gate.clone()))`. Every tool call of the
//! main agent and of sub-agents passes through it:
//!
//! - `before`: permission rules first (deny → the call is refused with the
//!   rule named; ask → in-run approval), then `pre_tool_use` hooks, whose
//!   `permissionDecision` / exit 2 / `updatedInput` are honoured (a hook
//!   `allow` skips the approval prompt unless a rule asked). On the approval
//!   retry (`call.approved`) hooks are not run again; deny rules still apply
//!   and an input rewritten by the first pass is re-applied.
//! - `after`: `post_tool_use` hooks for every tool and `post_edit` hooks
//!   (once per edited file) after successful edits; their
//!   `additionalContext` and block reasons are appended to the tool result.
//!
//! Allow rules return [`ToolGateDecision::Allow`], never `Approve`: the
//! driver auto-approves allowed bash commands itself (and shows a notice),
//! see [`CodeToolGate::allows_command`].
//!
//! Internal bookkeeping tools ([`UNGATED_TOOLS`]: progress, todo, clarify,
//! context and time helpers) are never gated: they touch nothing outside the
//! session, and a `tool(*)` rule or a catch-all hook should not break them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use microclaw_sdk::{ToolGate, ToolGateCall, ToolGateDecision, ToolGateOutcome, ToolGateResult};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedSender;

use crate::rules::{Effect, OUTSIDE_PROJECT, PermissionRules, edited_paths};
use crate::user_hooks::{HookDecision, HookEvent, HookPayload, UserHooks};

/// Tools the gate never looks at.
pub const UNGATED_TOOLS: &[&str] = &[
    "report_progress",
    "todo_read",
    "todo_write",
    "clarify",
    "context_note",
    "rewind_context",
    "get_current_time",
    "compare_time",
    "calculate",
    "time_math",
    "subagents_list",
    "subagents_info",
];

/// Something the gate did that the UI may want to show.
#[derive(Debug, Clone, PartialEq)]
pub enum GateEvent {
    /// A call was refused (by a rule or a hook).
    Denied { tool: String, reason: String },
    /// A rule (or the implicit outside-the-project rule) asked for approval.
    AskedByRule { tool: String, rule: String },
    /// A hook's `systemMessage` or stop request.
    HookMessage { event: HookEvent, text: String },
    /// A hook failed (bad exit code, timeout, HTTP error); not blocking.
    HookFailed { event: HookEvent, error: String },
}

/// The gate's reloadable state.
#[derive(Debug)]
pub struct GateState {
    pub rules: PermissionRules,
    pub hooks: Arc<UserHooks>,
    pub root: PathBuf,
}

/// What a `pre_tool_use` pass left for the approval retry / `after`.
#[derive(Debug, Default)]
struct Pending {
    updated_input: Option<Value>,
    context: Option<String>,
}

const MAX_PENDING: usize = 64;

/// Permission rules + user hooks as an engine [`ToolGate`].
#[derive(Clone)]
pub struct CodeToolGate {
    state: Arc<RwLock<GateState>>,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    events: Option<UnboundedSender<GateEvent>>,
}

impl std::fmt::Debug for CodeToolGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeToolGate").finish_non_exhaustive()
    }
}

fn pending_key(tool: &str, input: &Value) -> String {
    format!("{tool}\u{0}{input}")
}

impl CodeToolGate {
    pub fn new(rules: PermissionRules, hooks: Arc<UserHooks>, root: impl Into<PathBuf>) -> Self {
        Self {
            state: Arc::new(RwLock::new(GateState {
                rules,
                hooks,
                root: root.into(),
            })),
            pending: Arc::default(),
            events: None,
        }
    }

    /// Report what the gate does on `tx`.
    pub fn with_events(mut self, tx: UnboundedSender<GateEvent>) -> Self {
        self.events = Some(tx);
        self
    }

    /// Replace rules and hooks (settings reloaded). Clones share the state.
    pub fn update(&self, rules: PermissionRules, hooks: Arc<UserHooks>) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.rules = rules;
        state.hooks = hooks;
    }

    /// Run `f` with the current rules.
    pub fn with_rules<R>(&self, f: impl FnOnce(&PermissionRules) -> R) -> R {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        f(&state.rules)
    }

    /// The allow rule covering `command` (no deny / ask rule matching).
    pub fn allows_command(&self, command: &str) -> Option<String> {
        self.with_rules(|r| r.allows_command(command).map(str::to_string))
    }

    /// The current hooks.
    pub fn hooks(&self) -> Arc<UserHooks> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .hooks
            .clone()
    }

    fn root(&self) -> PathBuf {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .root
            .clone()
    }

    fn emit(&self, event: GateEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.send(event);
        }
    }

    fn report_hook(&self, event: HookEvent, messages: &[String], errors: &[String]) {
        for text in messages {
            self.emit(GateEvent::HookMessage {
                event,
                text: text.clone(),
            });
        }
        for error in errors {
            self.emit(GateEvent::HookFailed {
                event,
                error: error.clone(),
            });
        }
    }

    fn deny(&self, tool: &str, reason: String) -> ToolGateOutcome {
        self.emit(GateEvent::Denied {
            tool: tool.to_string(),
            reason: reason.clone(),
        });
        ToolGateOutcome::with(ToolGateDecision::Deny { reason })
    }

    fn take_pending(&self, key: &str) -> Option<Pending> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key)
    }

    fn store_pending(&self, key: String, pending: Pending) {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_PENDING {
            map.clear();
        }
        map.insert(key, pending);
    }
}

/// Map a hook's `updatedInput` back onto our input: Claude hooks edit
/// `file_path`, our tools read `path`.
fn our_input(original: &Value, mut updated: Value) -> Value {
    if let (Value::Object(orig), Value::Object(new)) = (original, &mut updated)
        && orig.contains_key("path")
        && !orig.contains_key("file_path")
        && let Some(fp) = new.remove("file_path")
        && (new.get("path").is_none() || new.get("path") == orig.get("path"))
    {
        new.insert("path".into(), fp);
    }
    updated
}

fn hook_response(result: &ToolGateResult<'_>) -> Value {
    json!({
        "content": result.content,
        "is_error": result.is_error,
        "error_type": result.error_type,
    })
}

#[async_trait]
impl ToolGate for CodeToolGate {
    async fn before(&self, call: &ToolGateCall<'_>) -> ToolGateOutcome {
        if UNGATED_TOOLS.contains(&call.tool) {
            return ToolGateOutcome::allow();
        }
        let (rule, hooks) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (
                state.rules.evaluate_call(call.tool, call.input),
                state.hooks.clone(),
            )
        };
        let mut ask: Option<String> = None;
        if let Some(m) = &rule {
            match m.effect {
                Effect::Deny => {
                    return self.deny(
                        call.tool,
                        format!("denied by permission rule `{}`", m.rule_source),
                    );
                }
                Effect::Ask => {
                    let reason = m.reason.clone().unwrap_or_else(|| {
                        if m.rule_source == OUTSIDE_PROJECT {
                            OUTSIDE_PROJECT.to_string()
                        } else {
                            format!("permission rule `{}`", m.rule_source)
                        }
                    });
                    if !call.approved {
                        self.emit(GateEvent::AskedByRule {
                            tool: call.tool.to_string(),
                            rule: m.rule_source.clone(),
                        });
                    }
                    ask = Some(reason);
                }
                Effect::Allow => {}
            }
        }
        let key = pending_key(call.tool, call.input);
        if call.approved {
            // The person approved; hooks already ran on the first pass.
            let updated_input = self
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&key)
                .and_then(|p| p.updated_input.clone());
            return ToolGateOutcome {
                decision: ToolGateDecision::Allow,
                updated_input,
            };
        }
        if !hooks.has(HookEvent::PreToolUse) {
            return match ask {
                Some(reason) => ToolGateOutcome::with(ToolGateDecision::Ask {
                    reason: Some(reason),
                }),
                None => ToolGateOutcome::allow(),
            };
        }
        let outcome = hooks
            .run(
                HookEvent::PreToolUse,
                HookPayload::tool(call.tool, call.input.clone()),
            )
            .await;
        self.report_hook(
            HookEvent::PreToolUse,
            &outcome.system_messages,
            &outcome.errors,
        );
        if let Some(stop) = &outcome.stop_reason {
            self.emit(GateEvent::HookMessage {
                event: HookEvent::PreToolUse,
                text: stop.clone(),
            });
            return self.deny(call.tool, format!("stopped by a pre_tool_use hook: {stop}"));
        }
        let updated_input = outcome
            .updated_input
            .clone()
            .map(|u| our_input(call.input, u));
        if outcome.decision == Some(HookDecision::Deny) {
            let reason = outcome
                .reason
                .clone()
                .unwrap_or_else(|| "blocked by a pre_tool_use hook".into());
            return self.deny(call.tool, reason);
        }
        if updated_input.is_some() || outcome.additional_context.is_some() {
            self.store_pending(
                key,
                Pending {
                    updated_input: updated_input.clone(),
                    context: outcome.additional_context.clone(),
                },
            );
        }
        let decision = match outcome.decision {
            Some(HookDecision::Ask) => ToolGateDecision::Ask {
                reason: ask
                    .or(outcome.reason.clone())
                    .or(Some("pre_tool_use hook".into())),
            },
            Some(HookDecision::Allow) if ask.is_none() => ToolGateDecision::Approve {
                rule: Some(
                    outcome
                        .reason
                        .clone()
                        .unwrap_or_else(|| "pre_tool_use hook".into()),
                ),
            },
            _ => match ask {
                Some(reason) => ToolGateDecision::Ask {
                    reason: Some(reason),
                },
                None => ToolGateDecision::Allow,
            },
        };
        ToolGateOutcome {
            decision,
            updated_input,
        }
    }

    async fn after(&self, call: &ToolGateCall<'_>, result: &ToolGateResult<'_>) -> Option<String> {
        if UNGATED_TOOLS.contains(&call.tool) || result.error_type == Some("approval_required") {
            return None;
        }
        let key = pending_key(call.tool, call.input);
        let mut parts: Vec<String> = Vec::new();
        if let Some(ctx) = self.take_pending(&key).and_then(|p| p.context) {
            parts.push(ctx);
        }
        let hooks = self.hooks();
        if hooks.has(HookEvent::PostToolUse) {
            let mut payload = HookPayload::tool(call.tool, call.input.clone());
            payload.tool_response = Some(hook_response(result));
            let outcome = hooks.run(HookEvent::PostToolUse, payload).await;
            self.report_hook(
                HookEvent::PostToolUse,
                &outcome.system_messages,
                &outcome.errors,
            );
            if outcome.blocked
                && let Some(reason) = &outcome.reason
            {
                parts.push(format!("post_tool_use hook: {reason}"));
            }
            parts.extend(outcome.additional_context);
        }
        if hooks.has(HookEvent::PostEdit) && !result.is_error {
            let root = self.root();
            let files = edited_paths(call.tool, call.input, &root).unwrap_or_default();
            for file in files.iter().filter(|f| f.exists()) {
                let mut payload = HookPayload::tool(call.tool, call.input.clone());
                payload.tool_response = Some(hook_response(result));
                payload.file = Some(relative_or_absolute(&root, file));
                let outcome = hooks.run(HookEvent::PostEdit, payload).await;
                self.report_hook(
                    HookEvent::PostEdit,
                    &outcome.system_messages,
                    &outcome.errors,
                );
                if outcome.blocked
                    && let Some(reason) = &outcome.reason
                {
                    parts.push(format!("post_edit hook ({}): {reason}", file.display()));
                }
                parts.extend(outcome.additional_context);
            }
        }
        let text = parts.join("\n");
        (!text.trim().is_empty()).then_some(text)
    }
}

/// Project-relative path when inside the root (what `{file}` hooks such as
/// formatters expect), otherwise absolute.
fn relative_or_absolute(root: &Path, file: &Path) -> PathBuf {
    file.strip_prefix(root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| file.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{HookSpec, HooksConfig, PermissionsConfig};

    fn call<'a>(tool: &'a str, input: &'a Value, approved: bool) -> ToolGateCall<'a> {
        ToolGateCall {
            tool,
            input,
            caller_channel: "code",
            principal: "main",
            chat_id: 1,
            approved,
        }
    }

    fn gate(
        root: &Path,
        allow: &[&str],
        ask: &[&str],
        deny: &[&str],
        hooks: HooksConfig,
    ) -> CodeToolGate {
        let config = PermissionsConfig {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ask: ask.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        CodeToolGate::new(
            PermissionRules::from_config(&config, root),
            Arc::new(UserHooks::new(hooks, root, "s")),
            root,
        )
    }

    #[tokio::test]
    async fn rules_decide() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let g = gate(
            dir.path(),
            &["bash(cargo test)"],
            &["bash(git push *)"],
            &["read(**/.env)", "tool(*)"],
            HooksConfig::default(),
        )
        .with_events(tx);
        let input = json!({"path": ".env"});
        let out = g.before(&call("read_file", &input, false)).await;
        match out.decision {
            ToolGateDecision::Deny { reason } => assert!(reason.contains("read(**/.env)")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(rx.try_recv(), Ok(GateEvent::Denied { .. })));
        // Ungated internal tools pass even `tool(*)` deny.
        let todo = json!({});
        assert_eq!(
            g.before(&call("todo_write", &todo, false)).await.decision,
            ToolGateDecision::Allow
        );

        let g = gate(
            dir.path(),
            &["bash(cargo test)"],
            &["bash(git push *)"],
            &[],
            HooksConfig::default(),
        );
        let push = json!({"command": "git push origin"});
        assert!(matches!(
            g.before(&call("bash", &push, false)).await.decision,
            ToolGateDecision::Ask { .. }
        ));
        assert_eq!(
            g.before(&call("bash", &push, true)).await.decision,
            ToolGateDecision::Allow
        );
        let test = json!({"command": "cargo test"});
        assert_eq!(
            g.before(&call("bash", &test, false)).await.decision,
            ToolGateDecision::Allow
        );
        assert_eq!(
            g.allows_command("cargo test -q").as_deref(),
            Some("bash(cargo test)")
        );
        let outside = json!({"path": "/somewhere/else.txt"});
        match g
            .before(&call("write_file", &outside, false))
            .await
            .decision
        {
            ToolGateDecision::Ask { reason } => {
                assert!(reason.unwrap().contains(OUTSIDE_PROJECT))
            }
            other => panic!("{other:?}"),
        }
        // Reload.
        g.update(
            PermissionRules::from_config(
                &PermissionsConfig {
                    deny: vec!["bash(cargo *)".into()],
                    ..Default::default()
                },
                dir.path(),
            ),
            Arc::new(UserHooks::empty(dir.path())),
        );
        assert!(matches!(
            g.before(&call("bash", &test, false)).await.decision,
            ToolGateDecision::Deny { .. }
        ));
        assert!(matches!(
            g.before(&call("bash", &test, true)).await.decision,
            ToolGateDecision::Deny { .. }
        ));
    }

    #[test]
    fn maps_file_path_back() {
        let orig = json!({"path": "a.rs", "content": "x"});
        let updated = json!({"path": "a.rs", "file_path": "b.rs", "content": "y"});
        assert_eq!(
            our_input(&orig, updated),
            json!({"path": "b.rs", "content": "y"})
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hooks_decide_and_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let spec = |matcher: &str, command: &str| HookSpec {
            matcher: Some(matcher.into()),
            command: Some(command.into()),
            ..Default::default()
        };
        let hooks = HooksConfig {
            pre_tool_use: vec![spec(
                "Bash",
                r#"if grep -q 'curl'; then echo nope >&2; exit 2; fi; echo '{"hookSpecificOutput":{"updatedInput":{"command":"ls -la"},"additionalContext":"pre-ctx"}}'"#,
            )],
            post_tool_use: vec![spec(
                "Bash",
                r#"echo '{"decision":"block","reason":"look again"}'"#,
            )],
            post_edit: vec![spec("Write", "echo formatted {file} >> log.txt")],
            ..Default::default()
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let g = gate(dir.path(), &[], &["bash(ls *)"], &[], hooks).with_events(tx);

        let curl = json!({"command": "curl x"});
        match g.before(&call("bash", &curl, false)).await.decision {
            ToolGateDecision::Deny { reason } => assert_eq!(reason, "nope"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(rx.try_recv(), Ok(GateEvent::Denied { .. })));

        let ls = json!({"command": "ls"});
        let first = g.before(&call("bash", &ls, false)).await;
        assert!(matches!(first.decision, ToolGateDecision::Ask { .. }));
        assert_eq!(first.updated_input, Some(json!({"command": "ls -la"})));
        // Approval retry: hooks skipped, rewrite kept.
        let retry = g.before(&call("bash", &ls, true)).await;
        assert_eq!(retry.decision, ToolGateDecision::Allow);
        assert_eq!(retry.updated_input, Some(json!({"command": "ls -la"})));
        let res = ToolGateResult {
            content: "out",
            is_error: false,
            error_type: None,
        };
        let extra = g.after(&call("bash", &ls, true), &res).await.unwrap();
        assert_eq!(extra, "pre-ctx\npost_tool_use hook: look again");

        std::fs::write(dir.path().join("a.rs"), "x").unwrap();
        let write = json!({"path": "a.rs", "content": "x"});
        g.after(&call("write_file", &write, true), &res).await;
        let log = std::fs::read_to_string(dir.path().join("log.txt")).unwrap();
        assert_eq!(log.trim(), "formatted a.rs");
        // No post_edit after a failed edit.
        let failed = ToolGateResult {
            content: "err",
            is_error: true,
            error_type: None,
        };
        g.after(&call("write_file", &write, true), &failed).await;
        let log = std::fs::read_to_string(dir.path().join("log.txt")).unwrap();
        assert_eq!(log.lines().count(), 1);
    }
}
