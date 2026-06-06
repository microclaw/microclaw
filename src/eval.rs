//! `microclaw eval` — deterministic trajectory checks for recorded agent sessions.
//!
//! This is the foundation of the v0.3.0 "Self-Improving Runtime" evaluation gate
//! (`docs/roadmap/v0.3.0-self-improving-runtime.md`, Pillar 5). It replays a recorded
//! session — the same `Vec<Message>` shape persisted in the `sessions` table — and
//! asserts that the *trajectory* is healthy, without calling any LLM:
//!
//! - every `tool_use` has a matching `tool_result` (no dangling tool calls);
//! - every `tool_result` references a prior `tool_use` (no orphaned results);
//! - the conversation ends on a real assistant answer, not a raw `tool_result`
//!   (the agent loop explicitly avoids ending on a tool_result — see `agent_engine`);
//! - the tool-call count stays within a budget;
//! - tool errors are surfaced (and optionally fail the run under `--strict-tool-errors`).
//!
//! It exits non-zero when any fixture fails, so it can gate CI. A later slice can layer
//! LLM-rubric scoring on top of this deterministic base.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use microclaw_core::llm_types::{ContentBlock, Message, MessageContent};
use serde::{Deserialize, Serialize};

/// Result of a single named check within a fixture.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Aggregated report for one fixture file.
#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    pub fixture: String,
    pub passed: bool,
    pub message_count: usize,
    pub tool_calls: usize,
    pub tool_errors: usize,
    pub checks: Vec<CheckResult>,
}

/// Parse a fixture: either a bare JSON array of messages, or an object with a
/// `messages` array (the persisted session shape).
fn load_messages(raw: &str) -> Result<Vec<Message>> {
    if let Ok(v) = serde_json::from_str::<Vec<Message>>(raw) {
        return Ok(v);
    }
    #[derive(Deserialize)]
    struct Wrapper {
        messages: Vec<Message>,
    }
    let w: Wrapper = serde_json::from_str(raw)
        .context("fixture must be a JSON array of messages or an object with a 'messages' array")?;
    Ok(w.messages)
}

fn blocks(msg: &Message) -> Option<&[ContentBlock]> {
    match &msg.content {
        MessageContent::Blocks(b) => Some(b),
        MessageContent::Text(_) => None,
    }
}

/// True if a message carries a non-empty natural-language answer (text), either as a
/// plain text body or a non-empty text block.
fn has_answer_text(msg: &Message) -> bool {
    match &msg.content {
        MessageContent::Text(t) => !t.trim().is_empty(),
        MessageContent::Blocks(bs) => bs.iter().any(|b| match b {
            ContentBlock::Text { text } => !text.trim().is_empty(),
            _ => false,
        }),
    }
}

/// True if a message's blocks contain at least one tool_result and no text.
fn is_pure_tool_result(msg: &Message) -> bool {
    match &msg.content {
        MessageContent::Text(_) => false,
        MessageContent::Blocks(bs) => {
            let has_tr = bs
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolResult { .. }));
            let has_text = bs.iter().any(|b| matches!(b, ContentBlock::Text { .. }));
            has_tr && !has_text
        }
    }
}

/// Thresholds for the trajectory checks. Bundled so call sites and the CLI stay
/// stable as more checks are added.
#[derive(Debug, Clone)]
pub struct EvalThresholds {
    /// Maximum allowed tool calls per session.
    pub max_tool_calls: usize,
    /// Treat any tool error as a failure.
    pub strict_tool_errors: bool,
    /// Flag a stuck loop when the same (tool name + arguments) is called at least
    /// this many times in a session.
    pub max_repeats: usize,
    /// Flag a session with at least this many consecutive tool errors.
    pub max_error_streak: usize,
}

impl Default for EvalThresholds {
    fn default() -> Self {
        Self {
            max_tool_calls: 100,
            strict_tool_errors: false,
            max_repeats: 3,
            max_error_streak: 3,
        }
    }
}

/// Evaluate a single parsed session.
pub fn evaluate(fixture: &str, messages: &[Message], t: &EvalThresholds) -> EvalReport {
    // Walk blocks in order, tracking tool_use ids and which got a result.
    let mut tool_use_ids: Vec<String> = Vec::new();
    let mut resulted_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut orphan_results: Vec<String> = Vec::new();
    let mut tool_errors = 0usize;
    // (tool name + serialized args) -> occurrences, for stuck-loop detection.
    let mut call_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    // Longest run of consecutive tool errors, in block order.
    let mut error_streak = 0usize;
    let mut cur_error_streak = 0usize;

    for msg in messages {
        let Some(bs) = blocks(msg) else { continue };
        for b in bs {
            match b {
                ContentBlock::ToolUse { id, name, input, .. } => {
                    tool_use_ids.push(id.clone());
                    let key = format!("{name}\u{1f}{input}");
                    *call_counts.entry(key).or_insert(0) += 1;
                }
                ContentBlock::ToolResult {
                    tool_use_id,
                    is_error,
                    ..
                } => {
                    if tool_use_ids.iter().any(|id| id == tool_use_id) {
                        resulted_ids.insert(tool_use_id.clone());
                    } else {
                        orphan_results.push(tool_use_id.clone());
                    }
                    if is_error.unwrap_or(false) {
                        tool_errors += 1;
                        cur_error_streak += 1;
                        error_streak = error_streak.max(cur_error_streak);
                    } else {
                        cur_error_streak = 0;
                    }
                }
                _ => {}
            }
        }
    }

    let (top_call_key, top_call_count) = call_counts
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(k, c)| (k.clone(), *c))
        .unwrap_or_default();

    let dangling: Vec<&String> = tool_use_ids
        .iter()
        .filter(|id| !resulted_ids.contains(*id))
        .collect();
    let tool_calls = tool_use_ids.len();

    let mut checks = Vec::new();

    // 1. No dangling tool_use.
    checks.push(CheckResult {
        name: "no_dangling_tool_use".into(),
        passed: dangling.is_empty(),
        detail: if dangling.is_empty() {
            "all tool_use blocks have a matching tool_result".into()
        } else {
            format!("{} tool_use without a tool_result: {:?}", dangling.len(), dangling)
        },
    });

    // 2. No orphaned tool_result.
    checks.push(CheckResult {
        name: "no_orphan_tool_result".into(),
        passed: orphan_results.is_empty(),
        detail: if orphan_results.is_empty() {
            "all tool_result blocks reference a prior tool_use".into()
        } else {
            format!(
                "{} tool_result without a prior tool_use: {:?}",
                orphan_results.len(),
                orphan_results
            )
        },
    });

    // 3. Ends on a real assistant answer, not a raw tool_result.
    let ends_cleanly = match messages.last() {
        None => false,
        Some(last) => !is_pure_tool_result(last) && (has_answer_text(last) || last.role == "assistant"),
    };
    checks.push(CheckResult {
        name: "ends_with_answer".into(),
        passed: ends_cleanly,
        detail: match messages.last() {
            None => "empty session".into(),
            Some(last) if is_pure_tool_result(last) => {
                "session ends on a tool_result (no final answer)".into()
            }
            Some(_) if ends_cleanly => "session ends with a final answer".into(),
            Some(last) => format!("session ends on a '{}' message without answer text", last.role),
        },
    });

    // 4. Tool-call budget.
    let within_budget = tool_calls <= t.max_tool_calls;
    checks.push(CheckResult {
        name: "within_tool_budget".into(),
        passed: within_budget,
        detail: format!("{tool_calls} tool calls (budget {})", t.max_tool_calls),
    });

    // 5. Tool errors — informational unless --strict-tool-errors.
    checks.push(CheckResult {
        name: "tool_errors".into(),
        passed: !t.strict_tool_errors || tool_errors == 0,
        detail: format!(
            "{tool_errors} tool error(s){}",
            if t.strict_tool_errors { " (strict)" } else { " (informational)" }
        ),
    });

    // 6. No stuck loop — the same (tool + arguments) repeated too many times.
    let no_loop = top_call_count < t.max_repeats.max(1);
    let top_tool = top_call_key
        .split('\u{1f}')
        .next()
        .unwrap_or("")
        .to_string();
    checks.push(CheckResult {
        name: "no_tool_call_loop".into(),
        passed: no_loop,
        detail: if no_loop {
            format!("max identical tool call repeated {top_call_count}x (limit {})", t.max_repeats)
        } else {
            format!(
                "tool '{top_tool}' called with identical arguments {top_call_count}x (limit {})",
                t.max_repeats
            )
        },
    });

    // 7. No long consecutive tool-error streak.
    let no_error_streak = error_streak < t.max_error_streak.max(1);
    checks.push(CheckResult {
        name: "no_error_streak".into(),
        passed: no_error_streak,
        detail: format!(
            "longest consecutive tool-error streak {error_streak} (limit {})",
            t.max_error_streak
        ),
    });

    let passed = checks.iter().all(|c| c.passed);
    EvalReport {
        fixture: fixture.to_string(),
        passed,
        message_count: messages.len(),
        tool_calls,
        tool_errors,
        checks,
    }
}

fn collect_fixtures(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_dir() {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("reading fixture directory {}", path.display()))?
        {
            let p = entry?.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                out.push(p);
            }
        }
        out.sort();
        Ok(out)
    } else {
        Ok(vec![path.to_path_buf()])
    }
}

/// CLI entry point. Returns the process exit code (0 = all passed, 1 = failure).
pub fn run_eval(path: &str, thresholds: &EvalThresholds, json: bool) -> Result<i32> {
    let fixtures = collect_fixtures(Path::new(path))?;
    if fixtures.is_empty() {
        anyhow::bail!("no .json fixtures found at {path}");
    }

    let mut reports = Vec::new();
    for f in &fixtures {
        let raw = std::fs::read_to_string(f)
            .with_context(|| format!("reading fixture {}", f.display()))?;
        let messages = load_messages(&raw)
            .with_context(|| format!("parsing fixture {}", f.display()))?;
        reports.push(evaluate(&f.display().to_string(), &messages, thresholds));
    }

    let all_passed = reports.iter().all(|r| r.passed);

    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        for r in &reports {
            println!(
                "{} {}  ({} msgs, {} tool calls, {} errors)",
                if r.passed { "PASS" } else { "FAIL" },
                r.fixture,
                r.message_count,
                r.tool_calls,
                r.tool_errors
            );
            for c in &r.checks {
                if !c.passed {
                    println!("    - {}: {}", c.name, c.detail);
                }
            }
        }
        let failed = reports.iter().filter(|r| !r.passed).count();
        println!(
            "\n{}/{} fixtures passed{}",
            reports.len() - failed,
            reports.len(),
            if all_passed { "" } else { " — eval gate FAILED" }
        );
    }

    Ok(if all_passed { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_core::llm_types::ContentBlock;

    fn assistant_text(t: &str) -> Message {
        Message {
            role: "assistant".into(),
            content: MessageContent::Text(t.into()),
        }
    }

    fn assistant_tool_use(id: &str) -> Message {
        Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                id: id.into(),
                name: "read_file".into(),
                input: serde_json::json!({}),
                thought_signature: None,
            }]),
        }
    }

    /// A tool_use with an explicit name + input (for loop detection tests).
    fn assistant_tool_use_named(id: &str, name: &str, input: serde_json::Value) -> Message {
        Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                id: id.into(),
                name: name.into(),
                input,
                thought_signature: None,
            }]),
        }
    }

    fn tool_result(id: &str, is_error: bool) -> Message {
        Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                tool_use_id: id.into(),
                content: "ok".into(),
                is_error: if is_error { Some(true) } else { None },
            }]),
        }
    }

    fn th(max_tool_calls: usize, strict: bool) -> EvalThresholds {
        EvalThresholds {
            max_tool_calls,
            strict_tool_errors: strict,
            ..EvalThresholds::default()
        }
    }

    #[test]
    fn clean_trajectory_passes() {
        let msgs = vec![
            Message { role: "user".into(), content: MessageContent::Text("hi".into()) },
            assistant_tool_use("t1"),
            tool_result("t1", false),
            assistant_text("here is the answer"),
        ];
        let r = evaluate("clean", &msgs, &th(100, false));
        assert!(r.passed, "checks: {:?}", r.checks);
        assert_eq!(r.tool_calls, 1);
    }

    #[test]
    fn dangling_tool_use_fails() {
        let msgs = vec![
            Message { role: "user".into(), content: MessageContent::Text("hi".into()) },
            assistant_tool_use("t1"), // no result
        ];
        let r = evaluate("dangling", &msgs, &th(100, false));
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.name == "no_dangling_tool_use" && !c.passed));
    }

    #[test]
    fn ending_on_tool_result_fails() {
        let msgs = vec![
            assistant_tool_use("t1"),
            tool_result("t1", false), // session ends on a tool_result
        ];
        let r = evaluate("ends_tr", &msgs, &th(100, false));
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.name == "ends_with_answer" && !c.passed));
    }

    #[test]
    fn over_budget_fails() {
        // Distinct inputs so we exercise the budget check, not the loop check.
        let msgs = vec![
            assistant_tool_use_named("t1", "read_file", serde_json::json!({"p": "a"})),
            tool_result("t1", false),
            assistant_tool_use_named("t2", "read_file", serde_json::json!({"p": "b"})),
            tool_result("t2", false),
            assistant_text("done"),
        ];
        let r = evaluate("budget", &msgs, &th(1, false));
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.name == "within_tool_budget" && !c.passed));
    }

    #[test]
    fn orphan_tool_result_fails() {
        let msgs = vec![tool_result("ghost", false), assistant_text("done")];
        let r = evaluate("orphan", &msgs, &th(100, false));
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.name == "no_orphan_tool_result" && !c.passed));
    }

    #[test]
    fn tool_errors_informational_unless_strict() {
        let msgs = vec![
            assistant_tool_use("t1"),
            tool_result("t1", true),
            assistant_text("recovered"),
        ];
        let lenient = evaluate("err", &msgs, &th(100, false));
        assert!(lenient.passed, "errors should be informational: {:?}", lenient.checks);
        assert_eq!(lenient.tool_errors, 1);
        let strict = evaluate("err", &msgs, &th(100, true));
        assert!(!strict.passed);
    }

    #[test]
    fn stuck_loop_fails() {
        // Same tool + identical arguments three times trips the loop check.
        let msgs = vec![
            assistant_tool_use_named("t1", "bash", serde_json::json!({"cmd": "ls"})),
            tool_result("t1", false),
            assistant_tool_use_named("t2", "bash", serde_json::json!({"cmd": "ls"})),
            tool_result("t2", false),
            assistant_tool_use_named("t3", "bash", serde_json::json!({"cmd": "ls"})),
            tool_result("t3", false),
            assistant_text("stuck"),
        ];
        let r = evaluate("loop", &msgs, &th(100, false));
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.name == "no_tool_call_loop" && !c.passed));
    }

    #[test]
    fn distinct_args_do_not_trip_loop() {
        let msgs = vec![
            assistant_tool_use_named("t1", "bash", serde_json::json!({"cmd": "ls a"})),
            tool_result("t1", false),
            assistant_tool_use_named("t2", "bash", serde_json::json!({"cmd": "ls b"})),
            tool_result("t2", false),
            assistant_tool_use_named("t3", "bash", serde_json::json!({"cmd": "ls c"})),
            tool_result("t3", false),
            assistant_text("done"),
        ];
        let r = evaluate("noloop", &msgs, &th(100, false));
        assert!(r.passed, "checks: {:?}", r.checks);
    }

    #[test]
    fn error_streak_fails() {
        let msgs = vec![
            assistant_tool_use_named("t1", "bash", serde_json::json!({"c": 1})),
            tool_result("t1", true),
            assistant_tool_use_named("t2", "bash", serde_json::json!({"c": 2})),
            tool_result("t2", true),
            assistant_tool_use_named("t3", "bash", serde_json::json!({"c": 3})),
            tool_result("t3", true),
            assistant_text("gave up"),
        ];
        let r = evaluate("streak", &msgs, &th(100, false));
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.name == "no_error_streak" && !c.passed));
    }

    #[test]
    fn loads_wrapped_messages() {
        let raw = r#"{"messages":[{"role":"assistant","content":"hello"}]}"#;
        let msgs = load_messages(raw).unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn loads_bare_array() {
        let raw = r#"[{"role":"assistant","content":"hello"}]"#;
        let msgs = load_messages(raw).unwrap();
        assert_eq!(msgs.len(), 1);
    }

    /// Guards against example-rot. The negative example fixtures in
    /// docs/test/eval-fixtures/negative/ exist to demonstrate failing
    /// trajectories, but the CI gate scans the parent dir non-recursively and
    /// never runs them — so without this test, an edit that made them pass
    /// would go unnoticed. Keep them failing their advertised checks.
    #[test]
    fn negative_fixture_files_still_fail() {
        let cases = [
            ("dangling-tool-use.json", "no_dangling_tool_use"),
            ("stuck-loop.json", "no_tool_call_loop"),
        ];
        for (file, expected_check) in cases {
            let path = format!(
                "{}/docs/test/eval-fixtures/negative/{}",
                env!("CARGO_MANIFEST_DIR"),
                file
            );
            let raw =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
            let messages =
                load_messages(&raw).unwrap_or_else(|e| panic!("parsing {path}: {e}"));
            let r = evaluate(file, &messages, &EvalThresholds::default());
            assert!(
                !r.passed,
                "{file} unexpectedly passed; it must demonstrate a failing trajectory"
            );
            assert!(
                r.checks.iter().any(|c| c.name == expected_check && !c.passed),
                "{file} did not fail its expected check {expected_check}; checks: {:?}",
                r.checks
            );
        }
    }
}
