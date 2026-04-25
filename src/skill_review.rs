//! Helpers for the autonomous skill-review pipeline.
//!
//! Skill review takes the conversation trace from a completed turn and
//! decides whether the agent's approach is worth saving as a reusable
//! skill. The first step is converting the raw `Vec<Message>` into a
//! structured tool-trajectory the review LLM can reason about — without
//! drowning in tool I/O bytes.
//!
//! The shape is deliberately small (one builder, one truncation knob) so
//! that future steps in the pipeline (success heuristics, evolution
//! decisions) can compose on top without entangling.
//!
//! Module entry points:
//! - [`build_tool_trajectory`] — render a `Vec<Message>` to a step list
//! - [`assess_success`] — cheap heuristic that flags failed/aborted turns
//!   so the review LLM doesn't waste budget packaging them as skills

use microclaw_core::llm_types::{ContentBlock, Message, MessageContent};

/// Cap per-tool-input JSON in the rendered trajectory. Generous enough to
/// preserve typical commands/queries, tight enough that one giant `bash`
/// payload doesn't blow up the review prompt.
pub const DEFAULT_TOOL_INPUT_PREVIEW_CHARS: usize = 300;

/// Cap per-tool-result body in the rendered trajectory. Tool results are
/// often the bulk of token cost; the head usually carries the headline,
/// so head-only truncation is fine for review purposes.
pub const DEFAULT_TOOL_RESULT_PREVIEW_CHARS: usize = 240;

/// Cap per assistant/user text block. Long-form messages (essays,
/// pasted-in code) get summarized; concise reasoning narrations pass
/// through unchanged.
pub const DEFAULT_TEXT_PREVIEW_CHARS: usize = 600;

/// One step in the rendered trajectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrajectoryStep {
    User {
        text: String,
    },
    AssistantText {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input_preview: String,
    },
    ToolResult {
        tool_use_id: String,
        preview: String,
        is_error: bool,
    },
}

/// Render the conversation as an ordered, structured tool trajectory
/// suitable for feeding to a review LLM. Image blocks are dropped (no
/// text signal) and oversized payloads are head-truncated using the
/// `DEFAULT_*_PREVIEW_CHARS` caps. The output is human-readable Markdown
/// — the leading numbers make it easy for the LLM to reference specific
/// steps in its rationale.
pub fn build_tool_trajectory(messages: &[Message]) -> String {
    let steps = collect_steps(messages);
    render_steps(&steps)
}

fn collect_steps(messages: &[Message]) -> Vec<TrajectoryStep> {
    let mut steps = Vec::new();
    for msg in messages {
        let role = msg.role.as_str();
        match &msg.content {
            MessageContent::Text(text) => {
                push_text_step(&mut steps, role, text);
            }
            MessageContent::Blocks(blocks) => {
                for block in blocks {
                    push_block_step(&mut steps, role, block);
                }
            }
        }
    }
    steps
}

fn push_text_step(steps: &mut Vec<TrajectoryStep>, role: &str, text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    let preview = head_preview(trimmed, DEFAULT_TEXT_PREVIEW_CHARS);
    if role == "user" {
        steps.push(TrajectoryStep::User { text: preview });
    } else {
        steps.push(TrajectoryStep::AssistantText { text: preview });
    }
}

fn push_block_step(steps: &mut Vec<TrajectoryStep>, role: &str, block: &ContentBlock) {
    match block {
        ContentBlock::Text { text } => push_text_step(steps, role, text),
        ContentBlock::ToolUse { id, name, input, .. } => {
            let input_preview = head_preview(
                &serde_json::to_string(input).unwrap_or_else(|_| "{}".into()),
                DEFAULT_TOOL_INPUT_PREVIEW_CHARS,
            );
            steps.push(TrajectoryStep::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input_preview,
            });
        }
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            let preview = head_preview(content, DEFAULT_TOOL_RESULT_PREVIEW_CHARS);
            steps.push(TrajectoryStep::ToolResult {
                tool_use_id: tool_use_id.clone(),
                preview,
                is_error: is_error.unwrap_or(false),
            });
        }
        ContentBlock::Image { .. } => {
            // No text signal; reviewer doesn't need pixel data.
        }
    }
}

fn render_steps(steps: &[TrajectoryStep]) -> String {
    if steps.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (idx, step) in steps.iter().enumerate() {
        let n = idx + 1;
        match step {
            TrajectoryStep::User { text } => {
                out.push_str(&format!("{n}. [user] {text}\n"));
            }
            TrajectoryStep::AssistantText { text } => {
                out.push_str(&format!("{n}. [assistant] {text}\n"));
            }
            TrajectoryStep::ToolUse {
                id,
                name,
                input_preview,
            } => {
                out.push_str(&format!(
                    "{n}. [tool_use id={id} name={name}] input={input_preview}\n"
                ));
            }
            TrajectoryStep::ToolResult {
                tool_use_id,
                preview,
                is_error,
            } => {
                let tag = if *is_error { "tool_result_error" } else { "tool_result" };
                out.push_str(&format!(
                    "{n}. [{tag} for={tool_use_id}] {preview}\n"
                ));
            }
        }
    }
    out
}

/// Cheap, no-LLM verdict on whether a completed turn is "successful
/// enough" to mine for a reusable skill. We bias toward false positives
/// (review more) over false negatives (miss a good skill) — only the
/// clear failure shapes are flagged as `Unlikely`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessSignal {
    /// Strong indicators of completion: low tool-error rate, no failure
    /// phrasing in the final assistant text, no circuit-breaker fires.
    Likely,
    /// Ambiguous: some errors recovered from, or short final text. Worth
    /// reviewing but caller may want to weight differently.
    Mixed,
    /// Clear failure signature: high tool-error rate, explicit apology,
    /// circuit-breaker triggered, or empty final assistant turn after
    /// tool work. Skip to save the review LLM call.
    Unlikely,
}

const FAILURE_PHRASES: &[&str] = &[
    "i'm sorry",
    "i am sorry",
    "i apologize",
    "unfortunately",
    "i couldn't",
    "i could not",
    "i was unable",
    "unable to",
    "i don't have access",
    "i don't have the ability",
    "no luck",
    "gave up",
    "抱歉",
    "无法",
    "不能完成",
    "失败",
    "做不到",
];

const CIRCUIT_BREAKER_MARKER: &str = "Circuit breaker:";

/// Inspect the trailing assistant text + the tool-result mix to decide
/// whether the task looks completed. Designed to be safe to call even on
/// short or pathological message lists.
pub fn assess_success(messages: &[Message]) -> SuccessSignal {
    let (tool_results, errors) = count_tool_results(messages);
    let final_text = last_assistant_text(messages);

    // Hard fail: the duplicate-call circuit breaker fired during the turn
    // — by definition the agent was looping, not progressing.
    if circuit_breaker_fired(messages) {
        return SuccessSignal::Unlikely;
    }

    // Hard fail: agent emitted tool calls but produced no closing text.
    if tool_results > 0 && final_text.trim().is_empty() {
        return SuccessSignal::Unlikely;
    }

    // Hard fail: more than half of tool results errored.
    if tool_results >= 4 && errors * 2 > tool_results {
        return SuccessSignal::Unlikely;
    }

    let lower = final_text.to_ascii_lowercase();
    let apology = FAILURE_PHRASES.iter().any(|p| lower.contains(p));
    if apology {
        return SuccessSignal::Unlikely;
    }

    // Soft fail: noticeable error rate or terse closing text.
    if (tool_results >= 4 && errors * 4 > tool_results) || final_text.trim().len() < 20 {
        return SuccessSignal::Mixed;
    }

    SuccessSignal::Likely
}

/// Last `assistant`-role plain-text content in the message list.
/// Concatenates Text blocks within the final assistant message; ignores
/// tool_use/tool_result blocks. Returns "" if the conversation does not
/// end on an assistant turn.
fn last_assistant_text(messages: &[Message]) -> String {
    let last_assistant = messages.iter().rev().find(|m| m.role == "assistant");
    let Some(msg) = last_assistant else {
        return String::new();
    };
    match &msg.content {
        MessageContent::Text(t) => t.clone(),
        MessageContent::Blocks(blocks) => {
            let mut buf = String::new();
            for block in blocks {
                if let ContentBlock::Text { text } = block {
                    if !buf.is_empty() {
                        buf.push('\n');
                    }
                    buf.push_str(text);
                }
            }
            buf
        }
    }
}

/// `(total_tool_results, errored_tool_results)` across the conversation.
fn count_tool_results(messages: &[Message]) -> (usize, usize) {
    let mut total = 0usize;
    let mut errors = 0usize;
    for msg in messages {
        if let MessageContent::Blocks(blocks) = &msg.content {
            for block in blocks {
                if let ContentBlock::ToolResult { is_error, .. } = block {
                    total += 1;
                    if is_error.unwrap_or(false) {
                        errors += 1;
                    }
                }
            }
        }
    }
    (total, errors)
}

/// True iff any tool_result body starts with the duplicate-call circuit
/// breaker marker. Marker text lives in `agent_engine.rs` — keep them in
/// sync if either changes.
fn circuit_breaker_fired(messages: &[Message]) -> bool {
    for msg in messages {
        if let MessageContent::Blocks(blocks) = &msg.content {
            for block in blocks {
                if let ContentBlock::ToolResult { content, .. } = block {
                    if content.contains(CIRCUIT_BREAKER_MARKER) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn head_preview(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    let total = trimmed.chars().count();
    if total <= max_chars {
        return trimmed.replace('\n', " ");
    }
    let head: String = trimmed.chars().take(max_chars).collect();
    format!("{}… (+{} chars)", head.replace('\n', " "), total - max_chars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user_text(text: &str) -> Message {
        Message {
            role: "user".into(),
            content: MessageContent::Text(text.into()),
        }
    }

    fn assistant_blocks(blocks: Vec<ContentBlock>) -> Message {
        Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(blocks),
        }
    }

    fn user_blocks(blocks: Vec<ContentBlock>) -> Message {
        Message {
            role: "user".into(),
            content: MessageContent::Blocks(blocks),
        }
    }

    #[test]
    fn empty_messages_yield_empty_trajectory() {
        assert_eq!(build_tool_trajectory(&[]), "");
    }

    #[test]
    fn renders_user_assistant_text_messages() {
        let msgs = vec![
            user_text("hello"),
            assistant_blocks(vec![ContentBlock::Text {
                text: "hi there".into(),
            }]),
        ];
        let out = build_tool_trajectory(&msgs);
        assert!(out.contains("1. [user] hello"), "got: {out}");
        assert!(out.contains("2. [assistant] hi there"), "got: {out}");
    }

    #[test]
    fn pairs_tool_use_and_tool_result_in_order() {
        let msgs = vec![
            user_text("find logs"),
            assistant_blocks(vec![
                ContentBlock::Text {
                    text: "I'll grep".into(),
                },
                ContentBlock::ToolUse {
                    id: "tu_1".into(),
                    name: "grep".into(),
                    input: json!({"pattern": "ERROR"}),
                    thought_signature: None,
                },
            ]),
            user_blocks(vec![ContentBlock::ToolResult {
                tool_use_id: "tu_1".into(),
                content: "src/foo.rs:1: ERROR boom".into(),
                is_error: None,
            }]),
            assistant_blocks(vec![ContentBlock::Text {
                text: "Found 1 match.".into(),
            }]),
        ];
        let out = build_tool_trajectory(&msgs);
        // Step ordering: user → assistant text → tool_use → tool_result → assistant text
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "got: {out}");
        assert!(lines[0].starts_with("1. [user] find logs"));
        assert!(lines[1].starts_with("2. [assistant] I'll grep"));
        assert!(
            lines[2].starts_with("3. [tool_use id=tu_1 name=grep]"),
            "got: {}",
            lines[2]
        );
        assert!(
            lines[3].starts_with("4. [tool_result for=tu_1]"),
            "got: {}",
            lines[3]
        );
        assert!(lines[4].starts_with("5. [assistant] Found 1 match."));
    }

    #[test]
    fn marks_tool_errors_distinctly() {
        let msgs = vec![user_blocks(vec![ContentBlock::ToolResult {
            tool_use_id: "tu_x".into(),
            content: "permission denied".into(),
            is_error: Some(true),
        }])];
        let out = build_tool_trajectory(&msgs);
        assert!(out.contains("tool_result_error"), "got: {out}");
    }

    #[test]
    fn truncates_oversized_tool_input_and_result() {
        let big_input = json!({"command": "x".repeat(2000)});
        let big_output = "y".repeat(2000);
        let msgs = vec![
            assistant_blocks(vec![ContentBlock::ToolUse {
                id: "tu_big".into(),
                name: "bash".into(),
                input: big_input,
                thought_signature: None,
            }]),
            user_blocks(vec![ContentBlock::ToolResult {
                tool_use_id: "tu_big".into(),
                content: big_output,
                is_error: None,
            }]),
        ];
        let out = build_tool_trajectory(&msgs);
        // Both lines must contain the "+N chars" suffix from head_preview.
        let use_line = out.lines().find(|l| l.contains("tool_use")).unwrap();
        let result_line = out.lines().find(|l| l.contains("tool_result")).unwrap();
        assert!(
            use_line.contains("+") && use_line.contains("chars)"),
            "input not truncated: {use_line}"
        );
        assert!(
            result_line.contains("+") && result_line.contains("chars)"),
            "result not truncated: {result_line}"
        );
    }

    #[test]
    fn drops_image_blocks() {
        let msgs = vec![user_blocks(vec![
            ContentBlock::Text {
                text: "see image".into(),
            },
            ContentBlock::Image {
                source: microclaw_core::llm_types::ImageSource {
                    source_type: "base64".into(),
                    media_type: "image/png".into(),
                    data: "ignored".into(),
                },
            },
        ])];
        let out = build_tool_trajectory(&msgs);
        assert!(out.contains("see image"));
        assert!(!out.contains("ignored"));
        assert_eq!(out.lines().count(), 1);
    }

    fn ok_tool_result(id: &str, body: &str) -> ContentBlock {
        ContentBlock::ToolResult {
            tool_use_id: id.into(),
            content: body.into(),
            is_error: None,
        }
    }

    fn err_tool_result(id: &str, body: &str) -> ContentBlock {
        ContentBlock::ToolResult {
            tool_use_id: id.into(),
            content: body.into(),
            is_error: Some(true),
        }
    }

    #[test]
    fn assess_success_likely_for_clean_completed_turn() {
        let msgs = vec![
            user_text("write a hello world"),
            assistant_blocks(vec![ContentBlock::ToolUse {
                id: "tu_1".into(),
                name: "write_file".into(),
                input: json!({"path": "hello.py"}),
                thought_signature: None,
            }]),
            user_blocks(vec![ok_tool_result("tu_1", "wrote 13 bytes")]),
            assistant_blocks(vec![ContentBlock::Text {
                text: "Done — wrote a Python hello-world to hello.py.".into(),
            }]),
        ];
        assert_eq!(assess_success(&msgs), SuccessSignal::Likely);
    }

    #[test]
    fn assess_success_unlikely_when_apology_in_final_text() {
        let msgs = vec![
            user_text("ship this"),
            assistant_blocks(vec![ContentBlock::Text {
                text: "I'm sorry, I couldn't complete the deploy.".into(),
            }]),
        ];
        assert_eq!(assess_success(&msgs), SuccessSignal::Unlikely);
    }

    #[test]
    fn assess_success_unlikely_when_majority_tool_errors() {
        let mut blocks_assist = Vec::new();
        let mut blocks_user = Vec::new();
        for i in 0..5 {
            blocks_assist.push(ContentBlock::ToolUse {
                id: format!("tu_{i}"),
                name: "bash".into(),
                input: json!({"cmd": "x"}),
                thought_signature: None,
            });
            // 3 of 5 errored.
            if i < 3 {
                blocks_user.push(err_tool_result(&format!("tu_{i}"), "failed"));
            } else {
                blocks_user.push(ok_tool_result(&format!("tu_{i}"), "ok"));
            }
        }
        let msgs = vec![
            user_text("debug this"),
            assistant_blocks(blocks_assist),
            user_blocks(blocks_user),
            assistant_blocks(vec![ContentBlock::Text {
                text: "Fixed it by switching shells.".into(),
            }]),
        ];
        assert_eq!(assess_success(&msgs), SuccessSignal::Unlikely);
    }

    #[test]
    fn assess_success_unlikely_when_circuit_breaker_fired() {
        let msgs = vec![
            user_text("find foo"),
            assistant_blocks(vec![ContentBlock::ToolUse {
                id: "tu_1".into(),
                name: "grep".into(),
                input: json!({"q": "foo"}),
                thought_signature: None,
            }]),
            user_blocks(vec![err_tool_result(
                "tu_1",
                "Circuit breaker: this exact `grep` call (same arguments) ...",
            )]),
            assistant_blocks(vec![ContentBlock::Text {
                text: "Let me try a different approach.".into(),
            }]),
        ];
        assert_eq!(assess_success(&msgs), SuccessSignal::Unlikely);
    }

    #[test]
    fn assess_success_unlikely_when_tools_ran_but_no_closing_text() {
        let msgs = vec![
            user_text("do stuff"),
            assistant_blocks(vec![ContentBlock::ToolUse {
                id: "tu_1".into(),
                name: "bash".into(),
                input: json!({"cmd": "ls"}),
                thought_signature: None,
            }]),
            user_blocks(vec![ok_tool_result("tu_1", "files...")]),
            assistant_blocks(vec![ContentBlock::Text { text: "".into() }]),
        ];
        assert_eq!(assess_success(&msgs), SuccessSignal::Unlikely);
    }

    #[test]
    fn assess_success_mixed_for_terse_closing_text() {
        let msgs = vec![
            user_text("compute pi"),
            assistant_blocks(vec![ContentBlock::ToolUse {
                id: "tu_1".into(),
                name: "calculate".into(),
                input: json!({"expr": "pi"}),
                thought_signature: None,
            }]),
            user_blocks(vec![ok_tool_result("tu_1", "3.14159")]),
            assistant_blocks(vec![ContentBlock::Text {
                text: "3.14159".into(),
            }]),
        ];
        assert_eq!(assess_success(&msgs), SuccessSignal::Mixed);
    }

    #[test]
    fn newlines_are_inlined_in_previews() {
        let msgs = vec![user_text("line1\nline2\nline3")];
        let out = build_tool_trajectory(&msgs);
        // Single trajectory line, no embedded newline that could break the
        // numbered formatting downstream consumers depend on.
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("line1 line2 line3"));
    }
}
