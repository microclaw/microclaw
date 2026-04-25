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

use std::sync::Arc;

use microclaw_core::llm_types::{ContentBlock, Message, MessageContent, ResponseContentBlock};
use microclaw_storage::db::call_blocking;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::runtime::AppState;

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

/// Cap on how many `agent-created` skills can coexist before the
/// pipeline self-throttles. Prevents runaway accumulation; the activation
/// tracker (added in a later commit) can later evict low-value entries.
const MAX_AGENT_CREATED_SKILLS: usize = 20;

const SKILL_REVIEW_SYSTEM_PROMPT: &str = r#"You are a skill review specialist. Analyze conversations to identify reusable approaches that should be saved as skills.

A "skill" is a set of step-by-step instructions for a task type the agent encountered. Only recommend creating a skill if:
1. The conversation shows a non-trivial multi-step approach (5+ distinct steps)
2. The approach required trial-and-error or domain-specific knowledge
3. The approach is REUSABLE — it would help with similar future tasks
4. No existing skill already covers this approach

If you find a worthy skill, output EXACTLY one JSON object:
{"create": true, "name": "skill-name", "description": "One-line description", "instructions": "Full markdown instructions"}

If nothing is worth saving as a skill, output:
{"create": false}

Output ONLY the JSON object, no other text."#;

/// Asynchronous queue for end-of-turn skill review requests. The agent
/// loop enqueues a `chat_id` after a successful turn; a dedicated worker
/// task drains the queue and invokes [`run_skill_review`] without
/// blocking the request path.
///
/// The wrapper struct exists so [`crate::runtime::AppState`] can hand
/// out cheap clones (`enqueue` only needs the sender). The worker
/// retains the receiver via [`SkillReviewWorker::start`].
#[derive(Clone)]
pub struct SkillReviewQueue {
    tx: mpsc::UnboundedSender<i64>,
}

impl SkillReviewQueue {
    /// Send a chat_id to the review worker. Silently drops the request if
    /// the worker has been shut down — review is best-effort and never
    /// blocks the caller.
    pub fn enqueue(&self, chat_id: i64) {
        let _ = self.tx.send(chat_id);
    }
}

/// Owning side of the skill-review queue. Created together with the
/// `SkillReviewQueue` handle and consumed by [`spawn_skill_review_worker`].
pub struct SkillReviewWorker {
    rx: mpsc::UnboundedReceiver<i64>,
}

/// Build the `(handle, worker)` pair that goes into [`AppState`] and the
/// scheduler boot, respectively.
pub fn build_skill_review_channel() -> (SkillReviewQueue, SkillReviewWorker) {
    let (tx, rx) = mpsc::unbounded_channel();
    (SkillReviewQueue { tx }, SkillReviewWorker { rx })
}

/// Run the worker loop on the current task. Drains all immediately-
/// available chat_ids into a dedup set before processing, so a flurry of
/// enqueues for the same chat collapses to one review.
pub async fn spawn_skill_review_worker(state: Arc<AppState>, mut worker: SkillReviewWorker) {
    use std::collections::HashSet;
    while let Some(first) = worker.rx.recv().await {
        let mut pending: HashSet<i64> = HashSet::new();
        pending.insert(first);
        while let Ok(more) = worker.rx.try_recv() {
            pending.insert(more);
        }
        for chat_id in pending {
            run_skill_review(state.clone(), chat_id).await;
        }
    }
}

/// Run the full review pipeline for one chat. Safe to call repeatedly
/// for the same chat — the cap on `agent-created` skills and the
/// duplicate-name check inside skill creation prevent runaway writes.
///
/// Steps (each may early-return without an LLM call):
///   1. Gate: feature must be enabled (`skill_review_min_tool_calls > 0`).
///   2. Load structured session; require `tool_use_count >= threshold`.
///   3. Run [`assess_success`] heuristic; skip on `Unlikely`.
///   4. Cap check: bail if `agent-created` count >= [`MAX_AGENT_CREATED_SKILLS`].
///   5. Build trajectory + ask LLM for a verdict.
///   6. On `{"create": true, ...}`, validate + write SKILL.md.
pub async fn run_skill_review(state: Arc<AppState>, chat_id: i64) {
    let min_tool_calls = state.config.skill_review_min_tool_calls;
    if min_tool_calls == 0 {
        return;
    }

    let session_messages = match load_session_messages(&state, chat_id).await {
        Some(msgs) if !msgs.is_empty() => msgs,
        _ => return,
    };

    let tool_use_count = count_tool_uses(&session_messages);
    if tool_use_count < min_tool_calls {
        return;
    }

    let signal = assess_success(&session_messages);
    if signal == SuccessSignal::Unlikely {
        info!(
            chat_id,
            tool_use_count, "Skill review: skipping — task did not look successful"
        );
        return;
    }

    let existing_skills = state.skills.discover_skills();
    let agent_created_count = existing_skills
        .iter()
        .filter(|s| s.source == "agent-created")
        .count();
    if agent_created_count >= MAX_AGENT_CREATED_SKILLS {
        info!(
            chat_id,
            agent_created_count,
            "Skill review: skipping — agent-created skill cap reached"
        );
        return;
    }

    let trajectory = build_tool_trajectory(&session_messages);
    if trajectory.trim().is_empty() {
        return;
    }

    let existing_skill_names: Vec<&str> =
        existing_skills.iter().map(|s| s.name.as_str()).collect();
    let skills_hint = if existing_skill_names.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nExisting skills (do NOT duplicate): {}",
            existing_skill_names.join(", ")
        )
    };

    let user_msg = Message {
        role: "user".into(),
        content: MessageContent::Text(format!(
            "Review this trajectory ({tool_use_count} tool calls) for skill-worthy approaches:{skills_hint}\n\nTrajectory:\n{trajectory}"
        )),
    };
    let response = match state
        .llm
        .send_message(SKILL_REVIEW_SYSTEM_PROMPT, vec![user_msg], None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Skill review: LLM call failed for chat {chat_id}: {e}");
            return;
        }
    };

    let text = response
        .content
        .iter()
        .filter_map(|b| {
            if let ResponseContentBlock::Text { text } = b {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("");

    let trimmed = text.trim();
    let review: serde_json::Value = match parse_review_json(trimmed) {
        Some(v) => v,
        None => return,
    };

    if !review.get("create").and_then(|v| v.as_bool()).unwrap_or(false) {
        return;
    }

    let skill_name = match review.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return,
    };
    let description = match review.get("description").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return,
    };
    let instructions = match review.get("instructions").and_then(|v| v.as_str()) {
        Some(i) => i,
        None => return,
    };

    if existing_skills.iter().any(|s| s.name == skill_name) {
        return;
    }

    if microclaw_storage::memory_quality::scan_for_injection(instructions).is_err() {
        warn!(
            "Skill review: rejected auto-created skill '{}' due to injection scan failure",
            skill_name
        );
        return;
    }

    let skills_dir = std::path::PathBuf::from(state.config.skills_data_dir());
    let skill_dir = skills_dir.join(&skill_name);
    if let Err(e) = std::fs::create_dir_all(&skill_dir) {
        error!(
            "Skill review: failed to create directory for '{}': {}",
            skill_name, e
        );
        return;
    }

    let content = format!(
        "---\nname: {}\ndescription: {}\nsource: agent-created\nupdated_at: \"{}\"\n---\n{}\n",
        skill_name,
        description,
        chrono::Utc::now().to_rfc3339(),
        instructions
    );

    if let Err(e) = std::fs::write(skill_dir.join("SKILL.md"), &content) {
        error!(
            "Skill review: failed to write SKILL.md for '{}': {}",
            skill_name, e
        );
        return;
    }

    info!(
        "Skill review: auto-created skill '{}' from chat {} conversation",
        skill_name, chat_id
    );
}

/// Tolerate review responses with leading/trailing prose by extracting
/// the outermost `{...}` substring before parsing.
fn parse_review_json(trimmed: &str) -> Option<serde_json::Value> {
    if let Ok(v) = serde_json::from_str(trimmed) {
        return Some(v);
    }
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}').map(|i| i + 1)?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&trimmed[start..end]).ok()
}

async fn load_session_messages(state: &Arc<AppState>, chat_id: i64) -> Option<Vec<Message>> {
    let loaded = call_blocking(state.db.clone(), move |db| db.load_session(chat_id))
        .await
        .ok()??;
    let (json, _updated_at) = loaded;
    match serde_json::from_str::<Vec<Message>>(&json) {
        Ok(msgs) => Some(msgs),
        Err(e) => {
            warn!(
                chat_id,
                "Skill review: failed to parse session messages_json: {e}"
            );
            None
        }
    }
}

fn count_tool_uses(messages: &[Message]) -> usize {
    let mut n = 0;
    for msg in messages {
        if let MessageContent::Blocks(blocks) = &msg.content {
            for block in blocks {
                if matches!(block, ContentBlock::ToolUse { .. }) {
                    n += 1;
                }
            }
        }
    }
    n
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
    fn parse_review_json_handles_bare_object() {
        let v = parse_review_json(r#"{"create": false}"#).unwrap();
        assert_eq!(v.get("create").and_then(|x| x.as_bool()), Some(false));
    }

    #[test]
    fn parse_review_json_strips_surrounding_prose() {
        let v = parse_review_json(
            "Sure! Here is the verdict:\n{\"create\": true, \"name\": \"x\"}\nThanks.",
        )
        .unwrap();
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
    }

    #[test]
    fn parse_review_json_returns_none_when_no_braces() {
        assert!(parse_review_json("nothing here").is_none());
    }

    #[tokio::test]
    async fn skill_review_queue_collapses_duplicate_enqueues() {
        let (queue, mut worker) = build_skill_review_channel();
        // Sender lives on; close it after enqueues so the worker drains
        // and exits cleanly.
        queue.enqueue(1);
        queue.enqueue(1);
        queue.enqueue(2);
        queue.enqueue(1);
        drop(queue);

        let mut received = Vec::new();
        // Mimic the worker's drain pattern: block on first, then non-block
        // until empty.
        if let Some(first) = worker.rx.recv().await {
            let mut pending = std::collections::HashSet::new();
            pending.insert(first);
            while let Ok(more) = worker.rx.try_recv() {
                pending.insert(more);
            }
            received.extend(pending);
        }
        received.sort();
        assert_eq!(received, vec![1, 2]);
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
