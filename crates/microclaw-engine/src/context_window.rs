//! Token-aware context management: per-model window sizes, token estimates,
//! tool-output pruning and the pieces of a structured compaction.
//!
//! Everything here is pure (no I/O, no provider calls) so it can be tested
//! directly; `agent_engine::compact_messages` drives it.

use std::collections::{HashMap, HashSet};

use microclaw_core::llm_types::{ContentBlock, Message, MessageContent};

use crate::config::Config;

/// Prefix of the user message that carries a compaction summary.
pub const SUMMARY_MARKER: &str = "[Conversation Summary]";

/// The `model_context_window` default; a config that still has it lets the
/// built-in model table decide.
const DEFAULT_WINDOW: usize = 200_000;

/// The automatic-compaction threshold never goes above this share of the
/// usable window, so a long tool loop cannot run straight into an overflow
/// (and a compaction cannot immediately re-trigger itself).
pub const MAX_AUTO_COMPACT_PCT: usize = 90;

/// Tokens counted for an inline image block.
const IMAGE_TOKENS: usize = 1_600;

/// Context window (input + output) of well-known model families, matched by
/// substring on the lower-cased model name; the first match wins. Values are
/// deliberately conservative.
const MODEL_WINDOWS: &[(&str, usize)] = &[
    ("[1m]", 1_000_000),
    ("-1m", 1_000_000),
    ("claude", 200_000),
    ("gpt-5", 272_000),
    ("gpt-4.1", 1_000_000),
    ("gpt-4o", 128_000),
    ("o4-mini", 200_000),
    ("o3", 200_000),
    ("codex", 272_000),
    ("gemini", 1_000_000),
    ("deepseek", 128_000),
    ("qwen3-coder", 256_000),
    ("qwen", 128_000),
    ("kimi", 256_000),
    ("moonshot", 128_000),
    ("glm-4.6", 200_000),
    ("glm", 128_000),
    ("grok-4", 256_000),
    ("grok", 128_000),
    ("minimax", 200_000),
    ("llama", 128_000),
    ("mistral", 128_000),
    ("codestral", 256_000),
];

/// Context window for `model`: an explicit `model_context_windows` entry,
/// then an explicitly configured `model_context_window`, then the built-in
/// table, then the default.
pub fn context_window_for(config: &Config, model: &str) -> usize {
    if let Some(window) = config.model_context_windows.get(model) {
        return (*window).max(1);
    }
    if config.model_context_window != DEFAULT_WINDOW && config.model_context_window > 0 {
        return config.model_context_window;
    }
    builtin_window(model).unwrap_or(DEFAULT_WINDOW)
}

fn builtin_window(model: &str) -> Option<usize> {
    let name = model.to_ascii_lowercase();
    MODEL_WINDOWS
        .iter()
        .find(|(pattern, _)| name.contains(pattern))
        .map(|(_, window)| *window)
}

/// Context budget of one request: the window, the output reserve and the
/// automatic-compaction threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudget {
    pub window: usize,
    pub reserved_output: usize,
    /// Input tokens at which automatic compaction starts; 0 when disabled.
    pub threshold: usize,
}

impl ContextBudget {
    pub fn for_model(config: &Config, model: &str) -> Self {
        let window = context_window_for(config, model);
        let reserved_output = (config.max_tokens as usize).min(window / 4);
        let usable = window.saturating_sub(reserved_output);
        let pct = config
            .context_pressure_compact_pct
            .min(MAX_AUTO_COMPACT_PCT);
        let threshold = if config.auto_compact && pct > 0 {
            usable.saturating_mul(pct) / 100
        } else {
            0
        };
        Self {
            window,
            reserved_output,
            threshold,
        }
    }

    pub fn enabled(&self) -> bool {
        self.threshold > 0
    }

    pub fn over(&self, tokens: usize) -> bool {
        self.enabled() && tokens >= self.threshold
    }
}

/// Rough token count of a string: four bytes per token for ASCII-heavy text,
/// three for text dominated by multi-byte characters (CJK).
pub fn estimate_text_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let bytes = text.len();
    let chars = text.chars().count();
    let per_token = if bytes >= chars * 2 { 3 } else { 4 };
    bytes.div_ceil(per_token)
}

pub fn estimate_block_tokens(block: &ContentBlock) -> usize {
    match block {
        ContentBlock::Text { text } => estimate_text_tokens(text),
        ContentBlock::Image { .. } => IMAGE_TOKENS,
        ContentBlock::ToolUse { name, input, .. } => {
            8 + estimate_text_tokens(name) + estimate_text_tokens(&input.to_string())
        }
        ContentBlock::ToolResult { content, .. } => 8 + estimate_text_tokens(content),
    }
}

pub fn estimate_message_tokens(message: &Message) -> usize {
    4 + match &message.content {
        MessageContent::Text(text) => estimate_text_tokens(text),
        MessageContent::Blocks(blocks) => blocks.iter().map(estimate_block_tokens).sum(),
    }
}

pub fn estimate_messages_tokens(messages: &[Message]) -> usize {
    messages.iter().map(estimate_message_tokens).sum()
}

/// Where the tokens of a conversation go (for `/context`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContextBreakdown {
    pub summary: usize,
    pub user_text: usize,
    pub assistant_text: usize,
    pub tool_calls: usize,
    pub tool_results: usize,
    pub images: usize,
    pub messages: usize,
}

impl ContextBreakdown {
    pub fn total(&self) -> usize {
        self.summary
            + self.user_text
            + self.assistant_text
            + self.tool_calls
            + self.tool_results
            + self.images
    }
}

pub fn breakdown(messages: &[Message]) -> ContextBreakdown {
    let mut out = ContextBreakdown {
        messages: messages.len(),
        ..Default::default()
    };
    for (index, message) in messages.iter().enumerate() {
        let user = message.role == "user";
        match &message.content {
            MessageContent::Text(text) => {
                let tokens = estimate_text_tokens(text) + 4;
                if index == 0 && is_summary_message(message) {
                    out.summary += tokens;
                } else if user {
                    out.user_text += tokens;
                } else {
                    out.assistant_text += tokens;
                }
            }
            MessageContent::Blocks(blocks) => {
                for block in blocks {
                    let tokens = estimate_block_tokens(block);
                    match block {
                        ContentBlock::Text { .. } if user => out.user_text += tokens,
                        ContentBlock::Text { .. } => out.assistant_text += tokens,
                        ContentBlock::Image { .. } => out.images += tokens,
                        ContentBlock::ToolUse { .. } => out.tool_calls += tokens,
                        ContentBlock::ToolResult { .. } => out.tool_results += tokens,
                    }
                }
            }
        }
    }
    out
}

pub fn is_summary_message(message: &Message) -> bool {
    message.role == "user"
        && matches!(&message.content, MessageContent::Text(text) if text.starts_with(SUMMARY_MARKER))
}

/// The summary text carried by a leading summary message, if any.
pub fn previous_summary(messages: &[Message]) -> Option<String> {
    let first = messages.first()?;
    if !is_summary_message(first) {
        return None;
    }
    match &first.content {
        MessageContent::Text(text) => Some(text[SUMMARY_MARKER.len()..].trim().to_string()),
        MessageContent::Blocks(_) => None,
    }
}

/// Result of [`prune_tool_results`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneStats {
    pub results_cleared: usize,
    pub tokens_saved: usize,
}

const CLEARED_PREFIX: &str = "[output cleared to save context";
const SUPERSEDED_PREFIX: &str = "[superseded by a later read";

fn already_reduced(content: &str) -> bool {
    content.starts_with(CLEARED_PREFIX) || content.starts_with(SUPERSEDED_PREFIX)
}

/// Tool results that must survive pruning: they are small and carry state
/// the agent relies on.
fn protected_tool(name: &str) -> bool {
    matches!(
        name,
        "todo_read"
            | "todo_write"
            | "activate_skill"
            | "report_progress"
            | "clarify"
            | "context_note"
    )
}

#[derive(Debug, Clone)]
struct ToolCall {
    name: String,
    input: serde_json::Value,
}

fn tool_calls_by_id(messages: &[Message]) -> HashMap<String, ToolCall> {
    let mut calls = HashMap::new();
    for message in messages {
        if let MessageContent::Blocks(blocks) = &message.content {
            for block in blocks {
                if let ContentBlock::ToolUse {
                    id, name, input, ..
                } = block
                {
                    calls.insert(
                        id.clone(),
                        ToolCall {
                            name: name.clone(),
                            input: input.clone(),
                        },
                    );
                }
            }
        }
    }
    calls
}

/// Short human description of a tool call: `read_file src/lib.rs`.
fn describe_call(call: &ToolCall) -> String {
    let arg = ["path", "file_path", "command", "pattern", "url", "query"]
        .iter()
        .find_map(|key| call.input.get(*key).and_then(|v| v.as_str()))
        .map(|value| {
            let first_line = value.lines().next().unwrap_or_default();
            truncate_chars(first_line, 120)
        })
        .unwrap_or_default();
    if arg.is_empty() {
        call.name.clone()
    } else {
        format!("{} {}", call.name, arg)
    }
}

/// Artifact pointer kept from a spilled tool result, so a cleared output can
/// still be fetched in full.
fn artifact_pointer(content: &str) -> Option<String> {
    let start = content.find("art_")?;
    let id: String = content[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (id.len() > 8).then_some(id)
}

fn read_key(call: &ToolCall) -> Option<String> {
    if call.name != "read_file" {
        return None;
    }
    let path = call
        .input
        .get("path")
        .or_else(|| call.input.get("file_path"))
        .and_then(|v| v.as_str())?;
    let offset = call.input.get("offset").map(|v| v.to_string());
    let limit = call.input.get("limit").map(|v| v.to_string());
    Some(format!("{path}|{offset:?}|{limit:?}"))
}

/// Clear older tool outputs without calling a model.
///
/// Scanning from the newest message backwards, the most recent
/// `protect_tokens` of tool output stay intact. Older outputs are replaced
/// with a one-line stub naming the call, but only when that frees at least
/// `minimum_tokens` (smaller savings are not worth invalidating the provider's
/// prompt cache). Independently, a `read_file` result that a later identical
/// read supersedes is always replaced. Tool use/result pairing is untouched:
/// only result *contents* change.
pub fn prune_tool_results(
    messages: &mut [Message],
    protect_tokens: usize,
    minimum_tokens: usize,
) -> PruneStats {
    let calls = tool_calls_by_id(messages);
    let mut stats = PruneStats::default();

    // Pass 1: superseded reads (latest read of a path/range wins).
    let mut seen_reads: HashSet<String> = HashSet::new();
    for message in messages.iter_mut().rev() {
        let MessageContent::Blocks(blocks) = &mut message.content else {
            continue;
        };
        for block in blocks.iter_mut().rev() {
            let ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } = block
            else {
                continue;
            };
            if is_error == &Some(true) || already_reduced(content) {
                continue;
            }
            let Some(key) = calls.get(tool_use_id.as_str()).and_then(read_key) else {
                continue;
            };
            if !seen_reads.insert(key) {
                let before = estimate_text_tokens(content);
                let path = calls
                    .get(tool_use_id.as_str())
                    .map(describe_call)
                    .unwrap_or_default();
                *content = format!("{SUPERSEDED_PREFIX} of the same file: {path}]");
                stats.tokens_saved += before.saturating_sub(estimate_text_tokens(content));
                stats.results_cleared += 1;
            }
        }
    }

    // Pass 2: find the tool results beyond the protected recent window.
    let mut running = 0usize;
    let mut candidates: Vec<(usize, usize)> = Vec::new();
    let mut prunable = 0usize;
    for (mi, message) in messages.iter().enumerate().rev() {
        let MessageContent::Blocks(blocks) = &message.content else {
            continue;
        };
        for (bi, block) in blocks.iter().enumerate().rev() {
            let ContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } = block
            else {
                continue;
            };
            if already_reduced(content) {
                continue;
            }
            let tokens = estimate_text_tokens(content);
            running += tokens;
            if running <= protect_tokens {
                continue;
            }
            let name = calls
                .get(tool_use_id.as_str())
                .map(|c| c.name.as_str())
                .unwrap_or("");
            if protected_tool(name) || tokens < 64 {
                continue;
            }
            prunable += tokens;
            candidates.push((mi, bi));
        }
    }
    if prunable < minimum_tokens || candidates.is_empty() {
        return stats;
    }
    for (mi, bi) in candidates {
        let MessageContent::Blocks(blocks) = &mut messages[mi].content else {
            continue;
        };
        let ContentBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } = &mut blocks[bi]
        else {
            continue;
        };
        let before = estimate_text_tokens(content);
        let lines = content.lines().count();
        let what = calls
            .get(tool_use_id.as_str())
            .map(describe_call)
            .unwrap_or_else(|| "tool".into());
        let artifact = artifact_pointer(content)
            .map(|id| format!("; full output in artifact `{id}` (fetch_artifact)"))
            .unwrap_or_default();
        *content = format!(
            "{CLEARED_PREFIX}: {what} ({lines} lines, ~{before} tokens){artifact}; run it again if you need it]"
        );
        stats.tokens_saved += before.saturating_sub(estimate_text_tokens(content));
        stats.results_cleared += 1;
    }
    stats
}

/// Index at which the kept (verbatim) tail starts when keeping roughly the
/// last `keep_tokens` tokens. The tail always starts on a plain user message
/// (never between a tool call and its result) and keeps at least the last
/// such message. Returns 0 when there is nothing older to summarize.
pub fn token_split(messages: &[Message], keep_tokens: usize) -> usize {
    let mut kept = 0usize;
    let mut candidate = messages.len();
    for (index, message) in messages.iter().enumerate().rev() {
        kept += estimate_message_tokens(message);
        candidate = index;
        if kept > keep_tokens {
            break;
        }
    }
    // Move forward to the next plain user message so the tail is valid and
    // stays within budget; fall back to the last plain user message.
    let plain_user = |m: &Message| m.role == "user" && !has_tool_blocks(m);
    let mut split = candidate;
    while split < messages.len() && !plain_user(&messages[split]) {
        split += 1;
    }
    if split >= messages.len() {
        split = match messages.iter().rposition(plain_user) {
            Some(index) => index,
            None => return 0,
        };
    }
    // Never "summarize" only a leading summary message.
    if split <= 1 && messages.first().is_some_and(is_summary_message) {
        return 0;
    }
    split
}

fn has_tool_blocks(message: &Message) -> bool {
    match &message.content {
        MessageContent::Blocks(blocks) => blocks.iter().any(|b| {
            matches!(
                b,
                ContentBlock::ToolUse { .. } | ContentBlock::ToolResult { .. }
            )
        }),
        MessageContent::Text(_) => false,
    }
}

pub fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// Render messages for the summarizer: tool results and tool inputs are
/// capped so one huge output cannot crowd out the rest.
pub fn render_for_summary(messages: &[Message]) -> String {
    let calls = tool_calls_by_id(messages);
    let mut out = String::new();
    for message in messages {
        if is_summary_message(message) {
            continue;
        }
        let role = &message.role;
        match &message.content {
            MessageContent::Text(text) => {
                out.push_str(&format!("[{role}]: {}\n\n", truncate_chars(text, 6_000)));
            }
            MessageContent::Blocks(blocks) => {
                for block in blocks {
                    match block {
                        ContentBlock::Text { text } => {
                            out.push_str(&format!("[{role}]: {}\n\n", truncate_chars(text, 6_000)))
                        }
                        ContentBlock::ToolUse { name, input, .. } => out.push_str(&format!(
                            "[tool call] {name}({})\n",
                            truncate_chars(&input.to_string(), 600)
                        )),
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                        } => {
                            let label = calls
                                .get(tool_use_id.as_str())
                                .map(|c| c.name.as_str())
                                .unwrap_or("tool");
                            let kind = if is_error == &Some(true) {
                                "error"
                            } else {
                                "result"
                            };
                            out.push_str(&format!(
                                "[{label} {kind}] {}\n\n",
                                truncate_chars(content, 1_500)
                            ));
                        }
                        ContentBlock::Image { .. } => out.push_str("[image]\n"),
                    }
                }
            }
        }
    }
    out
}

/// Split `text` into chunks of at most `max_chars` characters, on line
/// boundaries where possible.
pub fn chunk_text(text: &str, max_chars: usize) -> Vec<String> {
    let max_chars = max_chars.max(1);
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_chars = 0usize;
    for line in text.split_inclusive('\n') {
        let line_chars = line.chars().count();
        if current_chars + line_chars > max_chars && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            current_chars = 0;
        }
        if line_chars > max_chars {
            let mut rest: Vec<char> = line.chars().collect();
            while rest.len() > max_chars {
                let tail = rest.split_off(max_chars);
                chunks.push(rest.into_iter().collect());
                rest = tail;
            }
            current = rest.into_iter().collect();
            current_chars = current.chars().count();
            continue;
        }
        current.push_str(line);
        current_chars += line_chars;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Instructions for the summarizer. The sections are what a coding (or any
/// long-running) session needs to continue without the original history.
pub const SUMMARY_SYSTEM_PROMPT: &str = "You write handoff summaries of an AI assistant's working session. Another instance of the assistant will continue the work from your summary alone, so keep every fact it needs and drop chatter. Be specific: exact file paths, function names, commands, error messages and numbers. Never invent anything.";

pub fn summary_request(
    previous: Option<&str>,
    transcript: &str,
    focus: Option<&str>,
    instructions: Option<&str>,
) -> String {
    let mut prompt = String::from(
        "Update the handoff summary of this session. Write these sections, in this order, as Markdown headings (omit a section only when it has nothing):\n\
         ## Goal and constraints — what the user wants and every requirement, preference or prohibition they stated (quote short ones verbatim)\n\
         ## Decisions — what was decided and why\n\
         ## Files and state — files read, created or changed, with what changed and their current state\n\
         ## Errors and fixes — failures seen (commands, tests, checks) and how they were resolved or why they are still open\n\
         ## Plan — the current task list with each item's status\n\
         ## Verification — which checks or tests last passed or failed\n\
         ## Next step — exactly what to do next\n",
    );
    if let Some(focus) = focus.filter(|f| !f.trim().is_empty()) {
        prompt.push_str(&format!(
            "\nThe user asked this summary to focus on: {}\n",
            focus.trim()
        ));
    }
    if let Some(instructions) = instructions.filter(|i| !i.trim().is_empty()) {
        prompt.push_str(&format!(
            "\nProject instructions for summaries: {}\n",
            instructions.trim()
        ));
    }
    match previous.filter(|p| !p.trim().is_empty()) {
        Some(previous) => prompt.push_str(&format!(
            "\nThe summary so far (keep everything that still matters, merge in the new history):\n<summary>\n{}\n</summary>\n",
            previous.trim()
        )),
        None => prompt.push_str("\nThere is no earlier summary.\n"),
    }
    prompt.push_str(&format!(
        "\nNew history to merge in:\n<history>\n{transcript}\n</history>\n\nReply with the updated summary only."
    ));
    prompt
}

/// Files changed through the file tools in `messages`.
pub fn touched_files(messages: &[Message]) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    let mut push = |path: &str| {
        let path = path.trim();
        if !path.is_empty() && !files.iter().any(|f| f == path) {
            files.push(path.to_string());
        }
    };
    for message in messages {
        let MessageContent::Blocks(blocks) = &message.content else {
            continue;
        };
        for block in blocks {
            let ContentBlock::ToolUse { name, input, .. } = block else {
                continue;
            };
            match name.as_str() {
                "write_file" | "edit_file" => {
                    if let Some(path) = input
                        .get("path")
                        .or_else(|| input.get("file_path"))
                        .and_then(|v| v.as_str())
                    {
                        push(path);
                    }
                }
                "apply_patch" => {
                    let patch = input
                        .get("patch")
                        .or_else(|| input.get("input"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    for line in patch.lines() {
                        for prefix in [
                            "*** Update File: ",
                            "*** Add File: ",
                            "*** Delete File: ",
                            "*** Move to: ",
                        ] {
                            if let Some(path) = line.strip_prefix(prefix) {
                                push(path);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    files
}

/// The user's own words in `messages` (newest last), excluding tool results
/// and summaries, capped to `budget_tokens` counting from the newest.
pub fn recent_user_requests(messages: &[Message], budget_tokens: usize) -> Vec<String> {
    let mut picked: Vec<String> = Vec::new();
    let mut used = 0usize;
    for message in messages.iter().rev() {
        if message.role != "user" || is_summary_message(message) {
            continue;
        }
        let text = match &message.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let text = truncate_chars(text, 2_000);
        let tokens = estimate_text_tokens(&text);
        if used + tokens > budget_tokens && !picked.is_empty() {
            break;
        }
        used += tokens;
        picked.push(text);
    }
    picked.reverse();
    picked
}

/// Summary written without a model, used when summarization fails: it keeps
/// the earlier summary, the user's requests, the files changed and the last
/// commands run.
pub fn fallback_summary(messages: &[Message]) -> String {
    let mut out = String::from(
        "(Automatic summary unavailable; this is a mechanical digest of the earlier history.)\n",
    );
    if let Some(previous) = previous_summary(messages) {
        out.push_str("\n## Earlier summary\n");
        out.push_str(&previous);
        out.push('\n');
    }
    let requests = recent_user_requests(messages, 3_000);
    if !requests.is_empty() {
        out.push_str("\n## User requests\n");
        for request in requests {
            out.push_str(&format!("- {}\n", request.replace('\n', " ")));
        }
    }
    let files = touched_files(messages);
    if !files.is_empty() {
        out.push_str("\n## Files changed\n");
        for file in files {
            out.push_str(&format!("- {file}\n"));
        }
    }
    let calls = tool_calls_by_id(messages);
    let mut commands: Vec<String> = Vec::new();
    for message in messages {
        if let MessageContent::Blocks(blocks) = &message.content {
            for block in blocks {
                if let ContentBlock::ToolUse { id, name, .. } = block {
                    if name == "bash" {
                        if let Some(call) = calls.get(id.as_str()) {
                            commands.push(describe_call(call));
                        }
                    }
                }
            }
        }
    }
    if !commands.is_empty() {
        out.push_str("\n## Last commands\n");
        for command in commands.iter().rev().take(10).rev() {
            out.push_str(&format!("- {command}\n"));
        }
    }
    out
}

/// The user message that replaces summarized history: the summary plus the
/// facts re-injected verbatim (the user's own requests and the files changed).
pub fn summary_message_text(summary: &str, summarized: &[Message]) -> String {
    let mut text = format!(
        "{SUMMARY_MARKER}\nThis is a handoff summary of the earlier part of this conversation. Continue the work from here; do not restart it or redo finished steps.\n\n{}\n",
        summary.trim()
    );
    let requests = recent_user_requests(summarized, 3_000);
    if !requests.is_empty() {
        text.push_str("\n## The user's earlier messages (verbatim, most recent last)\n");
        for request in requests {
            text.push_str(&format!("> {}\n\n", request.replace('\n', "\n> ")));
        }
    }
    let files = touched_files(summarized);
    if !files.is_empty() {
        text.push_str("\n## Files changed earlier in this session\n");
        for file in files {
            text.push_str(&format!("- {file}\n"));
        }
    }
    text
}

/// One line telling the model how full its context is.
pub fn budget_note(budget: &ContextBudget, used_tokens: usize) -> String {
    let usable = budget.window.saturating_sub(budget.reserved_output).max(1);
    let pct = (used_tokens * 100 / usable).min(100);
    if budget.enabled() {
        format!(
            "<context_budget>~{used_tokens} of {usable} tokens used ({pct}%); older history is compacted automatically at ~{} tokens. Prefer targeted reads and delegate wide searches to `explore` when the budget is tight.</context_budget>",
            budget.threshold
        )
    } else {
        format!("<context_budget>~{used_tokens} of {usable} tokens used ({pct}%).</context_budget>")
    }
}

/// `context_note` and `rewind_context`, handled by the agent loop itself.
pub fn context_tool_definitions() -> Vec<microclaw_core::llm_types::ToolDefinition> {
    use microclaw_core::llm_types::ToolDefinition;
    vec![
        ToolDefinition {
            name: "context_note".into(),
            description: "Save a checkpoint in this turn with a one-line note about what you know so far (for example before trying an approach that may not work). Returns a checkpoint id for rewind_context. Notes also survive compaction.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "note": {"type": "string", "description": "What you have established so far"}
                },
                "required": ["note"]
            }),
        },
        ToolDefinition {
            name: "rewind_context".into(),
            description: "Drop everything after a checkpoint from your context (failed attempts, long useless outputs) and continue from there with a note to your earlier self, e.g. \"the bug is not in parser.rs; look at lexer.rs\". Files you changed are NOT reverted.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "checkpoint": {"type": "string", "description": "Checkpoint id from context_note, e.g. cp-1"},
                    "note": {"type": "string", "description": "What your earlier self should know"}
                },
                "required": ["checkpoint", "note"]
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(text: &str) -> Message {
        Message {
            role: "user".into(),
            content: MessageContent::Text(text.into()),
        }
    }

    fn assistant(text: &str) -> Message {
        Message {
            role: "assistant".into(),
            content: MessageContent::Text(text.into()),
        }
    }

    fn call(id: &str, name: &str, input: serde_json::Value) -> Message {
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

    fn result(id: &str, content: &str) -> Message {
        Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                tool_use_id: id.into(),
                content: content.into(),
                is_error: None,
            }]),
        }
    }

    fn result_text(message: &Message) -> &str {
        match &message.content {
            MessageContent::Blocks(blocks) => match &blocks[0] {
                ContentBlock::ToolResult { content, .. } => content,
                _ => panic!("not a tool result"),
            },
            _ => panic!("not blocks"),
        }
    }

    #[test]
    fn window_uses_override_then_explicit_then_table() {
        let mut config = Config::test_defaults();
        assert_eq!(context_window_for(&config, "claude-sonnet-4-5"), 200_000);
        assert_eq!(context_window_for(&config, "gpt-4o-mini"), 128_000);
        assert_eq!(context_window_for(&config, "gemini-2.5-pro"), 1_000_000);
        assert_eq!(context_window_for(&config, "unknown-model"), 200_000);
        config.model_context_window = 64_000;
        assert_eq!(context_window_for(&config, "gemini-2.5-pro"), 64_000);
        config
            .model_context_windows
            .insert("gemini-2.5-pro".into(), 500_000);
        assert_eq!(context_window_for(&config, "gemini-2.5-pro"), 500_000);
    }

    #[test]
    fn budget_threshold_is_clamped_and_can_be_disabled() {
        let mut config = Config::test_defaults();
        config.max_tokens = 8_000;
        config.context_pressure_compact_pct = 99;
        let budget = ContextBudget::for_model(&config, "claude-x");
        assert_eq!(budget.window, 200_000);
        assert_eq!(budget.threshold, (200_000 - 8_000) * 90 / 100);
        config.auto_compact = false;
        assert!(!ContextBudget::for_model(&config, "claude-x").enabled());
    }

    #[test]
    fn estimates_are_roughly_bytes_over_four() {
        assert_eq!(estimate_text_tokens(""), 0);
        assert_eq!(estimate_text_tokens(&"a".repeat(400)), 100);
        // CJK: 3 bytes per char, ~1 token per char.
        assert_eq!(estimate_text_tokens(&"上".repeat(300)), 300);
    }

    #[test]
    fn pruning_clears_old_outputs_and_keeps_recent_ones() {
        let big = "line\n".repeat(4_000); // ~5k tokens each
        let mut messages = vec![user("start")];
        for i in 0..6 {
            let id = format!("t{i}");
            messages.push(call(
                &id,
                "bash",
                json!({"command": format!("cargo test {i}")}),
            ));
            messages.push(result(&id, &big));
        }
        let stats = prune_tool_results(&mut messages, 12_000, 5_000);
        assert!(stats.results_cleared >= 3, "{stats:?}");
        assert!(result_text(&messages[2]).starts_with(CLEARED_PREFIX));
        assert!(result_text(&messages[2]).contains("bash cargo test 0"));
        // The newest output survives.
        assert_eq!(result_text(&messages[12]), big);
    }

    #[test]
    fn pruning_skips_small_savings() {
        let mut messages = vec![
            user("go"),
            call("a", "bash", json!({"command": "ls"})),
            result("a", &"x".repeat(2_000)),
            call("b", "bash", json!({"command": "ls"})),
            result("b", &"y".repeat(2_000)),
        ];
        let stats = prune_tool_results(&mut messages, 100, 50_000);
        assert_eq!(stats.results_cleared, 0);
    }

    #[test]
    fn superseded_reads_are_replaced() {
        let mut messages = vec![
            user("go"),
            call("a", "read_file", json!({"path": "src/lib.rs"})),
            result("a", &"old ".repeat(500)),
            call("b", "read_file", json!({"path": "src/lib.rs"})),
            result("b", &"new ".repeat(500)),
        ];
        let stats = prune_tool_results(&mut messages, 1_000_000, 1_000_000);
        assert_eq!(stats.results_cleared, 1);
        assert!(result_text(&messages[2]).starts_with(SUPERSEDED_PREFIX));
        assert!(result_text(&messages[4]).starts_with("new"));
    }

    #[test]
    fn pruned_output_keeps_artifact_pointer() {
        let content = format!(
            "{}\n[--- truncated. Full result saved as artifact `art_0123456789abcdef` for 24h.",
            "z".repeat(40_000)
        );
        let mut messages = vec![
            user("go"),
            call("a", "bash", json!({"command": "make"})),
            result("a", &content),
            call("b", "bash", json!({"command": "make"})),
            result("b", "ok"),
        ];
        prune_tool_results(&mut messages, 10, 100);
        assert!(result_text(&messages[2]).contains("art_0123456789abcdef"));
    }

    #[test]
    fn token_split_starts_on_plain_user_message() {
        let messages = vec![
            user("first"),
            assistant("a1"),
            user("second request"),
            call("a", "bash", json!({"command": "ls"})),
            result("a", &"r".repeat(4_000)),
            assistant("done"),
            user("third"),
            assistant("ok"),
        ];
        let split = token_split(&messages, 10);
        assert_eq!(split, 6);
        // A budget that covers everything from the second request on keeps
        // exactly that tail.
        let budget = estimate_messages_tokens(&messages[2..]) + 1;
        assert_eq!(token_split(&messages, budget), 2);
        assert_eq!(token_split(&messages[6..], 1_000_000), 0);
    }

    #[test]
    fn summary_request_has_sections_previous_summary_and_focus() {
        let prompt = summary_request(
            Some("old facts"),
            "[user]: hi",
            Some("the parser"),
            Some("keep API names"),
        );
        for section in [
            "## Goal and constraints",
            "## Files and state",
            "## Next step",
        ] {
            assert!(prompt.contains(section));
        }
        assert!(prompt.contains("old facts"));
        assert!(prompt.contains("the parser"));
        assert!(prompt.contains("keep API names"));
    }

    #[test]
    fn summary_message_reinjects_user_words_and_files() {
        let history = vec![
            user("Use pnpm, never npm."),
            call(
                "a",
                "edit_file",
                json!({"path": "src/a.rs", "old_string": "x", "new_string": "y"}),
            ),
            result("a", "ok"),
            call(
                "b",
                "apply_patch",
                json!({"patch": "*** Begin Patch\n*** Update File: src/b.rs\n@@\n-x\n+y\n*** End Patch"}),
            ),
            result("b", "ok"),
        ];
        let text = summary_message_text("## Goal\nfix it", &history);
        assert!(text.starts_with(SUMMARY_MARKER));
        assert!(text.contains("> Use pnpm, never npm."));
        assert!(text.contains("- src/a.rs"));
        assert!(text.contains("- src/b.rs"));
        let message = user(&text);
        let previous = previous_summary(&[message]).unwrap();
        assert!(previous.contains("fix it"), "{previous}");
    }

    #[test]
    fn fallback_summary_keeps_requests_files_and_commands() {
        let history = vec![
            user(&format!("{SUMMARY_MARKER}\nearlier facts")),
            assistant("ok"),
            user("Do not change the public API."),
            call(
                "a",
                "write_file",
                json!({"path": "README.md", "content": "x"}),
            ),
            result("a", "ok"),
            call("b", "bash", json!({"command": "cargo test -p parser"})),
            result("b", "ok"),
        ];
        let digest = fallback_summary(&history);
        assert!(digest.contains("earlier facts"));
        assert!(digest.contains("Do not change the public API."));
        assert!(digest.contains("README.md"));
        assert!(digest.contains("cargo test -p parser"));
    }

    #[test]
    fn render_caps_tool_output_and_chunks_split_on_lines() {
        let history = vec![
            user("go"),
            call("a", "bash", json!({"command": "ls"})),
            result("a", &"q".repeat(10_000)),
        ];
        let rendered = render_for_summary(&history);
        assert!(rendered.len() < 3_000);
        let chunks = chunk_text("aaa\nbbb\nccc\n", 8);
        assert_eq!(chunks, vec!["aaa\nbbb\n", "ccc\n"]);
        let chunks = chunk_text(&"x".repeat(25), 10);
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn breakdown_attributes_tokens() {
        let history = vec![
            user(&format!("{SUMMARY_MARKER}\nfacts")),
            assistant("ok"),
            call("a", "bash", json!({"command": "ls"})),
            result("a", "out"),
        ];
        let b = breakdown(&history);
        assert!(b.summary > 0 && b.assistant_text > 0 && b.tool_calls > 0 && b.tool_results > 0);
        assert_eq!(b.messages, 4);
        assert_eq!(
            b.total(),
            b.summary + b.user_text + b.assistant_text + b.tool_calls + b.tool_results + b.images
        );
    }
}
