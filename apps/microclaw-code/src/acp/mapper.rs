//! Driver updates → ACP session updates.
//!
//! Edits become real `diff` tool-call content (old and new file text, so
//! editors render and review them), shell commands show their output,
//! project checks appear as their own tool calls, and paths are absolute so
//! an editor can follow the agent.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use agent_client_protocol_schema::v1::{
    CompactionStatus, CompactionUpdate, ContentBlock, ContentChunk, Diff, Notice, NoticeSeverity,
    Plan, PlanEntry, PlanEntryPriority, PlanEntryStatus, SessionUpdate, ToolCall, ToolCallContent,
    ToolCallLocation, ToolCallStatus, ToolCallUpdate, ToolCallUpdateFields, ToolKind,
};
use microclaw_code_core::driver::Update;
use microclaw_sdk::{RuntimeEvent, RuntimePlanStepStatus};

/// Largest file whose text is attached to a diff.
const MAX_DIFF_FILE_BYTES: u64 = 512 * 1024;

pub fn tool_kind(name: &str) -> ToolKind {
    match name {
        "read_file" | "bash_output" | "explore" => ToolKind::Read,
        "edit_file" | "write_file" | "apply_patch" => ToolKind::Edit,
        "grep" | "glob" => ToolKind::Search,
        "bash" | "bash_kill" | "bash_input" => ToolKind::Execute,
        "web_fetch" | "web_search" => ToolKind::Fetch,
        "todo_write" | "sub_agent" => ToolKind::Think,
        _ => ToolKind::Other,
    }
}

/// Files an `apply_patch` envelope touches.
fn patch_paths(patch: &str) -> Vec<String> {
    patch
        .lines()
        .filter_map(|line| {
            [
                "*** Update File: ",
                "*** Add File: ",
                "*** Delete File: ",
                "*** Move to: ",
            ]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        })
        .map(|p| p.trim().to_string())
        .collect()
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_DIFF_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Undoes a unified diff (hunk headers and ` `/`-`/`+` lines, no file header)
/// on `current`, giving the text before that edit. Each hunk is located by its
/// content, starting at its header's line, so edits made since elsewhere in the
/// file are kept on both sides. `None` when a hunk no longer matches.
fn reverse_apply(current: &str, diff: &str) -> Option<String> {
    let lines: Vec<&str> = current.split_inclusive('\n').collect();
    let bare = |line: &str| line.strip_suffix('\n').unwrap_or(line).to_string();
    let mut hunks: Vec<(usize, Vec<(char, &str)>)> = Vec::new();
    for line in diff.lines() {
        if let Some(header) = line.strip_prefix("@@ ") {
            let start = header
                .split_whitespace()
                .find_map(|part| part.strip_prefix('+'))?
                .split(',')
                .next()?
                .parse::<usize>()
                .ok()?;
            hunks.push((start.saturating_sub(1), Vec::new()));
            continue;
        }
        let (_, body) = hunks.last_mut()?;
        let mut chars = line.chars();
        let sign = chars.next().unwrap_or(' ');
        if !matches!(sign, ' ' | '-' | '+') {
            return None;
        }
        body.push((sign, chars.as_str()));
    }
    let mut out = String::new();
    let mut cursor = 0;
    for (hint, body) in hunks {
        let after: Vec<&str> = body
            .iter()
            .filter(|(sign, _)| *sign != '-')
            .map(|(_, text)| *text)
            .collect();
        let matches = |at: usize| {
            at + after.len() <= lines.len()
                && after
                    .iter()
                    .enumerate()
                    .all(|(k, text)| bare(lines[at + k]) == *text)
        };
        let at = if hint >= cursor && matches(hint) {
            hint
        } else {
            (cursor..=lines.len()).find(|at| matches(*at))?
        };
        lines[cursor..at].iter().for_each(|line| out.push_str(line));
        let mut i = at;
        for (sign, text) in body {
            match sign {
                ' ' => {
                    out.push_str(lines[i]);
                    i += 1;
                }
                '+' => i += 1,
                _ => {
                    out.push_str(text);
                    out.push('\n');
                }
            }
        }
        cursor = i;
    }
    lines[cursor..].iter().for_each(|line| out.push_str(line));
    Some(out)
}

/// `text` as a Markdown code span, with a fence longer than any backtick run
/// inside it.
fn code_span(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}

fn thought(text: String) -> SessionUpdate {
    SessionUpdate::AgentThoughtChunk(ContentChunk::new(text.into()))
}

fn message(text: String) -> SessionUpdate {
    SessionUpdate::AgentMessageChunk(ContentChunk::new(text.into()))
}

/// Optional session updates the client advertised.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientSupport {
    /// `notice` updates (shown to the user, not kept in the thread).
    pub notices: bool,
    /// `compaction_update` updates.
    pub compaction: bool,
}

pub struct UpdateMapper {
    root: PathBuf,
    support: ClientSupport,
    compactions: u32,
    streamed: bool,
    /// Last running call id per tool name (for permission requests).
    running: HashMap<String, String>,
    /// Call id by absolute path (for diffs).
    by_path: HashMap<PathBuf, String>,
    /// Diffs shown so far, per call (an update replaces the whole content).
    diffs: HashMap<String, Vec<ToolCallContent>>,
    /// Calls whose content is richer than the result preview.
    rich: HashSet<String>,
    checks: u32,
}

impl UpdateMapper {
    pub fn new(root: impl Into<PathBuf>, support: ClientSupport) -> Self {
        Self {
            root: root.into(),
            support,
            compactions: 0,
            streamed: false,
            running: HashMap::new(),
            by_path: HashMap::new(),
            diffs: HashMap::new(),
            rich: HashSet::new(),
            checks: 0,
        }
    }

    pub fn absolute(&self, path: &str) -> PathBuf {
        let path = Path::new(path);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }

    /// The tool call an approval for `tool` belongs to.
    pub fn running_call(&self, tool: &str) -> Option<String> {
        self.running.get(tool).cloned()
    }

    fn track_edit(&mut self, path: PathBuf, call_id: &str) {
        self.by_path.insert(path, call_id.to_string());
    }

    pub fn map(&mut self, update: &Update) -> Vec<SessionUpdate> {
        match update {
            Update::Runtime(envelope) => self.runtime(&envelope.event),
            Update::RunFinished { final_text, .. } => {
                let mut out = Vec::new();
                if !self.streamed && !final_text.trim().is_empty() {
                    out.push(message(final_text.clone()));
                }
                self.streamed = false;
                out
            }
            Update::CheckStarted(check) => {
                self.checks += 1;
                let id = format!("check-{}", self.checks);
                vec![SessionUpdate::ToolCall(
                    ToolCall::new(
                        id,
                        format!(
                            "Check {}: {}",
                            code_span(&check.name),
                            code_span(&check.run)
                        ),
                    )
                    .kind(ToolKind::Execute)
                    .status(ToolCallStatus::InProgress),
                )]
            }
            Update::CheckFinished(outcome) => {
                let id = format!("check-{}", self.checks);
                let status = if outcome.success {
                    ToolCallStatus::Completed
                } else {
                    ToolCallStatus::Failed
                };
                let mut text = format!(
                    "{} in {:.1}s",
                    outcome.status_label(),
                    outcome.duration.as_secs_f32()
                );
                let output = outcome.output.trim();
                if !output.is_empty() {
                    text.push_str(&format!("\n```\n{}\n```", tail(output, 60)));
                }
                vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                    id,
                    ToolCallUpdateFields::new()
                        .status(status)
                        .content(vec![ToolCallContent::from(text)]),
                ))]
            }
            Update::FixRound { round, max, check } => vec![thought(format!(
                "`{check}` failed; asking the agent to fix it (round {round}/{max})."
            ))],
            Update::ChecksGaveUp(outcome) => vec![message(format!(
                "\n\nCheck `{}` still fails after the fix rounds ({}).",
                outcome.check.name,
                outcome.status_label()
            ))],
            // A failed run (an unknown model, a provider error) must be seen:
            // as a notice or a thought a client may show it folded or not at all.
            Update::Notice(text) if text.starts_with("error: ") => vec![message(format!(
                "\n\nError: {}",
                text.trim_start_matches("error: ")
            ))],
            Update::Notice(text) if self.support.notices => {
                let (title, detail) = match text.split_once('\n') {
                    Some((title, detail)) => (title.trim(), Some(detail.trim().to_string())),
                    None => (text.trim(), None),
                };
                vec![SessionUpdate::Notice(
                    Notice::new(NoticeSeverity::Info, title).description(detail),
                )]
            }
            Update::Notice(text) => vec![thought(text.clone())],
            Update::SteerAccepted(text) => vec![thought(format!("Guidance added: {text}"))],
            Update::SteerRejected(text) => vec![thought(format!("Guidance not added: {text}"))],
            _ => Vec::new(),
        }
    }

    fn runtime(&mut self, event: &RuntimeEvent) -> Vec<SessionUpdate> {
        match event {
            RuntimeEvent::TextDelta { delta } if !delta.is_empty() => {
                self.streamed = true;
                vec![message(delta.clone())]
            }
            RuntimeEvent::ToolStart {
                call_id,
                name,
                input,
            } => {
                self.running.insert(name.clone(), call_id.clone());
                let mut locations = Vec::new();
                if let Some(path) = input.get("path").and_then(|v| v.as_str()) {
                    let abs = self.absolute(path);
                    if matches!(name.as_str(), "edit_file" | "write_file") {
                        self.track_edit(abs.clone(), call_id);
                    }
                    let mut location = ToolCallLocation::new(abs);
                    if let Some(line) = input
                        .get("offset")
                        .or_else(|| input.get("line"))
                        .and_then(|v| v.as_u64())
                    {
                        location = location.line(line as u32);
                    }
                    locations.push(location);
                }
                if name == "apply_patch"
                    && let Some(patch) = input
                        .get("patch")
                        .or_else(|| input.get("input"))
                        .and_then(|v| v.as_str())
                {
                    for path in patch_paths(patch) {
                        let abs = self.absolute(&path);
                        self.track_edit(abs.clone(), call_id);
                        locations.push(ToolCallLocation::new(abs));
                    }
                }
                let summary = crate::format::tool_summary(name, input);
                let title = if summary.is_empty() {
                    name.clone()
                } else if name == "bash" {
                    code_span(&summary)
                } else {
                    // Clients render titles as Markdown: `__init__.py` would turn bold.
                    format!("{name}: {}", code_span(&summary))
                };
                let mut call = ToolCall::new(call_id.clone(), title)
                    .kind(tool_kind(name))
                    .status(ToolCallStatus::InProgress)
                    .raw_input(input.clone());
                if !locations.is_empty() {
                    call = call.locations(locations);
                }
                vec![SessionUpdate::ToolCall(call)]
            }
            RuntimeEvent::ProcessOutput {
                call_id,
                command,
                output,
                exit_code,
                ..
            } => {
                self.rich.insert(call_id.clone());
                let mut text = format!("```console\n$ {command}\n{}\n```", output.trim_end());
                if let Some(code) = exit_code.filter(|c| *c != 0) {
                    text.push_str(&format!("\nexit code {code}"));
                }
                vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                    call_id.clone(),
                    ToolCallUpdateFields::new().content(vec![ToolCallContent::from(text)]),
                ))]
            }
            RuntimeEvent::FileDiff {
                path,
                diff,
                truncated,
                ..
            } => {
                let abs = self.absolute(path);
                let Some(call_id) = self
                    .by_path
                    .get(&abs)
                    .cloned()
                    .or_else(|| self.running.get("apply_patch").cloned())
                else {
                    return Vec::new();
                };
                // The text before the edit comes from undoing this edit's own
                // diff on the file as it is now, so it does not depend on when
                // this event is handled.
                let texts = read_small(&abs).filter(|_| !truncated).and_then(|new| {
                    let old = reverse_apply(&new, diff)?;
                    Some(((!old.is_empty()).then_some(old), new))
                });
                let content = match texts {
                    Some((old, new)) => {
                        ToolCallContent::from(Diff::new(abs.clone(), new).old_text(old))
                    }
                    // Deleted, too large, truncated or no longer matching:
                    // show the unified diff.
                    None => ToolCallContent::from(format!("{path}\n```diff\n{diff}\n```")),
                };
                self.rich.insert(call_id.clone());
                let list = self.diffs.entry(call_id.clone()).or_default();
                list.push(content);
                vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                    call_id,
                    ToolCallUpdateFields::new()
                        .content(list.clone())
                        .locations(vec![ToolCallLocation::new(abs)]),
                ))]
            }
            RuntimeEvent::ToolResult {
                call_id,
                is_error,
                preview,
                error_type,
                ..
            } => {
                if error_type.as_deref() == Some("approval_required") {
                    return Vec::new();
                }
                let status = if *is_error {
                    ToolCallStatus::Failed
                } else {
                    ToolCallStatus::Completed
                };
                let mut fields = ToolCallUpdateFields::new().status(status);
                if (*is_error || !self.rich.contains(call_id)) && !preview.trim().is_empty() {
                    let mut content = self.diffs.get(call_id).cloned().unwrap_or_default();
                    content.push(ToolCallContent::from(format!(
                        "```\n{}\n```",
                        tail(preview.trim_end(), 40)
                    )));
                    fields = fields.content(content);
                }
                vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                    call_id.clone(),
                    fields,
                ))]
            }
            RuntimeEvent::PlanUpdated { steps } => {
                let entries = steps
                    .iter()
                    .map(|step| {
                        let status = match step.status {
                            RuntimePlanStepStatus::Completed => PlanEntryStatus::Completed,
                            RuntimePlanStepStatus::InProgress => PlanEntryStatus::InProgress,
                            RuntimePlanStepStatus::Pending => PlanEntryStatus::Pending,
                        };
                        PlanEntry::new(step.title.clone(), PlanEntryPriority::Medium, status)
                    })
                    .collect();
                vec![SessionUpdate::Plan(Plan::new(entries))]
            }
            RuntimeEvent::SubagentStarted { run_id, label } => vec![SessionUpdate::ToolCall(
                ToolCall::new(format!("subagent-{run_id}"), format!("Sub-agent: {label}"))
                    .kind(ToolKind::Think)
                    .status(ToolCallStatus::InProgress),
            )],
            RuntimeEvent::SubagentFinished { run_id, status } => {
                let status = if status == "completed" {
                    ToolCallStatus::Completed
                } else {
                    ToolCallStatus::Failed
                };
                vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                    format!("subagent-{run_id}"),
                    ToolCallUpdateFields::new().status(status),
                ))]
            }
            RuntimeEvent::ContextCompacted {
                tokens_before,
                tokens_after,
                ..
            } if self.support.compaction => {
                self.compactions += 1;
                let summary = format!(
                    "Older messages were summarized ({tokens_before} → {tokens_after} tokens)."
                );
                vec![SessionUpdate::CompactionUpdate(
                    CompactionUpdate::new(
                        format!("compaction-{}", self.compactions),
                        CompactionStatus::Completed,
                    )
                    .summary(vec![ContentBlock::from(summary)]),
                )]
            }
            RuntimeEvent::ContextCompacted {
                tokens_before,
                tokens_after,
                ..
            } => vec![thought(format!(
                "Context compacted ({tokens_before} → {tokens_after} tokens)."
            ))],
            _ => Vec::new(),
        }
    }
}

/// The last `lines` lines of `text`.
fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    if all.len() <= lines {
        return text.to_string();
    }
    format!(
        "… {} earlier lines\n{}",
        all.len() - lines,
        all[all.len() - lines..].join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_sdk::RuntimeEventEnvelope;

    fn runtime(seq: u64, event: RuntimeEvent) -> Update {
        Update::Runtime(RuntimeEventEnvelope::new("r", seq, event))
    }

    /// A `FileDiff` event shaped like the engine's (`microclaw-core::diff`).
    fn file_diff(path: &str, old: &str, new: &str) -> Update {
        let diff = similar::TextDiff::from_lines(old, new);
        let mut lines = Vec::new();
        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            lines.push(hunk.header().to_string());
            for change in hunk.iter_changes() {
                let sign = match change.tag() {
                    similar::ChangeTag::Insert => "+",
                    similar::ChangeTag::Delete => "-",
                    similar::ChangeTag::Equal => " ",
                };
                let value = change.value();
                lines.push(format!(
                    "{sign}{}",
                    value.strip_suffix('\n').unwrap_or(value)
                ));
            }
        }
        runtime(
            9,
            RuntimeEvent::FileDiff {
                path: path.into(),
                diff: lines.join("\n"),
                added: 0,
                removed: 0,
                truncated: false,
            },
        )
    }

    fn only_diff(updates: &[SessionUpdate]) -> &Diff {
        let SessionUpdate::ToolCallUpdate(update) = &updates[0] else {
            panic!("expected an update")
        };
        let content = update.fields.content.as_ref().unwrap();
        let ToolCallContent::Diff(d) = content.last().unwrap() else {
            panic!("expected a diff, got {content:?}")
        };
        d
    }

    fn start_edit(mapper: &mut UpdateMapper, call_id: &str, path: &str) {
        mapper.map(&runtime(
            1,
            RuntimeEvent::ToolStart {
                call_id: call_id.into(),
                name: "edit_file".into(),
                input: serde_json::json!({"path": path}),
            },
        ));
    }

    #[test]
    fn diffs_do_not_depend_on_when_tool_start_is_handled() {
        // Zed showed an empty diff when ToolStart arrived after the edit had
        // already been written: the text "before" was read too late.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.py");
        let v0 = "import a\n\n\ndef f():\n    return 1\n\n\ndef g():\n    return 2\n";
        let v1 = v0.replace("import a", "import a, b");
        let v2 = v1.replace(
            "    return 2\n",
            "    return 2\n\n\ndef h():\n    return 3\n",
        );
        std::fs::write(&path, &v2).unwrap();
        let mut mapper = UpdateMapper::new(dir.path(), ClientSupport::default());
        // Both edits already happened when their events are handled.
        start_edit(&mut mapper, "c1", "t.py");
        let first = mapper.map(&file_diff("t.py", v0, &v1));
        let d = only_diff(&first);
        assert_eq!(d.new_text, v2);
        let old = d.old_text.as_deref().unwrap();
        assert_eq!(
            old,
            v2.replace("import a, b", "import a"),
            "only this edit differs"
        );
        start_edit(&mut mapper, "c2", "t.py");
        let second = mapper.map(&file_diff("t.py", &v1, &v2));
        assert_eq!(only_diff(&second).old_text.as_deref(), Some(v1.as_str()));
    }

    #[test]
    fn new_files_and_stale_diffs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("n.txt"), "hello\nworld\n").unwrap();
        let mut mapper = UpdateMapper::new(dir.path(), ClientSupport::default());
        start_edit(&mut mapper, "c1", "n.txt");
        let created = mapper.map(&file_diff("n.txt", "", "hello\nworld\n"));
        assert_eq!(
            only_diff(&created).old_text,
            None,
            "a new file has no old text"
        );
        // A diff that no longer matches the file falls back to the diff text.
        start_edit(&mut mapper, "c2", "n.txt");
        let stale = mapper.map(&file_diff("n.txt", "x\n", "y\n"));
        let SessionUpdate::ToolCallUpdate(update) = &stale[0] else {
            panic!("expected an update")
        };
        let content = update.fields.content.as_ref().unwrap();
        assert!(matches!(content.last(), Some(ToolCallContent::Content(_))));
    }

    #[test]
    fn edits_become_diffs_with_old_and_new_text() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "old\n").unwrap();
        let mut mapper = UpdateMapper::new(dir.path(), ClientSupport::default());
        let start = mapper.map(&runtime(
            1,
            RuntimeEvent::ToolStart {
                call_id: "c1".into(),
                name: "edit_file".into(),
                input: serde_json::json!({"path": "a.txt"}),
            },
        ));
        let SessionUpdate::ToolCall(call) = &start[0] else {
            panic!("expected a tool call")
        };
        assert_eq!(call.locations[0].path, dir.path().join("a.txt"));
        std::fs::write(dir.path().join("a.txt"), "new\n").unwrap();
        let diff = mapper.map(&file_diff("a.txt", "old\n", "new\n"));
        let SessionUpdate::ToolCallUpdate(update) = &diff[0] else {
            panic!("expected an update")
        };
        let content = update.fields.content.as_ref().unwrap();
        let ToolCallContent::Diff(d) = &content[0] else {
            panic!("expected a diff")
        };
        assert_eq!(d.old_text.as_deref(), Some("old\n"));
        assert_eq!(d.new_text, "new\n");
        // The result does not replace the diff with the preview.
        let done = mapper.map(&runtime(
            3,
            RuntimeEvent::ToolResult {
                call_id: "c1".into(),
                name: "edit_file".into(),
                is_error: false,
                preview: "edited".into(),
                duration_ms: 1,
                status_code: None,
                bytes: 0,
                error_type: None,
            },
        ));
        let SessionUpdate::ToolCallUpdate(update) = &done[0] else {
            panic!("expected an update")
        };
        assert!(update.fields.content.is_none());
    }

    #[test]
    fn notices_and_compactions_follow_client_support() {
        let mut plain = UpdateMapper::new("/repo", ClientSupport::default());
        assert!(matches!(
            plain.map(&Update::Notice("sandbox: off".into()))[..],
            [SessionUpdate::AgentThoughtChunk(_)]
        ));
        let mut rich = UpdateMapper::new(
            "/repo",
            ClientSupport {
                notices: true,
                compaction: true,
            },
        );
        assert!(matches!(
            rich.map(&Update::Notice("sandbox: off\ndetails".into()))[..],
            [SessionUpdate::Notice(_)]
        ));
        let compacted = runtime(
            1,
            RuntimeEvent::ContextCompacted {
                method: "summarized".into(),
                trigger: "auto".into(),
                tokens_before: 900,
                tokens_after: 100,
                messages_before: 40,
                messages_after: 5,
                duration_ms: 10,
            },
        );
        assert!(matches!(
            rich.map(&compacted)[..],
            [SessionUpdate::CompactionUpdate(_)]
        ));
        assert!(matches!(
            plain.map(&compacted)[..],
            [SessionUpdate::AgentThoughtChunk(_)]
        ));
    }

    #[test]
    fn streamed_text_is_not_repeated_and_checks_are_tool_calls() {
        let mut mapper = UpdateMapper::new("/repo", ClientSupport::default());
        assert!(matches!(
            mapper.map(&runtime(1, RuntimeEvent::TextDelta { delta: "hi".into() }))[..],
            [SessionUpdate::AgentMessageChunk(_)]
        ));
        let finished = Update::RunFinished {
            status: microclaw_sdk::RunStatus::Completed,
            final_text: "hi".into(),
            error: None,
        };
        assert!(mapper.map(&finished).is_empty());
        let check = microclaw_code_core::project::Check {
            name: "tests".into(),
            run: "cargo test".into(),
            auto: true,
            timeout_secs: None,
        };
        let started = mapper.map(&Update::CheckStarted(check));
        let [SessionUpdate::ToolCall(call)] = &started[..] else {
            panic!("{started:?}");
        };
        assert_eq!(call.title, "Check `tests`: `cargo test`");
        assert_eq!(
            patch_paths("*** Begin Patch\n*** Update File: src/a.rs\n@@\n*** Add File: b.rs\n"),
            vec!["src/a.rs", "b.rs"]
        );
    }

    #[test]
    fn run_errors_are_messages_whatever_the_client_supports() {
        for support in [
            ClientSupport::default(),
            ClientSupport {
                notices: true,
                compaction: true,
            },
        ] {
            let mut mapper = UpdateMapper::new("/repo", support);
            let out = mapper.map(&Update::Notice(
                "error: LLM API error: not_found_error: model: claude-sonnet".into(),
            ));
            let [SessionUpdate::AgentMessageChunk(chunk)] = &out[..] else {
                panic!("{out:?}");
            };
            let ContentBlock::Text(text) = &chunk.content else {
                panic!("{chunk:?}");
            };
            assert!(text.text.contains("Error: LLM API error"), "{}", text.text);
        }
    }

    #[test]
    fn tool_titles_are_code_spans() {
        let mut mapper = UpdateMapper::new("/repo", ClientSupport::default());
        let title = |out: Vec<SessionUpdate>| match &out[..] {
            [SessionUpdate::ToolCall(call)] => call.title.clone(),
            other => panic!("{other:?}"),
        };
        let read = mapper.map(&runtime(
            1,
            RuntimeEvent::ToolStart {
                call_id: "r".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path": "calc/__init__.py"}),
            },
        ));
        assert_eq!(title(read), "read_file: `calc/__init__.py`");
        assert_eq!(code_span("a `b` c"), "``a `b` c``");
        assert_eq!(code_span("`x"), "`` `x ``");
    }
}
