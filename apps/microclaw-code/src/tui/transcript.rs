//! The conversation transcript: driver updates folded into display items,
//! rendered to wrapped terminal lines.

use std::time::Duration;

use microclaw_code_core::driver::Update;
use microclaw_code_core::verify::CheckOutcome;
use microclaw_sdk::{RuntimeEvent, RuntimePlanStepStatus};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthChar;

use crate::format::{elapsed, tool_summary, truncate};

/// Lines of command output kept under a finished `bash` call.
const TOOL_OUTPUT_LINES: usize = 4;
/// Diff lines shown per file change.
const DIFF_LINES: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolState {
    Running,
    WaitingForApproval,
    Done { duration_ms: u64 },
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckState {
    Running,
    Passed(Duration),
    Failed { label: String, duration: Duration },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    User(String),
    Steer(String),
    Assistant(String),
    Tool {
        call_id: String,
        name: String,
        summary: String,
        state: ToolState,
        output: Vec<String>,
    },
    Diff {
        path: String,
        added: usize,
        removed: usize,
        lines: Vec<String>,
        truncated: bool,
    },
    Plan(Vec<(RuntimePlanStepStatus, String)>),
    Check {
        name: String,
        run: String,
        state: CheckState,
    },
    Notice(String, Tone),
}

/// Transcript plus the bookkeeping needed to fold streaming updates.
#[derive(Debug, Default)]
pub struct Transcript {
    pub items: Vec<Item>,
    /// Assistant text was streamed during the current run.
    streamed: bool,
    /// The current run stopped for an approval that was not answered in-run
    /// (its final text is the approval prompt, shown as a dialog instead).
    approval_in_run: bool,
}

impl Transcript {
    pub fn push(&mut self, item: Item) {
        self.items.push(item);
    }

    pub fn notice(&mut self, text: impl Into<String>, tone: Tone) {
        self.items.push(Item::Notice(text.into(), tone));
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    fn push_assistant_text(&mut self, delta: &str) {
        if let Some(Item::Assistant(text)) = self.items.last_mut() {
            text.push_str(delta);
        } else {
            self.items.push(Item::Assistant(delta.to_string()));
        }
    }

    /// Fold one driver update into the transcript.
    pub fn apply(&mut self, update: &Update) {
        match update {
            Update::Runtime(envelope) => self.apply_event(&envelope.event),
            Update::RunFinished {
                final_text, error, ..
            } => {
                if !self.streamed && !self.approval_in_run && !final_text.trim().is_empty() {
                    self.items
                        .push(Item::Assistant(final_text.trim_end().to_string()));
                }
                if let Some(error) = error {
                    self.notice(format!("error: {error}"), Tone::Error);
                }
                self.streamed = false;
                self.approval_in_run = false;
            }
            Update::SteerAccepted(_) => {}
            Update::SteerRejected(reason) => {
                self.notice(format!("guidance not delivered: {reason}"), Tone::Warning)
            }
            Update::ApprovalRequested(_) => {}
            // The run continues after an in-run answer, so its final text is
            // a real reply again (the TUI already noted the chosen option).
            Update::ApprovalAnswered { .. } => self.approval_in_run = false,
            Update::AutoApproved { tool, rule } => {
                self.approval_in_run = false;
                match rule {
                    Some(rule) if rule == microclaw_code_core::driver::SANDBOX_RULE => self.notice(
                        format!("auto-approved {tool}: runs in the sandbox without network"),
                        Tone::Info,
                    ),
                    Some(rule) => self.notice(
                        format!("auto-approved {tool}: allowed by rule `{rule}`"),
                        Tone::Info,
                    ),
                    None => self.notice(format!("auto-approved {tool} (auto mode)"), Tone::Info),
                }
            }
            Update::CheckStarted(check) => self.items.push(Item::Check {
                name: check.name.clone(),
                run: check.run.clone(),
                state: CheckState::Running,
            }),
            Update::CheckFinished(outcome) => self.finish_check(outcome),
            Update::FixRound { round, max, check } => self.notice(
                format!("`{check}` failed; handing it back to the agent (round {round}/{max})"),
                Tone::Warning,
            ),
            Update::ChecksGaveUp(outcome) => {
                let tail = microclaw_code_core::verify::tail(outcome.output.trim_end(), 1_500);
                self.notice(
                    format!(
                        "Check `{}` still fails; over to you.\n{tail}",
                        outcome.check.name
                    ),
                    Tone::Error,
                );
            }
            Update::Notice(text) => self.notice(text.clone(), Tone::Info),
        }
    }

    fn finish_check(&mut self, outcome: &CheckOutcome) {
        let state = if outcome.success {
            CheckState::Passed(outcome.duration)
        } else {
            CheckState::Failed {
                label: outcome.status_label(),
                duration: outcome.duration,
            }
        };
        let running = self.items.iter_mut().rev().find(|i| {
            matches!(
                i,
                Item::Check {
                    state: CheckState::Running,
                    ..
                }
            )
        });
        if let Some(Item::Check { state: s, name, .. }) = running
            && *name == outcome.check.name
        {
            *s = state;
            return;
        }
        self.items.push(Item::Check {
            name: outcome.check.name.clone(),
            run: outcome.check.run.clone(),
            state,
        });
    }

    fn apply_event(&mut self, event: &RuntimeEvent) {
        match event {
            RuntimeEvent::TextDelta { delta } if !delta.is_empty() => {
                self.streamed = true;
                self.push_assistant_text(delta);
            }
            RuntimeEvent::ToolStart {
                call_id,
                name,
                input,
            } => self.items.push(Item::Tool {
                call_id: call_id.clone(),
                name: name.clone(),
                summary: tool_summary(name, input),
                state: ToolState::Running,
                output: Vec::new(),
            }),
            RuntimeEvent::ToolResult {
                call_id,
                is_error,
                preview,
                duration_ms,
                error_type,
                ..
            } => {
                let Some(Item::Tool {
                    state,
                    output,
                    name,
                    ..
                }) = self
                    .items
                    .iter_mut()
                    .rev()
                    .find(|i| matches!(i, Item::Tool { call_id: id, .. } if id == call_id))
                else {
                    return;
                };
                if *is_error {
                    if error_type.as_deref() == Some("approval_required") {
                        *state = ToolState::WaitingForApproval;
                        return;
                    }
                    let first = preview.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                    *state = ToolState::Failed {
                        message: truncate(first, 160),
                    };
                } else {
                    *state = ToolState::Done {
                        duration_ms: *duration_ms,
                    };
                    if matches!(name.as_str(), "bash" | "bash_output") {
                        let lines: Vec<&str> = preview.lines().collect();
                        let start = lines.len().saturating_sub(TOOL_OUTPUT_LINES);
                        *output = lines[start..].iter().map(|l| truncate(l, 200)).collect();
                    }
                }
            }
            RuntimeEvent::FileDiff {
                path,
                diff,
                added,
                removed,
                truncated,
            } => {
                let all: Vec<String> = diff
                    .lines()
                    .filter(|l| !l.starts_with("+++") && !l.starts_with("---"))
                    .map(str::to_string)
                    .collect();
                let cut = all.len() > DIFF_LINES;
                self.items.push(Item::Diff {
                    path: path.clone(),
                    added: *added,
                    removed: *removed,
                    lines: all.into_iter().take(DIFF_LINES).collect(),
                    truncated: *truncated || cut,
                });
            }
            RuntimeEvent::PlanUpdated { steps } => {
                let plan = steps.iter().map(|s| (s.status, s.title.clone())).collect();
                if let Some(Item::Plan(existing)) = self.items.last_mut() {
                    *existing = plan;
                } else {
                    self.items.push(Item::Plan(plan));
                }
            }
            RuntimeEvent::ApprovalRequired { .. } => self.approval_in_run = true,
            RuntimeEvent::SubagentStarted { label, .. } => {
                self.notice(format!("sub-agent started: {label}"), Tone::Info)
            }
            RuntimeEvent::SubagentFinished { status, .. } => {
                self.notice(format!("sub-agent {status}"), Tone::Info)
            }
            _ => {}
        }
    }

    /// Render all items to lines that fit `width` columns.
    pub fn lines(&self, width: u16) -> Vec<Line<'static>> {
        let width = width.max(10) as usize;
        let mut out = Vec::new();
        for item in &self.items {
            render_item(item, width, &mut out);
        }
        out
    }
}

fn style(color: Color) -> Style {
    Style::default().fg(color)
}

fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

fn render_item(item: &Item, width: usize, out: &mut Vec<Line<'static>>) {
    match item {
        Item::User(text) => {
            out.push(Line::default());
            for (i, line) in text.lines().enumerate() {
                let prefix = if i == 0 { "› " } else { "  " };
                wrap_into(
                    out,
                    vec![
                        Span::styled(prefix, style(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Span::styled(
                            line.to_string(),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                    ],
                    width,
                    2,
                );
            }
        }
        Item::Steer(text) => wrap_into(
            out,
            vec![
                Span::styled("↪ ", style(Color::Cyan)),
                Span::styled(text.clone(), dim()),
            ],
            width,
            2,
        ),
        Item::Assistant(text) => {
            out.push(Line::default());
            let mut in_code = false;
            for line in text.lines() {
                if line.trim_start().starts_with("```") {
                    in_code = !in_code;
                    out.push(Line::from(Span::styled(line.to_string(), dim())));
                    continue;
                }
                let span = if in_code {
                    Span::styled(line.to_string(), style(Color::Yellow))
                } else if line.starts_with('#') {
                    Span::styled(
                        line.to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw(line.to_string())
                };
                wrap_into(out, vec![span], width, 0);
            }
        }
        Item::Tool {
            name,
            summary,
            state,
            output,
            ..
        } => {
            let (mark, mark_style) = match state {
                ToolState::Running => ("● ", style(Color::Cyan)),
                ToolState::WaitingForApproval => ("● ", style(Color::Yellow)),
                ToolState::Done { .. } => ("● ", style(Color::Green)),
                ToolState::Failed { .. } => ("● ", style(Color::Red)),
            };
            let mut spans = vec![
                Span::styled(mark, mark_style),
                Span::styled(name.clone(), Style::default().add_modifier(Modifier::BOLD)),
            ];
            if !summary.is_empty() {
                spans.push(Span::raw(format!(" {summary}")));
            }
            match state {
                ToolState::Done { duration_ms } => {
                    spans.push(Span::styled(format!("  {duration_ms}ms"), dim()));
                }
                ToolState::WaitingForApproval => {
                    spans.push(Span::styled("  waiting for approval", style(Color::Yellow)));
                }
                _ => {}
            }
            wrap_into(out, spans, width, 2);
            if let ToolState::Failed { message } = state {
                wrap_into(
                    out,
                    vec![
                        Span::raw("  "),
                        Span::styled(format!("✗ {message}"), style(Color::Red)),
                    ],
                    width,
                    4,
                );
            }
            for line in output {
                wrap_into(
                    out,
                    vec![Span::raw("    "), Span::styled(line.clone(), dim())],
                    width,
                    4,
                );
            }
        }
        Item::Diff {
            path,
            added,
            removed,
            lines,
            truncated,
        } => {
            out.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(path.clone(), Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(format!(" +{added}"), style(Color::Green)),
                Span::styled(format!(" -{removed}"), style(Color::Red)),
            ]));
            for line in lines {
                let s = if line.starts_with('+') {
                    style(Color::Green)
                } else if line.starts_with('-') {
                    style(Color::Red)
                } else if line.starts_with("@@") {
                    style(Color::Cyan)
                } else {
                    dim()
                };
                wrap_into(
                    out,
                    vec![Span::raw("    "), Span::styled(line.clone(), s)],
                    width,
                    4,
                );
            }
            if *truncated {
                out.push(Line::from(Span::styled("    … diff truncated", dim())));
            }
        }
        Item::Plan(steps) => {
            out.push(Line::from(Span::styled(
                "  Plan",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for (status, title) in steps {
                let (mark, s) = match status {
                    RuntimePlanStepStatus::Completed => ("[x] ", style(Color::Green)),
                    RuntimePlanStepStatus::InProgress => ("[~] ", style(Color::Yellow)),
                    RuntimePlanStepStatus::Pending => ("[ ] ", Style::default()),
                };
                wrap_into(
                    out,
                    vec![
                        Span::raw("    "),
                        Span::styled(mark, s),
                        Span::raw(title.clone()),
                    ],
                    width,
                    8,
                );
            }
        }
        Item::Check { name, run, state } => {
            let (label, s) = match state {
                CheckState::Running => ("running…".to_string(), style(Color::Cyan)),
                CheckState::Passed(d) => (format!("passed {}", elapsed(*d)), style(Color::Green)),
                CheckState::Failed { label, duration } => {
                    (format!("{label} {}", elapsed(*duration)), style(Color::Red))
                }
            };
            wrap_into(
                out,
                vec![
                    Span::styled("▸ ", style(Color::Cyan)),
                    Span::styled(name.clone(), Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(format!(" {run}  "), dim()),
                    Span::styled(label, s),
                ],
                width,
                2,
            );
        }
        Item::Notice(text, tone) => {
            let s = match tone {
                Tone::Info => dim(),
                Tone::Success => style(Color::Green),
                Tone::Warning => style(Color::Yellow),
                Tone::Error => style(Color::Red),
            };
            for line in text.lines() {
                wrap_into(
                    out,
                    vec![Span::raw("  "), Span::styled(line.to_string(), s)],
                    width,
                    2,
                );
            }
        }
    }
}

/// Wrap styled spans to `width` columns; continuation lines are indented by
/// `indent` columns.
pub fn wrap_into(
    out: &mut Vec<Line<'static>>,
    spans: Vec<Span<'static>>,
    width: usize,
    indent: usize,
) {
    let indent = indent.min(width.saturating_sub(1));
    let mut current: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    for span in spans {
        let mut buffer = String::new();
        for ch in span.content.chars() {
            let w = ch.width().unwrap_or(0);
            if used + w > width && used > indent {
                if !buffer.is_empty() {
                    current.push(Span::styled(std::mem::take(&mut buffer), span.style));
                }
                out.push(Line::from(std::mem::take(&mut current)));
                current.push(Span::raw(" ".repeat(indent)));
                used = indent;
            }
            buffer.push(ch);
            used += w;
        }
        if !buffer.is_empty() {
            current.push(Span::styled(buffer, span.style));
        }
    }
    out.push(Line::from(current));
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_sdk::RuntimeEventEnvelope;

    fn runtime(seq: u64, event: RuntimeEvent) -> Update {
        Update::Runtime(RuntimeEventEnvelope::new("r", seq, event))
    }

    fn text(lines: &[Line]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn folds_streaming_text_tools_and_diffs() {
        let mut t = Transcript::default();
        t.apply(&runtime(
            0,
            RuntimeEvent::TextDelta {
                delta: "Hel".into(),
            },
        ));
        t.apply(&runtime(1, RuntimeEvent::TextDelta { delta: "lo".into() }));
        t.apply(&runtime(
            2,
            RuntimeEvent::ToolStart {
                call_id: "c1".into(),
                name: "bash".into(),
                input: serde_json::json!({"command": "cargo test"}),
            },
        ));
        t.apply(&runtime(
            3,
            RuntimeEvent::ToolResult {
                call_id: "c1".into(),
                name: "bash".into(),
                is_error: false,
                preview: "a\nb\nc\nd\ntest result: ok".into(),
                duration_ms: 12,
                status_code: Some(0),
                bytes: 0,
                error_type: None,
            },
        ));
        t.apply(&runtime(
            4,
            RuntimeEvent::FileDiff {
                path: "src/lib.rs".into(),
                diff: "--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y".into(),
                added: 1,
                removed: 1,
                truncated: false,
            },
        ));
        t.apply(&Update::RunFinished {
            status: microclaw_sdk::RunStatus::Completed,
            final_text: "Hello".into(),
            error: None,
        });
        assert_eq!(t.items[0], Item::Assistant("Hello".into()));
        let rendered = text(&t.lines(80));
        assert!(rendered.contains("● bash cargo test  12ms"));
        assert!(rendered.contains("test result: ok"));
        assert!(
            !rendered.contains("    a\n"),
            "only the output tail is kept"
        );
        assert!(rendered.contains("src/lib.rs +1 -1"));
        assert!(rendered.contains("    +y"));
        assert_eq!(
            rendered.matches("Hello").count(),
            1,
            "streamed text is not repeated"
        );
    }

    #[test]
    fn approval_prompt_text_is_not_shown_as_a_reply() {
        let mut t = Transcript::default();
        t.apply(&runtime(
            0,
            RuntimeEvent::ApprovalRequired {
                approval_id: "a".into(),
                tool: "bash".into(),
                preview: None,
                options: vec![],
                advisory: None,
            },
        ));
        t.apply(&Update::RunFinished {
            status: microclaw_sdk::RunStatus::Completed,
            final_text: "Approve? 1/2/3".into(),
            error: None,
        });
        assert!(t.items.is_empty());
    }

    #[test]
    fn wraps_to_width_with_indent() {
        let mut out = Vec::new();
        wrap_into(&mut out, vec![Span::raw("abcdefghij")], 4, 2);
        assert_eq!(text(&out), "abcd\n  ef\n  gh\n  ij");
        let mut wide = Vec::new();
        wrap_into(&mut wide, vec![Span::raw("你好世界")], 5, 0);
        assert_eq!(text(&wide), "你好\n世界");
    }
}
