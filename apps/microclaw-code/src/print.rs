//! Line-oriented output for `mccode -p` (and `--json`): renders driver
//! updates to stdout/stderr instead of the full-screen TUI.

use std::io::{IsTerminal, Write};

use microclaw_code_core::driver::{PendingApproval, Update};
use microclaw_sdk::{RuntimeEvent, RuntimePlanStepStatus};

use crate::format::{elapsed, tool_summary, truncate};

/// ANSI styling that switches off for pipes and `NO_COLOR`.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn detect() -> Self {
        let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        Self { color }
    }

    #[cfg(test)]
    pub fn plain() -> Self {
        Self { color: false }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }
    pub fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }
    pub fn red(&self, text: &str) -> String {
        self.paint("31", text)
    }
    pub fn green(&self, text: &str) -> String {
        self.paint("32", text)
    }
    pub fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
    }
    pub fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }
}

/// Render the approval card.
pub fn approval_card(style: Style, approval: &PendingApproval) -> String {
    let mut text = format!(
        "{} {}",
        style.yellow("?"),
        style.bold(&format!("Allow {}?", approval.tool))
    );
    if let Some(preview) = &approval.preview {
        for line in preview.lines().take(12) {
            text.push_str(&format!("\n    {line}"));
        }
    }
    if let Some(advisory) = &approval.advisory {
        text.push_str(&format!("\n  {}", style.dim(advisory)));
    }
    for option in &approval.options {
        text.push_str(&format!("\n  {}) {}", option.value, option.label));
    }
    text
}

/// Prints driver updates. Assistant text goes to stdout (so `-p` output can
/// be piped); progress, tools, diffs and checks go to stderr.
pub struct Printer {
    style: Style,
    json: bool,
    at_line_start: bool,
    streamed_text: bool,
    /// The run stopped for an approval; its final text is the approval
    /// prompt, which is printed as a card instead.
    approval_in_run: bool,
}

impl Printer {
    pub fn new(style: Style, json: bool) -> Self {
        Self {
            style,
            json,
            at_line_start: true,
            streamed_text: false,
            approval_in_run: false,
        }
    }

    fn end_text(&mut self, out: &mut impl Write) {
        if !self.at_line_start {
            let _ = writeln!(out);
            self.at_line_start = true;
        }
    }

    pub fn update(&mut self, update: &Update, out: &mut impl Write, err: &mut impl Write) {
        let style = self.style;
        if self.json {
            if let Update::Runtime(envelope) = update
                && let Ok(line) = serde_json::to_string(envelope)
            {
                let _ = writeln!(out, "{line}");
            }
            return;
        }
        match update {
            Update::Runtime(envelope) => match &envelope.event {
                RuntimeEvent::TextDelta { delta } if !delta.is_empty() => {
                    let _ = write!(out, "{delta}");
                    let _ = out.flush();
                    self.at_line_start = delta.ends_with('\n');
                    self.streamed_text = true;
                }
                RuntimeEvent::ToolStart { name, input, .. } => {
                    self.end_text(out);
                    let summary = tool_summary(name, input);
                    let _ = writeln!(err, "{} {} {}", style.cyan("●"), style.bold(name), summary);
                }
                RuntimeEvent::ToolResult {
                    is_error,
                    preview,
                    error_type,
                    ..
                } if *is_error && error_type.as_deref() != Some("approval_required") => {
                    let first = preview.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                    let _ = writeln!(err, "  {} {}", style.red("✗"), truncate(first, 140));
                }
                RuntimeEvent::FileDiff {
                    path,
                    diff,
                    added,
                    removed,
                    truncated,
                } => {
                    let _ = writeln!(
                        err,
                        "  {} {} {}",
                        style.bold(path),
                        style.green(&format!("+{added}")),
                        style.red(&format!("-{removed}"))
                    );
                    for line in diff.lines() {
                        let painted = if line.starts_with("+++") || line.starts_with("---") {
                            style.dim(line)
                        } else if line.starts_with('+') {
                            style.green(line)
                        } else if line.starts_with('-') {
                            style.red(line)
                        } else if line.starts_with("@@") {
                            style.cyan(line)
                        } else {
                            style.dim(line)
                        };
                        let _ = writeln!(err, "    {painted}");
                    }
                    if *truncated {
                        let _ = writeln!(err, "    {}", style.dim("… diff truncated"));
                    }
                }
                RuntimeEvent::ApprovalRequired { .. } => self.approval_in_run = true,
                RuntimeEvent::PlanUpdated { steps } => {
                    let _ = writeln!(err, "{}", style.bold("Plan"));
                    for step in steps {
                        let mark = match step.status {
                            RuntimePlanStepStatus::Completed => "[x]",
                            RuntimePlanStepStatus::InProgress => "[~]",
                            RuntimePlanStepStatus::Pending => "[ ]",
                        };
                        let _ = writeln!(err, "  {mark} {}", step.title);
                    }
                }
                _ => {}
            },
            Update::RunFinished {
                final_text, error, ..
            } => {
                if !self.streamed_text && !self.approval_in_run && !final_text.trim().is_empty() {
                    let _ = write!(out, "{}", final_text.trim_end());
                    self.at_line_start = false;
                }
                self.end_text(out);
                let _ = out.flush();
                self.streamed_text = false;
                self.approval_in_run = false;
                if let Some(error) = error {
                    let _ = writeln!(err, "{} {error}", style.red("error:"));
                }
            }
            Update::AutoApproved { tool, rule } => {
                self.approval_in_run = false;
                let why = match rule {
                    Some(rule) if rule == microclaw_code_core::driver::SANDBOX_RULE => {
                        "runs in the sandbox without network".to_string()
                    }
                    Some(rule) => format!("allowed by rule `{rule}`"),
                    None => "auto mode".to_string(),
                };
                let _ = writeln!(
                    err,
                    "{}",
                    style.dim(&format!("  auto-approved {tool} ({why})"))
                );
            }
            Update::ApprovalAnswered {
                tool,
                label,
                denied,
            } => {
                self.approval_in_run = false;
                let text = format!("  {tool}: {label}");
                let painted = if *denied {
                    style.yellow(&text)
                } else {
                    style.dim(&text)
                };
                let _ = writeln!(err, "{painted}");
            }
            Update::ApprovalRequested(approval) => {
                let _ = writeln!(err, "{}", approval_card(style, approval));
            }
            Update::CheckStarted(check) => {
                let _ = writeln!(
                    err,
                    "{} {} {}",
                    style.cyan("▸"),
                    style.bold(&check.name),
                    style.dim(&check.run)
                );
            }
            Update::CheckFinished(outcome) => {
                let label = outcome.status_label();
                let painted = if outcome.success {
                    style.green(&label)
                } else {
                    style.red(&label)
                };
                let _ = writeln!(err, "  {painted} {}", style.dim(&elapsed(outcome.duration)));
            }
            Update::FixRound { round, max, check } => {
                let _ = writeln!(
                    err,
                    "{}",
                    style.dim(&format!(
                        "  `{check}` failed; handing it back to the agent (round {round}/{max})"
                    ))
                );
            }
            Update::ChecksGaveUp(outcome) => {
                let _ = writeln!(
                    err,
                    "{}",
                    style.yellow(&format!(
                        "Check `{}` still fails; over to you.",
                        outcome.check.name
                    ))
                );
                for line in
                    microclaw_code_core::verify::tail(outcome.output.trim_end(), 2_000).lines()
                {
                    let _ = writeln!(err, "    {}", style.dim(line));
                }
            }
            Update::SteerAccepted(_) | Update::SteerRejected(_) => {}
            Update::Notice(text) => {
                let _ = writeln!(err, "{}", style.dim(text));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_sdk::RuntimeEventEnvelope;

    #[test]
    fn prints_text_to_stdout_and_progress_to_stderr() {
        let mut printer = Printer::new(Style::plain(), false);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        printer.update(
            &Update::Runtime(RuntimeEventEnvelope::new(
                "r",
                0,
                RuntimeEvent::ToolStart {
                    call_id: "c".into(),
                    name: "bash".into(),
                    input: serde_json::json!({"command": "ls"}),
                },
            )),
            &mut out,
            &mut err,
        );
        printer.update(
            &Update::Runtime(RuntimeEventEnvelope::new(
                "r",
                1,
                RuntimeEvent::TextDelta {
                    delta: "done".into(),
                },
            )),
            &mut out,
            &mut err,
        );
        printer.update(
            &Update::RunFinished {
                status: microclaw_sdk::RunStatus::Completed,
                final_text: "done".into(),
                error: None,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(String::from_utf8(out).unwrap(), "done\n");
        assert!(String::from_utf8(err).unwrap().contains("● bash ls"));
    }

    #[test]
    fn json_mode_prints_only_envelopes() {
        let mut printer = Printer::new(Style::plain(), true);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        printer.update(
            &Update::Runtime(RuntimeEventEnvelope::new(
                "r",
                0,
                RuntimeEvent::TextDelta { delta: "x".into() },
            )),
            &mut out,
            &mut err,
        );
        printer.update(&Update::Notice("n".into()), &mut out, &mut err);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"type\":\"text_delta\""));
        assert!(err.is_empty());
    }
}
