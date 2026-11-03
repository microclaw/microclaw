//! Terminal rendering of runtime events.

use std::io::{IsTerminal, Write};

use microclaw_sdk::{RuntimeApprovalOption, RuntimeEvent, RuntimePlanStepStatus};
use serde_json::Value;

/// ANSI styling that switches off for pipes and `NO_COLOR`.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn detect() -> Self {
        let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
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

fn truncate(text: &str, max: usize) -> String {
    let single_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() <= max {
        single_line
    } else {
        let cut: String = single_line.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// One-line summary of a tool call's input.
pub fn tool_summary(name: &str, input: &Value) -> String {
    let field = |key: &str| input.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let summary = match name {
        "bash" => {
            let mut s = field("command").to_string();
            if input.get("run_in_background").and_then(|v| v.as_bool()) == Some(true) {
                s.push_str("  (background)");
            }
            s
        }
        "read_file" | "write_file" | "edit_file" => {
            let mut s = field("path").to_string();
            if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
                s.push_str(&format!("  ({} edits)", edits.len()));
            }
            s
        }
        "grep" => {
            let path = field("path");
            if path.is_empty() {
                format!("/{}/", field("pattern"))
            } else {
                format!("/{}/ in {path}", field("pattern"))
            }
        }
        "glob" => field("pattern").to_string(),
        "bash_output" | "bash_kill" => field("id").to_string(),
        "web_fetch" => field("url").to_string(),
        "web_search" => field("query").to_string(),
        "sub_agent" | "sessions_spawn" => field("task").to_string(),
        _ => String::new(),
    };
    truncate(&summary, 110)
}

/// Renders a stream of events for one run and remembers what it saw.
pub struct Renderer {
    style: Style,
    at_line_start: bool,
    pub printed_text: bool,
    pub changed_files: Vec<String>,
    pub approval: Option<PendingApproval>,
    pub plan_presented: bool,
    /// Tool input by call id, kept to label results.
    pending_tools: std::collections::HashMap<String, String>,
}

/// An approval the agent is waiting for.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub tool: String,
    pub preview: Option<String>,
    pub options: Vec<RuntimeApprovalOption>,
    pub advisory: Option<String>,
}

impl Renderer {
    pub fn new(style: Style) -> Self {
        Self {
            style,
            at_line_start: true,
            printed_text: false,
            changed_files: Vec::new(),
            approval: None,
            plan_presented: false,
            pending_tools: Default::default(),
        }
    }

    fn line_break(&mut self, out: &mut impl Write) {
        if !self.at_line_start {
            let _ = writeln!(out);
            self.at_line_start = true;
        }
    }

    fn print_line(&mut self, out: &mut impl Write, line: &str) {
        self.line_break(out);
        let _ = writeln!(out, "{line}");
        self.at_line_start = true;
    }

    /// Print the final reply when no text was streamed (non-streaming
    /// providers) and end the line.
    pub fn finish(&mut self, out: &mut impl Write, final_text: &str) {
        if !self.printed_text && !final_text.trim().is_empty() {
            self.line_break(out);
            let _ = write!(out, "{}", final_text.trim_end());
            self.at_line_start = false;
        }
        self.line_break(out);
        let _ = out.flush();
    }

    pub fn event(&mut self, out: &mut impl Write, event: &RuntimeEvent) {
        let style = self.style;
        match event {
            RuntimeEvent::TextDelta { delta } => {
                if delta.is_empty() {
                    return;
                }
                let _ = write!(out, "{delta}");
                self.at_line_start = delta.ends_with('\n');
                self.printed_text = true;
            }
            RuntimeEvent::ToolStart {
                call_id,
                name,
                input,
            } => {
                let summary = tool_summary(name, input);
                self.pending_tools.insert(call_id.clone(), name.clone());
                let line = if summary.is_empty() {
                    format!("{} {}", style.cyan("●"), style.bold(name))
                } else {
                    format!("{} {} {}", style.cyan("●"), style.bold(name), summary)
                };
                self.print_line(out, &line);
            }
            RuntimeEvent::ToolResult {
                call_id,
                name,
                is_error,
                preview,
                duration_ms,
                error_type,
                ..
            } => {
                self.pending_tools.remove(call_id);
                if *is_error {
                    if error_type.as_deref() == Some("approval_required") {
                        return;
                    }
                    let first = preview.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                    let line = format!("  {} {}", style.red("✗"), truncate(first, 140));
                    self.print_line(out, &line);
                } else if matches!(name.as_str(), "bash" | "bash_output") {
                    let lines: Vec<&str> = preview.lines().collect();
                    let shown = lines.len().min(4);
                    let mut text = format!("  {} {}ms", style.green("✓"), duration_ms);
                    for line in &lines[lines.len() - shown..] {
                        text.push_str(&format!("\n    {}", style.dim(&truncate(line, 140))));
                    }
                    self.print_line(out, &text);
                }
            }
            RuntimeEvent::FileDiff {
                path,
                diff,
                added,
                removed,
                truncated,
            } => {
                if !self.changed_files.contains(path) {
                    self.changed_files.push(path.clone());
                }
                let header = format!(
                    "  {} {} {}",
                    style.bold(path),
                    style.green(&format!("+{added}")),
                    style.red(&format!("-{removed}"))
                );
                self.print_line(out, &header);
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
                    let _ = writeln!(out, "    {painted}");
                }
                if *truncated {
                    let _ = writeln!(out, "    {}", style.dim("… diff truncated"));
                }
            }
            RuntimeEvent::PlanUpdated { steps } => {
                let mut text = style.bold("Plan");
                for step in steps {
                    let mark = match step.status {
                        RuntimePlanStepStatus::Completed => style.green("[x]"),
                        RuntimePlanStepStatus::InProgress => style.yellow("[~]"),
                        RuntimePlanStepStatus::Pending => "[ ]".to_string(),
                    };
                    text.push_str(&format!("\n  {mark} {}", step.title));
                }
                self.plan_presented = true;
                self.print_line(out, &text);
            }
            RuntimeEvent::ApprovalRequired {
                tool,
                preview,
                options,
                advisory,
                ..
            } => {
                self.approval = Some(PendingApproval {
                    tool: tool.clone(),
                    preview: preview.clone(),
                    options: options.clone(),
                    advisory: advisory.clone(),
                });
            }
            RuntimeEvent::SubagentStarted { label, .. } => {
                let line = style.dim(&format!("  ↳ sub-agent started: {label}"));
                self.print_line(out, &line);
            }
            RuntimeEvent::SubagentFinished { status, .. } => {
                let line = style.dim(&format!("  ↳ sub-agent {status}"));
                self.print_line(out, &line);
            }
            RuntimeEvent::CheckpointCreated { commit, .. } => {
                let short: String = commit.chars().take(8).collect();
                let line = style.dim(&format!("  checkpoint {short}"));
                self.print_line(out, &line);
            }
            RuntimeEvent::Cancelled { .. } => {
                let line = style.yellow("(cancelled)");
                self.print_line(out, &line);
            }
            _ => {}
        }
        let _ = out.flush();
    }
}

/// Render the approval card and return the text shown to the user.
pub fn approval_card(style: Style, approval: &PendingApproval) -> String {
    let mut text = format!("{} {}", style.yellow("?"), style.bold(&format!("Allow {}?", approval.tool)));
    if let Some(preview) = &approval.preview {
        for line in preview.lines().take(12) {
            text.push_str(&format!("\n    {}", line));
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summarizes_common_tools() {
        assert_eq!(tool_summary("bash", &json!({"command": "cargo   test\n-q"})), "cargo test -q");
        assert_eq!(
            tool_summary("edit_file", &json!({"path": "a.rs", "edits": [{}, {}]})),
            "a.rs (2 edits)"
        );
        assert_eq!(tool_summary("grep", &json!({"pattern": "fn main"})), "/fn main/");
        assert!(tool_summary("bash", &json!({"command": "x".repeat(300)})).ends_with('…'));
    }

    #[test]
    fn records_diffs_and_approvals() {
        let mut renderer = Renderer::new(Style::plain());
        let mut out = Vec::new();
        renderer.event(
            &mut out,
            &RuntimeEvent::FileDiff {
                path: "src/lib.rs".into(),
                diff: "@@ -1 +1 @@\n-a\n+b\n".into(),
                added: 1,
                removed: 1,
                truncated: false,
            },
        );
        renderer.event(
            &mut out,
            &RuntimeEvent::TextDelta {
                delta: "done".into(),
            },
        );
        renderer.event(
            &mut out,
            &RuntimeEvent::ApprovalRequired {
                approval_id: "a".into(),
                tool: "bash".into(),
                preview: Some("rm -rf build".into()),
                options: vec![],
                advisory: None,
            },
        );
        renderer.finish(&mut out, "done");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("src/lib.rs +1 -1"));
        assert!(text.contains("+b"));
        assert!(text.ends_with("done\n"));
        assert_eq!(renderer.changed_files, vec!["src/lib.rs"]);
        assert_eq!(renderer.approval.unwrap().tool, "bash");
    }
}
