//! The conversation transcript: driver updates folded into display items,
//! rendered to wrapped, themed terminal lines.
//!
//! Rendering is cached per item and width; only items that changed (the
//! streaming reply, a running tool) are re-rendered on a frame, so long
//! sessions stay cheap to draw.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use microclaw_code_core::driver::Update;
use microclaw_code_core::settings::DiffStyle;
use microclaw_code_core::verify::CheckOutcome;
use microclaw_sdk::{RuntimeEvent, RuntimePlanStepStatus};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::format::{elapsed, tool_summary, truncate};
use crate::ui::theme::Theme;

/// Output lines shown under a collapsed `bash` call.
const TOOL_OUTPUT_LINES: usize = 4;
/// Output lines kept for an expanded call.
const TOOL_OUTPUT_KEEP: usize = 400;
/// Diff lines shown collapsed / expanded.
const DIFF_LINES: usize = 40;
const DIFF_LINES_EXPANDED: usize = 2_000;

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Tools that only look at the workspace; consecutive calls are grouped.
fn is_explore_tool(name: &str) -> bool {
    matches!(name, "read_file" | "glob" | "grep" | "list_dir" | "ls")
}

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
pub struct ToolCall {
    pub call_id: String,
    pub name: String,
    pub summary: String,
    pub state: ToolState,
    pub output: Vec<String>,
}

/// End-of-turn summary card.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Receipt {
    pub files: Vec<(String, usize, usize)>,
    pub checks: Vec<(String, bool)>,
    pub sandbox: Option<String>,
    pub network: bool,
    pub domains: Vec<String>,
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub cost: Option<f64>,
    pub checkpoint: Option<String>,
    pub duration: Duration,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    User(String),
    Steer(String),
    Assistant(String),
    Tool(ToolCall),
    /// Consecutive read/search calls shown as one line.
    Explore(Vec<ToolCall>),
    Diff {
        path: String,
        added: usize,
        removed: usize,
        diff: String,
        truncated: bool,
    },
    Plan(Vec<(RuntimePlanStepStatus, String)>),
    Check {
        name: String,
        run: String,
        state: CheckState,
    },
    Notice(String, Tone),
    Receipt(Receipt),
    /// A `!command` the user ran.
    Shell {
        command: String,
        output: Vec<String>,
        exit: Option<i32>,
        running: bool,
    },
    /// `/btw` side question and its answer.
    Side {
        question: String,
        answer: Option<String>,
    },
}

impl Item {
    /// The item animates (spinner) and must be re-rendered every frame.
    fn is_live(&self) -> bool {
        match self {
            Item::Tool(t) => t.state == ToolState::Running,
            Item::Explore(calls) => calls.iter().any(|c| c.state == ToolState::Running),
            Item::Check { state, .. } => *state == CheckState::Running,
            Item::Shell { running, .. } => *running,
            Item::Side { answer, .. } => answer.is_none(),
            _ => false,
        }
    }

    /// The item has hidden detail that Ctrl+O / a click reveals.
    pub fn expandable(&self) -> bool {
        matches!(
            self,
            Item::Tool(_) | Item::Explore(_) | Item::Diff { .. } | Item::Shell { .. }
        )
    }
}

/// Per-turn tallies for the receipt.
#[derive(Debug, Default)]
struct TurnTally {
    started: Option<Instant>,
    files: BTreeMap<String, (usize, usize)>,
    checks: BTreeMap<String, bool>,
    domains: Vec<String>,
    checkpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct Cached {
    width: u16,
    generation: u64,
    expanded: bool,
    lines: Vec<Line<'static>>,
}

/// Rendering options that apply to every item.
#[derive(Debug, Clone)]
pub struct RenderOptions {
    pub diff_style: DiffStyle,
    /// Show all tool output and full diffs.
    pub expand_all: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            diff_style: DiffStyle::Auto,
            expand_all: false,
        }
    }
}

/// Transcript plus the bookkeeping needed to fold streaming updates.
#[derive(Debug, Default)]
pub struct Transcript {
    pub items: Vec<Item>,
    /// Items expanded individually (by click).
    expanded: Vec<bool>,
    cache: Vec<Option<Cached>>,
    /// Bumped when the theme or options change (invalidates every cache).
    generation: u64,
    /// Assistant text was streamed during the current run.
    streamed: bool,
    /// The current run stopped for an approval that was not answered in-run
    /// (its final text is the approval prompt, shown as a dialog instead).
    approval_in_run: bool,
    tally: TurnTally,
    /// Running sub-agents (label by run id).
    pub subagents: BTreeMap<String, String>,
}

impl Transcript {
    pub fn push(&mut self, item: Item) {
        self.items.push(item);
        self.expanded.push(false);
        self.cache.push(None);
    }

    pub fn notice(&mut self, text: impl Into<String>, tone: Tone) {
        self.push(Item::Notice(text.into(), tone));
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.expanded.clear();
        self.cache.clear();
    }

    /// Forget every cached rendering (theme or options changed).
    pub fn invalidate(&mut self) {
        self.generation += 1;
    }

    fn mark(&mut self, i: usize) {
        if let Some(c) = self.cache.get_mut(i) {
            *c = None;
        }
    }

    fn mark_last(&mut self) {
        if !self.items.is_empty() {
            self.mark(self.items.len() - 1);
        }
    }

    /// The newest shell item changed (streamed output).
    pub fn invalidate_last_shell(&mut self) {
        if let Some(i) = self
            .items
            .iter()
            .rposition(|i| matches!(i, Item::Shell { .. }))
        {
            self.mark(i);
        }
    }

    /// Fill in the answer of a `/btw` item.
    pub fn set_side_answer(&mut self, i: usize, text: String) {
        if let Some(Item::Side { answer, .. }) = self.items.get_mut(i) {
            *answer = Some(text);
            self.mark(i);
        }
    }

    /// Toggle the detail of item `i` (mouse click).
    pub fn toggle(&mut self, i: usize) -> bool {
        if self.items.get(i).is_some_and(Item::expandable) {
            self.expanded[i] = !self.expanded[i];
            self.mark(i);
            true
        } else {
            false
        }
    }

    /// Start counting a new turn for its receipt.
    pub fn begin_turn(&mut self) {
        self.tally = TurnTally {
            started: Some(Instant::now()),
            ..TurnTally::default()
        };
    }

    /// Build the receipt for the turn that just ended (`None` when the turn
    /// touched nothing worth summarizing).
    pub fn take_receipt(&mut self) -> Option<Receipt> {
        let tally = std::mem::take(&mut self.tally);
        let started = tally.started?;
        Some(Receipt {
            files: tally
                .files
                .into_iter()
                .map(|(path, (a, r))| (path, a, r))
                .collect(),
            checks: tally.checks.into_iter().collect(),
            domains: tally.domains,
            checkpoint: tally.checkpoint,
            duration: started.elapsed(),
            ..Receipt::default()
        })
    }

    fn push_assistant_text(&mut self, delta: &str) {
        if let Some(Item::Assistant(text)) = self.items.last_mut() {
            text.push_str(delta);
            self.mark_last();
        } else {
            self.push(Item::Assistant(delta.to_string()));
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
                    self.push(Item::Assistant(final_text.trim_end().to_string()));
                }
                if let Some(error) = error {
                    self.notice(format!("error: {error}"), Tone::Error);
                }
                self.streamed = false;
                self.approval_in_run = false;
                self.subagents.clear();
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
            Update::CheckStarted(check) => self.push(Item::Check {
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
            Update::ContextPercent(_) | Update::TurnUsage { .. } => {}
        }
    }

    fn finish_check(&mut self, outcome: &CheckOutcome) {
        self.tally
            .checks
            .insert(outcome.check.name.clone(), outcome.success);
        let state = if outcome.success {
            CheckState::Passed(outcome.duration)
        } else {
            CheckState::Failed {
                label: outcome.status_label(),
                duration: outcome.duration,
            }
        };
        let running = self.items.iter().rposition(|i| {
            matches!(
                i,
                Item::Check {
                    state: CheckState::Running,
                    ..
                }
            )
        });
        if let Some(index) = running
            && let Item::Check { state: s, name, .. } = &mut self.items[index]
            && *name == outcome.check.name
        {
            *s = state;
            self.mark(index);
            return;
        }
        self.push(Item::Check {
            name: outcome.check.name.clone(),
            run: outcome.check.run.clone(),
            state,
        });
    }

    fn find_call(&mut self, call_id: &str) -> Option<(usize, &mut ToolCall)> {
        let index = self.items.iter().rposition(|i| match i {
            Item::Tool(t) => t.call_id == call_id,
            Item::Explore(calls) => calls.iter().any(|c| c.call_id == call_id),
            _ => false,
        })?;
        let call = match &mut self.items[index] {
            Item::Tool(t) => t,
            Item::Explore(calls) => calls.iter_mut().find(|c| c.call_id == call_id)?,
            _ => return None,
        };
        Some((index, call))
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
            } => {
                if name == "web_fetch"
                    && let Some(host) = input.get("url").and_then(|v| v.as_str()).and_then(host_of)
                    && !self.tally.domains.contains(&host)
                {
                    self.tally.domains.push(host);
                }
                let call = ToolCall {
                    call_id: call_id.clone(),
                    name: name.clone(),
                    summary: tool_summary(name, input),
                    state: ToolState::Running,
                    output: Vec::new(),
                };
                if is_explore_tool(name) {
                    if let Some(Item::Explore(calls)) = self.items.last_mut() {
                        calls.push(call);
                        self.mark_last();
                    } else {
                        self.push(Item::Explore(vec![call]));
                    }
                } else {
                    self.push(Item::Tool(call));
                }
            }
            RuntimeEvent::ToolResult {
                call_id,
                is_error,
                preview,
                duration_ms,
                error_type,
                ..
            } => {
                let Some((index, call)) = self.find_call(call_id) else {
                    return;
                };
                if *is_error {
                    if error_type.as_deref() == Some("approval_required") {
                        call.state = ToolState::WaitingForApproval;
                    } else {
                        let first = preview.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                        call.state = ToolState::Failed {
                            message: truncate(first, 160),
                        };
                    }
                } else {
                    call.state = ToolState::Done {
                        duration_ms: *duration_ms,
                    };
                    if matches!(call.name.as_str(), "bash" | "bash_output") {
                        let lines: Vec<&str> = preview.lines().collect();
                        let start = lines.len().saturating_sub(TOOL_OUTPUT_KEEP);
                        call.output = lines[start..]
                            .iter()
                            .map(|l| l.chars().take(400).collect())
                            .collect();
                    }
                }
                self.mark(index);
            }
            RuntimeEvent::FileDiff {
                path,
                diff,
                added,
                removed,
                truncated,
            } => {
                let entry = self.tally.files.entry(path.clone()).or_default();
                entry.0 += added;
                entry.1 += removed;
                self.push(Item::Diff {
                    path: path.clone(),
                    added: *added,
                    removed: *removed,
                    diff: diff.clone(),
                    truncated: *truncated,
                });
            }
            RuntimeEvent::PlanUpdated { steps } => {
                let plan = steps.iter().map(|s| (s.status, s.title.clone())).collect();
                if let Some(Item::Plan(existing)) = self.items.last_mut() {
                    *existing = plan;
                    self.mark_last();
                } else {
                    self.push(Item::Plan(plan));
                }
            }
            RuntimeEvent::CheckpointCreated { commit, .. } => {
                if self.tally.checkpoint.is_none() {
                    self.tally.checkpoint = Some(commit.chars().take(10).collect());
                }
            }
            RuntimeEvent::ApprovalRequired { .. } => self.approval_in_run = true,
            RuntimeEvent::ContextCompacted {
                method,
                tokens_before,
                tokens_after,
                ..
            } => self.notice(
                format!(
                    "context compacted ({}): ~{} → ~{} tokens",
                    crate::format::compaction_label(method),
                    crate::format::tokens(*tokens_before as i64),
                    crate::format::tokens(*tokens_after as i64)
                ),
                Tone::Info,
            ),
            RuntimeEvent::SubagentStarted { run_id, label } => {
                self.subagents.insert(run_id.clone(), label.clone());
                self.notice(format!("sub-agent started: {label}"), Tone::Info)
            }
            RuntimeEvent::SubagentFinished { run_id, status } => {
                let label = self.subagents.remove(run_id).unwrap_or_default();
                self.notice(format!("sub-agent {status}: {label}"), Tone::Info)
            }
            _ => {}
        }
    }

    /// The plan of the current conversation (latest plan item).
    pub fn plan(&self) -> Option<&[(RuntimePlanStepStatus, String)]> {
        self.items.iter().rev().find_map(|i| match i {
            Item::Plan(steps) => Some(steps.as_slice()),
            _ => None,
        })
    }

    /// Latest state of each check in this transcript.
    pub fn checks(&self) -> Vec<(String, CheckState)> {
        let mut seen: Vec<(String, CheckState)> = Vec::new();
        for item in &self.items {
            if let Item::Check { name, state, .. } = item {
                if let Some(entry) = seen.iter_mut().find(|(n, _)| n == name) {
                    entry.1 = state.clone();
                } else {
                    seen.push((name.clone(), state.clone()));
                }
            }
        }
        seen
    }

    /// Files changed in this transcript with summed stats.
    pub fn changed_files(&self) -> Vec<(String, usize, usize)> {
        let mut files: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for item in &self.items {
            if let Item::Diff {
                path,
                added,
                removed,
                ..
            } = item
            {
                let e = files.entry(path.clone()).or_default();
                e.0 += added;
                e.1 += removed;
            }
        }
        files.into_iter().map(|(p, (a, r))| (p, a, r)).collect()
    }

    /// Render item `i` (cached).
    fn item_lines(
        &mut self,
        i: usize,
        width: u16,
        theme: &Theme,
        options: &RenderOptions,
    ) -> &[Line<'static>] {
        let expanded = options.expand_all || self.expanded[i];
        let live = self.items[i].is_live();
        let fresh = matches!(&self.cache[i], Some(c) if c.width == width && c.generation == self.generation && c.expanded == expanded);
        if !fresh || live {
            let mut out = Vec::new();
            render_item(
                &self.items[i],
                width as usize,
                theme,
                options,
                expanded,
                &mut out,
            );
            self.cache[i] = Some(Cached {
                width,
                generation: self.generation,
                expanded,
                lines: out,
            });
        }
        &self.cache[i].as_ref().expect("cached").lines
    }

    /// Total rendered height at `width`.
    pub fn height(&mut self, width: u16, theme: &Theme, options: &RenderOptions) -> usize {
        (0..self.items.len())
            .map(|i| self.item_lines(i, width, theme, options).len())
            .sum()
    }

    /// The `height` lines ending `scroll` lines above the bottom, with the
    /// item index each line belongs to.
    pub fn window(
        &mut self,
        width: u16,
        height: usize,
        scroll: usize,
        theme: &Theme,
        options: &RenderOptions,
    ) -> (Vec<Line<'static>>, Vec<usize>, usize) {
        let total = self.height(width, theme, options);
        let max_scroll = total.saturating_sub(height);
        let scroll = scroll.min(max_scroll);
        let end = total - scroll;
        let start = end.saturating_sub(height);
        let mut lines = Vec::with_capacity(height);
        let mut owners = Vec::with_capacity(height);
        let mut offset = 0usize;
        for i in 0..self.items.len() {
            let rendered = self.item_lines(i, width, theme, options);
            let len = rendered.len();
            if offset + len > start && offset < end {
                let from = start.saturating_sub(offset);
                let to = (end - offset).min(len);
                for line in &rendered[from..to] {
                    lines.push(line.clone());
                    owners.push(i);
                }
            }
            offset += len;
            if offset >= end {
                break;
            }
        }
        (lines, owners, scroll)
    }

    /// Every line (inline mode flushes, pager, tests).
    pub fn lines(
        &mut self,
        width: u16,
        theme: &Theme,
        options: &RenderOptions,
    ) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        for i in 0..self.items.len() {
            out.extend(self.item_lines(i, width, theme, options).iter().cloned());
        }
        out
    }

    /// Lines of items `from..to` (inline mode).
    pub fn lines_of(
        &mut self,
        from: usize,
        to: usize,
        width: u16,
        theme: &Theme,
        options: &RenderOptions,
    ) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        for i in from..to.min(self.items.len()) {
            out.extend(self.item_lines(i, width, theme, options).iter().cloned());
        }
        out
    }
}

/// Host part of a URL.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn st(color: ratatui::style::Color) -> Style {
    Style::default().fg(color)
}

fn spinner() -> &'static str {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    SPINNER[(ms / 90) as usize % SPINNER.len()]
}

fn pad_to(spans: &mut Vec<Span<'static>>, width: usize, style: Style) {
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    if used < width {
        spans.push(Span::styled(" ".repeat(width - used), style));
    }
}

fn tool_label(name: &str) -> String {
    match name {
        "bash" => "Bash".into(),
        "bash_output" => "Output".into(),
        "bash_input" => "Input".into(),
        "bash_kill" => "Kill".into(),
        "write_file" => "Write".into(),
        "edit_file" => "Edit".into(),
        "apply_patch" => "Patch".into(),
        "read_file" => "Read".into(),
        "web_fetch" => "Fetch".into(),
        "web_search" => "Search".into(),
        "sub_agent" | "sessions_spawn" => "Agent".into(),
        "explore" => "Explore".into(),
        "todo_write" => "Todo".into(),
        other => match other.strip_prefix("mcp_") {
            Some(rest) => format!("MCP {rest}"),
            None => other.to_string(),
        },
    }
}

fn duration_label(ms: u64) -> String {
    if ms < 1_000 {
        format!("{ms}ms")
    } else {
        elapsed(Duration::from_millis(ms))
    }
}

/// Right-align `right` on a line that already holds `spans`.
fn with_right(mut spans: Vec<Span<'static>>, right: Span<'static>, width: usize) -> Line<'static> {
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    let rw = right.content.width();
    if used + rw + 2 <= width {
        spans.push(Span::raw(" ".repeat(width - used - rw)));
        spans.push(right);
    } else {
        spans.push(Span::raw("  "));
        spans.push(right);
    }
    Line::from(spans)
}

fn gutter(theme: &Theme) -> Span<'static> {
    Span::styled("  │ ", st(theme.border))
}

fn render_item(
    item: &Item,
    width: usize,
    theme: &Theme,
    options: &RenderOptions,
    expanded: bool,
    out: &mut Vec<Line<'static>>,
) {
    let muted = st(theme.text_muted);
    match item {
        Item::User(text) => {
            out.push(Line::default());
            let bg = theme
                .background_element
                .map(|c| Style::default().bg(c))
                .unwrap_or_default();
            for (i, line) in text.lines().enumerate() {
                let prefix = if i == 0 { " › " } else { "   " };
                let mut wrapped = Vec::new();
                wrap_into(
                    &mut wrapped,
                    vec![
                        Span::styled(prefix, bg.fg(theme.accent).add_modifier(Modifier::BOLD)),
                        Span::styled(line.to_string(), bg.fg(theme.text)),
                    ],
                    width.saturating_sub(1),
                    3,
                );
                for l in wrapped {
                    let mut spans = l.spans;
                    for s in spans.iter_mut() {
                        s.style = s.style.patch(bg);
                    }
                    pad_to(&mut spans, width, bg);
                    out.push(Line::from(spans));
                }
            }
        }
        Item::Steer(text) => wrap_into(
            out,
            vec![
                Span::styled(" ↪ ", st(theme.accent)),
                Span::styled(text.clone(), muted),
            ],
            width,
            3,
        ),
        Item::Assistant(text) => {
            out.push(Line::default());
            for line in crate::ui::markdown::render(text, width.saturating_sub(2) as u16, theme) {
                let mut spans = vec![Span::raw("  ")];
                spans.extend(line.spans);
                out.push(Line::from(spans).style(line.style));
            }
        }
        Item::Tool(call) => render_tool(call, width, theme, expanded, out),
        Item::Explore(calls) => {
            let files = calls.iter().filter(|c| c.name == "read_file").count();
            let searches = calls.len() - files;
            let running = calls.iter().any(|c| c.state == ToolState::Running);
            let failed = calls
                .iter()
                .filter(|c| matches!(c.state, ToolState::Failed { .. }))
                .count();
            let mut parts = Vec::new();
            if files > 0 {
                parts.push(format!("{files} file{}", if files == 1 { "" } else { "s" }));
            }
            if searches > 0 {
                parts.push(format!(
                    "{searches} search{}",
                    if searches == 1 { "" } else { "es" }
                ));
            }
            let (mark, mark_style) = if running {
                (spinner(), st(theme.accent))
            } else if failed > 0 {
                ("●", st(theme.warning))
            } else {
                ("●", st(theme.success))
            };
            let total_ms: u64 = calls
                .iter()
                .map(|c| match c.state {
                    ToolState::Done { duration_ms } => duration_ms,
                    _ => 0,
                })
                .sum();
            let verb = if running { "Exploring" } else { "Explored" };
            let mut spans = vec![
                Span::styled(format!("{mark} "), mark_style),
                Span::styled(verb, st(theme.tool_name).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" {}", parts.join(" · ")), st(theme.text)),
            ];
            if failed > 0 {
                spans.push(Span::styled(
                    format!(" · {failed} failed"),
                    st(theme.warning),
                ));
            }
            if !expanded {
                spans.push(Span::styled("  ▸", muted));
            }
            out.push(with_right(
                spans,
                Span::styled(duration_label(total_ms), muted),
                width,
            ));
            let show: Vec<&ToolCall> = if expanded {
                calls.iter().collect()
            } else if running {
                calls.iter().rev().take(1).collect()
            } else {
                Vec::new()
            };
            for c in show {
                let label = match c.name.as_str() {
                    "read_file" => "read",
                    "grep" => "grep",
                    "glob" => "glob",
                    other => other,
                };
                let mut spans = vec![
                    gutter(theme),
                    Span::styled(format!("{label} "), muted),
                    Span::styled(c.summary.clone(), st(theme.text)),
                ];
                if let ToolState::Failed { message } = &c.state {
                    spans.push(Span::styled(format!("  ✗ {message}"), st(theme.error)));
                }
                wrap_into(out, spans, width, 6);
            }
        }
        Item::Diff {
            path,
            added,
            removed,
            diff,
            truncated,
        } => {
            let header = vec![
                Span::styled("  ✎ ", st(theme.accent)),
                Span::styled(path.clone(), st(theme.text).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  +{added}"), st(theme.diff_added)),
                Span::styled(format!(" −{removed}"), st(theme.diff_removed)),
            ];
            out.push(Line::from(header));
            let inner = width.saturating_sub(4).max(20) as u16;
            let layout = crate::ui::diff::choose_layout(options.diff_style, inner);
            let max = if expanded {
                DIFF_LINES_EXPANDED
            } else {
                DIFF_LINES
            };
            for line in crate::ui::diff::render(diff, path, inner, theme, layout, Some(max)) {
                let mut spans = vec![Span::raw("    ")];
                spans.extend(line.spans);
                out.push(Line::from(spans));
            }
            if *truncated {
                out.push(Line::from(Span::styled(
                    "    … diff truncated by the tool",
                    muted,
                )));
            }
        }
        Item::Plan(steps) => {
            let done = steps
                .iter()
                .filter(|(s, _)| *s == RuntimePlanStepStatus::Completed)
                .count();
            out.push(Line::from(vec![
                Span::styled("  ▣ ", st(theme.accent)),
                Span::styled("Plan", st(theme.text).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  {done}/{}", steps.len()), muted),
            ]));
            for (status, title) in steps {
                let (mark, s, text_style) = match status {
                    RuntimePlanStepStatus::Completed => (
                        "✓ ",
                        st(theme.success),
                        muted.add_modifier(Modifier::CROSSED_OUT),
                    ),
                    RuntimePlanStepStatus::InProgress => (
                        "● ",
                        st(theme.warning),
                        st(theme.text).add_modifier(Modifier::BOLD),
                    ),
                    RuntimePlanStepStatus::Pending => ("○ ", muted, st(theme.text)),
                };
                wrap_into(
                    out,
                    vec![
                        Span::raw("    "),
                        Span::styled(mark, s),
                        Span::styled(title.clone(), text_style),
                    ],
                    width,
                    6,
                );
            }
        }
        Item::Check { name, run, state } => {
            let (mark, label, s) = match state {
                CheckState::Running => (
                    spinner().to_string(),
                    "running".to_string(),
                    st(theme.accent),
                ),
                CheckState::Passed(d) => ("✓".into(), elapsed(*d), st(theme.success)),
                CheckState::Failed { label, duration } => (
                    "✗".into(),
                    format!("{label} · {}", elapsed(*duration)),
                    st(theme.error),
                ),
            };
            let spans = vec![
                Span::styled(format!("  {mark} "), s),
                Span::styled(name.clone(), st(theme.text).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  {}", truncate(run, 60)), muted),
            ];
            out.push(with_right(spans, Span::styled(label, s), width));
        }
        Item::Notice(text, tone) => {
            let s = match tone {
                Tone::Info => muted,
                Tone::Success => st(theme.success),
                Tone::Warning => st(theme.warning),
                Tone::Error => st(theme.error),
            };
            for (i, line) in text.lines().enumerate() {
                let prefix = match (i, tone) {
                    (0, Tone::Error) => "  ✗ ",
                    (0, Tone::Warning) => "  ! ",
                    (0, Tone::Success) => "  ✓ ",
                    (0, Tone::Info) => "  · ",
                    _ => "    ",
                };
                wrap_into(
                    out,
                    vec![Span::styled(prefix, s), Span::styled(line.to_string(), s)],
                    width,
                    4,
                );
            }
        }
        Item::Receipt(r) => render_receipt(r, width, theme, out),
        Item::Shell {
            command,
            output,
            exit,
            running,
        } => {
            let (mark, s) = match (running, exit) {
                (true, _) => (spinner().to_string(), st(theme.mode_shell)),
                (false, Some(0)) => ("$".into(), st(theme.mode_shell)),
                (false, _) => ("$".into(), st(theme.error)),
            };
            let mut spans = vec![
                Span::styled(format!("{mark} "), s.add_modifier(Modifier::BOLD)),
                Span::styled(command.clone(), st(theme.text).add_modifier(Modifier::BOLD)),
            ];
            if let Some(code) = exit.filter(|c| *c != 0) {
                spans.push(Span::styled(format!("  exit {code}"), st(theme.error)));
            }
            wrap_into(out, spans, width, 2);
            let keep = if expanded { output.len() } else { 12 };
            let start = output.len().saturating_sub(keep);
            if start > 0 {
                out.push(Line::from(vec![
                    gutter(theme),
                    Span::styled(format!("… {start} earlier lines (ctrl+o)"), muted),
                ]));
            }
            for line in &output[start..] {
                wrap_into(
                    out,
                    vec![gutter(theme), Span::styled(line.clone(), st(theme.text))],
                    width,
                    4,
                );
            }
        }
        Item::Side { question, answer } => {
            out.push(Line::default());
            wrap_into(
                out,
                vec![
                    Span::styled("  ◇ btw ", st(theme.info).add_modifier(Modifier::BOLD)),
                    Span::styled(question.clone(), st(theme.text)),
                ],
                width,
                4,
            );
            match answer {
                None => out.push(Line::from(vec![
                    gutter(theme),
                    Span::styled(format!("{} thinking…", spinner()), muted),
                ])),
                Some(text) => {
                    for line in
                        crate::ui::markdown::render(text, width.saturating_sub(4) as u16, theme)
                    {
                        let mut spans = vec![gutter(theme)];
                        spans.extend(line.spans);
                        out.push(Line::from(spans));
                    }
                }
            }
        }
    }
}

fn render_tool(
    call: &ToolCall,
    width: usize,
    theme: &Theme,
    expanded: bool,
    out: &mut Vec<Line<'static>>,
) {
    let muted = st(theme.text_muted);
    let (mark, mark_style) = match &call.state {
        ToolState::Running => (spinner(), st(theme.accent)),
        ToolState::WaitingForApproval => ("●", st(theme.warning)),
        ToolState::Done { .. } => ("●", st(theme.success)),
        ToolState::Failed { .. } => ("●", st(theme.error)),
    };
    let mut spans = vec![
        Span::styled(format!("{mark} "), mark_style),
        Span::styled(
            tool_label(&call.name),
            st(theme.tool_name).add_modifier(Modifier::BOLD),
        ),
    ];
    if !call.summary.is_empty() {
        spans.push(Span::styled(format!("  {}", call.summary), st(theme.text)));
    }
    let right = match &call.state {
        ToolState::Done { duration_ms } => Span::styled(duration_label(*duration_ms), muted),
        ToolState::WaitingForApproval => Span::styled("waiting for approval", st(theme.warning)),
        ToolState::Running => Span::styled("running", muted),
        ToolState::Failed { .. } => Span::styled("failed", st(theme.error)),
    };
    let header_width: usize = spans.iter().map(|s| s.content.width()).sum();
    if header_width + right.content.width() + 2 <= width {
        out.push(with_right(spans, right, width));
    } else {
        spans.push(Span::raw("  "));
        spans.push(right);
        wrap_into(out, spans, width, 4);
    }
    if let ToolState::Failed { message } = &call.state {
        wrap_into(
            out,
            vec![
                gutter(theme),
                Span::styled(message.clone(), st(theme.error)),
            ],
            width,
            4,
        );
    }
    let keep = if expanded {
        call.output.len()
    } else {
        TOOL_OUTPUT_LINES
    };
    let start = call.output.len().saturating_sub(keep);
    if start > 0 {
        out.push(Line::from(vec![
            gutter(theme),
            Span::styled(format!("… +{start} lines (ctrl+o to expand)"), muted),
        ]));
    }
    for line in &call.output[start..] {
        wrap_into(
            out,
            vec![gutter(theme), Span::styled(line.clone(), muted)],
            width,
            4,
        );
    }
}

fn render_receipt(r: &Receipt, width: usize, theme: &Theme, out: &mut Vec<Line<'static>>) {
    let muted = st(theme.text_muted);
    let border = st(theme.border);
    let inner = width.saturating_sub(4).clamp(20, 100);
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    // Files and checks.
    let mut first = Vec::new();
    if r.files.is_empty() {
        first.push(Span::styled("no file changes", muted));
    } else {
        let added: usize = r.files.iter().map(|f| f.1).sum();
        let removed: usize = r.files.iter().map(|f| f.2).sum();
        first.push(Span::styled(
            format!(
                "{} file{} ",
                r.files.len(),
                if r.files.len() == 1 { "" } else { "s" }
            ),
            st(theme.text),
        ));
        first.push(Span::styled(format!("+{added}"), st(theme.diff_added)));
        first.push(Span::styled(format!(" −{removed}"), st(theme.diff_removed)));
    }
    for (name, passed) in &r.checks {
        first.push(Span::styled(" · ", muted));
        first.push(Span::styled(
            format!("{name} {}", if *passed { "✓" } else { "✗" }),
            st(if *passed { theme.success } else { theme.error }),
        ));
    }
    rows.push(first);
    // Safety.
    let mut second = Vec::new();
    match &r.sandbox {
        Some(s) => second.push(Span::styled(format!("sandbox {s}"), st(theme.success))),
        None => second.push(Span::styled("no sandbox", st(theme.warning))),
    }
    second.push(Span::styled(" · ", muted));
    if r.domains.is_empty() {
        second.push(Span::styled(
            if r.network {
                "network allowed, unused"
            } else {
                "no network"
            },
            muted,
        ));
    } else {
        second.push(Span::styled(
            format!("fetched {}", r.domains.join(", ")),
            st(theme.warning),
        ));
    }
    rows.push(second);
    // Cost.
    let mut third = vec![Span::styled(
        format!(
            "{} in · {} out",
            crate::format::tokens(r.tokens_in),
            crate::format::tokens(r.tokens_out)
        ),
        muted,
    )];
    if let Some(cost) = r.cost {
        third.push(Span::styled(format!(" · ${cost:.3}"), muted));
    }
    third.push(Span::styled(format!(" · {}", elapsed(r.duration)), muted));
    if let Some(cp) = &r.checkpoint {
        third.push(Span::styled(format!(" · checkpoint {cp}"), muted));
        third.push(Span::styled("  (esc esc to rewind)", muted));
    }
    rows.push(third);

    let title = format!(
        " {} ",
        if r.status.is_empty() {
            "turn"
        } else {
            &r.status
        }
    );
    let top_fill = inner.saturating_sub(title.width() + 1);
    out.push(Line::from(vec![
        Span::styled("  ╭─", border),
        Span::styled(title, st(theme.text_muted).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{}╮", "─".repeat(top_fill)), border),
    ]));
    for row in rows {
        let mut wrapped = Vec::new();
        wrap_into(&mut wrapped, row, inner.saturating_sub(2), 0);
        for line in wrapped {
            let mut spans = vec![Span::styled("  │ ", border)];
            let used: usize = line.spans.iter().map(|s| s.content.width()).sum();
            spans.extend(line.spans);
            spans.push(Span::raw(
                " ".repeat(inner.saturating_sub(2).saturating_sub(used)),
            ));
            spans.push(Span::styled(" │", border));
            out.push(Line::from(spans));
        }
    }
    out.push(Line::from(Span::styled(
        format!("  ╰{}╯", "─".repeat(inner)),
        border,
    )));
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

    fn theme() -> Theme {
        crate::ui::theme::resolve("dark", None, Some(true)).0
    }

    fn tool(seq: u64, id: &str, name: &str, input: serde_json::Value) -> Update {
        runtime(
            seq,
            RuntimeEvent::ToolStart {
                call_id: id.into(),
                name: name.into(),
                input,
            },
        )
    }

    fn result(seq: u64, id: &str, name: &str, preview: &str) -> Update {
        runtime(
            seq,
            RuntimeEvent::ToolResult {
                call_id: id.into(),
                name: name.into(),
                is_error: false,
                preview: preview.into(),
                duration_ms: 12,
                status_code: Some(0),
                bytes: 0,
                error_type: None,
            },
        )
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
        t.apply(&tool(
            2,
            "c1",
            "bash",
            serde_json::json!({"command": "cargo test"}),
        ));
        t.apply(&result(3, "c1", "bash", "a\nb\nc\nd\ne\ntest result: ok"));
        t.apply(&runtime(
            4,
            RuntimeEvent::FileDiff {
                path: "src/lib.rs".into(),
                diff: "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-x\n+y\n".into(),
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
        let rendered = text(&t.lines(80, &theme(), &RenderOptions::default()));
        assert!(rendered.contains("● Bash  cargo test"), "{rendered}");
        assert!(rendered.contains("12ms"));
        assert!(rendered.contains("test result: ok"));
        assert!(
            rendered.contains("+2 lines (ctrl+o to expand)"),
            "{rendered}"
        );
        assert!(rendered.contains("src/lib.rs  +1 −1"));
        assert_eq!(
            rendered.matches("Hello").count(),
            1,
            "streamed text is not repeated"
        );
        // Expanding shows the whole output.
        let expanded = text(&t.lines(
            80,
            &theme(),
            &RenderOptions {
                expand_all: true,
                ..RenderOptions::default()
            },
        ));
        assert!(expanded.contains("│ a"));
    }

    #[test]
    fn groups_consecutive_reads_and_searches() {
        let mut t = Transcript::default();
        t.apply(&tool(
            0,
            "r1",
            "read_file",
            serde_json::json!({"path": "a.rs"}),
        ));
        t.apply(&result(1, "r1", "read_file", "x"));
        t.apply(&tool(2, "g1", "grep", serde_json::json!({"pattern": "fn"})));
        t.apply(&result(3, "g1", "grep", "x"));
        t.apply(&tool(
            4,
            "r2",
            "read_file",
            serde_json::json!({"path": "b.rs"}),
        ));
        t.apply(&result(5, "r2", "read_file", "x"));
        assert_eq!(t.items.len(), 1);
        let rendered = text(&t.lines(80, &theme(), &RenderOptions::default()));
        assert!(
            rendered.contains("Explored 2 files · 1 search"),
            "{rendered}"
        );
        assert!(!rendered.contains("b.rs"));
        assert!(t.toggle(0));
        let rendered = text(&t.lines(80, &theme(), &RenderOptions::default()));
        assert!(rendered.contains("read b.rs"), "{rendered}");
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
    fn window_returns_the_bottom_and_owners() {
        let mut t = Transcript::default();
        for i in 0..50 {
            t.notice(format!("line {i}"), Tone::Info);
        }
        let (lines, owners, scroll) = t.window(40, 5, 0, &theme(), &RenderOptions::default());
        assert_eq!(scroll, 0);
        assert_eq!(lines.len(), 5);
        assert!(text(&lines).ends_with("line 49"));
        assert_eq!(*owners.last().unwrap(), 49);
        let (lines, _, _) = t.window(40, 5, 10, &theme(), &RenderOptions::default());
        assert!(text(&lines).ends_with("line 39"));
    }

    #[test]
    fn receipt_tallies_the_turn() {
        let mut t = Transcript::default();
        t.begin_turn();
        t.apply(&tool(
            0,
            "w",
            "web_fetch",
            serde_json::json!({"url": "https://docs.rs/x"}),
        ));
        t.apply(&runtime(
            1,
            RuntimeEvent::FileDiff {
                path: "a.rs".into(),
                diff: String::new(),
                added: 3,
                removed: 1,
                truncated: false,
            },
        ));
        let receipt = t.take_receipt().unwrap();
        assert_eq!(receipt.files, vec![("a.rs".to_string(), 3, 1)]);
        assert_eq!(receipt.domains, vec!["docs.rs".to_string()]);
        let mut out = Vec::new();
        render_receipt(&receipt, 80, &theme(), &mut out);
        let rendered = text(&out);
        assert!(rendered.contains("1 file +3 −1"), "{rendered}");
        assert!(rendered.contains("fetched docs.rs"));
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

    #[test]
    fn host_of_urls() {
        assert_eq!(
            host_of("https://user@Example.com:8080/a?b").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("docs.rs/x").as_deref(), Some("docs.rs"));
    }
}
