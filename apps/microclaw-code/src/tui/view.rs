//! Drawing: header, transcript, side panel, status line, queue, popup,
//! input box and dialogs.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

use microclaw_code_core::project::Mode;
use microclaw_sdk::RuntimePlanStepStatus;

use super::App;
use super::dialogs::{Dialog, PickerKind};
use super::popup::PopupKind;
use super::transcript::CheckState;
use crate::ui::theme::Theme;

const SIDEBAR_MIN_WIDTH: u16 = 130;
const SIDEBAR_WIDTH: u16 = 34;

fn st(color: Color) -> Style {
    Style::default().fg(color)
}

pub fn mode_color(theme: &Theme, mode: Mode, shell: bool) -> Color {
    if shell {
        return theme.mode_shell;
    }
    match mode {
        Mode::Plan => theme.mode_plan,
        Mode::Ask => theme.mode_ask,
        Mode::Auto => theme.mode_auto,
    }
}

/// Blend two RGB colours (`t` = 0 → `a`, 1 → `b`).
fn blend(a: Color, b: Color, t: f32) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
            Color::Rgb(mix(r1, r2), mix(g1, g2), mix(b1, b2))
        }
        _ => {
            if t > 0.5 {
                b
            } else {
                a
            }
        }
    }
}

/// A light band sweeping across `text` (truecolor themes; plain otherwise).
pub fn shimmer(text: &str, theme: &Theme, started: Instant, animate: bool) -> Vec<Span<'static>> {
    let base = theme.accent;
    let bright = theme.text;
    if !animate || !matches!(base, Color::Rgb(..)) {
        return vec![Span::styled(
            text.to_string(),
            st(base).add_modifier(Modifier::BOLD),
        )];
    }
    let chars: Vec<char> = text.chars().collect();
    let period = 1.8f32;
    let phase = (started.elapsed().as_secs_f32() % period) / period;
    let span = chars.len() as f32 + 6.0;
    let center = phase * span - 3.0;
    chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let d = (i as f32 - center).abs();
            let t = (1.0 - d / 3.0).clamp(0.0, 1.0);
            let t = 0.5 - 0.5 * (std::f32::consts::PI * t).cos();
            Span::styled(
                c.to_string(),
                st(blend(base, bright, t)).add_modifier(Modifier::BOLD),
            )
        })
        .collect()
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if let Some(bg) = app.theme.background {
        frame.render_widget(Block::default().style(Style::default().bg(bg)), area);
    }
    let input_width = area.width.saturating_sub(4) as usize;
    let (input_lines, cursor) = app.input.layout(input_width.max(2));
    let input_height = (input_lines.len() as u16).clamp(1, 10) + 2;
    let queue_height = app.queue.len().min(3) as u16;
    let header_height = if app.inline { 0 } else { 1 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(queue_height),
            Constraint::Length(input_height),
        ])
        .split(area);

    if header_height > 0 {
        draw_header(frame, app, chunks[0]);
    }
    // Body: transcript (+ side panel).
    let body = chunks[1];
    let sidebar = app.show_sidebar
        && !app.inline
        && body.width >= SIDEBAR_MIN_WIDTH
        && app.settings.tui.sidebar != Some(microclaw_code_core::settings::SidebarMode::Hide)
        && (app.settings.tui.sidebar == Some(microclaw_code_core::settings::SidebarMode::Show)
            || sidebar_has_content(app));
    let (transcript_area, side_area) = if sidebar {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(40), Constraint::Length(SIDEBAR_WIDTH)])
            .split(body);
        (cols[0], Some(cols[1]))
    } else {
        (body, None)
    };
    app.transcript_area = transcript_area;
    draw_transcript(frame, app, transcript_area);
    if let Some(side) = side_area {
        draw_sidebar(frame, app, side);
    }
    draw_status(frame, app, chunks[2]);
    if queue_height > 0 {
        draw_queue(frame, app, chunks[3]);
    }

    // Input box.
    let color = mode_color(&app.theme, app.mode, app.shell_mode);
    let inner_height = (input_height - 2) as usize;
    let first = cursor.0.saturating_sub(inner_height.saturating_sub(1));
    let text_style = st(app.theme.text);
    let visible: Vec<Line> = input_lines
        .iter()
        .skip(first)
        .take(inner_height)
        .map(|l| Line::from(Span::styled(l.clone(), text_style)))
        .collect();
    let label = if app.shell_mode {
        " ! shell ".to_string()
    } else {
        format!(" {} ", app.mode.as_str())
    };
    let hint = input_hint(app);
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(st(color))
        .title(Span::styled(label, st(color).add_modifier(Modifier::BOLD)));
    if !hint.is_empty() && (hint.width() as u16) + 12 < area.width {
        block = block.title_bottom(
            Line::from(Span::styled(format!(" {hint} "), st(app.theme.text_muted))).right_aligned(),
        );
    }
    if app.input.is_empty() && app.dialog.is_none() {
        let placeholder = if app.shell_mode {
            "run a shell command in the project"
        } else if app.running.is_some() {
            "queue a message, or Ctrl+S to steer now…"
        } else {
            "ask, or / for commands, @ for files, ! for shell"
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                placeholder,
                st(app.theme.text_muted).add_modifier(Modifier::ITALIC),
            )))
            .block(block),
            chunks[4],
        );
    } else {
        frame.render_widget(Paragraph::new(visible).block(block), chunks[4]);
    }
    if app.dialog.is_none() {
        frame.set_cursor_position((
            chunks[4].x + 1 + cursor.1 as u16,
            chunks[4].y + 1 + (cursor.0 - first) as u16,
        ));
    }

    if let Some(popup) = &app.popup {
        draw_popup(frame, app, popup, chunks[4]);
    }

    let overlay_area = Rect::new(area.x, area.y + header_height, area.width, body.height + 1);
    if let Some(dialog) = &app.dialog {
        draw_dialog(frame, app, dialog, area, overlay_area);
    }
}

fn input_hint(app: &App) -> String {
    if let Some(hint) = &app.hint {
        return hint.clone();
    }
    if app.running.is_some() {
        return "Enter queue · Ctrl+S steer · Esc stop".into();
    }
    let palette = app
        .keymap
        .label(super::keymap::Action::Palette)
        .unwrap_or_default();
    format!("Shift+Tab mode · {palette} commands · Ctrl+T transcript")
}

fn sidebar_has_content(app: &App) -> bool {
    app.transcript.plan().is_some()
        || !app.transcript.checks().is_empty()
        || !app.transcript.changed_files().is_empty()
        || !app.transcript.subagents.is_empty()
        || app.goal.is_some()
}

pub(super) fn header_line(app: &App, width: u16) -> Line<'static> {
    let theme = &app.theme;
    let muted = st(theme.text_muted);
    let mut left = vec![
        Span::styled(" ◆ ", st(theme.accent).add_modifier(Modifier::BOLD)),
        Span::styled(
            app.project_name.clone(),
            st(theme.text).add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(branch) = &app.branch {
        left.push(Span::styled(format!("  {branch}"), muted));
    }
    left.push(Span::styled("  ·  ", muted));
    left.push(Span::styled(
        app.mode.as_str().to_string(),
        st(mode_color(theme, app.mode, false)).add_modifier(Modifier::BOLD),
    ));
    if !app.model.is_empty() {
        left.push(Span::styled("  ·  ", muted));
        left.push(Span::styled(app.model.clone(), st(theme.text)));
    }
    if !app.trusted {
        left.push(Span::styled("  untrusted", st(theme.warning)));
    }
    let mut right: Vec<Span<'static>> = Vec::new();
    if let Some(session) = app.session.as_ref() {
        match &session.settings.sandbox {
            Some(s) => {
                right.push(Span::styled("sandbox ", muted));
                right.push(Span::styled("●", st(theme.success)));
                right.push(Span::styled("  net ", muted));
                right.push(Span::styled(
                    if s.network { "●" } else { "○" },
                    st(if s.network {
                        theme.warning
                    } else {
                        theme.text_muted
                    }),
                ));
            }
            None => right.push(Span::styled("no sandbox", st(theme.warning))),
        }
    }
    if let Some(pct) = app.context_pct {
        right.push(Span::styled("  ctx ", muted));
        right.push(Span::styled(
            format!("{pct}%"),
            st(context_color(theme, pct)),
        ));
    }
    if let Some(cost) = app.session_cost {
        right.push(Span::styled(format!("  ${cost:.2}"), muted));
    }
    right.push(Span::raw(" "));
    let lw: usize = left.iter().map(|s| s.content.width()).sum();
    let rw: usize = right.iter().map(|s| s.content.width()).sum();
    if lw + rw < width as usize {
        left.push(Span::raw(" ".repeat(width as usize - lw - rw)));
        left.extend(right);
    }
    Line::from(left)
}

fn context_color(theme: &Theme, pct: u8) -> Color {
    match pct {
        0..=69 => theme.text_muted,
        70..=84 => theme.warning,
        _ => theme.error,
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut paragraph = Paragraph::new(header_line(app, area.width));
    if let Some(bg) = app.theme.background_panel {
        paragraph = paragraph.style(Style::default().bg(bg));
    }
    frame.render_widget(paragraph, area);
}

fn draw_transcript(frame: &mut Frame, app: &mut App, area: Rect) {
    let height = area.height as usize;
    let (lines, owners, scroll) = if app.inline {
        let first = app.first_visible_item();
        let len = app.transcript.items.len();
        let all = app
            .transcript
            .lines_of(first, len, area.width, &app.theme, &app.render);
        let start = all.len().saturating_sub(height);
        let owners = vec![usize::MAX; all.len() - start];
        (all[start..].to_vec(), owners, 0)
    } else {
        app.transcript
            .window(area.width, height, app.scroll, &app.theme, &app.render)
    };
    app.scroll = scroll;
    app.line_owners = owners;
    // Bottom-align short transcripts so the conversation sits above the input.
    let pad = height.saturating_sub(lines.len());
    let mut shown: Vec<Line> = Vec::with_capacity(height);
    if pad > 0 && !app.inline {
        shown.extend(std::iter::repeat_n(Line::default(), pad));
        let mut owners = vec![usize::MAX; pad];
        owners.extend(std::mem::take(&mut app.line_owners));
        app.line_owners = owners;
    }
    shown.extend(lines);
    if app.transcript.items.len() <= 1 && app.running.is_none() && !app.inline {
        draw_welcome(frame, app, area);
    }
    frame.render_widget(Paragraph::new(shown), area);
    if app.scroll > 0 {
        let note = format!(" ↓ {} more lines · End ", app.scroll);
        let w = note.width() as u16;
        if area.width > w + 2 {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    note,
                    Style::default().fg(Color::Black).bg(app.theme.accent),
                )),
                Rect::new(area.x + area.width - w - 1, area.y + area.height - 1, w, 1),
            );
        }
    }
}

fn draw_welcome(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let muted = st(theme.text_muted);
    let lines = vec![
        Line::from(vec![
            Span::styled("◆ ", st(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled(
                "MicroClaw Code",
                st(theme.text).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "Describe a change, ask about the code, or try:",
            muted,
        )),
        Line::from(vec![
            Span::styled("  /plan ", st(theme.accent)),
            Span::styled("think first, change nothing", muted),
        ]),
        Line::from(vec![
            Span::styled("  /goal ", st(theme.accent)),
            Span::styled("work until checks pass", muted),
        ]),
        Line::from(vec![
            Span::styled("  @file ", st(theme.accent)),
            Span::styled("mention a file or image", muted),
        ]),
        Line::from(vec![
            Span::styled("  !cmd  ", st(theme.accent)),
            Span::styled("run a shell command yourself", muted),
        ]),
        Line::from(vec![
            Span::styled("  /theme ", st(theme.accent)),
            Span::styled("pick colours", muted),
        ]),
    ];
    let h = lines.len() as u16;
    let w = 46u16.min(area.width);
    if area.height < h + 4 {
        return;
    }
    let rect = Rect::new(
        area.x + (area.width.saturating_sub(w)) / 2,
        area.y + (area.height.saturating_sub(h)) / 3,
        w,
        h,
    );
    frame.render_widget(Paragraph::new(lines), rect);
}

fn draw_sidebar(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let muted = st(theme.text_muted);
    let title = |text: &str| {
        Line::from(Span::styled(
            text.to_string(),
            st(theme.text_muted).add_modifier(Modifier::BOLD),
        ))
    };
    let width = area.width.saturating_sub(3) as usize;
    let cut = |s: &str, n: usize| -> String {
        if s.width() <= n {
            s.to_string()
        } else {
            let mut out = String::new();
            for c in s.chars() {
                if out.width() + 2 > n {
                    break;
                }
                out.push(c);
            }
            out.push('…');
            out
        }
    };
    let mut lines: Vec<Line> = Vec::new();
    if let Some(goal) = &app.goal {
        lines.push(title("GOAL"));
        lines.push(Line::from(Span::styled(
            cut(&goal.spec.objective, width),
            st(theme.text),
        )));
        lines.push(Line::from(Span::styled(goal.progress(), muted)));
        if let Some(until) = &goal.spec.until {
            lines.push(Line::from(Span::styled(
                cut(&format!("until `{until}`"), width),
                muted,
            )));
        }
        lines.push(Line::default());
    }
    if let Some(plan) = app.transcript.plan() {
        let done = plan
            .iter()
            .filter(|(s, _)| *s == RuntimePlanStepStatus::Completed)
            .count();
        lines.push(Line::from(vec![
            Span::styled("PLAN", st(theme.text_muted).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {done}/{}", plan.len()), muted),
        ]));
        for (status, step) in plan.iter().take(12) {
            let (mark, s) = match status {
                RuntimePlanStepStatus::Completed => ("✓ ", st(theme.success)),
                RuntimePlanStepStatus::InProgress => ("● ", st(theme.warning)),
                RuntimePlanStepStatus::Pending => ("○ ", muted),
            };
            lines.push(Line::from(vec![
                Span::styled(mark, s),
                Span::styled(
                    cut(step, width.saturating_sub(2)),
                    if *status == RuntimePlanStepStatus::Completed {
                        muted
                    } else {
                        st(theme.text)
                    },
                ),
            ]));
        }
        lines.push(Line::default());
    }
    let checks = app.transcript.checks();
    if !checks.is_empty() {
        lines.push(title("CHECKS"));
        for (name, state) in checks {
            let (mark, s, extra) = match state {
                CheckState::Running => ("● ", st(theme.accent), "running".to_string()),
                CheckState::Passed(d) => ("✓ ", st(theme.success), crate::format::elapsed(d)),
                CheckState::Failed { label, .. } => ("✗ ", st(theme.error), label),
            };
            lines.push(Line::from(vec![
                Span::styled(mark, s),
                Span::styled(cut(&name, width.saturating_sub(12)), st(theme.text)),
                Span::styled(format!("  {extra}"), muted),
            ]));
        }
        lines.push(Line::default());
    }
    let files = app.transcript.changed_files();
    if !files.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("CHANGES", st(theme.text_muted).add_modifier(Modifier::BOLD)),
            Span::styled("  F2 review", muted),
        ]));
        for (path, added, removed) in files.iter().rev().take(14) {
            let stats = format!(" +{added} −{removed}");
            let room = width.saturating_sub(stats.width());
            let short = if path.width() > room {
                let name = std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.clone());
                cut(&format!("…/{name}"), room)
            } else {
                path.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(short, st(theme.text)),
                Span::styled(format!(" +{added}"), st(theme.diff_added)),
                Span::styled(format!(" −{removed}"), st(theme.diff_removed)),
            ]));
        }
        lines.push(Line::default());
    }
    if !app.transcript.subagents.is_empty() {
        lines.push(title("SUB-AGENTS"));
        for label in app.transcript.subagents.values() {
            lines.push(Line::from(vec![
                Span::styled("● ", st(theme.accent)),
                Span::styled(cut(label, width.saturating_sub(2)), st(theme.text)),
            ]));
        }
        lines.push(Line::default());
    }
    let mut block = Block::default()
        .borders(Borders::LEFT)
        .border_style(st(theme.border))
        .padding(ratatui::widgets::Padding::new(1, 1, 0, 0));
    if let Some(bg) = theme.background_panel {
        block = block.style(Style::default().bg(bg));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let muted = st(theme.text_muted);
    let animate = app.settings.tui.animations.unwrap_or(true);
    let line = if let Some(running) = &app.running {
        let mut spans = vec![Span::raw(" ")];
        spans.extend(shimmer(
            if app.goal.is_some() {
                "Working toward the goal"
            } else {
                "Working"
            },
            theme,
            running.started,
            animate,
        ));
        spans.push(Span::styled(
            format!("  {}", crate::format::elapsed(running.started.elapsed())),
            muted,
        ));
        if !app.transcript.subagents.is_empty() {
            spans.push(Span::styled(
                format!("  · {} sub-agent(s)", app.transcript.subagents.len()),
                muted,
            ));
        }
        if !app.queue.is_empty() {
            spans.push(Span::styled(
                format!("  · {} queued", app.queue.len()),
                muted,
            ));
        }
        spans.push(Span::styled("  · esc to stop", muted));
        Line::from(spans)
    } else {
        Line::from(status_items(app))
    };
    frame.render_widget(Paragraph::new(line), area);
}

/// The idle status line from `tui.status_line`.
fn status_items(app: &App) -> Vec<Span<'static>> {
    let theme = &app.theme;
    let muted = st(theme.text_muted);
    let default = ["mode", "model", "context", "tokens", "cost", "branch"];
    let items: Vec<String> = app
        .settings
        .tui
        .status_line
        .clone()
        .unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect());
    let mut spans: Vec<Span<'static>> = vec![Span::raw(" ")];
    let mut push = |parts: Vec<Span<'static>>| {
        if parts.is_empty() {
            return;
        }
        if spans.len() > 1 {
            spans.push(Span::styled("  ·  ", muted));
        }
        spans.extend(parts);
    };
    for item in items {
        match item.as_str() {
            "mode" => push(vec![Span::styled(
                format!("{} mode", app.mode.as_str()),
                st(mode_color(theme, app.mode, false)),
            )]),
            "model" if !app.model.is_empty() => push(vec![Span::styled(app.model.clone(), muted)]),
            "context" => {
                if let Some(pct) = app.context_pct {
                    let filled = (pct as usize * 10 / 100).min(10);
                    push(vec![
                        Span::styled("ctx ", muted),
                        Span::styled("▰".repeat(filled), st(context_color(theme, pct))),
                        Span::styled("▱".repeat(10 - filled), st(theme.border)),
                        Span::styled(format!(" {pct}%"), st(context_color(theme, pct))),
                    ]);
                }
            }
            "tokens" if app.session_tokens != (0, 0) => push(vec![Span::styled(
                format!(
                    "↑{} ↓{}",
                    crate::format::tokens(app.session_tokens.0),
                    crate::format::tokens(app.session_tokens.1)
                ),
                muted,
            )]),
            "cost" => {
                if let Some(cost) = app.session_cost {
                    push(vec![Span::styled(format!("${cost:.2}"), muted)]);
                }
            }
            "branch" => {
                if let Some(b) = &app.branch {
                    push(vec![Span::styled(format!(" {b}"), muted)]);
                }
            }
            "sandbox" => {
                let text = match app
                    .session
                    .as_ref()
                    .and_then(|s| s.settings.sandbox.as_ref())
                {
                    Some(s) => format!("sandbox {}", s.mechanism),
                    None => "no sandbox".into(),
                };
                push(vec![Span::styled(text, muted)]);
            }
            "session" => push(vec![Span::styled(app.session_label.clone(), muted)]),
            "checks" => {
                let checks = app.transcript.checks();
                if !checks.is_empty() {
                    let failed = checks
                        .iter()
                        .filter(|(_, s)| matches!(s, CheckState::Failed { .. }))
                        .count();
                    push(vec![Span::styled(
                        if failed == 0 {
                            "checks ✓".to_string()
                        } else {
                            format!("checks ✗{failed}")
                        },
                        st(if failed == 0 {
                            theme.success
                        } else {
                            theme.error
                        }),
                    )]);
                }
            }
            _ => {}
        }
    }
    if app.goal.is_some() {
        spans.push(Span::styled("  ·  goal active", st(theme.accent)));
    }
    spans
}

fn draw_queue(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let lines: Vec<Line> = app
        .queue
        .iter()
        .rev()
        .take(area.height as usize)
        .rev()
        .enumerate()
        .map(|(i, q)| {
            Line::from(vec![
                Span::styled(format!(" ↳ queued {} ", i + 1), st(theme.text_muted)),
                Span::styled(
                    crate::format::truncate(q, area.width.saturating_sub(10) as usize),
                    st(theme.text),
                ),
                Span::styled(
                    if i + 1 == app.queue.len().min(area.height as usize) {
                        "  (↑ edits)"
                    } else {
                        ""
                    },
                    st(theme.text_muted),
                ),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_popup(frame: &mut Frame, app: &App, popup: &super::popup::Popup, input: Rect) {
    let theme = &app.theme;
    let rows = popup.entries.len().min(8) as u16;
    if rows == 0 && popup.kind != PopupKind::History {
        return;
    }
    let height = rows.max(1) + 2;
    let width = input.width.min(90);
    let y = input.y.saturating_sub(height);
    let rect = Rect::new(input.x, y, width, height);
    let first = popup
        .selected
        .saturating_sub(rows.saturating_sub(1) as usize);
    let label_width = popup
        .entries
        .iter()
        .map(|e| e.label.width())
        .max()
        .unwrap_or(0)
        .min(width as usize / 2);
    let mut lines: Vec<Line> = popup
        .entries
        .iter()
        .enumerate()
        .skip(first)
        .take(rows as usize)
        .map(|(i, e)| {
            let selected = i == popup.selected;
            let style = if selected {
                Style::default()
                    .fg(theme.text)
                    .bg(theme.background_element.unwrap_or(theme.border))
                    .add_modifier(Modifier::BOLD)
            } else {
                st(theme.text)
            };
            let label = crate::format::truncate(&e.label, label_width.max(8));
            let pad = label_width.saturating_sub(label.width());
            let mut spans = vec![
                Span::styled(if selected { "› " } else { "  " }, st(theme.accent)),
                Span::styled(format!("{label}{}", " ".repeat(pad)), style),
            ];
            if !e.detail.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", e.detail),
                    st(theme.text_muted),
                ));
            }
            Line::from(spans)
        })
        .collect();
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no matches",
            st(theme.text_muted),
        )));
    }
    let title = match popup.kind {
        PopupKind::Slash => " commands ".to_string(),
        PopupKind::File => " files ".to_string(),
        PopupKind::History => format!(" history: {} ", popup.query),
    };
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(st(theme.border_active))
        .title(Span::styled(title, st(theme.text_muted)));
    if let Some(bg) = theme.background_panel {
        block = block.style(Style::default().bg(bg));
    }
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

fn key_chip(theme: &Theme, key: &str, color: Color) -> Span<'static> {
    let fg = if matches!(color, Color::Rgb(..)) {
        theme.background.unwrap_or(Color::Black)
    } else {
        Color::Black
    };
    Span::styled(
        format!(" {key} "),
        Style::default()
            .fg(fg)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

fn draw_dialog(frame: &mut Frame, app: &App, dialog: &Dialog, area: Rect, overlay: Rect) {
    let theme = &app.theme;
    let muted = st(theme.text_muted);
    match dialog {
        Dialog::Pager(p) => {
            frame.render_widget(Clear, overlay);
            let lines = p.render(overlay.width, overlay.height as usize, theme);
            let mut para = Paragraph::new(lines);
            if let Some(bg) = theme.background {
                para = para.style(Style::default().bg(bg));
            }
            frame.render_widget(para, overlay);
            return;
        }
        Dialog::Review(state) => {
            frame.render_widget(Clear, overlay);
            let lines = state.render(overlay.width, overlay.height, theme, app.render.diff_style);
            let mut para = Paragraph::new(lines);
            if let Some(bg) = theme.background {
                para = para.style(Style::default().bg(bg));
            }
            frame.render_widget(para, overlay);
            return;
        }
        _ => {}
    }
    let (title, lines, border, width): (String, Vec<Line>, Color, u16) = match dialog {
        Dialog::Approval(d) => {
            let approval = &d.approval;
            let mut lines = vec![Line::from(vec![
                Span::styled("The agent wants to run ", st(theme.text)),
                Span::styled(
                    approval.tool.clone(),
                    st(theme.tool_name).add_modifier(Modifier::BOLD),
                ),
            ])];
            if let Some(preview) = &approval.preview {
                lines.push(Line::default());
                let code_bg = theme
                    .background_element
                    .map(|c| Style::default().bg(c))
                    .unwrap_or_default();
                let all: Vec<&str> = preview.lines().collect();
                for l in all.iter().take(16) {
                    lines.push(Line::from(Span::styled(
                        format!("  {l}"),
                        code_bg.fg(theme.warning),
                    )));
                }
                if all.len() > 16 {
                    lines.push(Line::from(Span::styled(
                        format!("  … {} more lines", all.len() - 16),
                        muted,
                    )));
                }
            }
            if let Some(advisory) = &approval.advisory {
                lines.push(Line::default());
                let dangerous = advisory
                    .trim_start()
                    .to_ascii_uppercase()
                    .starts_with("DANGEROUS");
                lines.push(Line::from(Span::styled(
                    format!("reviewer: {advisory}"),
                    st(if dangerous {
                        theme.error
                    } else {
                        theme.text_muted
                    }),
                )));
            }
            if let Some(rule) = &approval.suggested_rule {
                lines.push(Line::from(Span::styled(
                    format!("“always allow” saves the rule `{rule}` for this project"),
                    muted,
                )));
            }
            lines.push(Line::default());
            for (i, (value, label)) in d.rows().iter().enumerate() {
                let selected = i == d.selected;
                let chip_color = if value == "r"
                    || label.to_ascii_lowercase().starts_with("no")
                    || label.to_ascii_lowercase().starts_with("deny")
                {
                    theme.error
                } else {
                    theme.accent
                };
                lines.push(Line::from(vec![
                    Span::styled(if selected { "› " } else { "  " }, st(theme.accent)),
                    key_chip(theme, value, chip_color),
                    Span::styled(
                        format!(" {label}"),
                        if selected {
                            st(theme.text).add_modifier(Modifier::BOLD)
                        } else {
                            st(theme.text)
                        },
                    ),
                ]));
            }
            if let Some(reason) = &d.reason {
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled(
                        "tell the agent › ",
                        st(theme.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("{reason}▌"), st(theme.text)),
                ]));
                lines.push(Line::from(Span::styled(
                    "Enter denies and sends this · Esc back",
                    muted,
                )));
            } else {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    if d.remote.as_deref().is_some_and(|r| !r.is_empty()) {
                        "↑↓ Enter or option key · Esc denies · also waiting for an answer from your chat"
                    } else {
                        "↑↓ Enter or option key · Esc denies"
                    },
                    muted,
                )));
            }
            (" Approval needed ".to_string(), lines, theme.warning, 84)
        }
        Dialog::Trust {
            root,
            has_config,
            changed,
        } => {
            let mut lines = vec![Line::from(Span::styled(
                format!("Trust {root}?"),
                st(theme.text).add_modifier(Modifier::BOLD),
            ))];
            if *changed {
                lines.push(Line::from(Span::styled(
                    "Its .microclaw/project.yaml changed since you last trusted it.",
                    st(theme.warning),
                )));
            }
            lines.push(Line::default());
            if *has_config {
                lines.push(Line::from(Span::styled(
                    "Its .microclaw files can set the permission mode, rules, hooks, instructions and check commands.",
                    st(theme.text),
                )));
            }
            lines.push(Line::from(Span::styled(
                "Trusted projects run their checks (build scripts included) automatically after edits.",
                st(theme.text),
            )));
            lines.push(Line::from(Span::styled(
                "Untrusted projects ignore the project files.",
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(vec![
                key_chip(theme, "y", theme.success),
                Span::styled(" trust    ", st(theme.text)),
                key_chip(theme, "n", theme.error),
                Span::styled(" not now", st(theme.text)),
            ]));
            (" Project trust ".to_string(), lines, theme.accent, 84)
        }
        Dialog::ExecutePlan => (
            " Plan ready ".to_string(),
            vec![
                Line::from(Span::styled(
                    "Execute this plan now?",
                    st(theme.text).add_modifier(Modifier::BOLD),
                )),
                Line::default(),
                Line::from(vec![
                    key_chip(theme, "y", theme.mode_ask),
                    Span::styled(" run it in ask mode   ", st(theme.text)),
                    key_chip(theme, "a", theme.mode_auto),
                    Span::styled(" run it in auto mode   ", st(theme.text)),
                    key_chip(theme, "n", theme.border),
                    Span::styled(" keep planning", st(theme.text)),
                ]),
            ],
            theme.mode_plan,
            84,
        ),
        Dialog::Picker(p) => {
            let mut lines = vec![Line::from(vec![
                Span::styled("› ", st(theme.accent).add_modifier(Modifier::BOLD)),
                Span::styled(
                    if p.filter.is_empty() {
                        "type to filter".to_string()
                    } else {
                        format!("{}▌", p.filter)
                    },
                    if p.filter.is_empty() {
                        muted.add_modifier(Modifier::ITALIC)
                    } else {
                        st(theme.text)
                    },
                ),
            ])];
            lines.push(Line::default());
            let rows = (area.height as usize).saturating_sub(10).clamp(4, 16);
            let first = p.selected.saturating_sub(rows.saturating_sub(1));
            let label_w = p
                .shown
                .iter()
                .map(|e| e.label.width())
                .max()
                .unwrap_or(0)
                .min(48);
            for (i, e) in p.shown.iter().enumerate().skip(first).take(rows) {
                let selected = i == p.selected;
                let label = crate::format::truncate(&e.label, label_w.max(8));
                let pad = label_w.saturating_sub(label.width());
                let style = if selected {
                    Style::default()
                        .fg(theme.text)
                        .bg(theme.background_element.unwrap_or(theme.border))
                        .add_modifier(Modifier::BOLD)
                } else {
                    st(theme.text)
                };
                lines.push(Line::from(vec![
                    Span::styled(if selected { "› " } else { "  " }, st(theme.accent)),
                    Span::styled(format!("{label}{}", " ".repeat(pad)), style),
                    Span::styled(format!("  {}", e.detail), muted),
                ]));
            }
            if p.shown.is_empty() {
                lines.push(Line::from(Span::styled("  no matches", muted)));
            }
            lines.push(Line::default());
            let help = match p.kind {
                PickerKind::Timeline => {
                    "↑↓ choose · Enter restore files + edit prompt · e edit prompt only · Esc close"
                }
                PickerKind::Theme => "↑↓ preview · Enter save · Esc restore",
                _ => "↑↓ choose · Enter select · Esc close",
            };
            lines.push(Line::from(Span::styled(help, muted)));
            (format!(" {} ", p.title), lines, theme.border_active, 96)
        }
        Dialog::Configure {
            explanation,
            changes,
        } => {
            let mut lines = Vec::new();
            for l in explanation.lines().take(8) {
                lines.push(Line::from(Span::styled(l.to_string(), st(theme.text))));
            }
            lines.push(Line::default());
            for c in changes {
                lines.push(Line::from(vec![
                    Span::styled("  • ", st(theme.accent)),
                    Span::styled(c.describe(), st(theme.text).add_modifier(Modifier::BOLD)),
                ]));
            }
            lines.push(Line::default());
            lines.push(Line::from(vec![
                key_chip(theme, "y", theme.success),
                Span::styled(" apply    ", st(theme.text)),
                key_chip(theme, "n", theme.border),
                Span::styled(" keep my settings", st(theme.text)),
            ]));
            (" Settings changes ".to_string(), lines, theme.accent, 90)
        }
        Dialog::Pager(_) | Dialog::Review(_) => unreachable!(),
    };
    let inner_width = width.min(area.width.saturating_sub(4)).saturating_sub(2);
    let wrapped_height: u16 = lines
        .iter()
        .map(|l| {
            let w: usize = l.spans.iter().map(|s| s.content.width()).sum();
            (w as u16).div_ceil(inner_width.max(1)).max(1)
        })
        .sum();
    let rect = centered(area, width, wrapped_height + 2);
    frame.render_widget(Clear, rect);
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(st(border))
        .padding(ratatui::widgets::Padding::horizontal(1))
        .title(Span::styled(title, st(border).add_modifier(Modifier::BOLD)));
    if let Some(bg) = theme.background_panel.or(theme.background) {
        block = block.style(Style::default().bg(bg));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        rect,
    );
}
