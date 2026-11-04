//! Drawing: header, transcript, status line, input box and dialogs.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use microclaw_code_core::project::Mode;

use super::{App, Dialog};

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn mode_style(mode: Mode) -> Style {
    let color = match mode {
        Mode::Plan => Color::Blue,
        Mode::Ask => Color::Green,
        Mode::Auto => Color::Yellow,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let input_width = area.width.saturating_sub(4) as usize;
    let (input_lines, cursor) = app.input.layout(input_width.max(2));
    let input_height = (input_lines.len() as u16).clamp(1, 8) + 2;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(input_height),
        ])
        .split(area);

    draw_header(frame, app, chunks[0]);
    draw_transcript(frame, app, chunks[1]);
    draw_status(frame, app, chunks[2]);

    // Input box; keep the cursor row visible when the text is taller.
    let inner_height = (input_height - 2) as usize;
    let first = cursor.0.saturating_sub(inner_height.saturating_sub(1));
    let visible: Vec<Line> = input_lines
        .iter()
        .skip(first)
        .take(inner_height)
        .map(|l| Line::raw(l.clone()))
        .collect();
    let title = if app.running.is_some() {
        " guide the agent (Enter) "
    } else {
        " message (Enter to send, Alt+Enter for a new line) "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(title, Style::default().fg(Color::DarkGray)));
    frame.render_widget(Paragraph::new(visible).block(block), chunks[3]);
    if app.dialog.is_none() {
        frame.set_cursor_position((
            chunks[3].x + 1 + cursor.1 as u16,
            chunks[3].y + 1 + (cursor.0 - first) as u16,
        ));
    }

    if let Some(dialog) = &app.dialog {
        draw_dialog(frame, dialog, area);
    }
}

pub(super) fn header_line(
    project_name: &str,
    branch: Option<&str>,
    mode: Mode,
    trusted: bool,
    session_label: &str,
) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            " MicroClaw Code ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            project_name.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(branch) = branch {
        spans.push(Span::styled(
            format!(" ({branch})"),
            Style::default().fg(Color::DarkGray),
        ));
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!("{} mode", mode.as_str()),
        mode_style(mode),
    ));
    if !trusted {
        spans.push(Span::styled(
            "  untrusted",
            Style::default().fg(Color::Yellow),
        ));
    }
    spans.push(Span::styled(
        format!("  {}", session_label),
        Style::default().fg(Color::DarkGray),
    ));
    Line::from(spans)
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let line = header_line(
        &app.project_name,
        app.branch.as_deref(),
        app.mode,
        app.trusted,
        &app.session_label,
    );
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_transcript(frame: &mut Frame, app: &mut App, area: Rect) {
    let lines = app.transcript.lines(area.width);
    let height = area.height as usize;
    let max_scroll = lines.len().saturating_sub(height);
    app.scroll = app.scroll.min(max_scroll);
    let start = lines.len().saturating_sub(height + app.scroll);
    let visible: Vec<Line> = lines.into_iter().skip(start).take(height).collect();
    frame.render_widget(Paragraph::new(visible), area);
    if app.scroll > 0 {
        let note = format!(" ↓ {} more lines (End) ", app.scroll);
        let w = note.chars().count() as u16;
        if area.width > w {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    note,
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                )),
                Rect::new(area.x + area.width - w, area.y + area.height - 1, w, 1),
            );
        }
    }
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let dim = Style::default().fg(Color::DarkGray);
    let line = if let Some(running) = &app.running {
        let tick = SPINNER[(running.started.elapsed().as_millis() / 100) as usize % SPINNER.len()];
        Line::from(vec![
            Span::styled(format!(" {tick} "), Style::default().fg(Color::Cyan)),
            Span::raw(format!("Working… {}s", running.started.elapsed().as_secs())),
            Span::styled("  ·  type to guide  ·  Esc to stop", dim),
        ])
    } else if let Some(hint) = &app.hint {
        Line::from(Span::styled(format!(" {hint}"), dim))
    } else {
        Line::from(vec![
            Span::styled(" Shift+Tab", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" mode  ·  ", dim),
            Span::styled("/help", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" commands  ·  ", dim),
            Span::styled("@path", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" + Tab to mention a file  ·  ", dim),
            Span::styled("PgUp/PgDn", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" scroll  ·  Ctrl+C twice to quit", dim),
        ])
    };
    frame.render_widget(Paragraph::new(line), area);
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

fn draw_dialog(frame: &mut Frame, dialog: &Dialog, area: Rect) {
    let (title, lines): (&str, Vec<Line>) = match dialog {
        Dialog::Approval(approval) => {
            let mut lines = vec![Line::from(Span::styled(
                format!("The agent wants to run {}:", approval.tool),
                Style::default().add_modifier(Modifier::BOLD),
            ))];
            if let Some(preview) = &approval.preview {
                for l in preview.lines().take(10) {
                    lines.push(Line::from(Span::styled(
                        format!("  {l}"),
                        Style::default().fg(Color::Yellow),
                    )));
                }
            }
            if let Some(advisory) = &approval.advisory {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    advisory.clone(),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            lines.push(Line::default());
            for option in &approval.options {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" {} ", option.value),
                        Style::default().fg(Color::Black).bg(Color::Cyan),
                    ),
                    Span::raw(format!(" {}", option.label)),
                ]));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press an option key · Esc denies",
                Style::default().fg(Color::DarkGray),
            )));
            (" Approval needed ", lines)
        }
        Dialog::Trust {
            root,
            has_config,
            changed,
        } => {
            let mut lines = vec![Line::from(Span::styled(
                format!("Trust {root}?"),
                Style::default().add_modifier(Modifier::BOLD),
            ))];
            if *changed {
                lines.push(Line::from(Span::styled(
                    "Its .microclaw/project.yaml changed since you last trusted it.",
                    Style::default().fg(Color::Yellow),
                )));
            }
            lines.push(Line::default());
            if *has_config {
                lines.push(Line::raw(
                    "Its .microclaw/project.yaml can set the permission mode, add instructions and define check commands.",
                ));
            }
            lines.push(Line::raw(
                "Trusted projects run their checks (build scripts included) automatically after edits.",
            ));
            lines.push(Line::raw("Untrusted projects ignore the project file."));
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled(" y ", Style::default().fg(Color::Black).bg(Color::Green)),
                Span::raw(" trust    "),
                Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Red)),
                Span::raw(" not now"),
            ]));
            (" Project trust ", lines)
        }
        Dialog::ExecutePlan => (
            " Plan ready ",
            vec![
                Line::raw("Execute this plan now?"),
                Line::default(),
                Line::from(vec![
                    Span::styled(" y ", Style::default().fg(Color::Black).bg(Color::Green)),
                    Span::raw(" switch to ask mode and run it    "),
                    Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
                    Span::raw(" keep planning"),
                ]),
            ],
        ),
    };
    let height = (lines.len() as u16 + 2).max(5);
    let rect = centered(area, 76, height + 2);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(Span::styled(
                    title,
                    Style::default().add_modifier(Modifier::BOLD),
                )),
        ),
        rect,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn header_renders_project_branch_and_mode() {
        let mut terminal = Terminal::new(TestBackend::new(80, 1)).unwrap();
        terminal
            .draw(|frame| {
                let line = header_line("repo2", Some("main"), Mode::Auto, false, "code-1");
                frame.render_widget(Paragraph::new(line), frame.area());
            })
            .unwrap();
        let row: String = (0..80)
            .map(|x| terminal.backend().buffer()[(x, 0)].symbol().to_string())
            .collect();
        assert!(
            row.starts_with(" MicroClaw Code  repo2 (main)  auto mode  untrusted  code-1"),
            "{row:?}"
        );
    }
}
