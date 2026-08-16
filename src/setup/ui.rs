use super::*;

pub(crate) const UI_FIELD_WINDOW: usize = 14;

// Box widgets with borders need at least 3 rows to render one content line.
// Header contains 2 content lines, so it needs at least 4 rows.
pub(crate) const UI_HEADER_HEIGHT: u16 = 4;

pub(crate) const UI_STATUS_HEIGHT: u16 = 3;

pub(crate) fn field_window_for_area(area: Rect) -> usize {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(UI_HEADER_HEIGHT),
            Constraint::Min(14),
            Constraint::Length(UI_STATUS_HEIGHT),
        ])
        .split(area);
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);
    let left_inner = body_chunks[0].inner(Margin::new(1, 0));
    left_inner.height.saturating_sub(2).max(1) as usize
}

pub(crate) fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &SetupApp) {
    if app.completed {
        let done = Paragraph::new(vec![
            Line::from(Span::styled(
                "✅ Setup saved successfully",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Checks:"),
            Line::from(
                app.completion_summary
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Config validated".into()),
            ),
            Line::from(app.completion_summary.get(1).cloned().unwrap_or_default()),
            Line::from(""),
            Line::from(format!(
                "Backup: {}",
                app.backup_path.as_deref().unwrap_or("none")
            )),
            Line::from(""),
            Line::from("Next:"),
            Line::from("  1) microclaw start"),
            Line::from(""),
            Line::from("Press Enter to finish."),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Setup Complete"),
        );
        frame.render_widget(done, frame.area().inner(Margin::new(2, 2)));
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(UI_HEADER_HEIGHT),
            Constraint::Min(14),
            Constraint::Length(UI_STATUS_HEIGHT),
        ])
        .split(frame.area());

    let (selected_visible, visible_total) = app.selected_progress();
    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "MicroClaw • Interactive Setup",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                format!(
                    "Field {}/{}  ·  Section: {}  ·  ",
                    selected_visible,
                    visible_total,
                    app.current_section()
                ),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(app.progress_bar(16), Style::default().fg(Color::LightCyan)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let mut lines = Vec::<Line>::new();
    let mut last_section = "";
    let visible_indices = app.visible_field_indices();
    let left_inner = body_chunks[0].inner(Margin::new(1, 0));
    let start = app
        .field_scroll
        .min(visible_indices.len().saturating_sub(1));
    let end = app.window_end_for_start_pos(&visible_indices, start, app.field_window.max(1));
    for i in visible_indices[start..end].iter().copied() {
        let f = &app.fields[i];
        let section = SetupApp::section_for_key(&f.key);
        if section != last_section {
            if !lines.is_empty() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!("[{}]", section),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )));
            last_section = section;
        }

        let selected = i == app.selected;
        let is_required = app.is_field_required(f);
        // Mark every field so "unmarked" is never ambiguous: required fields
        // must be filled before saving; optional ones can be left blank.
        let label = if is_required {
            format!("{}  [required]", f.label)
        } else {
            format!("{}  [optional]", f.label)
        };
        let value = if f.key == "LLM_PROVIDER" {
            provider_display(&f.value)
        } else if let Some(provider_key) = SetupApp::llm_provider_key_for_model_field(&f.key) {
            let provider = app.field_value(&provider_key);
            if provider.is_empty() {
                "main".to_string()
            } else {
                provider
            }
        } else if f.key == llm_provider_profiles_key() {
            let presets = app.llm_provider_presets();
            if presets.is_empty() {
                String::new()
            } else {
                let mut ids: Vec<String> = presets.keys().cloned().collect();
                ids.sort();
                format!("{} preset(s): {}", ids.len(), ids.join(", "))
            }
        } else {
            f.display_value(selected && app.editing)
        };
        let prefix = if selected { "▶" } else { " " };
        let color = if selected {
            Color::Yellow
        } else {
            Color::White
        };
        let label_text = format!("{} {}: ", prefix, label);
        let line_width = left_inner.width.max(1) as usize;
        let max_value_chars = line_width.saturating_sub(label_text.chars().count()).max(1);
        let value_single_line = truncate_single_line(&value, max_value_chars);
        lines.push(Line::from(vec![
            Span::styled(label_text, Style::default().fg(color)),
            Span::styled(value_single_line, Style::default().fg(Color::Green)),
        ]));
    }
    if end < visible_indices.len() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("… more fields below ({}/{})", end, visible_indices.len()),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let body = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Fields"));
    frame.render_widget(body, left_inner);

    let field = app.selected_field();
    let (field_desc, field_example_raw) = SetupApp::field_guidance(&field.key);
    let field_example = field_example_raw
        .strip_prefix("Example: ")
        .unwrap_or(field_example_raw);
    let is_required = app.is_field_required(field);
    let mut help_lines = vec![
        Line::from(vec![
            Span::styled("Key: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                SetupApp::key_display(&field.key),
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(vec![
            Span::styled("Required: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if is_required { "yes" } else { "no" }),
        ]),
        Line::from(vec![
            Span::styled("Editing: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if app.editing { "active" } else { "idle" }),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("What: ", Style::default().fg(Color::DarkGray)),
            Span::raw(field_desc),
        ]),
    ];
    if !field_example.is_empty() {
        help_lines.push(Line::from(vec![
            Span::styled("Example: ", Style::default().fg(Color::DarkGray)),
            Span::styled(field_example, Style::default().fg(Color::LightGreen)),
        ]));
    }
    if !is_required {
        let default_value = if field.key == "LLM_USER_AGENT" {
            crate::http_client::default_llm_user_agent()
        } else {
            app.default_value_for_field(&field.key)
        };
        let default_display = if default_value.trim().is_empty() {
            "(empty)".to_string()
        } else {
            default_value
        };
        help_lines.push(Line::from(vec![
            Span::styled("Default value: ", Style::default().fg(Color::DarkGray)),
            Span::styled(default_display, Style::default().fg(Color::LightBlue)),
        ]));
    }
    help_lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "Tips",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("• Enter: edit field / open selection list"),
        Line::from("• Enter on any channel model override: open channel LLM page"),
        Line::from("• Channels picker: Space toggle, Enter apply"),
        Line::from("• Tab / Shift+Tab: next/prev field"),
        Line::from("• ↑/↓ or j/k or Ctrl+N/Ctrl+P: move"),
        Line::from("• In selection list: Enter confirm, Esc close"),
        Line::from("• PgUp/PgDn or Ctrl+U/Ctrl+F: page up/down"),
        Line::from("• g / G: jump to top / bottom"),
        Line::from("• ←/→ on provider/model: rotate presets"),
        Line::from("• e: force manual text edit"),
        Line::from("• Ctrl+D / Del: clear field"),
        Line::from("• Ctrl+R: restore field default"),
        Line::from("• F2: validate + online checks"),
        Line::from("• s: save with online validation"),
        Line::from("• Ctrl+S / Ctrl+Shift+S: save without online model validation"),
    ]);
    let help = Paragraph::new(help_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Details / Help"),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(help, body_chunks[1].inner(Margin::new(1, 0)));

    let (status_icon, status_color) =
        if app.status.contains("failed") || app.status.contains("Cannot save") {
            ("✖ ", Color::LightRed)
        } else if app.status.contains("saved") || app.status.contains("Saved") {
            ("✔ ", Color::LightGreen)
        } else {
            ("• ", Color::White)
        };
    let status = Paragraph::new(vec![Line::from(vec![
        Span::styled(status_icon, Style::default().fg(status_color)),
        Span::styled(app.status.clone(), Style::default().fg(status_color)),
    ])])
    .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);

    if let Some(page) = &app.provider_preset_page {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        if let Some(picker) = &page.picker {
            let mut list_lines = Vec::with_capacity(picker.options.len());
            for (i, (label, _)) in picker.options.iter().enumerate() {
                let selected = i == picker.selected;
                let pointer = if selected { "▶ " } else { "  " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                list_lines.push(Line::from(Span::styled(format!("{pointer}{label}"), style)));
            }
            let overlay = Paragraph::new(list_lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Preset Picker")
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        } else if page.mode == ProviderPresetPageMode::List {
            let mut lines = Vec::new();
            let next_id_hint = SetupApp::next_provider_preset_id(&page.entries);
            if page.entries.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No provider profiles yet. Press a to add one.",
                    Style::default().fg(Color::White),
                )));
            } else {
                for (idx, entry) in page.entries.iter().enumerate() {
                    let selected = idx == page.selected;
                    let pointer = if selected { "▶ " } else { "  " };
                    let model = if entry.default_model.trim().is_empty() {
                        "(no default model)".to_string()
                    } else {
                        entry.default_model.clone()
                    };
                    let ref_summary = app.provider_preset_reference_summary(&entry.id);
                    let in_use_marker = if ref_summary == "unused" {
                        String::new()
                    } else {
                        "  IN USE".to_string()
                    };
                    let summary = format!(
                        "{}  {} / {}  [{}]{}",
                        entry.id, entry.provider, model, ref_summary, in_use_marker
                    );
                    let style = if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{pointer}{summary}"),
                        style,
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "----------------------------------------------------------------",
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(Span::styled(
                format!("Next default preset id: {next_id_hint}"),
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(Span::styled(
                "a add · c clone · Enter edit · d delete only if unused · x reset refs to main and delete · Esc close",
                Style::default().fg(Color::White),
            )));
            let overlay = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Provider Profiles")
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        } else {
            let labels = SetupApp::provider_preset_field_labels();
            let mut lines = Vec::new();
            if let Some(entry) = page.entries.get(page.selected) {
                for (idx, label) in labels.iter().enumerate() {
                    let selected = idx == page.field_selected;
                    let pointer = if selected { "▶ " } else { "  " };
                    let raw = match idx {
                        0 => entry.id.clone(),
                        1 => entry.provider.clone(),
                        2 => {
                            if selected && page.editing {
                                entry.api_key.clone()
                            } else {
                                mask_secret(&entry.api_key)
                            }
                        }
                        3 => entry.default_model.clone(),
                        4 => entry.base_url.clone(),
                        5 => entry.show_thinking.to_string(),
                        6 => entry.user_agent.clone(),
                        _ => String::new(),
                    };
                    let style = if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{pointer}{label}: {raw}"),
                        style,
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "----------------------------------------------------------------",
                    Style::default().fg(Color::Gray),
                )));
                let refs = app.provider_preset_references(&entry.id);
                lines.push(Line::from(Span::styled(
                    format!(
                        "References: {}",
                        if refs.is_empty() {
                            "none".to_string()
                        } else {
                            refs.join(", ")
                        }
                    ),
                    Style::default().fg(Color::Gray),
                )));
                lines.push(Line::from(Span::styled(
                    "Delete actions: d = delete only when unused; x = reset all refs to main, then delete",
                    Style::default().fg(Color::White),
                )));
                lines.push(Line::from(Span::styled(
                    "Use d when you expect zero references. Use x when this preset is still attached somewhere.",
                    Style::default().fg(Color::Gray),
                )));
                if entry.id.strip_prefix("provider").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
                }) {
                    lines.push(Line::from(Span::styled(
                        "Tip: providerN ids are convenient for sequential presets; descriptive ids also work.",
                        Style::default().fg(Color::Gray),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "Tip: next default preset id would be {}",
                            SetupApp::next_provider_preset_id(&page.entries)
                        ),
                        Style::default().fg(Color::Gray),
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter edit/select · t test current profile · Esc back · ↑/↓ move · Ctrl+D clear · Ctrl+R default",
                Style::default().fg(Color::White),
            )));
            let overlay = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Provider Profile Detail")
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        }
    } else if let Some(picker) = &app.llm_override_picker {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        let mut list_lines = Vec::with_capacity(picker.options.len());
        for (i, (label, _)) in picker.options.iter().enumerate() {
            let selected = i == picker.selected;
            let pointer = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            list_lines.push(Line::from(Span::styled(format!("{pointer}{label}"), style)));
        }
        let overlay = Paragraph::new(list_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(picker.title.as_str())
                    .style(Style::default().bg(Color::Black)),
            )
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(Clear, overlay_area);
        frame.render_widget(overlay, overlay_area);
    } else if let Some(page) = &app.llm_override_page {
        let overlay_area = frame.area().inner(Margin::new(6, 3));
        {
            let keys = SetupApp::llm_override_keys_for_page(page);
            let mut lines = Vec::new();
            for (idx, key) in keys.iter().enumerate() {
                let selected = idx == page.selected;
                let pointer = if selected { "▶ " } else { "  " };
                let label = SetupApp::llm_override_label_for_key(key);
                let raw = app.field_value(key);
                let value = if *key == page.api_key_key.as_str() {
                    if selected && page.editing {
                        raw
                    } else {
                        mask_secret(&raw)
                    }
                } else if *key == page.provider_key.as_str() && raw.trim().is_empty() {
                    "main (global default)".to_string()
                } else {
                    raw
                };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                lines.push(Line::from(Span::styled(
                    format!("{pointer}{label}: {value}"),
                    style,
                )));
            }
            lines.push(Line::from(""));
            if !page.show_legacy_fields {
                lines.push(Line::from(Span::styled(
                    "Using preset-only mode. Legacy API/base-url fields stay hidden until an old override exists.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                "Enter edit/select · Esc close · ↑/↓/j/k/Ctrl+N/Ctrl+P move",
                Style::default().fg(Color::DarkGray),
            )));
            let overlay = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(page.title.as_str())
                        .style(Style::default().bg(Color::Black)),
                )
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(Clear, overlay_area);
            frame.render_widget(overlay, overlay_area);
        }
    } else if let Some(picker) = &app.picker {
        let overlay_area = frame.area().inner(Margin::new(8, 4));
        let (title, options): (&str, Vec<String>) = match picker.kind {
            PickerKind::Provider => (
                "Select LLM Provider",
                PROVIDER_PRESETS
                    .iter()
                    .map(|p| format!("{} - {}", p.id, p.label))
                    .collect(),
            ),
            PickerKind::Model => ("Select LLM Model", app.model_picker_options()),
            PickerKind::Channels => (
                "Select Channels (Space=toggle, Enter=apply)",
                SetupApp::channel_options()
                    .iter()
                    .map(|c| (*c).to_string())
                    .collect(),
            ),
            PickerKind::SoulPath => (
                "Select SOUL.md (Enter=apply, choose manual to type filename)",
                app.soul_picker_options(),
            ),
            PickerKind::Timezone => (
                "Select Timezone (Enter=apply, choose custom to type IANA name)",
                app.timezone_picker_options(),
            ),
        };
        let mut list_lines = Vec::with_capacity(options.len());
        for (i, item) in options.iter().enumerate() {
            let selected = i == picker.selected;
            let pointer = if selected { "▶ " } else { "  " };
            let checkbox = if picker.kind == PickerKind::Channels {
                if picker.selected_multi.get(i).copied().unwrap_or(false) {
                    "[x] "
                } else {
                    "[ ] "
                }
            } else {
                ""
            };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            list_lines.push(Line::from(Span::styled(
                format!("{pointer}{checkbox}{item}"),
                style,
            )));
        }
        let overlay = Paragraph::new(list_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .style(Style::default().bg(Color::Black)),
            )
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(Clear, overlay_area);
        frame.render_widget(overlay, overlay_area);
    }
}
