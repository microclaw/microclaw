use super::*;

pub(crate) fn run_with_spinner<T, F>(
    terminal: &mut DefaultTerminal,
    app: &mut SetupApp,
    label: &str,
    work: F,
) -> Result<T, MicroClawError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, MicroClawError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Result<T, MicroClawError>>();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });

    let frames = ["-", "\\", "|", "/"];
    let mut i = 0usize;
    loop {
        app.status = format!("{label} {}", frames[i % frames.len()]);
        terminal.draw(|f| draw_ui(f, app))?;
        i += 1;

        match rx.recv_timeout(Duration::from_millis(120)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(MicroClawError::Config(
                    "save worker disconnected unexpectedly".into(),
                ));
            }
        }
    }
}

pub(crate) fn run_wizard(mut terminal: DefaultTerminal) -> Result<bool, MicroClawError> {
    let mut app = SetupApp::new();

    loop {
        if let Ok(size) = terminal.size() {
            let area = Rect::new(0, 0, size.width, size.height);
            app.field_window = field_window_for_area(area);
        }
        app.ensure_selected_visible();
        terminal.draw(|f| draw_ui(f, &app))?;
        if event::poll(Duration::from_millis(250))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if app.completed {
                match key.code {
                    KeyCode::Enter | KeyCode::Char('q') => return Ok(true),
                    _ => continue,
                }
            }

            if app.provider_preset_page.is_some() {
                let mode = app
                    .provider_preset_page
                    .as_ref()
                    .map(|page| page.mode)
                    .unwrap_or(ProviderPresetPageMode::List);
                let field_count = SetupApp::provider_preset_field_labels().len();
                let picker_open = app
                    .provider_preset_page
                    .as_ref()
                    .and_then(|page| page.picker.as_ref())
                    .is_some();
                if picker_open {
                    match key.code {
                        KeyCode::Esc => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.picker = None;
                            }
                            app.status = "Selection closed".into();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = picker.selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = (picker.selected + 1)
                                        .min(picker.options.len().saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = picker.selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if let Some(picker) = page.picker.as_mut() {
                                    picker.selected = (picker.selected + 1)
                                        .min(picker.options.len().saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Enter => app.apply_provider_preset_picker_selection(),
                        _ => {}
                    }
                    continue;
                }
                match mode {
                    ProviderPresetPageMode::List => match key.code {
                        KeyCode::Esc => {
                            app.provider_preset_page = None;
                            app.status = "Closed provider profiles".into();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected =
                                    (page.selected + 1).min(page.entries.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.selected =
                                    (page.selected + 1).min(page.entries.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Char('a') => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                let next_id = SetupApp::next_provider_preset_id(&page.entries);
                                page.entries.push(ProviderPresetDraft {
                                    id: next_id,
                                    provider: "anthropic".to_string(),
                                    api_key: String::new(),
                                    base_url: String::new(),
                                    user_agent: String::new(),
                                    default_model: default_model_for_provider("anthropic")
                                        .to_string(),
                                    show_thinking: false,
                                });
                                page.selected = page.entries.len().saturating_sub(1);
                                page.mode = ProviderPresetPageMode::Edit;
                                page.field_selected = 0;
                                page.editing = true;
                            }
                            let _ = app.sync_provider_preset_page_field();
                            app.status = "Added provider profile".into();
                        }
                        KeyCode::Char('c') => match app.clone_selected_provider_preset() {
                            Ok(Some(cloned_id)) => {
                                app.status = format!("Cloned provider profile as {cloned_id}")
                            }
                            Ok(None) => app.status = "No provider profile selected to clone".into(),
                            Err(e) => app.status = e.to_string(),
                        },
                        KeyCode::Char('d') => match app.delete_selected_provider_preset(false) {
                            Ok(_) => app.status = "Deleted provider profile".into(),
                            Err(e) => app.status = e.to_string(),
                        },
                        KeyCode::Char('x') => match app.delete_selected_provider_preset(true) {
                            Ok(reset_refs) => {
                                if reset_refs.is_empty() {
                                    app.status =
                                        "Deleted provider profile (no references needed reset)"
                                            .into();
                                } else {
                                    app.status = format!(
                                        "Reset to main and deleted provider preset: {}",
                                        reset_refs.join(", ")
                                    );
                                }
                            }
                            Err(e) => app.status = e.to_string(),
                        },
                        KeyCode::Enter => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if page.entries.is_empty() {
                                    page.entries.push(ProviderPresetDraft {
                                        id: SetupApp::next_provider_preset_id(&page.entries),
                                        provider: "anthropic".to_string(),
                                        api_key: String::new(),
                                        base_url: String::new(),
                                        user_agent: String::new(),
                                        default_model: default_model_for_provider("anthropic")
                                            .to_string(),
                                        show_thinking: false,
                                    });
                                    page.selected = 0;
                                }
                                page.mode = ProviderPresetPageMode::Edit;
                                page.field_selected = 0;
                                page.editing = false;
                            }
                            let _ = app.sync_provider_preset_page_field();
                            app.status = "Editing provider profile".into();
                        }
                        _ => {}
                    },
                    ProviderPresetPageMode::Edit => match key.code {
                        KeyCode::Esc => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if page.editing {
                                    page.editing = false;
                                    app.status = "Preset field edit canceled".into();
                                } else {
                                    page.mode = ProviderPresetPageMode::List;
                                    page.field_selected = 0;
                                    app.status = "Back to provider profile list".into();
                                }
                            }
                        }
                        KeyCode::Char('t')
                            if app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| !page.editing)
                                .unwrap_or(false) =>
                        {
                            let profile_id = app
                                .provider_preset_page
                                .as_ref()
                                .and_then(|page| page.entries.get(page.selected))
                                .map(|entry| entry.id.clone())
                                .unwrap_or_else(|| "current".to_string());
                            let app_for_online = app.clone();
                            match run_with_spinner(
                                &mut terminal,
                                &mut app,
                                &format!("Testing model for provider profile {profile_id}"),
                                move || app_for_online.validate_selected_provider_preset_online(),
                            ) {
                                Ok((validated_profile_id, checks)) => {
                                    app.status = format!(
                                        "Model test for {validated_profile_id} passed: {}",
                                        checks.join(" | ")
                                    );
                                }
                                Err(e) => {
                                    app.status = format!("Model test for {profile_id} failed: {e}");
                                }
                            }
                        }
                        KeyCode::Up => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = page.field_selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Down => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = (page.field_selected + 1)
                                        .min(field_count.saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Char('k')
                            if app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| !page.editing)
                                .unwrap_or(false) =>
                        {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.field_selected = page.field_selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('j')
                            if app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| !page.editing)
                                .unwrap_or(false) =>
                        {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.field_selected =
                                    (page.field_selected + 1).min(field_count.saturating_sub(1));
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = page.field_selected.saturating_sub(1);
                                }
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                if !page.editing {
                                    page.field_selected = (page.field_selected + 1)
                                        .min(field_count.saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Enter => {
                            app.handle_provider_preset_enter();
                        }
                        KeyCode::Backspace => {
                            let editing = app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| page.editing)
                                .unwrap_or(false);
                            if editing {
                                let mut value = app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(SetupApp::provider_preset_selected_field_value)
                                    .unwrap_or_default();
                                value.pop();
                                app.set_provider_preset_selected_field_value(value);
                                let _ = app.sync_provider_preset_page_field();
                            }
                        }
                        KeyCode::Char('d')
                            if key.modifiers.contains(KeyModifiers::CONTROL)
                                && app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(|page| !page.editing)
                                    .unwrap_or(false) =>
                        {
                            app.clear_selected_provider_preset_field();
                            let _ = app.sync_provider_preset_page_field();
                            if let Some(page) = app.provider_preset_page.as_mut() {
                                page.editing = false;
                            }
                            app.status = "Cleared provider profile field".into();
                        }
                        KeyCode::Char('r')
                            if key.modifiers.contains(KeyModifiers::CONTROL)
                                && app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(|page| !page.editing)
                                    .unwrap_or(false) =>
                        {
                            match app.restore_selected_provider_preset_field_default() {
                                Some(default) => {
                                    let _ = app.sync_provider_preset_page_field();
                                    if let Some(page) = app.provider_preset_page.as_mut() {
                                        page.editing = false;
                                    }
                                    app.status = if default.is_empty() {
                                        "Restored provider profile field to default (empty)".into()
                                    } else {
                                        format!(
                                            "Restored provider profile field to default: {default}"
                                        )
                                    };
                                }
                                None => {
                                    app.status =
                                        "Selected provider profile field has no default".into();
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            let editing = app
                                .provider_preset_page
                                .as_ref()
                                .map(|page| page.editing)
                                .unwrap_or(false);
                            if editing {
                                let mut value = app
                                    .provider_preset_page
                                    .as_ref()
                                    .map(SetupApp::provider_preset_selected_field_value)
                                    .unwrap_or_default();
                                value.push(c);
                                app.set_provider_preset_selected_field_value(value);
                                let _ = app.sync_provider_preset_page_field();
                            }
                        }
                        _ => {}
                    },
                }
                continue;
            }

            if app.llm_override_picker.is_some() && app.llm_override_page.is_none() {
                match key.code {
                    KeyCode::Esc => {
                        app.llm_override_picker = None;
                        app.status = "Selection closed".into();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected = picker.selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected =
                                (picker.selected + 1).min(picker.options.len().saturating_sub(1));
                        }
                    }
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected = picker.selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(picker) = app.llm_override_picker.as_mut() {
                            picker.selected =
                                (picker.selected + 1).min(picker.options.len().saturating_sub(1));
                        }
                    }
                    KeyCode::Enter => app.apply_llm_override_picker_selection(),
                    _ => {}
                }
                continue;
            }

            if app.llm_override_page.is_some() {
                let keys: Vec<String> = if let Some(page) = app.llm_override_page.as_ref() {
                    SetupApp::llm_override_keys_for_page(page)
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect()
                } else {
                    Vec::new()
                };
                if app.llm_override_picker.is_some() {
                    match key.code {
                        KeyCode::Esc => {
                            app.llm_override_picker = None;
                            app.status = "Selection closed".into();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = picker.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = (picker.selected + 1)
                                    .min(picker.options.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = picker.selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(picker) = app.llm_override_picker.as_mut() {
                                picker.selected = (picker.selected + 1)
                                    .min(picker.options.len().saturating_sub(1));
                            }
                        }
                        KeyCode::Enter => app.apply_llm_override_picker_selection(),
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Esc => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if page.editing {
                                page.editing = false;
                                app.status = "LLM override field edit canceled".into();
                            } else {
                                app.llm_override_page = None;
                                app.status = "Closed channel LLM page".into();
                            }
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected =
                                    (page.selected + 1).min(keys.len().saturating_sub(1));
                            }
                        }
                    }
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected = page.selected.saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(page) = app.llm_override_page.as_mut() {
                            if !page.editing {
                                page.selected =
                                    (page.selected + 1).min(keys.len().saturating_sub(1));
                            }
                        }
                    }
                    KeyCode::Enter => {
                        let (selected_key, provider_key, editing) =
                            if let Some(page) = app.llm_override_page.as_ref() {
                                (
                                    keys.get(page.selected).cloned().unwrap_or_default(),
                                    page.provider_key.clone(),
                                    page.editing,
                                )
                            } else {
                                (String::new(), String::new(), false)
                            };
                        if editing {
                            if let Some(page) = app.llm_override_page.as_mut() {
                                page.editing = false;
                            }
                            app.status = "Updated channel LLM override field".into();
                        } else if selected_key == provider_key {
                            app.open_llm_override_provider_picker();
                        } else if let Some(page) = app.llm_override_page.as_mut() {
                            page.editing = true;
                            app.status = "Editing channel LLM override field".into();
                        }
                    }
                    KeyCode::Backspace => {
                        let (editing, selected) = if let Some(page) = app.llm_override_page.as_ref()
                        {
                            (page.editing, page.selected)
                        } else {
                            (false, 0)
                        };
                        if editing {
                            let Some(key_name) = keys.get(selected) else {
                                continue;
                            };
                            if let Some(field) = app.fields.iter_mut().find(|f| f.key == *key_name)
                            {
                                field.value.pop();
                            }
                        }
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let (editing, selected) = if let Some(page) = app.llm_override_page.as_ref()
                        {
                            (page.editing, page.selected)
                        } else {
                            (false, 0)
                        };
                        if editing {
                            let Some(key_name) = keys.get(selected) else {
                                continue;
                            };
                            app.set_field_value(key_name, String::new());
                        }
                    }
                    KeyCode::Char(c) => {
                        let (editing, selected) = if let Some(page) = app.llm_override_page.as_ref()
                        {
                            (page.editing, page.selected)
                        } else {
                            (false, 0)
                        };
                        if editing {
                            let Some(key_name) = keys.get(selected) else {
                                continue;
                            };
                            let mut next = app.field_value(key_name);
                            next.push(c);
                            app.set_field_value(key_name, next);
                        }
                    }
                    _ => {}
                }
                continue;
            }

            if app.picker.is_some() {
                match key.code {
                    KeyCode::Esc => {
                        app.picker = None;
                        app.status = "Selection closed".into();
                    }
                    KeyCode::Up => app.move_picker(-1),
                    KeyCode::Down => app.move_picker(1),
                    KeyCode::Char('k') => app.move_picker(-1),
                    KeyCode::Char('j') => app.move_picker(1),
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.move_picker(-1)
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.move_picker(1)
                    }
                    KeyCode::Char(' ') => app.toggle_picker_multi(),
                    KeyCode::Enter => app.apply_picker_selection(),
                    _ => {}
                }
                continue;
            }

            if app.editing {
                match key.code {
                    KeyCode::Esc => {
                        app.editing = false;
                        app.status = "Edit canceled".into();
                    }
                    KeyCode::Enter => {
                        app.editing = false;
                        app.status = format!("Updated {}", app.selected_field().key);
                    }
                    KeyCode::Backspace => {
                        app.selected_field_mut().value.pop();
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.clear_selected_field();
                    }
                    KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.restore_selected_field_default();
                    }
                    KeyCode::Char(c) => {
                        app.selected_field_mut().value.push(c);
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') => return Ok(false),
                KeyCode::Up => app.prev(),
                KeyCode::Down => app.next(),
                KeyCode::Char('k') => app.prev(),
                KeyCode::Char('j') => app.next(),
                KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => app.prev(),
                KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => app.next(),
                KeyCode::PageDown => app.page_down(app.field_window.max(1)),
                KeyCode::PageUp => app.page_up(app.field_window.max(1)),
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.page_up(app.field_window.max(1))
                }
                KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.page_down(app.field_window.max(1))
                }
                KeyCode::Char('g') if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                    app.jump_top()
                }
                KeyCode::Char('G') => app.jump_bottom(),
                KeyCode::Tab => app.next(),
                KeyCode::BackTab => app.prev(),
                KeyCode::Enter => {
                    let selected_key = app.selected_field().key.clone();
                    if app.open_llm_override_page_for_field(&selected_key) {
                        app.status = format!("Editing {}", selected_key);
                    } else if app.open_picker_for_selected() {
                        app.status = format!("Selecting {}", app.selected_field().key);
                    } else {
                        app.editing = true;
                        app.status = format!("Editing {}", app.selected_field().key);
                    }
                }
                KeyCode::Left => {
                    if app.selected_field().key == "LLM_PROVIDER" {
                        app.cycle_provider(-1);
                        app.status = format!("Provider set to {}", app.field_value("LLM_PROVIDER"));
                    } else if app.selected_field().key == "LLM_MODEL" {
                        app.cycle_model(-1);
                        app.status = format!("Model set to {}", app.field_value("LLM_MODEL"));
                    }
                }
                KeyCode::Right => {
                    if app.selected_field().key == "LLM_PROVIDER" {
                        app.cycle_provider(1);
                        app.status = format!("Provider set to {}", app.field_value("LLM_PROVIDER"));
                    } else if app.selected_field().key == "LLM_MODEL" {
                        app.cycle_model(1);
                        app.status = format!("Model set to {}", app.field_value("LLM_MODEL"));
                    }
                }
                KeyCode::Char('e') => {
                    let selected_key = app.selected_field().key.clone();
                    if selected_key == llm_provider_profiles_key() {
                        app.open_provider_preset_page();
                        app.status = "Editing provider profiles".into();
                    } else if app.open_llm_override_page_for_field(&selected_key) {
                        app.status = format!("Editing {}", selected_key);
                    } else {
                        app.editing = true;
                        app.status = format!("Editing {}", app.selected_field().key);
                    }
                }
                KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.clear_selected_field();
                }
                KeyCode::Delete => {
                    app.clear_selected_field();
                }
                KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.restore_selected_field_default();
                }
                KeyCode::F(2) => match app.validate_local().and_then(|_| app.validate_online()) {
                    Ok(checks) => app.status = format!("Validation passed: {}", checks.join(" | ")),
                    Err(e) => app.status = format!("Validation failed: {e}"),
                },
                KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    try_save_skip_online(&mut terminal, &mut app)?;
                }
                KeyCode::Char('S') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    try_save_skip_online(&mut terminal, &mut app)?;
                }
                KeyCode::Char('s') => {
                    try_save(&mut terminal, &mut app)?;
                }
                _ => {}
            }
        }
    }
}

pub fn run_setup_wizard() -> Result<bool, MicroClawError> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let terminal = ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(stdout))?;
    let result = run_wizard(terminal);
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

pub fn enable_sandbox_in_config() -> Result<String, MicroClawError> {
    let Some(path) = Config::resolve_config_path()? else {
        return Err(MicroClawError::Config(
            "No microclaw.config.yaml found. Run `microclaw setup` first.".to_string(),
        ));
    };
    let mut cfg = Config::load()?;
    let before_cfg = cfg.clone();
    cfg.sandbox.mode = SandboxMode::All;
    cfg.sandbox.backend = SandboxBackend::Auto;
    cfg.sandbox.no_network = true;
    cfg.sandbox.require_runtime = true;
    crate::config_persistence::save_config_delta_preserving_comments(&path, &before_cfg, &cfg)?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

    #[test]
    fn test_enable_sandbox_in_config_updates_mode() {
        let _guard = env_lock();
        let path = std::env::temp_dir().join(format!(
            "microclaw_setup_enable_sandbox_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(
            &path,
            r#"
llm_provider: "anthropic"
api_key: "k"
model: "claude-sonnet-4-5-20250929"
telegram_bot_token: "tok"
bot_username: "bot"
sandbox:
  mode: "off"
"#,
        )
        .unwrap();
        std::env::set_var("MICROCLAW_CONFIG", &path);
        let out = enable_sandbox_in_config().unwrap();
        assert!(out.contains(path.to_string_lossy().as_ref()));
        let cfg = Config::load().unwrap();
        assert!(matches!(cfg.sandbox.mode, SandboxMode::All));
        assert!(cfg.sandbox.require_runtime);
        std::env::remove_var("MICROCLAW_CONFIG");
        let _ = std::fs::remove_file(path);
    }
}
