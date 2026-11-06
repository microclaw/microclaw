//! Keyboard handling: the input box, completion popups, configurable
//! actions and dialogs.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use microclaw_code_core::driver::Control;
use microclaw_code_core::project::Mode;

use super::dialogs::{Dialog, PickerKind};
use super::keymap::Action;
use super::pager::{Pager, PagerKey};
use super::popup::{Entry, Popup, PopupKind};
use super::review::{ReviewKey, ReviewOutcome};
use super::transcript::Tone;
use super::{App, commands::SLASH_COMMANDS};

/// Text to edit in `$EDITOR` (the TUI suspends while it runs).
pub struct EditorRequest {
    pub text: String,
    /// Read-only view (pager): the result is discarded.
    pub view_only: bool,
}

const DOUBLE_ESC: Duration = Duration::from_millis(600);

impl App {
    /// Handle a key; returns an editor request when the TUI must suspend.
    pub(super) fn on_key(&mut self, key: KeyEvent) -> Option<EditorRequest> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        if !matches!(key.code, KeyCode::Char('c') if ctrl) {
            self.quit_armed = None;
        }
        if self.dialog.is_some() {
            return self.on_dialog_key(key);
        }
        self.hint = None;

        if matches!(key.code, KeyCode::Char('c') if ctrl) {
            if self.running.is_some() {
                self.send(Control::Cancel);
                self.goal = None;
                self.hint = Some("stopping…".into());
            } else if !self.input.is_empty() || self.shell_mode {
                self.input.clear();
                self.shell_mode = false;
                self.popup = None;
            } else if self
                .quit_armed
                .is_some_and(|at| at.elapsed() < Duration::from_secs(2))
            {
                self.should_quit = true;
            } else {
                self.quit_armed = Some(Instant::now());
                self.hint = Some("press Ctrl+C again to quit".into());
            }
            return None;
        }

        // Popup navigation.
        if self.popup.is_some() {
            match key.code {
                KeyCode::Up => {
                    self.popup.as_mut().unwrap().up();
                    return None;
                }
                KeyCode::Down => {
                    self.popup.as_mut().unwrap().down();
                    return None;
                }
                KeyCode::Esc => {
                    self.popup = None;
                    return None;
                }
                KeyCode::Tab => {
                    self.accept_popup(false);
                    return None;
                }
                KeyCode::Enter if !alt && !key.modifiers.contains(KeyModifiers::SHIFT) => {
                    let submit = self
                        .popup
                        .as_ref()
                        .is_some_and(|p| p.kind != PopupKind::File);
                    self.accept_popup(submit);
                    return None;
                }
                _ => {}
            }
        }

        if let Some(action) = self.keymap.action(&key) {
            return self.on_action(action);
        }

        match key.code {
            KeyCode::Char('d') if ctrl && self.input.is_empty() && self.running.is_none() => {
                self.should_quit = true;
            }
            KeyCode::Esc => {
                if self.running.is_some() {
                    self.send(Control::Cancel);
                    self.goal = None;
                    self.hint = Some("stopping…".into());
                } else if self.shell_mode {
                    self.shell_mode = false;
                } else if self.last_esc.is_some_and(|t| t.elapsed() < DOUBLE_ESC) {
                    self.last_esc = None;
                    self.open_timeline();
                } else {
                    self.last_esc = Some(Instant::now());
                    if self.input.is_empty() {
                        self.hint = Some("Esc again to rewind to an earlier turn".into());
                    }
                }
            }
            KeyCode::Enter => {
                let text = self.input.text();
                if let Some(stripped) = text.strip_suffix('\\') {
                    self.input.set_text(&format!("{stripped}\n"));
                } else {
                    let text = self.input.submit();
                    self.popup = None;
                    if self.shell_mode {
                        self.shell_mode = false;
                        if !text.trim().is_empty() {
                            self.run_shell(text.trim().to_string());
                        }
                    } else {
                        self.submit(text);
                    }
                }
            }
            KeyCode::Char('!') if self.input.is_empty() && !self.shell_mode => {
                self.shell_mode = true;
                self.hint = Some("shell mode: Enter runs the command here · Esc leaves".into());
            }
            KeyCode::Tab => self.complete(),
            KeyCode::Backspace if self.input.is_empty() && self.shell_mode => {
                self.shell_mode = false;
            }
            KeyCode::Backspace if alt || ctrl => self.input.delete_word(),
            KeyCode::Char('w') if ctrl => self.input.delete_word(),
            KeyCode::Backspace => self.input.backspace(),
            KeyCode::Delete => self.input.delete(),
            KeyCode::Left if alt || ctrl => self.input.word_left(),
            KeyCode::Right if alt || ctrl => self.input.word_right(),
            KeyCode::Char('b') if alt => self.input.word_left(),
            KeyCode::Char('f') if alt => self.input.word_right(),
            KeyCode::Left => self.input.left(),
            KeyCode::Right => self.input.right(),
            KeyCode::Home => self.input.home(),
            KeyCode::Char('a') if ctrl => self.input.home(),
            KeyCode::End if self.input.is_empty() => self.scroll = 0,
            KeyCode::End => self.input.end(),
            KeyCode::Char('e') if ctrl => self.input.end(),
            KeyCode::Char('u') if ctrl => self.input.clear(),
            KeyCode::Char('k') if ctrl => self.input.kill_line(),
            KeyCode::Up if self.input.is_empty() && !self.queue.is_empty() => {
                // Pull the last queued message back for editing.
                if let Some(last) = self.queue.pop() {
                    self.input.set_text(&last);
                    self.hint = Some("took the queued message back".into());
                }
            }
            KeyCode::Up if self.input.is_multiline() && !self.input.on_first_line() => {
                self.input.line_up()
            }
            KeyCode::Down if self.input.is_multiline() && !self.input.on_last_line() => {
                self.input.line_down()
            }
            KeyCode::Up => self.input.history_prev(),
            KeyCode::Down => self.input.history_next(),
            KeyCode::PageUp => self.scroll += (self.transcript_area.height as usize).max(10) / 2,
            KeyCode::PageDown => {
                self.scroll = self
                    .scroll
                    .saturating_sub((self.transcript_area.height as usize).max(10) / 2)
            }
            KeyCode::Char(ch) if !ctrl => self.input.insert(ch),
            _ => {}
        }
        self.refresh_popup();
        None
    }

    pub(super) fn on_action(&mut self, action: Action) -> Option<EditorRequest> {
        match action {
            Action::Steer => {
                let text = self.input.submit();
                self.popup = None;
                if self.running.is_some() {
                    self.steer(text);
                } else {
                    self.submit(text);
                }
            }
            Action::Newline => self.input.insert('\n'),
            Action::Palette => self.open_palette(),
            Action::Pager => self.open_pager(),
            Action::Expand => {
                self.render.expand_all = !self.render.expand_all;
                self.hint = Some(if self.render.expand_all {
                    "showing all tool output and full diffs".into()
                } else {
                    "tool output collapsed".into()
                });
            }
            Action::Editor => {
                return Some(EditorRequest {
                    text: self.input.expanded_text(),
                    view_only: false,
                });
            }
            Action::HistorySearch => self.open_history_search(),
            Action::CycleMode => self.cycle_mode(),
            Action::Sidebar => {
                self.show_sidebar = !self.show_sidebar;
            }
            Action::Clear => {
                self.transcript.clear();
                self.flushed = 0;
            }
            Action::Changes => self.open_review_now(),
            Action::PasteImage => self.paste_image(),
        }
        None
    }

    /// Recompute the `/` / `@` popup for the word at the cursor.
    pub(super) fn refresh_popup(&mut self) {
        if matches!(
            self.popup.as_ref().map(|p| p.kind),
            Some(PopupKind::History)
        ) {
            let query = self.input.text();
            let entries: Vec<Entry> = self
                .input
                .search_history(&query)
                .into_iter()
                .map(|h| Entry {
                    label: h.lines().next().unwrap_or("").to_string(),
                    detail: if h.lines().count() > 1 {
                        format!("+{} lines", h.lines().count() - 1)
                    } else {
                        String::new()
                    },
                    insert: h,
                })
                .collect();
            let selected = 0;
            self.popup = Some(Popup {
                kind: PopupKind::History,
                query,
                entries,
                selected,
            });
            return;
        }
        if self.shell_mode {
            self.popup = None;
            return;
        }
        let word = self.input.current_word();
        let whole = self.input.text();
        if word.starts_with('/') && whole.trim_start() == word && !word.contains(' ') {
            let candidates = self.slash_entries();
            let popup = Popup::new(PopupKind::Slash, word.clone(), &candidates);
            self.popup = (!popup.is_empty()).then_some(popup);
        } else if let Some(query) = word.strip_prefix('@') {
            let query = query.to_string();
            let candidates: Vec<Entry> = self
                .files()
                .iter()
                .map(|f| Entry {
                    label: f.clone(),
                    detail: String::new(),
                    insert: format!("@{f} "),
                })
                .collect();
            let popup = Popup::new(PopupKind::File, query, &candidates);
            self.popup = (!popup.is_empty()).then_some(popup);
        } else {
            self.popup = None;
        }
    }

    pub(super) fn slash_entries(&self) -> Vec<Entry> {
        SLASH_COMMANDS
            .iter()
            .map(|(c, d)| Entry {
                label: c.to_string(),
                detail: d.to_string(),
                insert: format!("{c} "),
            })
            .chain(self.custom_commands().iter().map(|c| Entry {
                label: format!("/{}", c.name),
                detail: format!("{} ({})", c.description, c.scope),
                insert: format!("/{} ", c.name),
            }))
            .collect()
    }

    fn accept_popup(&mut self, submit: bool) {
        let Some(popup) = self.popup.take() else {
            return;
        };
        let Some(entry) = popup.current().cloned() else {
            return;
        };
        match popup.kind {
            PopupKind::History => {
                self.input.set_text(&entry.insert);
            }
            PopupKind::Slash => {
                self.input.replace_current_word(&entry.insert);
                if submit {
                    // Commands that need an argument stay in the box.
                    let name = entry.label.as_str();
                    let needs_arg = matches!(
                        name,
                        "/handoff"
                            | "/btw"
                            | "/goal"
                            | "/allow"
                            | "/config"
                            | "/import"
                            | "/configure"
                    );
                    if !needs_arg {
                        let text = self.input.submit();
                        self.submit(text);
                    }
                }
            }
            PopupKind::File => self.input.replace_current_word(&entry.insert),
        }
    }

    fn open_history_search(&mut self) {
        self.popup = Some(Popup {
            kind: PopupKind::History,
            query: String::new(),
            entries: Vec::new(),
            selected: 0,
        });
        self.input.clear();
        self.refresh_popup();
        self.hint = Some("type to search earlier prompts · Enter picks · Esc cancels".into());
    }

    fn open_pager(&mut self) {
        let width = self.transcript_area.width.max(40);
        let height = self.transcript_area.height.max(10) as usize;
        let mut options = self.render.clone();
        options.expand_all = true;
        let lines = self.transcript.lines(width, &self.theme, &options);
        self.dialog = Some(Dialog::Pager(Pager::new(lines, height)));
    }

    /// Esc Esc: earlier turns of this session with their checkpoints.
    pub(super) fn open_timeline(&mut self) {
        let Some(session) = &self.session else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        let entries: Vec<Entry> = session
            .turn_checkpoints()
            .iter()
            .rev()
            .map(|(c, prompt)| Entry {
                label: crate::format::truncate(prompt, 70),
                detail: format!("checkpoint {}", c.commit),
                insert: c.commit.clone(),
            })
            .collect();
        if entries.is_empty() {
            self.hint = Some("no earlier turns in this session yet".into());
            return;
        }
        self.dialog = Some(Dialog::Picker(super::dialogs::Picker::new(
            PickerKind::Timeline,
            "Rewind · Enter restores files to before that turn and puts its prompt back · e only edits the prompt",
            entries,
        )));
    }

    /// Ctrl+V: save a clipboard image and mention it.
    fn paste_image(&mut self) {
        let Some(root) = self.project().map(|p| p.root.clone()) else {
            return;
        };
        match crate::clipboard::save_image(&root) {
            Ok(Some(path)) => {
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                self.input.insert_str(&format!("@{rel} "));
                self.hint = Some(format!("attached clipboard image {rel}"));
            }
            Ok(None) => self.hint = Some("no image on the clipboard".into()),
            Err(e) => self.hint = Some(format!("could not read the clipboard: {e}")),
        }
    }

    fn on_dialog_key(&mut self, key: KeyEvent) -> Option<EditorRequest> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let dialog = self.dialog.take()?;
        match dialog {
            Dialog::Approval(mut d) => {
                if let Some(reason) = &mut d.reason {
                    match key.code {
                        KeyCode::Enter => {
                            let reason = std::mem::take(reason);
                            let deny = d.deny_value();
                            self.transcript.notice(
                                format!(
                                    "denied: {}",
                                    if reason.is_empty() {
                                        "no reason"
                                    } else {
                                        &reason
                                    }
                                ),
                                Tone::Info,
                            );
                            self.send(Control::Approve(deny));
                            if !reason.trim().is_empty() {
                                self.send(Control::Steer(format!(
                                    "I denied that {} call. Instead: {}",
                                    d.approval.tool, reason
                                )));
                            }
                            if let Some(id) = d.remote.take() {
                                self.cancel_remote(id);
                            }
                            return None;
                        }
                        KeyCode::Esc => d.reason = None,
                        KeyCode::Backspace => {
                            reason.pop();
                        }
                        KeyCode::Char(c) if !ctrl => reason.push(c),
                        _ => {}
                    }
                    self.dialog = Some(Dialog::Approval(d));
                    return None;
                }
                let rows = d.rows();
                let choose = |value: String, this: &mut App, d: super::dialogs::ApprovalDialog| {
                    if value == "r" {
                        let mut d = d;
                        d.reason = Some(String::new());
                        this.dialog = Some(Dialog::Approval(d));
                        return;
                    }
                    if d.approval.has_option(&value) {
                        let label = d
                            .approval
                            .option_label(&value)
                            .unwrap_or(&value)
                            .to_string();
                        this.transcript.notice(label, Tone::Info);
                        this.send(Control::Approve(value));
                        if let Some(id) = d.remote {
                            this.cancel_remote(id);
                        }
                    } else {
                        this.dialog = Some(Dialog::Approval(d));
                    }
                };
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        d.selected = (d.selected + rows.len() - 1) % rows.len();
                        self.dialog = Some(Dialog::Approval(d));
                    }
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                        d.selected = (d.selected + 1) % rows.len();
                        self.dialog = Some(Dialog::Approval(d));
                    }
                    KeyCode::Enter => {
                        let value = rows[d.selected].0.clone();
                        choose(value, self, d);
                    }
                    KeyCode::Esc => {
                        let deny = d.deny_value();
                        choose(deny, self, d);
                    }
                    KeyCode::Char('c') if ctrl => {
                        let deny = d.deny_value();
                        choose(deny, self, d);
                    }
                    KeyCode::Char(ch) => {
                        let value = match ch.to_ascii_lowercase() {
                            c @ '1'..='9' => c.to_string(),
                            'y' => "1".to_string(),
                            'p' => microclaw_code_core::driver::ALLOW_RULE_OPTION.to_string(),
                            'n' => d.deny_value(),
                            'r' => "r".to_string(),
                            _ => {
                                self.dialog = Some(Dialog::Approval(d));
                                return None;
                            }
                        };
                        choose(value, self, d);
                    }
                    _ => self.dialog = Some(Dialog::Approval(d)),
                }
            }
            Dialog::Trust {
                root,
                has_config,
                changed,
            } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.set_trust(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.set_trust(false),
                _ => {
                    self.dialog = Some(Dialog::Trust {
                        root,
                        has_config,
                        changed,
                    })
                }
            },
            Dialog::Configure {
                explanation,
                changes,
            } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let Some(root) = self.project().map(|p| p.root.clone()) else {
                        self.dialog = Some(Dialog::Configure {
                            explanation,
                            changes,
                        });
                        self.hint = Some("wait for the current turn to finish".into());
                        return None;
                    };
                    for result in super::configure::apply(&root, &changes) {
                        match result {
                            Ok(line) => self.transcript.notice(line, Tone::Success),
                            Err(line) => self.transcript.notice(line, Tone::Error),
                        }
                    }
                    self.reload_settings();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.hint = Some("settings unchanged".into())
                }
                _ => {
                    self.dialog = Some(Dialog::Configure {
                        explanation,
                        changes,
                    })
                }
            },
            Dialog::ExecutePlan => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    if self.set_mode(Mode::Ask) {
                        self.start_turn(
                            "The plan above is approved. Execute it now, then verify the result."
                                .into(),
                            Some("execute the plan".into()),
                        );
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    if self.set_mode(Mode::Auto) {
                        self.start_turn(
                            "The plan above is approved. Execute it now, then verify the result."
                                .into(),
                            Some("execute the plan (auto mode)".into()),
                        );
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.hint = Some("still in plan mode; Shift+Tab switches mode".into())
                }
                _ => self.dialog = Some(Dialog::ExecutePlan),
            },
            Dialog::Picker(mut p) => match key.code {
                KeyCode::Esc => {
                    if p.kind == PickerKind::Theme
                        && let Some(original) = p.original.clone()
                    {
                        self.preview_theme(&original);
                    }
                }
                KeyCode::Up => {
                    p.up();
                    self.picker_moved(&p);
                    self.dialog = Some(Dialog::Picker(p));
                }
                KeyCode::Down | KeyCode::Tab => {
                    p.down();
                    self.picker_moved(&p);
                    self.dialog = Some(Dialog::Picker(p));
                }
                KeyCode::Enter => {
                    if let Some(entry) = p.current().cloned() {
                        self.picker_chosen(p.kind, &entry, false);
                    }
                }
                KeyCode::Char('e') if p.kind == PickerKind::Timeline && p.filter.is_empty() => {
                    if let Some(entry) = p.current().cloned() {
                        self.picker_chosen(p.kind, &entry, true);
                    }
                }
                KeyCode::Backspace => {
                    p.backspace();
                    self.picker_moved(&p);
                    self.dialog = Some(Dialog::Picker(p));
                }
                KeyCode::Char(c) if !ctrl => {
                    p.type_char(c);
                    self.picker_moved(&p);
                    self.dialog = Some(Dialog::Picker(p));
                }
                _ => self.dialog = Some(Dialog::Picker(p)),
            },
            Dialog::Review(mut state) => {
                let k = match key.code {
                    _ if state.composing.is_some() => match key.code {
                        KeyCode::Enter => Some(ReviewKey::Enter),
                        KeyCode::Esc => Some(ReviewKey::Cancel),
                        KeyCode::Backspace => Some(ReviewKey::Backspace),
                        KeyCode::Char(c) => Some(ReviewKey::Char(c)),
                        _ => None,
                    },
                    KeyCode::Up | KeyCode::Char('k') => Some(ReviewKey::Up),
                    KeyCode::Down | KeyCode::Char('j') => Some(ReviewKey::Down),
                    KeyCode::Tab | KeyCode::Right => Some(ReviewKey::NextFile),
                    KeyCode::BackTab | KeyCode::Left => Some(ReviewKey::PrevFile),
                    KeyCode::Char('r') => Some(ReviewKey::Revert),
                    KeyCode::Char('y') => Some(ReviewKey::Confirm),
                    KeyCode::Char('n') => Some(ReviewKey::Cancel),
                    KeyCode::Char('c') if !ctrl => Some(ReviewKey::Comment),
                    KeyCode::Char('v') => Some(ReviewKey::Reviewed),
                    KeyCode::PageDown => {
                        state.scroll += 10;
                        None
                    }
                    KeyCode::PageUp => {
                        state.scroll = state.scroll.saturating_sub(10);
                        None
                    }
                    KeyCode::Char('q') | KeyCode::Esc => Some(ReviewKey::Close),
                    KeyCode::Char('c') if ctrl => Some(ReviewKey::Close),
                    _ => None,
                };
                match k.map(|k| state.key(k)) {
                    Some(ReviewOutcome::Close(prompt)) => {
                        self.files = None;
                        if let Some(prompt) = prompt {
                            self.input.set_text(&prompt);
                            self.hint =
                                Some("review comments are in the prompt; Enter sends them".into());
                        }
                    }
                    _ => self.dialog = Some(Dialog::Review(state)),
                }
            }
            Dialog::Pager(mut p) => {
                let h = self.transcript_area.height.max(10) as usize + 2;
                let k = if p.searching {
                    match key.code {
                        KeyCode::Enter => Some(PagerKey::Enter),
                        KeyCode::Esc => Some(PagerKey::Close),
                        KeyCode::Backspace => Some(PagerKey::Backspace),
                        KeyCode::Char(c) => Some(PagerKey::Char(c)),
                        _ => None,
                    }
                } else {
                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => Some(PagerKey::Up(1)),
                        KeyCode::Down | KeyCode::Char('j') => Some(PagerKey::Down(1)),
                        KeyCode::PageUp | KeyCode::Char('b') => Some(PagerKey::Up(h / 2)),
                        KeyCode::PageDown | KeyCode::Char(' ') => Some(PagerKey::Down(h / 2)),
                        KeyCode::Char('g') | KeyCode::Home => Some(PagerKey::Top),
                        KeyCode::Char('G') | KeyCode::End => Some(PagerKey::Bottom),
                        KeyCode::Char('/') => Some(PagerKey::StartSearch),
                        KeyCode::Char('n') => Some(PagerKey::Next),
                        KeyCode::Char('N') => Some(PagerKey::Prev),
                        KeyCode::Char('v') => {
                            let text = p.text();
                            self.dialog = Some(Dialog::Pager(p));
                            return Some(EditorRequest {
                                text,
                                view_only: true,
                            });
                        }
                        KeyCode::Char('q') | KeyCode::Esc => Some(PagerKey::Close),
                        KeyCode::Char('t') if ctrl => Some(PagerKey::Close),
                        KeyCode::Char('c') if ctrl => Some(PagerKey::Close),
                        _ => None,
                    }
                };
                let open = match k {
                    Some(k) => p.key(k, h),
                    None => true,
                };
                if open {
                    self.dialog = Some(Dialog::Pager(p));
                }
            }
        }
        None
    }

    fn picker_moved(&mut self, p: &super::dialogs::Picker) {
        if p.kind == PickerKind::Theme
            && let Some(entry) = p.current()
        {
            let name = entry.insert.clone();
            self.preview_theme(&name);
        }
    }

    pub(super) fn preview_theme(&mut self, name: &str) {
        let (theme, _) = super::load_theme(Some(name), &self.themes_dir);
        self.theme = theme;
        self.transcript.invalidate();
    }

    /// Run the external editor on `request` (TUI suspended).
    pub(super) fn run_editor(
        &mut self,
        terminal: &mut super::Term,
        request: EditorRequest,
    ) -> anyhow::Result<()> {
        let editor = std::env::var("VISUAL")
            .or_else(|_| std::env::var("EDITOR"))
            .unwrap_or_else(|_| {
                if cfg!(windows) {
                    "notepad".into()
                } else {
                    "vi".into()
                }
            });
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mccode-{}.md", std::process::id()));
        std::fs::write(&path, &request.text)?;
        crossterm::terminal::disable_raw_mode()?;
        if !self.inline {
            crossterm::execute!(
                terminal.backend_mut(),
                crossterm::terminal::LeaveAlternateScreen,
                crossterm::event::DisableMouseCapture
            )?;
        }
        let status = {
            let mut parts = editor.split_whitespace();
            let program = parts.next().unwrap_or("vi");
            std::process::Command::new(program)
                .args(parts)
                .arg(&path)
                .status()
        };
        crossterm::terminal::enable_raw_mode()?;
        if !self.inline {
            crossterm::execute!(
                terminal.backend_mut(),
                crossterm::terminal::EnterAlternateScreen
            )?;
            if self.settings.tui.mouse.unwrap_or(true) {
                crossterm::execute!(terminal.backend_mut(), crossterm::event::EnableMouseCapture)?;
            }
        }
        terminal.clear()?;
        match status {
            Ok(s) if s.success() && !request.view_only => {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                self.input.clear();
                self.input.set_text(text.trim_end());
            }
            Ok(_) if request.view_only => {}
            Ok(s) => self.hint = Some(format!("{editor} exited with {s}")),
            Err(e) => self.hint = Some(format!("could not start {editor}: {e}")),
        }
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}
