//! Configurable key bindings (`tui.keymap` in settings).
//!
//! Actions have default keys; settings map an action name to one or more
//! keys (`ctrl+s`, `alt+enter`, `f2`, `ctrl+x ctrl+e` is not supported —
//! single keys only) or to `none` to unbind it.

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Send now as guidance to the running turn.
    Steer,
    /// Insert a new line.
    Newline,
    /// Command palette.
    Palette,
    /// Full transcript pager with search.
    Pager,
    /// Expand / collapse all tool output and diffs.
    Expand,
    /// Edit the prompt in `$EDITOR`.
    Editor,
    /// Reverse history search.
    HistorySearch,
    /// Cycle plan → ask → auto.
    CycleMode,
    /// Show / hide the side panel.
    Sidebar,
    /// Clear the screen.
    Clear,
    /// Review the working-tree changes hunk by hunk.
    Changes,
    /// Paste an image from the clipboard.
    PasteImage,
}

impl Action {
    pub const ALL: &'static [Action] = &[
        Action::Steer,
        Action::Newline,
        Action::Palette,
        Action::Pager,
        Action::Expand,
        Action::Editor,
        Action::HistorySearch,
        Action::CycleMode,
        Action::Sidebar,
        Action::Clear,
        Action::Changes,
        Action::PasteImage,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Action::Steer => "chat.steer",
            Action::Newline => "chat.newline",
            Action::Palette => "app.palette",
            Action::Pager => "transcript.pager",
            Action::Expand => "transcript.expand",
            Action::Editor => "chat.editor",
            Action::HistorySearch => "history.search",
            Action::CycleMode => "app.mode",
            Action::Sidebar => "app.sidebar",
            Action::Clear => "app.clear",
            Action::Changes => "app.changes",
            Action::PasteImage => "chat.paste_image",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Action::Steer => "send as guidance to the running turn now",
            Action::Newline => "new line",
            Action::Palette => "command palette",
            Action::Pager => "full transcript with search",
            Action::Expand => "expand / collapse tool output",
            Action::Editor => "edit the prompt in $EDITOR",
            Action::HistorySearch => "search earlier prompts",
            Action::CycleMode => "switch mode (plan / ask / auto)",
            Action::Sidebar => "show / hide the side panel",
            Action::Clear => "clear the screen",
            Action::Changes => "review changes hunk by hunk",
            Action::PasteImage => "paste an image from the clipboard",
        }
    }

    fn defaults(self) -> &'static [&'static str] {
        match self {
            Action::Steer => &["ctrl+s"],
            Action::Newline => &["alt+enter", "shift+enter", "ctrl+j"],
            Action::Palette => &["ctrl+p"],
            Action::Pager => &["ctrl+t"],
            Action::Expand => &["ctrl+o"],
            Action::Editor => &["ctrl+g"],
            Action::HistorySearch => &["ctrl+r"],
            Action::CycleMode => &["shift+tab"],
            Action::Sidebar => &["ctrl+b"],
            Action::Clear => &["ctrl+l"],
            Action::Changes => &["f2"],
            Action::PasteImage => &["ctrl+v"],
        }
    }

    fn from_name(name: &str) -> Option<Action> {
        Action::ALL.iter().copied().find(|a| a.name() == name)
    }
}

/// One key with modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl Key {
    fn matches(&self, event: &KeyEvent) -> bool {
        let mut mods = event.modifiers;
        let mut code = event.code;
        // Shift+Tab arrives as BackTab (sometimes with SHIFT set).
        if code == KeyCode::BackTab {
            code = KeyCode::Tab;
            mods |= KeyModifiers::SHIFT;
        }
        // Shifted characters carry SHIFT in some terminals only.
        if let KeyCode::Char(c) = code {
            code = KeyCode::Char(c.to_ascii_lowercase());
            if c.is_ascii_uppercase() {
                mods |= KeyModifiers::SHIFT;
            }
        }
        let wanted = self.modifiers;
        code == self.code
            && mods & (KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT) == wanted
    }

    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            parts.push("Ctrl".to_string());
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            parts.push("Alt".to_string());
        }
        if self.modifiers.contains(KeyModifiers::SHIFT) {
            parts.push("Shift".to_string());
        }
        parts.push(match self.code {
            KeyCode::Char(' ') => "Space".into(),
            KeyCode::Char(c) => c.to_ascii_uppercase().to_string(),
            KeyCode::Enter => "Enter".into(),
            KeyCode::Tab => "Tab".into(),
            KeyCode::Esc => "Esc".into(),
            KeyCode::F(n) => format!("F{n}"),
            KeyCode::Up => "Up".into(),
            KeyCode::Down => "Down".into(),
            KeyCode::Left => "Left".into(),
            KeyCode::Right => "Right".into(),
            KeyCode::Home => "Home".into(),
            KeyCode::End => "End".into(),
            KeyCode::PageUp => "PgUp".into(),
            KeyCode::PageDown => "PgDn".into(),
            KeyCode::Backspace => "Backspace".into(),
            KeyCode::Delete => "Delete".into(),
            _ => "?".into(),
        });
        parts.join("+")
    }
}

/// Parse `ctrl+s`, `alt+enter`, `shift+tab`, `f2`, `ctrl+space`.
pub fn parse_key(text: &str) -> Result<Key, String> {
    let mut modifiers = KeyModifiers::NONE;
    let lower = text.trim().to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('+').map(str::trim).collect();
    let (last, mods) = parts.split_last().ok_or_else(|| "empty key".to_string())?;
    for m in mods {
        match *m {
            "ctrl" | "control" | "c" => modifiers |= KeyModifiers::CONTROL,
            "alt" | "meta" | "option" | "opt" | "m" => modifiers |= KeyModifiers::ALT,
            "shift" | "s" => modifiers |= KeyModifiers::SHIFT,
            other => return Err(format!("unknown modifier `{other}` in `{text}`")),
        }
    }
    let code = match *last {
        "enter" | "return" => KeyCode::Enter,
        "tab" => KeyCode::Tab,
        "esc" | "escape" => KeyCode::Esc,
        "space" => KeyCode::Char(' '),
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" => KeyCode::PageDown,
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        f if f.starts_with('f') && f.len() > 1 && f[1..].parse::<u8>().is_ok() => {
            KeyCode::F(f[1..].parse().unwrap_or(1))
        }
        c if c.chars().count() == 1 => KeyCode::Char(c.chars().next().unwrap_or(' ')),
        other => return Err(format!("unknown key `{other}` in `{text}`")),
    };
    Ok(Key { code, modifiers })
}

#[derive(Debug, Clone)]
pub struct Keymap {
    bindings: BTreeMap<Action, Vec<Key>>,
}

impl Default for Keymap {
    fn default() -> Self {
        Self::from_config(&BTreeMap::new()).0
    }
}

impl Keymap {
    /// Defaults overridden by `tui.keymap`; returns warnings for unknown
    /// actions or keys.
    pub fn from_config(config: &BTreeMap<String, String>) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut bindings: BTreeMap<Action, Vec<Key>> = Action::ALL
            .iter()
            .map(|a| {
                (
                    *a,
                    a.defaults()
                        .iter()
                        .filter_map(|k| parse_key(k).ok())
                        .collect(),
                )
            })
            .collect();
        for (name, keys) in config {
            let Some(action) = Action::from_name(name) else {
                warnings.push(format!("tui.keymap: unknown action `{name}`"));
                continue;
            };
            let keys = keys.trim();
            if keys.eq_ignore_ascii_case("none") || keys.is_empty() {
                bindings.insert(action, Vec::new());
                continue;
            }
            let mut parsed = Vec::new();
            for k in keys.split(',') {
                match parse_key(k) {
                    Ok(key) => parsed.push(key),
                    Err(e) => warnings.push(format!("tui.keymap.{name}: {e}")),
                }
            }
            if !parsed.is_empty() {
                // A key bound here is removed from other actions.
                for other in bindings.values_mut() {
                    other.retain(|k| !parsed.contains(k));
                }
                bindings.insert(action, parsed);
            }
        }
        (Self { bindings }, warnings)
    }

    pub fn action(&self, event: &KeyEvent) -> Option<Action> {
        self.bindings
            .iter()
            .find(|(_, keys)| keys.iter().any(|k| k.matches(event)))
            .map(|(a, _)| *a)
    }

    /// The first key of `action` for hints (`None` when unbound).
    pub fn label(&self, action: Action) -> Option<String> {
        self.bindings
            .get(&action)
            .and_then(|keys| keys.first())
            .map(Key::label)
    }

    /// Help text listing every binding.
    pub fn help(&self) -> String {
        let mut text = String::new();
        for action in Action::ALL {
            let keys = self
                .bindings
                .get(action)
                .map(|ks| ks.iter().map(Key::label).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            text.push_str(&format!(
                "\n  {:<18} {:<22} {}",
                action.name(),
                if keys.is_empty() {
                    "(unbound)".into()
                } else {
                    keys
                },
                action.describe()
            ));
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn defaults_and_overrides() {
        let km = Keymap::default();
        assert_eq!(
            km.action(&ev(KeyCode::Char('s'), KeyModifiers::CONTROL)),
            Some(Action::Steer)
        );
        assert_eq!(
            km.action(&ev(KeyCode::BackTab, KeyModifiers::SHIFT)),
            Some(Action::CycleMode)
        );
        let mut cfg = BTreeMap::new();
        cfg.insert("chat.steer".to_string(), "alt+s".to_string());
        cfg.insert("app.sidebar".to_string(), "none".to_string());
        cfg.insert("nope".to_string(), "ctrl+q".to_string());
        cfg.insert("app.palette".to_string(), "ctrl+shift+zz".to_string());
        let (km, warnings) = Keymap::from_config(&cfg);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert_eq!(
            km.action(&ev(KeyCode::Char('s'), KeyModifiers::CONTROL)),
            None
        );
        assert_eq!(
            km.action(&ev(KeyCode::Char('s'), KeyModifiers::ALT)),
            Some(Action::Steer)
        );
        assert_eq!(
            km.action(&ev(KeyCode::Char('b'), KeyModifiers::CONTROL)),
            None
        );
        assert_eq!(km.label(Action::Steer).as_deref(), Some("Alt+S"));
    }

    #[test]
    fn parses_keys() {
        assert_eq!(
            parse_key("Ctrl+Enter").unwrap(),
            Key {
                code: KeyCode::Enter,
                modifiers: KeyModifiers::CONTROL
            }
        );
        assert_eq!(parse_key("f2").unwrap().code, KeyCode::F(2));
        assert!(parse_key("hyper+x").is_err());
    }
}
