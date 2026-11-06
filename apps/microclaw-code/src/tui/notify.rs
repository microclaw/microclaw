//! Terminal notifications (OSC 9 / OSC 777 / bell) and the window title.

use std::io::Write;

use microclaw_code_core::settings::TerminalNotifications;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Off,
    Bell,
    Osc9,
    Osc777,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notifier {
    pub method: Method,
    /// Notify even while the terminal has focus.
    pub always: bool,
}

impl Notifier {
    pub fn from_settings(settings: Option<&TerminalNotifications>) -> Self {
        let method = settings.and_then(|s| s.method.as_deref()).unwrap_or("auto");
        let method = match method {
            "off" | "none" => Method::Off,
            "bell" | "bel" => Method::Bell,
            "osc9" => Method::Osc9,
            "osc777" => Method::Osc777,
            _ => auto_method(),
        };
        let always = settings.and_then(|s| s.when.as_deref()) == Some("always");
        Self { method, always }
    }

    /// Send `title: body` unless the terminal has focus (or `when: always`).
    pub fn notify(&self, focused: bool, title: &str, body: &str) {
        if self.method == Method::Off || (focused && !self.always) {
            return;
        }
        let clean = |s: &str| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect::<String>()
                .replace(';', ",")
        };
        let seq = match self.method {
            Method::Off => return,
            Method::Bell => "\x07".to_string(),
            Method::Osc9 => format!("\x1b]9;{}: {}\x07", clean(title), clean(body)),
            Method::Osc777 => format!("\x1b]777;notify;{};{}\x07", clean(title), clean(body)),
        };
        let mut out = std::io::stdout();
        let _ = out.write_all(wrap_for_tmux(&seq).as_bytes());
        let _ = out.flush();
    }
}

/// Pick a method from the terminal: OSC 777 for terminals known to show it,
/// OSC 9 for iTerm2 / WezTerm / Ghostty / kitty-likes, bell otherwise.
fn auto_method() -> Method {
    let term_program = std::env::var("TERM_PROGRAM").unwrap_or_default();
    let term = std::env::var("TERM").unwrap_or_default();
    if std::env::var_os("VTE_VERSION").is_some() || term.contains("foot") {
        Method::Osc777
    } else if matches!(
        term_program.as_str(),
        "iTerm.app" | "WezTerm" | "ghostty" | "WarpTerminal"
    ) || term.contains("kitty")
        || term.contains("ghostty")
    {
        Method::Osc9
    } else {
        Method::Bell
    }
}

/// tmux swallows OSC sequences unless they are passed through.
fn wrap_for_tmux(seq: &str) -> String {
    if std::env::var_os("TMUX").is_some() && seq.starts_with("\x1b]") {
        format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
    } else {
        seq.to_string()
    }
}

/// Set the terminal window title.
pub fn set_title(title: &str) {
    let clean: String = title
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    let mut out = std::io::stdout();
    let _ = out.write_all(format!("\x1b]0;{clean}\x07").as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_select_the_method() {
        let off = TerminalNotifications {
            method: Some("off".into()),
            when: None,
        };
        assert_eq!(Notifier::from_settings(Some(&off)).method, Method::Off);
        let bell = TerminalNotifications {
            method: Some("bell".into()),
            when: Some("always".into()),
        };
        let n = Notifier::from_settings(Some(&bell));
        assert_eq!(n.method, Method::Bell);
        assert!(n.always);
    }
}
