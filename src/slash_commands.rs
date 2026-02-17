//! Central slash-command parsing. All channels MUST run this first on incoming text.
//! If a command is detected, run the corresponding handler and do NOT store the message or send to the LLM.

/// Slash command variants. Persona carries the full input for subcommand parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashCommand {
    Reset,
    Skills,
    Persona,
    Archive,
    Schedule,
}

/// Normalize message text for command detection: trim, slash-like and invisible chars so commands are recognized.
fn normalize(text: &str) -> String {
    // Strip BOM, zero-width, and bidirectional/format characters that can appear before the slash
    let invisibles = [
        '\u{feff}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', // zero-width, BOM
        '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', // RTL/LTR format
    ];
    let mut s = text.trim().to_string();
    for c in invisibles {
        s = s.replace(c, "");
    }
    s = s.trim().to_string();
    // Normalize slash-like characters to ASCII / (before any starts_with check)
    s = s.replace('\u{ff0f}', "/");   // fullwidth solidus
    s = s.replace('\u{2044}', "/");   // fraction slash
    s = s.replace('\u{2215}', "/");   // division slash
    // Normalize homoglyphs so e.g. Cyrillic 'а' (U+0430) in "personа" becomes Latin "persona"
    s = s.replace('\u{0430}', "a");   // Cyrillic small a
    s = s.replace('\u{0435}', "e");   // Cyrillic small e
    s = s.replace('\u{043e}', "o");   // Cyrillic small o
    s = s.replace('\u{0440}', "p");   // Cyrillic small r
    s = s.replace('\u{043d}', "n");   // Cyrillic small n
    s = s.replace('\u{0441}', "s");   // Cyrillic small s
    s.trim().to_string()
}

/// Parse slash command from raw message text.
/// Returns `Some(cmd)` only when the message is *unambiguously* a slash command (starts with `/` and a known command).
/// Call this first on every incoming message; if `Some`, run the handler and return — do not store or send to LLM.
pub fn parse(text: &str) -> Option<SlashCommand> {
    let t = normalize(text);
    if t.is_empty() || !t.starts_with('/') {
        return None;
    }
    let lower = t.to_lowercase();
    // Check /persona first so it's never shadowed; also matches /persona@bot
    if lower == "/persona"
        || lower == "/personas"
        || lower.starts_with("/persona ")
        || lower.starts_with("/personas ")
        || lower.starts_with("/persona@")
        || lower.starts_with("/personas@")
    {
        return Some(SlashCommand::Persona);
    }
    if lower == "/reset" || lower.starts_with("/reset ") {
        return Some(SlashCommand::Reset);
    }
    if lower == "/skills" || lower.starts_with("/skills ") {
        return Some(SlashCommand::Skills);
    }
    if lower == "/archive" || lower.starts_with("/archive ") {
        return Some(SlashCommand::Archive);
    }
    if lower == "/schedule" || lower.starts_with("/schedule ")
        || lower == "/jobs" || lower.starts_with("/jobs ")
        || lower == "/scheduled" || lower.starts_with("/scheduled ")
        || lower == "/scheduledjob" || lower.starts_with("/scheduledjob ")
        || lower == "/scheduled_job" || lower.starts_with("/scheduled_job ")
    {
        return Some(SlashCommand::Schedule);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reset() {
        assert_eq!(parse("/reset"), Some(SlashCommand::Reset));
        assert_eq!(parse("  /reset  "), Some(SlashCommand::Reset));
        assert_eq!(parse("/reset "), Some(SlashCommand::Reset));
        assert_eq!(parse("hello /reset"), None);
    }

    #[test]
    fn parse_persona() {
        assert_eq!(parse("/persona"), Some(SlashCommand::Persona));
        assert_eq!(parse("/personas"), Some(SlashCommand::Persona));
        assert_eq!(parse("/persona switch x"), Some(SlashCommand::Persona));
        assert_eq!(parse("/persona@bot"), Some(SlashCommand::Persona));
        assert_eq!(parse("tell me about /persona"), None);
    }

    #[test]
    fn parse_skills_archive() {
        assert_eq!(parse("/skills"), Some(SlashCommand::Skills));
        assert_eq!(parse("/archive"), Some(SlashCommand::Archive));
    }

    #[test]
    fn parse_schedule() {
        assert_eq!(parse("/schedule"), Some(SlashCommand::Schedule));
        assert_eq!(parse("/jobs"), Some(SlashCommand::Schedule));
        assert_eq!(parse("/schedule "), Some(SlashCommand::Schedule));
        assert_eq!(parse("/scheduled"), Some(SlashCommand::Schedule));
        assert_eq!(parse("/scheduledjob"), Some(SlashCommand::Schedule));
        assert_eq!(parse("/scheduled_job"), Some(SlashCommand::Schedule));
    }

    #[test]
    fn parse_not_commands() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("hello"), None);
        assert_eq!(parse("use /persona to switch"), None);
    }

    #[test]
    fn parse_persona_normalizes_unicode() {
        // Fullwidth slash, zero-width space, BOM
        assert_eq!(parse("\u{feff}/persona"), Some(SlashCommand::Persona));
        assert_eq!(parse("/\u{200b}persona"), Some(SlashCommand::Persona));
        assert_eq!(parse("\u{ff0f}persona"), Some(SlashCommand::Persona));
        // Homoglyph: Cyrillic 'а' (U+0430) in "personа" normalizes to "persona"
        assert_eq!(parse("/person\u{0430}"), Some(SlashCommand::Persona));
    }
}
