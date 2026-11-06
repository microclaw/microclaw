//! Syntax highlighting (syntect + two-face).
//!
//! Syntax and theme sets are loaded lazily once per process. Highlighting
//! is foreground-only so callers can lay their own backgrounds (diff tints,
//! code-block panels) underneath. Large inputs are skipped (`None`) to keep
//! rendering snappy; callers then fall back to plain text.

use std::sync::OnceLock;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use syntect::highlighting::{
    Color as SynColor, FontStyle, HighlightIterator, HighlightState, Highlighter, Theme as SynTheme,
};
use syntect::parsing::{ParseState, ScopeStack, SyntaxReference, SyntaxSet};
use two_face::theme::{EmbeddedLazyThemeSet, EmbeddedThemeName};

use super::theme::{ColorDepth, Theme, rgb_at_depth};

/// Inputs above this many bytes are not highlighted.
pub const MAX_BYTES: usize = 200 * 1024;
/// Inputs above this many lines are not highlighted.
pub const MAX_LINES: usize = 5_000;
/// A single line longer than this (minified code) disables highlighting.
pub const MAX_LINE_BYTES: usize = 4_000;

fn syntax_set() -> &'static SyntaxSet {
    static SET: OnceLock<SyntaxSet> = OnceLock::new();
    SET.get_or_init(two_face::syntax::extra_newlines)
}

fn theme_set() -> &'static EmbeddedLazyThemeSet {
    static SET: OnceLock<EmbeddedLazyThemeSet> = OnceLock::new();
    SET.get_or_init(two_face::theme::extra)
}

fn squash(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The embedded syntect theme used for a MicroClaw `syntax_theme` name.
/// Exact two-face names match first, then well-known families; anything
/// else falls back to One Half Dark / Light.
pub fn embedded_theme_for(name: &str, is_dark: bool) -> EmbeddedThemeName {
    let key = squash(name);
    if let Some(found) = EmbeddedLazyThemeSet::theme_names()
        .iter()
        .find(|t| squash(t.as_name()) == key)
    {
        return *found;
    }
    let pick = |dark: EmbeddedThemeName, light: EmbeddedThemeName| {
        if is_dark { dark } else { light }
    };
    use EmbeddedThemeName as E;
    let families: &[(&str, EmbeddedThemeName)] = &[
        ("tokyo", E::ColdarkDark),
        ("catppuccin", pick(E::OneHalfDark, E::OneHalfLight)),
        ("onedark", E::TwoDark),
        ("atom", pick(E::TwoDark, E::OneHalfLight)),
        ("dracula", E::Dracula),
        ("nord", E::Nord),
        ("gruvbox", pick(E::GruvboxDark, E::GruvboxLight)),
        ("solarized", pick(E::SolarizedDark, E::SolarizedLight)),
        ("github", pick(E::OneHalfDark, E::Github)),
        ("monokai", pick(E::MonokaiExtended, E::MonokaiExtendedLight)),
        ("zenburn", E::Zenburn),
        ("coldark", pick(E::ColdarkDark, E::ColdarkCold)),
        ("snazzy", E::SublimeSnazzy),
    ];
    families
        .iter()
        .find(|(k, _)| key.contains(k))
        .map(|(_, t)| *t)
        .unwrap_or_else(|| pick(E::OneHalfDark, E::OneHalfLight))
}

fn syntect_theme(theme: &Theme) -> &'static SynTheme {
    theme_set().get(embedded_theme_for(&theme.syntax_theme, theme.is_dark))
}

/// Find a syntax for a fence info string (`rust`, `ts`, `py`, …) or a file
/// path (`src/main.rs`, `Dockerfile`). Returns `None` for plain text.
pub fn syntax_for(lang_or_path: &str) -> Option<&'static SyntaxReference> {
    let ss = syntax_set();
    let raw = lang_or_path
        .trim()
        .split(|c: char| c.is_whitespace() || c == ',' || c == '{')
        .next()
        .unwrap_or("");
    let lower = raw.to_lowercase();
    let token = match lower.as_str() {
        "" | "text" | "txt" | "plain" | "plaintext" | "output" | "log" | "console" => {
            return None;
        }
        "sh" | "shell" | "zsh" | "shellscript" | "bash" => "bash",
        "c++" | "cxx" | "hpp" => "cpp",
        "golang" => "go",
        "py3" | "python3" => "py",
        "jsonc" | "json5" => "json",
        "yml" => "yaml",
        "tsx" => "tsx",
        "rs" => "rs",
        "patch" => "diff",
        "dockerfile" => "Dockerfile",
        other => other,
    };
    if let Some(s) = ss.find_syntax_by_token(token) {
        return Some(s);
    }
    // File path: try the extension, then the whole file name.
    let file = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    if let Some((_, ext)) = file.rsplit_once('.')
        && let Some(s) = ss.find_syntax_by_extension(ext)
    {
        return Some(s);
    }
    ss.find_syntax_by_extension(file)
        .or_else(|| ss.find_syntax_by_name(raw))
}

/// A syntax + colour theme pair that highlights one line at a time.
///
/// Parser state lives in a separate, cloneable [`LineState`] so callers
/// can follow several streams (e.g. the old and new side of a diff) and
/// share work when the states coincide.
pub struct SyntaxHighlighter {
    highlighter: Highlighter<'static>,
    syntax: &'static SyntaxReference,
    default_fg: Option<SynColor>,
    depth: ColorDepth,
}

/// Parser + highlighter state between lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineState {
    parse: ParseState,
    highlight: HighlightState,
}

impl SyntaxHighlighter {
    /// `None` for plain text / unknown languages and 16-colour themes.
    pub fn new(lang_or_path: &str, theme: &Theme) -> Option<Self> {
        if theme.depth == ColorDepth::Ansi16 || theme.syntax_theme == "ansi" {
            return None;
        }
        let syntax = syntax_for(lang_or_path)?;
        let syn_theme = syntect_theme(theme);
        Some(Self {
            highlighter: Highlighter::new(syn_theme),
            syntax,
            default_fg: syn_theme.settings.foreground,
            depth: theme.depth,
        })
    }

    /// Fresh state for the start of a file / block.
    pub fn start(&self) -> LineState {
        LineState {
            parse: ParseState::new(self.syntax),
            highlight: HighlightState::new(&self.highlighter, ScopeStack::new()),
        }
    }

    /// Highlight one line (without its newline), advancing `state`.
    /// Lines over [`MAX_LINE_BYTES`] are skipped (`None`, state untouched).
    pub fn line(&self, state: &mut LineState, line: &str) -> Option<Vec<Span<'static>>> {
        if line.len() > MAX_LINE_BYTES {
            return None;
        }
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        let ops = state.parse.parse_line(&buf, syntax_set()).ok()?;
        let iter = HighlightIterator::new(&mut state.highlight, &ops, &buf, &self.highlighter);
        let mut spans: Vec<Span<'static>> = Vec::new();
        for (style, text) in iter {
            let text = text.trim_end_matches(['\n', '\r']);
            if text.is_empty() {
                continue;
            }
            let mut st = Style::default();
            let fg = style.foreground;
            if Some(fg) != self.default_fg && fg.a > 0 {
                st = st.fg(rgb_at_depth(self.depth, fg.r, fg.g, fg.b));
            }
            if style.font_style.contains(FontStyle::BOLD) {
                st = st.add_modifier(Modifier::BOLD);
            }
            if style.font_style.contains(FontStyle::ITALIC) {
                st = st.add_modifier(Modifier::ITALIC);
            }
            super::push_str(&mut spans, text, st);
        }
        Some(spans)
    }
}

/// Highlight `code` into one span list per line (no trailing newline
/// characters). Spans carry foreground (and bold / italic) only; text in
/// the syntax theme's default colour gets no foreground so the caller's
/// base style shows through.
///
/// `None` when the language is unknown / plain, the input exceeds the
/// limits, the theme is 16-colour, or the parser fails.
pub fn highlight_spans(
    code: &str,
    lang_or_path: &str,
    theme: &Theme,
) -> Option<Vec<Vec<Span<'static>>>> {
    if code.len() > MAX_BYTES {
        return None;
    }
    let line_count = code.lines().count();
    if line_count > MAX_LINES || code.lines().any(|l| l.len() > MAX_LINE_BYTES) {
        return None;
    }
    let hl = SyntaxHighlighter::new(lang_or_path, theme)?;
    let mut state = hl.start();
    code.lines()
        .map(|line| hl.line(&mut state, line.trim_end_matches('\r')))
        .collect()
}

/// Highlight `code` (fence language or file path) into ratatui lines; see
/// [`highlight_spans`] for when this returns `None`.
pub fn highlight_lines(
    code: &str,
    lang_or_path: &str,
    theme: &Theme,
) -> Option<Vec<Line<'static>>> {
    highlight_spans(code, lang_or_path, theme)
        .map(|rows| rows.into_iter().map(Line::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    #[test]
    fn finds_syntaxes() {
        assert_eq!(syntax_for("rust").unwrap().name, "Rust");
        assert_eq!(syntax_for("rs").unwrap().name, "Rust");
        assert_eq!(syntax_for("src/main.rs").unwrap().name, "Rust");
        assert_eq!(syntax_for("ts").unwrap().name, "TypeScript");
        assert_eq!(syntax_for("python").unwrap().name, "Python");
        assert!(syntax_for("sh").is_some());
        assert!(syntax_for("Cargo.toml").is_some());
        assert!(syntax_for("Dockerfile").is_some());
        assert!(syntax_for("rust,ignore").is_some());
        assert!(syntax_for("text").is_none());
        assert!(syntax_for("").is_none());
        assert!(syntax_for("no-such-language").is_none());
    }

    #[test]
    fn maps_theme_names() {
        use EmbeddedThemeName as E;
        assert_eq!(embedded_theme_for("Nord", true), E::Nord);
        assert_eq!(
            embedded_theme_for("Solarized (light)", false),
            E::SolarizedLight
        );
        assert_eq!(embedded_theme_for("gruvbox-dark", true), E::GruvboxDark);
        assert_eq!(embedded_theme_for("tokyo-night", true), E::ColdarkDark);
        assert_eq!(embedded_theme_for("whatever", false), E::OneHalfLight);
        assert_eq!(embedded_theme_for("my-dracula-ish", true), E::Dracula);
    }

    #[test]
    fn highlights_rust_with_colours() {
        let theme = Theme::dark();
        let lines = highlight_lines("fn main() {\n    let x = 1;\n}\n", "rust", &theme).unwrap();
        assert_eq!(lines.len(), 3);
        let text: String = lines[1].spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "    let x = 1;");
        let kw = lines[0].spans.iter().find(|s| s.content == "fn").unwrap();
        assert!(matches!(kw.style.fg, Some(Color::Rgb(..))));
        assert_eq!(kw.style.bg, None);
    }

    #[test]
    fn respects_depth_and_limits() {
        let t256 = Theme::dark().downgrade(ColorDepth::Ansi256);
        let lines = highlight_lines("let x = \"s\";", "js", &t256).unwrap();
        assert!(
            lines[0]
                .spans
                .iter()
                .filter_map(|s| s.style.fg)
                .all(|c| matches!(c, Color::Indexed(_)))
        );
        assert!(highlight_lines("let x = 1;", "js", &Theme::ansi()).is_none());
        let huge = "x\n".repeat(MAX_LINES + 1);
        assert!(highlight_lines(&huge, "rust", &Theme::dark()).is_none());
        let long = "a".repeat(MAX_LINE_BYTES + 1);
        assert!(highlight_lines(&long, "rust", &Theme::dark()).is_none());
    }
}
