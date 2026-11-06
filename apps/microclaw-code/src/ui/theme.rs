//! Semantic colour tokens, built-in themes and colour-depth fallback.
//!
//! Components never hard-code colours: they read tokens from a [`Theme`].
//! A theme is resolved once (built-in name, custom YAML theme or OpenCode
//! theme JSON), then [`Theme::downgrade`]d to the terminal's colour depth.
//!
//! Background-like tokens are `Option<Color>`: `None` means "leave the
//! terminal's own background", which is what the `ansi` theme uses
//! everywhere so it renders correctly on any palette.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ratatui::style::{Color, Modifier, Style};

/// How many colours the terminal can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorDepth {
    /// 24-bit RGB.
    #[default]
    TrueColor,
    /// xterm 256-colour palette.
    Ansi256,
    /// The 16 user-configurable ANSI colours only.
    Ansi16,
}

impl ColorDepth {
    /// Detect the colour depth from the process environment.
    pub fn detect() -> Self {
        Self::from_env(|key| std::env::var(key).ok())
    }

    /// Detect from an arbitrary environment lookup (testable).
    ///
    /// `NO_COLOR` (non-empty) forces [`ColorDepth::Ansi16`]; callers that
    /// want strictly monochrome output should also check [`no_color`].
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        let non_empty = |key: &str| get(key).filter(|v| !v.is_empty());
        if non_empty("NO_COLOR").is_some() {
            return Self::Ansi16;
        }
        let colorterm = non_empty("COLORTERM").unwrap_or_default().to_lowercase();
        if colorterm == "truecolor" || colorterm == "24bit" {
            return Self::TrueColor;
        }
        let term = non_empty("TERM").unwrap_or_default().to_lowercase();
        if term == "dumb" || term == "linux" || term == "vt100" || term == "ansi" {
            return Self::Ansi16;
        }
        if term.contains("truecolor") || term.contains("direct") || term.contains("24bit") {
            return Self::TrueColor;
        }
        // Terminals that support 24-bit colour without advertising it.
        if non_empty("WT_SESSION").is_some() {
            return Self::TrueColor;
        }
        match non_empty("TERM_PROGRAM").as_deref() {
            Some("iTerm.app" | "WezTerm" | "vscode" | "ghostty" | "Hyper" | "rio") => {
                return Self::TrueColor;
            }
            Some("Apple_Terminal") => return Self::Ansi256,
            _ => {}
        }
        if term.contains("kitty") || term.contains("alacritty") || term.contains("ghostty") {
            return Self::TrueColor;
        }
        if term.contains("256") {
            return Self::Ansi256;
        }
        if term.is_empty() {
            Self::Ansi16
        } else {
            Self::Ansi256
        }
    }
}

/// `true` when the user asked for no colour (`NO_COLOR`, non-empty).
pub fn no_color() -> bool {
    std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty())
}

/// A complete set of semantic colours.
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    /// Display name (`dark`, `tokyonight`, a custom file stem, …).
    pub name: String,
    /// Dark variant (light text on a dark background).
    pub is_dark: bool,
    /// Syntax-highlighting theme name, mapped by `highlight.rs`.
    pub syntax_theme: String,
    /// Colour depth the tokens have been fitted to.
    pub depth: ColorDepth,

    pub text: Color,
    pub text_muted: Color,
    pub accent: Color,
    /// `None` = terminal background.
    pub background: Option<Color>,
    pub background_panel: Option<Color>,
    pub background_element: Option<Color>,
    pub border: Color,
    pub border_active: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub mode_plan: Color,
    pub mode_ask: Color,
    pub mode_auto: Color,
    pub mode_shell: Color,
    pub user_prompt: Color,
    pub tool_name: Color,
    pub diff_added: Color,
    pub diff_removed: Color,
    pub diff_added_bg: Option<Color>,
    pub diff_removed_bg: Option<Color>,
    pub diff_added_word_bg: Option<Color>,
    pub diff_removed_word_bg: Option<Color>,
    pub diff_line_number: Color,
    pub diff_hunk: Color,
    pub markdown_heading: Color,
    pub markdown_code: Color,
    pub markdown_link: Color,
    pub markdown_quote: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

/// All built-in theme names, `auto` first.
pub fn builtin_names() -> &'static [&'static str] {
    &[
        "auto",
        "dark",
        "light",
        "ansi",
        "tokyonight",
        "catppuccin",
        "gruvbox",
        "nord",
        "dracula",
        "one-dark",
        "solarized-light",
        "github-light",
    ]
}

/// Token names accepted by custom themes (`tokens:` keys).
pub const TOKEN_NAMES: &[&str] = &[
    "text",
    "text_muted",
    "accent",
    "background",
    "background_panel",
    "background_element",
    "border",
    "border_active",
    "success",
    "warning",
    "error",
    "info",
    "mode_plan",
    "mode_ask",
    "mode_auto",
    "mode_shell",
    "user_prompt",
    "tool_name",
    "diff_added",
    "diff_removed",
    "diff_added_bg",
    "diff_removed_bg",
    "diff_added_word_bg",
    "diff_removed_word_bg",
    "diff_line_number",
    "diff_hunk",
    "markdown_heading",
    "markdown_code",
    "markdown_link",
    "markdown_quote",
];

enum TokenMut<'a> {
    Fg(&'a mut Color),
    Bg(&'a mut Option<Color>),
}

/// Compact palette from which a built-in theme's tokens are derived.
struct Spec {
    name: &'static str,
    dark: bool,
    syntax: &'static str,
    bg: Option<u32>,
    panel: u32,
    element: u32,
    border: u32,
    text: u32,
    muted: u32,
    accent: u32,
    blue: u32,
    green: u32,
    yellow: u32,
    red: u32,
    purple: u32,
    cyan: u32,
    orange: u32,
    added_bg: u32,
    removed_bg: u32,
    added_word: u32,
    removed_word: u32,
    line_number: u32,
}

const fn hex(v: u32) -> Color {
    Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

impl Spec {
    fn build(&self) -> Theme {
        Theme {
            name: self.name.to_string(),
            is_dark: self.dark,
            syntax_theme: self.syntax.to_string(),
            depth: ColorDepth::TrueColor,
            text: hex(self.text),
            text_muted: hex(self.muted),
            accent: hex(self.accent),
            background: self.bg.map(hex),
            background_panel: Some(hex(self.panel)),
            background_element: Some(hex(self.element)),
            border: hex(self.border),
            border_active: hex(self.accent),
            success: hex(self.green),
            warning: hex(self.yellow),
            error: hex(self.red),
            info: hex(self.cyan),
            mode_plan: hex(self.blue),
            mode_ask: hex(self.green),
            mode_auto: hex(self.yellow),
            mode_shell: hex(self.purple),
            user_prompt: hex(self.accent),
            tool_name: hex(self.blue),
            diff_added: hex(self.green),
            diff_removed: hex(self.red),
            diff_added_bg: Some(hex(self.added_bg)),
            diff_removed_bg: Some(hex(self.removed_bg)),
            diff_added_word_bg: Some(hex(self.added_word)),
            diff_removed_word_bg: Some(hex(self.removed_word)),
            diff_line_number: hex(self.line_number),
            diff_hunk: hex(self.muted),
            markdown_heading: hex(self.purple),
            markdown_code: hex(self.orange),
            markdown_link: hex(self.blue),
            markdown_quote: hex(self.muted),
        }
    }
}

impl Theme {
    /// MicroClaw's default dark theme (terminal background).
    pub fn dark() -> Self {
        Spec {
            name: "dark",
            dark: true,
            syntax: "OneHalfDark",
            bg: None,
            panel: 0x1b1e24,
            element: 0x262a33,
            border: 0x363c47,
            text: 0xdcdfe4,
            muted: 0x8a919c,
            accent: 0x82aaff,
            blue: 0x82aaff,
            green: 0x7fd09a,
            yellow: 0xe6c07b,
            red: 0xf07178,
            purple: 0xc792ea,
            cyan: 0x7fcfd9,
            orange: 0xf4a86a,
            added_bg: 0x1f3326,
            removed_bg: 0x3c1f22,
            added_word: 0x2c5238,
            removed_word: 0x5f2a30,
            line_number: 0x5a606b,
        }
        .build()
    }

    /// MicroClaw's default light theme (terminal background).
    pub fn light() -> Self {
        Spec {
            name: "light",
            dark: false,
            syntax: "OneHalfLight",
            bg: None,
            panel: 0xf4f5f7,
            element: 0xe9ebef,
            border: 0xd4d8de,
            text: 0x1f2328,
            muted: 0x6b7280,
            accent: 0x2f6fdb,
            blue: 0x2f6fdb,
            green: 0x2e7d32,
            yellow: 0xa15c00,
            red: 0xc62828,
            purple: 0x7b3fbf,
            cyan: 0x00838f,
            orange: 0xb45309,
            added_bg: 0xe3f5e6,
            removed_bg: 0xfbe7e7,
            added_word: 0xb8e6c0,
            removed_word: 0xf4c4c4,
            line_number: 0x9aa1ab,
        }
        .build()
    }

    /// Only the 16 ANSI colours and no backgrounds: correct on any palette.
    pub fn ansi() -> Self {
        Theme {
            name: "ansi".to_string(),
            is_dark: true,
            syntax_theme: "ansi".to_string(),
            depth: ColorDepth::Ansi16,
            text: Color::Reset,
            text_muted: Color::DarkGray,
            accent: Color::Cyan,
            background: None,
            background_panel: None,
            background_element: None,
            border: Color::DarkGray,
            border_active: Color::Cyan,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            info: Color::Cyan,
            mode_plan: Color::Blue,
            mode_ask: Color::Green,
            mode_auto: Color::Yellow,
            mode_shell: Color::Magenta,
            user_prompt: Color::Cyan,
            tool_name: Color::Blue,
            diff_added: Color::Green,
            diff_removed: Color::Red,
            diff_added_bg: None,
            diff_removed_bg: None,
            diff_added_word_bg: None,
            diff_removed_word_bg: None,
            diff_line_number: Color::DarkGray,
            diff_hunk: Color::DarkGray,
            markdown_heading: Color::Magenta,
            markdown_code: Color::Cyan,
            markdown_link: Color::Blue,
            markdown_quote: Color::DarkGray,
        }
    }

    /// Look up a built-in theme (`auto` is not a theme; see [`resolve`]).
    pub fn builtin(name: &str) -> Option<Self> {
        let theme = match normalize_name(name).as_str() {
            "dark" | "default" => Self::dark(),
            "light" => Self::light(),
            "ansi" | "16" | "ansi16" => Self::ansi(),
            "tokyonight" | "tokyo-night" | "tokyonight-night" => Spec {
                name: "tokyonight",
                dark: true,
                syntax: "tokyonight",
                bg: Some(0x1a1b26),
                panel: 0x1f2335,
                element: 0x292e42,
                border: 0x3b4261,
                text: 0xc0caf5,
                muted: 0x737aa2,
                accent: 0x7aa2f7,
                blue: 0x7aa2f7,
                green: 0x9ece6a,
                yellow: 0xe0af68,
                red: 0xf7768e,
                purple: 0xbb9af7,
                cyan: 0x7dcfff,
                orange: 0xff9e64,
                added_bg: 0x20303b,
                removed_bg: 0x37222c,
                added_word: 0x2f5a49,
                removed_word: 0x713137,
                line_number: 0x545c7e,
            }
            .build(),
            "catppuccin" | "catppuccin-mocha" | "mocha" => Spec {
                name: "catppuccin",
                dark: true,
                syntax: "catppuccin",
                bg: Some(0x1e1e2e),
                panel: 0x181825,
                element: 0x313244,
                border: 0x45475a,
                text: 0xcdd6f4,
                muted: 0x9399b2,
                accent: 0xcba6f7,
                blue: 0x89b4fa,
                green: 0xa6e3a1,
                yellow: 0xf9e2af,
                red: 0xf38ba8,
                purple: 0xcba6f7,
                cyan: 0x94e2d5,
                orange: 0xfab387,
                added_bg: 0x24312b,
                removed_bg: 0x3c2a32,
                added_word: 0x32503d,
                removed_word: 0x5a3340,
                line_number: 0x6c7086,
            }
            .build(),
            "gruvbox" | "gruvbox-dark" => Spec {
                name: "gruvbox",
                dark: true,
                syntax: "gruvbox-dark",
                bg: Some(0x282828),
                panel: 0x32302f,
                element: 0x3c3836,
                border: 0x504945,
                text: 0xebdbb2,
                muted: 0xa89984,
                accent: 0xfe8019,
                blue: 0x83a598,
                green: 0xb8bb26,
                yellow: 0xfabd2f,
                red: 0xfb4934,
                purple: 0xd3869b,
                cyan: 0x8ec07c,
                orange: 0xfe8019,
                added_bg: 0x32361a,
                removed_bg: 0x3c1f1e,
                added_word: 0x4b5320,
                removed_word: 0x5f2725,
                line_number: 0x7c6f64,
            }
            .build(),
            "nord" => Spec {
                name: "nord",
                dark: true,
                syntax: "Nord",
                bg: Some(0x2e3440),
                panel: 0x3b4252,
                element: 0x434c5e,
                border: 0x4c566a,
                text: 0xd8dee9,
                muted: 0x7b88a1,
                accent: 0x88c0d0,
                blue: 0x81a1c1,
                green: 0xa3be8c,
                yellow: 0xebcb8b,
                red: 0xbf616a,
                purple: 0xb48ead,
                cyan: 0x8fbcbb,
                orange: 0xd08770,
                added_bg: 0x364540,
                removed_bg: 0x45363d,
                added_word: 0x4a5e4f,
                removed_word: 0x5f414a,
                line_number: 0x616e88,
            }
            .build(),
            "dracula" => Spec {
                name: "dracula",
                dark: true,
                syntax: "Dracula",
                bg: Some(0x282a36),
                panel: 0x21222c,
                element: 0x343746,
                border: 0x44475a,
                text: 0xf8f8f2,
                muted: 0x8390bd,
                accent: 0xbd93f9,
                blue: 0x8be9fd,
                green: 0x50fa7b,
                yellow: 0xf1fa8c,
                red: 0xff5555,
                purple: 0xff79c6,
                cyan: 0x8be9fd,
                orange: 0xffb86c,
                added_bg: 0x233a2e,
                removed_bg: 0x44262c,
                added_word: 0x2f5e40,
                removed_word: 0x6b2f38,
                line_number: 0x6272a4,
            }
            .build(),
            "one-dark" | "onedark" | "one" => Spec {
                name: "one-dark",
                dark: true,
                syntax: "TwoDark",
                bg: Some(0x282c34),
                panel: 0x21252b,
                element: 0x2c313a,
                border: 0x3e4451,
                text: 0xabb2bf,
                muted: 0x7f848e,
                accent: 0x61afef,
                blue: 0x61afef,
                green: 0x98c379,
                yellow: 0xe5c07b,
                red: 0xe06c75,
                purple: 0xc678dd,
                cyan: 0x56b6c2,
                orange: 0xd19a66,
                added_bg: 0x2a3b2f,
                removed_bg: 0x3f2a2e,
                added_word: 0x3a5a3c,
                removed_word: 0x6a3239,
                line_number: 0x4b5263,
            }
            .build(),
            "solarized-light" | "solarized" => Spec {
                name: "solarized-light",
                dark: false,
                syntax: "Solarized (light)",
                bg: Some(0xfdf6e3),
                panel: 0xeee8d5,
                element: 0xe6dfc8,
                border: 0xd3cbb7,
                text: 0x586e75,
                muted: 0x93a1a1,
                accent: 0x268bd2,
                blue: 0x268bd2,
                green: 0x859900,
                yellow: 0xb58900,
                red: 0xdc322f,
                purple: 0xd33682,
                cyan: 0x2aa198,
                orange: 0xcb4b16,
                added_bg: 0xe7efcc,
                removed_bg: 0xf9e1d6,
                added_word: 0xd2e1a1,
                removed_word: 0xf3c4b6,
                line_number: 0x93a1a1,
            }
            .build(),
            "github-light" | "github" => Spec {
                name: "github-light",
                dark: false,
                syntax: "GitHub",
                bg: Some(0xffffff),
                panel: 0xf6f8fa,
                element: 0xeaeef2,
                border: 0xd0d7de,
                text: 0x1f2328,
                muted: 0x656d76,
                accent: 0x0969da,
                blue: 0x0969da,
                green: 0x1a7f37,
                yellow: 0x9a6700,
                red: 0xd1242f,
                purple: 0x8250df,
                cyan: 0x1b7c83,
                orange: 0xbc4c00,
                added_bg: 0xdafbe1,
                removed_bg: 0xffebe9,
                added_word: 0xaceebb,
                removed_word: 0xffcecb,
                line_number: 0x8c959f,
            }
            .build(),
            _ => return None,
        };
        Some(theme)
    }

    /// Fit every token to `depth`: RGB → nearest xterm-256 index, or the
    /// whole theme → [`Theme::ansi`] for 16 colours (no per-component
    /// branching needed downstream).
    pub fn downgrade(&self, depth: ColorDepth) -> Theme {
        match depth {
            ColorDepth::TrueColor => {
                let mut t = self.clone();
                t.depth = ColorDepth::TrueColor;
                t
            }
            ColorDepth::Ansi16 => {
                let mut t = Theme::ansi();
                t.name = self.name.clone();
                t.is_dark = self.is_dark;
                t
            }
            ColorDepth::Ansi256 => {
                let mut t = self.clone();
                t.depth = ColorDepth::Ansi256;
                for name in TOKEN_NAMES {
                    match t.token_mut(name) {
                        Some(TokenMut::Fg(c)) => *c = to_ansi256(*c),
                        Some(TokenMut::Bg(c)) => *c = c.map(to_ansi256),
                        None => {}
                    }
                }
                t
            }
        }
    }

    /// Map an RGB colour (e.g. from a syntax theme) to this theme's depth.
    pub fn rgb(&self, r: u8, g: u8, b: u8) -> Color {
        rgb_at_depth(self.depth, r, g, b)
    }

    /// Style with only a foreground.
    pub fn fg(&self, color: Color) -> Style {
        Style::default().fg(color)
    }

    /// Style for a muted / secondary text run.
    pub fn muted(&self) -> Style {
        Style::default().fg(self.text_muted)
    }

    /// Emphasis for word-level diff changes. Uses the word background when
    /// the theme has one, otherwise reverse video (works on 16 colours).
    pub fn diff_word_style(&self, added: bool) -> Style {
        let bg = if added {
            self.diff_added_word_bg
        } else {
            self.diff_removed_word_bg
        };
        match bg {
            Some(bg) => Style::default().bg(bg),
            None => Style::default().add_modifier(Modifier::REVERSED),
        }
    }

    fn token_mut(&mut self, name: &str) -> Option<TokenMut<'_>> {
        use TokenMut::{Bg, Fg};
        Some(match name {
            "text" => Fg(&mut self.text),
            "text_muted" => Fg(&mut self.text_muted),
            "accent" => Fg(&mut self.accent),
            "background" => Bg(&mut self.background),
            "background_panel" => Bg(&mut self.background_panel),
            "background_element" => Bg(&mut self.background_element),
            "border" => Fg(&mut self.border),
            "border_active" => Fg(&mut self.border_active),
            "success" => Fg(&mut self.success),
            "warning" => Fg(&mut self.warning),
            "error" => Fg(&mut self.error),
            "info" => Fg(&mut self.info),
            "mode_plan" => Fg(&mut self.mode_plan),
            "mode_ask" => Fg(&mut self.mode_ask),
            "mode_auto" => Fg(&mut self.mode_auto),
            "mode_shell" => Fg(&mut self.mode_shell),
            "user_prompt" => Fg(&mut self.user_prompt),
            "tool_name" => Fg(&mut self.tool_name),
            "diff_added" => Fg(&mut self.diff_added),
            "diff_removed" => Fg(&mut self.diff_removed),
            "diff_added_bg" => Bg(&mut self.diff_added_bg),
            "diff_removed_bg" => Bg(&mut self.diff_removed_bg),
            "diff_added_word_bg" | "diff_added_word" => Bg(&mut self.diff_added_word_bg),
            "diff_removed_word_bg" | "diff_removed_word" => Bg(&mut self.diff_removed_word_bg),
            "diff_line_number" => Fg(&mut self.diff_line_number),
            "diff_hunk" => Fg(&mut self.diff_hunk),
            "markdown_heading" => Fg(&mut self.markdown_heading),
            "markdown_code" => Fg(&mut self.markdown_code),
            "markdown_link" => Fg(&mut self.markdown_link),
            "markdown_quote" => Fg(&mut self.markdown_quote),
            _ => return None,
        })
    }

    fn set_token(&mut self, name: &str, value: Option<Color>) -> bool {
        match self.token_mut(name) {
            Some(TokenMut::Fg(c)) => {
                *c = value.unwrap_or(Color::Reset);
                true
            }
            Some(TokenMut::Bg(c)) => {
                *c = value;
                true
            }
            None => false,
        }
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().to_lowercase().replace([' ', '_'], "-")
}

// ---------------------------------------------------------------------------
// Colour-depth mapping
// ---------------------------------------------------------------------------

const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

fn dist(a: (u8, u8, u8), b: (u8, u8, u8)) -> u32 {
    // Weighted RGB distance ("redmean"-style weights, integer only).
    let dr = a.0 as i32 - b.0 as i32;
    let dg = a.1 as i32 - b.1 as i32;
    let db = a.2 as i32 - b.2 as i32;
    (2 * dr * dr + 4 * dg * dg + 3 * db * db) as u32
}

/// Nearest xterm-256 index (cube or grey ramp; never 0–15, which are
/// user-themed and unpredictable).
pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    let nearest = |v: u8| -> usize {
        (0..6)
            .min_by_key(|&i| (CUBE[i] as i32 - v as i32).unsigned_abs())
            .unwrap_or(0)
    };
    let (ri, gi, bi) = (nearest(r), nearest(g), nearest(b));
    let cube_idx = 16 + 36 * ri + 6 * gi + bi;
    let cube_rgb = (CUBE[ri], CUBE[gi], CUBE[bi]);
    let avg = (r as u32 + g as u32 + b as u32) / 3;
    let gi = if avg < 8 { 0 } else { ((avg - 8) / 10).min(23) };
    let grey = (8 + 10 * gi) as u8;
    let grey_idx = 232 + gi as usize;
    if dist((r, g, b), (grey, grey, grey)) < dist((r, g, b), cube_rgb) {
        grey_idx as u8
    } else {
        cube_idx as u8
    }
}

fn indexed_to_rgb(i: u8) -> Option<(u8, u8, u8)> {
    match i {
        16..=231 => {
            let i = i - 16;
            Some((
                CUBE[(i / 36) as usize],
                CUBE[((i / 6) % 6) as usize],
                CUBE[(i % 6) as usize],
            ))
        }
        232..=255 => {
            let v = 8 + 10 * (i - 232);
            Some((v, v, v))
        }
        _ => None,
    }
}

/// Nearest of the 16 ANSI colours (using typical xterm values).
pub fn rgb_to_ansi16(r: u8, g: u8, b: u8) -> Color {
    const TABLE: [(Color, (u8, u8, u8)); 16] = [
        (Color::Black, (0, 0, 0)),
        (Color::Red, (205, 49, 49)),
        (Color::Green, (13, 188, 121)),
        (Color::Yellow, (229, 229, 16)),
        (Color::Blue, (36, 114, 200)),
        (Color::Magenta, (188, 63, 188)),
        (Color::Cyan, (17, 168, 205)),
        (Color::Gray, (229, 229, 229)),
        (Color::DarkGray, (102, 102, 102)),
        (Color::LightRed, (241, 76, 76)),
        (Color::LightGreen, (35, 209, 139)),
        (Color::LightYellow, (245, 245, 67)),
        (Color::LightBlue, (59, 142, 234)),
        (Color::LightMagenta, (214, 112, 214)),
        (Color::LightCyan, (41, 184, 219)),
        (Color::White, (255, 255, 255)),
    ];
    TABLE
        .iter()
        .min_by_key(|(_, rgb)| dist((r, g, b), *rgb))
        .map(|(c, _)| *c)
        .unwrap_or(Color::Reset)
}

/// Map an RGB colour to the nearest colour available at `depth`.
pub fn rgb_at_depth(depth: ColorDepth, r: u8, g: u8, b: u8) -> Color {
    match depth {
        ColorDepth::TrueColor => Color::Rgb(r, g, b),
        ColorDepth::Ansi256 => Color::Indexed(rgb_to_ansi256(r, g, b)),
        ColorDepth::Ansi16 => rgb_to_ansi16(r, g, b),
    }
}

fn to_ansi256(c: Color) -> Color {
    match c {
        Color::Rgb(r, g, b) => Color::Indexed(rgb_to_ansi256(r, g, b)),
        other => other,
    }
}

/// Linear blend `a → b` by `t` (0..=1); non-RGB inputs return `a`.
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    let rgb = |c: Color| match c {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        Color::Indexed(i) => indexed_to_rgb(i),
        _ => None,
    };
    match (rgb(a), rgb(b)) {
        (Some(x), Some(y)) => {
            let l = |p: u8, q: u8| (p as f32 + (q as f32 - p as f32) * t).round() as u8;
            Color::Rgb(l(x.0, y.0), l(x.1, y.1), l(x.2, y.2))
        }
        _ => a,
    }
}

// ---------------------------------------------------------------------------
// Terminal background detection
// ---------------------------------------------------------------------------

/// Guess whether the terminal background is dark from `COLORFGBG`
/// (`"fg;bg"` or `"fg;default;bg"`, set by rxvt, Konsole, iTerm2 …).
/// Returns `None` when unknown; callers default to dark.
pub fn detect_dark_background() -> Option<bool> {
    // TODO: OSC 11 query (`ESC ] 11 ; ? BEL`) with a short timeout, done
    // before raw mode is entered so the reply cannot leak into stdin.
    colorfgbg_is_dark(&std::env::var("COLORFGBG").ok()?)
}

/// Parse a `COLORFGBG` value; `Some(true)` for a dark background.
pub fn colorfgbg_is_dark(value: &str) -> Option<bool> {
    let bg = value.rsplit(';').next()?.trim();
    let idx: u8 = bg.parse().ok()?;
    Some(matches!(idx, 0..=6 | 8))
}

// ---------------------------------------------------------------------------
// Resolution and custom themes
// ---------------------------------------------------------------------------

/// Resolve a theme by name.
///
/// * `auto` / `system` / empty: `dark` or `light` from `terminal_is_dark`
///   (unknown → dark).
/// * a built-in name ([`builtin_names`]).
/// * `<themes_dir>/<name>.yaml|.yml|.json` (YAML theme or OpenCode JSON),
///   or a direct path to such a file.
///
/// Never fails: problems are reported as warnings and the closest
/// fallback is returned. The result is true-colour; call
/// [`Theme::downgrade`] with the detected [`ColorDepth`] afterwards.
pub fn resolve(
    name: &str,
    themes_dir: Option<&Path>,
    terminal_is_dark: Option<bool>,
) -> (Theme, Vec<String>) {
    let mut warnings = Vec::new();
    let auto = || {
        if terminal_is_dark.unwrap_or(true) {
            Theme::dark()
        } else {
            Theme::light()
        }
    };
    let norm = normalize_name(name);
    if matches!(norm.as_str(), "" | "auto" | "system") {
        return (auto(), warnings);
    }
    if let Some(theme) = Theme::builtin(&norm) {
        return (theme, warnings);
    }
    let Some(path) = find_theme_file(name, themes_dir) else {
        warnings.push(format!(
            "theme `{name}` not found (built-ins: {}); using {}",
            builtin_names().join(", "),
            if terminal_is_dark.unwrap_or(true) {
                "dark"
            } else {
                "light"
            }
        ));
        return (auto(), warnings);
    };
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name)
        .to_string();
    match std::fs::read_to_string(&path) {
        Ok(src) => {
            let is_json = path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"));
            let result = if is_json {
                load_opencode_json(&src, &stem, terminal_is_dark, &mut warnings)
            } else {
                load_yaml_theme(&src, &stem, terminal_is_dark, &mut warnings)
            };
            match result {
                Ok(theme) => (theme, warnings),
                Err(e) => {
                    warnings.push(format!("theme {}: {e}; using default", path.display()));
                    (auto(), warnings)
                }
            }
        }
        Err(e) => {
            warnings.push(format!("theme {}: {e}; using default", path.display()));
            (auto(), warnings)
        }
    }
}

/// Custom theme names (file stems) found in `themes_dir`, sorted.
pub fn custom_theme_names(themes_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(themes_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let ext = p.extension()?.to_str()?.to_lowercase();
            matches!(ext.as_str(), "yaml" | "yml" | "json")
                .then(|| p.file_stem()?.to_str().map(str::to_string))
                .flatten()
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn find_theme_file(name: &str, themes_dir: Option<&Path>) -> Option<PathBuf> {
    let direct = Path::new(name);
    if direct.extension().is_some() && direct.is_file() {
        return Some(direct.to_path_buf());
    }
    let dir = themes_dir?;
    ["yaml", "yml", "json"]
        .iter()
        .map(|ext| dir.join(format!("{name}.{ext}")))
        .find(|p| p.is_file())
}

type Palette = HashMap<String, serde_yaml::Value>;

/// Resolve a colour value: `#rrggbb` / `#rgb`, `0..=255`, palette name,
/// ANSI colour name, `{dark: …, light: …}` or `none` / `transparent`.
/// `Ok(None)` means "no colour" (terminal default).
fn resolve_value(
    value: &serde_yaml::Value,
    palette: &Palette,
    dark: bool,
    depth: u8,
) -> Result<Option<Color>, String> {
    use serde_yaml::Value;
    if depth > 8 {
        return Err("palette reference cycle".into());
    }
    match value {
        Value::Null => Ok(None),
        Value::Number(n) => {
            let i = n
                .as_u64()
                .filter(|i| *i <= 255)
                .ok_or_else(|| format!("colour index {n} out of range 0..=255"))?;
            Ok(Some(index_color(i as u8)))
        }
        Value::String(s) => {
            let s = s.trim();
            let lower = s.to_lowercase();
            if matches!(lower.as_str(), "none" | "transparent" | "default" | "") {
                return Ok(None);
            }
            if let Some(hex) = s.strip_prefix('#') {
                return parse_hex(hex)
                    .map(Some)
                    .ok_or_else(|| format!("invalid hex colour `{s}`"));
            }
            if let Some(v) = palette.get(s) {
                return resolve_value(v, palette, dark, depth + 1);
            }
            if let Ok(i) = s.parse::<u8>() {
                return Ok(Some(index_color(i)));
            }
            Color::from_str(s)
                .map(Some)
                .map_err(|_| format!("unknown colour `{s}`"))
        }
        Value::Mapping(m) => {
            let key = if dark { "dark" } else { "light" };
            let other = if dark { "light" } else { "dark" };
            let v = m
                .get(key)
                .or_else(|| m.get(other))
                .ok_or_else(|| "variant map needs `dark` / `light`".to_string())?;
            resolve_value(v, palette, dark, depth + 1)
        }
        _ => Err("unsupported colour value".into()),
    }
}

fn index_color(i: u8) -> Color {
    const NAMED: [Color; 16] = [
        Color::Black,
        Color::Red,
        Color::Green,
        Color::Yellow,
        Color::Blue,
        Color::Magenta,
        Color::Cyan,
        Color::Gray,
        Color::DarkGray,
        Color::LightRed,
        Color::LightGreen,
        Color::LightYellow,
        Color::LightBlue,
        Color::LightMagenta,
        Color::LightCyan,
        Color::White,
    ];
    NAMED.get(i as usize).copied().unwrap_or(Color::Indexed(i))
}

fn parse_hex(hex: &str) -> Option<Color> {
    let hex = hex.trim();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match hex.len() {
        6 => {
            let v = u32::from_str_radix(hex, 16).ok()?;
            Some(Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
        }
        3 => {
            let d = |i: usize| u8::from_str_radix(&hex[i..i + 1], 16).ok().map(|v| v * 17);
            Some(Color::Rgb(d(0)?, d(1)?, d(2)?))
        }
        _ => None,
    }
}

fn mapping_to_palette(v: Option<&serde_yaml::Value>) -> Palette {
    v.and_then(|v| v.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.clone())))
                .collect()
        })
        .unwrap_or_default()
}

/// Load a MicroClaw YAML theme (`name`, `base`, `palette`, `tokens`).
pub fn load_yaml_theme(
    src: &str,
    fallback_name: &str,
    terminal_is_dark: Option<bool>,
    warnings: &mut Vec<String>,
) -> Result<Theme, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(src).map_err(|e| e.to_string())?;
    if !doc.is_mapping() {
        return Err("theme file must be a mapping".into());
    }
    let base_name = doc.get("base").and_then(|v| v.as_str()).unwrap_or("auto");
    let mut theme = base_theme(base_name, terminal_is_dark, warnings);
    if let Some(dark) = doc
        .get("variant")
        .and_then(|v| v.as_str())
        .map(|v| v.eq_ignore_ascii_case("dark"))
    {
        theme.is_dark = dark;
    }
    theme.name = doc
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_name)
        .to_string();
    let palette = mapping_to_palette(doc.get("palette"));
    let dark = theme.is_dark;
    if let Some(s) = doc.get("syntax_theme").and_then(|v| v.as_str()) {
        theme.syntax_theme = s.to_string();
    }
    if let Some(tokens) = doc.get("tokens").and_then(|v| v.as_mapping()) {
        for (k, v) in tokens {
            let Some(key) = k.as_str() else { continue };
            if key == "syntax_theme" {
                if let Some(s) = v.as_str() {
                    theme.syntax_theme = s.to_string();
                }
                continue;
            }
            match resolve_value(v, &palette, dark, 0) {
                Ok(color) => {
                    if !theme.set_token(key, color) {
                        warnings.push(format!("theme {}: unknown token `{key}`", theme.name));
                    }
                }
                Err(e) => warnings.push(format!("theme {}: token `{key}`: {e}", theme.name)),
            }
        }
    }
    Ok(theme)
}

fn base_theme(base: &str, terminal_is_dark: Option<bool>, warnings: &mut Vec<String>) -> Theme {
    let norm = normalize_name(base);
    if matches!(norm.as_str(), "" | "auto" | "system") {
        return if terminal_is_dark.unwrap_or(true) {
            Theme::dark()
        } else {
            Theme::light()
        };
    }
    Theme::builtin(&norm).unwrap_or_else(|| {
        warnings.push(format!("unknown base theme `{base}`; using dark"));
        Theme::dark()
    })
}

/// OpenCode token → MicroClaw tokens it feeds (first wins when several
/// OpenCode tokens map to the same MicroClaw token).
const OPENCODE_MAP: &[(&str, &[&str])] = &[
    ("primary", &["accent", "user_prompt", "border_active"]),
    ("secondary", &["tool_name"]),
    ("accent", &["mode_shell"]),
    ("error", &["error"]),
    ("warning", &["warning", "mode_auto"]),
    ("success", &["success", "mode_ask"]),
    ("info", &["info", "mode_plan"]),
    ("text", &["text"]),
    ("textMuted", &["text_muted", "diff_hunk"]),
    ("background", &["background"]),
    ("backgroundPanel", &["background_panel"]),
    ("backgroundElement", &["background_element"]),
    ("border", &["border"]),
    ("borderActive", &["border_active"]),
    ("diffAdded", &["diff_added"]),
    ("diffRemoved", &["diff_removed"]),
    ("diffAddedBg", &["diff_added_bg"]),
    ("diffRemovedBg", &["diff_removed_bg"]),
    ("diffLineNumber", &["diff_line_number"]),
    ("diffHunkHeader", &["diff_hunk"]),
    ("markdownHeading", &["markdown_heading"]),
    ("markdownCode", &["markdown_code"]),
    ("markdownLink", &["markdown_link"]),
    ("markdownBlockQuote", &["markdown_quote"]),
];

/// Load an OpenCode theme JSON (`defs` + `theme`). Missing tokens fall
/// back to `dark` / `light` (picked from `terminal_is_dark`).
pub fn load_opencode_json(
    src: &str,
    name: &str,
    terminal_is_dark: Option<bool>,
    warnings: &mut Vec<String>,
) -> Result<Theme, String> {
    let json: serde_json::Value = serde_json::from_str(src).map_err(|e| e.to_string())?;
    let doc: serde_yaml::Value = serde_yaml::to_value(&json).map_err(|e| e.to_string())?;
    let tokens = doc
        .get("theme")
        .and_then(|v| v.as_mapping())
        .ok_or("missing `theme` object")?;
    let dark = terminal_is_dark.unwrap_or(true);
    let mut theme = if dark { Theme::dark() } else { Theme::light() };
    theme.name = name.to_string();
    theme.syntax_theme = name.to_string();
    let palette = mapping_to_palette(doc.get("defs"));
    let mut assigned: Vec<&str> = Vec::new();
    for (oc, targets) in OPENCODE_MAP {
        let Some(v) = tokens.get(*oc) else { continue };
        match resolve_value(v, &palette, dark, 0) {
            Ok(color) => {
                for target in targets.iter() {
                    // Explicit mappings beat derived ones (`borderActive`
                    // over `primary`); otherwise first mapping wins.
                    let explicit = *oc == "borderActive" || *oc == "diffHunkHeader";
                    if explicit || !assigned.contains(target) {
                        theme.set_token(target, color);
                        assigned.push(target);
                    }
                }
            }
            Err(e) => warnings.push(format!("theme {name}: `{oc}`: {e}")),
        }
    }
    // Word-level diff backgrounds: OpenCode has bright highlight
    // foregrounds instead; derive a stronger tint of the line background.
    if let (Some(bg), Some(_)) = (theme.diff_added_bg, tokens.get("diffAddedBg")) {
        theme.diff_added_word_bg = Some(mix(bg, theme.diff_added, 0.22));
    }
    if let (Some(bg), Some(_)) = (theme.diff_removed_bg, tokens.get("diffRemovedBg")) {
        theme.diff_removed_word_bg = Some(mix(bg, theme.diff_removed, 0.22));
    }
    Ok(theme)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn all_builtins_resolve() {
        for name in builtin_names() {
            let (theme, warnings) = resolve(name, None, Some(true));
            assert!(warnings.is_empty(), "{name}: {warnings:?}");
            if *name != "auto" {
                assert_eq!(&theme.name, name);
            }
        }
        assert_eq!(resolve("auto", None, Some(false)).0.name, "light");
        assert_eq!(resolve("auto", None, None).0.name, "dark");
        assert_eq!(resolve("Tokyo Night", None, None).0.name, "tokyonight");
    }

    #[test]
    fn unknown_theme_warns_and_falls_back() {
        let (theme, warnings) = resolve("nope", None, Some(false));
        assert_eq!(theme.name, "light");
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn color_depth_detection() {
        assert_eq!(
            ColorDepth::from_env(env(&[("COLORTERM", "truecolor"), ("TERM", "xterm")])),
            ColorDepth::TrueColor
        );
        assert_eq!(
            ColorDepth::from_env(env(&[("TERM", "xterm-256color")])),
            ColorDepth::Ansi256
        );
        assert_eq!(
            ColorDepth::from_env(env(&[("TERM", "linux")])),
            ColorDepth::Ansi16
        );
        assert_eq!(
            ColorDepth::from_env(env(&[("COLORTERM", "truecolor"), ("NO_COLOR", "1")])),
            ColorDepth::Ansi16
        );
        assert_eq!(
            ColorDepth::from_env(env(&[
                ("TERM", "xterm-256color"),
                ("TERM_PROGRAM", "Apple_Terminal")
            ])),
            ColorDepth::Ansi256
        );
        assert_eq!(ColorDepth::from_env(env(&[])), ColorDepth::Ansi16);
    }

    #[test]
    fn ansi256_mapping() {
        assert_eq!(rgb_to_ansi256(0, 0, 0), 16);
        assert_eq!(rgb_to_ansi256(255, 255, 255), 231);
        assert_eq!(rgb_to_ansi256(255, 0, 0), 196);
        // A mid grey should land on the grey ramp.
        let g = rgb_to_ansi256(0x80, 0x80, 0x80);
        assert!((232..=255).contains(&g), "{g}");
        let t = Theme::dark().downgrade(ColorDepth::Ansi256);
        assert_eq!(t.depth, ColorDepth::Ansi256);
        assert!(matches!(t.text, Color::Indexed(_)));
        assert!(matches!(t.diff_added_bg, Some(Color::Indexed(_))));
        assert_eq!(t.background, None);
        assert!(matches!(t.rgb(1, 2, 3), Color::Indexed(_)));
    }

    #[test]
    fn ansi16_downgrade_uses_ansi_theme() {
        let t = Theme::builtin("dracula")
            .unwrap()
            .downgrade(ColorDepth::Ansi16);
        assert_eq!(t.name, "dracula");
        assert_eq!(t.depth, ColorDepth::Ansi16);
        assert_eq!(t.background, None);
        assert_eq!(t.diff_added_bg, None);
        assert_eq!(t.diff_added, Color::Green);
        let all_fg = [
            t.text,
            t.text_muted,
            t.accent,
            t.diff_line_number,
            t.markdown_code,
            t.mode_shell,
        ];
        assert!(
            all_fg
                .iter()
                .all(|c| !matches!(c, Color::Rgb(..) | Color::Indexed(_)))
        );
        assert_eq!(rgb_to_ansi16(245, 80, 80), Color::LightRed);
        assert_eq!(rgb_to_ansi16(200, 40, 40), Color::Red);
        assert_eq!(
            t.diff_word_style(true),
            Style::default().add_modifier(Modifier::REVERSED)
        );
    }

    #[test]
    fn colorfgbg() {
        assert_eq!(colorfgbg_is_dark("15;0"), Some(true));
        assert_eq!(colorfgbg_is_dark("0;15"), Some(false));
        assert_eq!(colorfgbg_is_dark("0;default;15"), Some(false));
        assert_eq!(colorfgbg_is_dark("default;default"), None);
    }

    #[test]
    fn yaml_theme_with_base_and_palette() {
        let src = r##"
name: my-theme
base: light
palette:
  blue: "#7aa2f7"
  link: blue
tokens:
  text: "#c0caf5"
  accent: blue
  markdown_link: link
  background: none
  background_panel: 236
  border: 4
  diff_added_word: "#2f5a49"
  mode_shell: { dark: "#bb9af7", light: "#7847bd" }
  warning: bright-yellow
  bogus: "#000000"
  error: "#zzzzzz"
  syntax_theme: Nord
"##;
        let mut warnings = Vec::new();
        let t = load_yaml_theme(src, "file", None, &mut warnings).unwrap();
        assert_eq!(t.name, "my-theme");
        assert!(!t.is_dark, "inherits light base");
        assert_eq!(t.text, Color::Rgb(0xc0, 0xca, 0xf5));
        assert_eq!(t.accent, Color::Rgb(0x7a, 0xa2, 0xf7));
        assert_eq!(t.markdown_link, t.accent, "nested palette ref");
        assert_eq!(t.background, None);
        assert_eq!(t.background_panel, Some(Color::Indexed(236)));
        assert_eq!(t.border, Color::Blue);
        assert_eq!(t.diff_added_word_bg, Some(Color::Rgb(0x2f, 0x5a, 0x49)));
        assert_eq!(t.mode_shell, Color::Rgb(0x78, 0x47, 0xbd), "light variant");
        assert_eq!(t.warning, Color::LightYellow);
        assert_eq!(t.syntax_theme, "Nord");
        // Untouched tokens come from the base.
        assert_eq!(t.success, Theme::light().success);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    #[test]
    fn resolve_loads_from_themes_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("mine.yaml"),
            "base: nord\ntokens:\n  accent: \"#ff0000\"\n",
        )
        .unwrap();
        let (t, warnings) = resolve("mine", Some(dir.path()), None);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(t.name, "mine");
        assert_eq!(t.accent, Color::Rgb(255, 0, 0));
        assert_eq!(t.background, Theme::builtin("nord").unwrap().background);
        std::fs::write(dir.path().join("broken.yaml"), "tokens: [").unwrap();
        let (t, warnings) = resolve("broken", Some(dir.path()), None);
        assert_eq!(t.name, "dark");
        assert_eq!(warnings.len(), 1);
        assert_eq!(custom_theme_names(dir.path()), vec!["broken", "mine"]);
    }

    const OPENCODE_FIXTURE: &str = r##"{
  "$schema": "https://opencode.ai/theme.json",
  "defs": {
    "nord0": "#2E3440",
    "nord1": "#3B4252",
    "nord4": "#D8DEE9",
    "nord8": "#88C0D0",
    "nord10": "#5E81AC",
    "nord14": "#A3BE8C",
    "nord11": "#BF616A"
  },
  "theme": {
    "primary": { "dark": "nord8", "light": "nord10" },
    "text": { "dark": "nord4", "light": "nord0" },
    "textMuted": { "dark": "#8B95A7", "light": "#4C566A" },
    "background": { "dark": "nord0", "light": "#ECEFF4" },
    "backgroundPanel": { "dark": "nord1", "light": "#E5E9F0" },
    "borderActive": { "dark": "#ffffff", "light": "#000000" },
    "success": { "dark": "nord14", "light": "nord14" },
    "error": "nord11",
    "diffAdded": { "dark": "nord14", "light": "nord14" },
    "diffAddedBg": { "dark": "#3B4A3D", "light": "#E6F0E0" },
    "diffRemovedBg": { "dark": "#4A3437", "light": "#F5E1E3" },
    "diffHighlightAdded": { "dark": "#C3E88D", "light": "#C3E88D" },
    "markdownBlockQuote": "none",
    "syntaxKeyword": { "dark": "nord8", "light": "nord10" },
    "bogus": "#123456"
  }
}"##;

    #[test]
    fn opencode_json_import() {
        let mut warnings = Vec::new();
        let t = load_opencode_json(OPENCODE_FIXTURE, "nord", Some(true), &mut warnings).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(t.is_dark);
        assert_eq!(t.accent, Color::Rgb(0x88, 0xc0, 0xd0));
        assert_eq!(t.user_prompt, t.accent);
        assert_eq!(t.border_active, Color::Rgb(255, 255, 255), "explicit wins");
        assert_eq!(t.text, Color::Rgb(0xd8, 0xde, 0xe9));
        assert_eq!(t.background, Some(Color::Rgb(0x2e, 0x34, 0x40)));
        assert_eq!(t.background_panel, Some(Color::Rgb(0x3b, 0x42, 0x52)));
        assert_eq!(t.error, Color::Rgb(0xbf, 0x61, 0x6a));
        assert_eq!(t.diff_added_bg, Some(Color::Rgb(0x3b, 0x4a, 0x3d)));
        assert_eq!(t.markdown_quote, Color::Reset);
        // Derived word bg sits between the line bg and the added colour.
        let Some(Color::Rgb(r, g, _)) = t.diff_added_word_bg else {
            panic!("word bg")
        };
        assert!(r > 0x3b && g > 0x4a);
        // Missing tokens fall back to the dark base.
        assert_eq!(t.warning, Theme::dark().warning);

        let light =
            load_opencode_json(OPENCODE_FIXTURE, "nord", Some(false), &mut warnings).unwrap();
        assert!(!light.is_dark);
        assert_eq!(light.accent, Color::Rgb(0x5e, 0x81, 0xac));

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("oc.json"), OPENCODE_FIXTURE).unwrap();
        let (t, w) = resolve("oc", Some(dir.path()), Some(true));
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(t.name, "oc");
    }

    #[test]
    fn mix_blends() {
        assert_eq!(
            mix(Color::Rgb(0, 0, 0), Color::Rgb(200, 100, 50), 0.5),
            Color::Rgb(100, 50, 25)
        );
        assert_eq!(mix(Color::Red, Color::Rgb(1, 1, 1), 0.5), Color::Red);
    }
}
