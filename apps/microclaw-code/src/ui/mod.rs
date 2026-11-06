//! Presentation building blocks shared by the TUI: themes, Markdown,
//! syntax highlighting and diff rendering. Pure functions over ratatui
//! `Line`s; no terminal I/O (apart from the theme's environment-based
//! detection helpers).
//!
//! Width handling is unicode-aware throughout (`unicode-width`): wide CJK
//! characters are never split, and wrapping may break between two CJK
//! characters as well as at spaces.

// A small library consumed by `tui/`; not every helper is wired up yet.
#![allow(dead_code)]

pub mod diff;
pub mod highlight;
pub mod markdown;
pub mod theme;

#[allow(unused_imports)]
pub use diff::{DiffLayout, DiffLayoutSetting};
#[allow(unused_imports)]
pub use theme::{ColorDepth, Theme};

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Display width of a string in terminal cells.
pub fn display_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Display width of a span sequence.
pub fn spans_width(spans: &[Span<'_>]) -> usize {
    spans.iter().map(|s| display_width(&s.content)).sum()
}

fn char_width(c: char) -> usize {
    if c == '\t' {
        4
    } else {
        UnicodeWidthChar::width(c).unwrap_or(0)
    }
}

/// Characters that should not start a line (CJK closing punctuation): they
/// stay glued to the previous character when wrapping.
fn no_line_start(c: char) -> bool {
    matches!(
        c,
        '，' | '。'
            | '、'
            | '；'
            | '：'
            | '！'
            | '？'
            | '）'
            | '」'
            | '』'
            | '》'
            | '〉'
            | '】'
            | '”'
            | '’'
            | '…'
            | '·'
    )
}

fn is_wide(c: char) -> bool {
    char_width(c) >= 2
}

/// Append `ch` with `style` to `out`, merging into the last span when the
/// style matches.
fn push_char(out: &mut Vec<Span<'static>>, ch: char, style: Style) {
    if let Some(last) = out.last_mut()
        && last.style == style
    {
        last.content.to_mut().push(ch);
        return;
    }
    out.push(Span::styled(ch.to_string(), style));
}

/// Push a whole string as one styled span, merging with the previous span
/// when the style matches.
pub fn push_str(out: &mut Vec<Span<'static>>, s: &str, style: Style) {
    if s.is_empty() {
        return;
    }
    if let Some(last) = out.last_mut()
        && last.style == style
    {
        last.content.to_mut().push_str(s);
        return;
    }
    out.push(Span::styled(s.to_string(), style));
}

#[derive(Clone, Copy, PartialEq)]
enum Tok {
    Word,
    Space,
    Newline,
}

/// Word-wrap styled spans to `width` cells.
///
/// Breaks at spaces and between wide (CJK) characters; words longer than a
/// line are split at character boundaries. Leading spaces of continuation
/// lines are dropped, `\n` forces a break. Returns at least one (possibly
/// empty) line.
pub fn wrap_spans(spans: &[Span<'_>], width: usize) -> Vec<Vec<Span<'static>>> {
    let width = width.max(1);
    // Tokenise into (kind, chars-with-style).
    let mut tokens: Vec<(Tok, Vec<(char, Style)>)> = Vec::new();
    for span in spans {
        for ch in span.content.chars() {
            let kind = match ch {
                '\n' => Tok::Newline,
                ' ' | '\t' => Tok::Space,
                _ => Tok::Word,
            };
            let ch = if ch == '\t' { ' ' } else { ch };
            let glue = match (tokens.last(), kind) {
                (Some((Tok::Word, prev)), Tok::Word) => {
                    let p = prev.last().map(|(c, _)| *c).unwrap_or(' ');
                    // Wide chars stand alone, except closing punctuation
                    // which sticks to whatever precedes it.
                    no_line_start(ch) || (!is_wide(ch) && !is_wide(p))
                }
                (Some((Tok::Space, _)), Tok::Space) => true,
                _ => false,
            };
            if glue {
                if let Some(last) = tokens.last_mut() {
                    last.1.push((ch, span.style));
                }
            } else {
                tokens.push((kind, vec![(ch, span.style)]));
            }
        }
    }

    let mut lines: Vec<Vec<Span<'static>>> = Vec::new();
    let mut cur: Vec<Span<'static>> = Vec::new();
    let mut cur_w = 0usize;
    let mut pending_space: Vec<(char, Style)> = Vec::new();
    for (kind, chars) in tokens {
        match kind {
            Tok::Newline => {
                lines.push(std::mem::take(&mut cur));
                cur_w = 0;
                pending_space.clear();
            }
            Tok::Space => {
                if cur_w > 0 {
                    pending_space = chars;
                }
            }
            Tok::Word => {
                let w: usize = chars.iter().map(|(c, _)| char_width(*c)).sum();
                let space_w = pending_space.len();
                if cur_w > 0 && cur_w + space_w + w > width {
                    lines.push(std::mem::take(&mut cur));
                    cur_w = 0;
                    pending_space.clear();
                }
                if cur_w > 0 {
                    for (c, s) in pending_space.drain(..) {
                        push_char(&mut cur, c, s);
                        cur_w += 1;
                    }
                }
                pending_space.clear();
                for (c, s) in chars {
                    let cw = char_width(c);
                    if cur_w + cw > width && cur_w > 0 {
                        lines.push(std::mem::take(&mut cur));
                        cur_w = 0;
                    }
                    push_char(&mut cur, c, s);
                    cur_w += cw;
                }
            }
        }
    }
    if !cur.is_empty() || lines.is_empty() {
        lines.push(cur);
    }
    lines
}

/// Wrap `spans` and prepend `first` to the first line and `rest` to each
/// continuation line (hanging indent / gutters). The content width is
/// `width` minus the prefix width.
pub fn wrap_with_prefix(
    spans: &[Span<'_>],
    width: usize,
    first: &[Span<'static>],
    rest: &[Span<'static>],
) -> Vec<Line<'static>> {
    let prefix_w = spans_width(first).max(spans_width(rest));
    let content_w = width.saturating_sub(prefix_w).max(1);
    wrap_spans(spans, content_w)
        .into_iter()
        .enumerate()
        .map(|(i, body)| {
            let mut out = if i == 0 {
                first.to_vec()
            } else {
                rest.to_vec()
            };
            out.extend(body);
            Line::from(out)
        })
        .collect()
}

/// Split styled spans into rows of exactly `width` cells (character
/// wrapping, whitespace preserved; for code). A wide character that would
/// straddle the edge moves to the next row. Tabs become 4 spaces.
pub fn hard_wrap(spans: &[Span<'_>], width: usize) -> Vec<Vec<Span<'static>>> {
    let width = width.max(2);
    let mut rows = vec![Vec::new()];
    let mut w = 0usize;
    for span in spans {
        for ch in span.content.chars() {
            if ch == '\n' || ch == '\r' {
                continue;
            }
            let (ch, n) = if ch == '\t' { (' ', 4) } else { (ch, 1) };
            for _ in 0..n {
                let cw = char_width(ch);
                if w + cw > width {
                    rows.push(Vec::new());
                    w = 0;
                }
                if let Some(row) = rows.last_mut() {
                    push_char(row, ch, span.style);
                }
                w += cw;
            }
        }
    }
    rows
}

/// Cut styled spans to at most `width` cells, ending with `…` when
/// anything was dropped. Tabs become 4 spaces.
pub fn truncate_spans(spans: &[Span<'_>], width: usize) -> Vec<Span<'static>> {
    let total: usize = spans
        .iter()
        .flat_map(|s| s.content.chars())
        .map(char_width)
        .sum();
    let mut out = Vec::new();
    if total <= width {
        for span in spans {
            push_str(&mut out, &span.content.replace('\t', "    "), span.style);
        }
        return out;
    }
    if width == 0 {
        return out;
    }
    let budget = width - 1;
    let mut w = 0usize;
    let mut last_style = Style::default();
    'outer: for span in spans {
        last_style = span.style;
        for ch in span.content.chars() {
            let (ch, n) = if ch == '\t' { (' ', 4) } else { (ch, 1) };
            for _ in 0..n {
                let cw = char_width(ch);
                if w + cw > budget {
                    break 'outer;
                }
                push_char(&mut out, ch, span.style);
                w += cw;
            }
        }
    }
    push_char(&mut out, '…', last_style);
    out
}

/// Concatenated text of a line (test / inspection helper).
pub fn line_text(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Modifier};

    fn texts(rows: &[Vec<Span<'static>>]) -> Vec<String> {
        rows.iter()
            .map(|r| r.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn wraps_words_and_keeps_styles() {
        let bold = Style::default().add_modifier(Modifier::BOLD);
        let spans = vec![
            Span::raw("hello "),
            Span::styled("bold world", bold),
            Span::raw(" again"),
        ];
        let rows = wrap_spans(&spans, 11);
        assert_eq!(texts(&rows), vec!["hello bold", "world again"]);
        assert_eq!(rows[0][1].style, bold);
        assert_eq!(rows[1][0].content, "world");
        assert_eq!(rows[1][0].style, bold);
    }

    #[test]
    fn wraps_cjk_without_splitting_wide_chars() {
        let rows = wrap_spans(&[Span::raw("修一下解析器里的空行问题，并补测试。")], 9);
        for row in texts(&rows) {
            assert!(display_width(&row) <= 9, "{row}");
        }
        // Closing punctuation never starts a line.
        for row in texts(&rows).iter().skip(1) {
            assert!(!row.starts_with('，') && !row.starts_with('。'), "{row}");
        }
        let joined: String = texts(&rows).concat();
        assert_eq!(joined, "修一下解析器里的空行问题，并补测试。");
        // Odd width: a 2-cell char never straddles the edge.
        let rows = wrap_spans(&[Span::raw("中文中文中文")], 5);
        assert_eq!(texts(&rows), vec!["中文", "中文", "中文"]);
        // Mixed Latin and CJK.
        let rows = wrap_spans(&[Span::raw("use 中文 words")], 8);
        assert_eq!(texts(&rows), vec!["use 中文", "words"]);
    }

    #[test]
    fn long_words_and_newlines() {
        let rows = wrap_spans(&[Span::raw("abcdefghij\nxy")], 4);
        assert_eq!(texts(&rows), vec!["abcd", "efgh", "ij", "xy"]);
        assert_eq!(wrap_spans(&[], 10).len(), 1);
    }

    #[test]
    fn prefix_and_truncate() {
        let lines = wrap_with_prefix(
            &[Span::raw("one two three")],
            8,
            &[Span::raw("• ")],
            &[Span::raw("  ")],
        );
        let t: Vec<String> = lines.iter().map(line_text).collect();
        assert_eq!(t, vec!["• one", "  two", "  three"]);

        let cut = truncate_spans(
            &[Span::styled("abcdef", Style::default().fg(Color::Red))],
            4,
        );
        assert_eq!(cut.len(), 1);
        assert_eq!(cut[0].content, "abc…");
        assert_eq!(
            truncate_spans(&[Span::raw("中文中文")], 4)
                .iter()
                .map(|s| s.content.to_string())
                .collect::<String>(),
            "中…"
        );
        let rows = hard_wrap(&[Span::raw("a\tb中文")], 4);
        assert_eq!(texts(&rows), vec!["a   ", " b中", "文"]);
    }
}
