//! Diff rendering: line numbers, tinted backgrounds, word-level highlights, split view.
//!
//! Input is a unified diff body as produced by `microclaw_core::diff`
//! (`@@ -a,b +c,d @@` hunks, `+`/`-`/` ` lines, optional `… (diff
//! truncated …)` note); `---`/`+++`/`diff --git` file headers are accepted
//! and skipped. Output is themed ratatui lines fitted to a width.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use similar::{Algorithm, DiffOp, capture_diff_slices};

use super::theme::Theme;
use super::{hard_wrap, highlight, push_str, spans_width};

/// Terminal width from which `auto` picks the side-by-side view.
pub const SPLIT_MIN_WIDTH: u16 = 160;
/// Below this width even an explicit `split` setting falls back to unified.
const SPLIT_HARD_MIN: u16 = 60;

/// How a diff is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLayout {
    Unified,
    Split,
}

/// The user's `diff layout` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiffLayoutSetting {
    #[default]
    Auto,
    Split,
    Unified,
}

impl DiffLayoutSetting {
    /// Parse `auto` / `split` / `unified` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "split" | "side-by-side" | "sidebyside" => Some(Self::Split),
            "unified" | "inline" => Some(Self::Unified),
            _ => None,
        }
    }
}

impl From<microclaw_code_core::settings::DiffStyle> for DiffLayoutSetting {
    fn from(style: microclaw_code_core::settings::DiffStyle) -> Self {
        use microclaw_code_core::settings::DiffStyle;
        match style {
            DiffStyle::Auto => Self::Auto,
            DiffStyle::Split => Self::Split,
            DiffStyle::Unified => Self::Unified,
        }
    }
}

/// Pick the layout for a setting (`DiffLayoutSetting` or the settings
/// file's `DiffStyle`) at a terminal width.
pub fn choose_layout(setting: impl Into<DiffLayoutSetting>, width: u16) -> DiffLayout {
    match setting.into() {
        DiffLayoutSetting::Unified => DiffLayout::Unified,
        DiffLayoutSetting::Split if width >= SPLIT_HARD_MIN => DiffLayout::Split,
        DiffLayoutSetting::Split => DiffLayout::Unified,
        DiffLayoutSetting::Auto if width >= SPLIT_MIN_WIDTH => DiffLayout::Split,
        DiffLayoutSetting::Auto => DiffLayout::Unified,
    }
}

/// One-line header: `path  +N −M`.
pub fn header(path: &str, added: usize, removed: usize, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::styled(
        path.to_string(),
        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
    )];
    if added > 0 || removed > 0 {
        spans.push(Span::raw("  "));
    }
    if added > 0 {
        spans.push(Span::styled(
            format!("+{added}"),
            Style::default().fg(theme.diff_added),
        ));
    }
    if added > 0 && removed > 0 {
        spans.push(Span::raw(" "));
    }
    if removed > 0 {
        spans.push(Span::styled(
            format!("−{removed}"),
            Style::default().fg(theme.diff_removed),
        ));
    }
    Line::from(spans)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Context,
    Added,
    Removed,
}

#[derive(Debug)]
enum Row {
    Hunk,
    Line {
        kind: Kind,
        old: Option<usize>,
        new: Option<usize>,
        text: String,
        /// Syntax-highlighted code (filled by `highlight_rows`).
        hl: Option<Vec<Span<'static>>>,
        /// Changed byte ranges (word-level).
        words: Vec<(usize, usize)>,
    },
    Note(String),
}

fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    let rest = line.strip_prefix("@@ -")?;
    let (old, rest) = rest.split_once(" +")?;
    let new = rest.split_whitespace().next()?;
    let start = |s: &str| s.split(',').next()?.parse::<usize>().ok();
    Some((start(old)?, start(new)?))
}

fn parse(diff: &str) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut old_no = 1usize;
    let mut new_no = 1usize;
    let mut seen_hunk = false;
    let lines: Vec<&str> = diff.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim_end_matches('\r');
        i += 1;
        if let Some((o, n)) = parse_hunk_header(line) {
            // Empty sides are reported as `-0,0`.
            old_no = o.max(1);
            new_no = n.max(1);
            rows.push(Row::Hunk);
            seen_hunk = true;
            continue;
        }
        let file_header =
            line.starts_with("--- ") && lines.get(i).is_some_and(|next| next.starts_with("+++ "));
        if file_header {
            i += 1;
            continue;
        }
        if !seen_hunk
            && (line.starts_with("diff ")
                || line.starts_with("index ")
                || line.starts_with("new file")
                || line.starts_with("deleted file")
                || line.starts_with("similarity ")
                || line.starts_with("rename ")
                || line.starts_with("+++ ")
                || line.starts_with("--- "))
        {
            continue;
        }
        let (kind, text) = match line.chars().next() {
            Some('+') => (Kind::Added, &line[1..]),
            Some('-') => (Kind::Removed, &line[1..]),
            Some(' ') => (Kind::Context, &line[1..]),
            None => (Kind::Context, ""),
            Some(_) => {
                rows.push(Row::Note(line.to_string()));
                continue;
            }
        };
        let (old, new) = match kind {
            Kind::Context => {
                old_no += 1;
                new_no += 1;
                (Some(old_no - 1), Some(new_no - 1))
            }
            Kind::Removed => {
                old_no += 1;
                (Some(old_no - 1), None)
            }
            Kind::Added => {
                new_no += 1;
                (None, Some(new_no - 1))
            }
        };
        rows.push(Row::Line {
            kind,
            old,
            new,
            text: text.to_string(),
            hl: None,
            words: Vec::new(),
        });
    }
    rows
}

// ---------------------------------------------------------------------------
// Word-level diff
// ---------------------------------------------------------------------------

/// Split into identifier runs, whitespace runs and single punctuation
/// characters, returning (token, byte offset).
fn tokenize(s: &str) -> Vec<(&str, usize)> {
    let mut out = Vec::new();
    let mut start = None::<(usize, u8)>;
    let class = |c: char| -> u8 {
        if c.is_alphanumeric() || c == '_' {
            if c.is_ascii() { 1 } else { 3 }
        } else if c.is_whitespace() {
            2
        } else {
            0
        }
    };
    for (i, c) in s.char_indices() {
        let k = class(c);
        match start {
            // CJK / non-ASCII letters and punctuation are compared one
            // character at a time.
            Some((_, sk)) if sk == k && (k == 1 || k == 2) => {}
            Some((st, _)) => {
                out.push((&s[st..i], st));
                start = Some((i, k));
            }
            None => start = Some((i, k)),
        }
    }
    if let Some((st, _)) = start {
        out.push((&s[st..], st));
    }
    out
}

/// Byte ranges `[start, end)` within one line.
type Ranges = Vec<(usize, usize)>;

/// Changed byte ranges in `old` and `new`, or `None` when the lines are
/// too different for word highlighting to help.
fn word_ranges(old: &str, new: &str) -> Option<(Ranges, Ranges)> {
    if old.len() > 1_000 || new.len() > 1_000 {
        return None;
    }
    let a = tokenize(old);
    let b = tokenize(new);
    let at: Vec<&str> = a.iter().map(|t| t.0).collect();
    let bt: Vec<&str> = b.iter().map(|t| t.0).collect();
    let ops = capture_diff_slices(Algorithm::Myers, &at, &bt);
    let mut equal_bytes = 0usize;
    let mut ro = Vec::new();
    let mut rn = Vec::new();
    let range = |toks: &[(&str, usize)], idx: usize, len: usize| -> Option<(usize, usize)> {
        if len == 0 {
            return None;
        }
        let first = toks.get(idx)?;
        let last = toks.get(idx + len - 1)?;
        Some((first.1, last.1 + last.0.len()))
    };
    for op in ops {
        match op {
            DiffOp::Equal { old_index, len, .. } => {
                equal_bytes += a[old_index..old_index + len]
                    .iter()
                    .filter(|t| !t.0.trim().is_empty())
                    .map(|t| t.0.len())
                    .sum::<usize>();
            }
            DiffOp::Delete {
                old_index, old_len, ..
            } => ro.extend(range(&a, old_index, old_len)),
            DiffOp::Insert {
                new_index, new_len, ..
            } => rn.extend(range(&b, new_index, new_len)),
            DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => {
                ro.extend(range(&a, old_index, old_len));
                rn.extend(range(&b, new_index, new_len));
            }
        }
    }
    let longest = old.trim().len().max(new.trim().len()).max(1);
    if equal_bytes * 10 < longest * 4 {
        return None;
    }
    Some((ro, rn))
}

fn add_word_ranges(rows: &mut [Row]) {
    let mut i = 0;
    while i < rows.len() {
        let is = |r: &Row, k: Kind| matches!(r, Row::Line { kind, .. } if *kind == k);
        if !is(&rows[i], Kind::Removed) {
            i += 1;
            continue;
        }
        let del_start = i;
        while i < rows.len() && is(&rows[i], Kind::Removed) {
            i += 1;
        }
        let add_start = i;
        while i < rows.len() && is(&rows[i], Kind::Added) {
            i += 1;
        }
        let pairs = (add_start - del_start).min(i - add_start);
        for p in 0..pairs {
            let text = |r: &Row| match r {
                Row::Line { text, .. } => text.clone(),
                _ => String::new(),
            };
            let (old, new) = (text(&rows[del_start + p]), text(&rows[add_start + p]));
            if let Some((ro, rn)) = word_ranges(&old, &new) {
                if let Row::Line { words, .. } = &mut rows[del_start + p] {
                    *words = ro;
                }
                if let Row::Line { words, .. } = &mut rows[add_start + p] {
                    *words = rn;
                }
            }
        }
    }
}

/// Patch `style` onto the byte `ranges` of a span list.
fn overlay(
    spans: Vec<Span<'static>>,
    ranges: &[(usize, usize)],
    style: Style,
) -> Vec<Span<'static>> {
    if ranges.is_empty() {
        return spans;
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    for span in spans {
        let content = span.content.as_ref();
        let mut cuts = vec![0, content.len()];
        for (s, e) in ranges {
            for b in [*s, *e] {
                if b > offset && b < offset + content.len() {
                    cuts.push(b - offset);
                }
            }
        }
        cuts.sort_unstable();
        cuts.dedup();
        for w in cuts.windows(2) {
            let (a, b) = (w[0], w[1]);
            if a == b || !content.is_char_boundary(a) || !content.is_char_boundary(b) {
                continue;
            }
            let abs = offset + a;
            let inside = ranges.iter().any(|(s, e)| abs >= *s && abs < *e);
            let st = if inside {
                span.style.patch(style)
            } else {
                span.style
            };
            push_str(&mut out, &content[a..b], st);
        }
        offset += content.len();
    }
    out
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

struct Ctx<'a> {
    theme: &'a Theme,
    num_w: usize,
}

impl Ctx<'_> {
    fn line_bg(&self, kind: Kind) -> Option<ratatui::style::Color> {
        match kind {
            Kind::Added => self.theme.diff_added_bg,
            Kind::Removed => self.theme.diff_removed_bg,
            Kind::Context => None,
        }
    }

    fn base_style(&self, kind: Kind) -> Style {
        let mut s = Style::default();
        if let Some(bg) = self.line_bg(kind) {
            s = s.bg(bg);
        }
        s
    }

    /// Styled code for one diff line (highlighting + word overlay), using
    /// the old side for removed rows and the new side otherwise.
    fn code(&self, row: &Row) -> Vec<Span<'static>> {
        let Row::Line {
            kind,
            text,
            hl,
            words,
            ..
        } = row
        else {
            return Vec::new();
        };
        let t = self.theme;
        let fallback_fg = match (kind, self.line_bg(*kind)) {
            (Kind::Added, None) => t.diff_added,
            (Kind::Removed, None) => t.diff_removed,
            _ => t.text,
        };
        let base = self.base_style(*kind).fg(fallback_fg);
        let spans: Vec<Span<'static>> = match hl {
            Some(spans) => spans
                .iter()
                .map(|s| Span::styled(s.content.clone(), base.patch(s.style)))
                .collect(),
            None => vec![Span::styled(text.clone(), base)],
        };
        if words.is_empty() {
            return spans;
        }
        let word_style = t.diff_word_style(*kind == Kind::Added);
        overlay(spans, words, word_style)
    }

    fn number(&self, n: Option<usize>, style: Style) -> Span<'static> {
        let text = match n {
            Some(n) => format!("{n:>w$}", w = self.num_w),
            None => " ".repeat(self.num_w),
        };
        Span::styled(text, style.fg(self.theme.diff_line_number))
    }

    fn sign(&self, kind: Kind, style: Style) -> Span<'static> {
        let t = self.theme;
        match kind {
            Kind::Added => Span::styled("+", style.fg(t.diff_added)),
            Kind::Removed => Span::styled("-", style.fg(t.diff_removed)),
            Kind::Context => Span::styled(" ", style),
        }
    }

    fn note(&self, text: &str, width: usize) -> Line<'static> {
        let style = Style::default()
            .fg(self.theme.text_muted)
            .add_modifier(Modifier::ITALIC);
        let body = vec![Span::styled(
            format!("{} {}", " ".repeat(self.num_w), text),
            style,
        )];
        Line::from(super::truncate_spans(&body, width))
    }

    fn hunk(&self) -> Line<'static> {
        Line::from(Span::styled(
            format!("{}⋯", " ".repeat(self.num_w)),
            Style::default().fg(self.theme.diff_hunk),
        ))
    }
}

/// Pad a row to `width` with `style` (only when it carries a background).
fn pad(mut spans: Vec<Span<'static>>, width: usize, style: Style) -> Vec<Span<'static>> {
    let w = spans_width(&spans);
    if w < width && style.bg.is_some() {
        spans.push(Span::styled(" ".repeat(width - w), style));
    }
    spans
}

fn digits(n: usize) -> usize {
    n.max(1).to_string().len()
}

/// Syntax-highlight the first `limit` rows, following the old and new
/// file separately. Context lines are highlighted once while both sides'
/// parser states agree (the common case), so the cost is ~one pass.
fn highlight_rows(rows: &mut [Row], path: &str, theme: &Theme, limit: usize) {
    let Some(hl) = highlight::SyntaxHighlighter::new(path, theme) else {
        return;
    };
    let mut old = hl.start();
    let mut new = old.clone();
    let mut budget_lines = highlight::MAX_LINES;
    let mut budget_bytes = highlight::MAX_BYTES;
    for row in rows.iter_mut().take(limit) {
        let Row::Line {
            kind,
            text,
            hl: out,
            ..
        } = row
        else {
            continue;
        };
        if budget_lines == 0 || budget_bytes < text.len() {
            return;
        }
        budget_lines -= 1;
        budget_bytes -= text.len();
        *out = match kind {
            Kind::Removed => hl.line(&mut old, text),
            Kind::Added => hl.line(&mut new, text),
            Kind::Context if old == new => {
                let spans = hl.line(&mut new, text);
                old.clone_from(&new);
                spans
            }
            Kind::Context => {
                let _ = hl.line(&mut old, text);
                hl.line(&mut new, text)
            }
        };
    }
}

/// Render a unified diff body for `path` (used for syntax detection).
///
/// `max_lines` caps the number of output lines; when it cuts, the last
/// line is a `… N more lines` footer (N counts diff lines not shown).
pub fn render(
    diff: &str,
    path: &str,
    width: u16,
    theme: &Theme,
    layout: DiffLayout,
    max_lines: Option<usize>,
) -> Vec<Line<'static>> {
    let width = (width as usize).max(10);
    let mut rows = parse(diff);
    add_word_ranges(&mut rows);

    // Every row yields at least one line, so rows past the cap never show.
    highlight_rows(&mut rows, path, theme, max_lines.unwrap_or(usize::MAX));
    let max_no = rows
        .iter()
        .filter_map(|r| match r {
            Row::Line { old, new, .. } => Some(old.unwrap_or(0).max(new.unwrap_or(0))),
            _ => None,
        })
        .max()
        .unwrap_or(1);
    let ctx = Ctx {
        theme,
        num_w: digits(max_no),
    };

    let units = match layout {
        DiffLayout::Unified => unified_units(&ctx, &rows, width),
        DiffLayout::Split => split_units(&ctx, &rows, width),
    };
    apply_limit(units, max_lines, theme, ctx.num_w)
}

/// A rendered group of lines plus how many diff lines it represents.
struct Unit {
    lines: Vec<Line<'static>>,
    source: usize,
}

fn apply_limit(
    units: Vec<Unit>,
    max_lines: Option<usize>,
    theme: &Theme,
    num_w: usize,
) -> Vec<Line<'static>> {
    let Some(limit) = max_lines else {
        return units.into_iter().flat_map(|u| u.lines).collect();
    };
    let limit = limit.max(1);
    let mut out: Vec<Line<'static>> = Vec::new();
    let n = units.len();
    let mut remaining = 0usize;
    let mut cut = false;
    for (i, unit) in units.into_iter().enumerate() {
        if cut {
            remaining += unit.source;
            continue;
        }
        let fits = out.len() + unit.lines.len() < limit
            || (i + 1 == n && out.len() + unit.lines.len() <= limit);
        if fits {
            out.extend(unit.lines);
        } else {
            cut = true;
            remaining += unit.source;
        }
    }
    if cut {
        // Hunk separators without any following content are noise.
        while out
            .last()
            .is_some_and(|l| super::line_text(l).trim() == "⋯")
        {
            out.pop();
        }
        let label = if remaining == 1 { "line" } else { "lines" };
        out.push(Line::from(Span::styled(
            format!("{}… {remaining} more {label}", " ".repeat(num_w)),
            Style::default().fg(theme.text_muted),
        )));
    }
    out
}

fn unified_units(ctx: &Ctx<'_>, rows: &[Row], width: usize) -> Vec<Unit> {
    let gutter_w = ctx.num_w * 2 + 4;
    let code_w = width.saturating_sub(gutter_w).max(4);
    let mut units = Vec::new();
    let mut first_hunk = true;
    for row in rows {
        match row {
            Row::Hunk => {
                if !first_hunk {
                    units.push(Unit {
                        lines: vec![ctx.hunk()],
                        source: 0,
                    });
                }
                first_hunk = false;
            }
            Row::Note(text) => units.push(Unit {
                lines: vec![ctx.note(text, width)],
                source: 1,
            }),
            Row::Line { kind, old, new, .. } => {
                first_hunk = false;
                let style = ctx.base_style(*kind);
                let code = ctx.code(row);
                let mut lines = Vec::new();
                for (i, chunk) in hard_wrap(&code, code_w).into_iter().enumerate() {
                    let mut spans = if i == 0 {
                        vec![
                            ctx.number(*old, style),
                            Span::styled(" ", style),
                            ctx.number(*new, style),
                            Span::styled(" ", style),
                            ctx.sign(*kind, style),
                            Span::styled(" ", style),
                        ]
                    } else {
                        vec![Span::styled(" ".repeat(gutter_w), style)]
                    };
                    spans.extend(chunk);
                    lines.push(Line::from(pad(spans, width, style)));
                }
                units.push(Unit { lines, source: 1 });
            }
        }
    }
    units
}

/// One side of a split row: numbered, wrapped, padded cells.
fn side_cells(
    ctx: &Ctx<'_>,
    row: Option<&Row>,
    old_side: bool,
    w: usize,
) -> Vec<Vec<Span<'static>>> {
    let gutter_w = ctx.num_w + 3;
    let code_w = w.saturating_sub(gutter_w).max(2);
    let Some(row @ Row::Line { kind, old, new, .. }) = row else {
        return Vec::new();
    };
    let style = ctx.base_style(*kind);
    let num = if old_side { *old } else { *new };
    let code = ctx.code(row);
    hard_wrap(&code, code_w)
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut spans = if i == 0 {
                vec![
                    ctx.number(num, style),
                    Span::styled(" ", style),
                    ctx.sign(*kind, style),
                    Span::styled(" ", style),
                ]
            } else {
                vec![Span::styled(" ".repeat(gutter_w), style)]
            };
            spans.extend(chunk);
            pad(spans, w, style)
        })
        .collect()
}

fn split_units(ctx: &Ctx<'_>, rows: &[Row], width: usize) -> Vec<Unit> {
    let left_w = (width - 1) / 2;
    let right_w = width - 1 - left_w;
    let sep = Span::styled("│", Style::default().fg(ctx.theme.border));
    let combine = |l: Vec<Vec<Span<'static>>>, r: Vec<Vec<Span<'static>>>| -> Vec<Line<'static>> {
        let h = l.len().max(r.len());
        (0..h)
            .map(|i| {
                let mut left = l.get(i).cloned().unwrap_or_default();
                let lw = spans_width(&left);
                if lw < left_w {
                    left.push(Span::raw(" ".repeat(left_w - lw)));
                }
                left.push(sep.clone());
                let mut right = r.get(i).cloned().unwrap_or_default();
                let rw = spans_width(&right);
                if rw < right_w {
                    right.push(Span::raw(" ".repeat(right_w - rw)));
                }
                left.extend(right);
                Line::from(left)
            })
            .collect()
    };
    let mut units = Vec::new();
    let mut first_hunk = true;
    let mut i = 0;
    while i < rows.len() {
        match &rows[i] {
            Row::Hunk => {
                if !first_hunk {
                    let mut line = ctx.hunk();
                    let w = line.width();
                    line.spans
                        .push(Span::raw(" ".repeat(left_w.saturating_sub(w))));
                    line.spans.push(sep.clone());
                    line.spans.push(ctx.hunk().spans[0].clone());
                    units.push(Unit {
                        lines: vec![line],
                        source: 0,
                    });
                }
                first_hunk = false;
                i += 1;
            }
            Row::Note(text) => {
                units.push(Unit {
                    lines: vec![ctx.note(text, width)],
                    source: 1,
                });
                i += 1;
            }
            Row::Line {
                kind: Kind::Context,
                ..
            } => {
                first_hunk = false;
                let row = Some(&rows[i]);
                units.push(Unit {
                    lines: combine(
                        side_cells(ctx, row, true, left_w),
                        side_cells(ctx, row, false, right_w),
                    ),
                    source: 1,
                });
                i += 1;
            }
            Row::Line { .. } => {
                first_hunk = false;
                // A change block: removed lines then added lines.
                let mut removed = Vec::new();
                let mut added = Vec::new();
                while let Some(
                    r @ Row::Line {
                        kind: Kind::Removed,
                        ..
                    },
                ) = rows.get(i)
                {
                    removed.push(r);
                    i += 1;
                }
                while let Some(
                    r @ Row::Line {
                        kind: Kind::Added, ..
                    },
                ) = rows.get(i)
                {
                    added.push(r);
                    i += 1;
                }
                for p in 0..removed.len().max(added.len()) {
                    let l = removed.get(p).copied();
                    let r = added.get(p).copied();
                    units.push(Unit {
                        lines: combine(
                            side_cells(ctx, l, true, left_w),
                            side_cells(ctx, r, false, right_w),
                        ),
                        source: usize::from(l.is_some()) + usize::from(r.is_some()),
                    });
                }
            }
        }
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::line_text;
    use ratatui::style::Color;

    const DIFF: &str = "@@ -1,4 +1,4 @@\n fn main() {\n-    let x = 1;\n+    let x = 2;\n     println!(\"{x}\");\n }\n@@ -40,2 +40,3 @@\n fn tail() {}\n+fn added() {}\n // end";

    fn texts(lines: &[Line<'_>]) -> Vec<String> {
        lines.iter().map(line_text).collect()
    }

    #[test]
    fn layout_choice() {
        use DiffLayoutSetting as S;
        assert_eq!(choose_layout(S::Auto, 200), DiffLayout::Split);
        assert_eq!(choose_layout(S::Auto, 159), DiffLayout::Unified);
        assert_eq!(choose_layout(S::Split, 100), DiffLayout::Split);
        assert_eq!(choose_layout(S::Split, 40), DiffLayout::Unified);
        assert_eq!(choose_layout(S::Unified, 300), DiffLayout::Unified);
        assert_eq!(DiffLayoutSetting::parse("Split"), Some(S::Split));
        assert_eq!(DiffLayoutSetting::parse("x"), None);
    }

    #[test]
    fn unified_numbering_and_backgrounds() {
        let theme = Theme::dark();
        let lines = render(DIFF, "main.rs", 60, &theme, DiffLayout::Unified, None);
        let t = texts(&lines);
        assert_eq!(t[0].trim_end(), " 1  1   fn main() {");
        assert_eq!(t[1].trim_end(), " 2    -     let x = 1;");
        assert_eq!(t[2].trim_end(), "    2 +     let x = 2;");
        assert_eq!(t[3].trim_end(), " 3  3       println!(\"{x}\");");
        assert_eq!(t[5].trim(), "⋯");
        assert_eq!(t[6].trim_end(), "40 40   fn tail() {}");
        assert_eq!(t[7].trim_end(), "   41 + fn added() {}");
        assert_eq!(t[8].trim_end(), "41 42   // end");
        // Added / removed rows are padded to the full width with the tint.
        assert_eq!(lines[2].width(), 60);
        assert!(
            lines[2].spans.iter().all(
                |s| s.style.bg == theme.diff_added_bg || s.style.bg == theme.diff_added_word_bg
            )
        );
        assert!(lines[0].spans.iter().all(|s| s.style.bg.is_none()));
        assert_eq!(lines[1].spans[0].style.fg, Some(theme.diff_line_number));
        assert_eq!(lines[1].spans[4].content, "-");
        assert_eq!(lines[1].spans[4].style.fg, Some(theme.diff_removed));
    }

    #[test]
    fn word_level_spans() {
        let theme = Theme::dark();
        let lines = render(DIFF, "main.rs", 60, &theme, DiffLayout::Unified, None);
        let word = |l: &Line<'static>, bg| -> String {
            l.spans
                .iter()
                .filter(|s| s.style.bg == bg)
                .map(|s| s.content.as_ref())
                .collect()
        };
        assert_eq!(word(&lines[1], theme.diff_removed_word_bg), "1");
        assert_eq!(word(&lines[2], theme.diff_added_word_bg), "2");
        // Syntax colours survive underneath the tint.
        let kw = lines[2].spans.iter().find(|s| s.content == "let").unwrap();
        assert!(matches!(kw.style.fg, Some(Color::Rgb(..))));
        assert_ne!(kw.style.fg, Some(theme.text));
        // Unrelated lines get no word highlight.
        assert_eq!(
            word_ranges("completely different", "nothing alike here at all"),
            None
        );
    }

    #[test]
    fn split_alignment() {
        let theme = Theme::dark();
        let diff = "@@ -1,3 +1,4 @@\n a\n-b\n+B\n+C\n d";
        let lines = render(diff, "x.txt", 61, &theme, DiffLayout::Split, None);
        let t = texts(&lines);
        assert_eq!(t.len(), 4);
        for l in &lines {
            assert_eq!(l.width(), 61, "{:?}", line_text(l));
        }
        let halves: Vec<(String, String)> = t
            .iter()
            .map(|l| {
                let (a, b) = l.split_once('│').unwrap();
                (a.trim_end().to_string(), b.trim_end().to_string())
            })
            .collect();
        assert_eq!(halves[0], ("1   a".into(), "1   a".into()));
        assert_eq!(halves[1], ("2 - b".into(), "2 + B".into()));
        assert_eq!(halves[2], ("".into(), "3 + C".into()), "filler on the left");
        assert_eq!(halves[3], ("3   d".into(), "4   d".into()));
        // The separator sits at the same column on every row.
        let col = |l: &Line<'_>| {
            let mut w = 0;
            for s in &l.spans {
                if s.content == "│" {
                    return w;
                }
                w += s.width();
            }
            usize::MAX
        };
        assert!(lines.iter().all(|l| col(l) == 30));
    }

    #[test]
    fn truncation_footer() {
        let theme = Theme::dark();
        let body: String = (1..=50).map(|i| format!("+line {i}\n")).collect();
        let diff = format!("@@ -0,0 +1,50 @@\n{body}");
        let lines = render(&diff, "a.txt", 40, &theme, DiffLayout::Unified, Some(10));
        assert_eq!(lines.len(), 10);
        assert_eq!(line_text(&lines[9]).trim(), "… 41 more lines");
        assert_eq!(lines[9].spans[0].style.fg, Some(theme.text_muted));
        // Exactly fitting needs no footer.
        let small = "@@ -1,1 +1,1 @@\n-a\n+b";
        assert_eq!(
            render(small, "a", 40, &theme, DiffLayout::Unified, Some(2)).len(),
            2
        );
    }

    #[test]
    fn wraps_long_lines_and_handles_headers() {
        let theme = Theme::dark();
        let diff = format!(
            "--- a/x.txt\n+++ b/x.txt\n@@ -1 +1 @@\n-short\n+{}\n\\ No newline at end of file\n… (diff truncated at 4 lines)",
            "y".repeat(50)
        );
        let lines = render(&diff, "x.txt", 30, &theme, DiffLayout::Unified, None);
        let t = texts(&lines);
        assert!(t[0].starts_with("1   - short"), "{t:?}");
        assert!(t[1].starts_with("  1 + yyyy"));
        assert!(t[2].starts_with("      yyyy"), "continuation keeps gutter");
        assert!(lines.iter().all(|l| l.width() <= 30));
        assert!(t.iter().any(|l| l.contains("No newline")));
        assert!(t.last().unwrap().contains("diff truncated"));
    }

    #[test]
    fn ansi_theme_uses_fg_and_reverse() {
        let theme = Theme::ansi();
        let lines = render(DIFF, "main.rs", 60, &theme, DiffLayout::Unified, None);
        assert!(
            lines
                .iter()
                .flat_map(|l| l.spans.iter())
                .all(|s| s.style.bg.is_none())
        );
        let two = lines[2]
            .spans
            .iter()
            .find(|s| s.content == "2" && s.style.add_modifier.contains(Modifier::REVERSED));
        assert!(two.is_some());
        let code = lines[2]
            .spans
            .iter()
            .find(|s| s.content.contains("let"))
            .unwrap();
        assert_eq!(code.style.fg, Some(Color::Green));
    }

    #[test]
    fn header_line() {
        let theme = Theme::dark();
        let h = header("src/a.rs", 3, 1, &theme);
        assert_eq!(line_text(&h), "src/a.rs  +3 −1");
        assert_eq!(h.spans[2].style.fg, Some(theme.diff_added));
        assert_eq!(line_text(&header("b", 0, 0, &theme)), "b");
    }
}
