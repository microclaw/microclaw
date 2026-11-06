//! Markdown to styled ratatui lines.
//!
//! [`render`] turns CommonMark (+ tables, strikethrough, task lists) into
//! wrapped, themed lines; [`render_streaming`] does the same for a message
//! that is still arriving and reports how many leading lines are stable.

use pulldown_cmark::{Alignment, CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::theme::Theme;
use super::{
    display_width, highlight, push_str, spans_width, truncate_spans, wrap_spans, wrap_with_prefix,
};

/// Render a complete Markdown document to lines no wider than `width`.
pub fn render(markdown: &str, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let mut r = Renderer::new(theme, width.max(4) as usize);
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    for event in Parser::new_ext(markdown, options) {
        r.event(event);
    }
    r.finish()
}

/// Render a message that is still streaming in.
///
/// Returns the lines plus the number of leading lines that will not change
/// when more text arrives (everything before the last block boundary), so
/// a caller can cache / commit them. Partial constructs are handled:
/// an unclosed code fence renders as code, a trailing incomplete table row
/// (and a table header still waiting for its delimiter row) is held back,
/// as is a half-typed closing fence.
pub fn render_streaming(markdown: &str, width: u16, theme: &Theme) -> (Vec<Line<'static>>, usize) {
    let visible = streaming_visible(markdown);
    let lines = render(visible, width, theme);
    let boundary = last_block_boundary(visible);
    if boundary == 0 {
        return (lines, 0);
    }
    let stable_lines = render(&visible[..boundary], width, theme);
    let stable = stable_lines
        .iter()
        .zip(lines.iter())
        .take_while(|(a, b)| a == b)
        .count();
    (lines, stable)
}

fn is_table_line(line: &str) -> bool {
    line.trim_start().starts_with('|')
}

fn is_fence_line(line: &str) -> bool {
    let t = line.trim_start();
    line.len() - t.len() <= 3 && (t.starts_with("```") || t.starts_with("~~~"))
}

/// The prefix of a streaming message that is safe to render.
fn streaming_visible(md: &str) -> &str {
    let mut visible = md;
    if !visible.ends_with('\n') {
        let start = visible.rfind('\n').map(|i| i + 1).unwrap_or(0);
        let partial = visible[start..].trim_start();
        let half_fence = partial.starts_with('`') || partial.starts_with('~');
        if is_table_line(partial) || (half_fence && partial.len() < 3) || is_fence_line(partial) {
            visible = &visible[..start];
        }
    }
    // A lone table header line still waiting for its delimiter row.
    let body = visible.strip_suffix('\n').unwrap_or(visible);
    let last_start = body.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let last = &body[last_start..];
    if is_table_line(last) && !last.contains("---") {
        let prev = body[..last_start.saturating_sub(1)]
            .rsplit('\n')
            .next()
            .unwrap_or("");
        if last_start == 0 || !is_table_line(prev) {
            visible = &visible[..last_start];
        }
    }
    visible
}

/// Byte offset just after the last blank line outside a code fence.
fn last_block_boundary(md: &str) -> usize {
    let mut in_fence = false;
    let mut boundary = 0;
    let mut offset = 0;
    for line in md.split_inclusive('\n') {
        offset += line.len();
        if is_fence_line(line) {
            in_fence = !in_fence;
        } else if !in_fence && line.trim().is_empty() && line.ends_with('\n') {
            boundary = offset;
        }
    }
    boundary
}

enum Container {
    Quote,
    Item {
        marker: Vec<Span<'static>>,
        indent: usize,
        used: bool,
    },
}

struct ListState {
    next: Option<u64>,
}

struct TableState {
    aligns: Vec<Alignment>,
    rows: Vec<Vec<Vec<Span<'static>>>>,
    header_rows: usize,
}

struct Renderer<'t> {
    theme: &'t Theme,
    width: usize,
    out: Vec<Line<'static>>,
    inline: Vec<Span<'static>>,
    bold: u32,
    italic: u32,
    strike: u32,
    links: Vec<(String, usize)>,
    heading: Option<HeadingLevel>,
    containers: Vec<Container>,
    lists: Vec<ListState>,
    pending_blank: bool,
    code: Option<(String, String)>,
    table: Option<TableState>,
}

impl<'t> Renderer<'t> {
    fn new(theme: &'t Theme, width: usize) -> Self {
        Self {
            theme,
            width,
            out: Vec::new(),
            inline: Vec::new(),
            bold: 0,
            italic: 0,
            strike: 0,
            links: Vec::new(),
            heading: None,
            containers: Vec::new(),
            lists: Vec::new(),
            pending_blank: false,
            code: None,
            table: None,
        }
    }

    fn finish(mut self) -> Vec<Line<'static>> {
        if let Some((lang, text)) = self.code.take() {
            self.render_code(&lang, &text);
        }
        if self.table.is_some() {
            self.end_table();
        }
        self.flush_inline();
        while self.out.last().is_some_and(|l| l.width() == 0) {
            self.out.pop();
        }
        self.out
    }

    // -- styles -------------------------------------------------------------

    fn in_quote(&self) -> bool {
        self.containers
            .iter()
            .any(|c| matches!(c, Container::Quote))
    }

    fn text_style(&self) -> Style {
        let t = self.theme;
        let mut s = Style::default().fg(if self.in_quote() {
            t.markdown_quote
        } else {
            t.text
        });
        if let Some(level) = self.heading {
            s = s.add_modifier(Modifier::BOLD);
            s = match level {
                HeadingLevel::H1 => s.fg(t.markdown_heading).add_modifier(Modifier::UNDERLINED),
                HeadingLevel::H2 | HeadingLevel::H3 => s.fg(t.markdown_heading),
                _ => s.fg(t.text),
            };
        }
        if self.bold > 0 {
            s = s.add_modifier(Modifier::BOLD);
        }
        if self.italic > 0 {
            s = s.add_modifier(Modifier::ITALIC);
        }
        if self.strike > 0 {
            s = s.add_modifier(Modifier::CROSSED_OUT);
        }
        if !self.links.is_empty() {
            s = s.fg(t.markdown_link).add_modifier(Modifier::UNDERLINED);
        }
        s
    }

    fn code_style(&self) -> Style {
        let mut s = Style::default().fg(self.theme.markdown_code);
        if let Some(bg) = self.theme.background_element {
            s = s.bg(bg);
        }
        if self.bold > 0 || self.heading.is_some() {
            s = s.add_modifier(Modifier::BOLD);
        }
        s
    }

    // -- prefixes -----------------------------------------------------------

    fn quote_gutter(&self) -> Span<'static> {
        Span::styled("▎ ", Style::default().fg(self.theme.markdown_quote))
    }

    /// (first-line prefix, continuation prefix) for the current containers.
    fn prefixes(&self) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
        let mut first = Vec::new();
        let mut rest = Vec::new();
        for c in &self.containers {
            match c {
                Container::Quote => {
                    first.push(self.quote_gutter());
                    rest.push(self.quote_gutter());
                }
                Container::Item {
                    marker,
                    indent,
                    used,
                } => {
                    let pad = Span::raw(" ".repeat(*indent));
                    if *used {
                        first.push(pad.clone());
                    } else {
                        first.extend(marker.iter().cloned());
                    }
                    rest.push(pad);
                }
            }
        }
        (first, rest)
    }

    fn mark_items_used(&mut self) {
        for c in &mut self.containers {
            if let Container::Item { used, .. } = c {
                *used = true;
            }
        }
    }

    fn content_width(&self) -> usize {
        let (first, rest) = self.prefixes();
        self.width
            .saturating_sub(spans_width(&first).max(spans_width(&rest)))
            .max(1)
    }

    /// Emit pre-laid-out rows with container prefixes.
    fn emit_rows(&mut self, rows: Vec<Vec<Span<'static>>>) {
        let (first, rest) = self.prefixes();
        for (i, body) in rows.into_iter().enumerate() {
            let mut spans = if i == 0 { first.clone() } else { rest.clone() };
            spans.extend(body);
            self.out.push(Line::from(spans));
        }
        self.mark_items_used();
    }

    fn blank(&mut self) {
        let mut spans = Vec::new();
        for c in &self.containers {
            if matches!(c, Container::Quote) {
                spans.push(Span::styled(
                    "▎",
                    Style::default().fg(self.theme.markdown_quote),
                ));
            }
        }
        self.out.push(Line::from(spans));
    }

    fn block_start(&mut self) {
        self.flush_inline();
        if self.pending_blank && !self.out.is_empty() {
            self.blank();
        }
        self.pending_blank = false;
    }

    fn flush_inline(&mut self) {
        if self.inline.is_empty() {
            return;
        }
        let spans = std::mem::take(&mut self.inline);
        let (first, rest) = self.prefixes();
        let lines = wrap_with_prefix(&spans, self.width, &first, &rest);
        self.out.extend(lines);
        self.mark_items_used();
    }

    fn push_text(&mut self, text: &str) {
        let style = self.text_style();
        push_str(&mut self.inline, text, style);
    }

    // -- events -------------------------------------------------------------

    fn event(&mut self, event: Event<'_>) {
        if let Some((_, buf)) = self.code.as_mut() {
            match event {
                Event::Text(t) | Event::Html(t) => {
                    buf.push_str(&t);
                    return;
                }
                Event::End(TagEnd::CodeBlock) => {}
                _ => return,
            }
        }
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(t) => self.push_text(&t),
            Event::Code(t) => {
                let style = self.code_style();
                push_str(&mut self.inline, &t, style);
            }
            Event::InlineMath(t) | Event::DisplayMath(t) => {
                let style = self.code_style();
                push_str(&mut self.inline, &t, style);
            }
            Event::InlineHtml(t) => {
                let style = self.theme.muted();
                push_str(&mut self.inline, &t, style);
            }
            Event::Html(t) => {
                for line in t.lines() {
                    if !line.trim().is_empty() {
                        let row = vec![Span::styled(line.to_string(), self.theme.muted())];
                        let w = self.content_width();
                        self.emit_rows(vec![truncate_spans(&row, w)]);
                    }
                }
            }
            Event::FootnoteReference(name) => {
                let style = self.theme.muted();
                push_str(&mut self.inline, &format!("[^{name}]"), style);
            }
            Event::SoftBreak => self.push_text(" "),
            Event::HardBreak => self.push_text("\n"),
            Event::Rule => {
                self.block_start();
                let w = self.content_width();
                let rule = Span::styled("─".repeat(w), Style::default().fg(self.theme.border));
                self.emit_rows(vec![vec![rule]]);
                self.pending_blank = true;
            }
            Event::TaskListMarker(checked) => {
                let (glyph, color) = if checked {
                    ("☑ ", self.theme.success)
                } else {
                    ("☐ ", self.theme.text_muted)
                };
                if let Some(Container::Item { marker, indent, .. }) = self.containers.last_mut() {
                    *marker = vec![Span::styled(glyph, Style::default().fg(color))];
                    *indent = display_width(glyph);
                }
            }
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph => self.block_start(),
            Tag::Heading { level, .. } => {
                self.block_start();
                self.heading = Some(level);
            }
            Tag::BlockQuote(_) => {
                self.block_start();
                self.containers.push(Container::Quote);
            }
            Tag::CodeBlock(kind) => {
                self.block_start();
                let lang = match kind {
                    CodeBlockKind::Fenced(info) => info.to_string(),
                    CodeBlockKind::Indented => String::new(),
                };
                self.code = Some((lang, String::new()));
            }
            Tag::HtmlBlock => self.block_start(),
            Tag::List(start) => {
                let nested = self
                    .containers
                    .iter()
                    .any(|c| matches!(c, Container::Item { .. }));
                if nested {
                    self.flush_inline();
                    self.pending_blank = false;
                } else {
                    self.block_start();
                }
                self.lists.push(ListState { next: start });
            }
            Tag::Item => {
                self.flush_inline();
                self.pending_blank = false;
                let depth = self.lists.len().saturating_sub(1);
                let (text, style) = match self.lists.last_mut().and_then(|l| l.next.as_mut()) {
                    Some(n) => {
                        let s = format!("{n}. ");
                        *n += 1;
                        (s, Style::default().fg(self.theme.text_muted))
                    }
                    None => {
                        let bullet = ["• ", "◦ ", "▪ "][depth % 3];
                        (bullet.to_string(), Style::default().fg(self.theme.accent))
                    }
                };
                let indent = display_width(&text);
                self.containers.push(Container::Item {
                    marker: vec![Span::styled(text, style)],
                    indent,
                    used: false,
                });
            }
            Tag::FootnoteDefinition(name) => {
                self.block_start();
                let style = self.theme.muted();
                push_str(&mut self.inline, &format!("[^{name}]: "), style);
            }
            Tag::DefinitionList => self.block_start(),
            Tag::DefinitionListTitle => {
                self.flush_inline();
                self.bold += 1;
            }
            Tag::DefinitionListDefinition => {
                self.flush_inline();
                self.push_text("  ");
            }
            Tag::Table(aligns) => {
                self.block_start();
                self.table = Some(TableState {
                    aligns,
                    rows: Vec::new(),
                    header_rows: 0,
                });
            }
            Tag::TableHead | Tag::TableRow => {
                self.inline.clear();
                if let Some(t) = self.table.as_mut() {
                    t.rows.push(Vec::new());
                }
            }
            Tag::TableCell => self.inline.clear(),
            Tag::Emphasis => self.italic += 1,
            Tag::Strong => self.bold += 1,
            Tag::Strikethrough => self.strike += 1,
            Tag::Link { dest_url, .. } => {
                let start = self.inline.len();
                self.links.push((dest_url.to_string(), start));
            }
            Tag::Image { dest_url, .. } => {
                let style = self.theme.muted();
                push_str(&mut self.inline, "[image: ", style);
                self.links.push((dest_url.to_string(), usize::MAX));
            }
            Tag::MetadataBlock(_) => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph => {
                self.flush_inline();
                self.pending_blank = true;
            }
            TagEnd::Heading(_) => {
                self.flush_inline();
                self.heading = None;
                self.pending_blank = true;
            }
            TagEnd::BlockQuote(_) => {
                self.flush_inline();
                if let Some(pos) = self
                    .containers
                    .iter()
                    .rposition(|c| matches!(c, Container::Quote))
                {
                    self.containers.truncate(pos);
                }
                self.pending_blank = true;
            }
            TagEnd::CodeBlock => {
                if let Some((lang, text)) = self.code.take() {
                    self.render_code(&lang, &text);
                }
                self.pending_blank = true;
            }
            TagEnd::HtmlBlock => self.pending_blank = true,
            TagEnd::List(_) => {
                self.flush_inline();
                self.lists.pop();
                self.pending_blank = self.lists.is_empty();
            }
            TagEnd::Item => {
                self.flush_inline();
                if let Some(Container::Item { used: false, .. }) = self.containers.last() {
                    self.emit_rows(vec![Vec::new()]);
                }
                if let Some(pos) = self
                    .containers
                    .iter()
                    .rposition(|c| matches!(c, Container::Item { .. }))
                {
                    self.containers.truncate(pos);
                }
                self.pending_blank = false;
            }
            TagEnd::FootnoteDefinition | TagEnd::DefinitionList => {
                self.flush_inline();
                self.pending_blank = true;
            }
            TagEnd::DefinitionListTitle => {
                self.flush_inline();
                self.bold = self.bold.saturating_sub(1);
            }
            TagEnd::DefinitionListDefinition => self.flush_inline(),
            TagEnd::Table => self.end_table(),
            TagEnd::TableHead => {
                if let Some(t) = self.table.as_mut() {
                    t.header_rows = t.rows.len();
                }
            }
            TagEnd::TableRow => {}
            TagEnd::TableCell => {
                let cell = std::mem::take(&mut self.inline);
                if let Some(row) = self.table.as_mut().and_then(|t| t.rows.last_mut()) {
                    row.push(cell);
                }
            }
            TagEnd::Emphasis => self.italic = self.italic.saturating_sub(1),
            TagEnd::Strong => self.bold = self.bold.saturating_sub(1),
            TagEnd::Strikethrough => self.strike = self.strike.saturating_sub(1),
            TagEnd::Link => {
                if let Some((url, start)) = self.links.pop() {
                    let text: String = self.inline[start.min(self.inline.len())..]
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect();
                    let same = text == url
                        || url.strip_prefix("mailto:") == Some(text.as_str())
                        || url.trim_end_matches('/') == text.trim_end_matches('/');
                    if !url.is_empty() && !url.starts_with('#') && !same {
                        let style = self.theme.muted();
                        push_str(&mut self.inline, &format!(" ({url})"), style);
                    }
                }
            }
            TagEnd::Image => {
                let url = self.links.pop().map(|(u, _)| u).unwrap_or_default();
                let style = self.theme.muted();
                let tail = if url.is_empty() {
                    "]".to_string()
                } else {
                    format!("] ({url})")
                };
                push_str(&mut self.inline, &tail, style);
            }
            TagEnd::MetadataBlock(_) => {}
        }
    }

    // -- blocks -------------------------------------------------------------

    fn render_code(&mut self, lang: &str, text: &str) {
        let gutter = Span::styled("│ ", Style::default().fg(self.theme.border));
        let width = self.content_width().saturating_sub(2).max(1);
        let lang = lang.split_whitespace().next().unwrap_or("");
        let body = text.strip_suffix('\n').unwrap_or(text);
        let rows: Vec<Vec<Span<'static>>> = match highlight::highlight_spans(body, lang, self.theme)
        {
            Some(rows) => rows,
            None => {
                let style = Style::default().fg(self.theme.text);
                body.split('\n')
                    .map(|l| vec![Span::styled(l.trim_end_matches('\r').to_string(), style)])
                    .collect()
            }
        };
        let base = Style::default().fg(self.theme.text);
        let rows: Vec<Vec<Span<'static>>> = rows
            .into_iter()
            .map(|row| {
                let row: Vec<Span<'static>> = row
                    .into_iter()
                    .map(|s| {
                        let style = base.patch(s.style);
                        Span::styled(s.content, style)
                    })
                    .collect();
                let mut out = vec![gutter.clone()];
                out.extend(truncate_spans(&row, width));
                out
            })
            .collect();
        let rows = if rows.is_empty() {
            vec![vec![gutter]]
        } else {
            rows
        };
        self.emit_rows(rows);
    }

    fn end_table(&mut self) {
        let Some(table) = self.table.take() else {
            return;
        };
        self.inline.clear();
        let ncols = table.rows.iter().map(Vec::len).max().unwrap_or(0);
        if ncols == 0 {
            return;
        }
        let border = Style::default().fg(self.theme.border);
        let available = self.content_width();
        let sep_w = 3 * (ncols - 1);
        let mut widths = vec![1usize; ncols];
        for row in &table.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(spans_width(cell));
            }
        }
        let budget = available.saturating_sub(sep_w);
        if budget < ncols * 3 {
            // Far too narrow for a grid: one truncated line per row.
            let rows = table
                .rows
                .iter()
                .map(|row| {
                    let mut spans = Vec::new();
                    for (i, cell) in row.iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::styled(" │ ", border));
                        }
                        spans.extend(cell.iter().cloned());
                    }
                    truncate_spans(&spans, available)
                })
                .collect();
            self.emit_rows(rows);
            self.pending_blank = true;
            return;
        }
        while widths.iter().sum::<usize>() > budget {
            if let Some(max) = widths.iter_mut().max_by_key(|w| **w) {
                *max -= 1;
            }
        }

        let header_style = Style::default().add_modifier(Modifier::BOLD);
        let mut out_rows: Vec<Vec<Span<'static>>> = Vec::new();
        for (r, row) in table.rows.iter().enumerate() {
            let is_header = r < table.header_rows;
            let wrapped: Vec<Vec<Vec<Span<'static>>>> = (0..ncols)
                .map(|i| {
                    let cell: Vec<Span<'static>> = row
                        .get(i)
                        .map(|c| {
                            c.iter()
                                .map(|s| {
                                    let st = if is_header {
                                        s.style.patch(header_style)
                                    } else {
                                        s.style
                                    };
                                    Span::styled(s.content.clone(), st)
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    wrap_spans(&cell, widths[i])
                })
                .collect();
            let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
            for line in 0..height {
                let mut spans = Vec::new();
                for (i, cell) in wrapped.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::styled(" │ ", border));
                    }
                    let content = cell.get(line).cloned().unwrap_or_default();
                    let pad = widths[i].saturating_sub(spans_width(&content));
                    let align = table.aligns.get(i).copied().unwrap_or(Alignment::None);
                    let (left, right) = match align {
                        Alignment::Right => (pad, 0),
                        Alignment::Center => (pad / 2, pad - pad / 2),
                        _ => (0, pad),
                    };
                    if left > 0 {
                        spans.push(Span::raw(" ".repeat(left)));
                    }
                    spans.extend(content);
                    // Trailing padding is only needed between columns.
                    if right > 0 && i + 1 < ncols {
                        spans.push(Span::raw(" ".repeat(right)));
                    }
                }
                out_rows.push(spans);
            }
            if is_header && r + 1 == table.header_rows {
                let parts: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
                out_rows.push(vec![Span::styled(parts.join("─┼─"), border)]);
            }
        }
        self.emit_rows(out_rows);
        self.pending_blank = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::line_text;

    fn texts(lines: &[Line<'_>]) -> Vec<String> {
        lines.iter().map(line_text).collect()
    }

    fn find<'a>(lines: &'a [Line<'static>], needle: &str) -> &'a Span<'static> {
        lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .find(|s| s.content == needle)
            .or_else(|| {
                lines
                    .iter()
                    .flat_map(|l| l.spans.iter())
                    .find(|s| s.content.contains(needle))
            })
            .unwrap_or_else(|| panic!("no span containing {needle:?}"))
    }

    #[test]
    fn headings_and_inline_styles() {
        let theme = Theme::dark();
        let md = "# Title\n\nSome **bold**, *it*, ~~gone~~ and `code` here.";
        let lines = render(md, 80, &theme);
        assert_eq!(
            texts(&lines),
            vec!["Title", "", "Some bold, it, gone and code here."]
        );
        let title = find(&lines, "Title");
        assert_eq!(title.style.fg, Some(theme.markdown_heading));
        assert!(title.style.add_modifier.contains(Modifier::BOLD));
        assert!(
            find(&lines, "bold")
                .style
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert!(
            find(&lines, "it")
                .style
                .add_modifier
                .contains(Modifier::ITALIC)
        );
        assert!(
            find(&lines, "gone")
                .style
                .add_modifier
                .contains(Modifier::CROSSED_OUT)
        );
        let code = find(&lines, "code");
        assert_eq!(code.style.fg, Some(theme.markdown_code));
        assert_eq!(code.style.bg, theme.background_element);
    }

    #[test]
    fn links_show_url_unless_same() {
        let theme = Theme::dark();
        let lines = render(
            "See [docs](https://x.dev/docs) and <https://y.dev>.",
            80,
            &theme,
        );
        assert_eq!(
            texts(&lines),
            vec!["See docs (https://x.dev/docs) and https://y.dev."]
        );
        let docs = find(&lines, "docs");
        assert_eq!(docs.style.fg, Some(theme.markdown_link));
        assert!(docs.style.add_modifier.contains(Modifier::UNDERLINED));
        assert_eq!(
            find(&lines, "(https://x.dev").style.fg,
            Some(theme.text_muted)
        );
    }

    #[test]
    fn wraps_cjk_paragraphs() {
        let theme = Theme::dark();
        let md = "这是一个很长的中文段落，用来测试按显示宽度折行是否正确，不能把宽字符劈开。";
        let lines = render(md, 20, &theme);
        assert!(lines.len() > 1);
        for l in &lines {
            assert!(l.width() <= 20, "{:?}", line_text(l));
        }
        assert_eq!(texts(&lines).concat(), md);
    }

    #[test]
    fn lists_nested_numbered_and_tasks() {
        let theme = Theme::dark();
        let md = "- first item that wraps onto another line\n  - nested\n- second\n\n1. one\n2. two\n\n- [ ] todo\n- [x] done\n";
        let lines = render(md, 24, &theme);
        assert_eq!(
            texts(&lines),
            vec![
                "• first item that wraps",
                "  onto another line",
                "  ◦ nested",
                "• second",
                "",
                "1. one",
                "2. two",
                "",
                "☐ todo",
                "☑ done",
            ]
        );
        assert_eq!(find(&lines, "☑").style.fg, Some(theme.success));
    }

    #[test]
    fn block_quote_and_rule() {
        let theme = Theme::dark();
        let lines = render("> quoted words here\n> more\n\n---\n\nafter", 12, &theme);
        let t = texts(&lines);
        assert_eq!(t[0], "▎ quoted");
        assert!(
            t.iter()
                .take_while(|l| !l.is_empty())
                .all(|l| l.starts_with('▎'))
        );
        assert!(
            t.iter()
                .any(|l| l.chars().all(|c| c == '─') && l.chars().count() == 12)
        );
        assert_eq!(t.last().unwrap(), "after");
        assert_eq!(find(&lines, "quoted").style.fg, Some(theme.markdown_quote));
    }

    #[test]
    fn code_block_highlighted_with_gutter_and_cut() {
        let theme = Theme::dark();
        let md = "```rust\nfn main() { let a_very_long_identifier_name = 1; }\n```\n";
        let lines = render(md, 30, &theme);
        assert_eq!(lines.len(), 1);
        let t = line_text(&lines[0]);
        assert!(t.starts_with("│ fn main()"), "{t}");
        assert!(t.ends_with('…'));
        assert_eq!(lines[0].width(), 30);
        let fn_kw = &lines[0].spans[1];
        assert_eq!(fn_kw.content, "fn");
        assert_ne!(fn_kw.style.fg, Some(theme.text));
    }

    #[test]
    fn unclosed_fence_renders_as_code() {
        let theme = Theme::dark();
        let lines = render("Intro\n\n```python\nprint('hi')\nx = 1\n", 40, &theme);
        assert_eq!(texts(&lines), vec!["Intro", "", "│ print('hi')", "│ x = 1"]);
    }

    #[test]
    fn table_layout() {
        let theme = Theme::dark();
        let md = "| Name | Qty |\n|:-----|----:|\n| apple | 3 |\n| 香蕉 | 12 |\n";
        let lines = render(md, 40, &theme);
        assert_eq!(
            texts(&lines),
            vec!["Name  │ Qty", "──────┼────", "apple │   3", "香蕉  │  12",]
        );
        assert!(
            find(&lines, "Name")
                .style
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert_eq!(find(&lines, "┼").style.fg, Some(theme.border));
    }

    #[test]
    fn table_shrinks_and_wraps_to_width() {
        let theme = Theme::dark();
        let md = "| a | b |\n|---|---|\n| short | a much longer cell that must wrap |\n";
        let lines = render(md, 24, &theme);
        for l in &lines {
            assert!(l.width() <= 24, "{:?}", line_text(l));
        }
        assert!(lines.len() > 3);
        let t = texts(&lines);
        assert!(t[1].contains('┼'));
        assert!(t[2].starts_with("short │ "));
    }

    #[test]
    fn streaming_holds_back_partial_table_and_fence() {
        let theme = Theme::dark();
        let md = "Text\n\n| a | b |\n|---|---|\n| 1 | 2 |\n| 3 |";
        let (lines, stable) = render_streaming(md, 40, &theme);
        let t = texts(&lines);
        assert!(!t.iter().any(|l| l.contains('3')), "{t:?}");
        assert_eq!(t.last().unwrap(), "1 │ 2");
        assert_eq!(stable, 1, "the paragraph before the table is stable");

        // Header waiting for its delimiter row is not shown as a paragraph.
        let (lines, _) = render_streaming("Hi\n\n| a | b |\n", 40, &theme);
        assert_eq!(texts(&lines), vec!["Hi"]);

        // Half-typed closing fence is hidden; content renders as code.
        let (lines, _) = render_streaming("```sh\nls -la\n``", 40, &theme);
        assert_eq!(texts(&lines), vec!["│ ls -la"]);

        // Blank lines inside a fence are not block boundaries.
        let (_, stable) = render_streaming("```\na\n\nb\n", 40, &theme);
        assert_eq!(stable, 0);
    }

    #[test]
    fn ansi_theme_has_no_backgrounds() {
        let theme = Theme::ansi();
        let lines = render("`x` and\n\n```rust\nfn a() {}\n```", 40, &theme);
        assert!(
            lines
                .iter()
                .flat_map(|l| l.spans.iter())
                .all(|s| s.style.bg.is_none())
        );
    }
}
