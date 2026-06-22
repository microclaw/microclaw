use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use genpdf::elements::{Break, PageBreak, Paragraph};
use genpdf::fonts::{FontCache, FontData, FontFamily};
use genpdf::style::Style;
use genpdf::{Alignment, Document, Margins, SimplePageDecorator, Size};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};

use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_tools::media_client::persist_output;
use microclaw_tools::runtime::auth_context_from_input;

use super::{schema_object, Tool, ToolResult};
use crate::config::{BookConfig, Config};

/// System fonts probed (in order) when `media.book.font_path` is unset. Only
/// single-face TrueType (`.ttf`) files work — rusttype (genpdf's backend)
/// cannot read `.ttc` collections or CFF/OpenType outlines.
///
/// Compact Latin-only fonts (used when the document contains no CJK, keeping
/// the embedded-font payload — and thus the PDF — small). The default is
/// English, so these are tried first.
const LATIN_FONT_CANDIDATES: &[&str] = &[
    // macOS — small single-face TrueType faces (~0.2–0.8 MB).
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Supplemental/Georgia.ttf",
    "/System/Library/Fonts/Supplemental/Verdana.ttf",
    "/Library/Fonts/Arial.ttf",
    // Debian/Ubuntu.
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    // Fedora/RHEL.
    "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
    "/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf",
];

/// Large CJK-capable fonts (used when the document contains CJK characters).
const CJK_FONT_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttf",
    "/usr/share/fonts/truetype/arphic/uming.ttf",
];

const PAGE_MARGIN_MM: f64 = 20.0;
const BASE_FONT_SIZE: u8 = 11;
const MAX_SECTIONS: usize = 64;
/// Safety factor so our pre-wrapped lines never reach genpdf's own (whitespace
/// only) re-wrap path — important because CJK text has no break opportunities
/// for genpdf to fall back on, so an over-long line would overflow the page.
const WRAP_SAFETY: f64 = 0.97;

/// Native "generate a book" tool: renders structured content to a self-contained
/// PDF (cover, optional table of contents, headed sections with Markdown bodies,
/// page numbers) using the pure-Rust `genpdf` backend — no external binaries.
pub struct RenderPdfTool {
    data_dir: PathBuf,
    channels: Arc<ChannelRegistry>,
    db: Arc<Database>,
    cfg: BookConfig,
}

impl RenderPdfTool {
    pub fn new(config: &Config, channels: Arc<ChannelRegistry>, db: Arc<Database>) -> Self {
        Self {
            data_dir: PathBuf::from(&config.data_dir),
            channels,
            db,
            cfg: config.media.book.clone(),
        }
    }
}

struct Section {
    heading: String,
    level: u8,
    body: String,
}

#[async_trait]
impl Tool for RenderPdfTool {
    fn name(&self) -> &str {
        "render_pdf"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Render a structured document (a \"book\" / report) to a PDF. \
                Provide a `title` and an ordered list of `sections`, each with a \
                `heading` and a Markdown `body`. Produces a cover page, an optional \
                table of contents, and headed sections with page numbers. The PDF is \
                saved under the bot's data directory and — when the active channel \
                supports attachments — sent back inline. Self-contained (pure-Rust, no \
                external tools). Disabled by default; requires operator opt-in via \
                `media.book.enabled`."
                .into(),
            input_schema: schema_object(
                json!({
                    "title": {"type": "string", "description": "Document title (shown on the cover)."},
                    "subtitle": {"type": "string", "description": "Optional subtitle (cover)."},
                    "author": {"type": "string", "description": "Optional author/byline (cover)."},
                    "cover": {"type": "boolean", "description": "Render a cover page (default true)."},
                    "toc": {"type": "boolean", "description": "Render a table of contents (default true)."},
                    "sections": {
                        "type": "array",
                        "description": "Ordered sections of the document.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "heading": {"type": "string", "description": "Section heading."},
                                "level": {"type": "integer", "description": "Heading level 1-3 (default 1)."},
                                "body_markdown": {"type": "string", "description": "Section body as Markdown (headings, paragraphs, lists, code)."}
                            },
                            "required": ["heading", "body_markdown"]
                        }
                    },
                    "deliver": {"type": "boolean", "description": "Attempt channel delivery (default true)."}
                }),
                &["title", "sections"],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        if !self.cfg.enabled {
            return ToolResult::error(
                "render_pdf is disabled. Set media.book.enabled=true to enable.".into(),
            );
        }
        let title = match input.get("title").and_then(|v| v.as_str()) {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => return ToolResult::error("Missing parameter: title".into()),
        };
        let subtitle = input
            .get("subtitle")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let author = input
            .get("author")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let want_cover = input.get("cover").and_then(|v| v.as_bool()).unwrap_or(true);
        let want_toc = input.get("toc").and_then(|v| v.as_bool()).unwrap_or(true);
        let deliver = input.get("deliver").and_then(|v| v.as_bool()).unwrap_or(true);

        let sections = match parse_sections(&input) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(e),
        };

        // PDF rendering is CPU-bound and synchronous; keep it off the async
        // executor. Move owned inputs into a blocking task.
        let cfg = self.cfg.clone();
        let data_dir = self.data_dir.clone();
        let title_for_doc = title.clone();
        let render_res = tokio::task::spawn_blocking(move || {
            render_document(
                &cfg,
                &data_dir,
                &title_for_doc,
                subtitle.as_deref(),
                author.as_deref(),
                want_cover,
                want_toc,
                &sections,
            )
        })
        .await;

        let saved = match render_res {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => return ToolResult::error(e),
            Err(e) => return ToolResult::error(format!("render task panicked: {e}")),
        };

        let mut summary = format!("rendered PDF '{}' -> {}", title, saved.display());
        if deliver {
            if let Some(auth) = auth_context_from_input(&input) {
                match deliver_attachment(
                    &self.channels,
                    self.db.clone(),
                    auth.caller_chat_id,
                    &saved,
                    &title,
                )
                .await
                {
                    Ok(msg) => summary.push_str(&format!("; {msg}")),
                    Err(e) => summary.push_str(&format!("; delivery skipped: {e}")),
                }
            }
        }
        ToolResult::success(summary).with_metadata(json!({
            "path": saved.to_string_lossy(),
            "title": title,
        }))
    }
}

fn parse_sections(input: &Value) -> Result<Vec<Section>, String> {
    let arr = input
        .get("sections")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or invalid parameter: sections (expected an array)".to_string())?;
    if arr.is_empty() {
        return Err("sections must contain at least one entry".into());
    }
    if arr.len() > MAX_SECTIONS {
        return Err(format!("too many sections ({}); max is {MAX_SECTIONS}", arr.len()));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, s) in arr.iter().enumerate() {
        let heading = match s.get("heading").and_then(|v| v.as_str()) {
            Some(h) if !h.trim().is_empty() => h.trim().to_string(),
            _ => return Err(format!("section {i}: missing or empty 'heading'")),
        };
        let body = s
            .get("body_markdown")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let level = s
            .get("level")
            .and_then(|v| v.as_u64())
            .map(|v| v.clamp(1, 3) as u8)
            .unwrap_or(1);
        out.push(Section { heading, level, body });
    }
    Ok(out)
}

/// Load the configured/auto-detected font as bytes. `needs_cjk` selects a
/// CJK-capable font for Chinese/Japanese/Korean content; otherwise a compact
/// Latin font is preferred (smaller embedded payload).
fn load_font_bytes(cfg: &BookConfig, needs_cjk: bool) -> Result<Vec<u8>, String> {
    if let Some(p) = cfg.font_path.as_deref().filter(|s| !s.trim().is_empty()) {
        return std::fs::read(p)
            .map_err(|e| format!("failed to read media.book.font_path '{p}': {e}"));
    }
    // Prefer the family matching the content; fall back to the other so we
    // still render *something* (CJK font also covers Latin).
    let order: [&[&str]; 2] = if needs_cjk {
        [CJK_FONT_CANDIDATES, LATIN_FONT_CANDIDATES]
    } else {
        [LATIN_FONT_CANDIDATES, CJK_FONT_CANDIDATES]
    };
    for group in order {
        for cand in group {
            if Path::new(cand).exists() {
                if let Ok(b) = std::fs::read(cand) {
                    return Ok(b);
                }
            }
        }
    }
    let hint = if needs_cjk {
        " The document contains CJK text, so a CJK-capable font is required."
    } else {
        ""
    };
    Err(format!(
        "no usable font found. Set media.book.font_path to a single-face TrueType (.ttf) font.{hint}"
    ))
}

/// Build a font family that embeds the face exactly once. Only the `regular`
/// face is embedded; the bold/italic faces are mapped to non-embedded PDF
/// built-ins (and are never selected, since rendering uses size — not weight —
/// to mark headings). This keeps a CJK PDF near the font's own size instead of
/// embedding it four times.
fn font_family(bytes: &[u8]) -> Result<FontFamily<FontData>, String> {
    use printpdf::BuiltinFont;
    let regular =
        FontData::new(bytes.to_vec(), None).map_err(|e| format!("invalid font: {e}"))?;
    let builtin = |b| FontData::new(bytes.to_vec(), Some(b)).map_err(|e| format!("invalid font: {e}"));
    Ok(FontFamily {
        regular,
        bold: builtin(BuiltinFont::HelveticaBold)?,
        italic: builtin(BuiltinFont::HelveticaOblique)?,
        bold_italic: builtin(BuiltinFont::HelveticaBoldOblique)?,
    })
}

/// Does any string in the document contain a CJK character?
fn contains_cjk(sections: &[Section], title: &str) -> bool {
    let is_cjk = |c: char| {
        matches!(c as u32,
            0x3000..=0x303F   // CJK punctuation
            | 0x3040..=0x30FF // Hiragana + Katakana
            | 0x3400..=0x4DBF // CJK ext A
            | 0x4E00..=0x9FFF // CJK unified
            | 0xF900..=0xFAFF // compatibility ideographs
            | 0xAC00..=0xD7AF // Hangul syllables
            | 0xFF00..=0xFFEF // fullwidth forms
        )
    };
    title.chars().any(is_cjk)
        || sections
            .iter()
            .any(|s| s.heading.chars().any(is_cjk) || s.body.chars().any(is_cjk))
}

fn paper_size(page_size: &str) -> (Size, f64) {
    // (size, usable text width in mm)
    let (w, h) = match page_size.to_ascii_lowercase().as_str() {
        "letter" => (215.9, 279.4),
        _ => (210.0, 297.0), // A4
    };
    let text_width = (w - 2.0 * PAGE_MARGIN_MM) * WRAP_SAFETY;
    (Size::new(w as f32, h as f32), text_width)
}

#[allow(clippy::too_many_arguments)]
fn render_document(
    cfg: &BookConfig,
    data_dir: &Path,
    title: &str,
    subtitle: Option<&str>,
    author: Option<&str>,
    want_cover: bool,
    want_toc: bool,
    sections: &[Section],
) -> Result<PathBuf, String> {
    let needs_cjk = contains_cjk(sections, title);
    let bytes = load_font_bytes(cfg, needs_cjk)?;
    let family = font_family(&bytes)?;

    let mut doc = Document::new(family);
    doc.set_title(title);
    doc.set_font_size(BASE_FONT_SIZE);
    let (size, text_width) = paper_size(&cfg.page_size);
    doc.set_paper_size(size);

    let mut deco = SimplePageDecorator::new();
    deco.set_margins(Margins::all(PAGE_MARGIN_MM as f32));
    // Page number, top-right, suppressed on the cover.
    deco.set_header(|page| {
        let mut p = Paragraph::new(if page > 1 { page.to_string() } else { String::new() });
        p.set_alignment(Alignment::Right);
        p
    });
    doc.set_page_decorator(deco);

    // Plan all content up front while we hold an immutable borrow of the font
    // cache (used for measuring), then push — push needs &mut doc.
    let lines: Vec<Line> = {
        let fc = doc.font_cache();
        plan_lines(
            fc, text_width, title, subtitle, author, want_cover, want_toc, sections,
        )
    };

    for line in lines {
        match line {
            Line::Break(n) => doc.push(Break::new(n)),
            Line::PageBreak => doc.push(PageBreak::new()),
            Line::Text { text, size, align } => {
                // Only the regular (embedded) face is CJK-safe, so we never
                // switch to a bold/italic face; headings stand out by size.
                let style = Style::new().with_font_size(size);
                let mut p = Paragraph::default();
                p.push_styled(text, style);
                p.set_alignment(align);
                doc.push(p);
            }
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    doc.render(&mut buf)
        .map_err(|e| format!("PDF render failed: {e}"))?;
    persist_output(data_dir, "docs", "pdf", &buf).map_err(|e| format!("failed to save PDF: {e}"))
}

/// A planned, already-wrapped output line (or spacing/page-break marker).
enum Line {
    Text {
        text: String,
        size: u8,
        align: Alignment,
    },
    Break(f64),
    PageBreak,
}

#[allow(clippy::too_many_arguments)]
fn plan_lines(
    fc: &FontCache,
    text_width: f64,
    title: &str,
    subtitle: Option<&str>,
    author: Option<&str>,
    want_cover: bool,
    want_toc: bool,
    sections: &[Section],
) -> Vec<Line> {
    let mut out = Vec::new();

    if want_cover {
        out.push(Line::Break(6.0));
        push_wrapped(&mut out, fc, text_width, title, 28, Alignment::Center);
        if let Some(sub) = subtitle {
            out.push(Line::Break(1.0));
            push_wrapped(&mut out, fc, text_width, sub, 16, Alignment::Center);
        }
        if let Some(a) = author {
            out.push(Line::Break(2.0));
            push_wrapped(&mut out, fc, text_width, a, 12, Alignment::Center);
        }
        out.push(Line::PageBreak);
    }

    if want_toc && sections.len() > 1 {
        push_wrapped(&mut out, fc, text_width, "Contents", 18, Alignment::Left);
        out.push(Line::Break(1.0));
        for s in sections {
            push_wrapped(&mut out, fc, text_width, &s.heading, BASE_FONT_SIZE, Alignment::Left);
        }
        out.push(Line::PageBreak);
    }

    for (i, s) in sections.iter().enumerate() {
        if i > 0 {
            out.push(Line::Break(1.5));
        }
        let hsize = heading_size(s.level);
        push_wrapped(&mut out, fc, text_width, &s.heading, hsize, Alignment::Left);
        out.push(Line::Break(0.5));
        for block in markdown_blocks(&s.body) {
            render_block(&mut out, fc, text_width, &block);
        }
    }
    out
}

fn heading_size(level: u8) -> u8 {
    match level {
        1 => 18,
        2 => 14,
        _ => 12,
    }
}

/// A parsed Markdown block (inline styling is flattened to plain text for v1).
enum Block {
    Heading(u8, String),
    Paragraph(String),
    ListItem(String),
    Code(String),
}

fn markdown_blocks(md: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut buf = String::new();
    // Active block kind: 0 none, 1 paragraph, 2 item, 3 code; heading carries level.
    let mut mode: u8 = 0;
    let mut heading_level: u8 = 1;

    let flush = |blocks: &mut Vec<Block>, buf: &mut String, mode: u8, hl: u8| {
        let text = buf.trim().to_string();
        if !text.is_empty() {
            match mode {
                1 => blocks.push(Block::Paragraph(text)),
                2 => blocks.push(Block::ListItem(text)),
                3 => blocks.push(Block::Code(text)),
                4 => blocks.push(Block::Heading(hl, text)),
                _ => {}
            }
        }
        buf.clear();
    };

    for ev in Parser::new(md) {
        match ev {
            Event::Start(Tag::Paragraph) => {
                flush(&mut blocks, &mut buf, mode, heading_level);
                mode = 1;
            }
            Event::Start(Tag::Item) => {
                flush(&mut blocks, &mut buf, mode, heading_level);
                mode = 2;
            }
            Event::Start(Tag::CodeBlock(_)) => {
                flush(&mut blocks, &mut buf, mode, heading_level);
                mode = 3;
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush(&mut blocks, &mut buf, mode, heading_level);
                mode = 4;
                heading_level = heading_md_level(level);
            }
            Event::End(TagEnd::Paragraph | TagEnd::Item | TagEnd::CodeBlock | TagEnd::Heading(_)) => {
                flush(&mut blocks, &mut buf, mode, heading_level);
                mode = 0;
            }
            Event::Text(t) | Event::Code(t) => buf.push_str(&t),
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => buf.push('\n'),
            _ => {}
        }
    }
    flush(&mut blocks, &mut buf, mode, heading_level);
    blocks
}

fn heading_md_level(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        _ => 3,
    }
}

fn render_block(out: &mut Vec<Line>, fc: &FontCache, text_width: f64, block: &Block) {
    match block {
        Block::Heading(level, text) => {
            out.push(Line::Break(0.8));
            push_wrapped(out, fc, text_width, text, heading_size(*level), Alignment::Left);
            out.push(Line::Break(0.3));
        }
        Block::Paragraph(text) => {
            push_wrapped(out, fc, text_width, text, BASE_FONT_SIZE, Alignment::Left);
            out.push(Line::Break(0.6));
        }
        Block::ListItem(text) => {
            push_wrapped(
                out,
                fc,
                text_width,
                &format!("• {text}"),
                BASE_FONT_SIZE,
                Alignment::Left,
            );
            out.push(Line::Break(0.2));
        }
        Block::Code(text) => {
            for raw in text.lines() {
                push_wrapped(out, fc, text_width, raw, BASE_FONT_SIZE, Alignment::Left);
            }
            out.push(Line::Break(0.6));
        }
    }
}

/// Wrap `text` to `text_width` (CJK-aware) and append the resulting lines.
fn push_wrapped(
    out: &mut Vec<Line>,
    fc: &FontCache,
    text_width: f64,
    text: &str,
    size: u8,
    align: Alignment,
) {
    let style = Style::new().with_font_size(size);
    for line in wrap_text(fc, &style, text_width, text) {
        out.push(Line::Text {
            text: line,
            size,
            align,
        });
    }
}

fn width_of(fc: &FontCache, style: &Style, s: &str) -> f64 {
    f64::from(style.str_width(fc, s))
}

/// Greedy line-wrap that works for both space-separated (Latin) and
/// space-free (CJK) text. Whole words are kept together when they fit; an
/// over-long single token (e.g. a Chinese sentence) is broken character by
/// character so it still fills lines instead of overflowing.
fn wrap_text(fc: &FontCache, style: &Style, max_width: f64, text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for segment in text.split('\n') {
        wrap_segment(fc, style, max_width, segment, &mut lines);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn wrap_segment(fc: &FontCache, style: &Style, max_width: f64, segment: &str, lines: &mut Vec<String>) {
    let mut cur = String::new();
    for word in segment.split_whitespace() {
        let candidate = if cur.is_empty() {
            word.to_string()
        } else {
            format!("{cur} {word}")
        };
        if width_of(fc, style, &candidate) <= max_width {
            cur = candidate;
            continue;
        }
        if !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
        if width_of(fc, style, word) <= max_width {
            cur = word.to_string();
        } else {
            // Single token too wide for a line — break it by character.
            cur = break_long(fc, style, max_width, word, lines);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
}

/// Break a single over-long token character by character. Pushes full lines
/// into `lines` and returns the trailing remainder for the caller to continue.
fn break_long(fc: &FontCache, style: &Style, max_width: f64, word: &str, lines: &mut Vec<String>) -> String {
    let mut cur = String::new();
    for ch in word.chars() {
        let mut candidate = cur.clone();
        candidate.push(ch);
        if !cur.is_empty() && width_of(fc, style, &candidate) > max_width {
            lines.push(std::mem::take(&mut cur));
            cur.push(ch);
        } else {
            cur = candidate;
        }
    }
    cur
}

async fn deliver_attachment(
    channels: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
    file: &Path,
    caption: &str,
) -> Result<String, String> {
    let routing =
        microclaw_channels::channel::get_required_chat_routing(channels, db.clone(), chat_id)
            .await?;
    let Some(adapter) = channels.get(&routing.channel_name) else {
        return Err(format!("no adapter for channel '{}'", routing.channel_name));
    };
    if adapter.is_local_only() {
        return Ok(format!(
            "channel '{}' is local-only, path retained at: {}",
            routing.channel_name,
            file.display()
        ));
    }
    let external_chat_id = microclaw_storage::db::call_blocking(db.clone(), move |d| {
        d.get_chat_external_id(chat_id)
    })
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_else(|| chat_id.to_string());
    let caption_short = caption.chars().take(120).collect::<String>();
    match adapter
        .send_attachment(&external_chat_id, file, Some(&caption_short))
        .await
    {
        Ok(_) => {
            let _ = deliver_and_store_bot_message(
                channels,
                db,
                "bot",
                chat_id,
                &format!("[document attached: {}]", file.display()),
            )
            .await;
            Ok(format!("delivered via channel '{}'", routing.channel_name))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_sections() {
        let input = json!({"title": "t", "sections": []});
        assert!(parse_sections(&input).is_err());
    }

    #[test]
    fn parses_sections_with_defaults() {
        let input = json!({"title": "t", "sections": [{"heading": "Intro", "body_markdown": "hi"}]});
        let s = parse_sections(&input).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].level, 1);
        assert_eq!(s[0].heading, "Intro");
    }

    // Real render smoke test — needs a system font, so it's #[ignore] by
    // default. Run with: cargo test --lib render_smoke -- --ignored --nocapture
    #[test]
    #[ignore]
    fn render_smoke() {
        let cfg = BookConfig {
            enabled: true,
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("microclaw_render_smoke");
        let _ = std::fs::create_dir_all(&dir);
        let sections = vec![
            Section {
                heading: "Introduction".into(),
                level: 1,
                body: "This is a **first** paragraph with enough words to require \
                       wrapping across multiple lines so we exercise the greedy \
                       Latin line-breaker thoroughly.\n\n- bullet one\n- bullet two"
                    .into(),
            },
            Section {
                heading: "中文章节".into(),
                level: 1,
                body: "这是一段没有空格的中文文本，用来验证按字符断行的逻辑是否\
                       正确工作。我们需要足够长的内容，使其超过一行的宽度，从而\
                       触发自动换行，避免文字溢出页面边界。"
                    .into(),
            },
        ];
        let out = render_document(
            &cfg,
            &dir,
            "Smoke Test 烟雾测试",
            Some("A self-contained PDF"),
            Some("MicroClaw"),
            true,
            true,
            &sections,
        )
        .expect("render should succeed");
        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "output is not a PDF");
        assert!(bytes.len() > 1500, "PDF suspiciously small: {}", bytes.len());
        eprintln!("rendered {} bytes -> {}", bytes.len(), out.display());
    }

    // English-only content should pick a compact Latin font (small PDF), not
    // fall back to a large CJK font. #[ignore] — needs a system font.
    // Run with: cargo test --lib render_smoke_english -- --ignored --nocapture
    #[test]
    #[ignore]
    fn render_smoke_english() {
        let cfg = BookConfig {
            enabled: true,
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("microclaw_render_smoke_en");
        let _ = std::fs::create_dir_all(&dir);
        let sections = vec![Section {
            heading: "Introduction".into(),
            level: 1,
            body: "A short English-only document. It should render with a compact \
                   Latin font so the resulting PDF stays small.\n\n- one\n- two"
                .into(),
        }];
        let out = render_document(
            &cfg, &dir, "English Report", None, None, true, true, &sections,
        )
        .expect("render should succeed");
        let len = std::fs::read(&out).unwrap().len();
        eprintln!("english PDF: {} bytes -> {}", len, out.display());
        // Compact Latin faces are well under 5 MB embedded; a CJK fallback
        // would be ~20 MB+.
        assert!(len < 5_000_000, "English PDF unexpectedly large: {len} bytes");
    }

    // Live end-to-end "write a book" test: a real LLM drafts the chapters, then
    // the real render_pdf tool renders them. #[ignore] — needs an API key (LLM
    // only; rendering itself is keyless) and a system font; costs ~a cent.
    // Run with: OPENAI_API_KEY=... cargo test --lib live_render_book -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_render_book() {
        let key = std::env::var("OPENAI_API_KEY")
            .or_else(|_| std::env::var("MICROCLAW_OPENAI_API_KEY"))
            .expect("set OPENAI_API_KEY (or MICROCLAW_OPENAI_API_KEY) to run this live test");

        // 1) Ask a real LLM to draft a tiny multi-chapter book as JSON.
        let prompt = "Write a very short book on \"the history of the quartz \
            watch\". Respond with ONLY a JSON object of the form {\"title\": \
            string, \"subtitle\": string, \"sections\": [{\"heading\": string, \
            \"body_markdown\": string}]} with exactly 3 sections. Each \
            body_markdown is ~120 words of real prose plus a short markdown \
            bullet list.";
        let req = json!({
            "model": "gpt-4o-mini",
            "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": prompt}]
        });
        let resp = reqwest::Client::new()
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(&key)
            .json(&req)
            .send()
            .await
            .expect("chat request failed");
        assert!(resp.status().is_success(), "chat HTTP {}", resp.status());
        let v: Value = resp.json().await.expect("bad chat json");
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .expect("no message content");
        let mut book: Value = serde_json::from_str(content).expect("LLM did not return JSON");
        let n = book["sections"].as_array().map(|a| a.len()).unwrap_or(0);
        assert!(n > 0, "LLM returned no sections");

        // 2) Render with the real render_pdf tool (keyless, deliver:false).
        let work = std::env::temp_dir().join(format!("microclaw_book_live_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work).unwrap();
        let mut cfg = crate::config::Config::test_defaults();
        cfg.data_dir = work.to_string_lossy().into_owned();
        cfg.media.book.enabled = true;
        let db_dir = work.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();
        let db = Arc::new(Database::new(db_dir.to_str().unwrap()).unwrap());
        let tool = RenderPdfTool::new(&cfg, Arc::new(ChannelRegistry::new()), db);

        book["deliver"] = json!(false);
        let res = tool.execute(book.clone()).await;
        assert!(!res.is_error, "render_pdf errored: {}", res.content);

        let path = res
            .metadata
            .as_ref()
            .and_then(|m| m.get("path"))
            .and_then(|x| x.as_str())
            .expect("metadata.path missing");
        let bytes = std::fs::read(path).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "output is not a PDF");
        assert!(bytes.len() > 1500, "PDF suspiciously small: {} bytes", bytes.len());
        eprintln!(
            "OK: book \"{}\" ({} sections) -> {} ({} bytes)",
            book["title"].as_str().unwrap_or("?"),
            n,
            path,
            bytes.len()
        );
    }

    #[test]
    fn markdown_blocks_splits_paragraph_and_list() {
        let blocks = markdown_blocks("Hello world.\n\n- one\n- two");
        // one paragraph + two list items
        assert_eq!(blocks.len(), 3);
        assert!(matches!(blocks[0], Block::Paragraph(_)));
        assert!(matches!(blocks[1], Block::ListItem(_)));
        assert!(matches!(blocks[2], Block::ListItem(_)));
    }
}
