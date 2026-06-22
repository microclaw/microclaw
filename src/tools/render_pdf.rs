use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};

use typst::diag::{FileError, FileResult, SourceDiagnostic, Warned};
use typst::foundations::{Bytes, Datetime, Duration};
use typst::syntax::{FileId, RootedPath, Source, VirtualPath, VirtualRoot};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::{Library, LibraryExt, World};
use typst_layout::PagedDocument;
use typst_pdf::PdfOptions;

use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_tools::media_client::persist_output;
use microclaw_tools::runtime::auth_context_from_input;

use super::{schema_object, Tool, ToolResult};
use crate::config::{BookConfig, Config};

/// Fonts probed (in order) when `media.book.font_path` is unset. Typst subsets
/// whatever font it uses, so output stays small either way; we still prefer a
/// compact Latin face for Latin-only docs and a CJK-capable face for CJK docs.
const LATIN_FONT_CANDIDATES: &[&str] = &[
    // macOS.
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

/// CJK-capable fonts (used when the document contains CJK characters). Typst
/// reads `.ttc` collections and OTF/CFF too, but single-face `.ttf` is simplest.
const CJK_FONT_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttf",
    "/usr/share/fonts/truetype/arphic/uming.ttf",
];

const BASE_FONT_SIZE: u8 = 11;
const MAX_SECTIONS: usize = 64;

/// "Generate a book" tool: renders structured content to a self-contained PDF
/// (cover, optional table of contents, headed sections with Markdown bodies,
/// page numbers) via the pure-Rust Typst backend — no external binaries, and
/// fonts are subsetted so CJK PDFs stay small.
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
                external tools); supports CJK and inline bold/italic. Disabled by \
                default; requires operator opt-in via `media.book.enabled`."
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

        // Typesetting is CPU-bound and synchronous; keep it off the async
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

// ---------------------------------------------------------------------------
// Font selection
// ---------------------------------------------------------------------------

fn resolve_font_path(cfg: &BookConfig, needs_cjk: bool) -> Result<PathBuf, String> {
    if let Some(p) = cfg.font_path.as_deref().filter(|s| !s.trim().is_empty()) {
        let pb = PathBuf::from(p);
        if !pb.exists() {
            return Err(format!("media.book.font_path '{p}' does not exist"));
        }
        return Ok(pb);
    }
    let order: [&[&str]; 2] = if needs_cjk {
        [CJK_FONT_CANDIDATES, LATIN_FONT_CANDIDATES]
    } else {
        [LATIN_FONT_CANDIDATES, CJK_FONT_CANDIDATES]
    };
    for group in order {
        for cand in group {
            if Path::new(cand).exists() {
                return Ok(PathBuf::from(cand));
            }
        }
    }
    let hint = if needs_cjk {
        " The document contains CJK text, so a CJK-capable font is required."
    } else {
        ""
    };
    Err(format!(
        "no usable font found. Set media.book.font_path to a TrueType/OpenType font.{hint}"
    ))
}

#[derive(Clone, Copy)]
enum FaceKind {
    Bold,
    Italic,
    BoldItalic,
}

/// Find the sibling variant file for a regular font, trying common naming
/// conventions (`Arial Bold.ttf`, `DejaVuSans-Bold.ttf`, …).
fn variant_path(regular: &Path, kind: FaceKind) -> Option<PathBuf> {
    let dir = regular.parent()?;
    let stem = regular.file_stem()?.to_str()?;
    let ext = regular.extension().and_then(|e| e.to_str()).unwrap_or("ttf");
    let (spaced, hyphen, oblique) = match kind {
        FaceKind::Bold => (" Bold", "-Bold", "-Bold"),
        FaceKind::Italic => (" Italic", "-Italic", "-Oblique"),
        FaceKind::BoldItalic => (" Bold Italic", "-BoldItalic", "-BoldOblique"),
    };
    let base = stem
        .trim_end_matches("-Regular")
        .trim_end_matches("Regular")
        .trim_end_matches(['-', ' ']);
    let base = if base.is_empty() { stem } else { base };
    for n in [
        format!("{stem}{spaced}.{ext}"),
        format!("{base}{hyphen}.{ext}"),
        format!("{base}{oblique}.{ext}"),
        format!("{base}{spaced}.{ext}"),
    ] {
        let p = dir.join(n);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Load the regular face (plus any Bold/Italic siblings) as Typst fonts and
/// return them with the regular face's family name.
fn load_fonts(cfg: &BookConfig, needs_cjk: bool) -> Result<(Vec<Font>, String), String> {
    let regular_path = resolve_font_path(cfg, needs_cjk)?;
    let regular_bytes = std::fs::read(&regular_path)
        .map_err(|e| format!("failed to read font '{}': {e}", regular_path.display()))?;
    let regular = Font::new(Bytes::new(regular_bytes), 0)
        .ok_or_else(|| format!("could not parse font '{}'", regular_path.display()))?;
    let family = regular.info().family.clone();

    let mut fonts = vec![regular];
    for kind in [FaceKind::Bold, FaceKind::Italic, FaceKind::BoldItalic] {
        if let Some(p) = variant_path(&regular_path, kind) {
            if let Ok(b) = std::fs::read(&p) {
                if let Some(f) = Font::new(Bytes::new(b), 0) {
                    fonts.push(f);
                }
            }
        }
    }
    Ok((fonts, family))
}

fn contains_cjk(sections: &[Section], title: &str) -> bool {
    let is_cjk = |c: char| {
        matches!(c as u32,
            0x3000..=0x303F
            | 0x3040..=0x30FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFAFF
            | 0xAC00..=0xD7AF
            | 0xFF00..=0xFFEF
        )
    };
    title.chars().any(is_cjk)
        || sections
            .iter()
            .any(|s| s.heading.chars().any(is_cjk) || s.body.chars().any(is_cjk))
}

// ---------------------------------------------------------------------------
// Rendering (Typst)
// ---------------------------------------------------------------------------

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
    let (fonts, family) = load_fonts(cfg, needs_cjk)?;
    let markup = build_markup(title, subtitle, author, want_cover, want_toc, sections, &family);

    let world = TypstWorld::new(fonts, markup);
    let Warned { output, .. } = typst::compile::<PagedDocument>(&world);
    let document =
        output.map_err(|d| format!("typst compile failed: {}", format_diagnostics(&d)))?;
    let pdf = typst_pdf::pdf(&document, &PdfOptions::default())
        .map_err(|d| format!("typst PDF export failed: {}", format_diagnostics(&d)))?;

    persist_output(data_dir, "docs", "pdf", &pdf).map_err(|e| format!("failed to save PDF: {e}"))
}

fn format_diagnostics(diags: &[SourceDiagnostic]) -> String {
    diags
        .iter()
        .map(|d| d.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Build the Typst markup for the whole document.
fn build_markup(
    title: &str,
    subtitle: Option<&str>,
    author: Option<&str>,
    want_cover: bool,
    want_toc: bool,
    sections: &[Section],
    family: &str,
) -> String {
    let mut m = String::new();
    m.push_str(&format!("#set document(title: {})\n", typst_string(title)));
    m.push_str(&format!(
        "#set text(font: {}, size: {}pt)\n",
        typst_string(family),
        BASE_FONT_SIZE
    ));
    m.push_str("#set par(justify: false, leading: 0.7em)\n");
    m.push_str("#set heading(numbering: none)\n");
    m.push_str("#show heading.where(level: 1): set text(size: 18pt)\n");
    m.push_str("#show heading.where(level: 2): set text(size: 14pt)\n");
    m.push_str("#show heading.where(level: 3): set text(size: 12pt)\n");
    m.push_str("#set page(paper: \"a4\", margin: 2cm, numbering: none)\n\n");

    if want_cover {
        m.push_str("#align(center)[\n  #v(5cm)\n");
        m.push_str(&format!(
            "  #text(size: 28pt, weight: \"bold\")[{}]\n",
            escape_typst(title)
        ));
        if let Some(sub) = subtitle {
            m.push_str(&format!(
                "  #v(0.6cm)\n  #text(size: 16pt)[{}]\n",
                escape_typst(sub)
            ));
        }
        if let Some(a) = author {
            m.push_str(&format!(
                "  #v(1.2cm)\n  #text(size: 12pt)[{}]\n",
                escape_typst(a)
            ));
        }
        m.push_str("]\n#pagebreak()\n\n");
    }

    // Number pages from 1 starting after the cover.
    m.push_str("#set page(numbering: \"1\")\n#counter(page).update(1)\n\n");

    if want_toc && sections.len() > 1 {
        m.push_str("#outline(title: [Contents], depth: 1)\n#pagebreak()\n\n");
    }

    for s in sections {
        let level = s.level.clamp(1, 3) as usize;
        m.push_str(&format!(
            "{} {}\n\n",
            "=".repeat(level),
            escape_typst(&s.heading)
        ));
        for block in markdown_blocks(&s.body) {
            m.push_str(&emit_block(&block));
        }
        m.push('\n');
    }
    m
}

/// Render one Markdown block to Typst markup.
fn emit_block(block: &Block) -> String {
    match block {
        Block::Heading(level, text) => {
            format!("\n{} {}\n\n", "=".repeat(*level as usize), escape_typst(text))
        }
        Block::Paragraph(spans) => format!("{}\n\n", emit_spans(spans)),
        // No blank line after a list item, so consecutive items form one list.
        Block::ListItem(spans) => format!("- {}\n", emit_spans(spans)),
        Block::Code(text) => format!("#raw(block: true, {})\n\n", typst_string(text)),
    }
}

/// Render inline spans to Typst markup, applying bold/italic via `#strong` /
/// `#emph` (function form, so escaping is unambiguous).
fn emit_spans(spans: &[Span]) -> String {
    let mut out = String::new();
    for span in spans {
        let esc = escape_typst(&span.text);
        let rendered = match (span.bold, span.italic) {
            (true, true) => format!("#strong[#emph[{esc}]]"),
            (true, false) => format!("#strong[{esc}]"),
            (false, true) => format!("#emph[{esc}]"),
            (false, false) => esc,
        };
        out.push_str(&rendered);
    }
    out
}

/// Escape text for use in Typst markup context. Over-escapes a few characters
/// that are only special at line start (`-`, `+`, `=`) — harmless, they render
/// literally — to keep arbitrary user text from triggering markup.
fn escape_typst(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' | '#' | '$' | '*' | '_' | '`' | '<' | '>' | '@' | '[' | ']' | '~' | '=' | '+'
            | '-' | '/' | '"' => {
                out.push('\\');
                out.push(c);
            }
            // A bare newline would end the paragraph; keep runs on one line.
            '\n' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Quote a Rust string as a Typst string literal (`"..."`).
fn typst_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A minimal in-memory Typst [`World`] backed by a single source string and a
/// fixed set of fonts. No filesystem or package access.
struct TypstWorld {
    library: LazyHash<Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
    main: FileId,
    source: Source,
}

impl TypstWorld {
    fn new(fonts: Vec<Font>, markup: String) -> Self {
        let book = FontBook::from_fonts(fonts.iter());
        let vpath = VirtualPath::new("main.typ").expect("valid virtual path");
        let main = FileId::new(RootedPath::new(VirtualRoot::Project, vpath));
        let source = Source::new(main, markup);
        Self {
            library: LazyHash::new(Library::builder().build()),
            book: LazyHash::new(book),
            fonts,
            main,
            source,
        }
    }
}

impl World for TypstWorld {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }
    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }
    fn main(&self) -> FileId {
        self.main
    }
    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.main {
            Ok(self.source.clone())
        } else {
            Err(FileError::NotFound(PathBuf::new()))
        }
    }
    fn file(&self, _id: FileId) -> FileResult<Bytes> {
        Err(FileError::NotFound(PathBuf::new()))
    }
    fn font(&self, index: usize) -> Option<Font> {
        self.fonts.get(index).cloned()
    }
    fn today(&self, _offset: Option<Duration>) -> Option<Datetime> {
        None
    }
}

// ---------------------------------------------------------------------------
// Markdown parsing (block + inline spans)
// ---------------------------------------------------------------------------

/// An inline run of text sharing one style (bold/italic).
struct Span {
    text: String,
    bold: bool,
    italic: bool,
}

/// A parsed Markdown block. Paragraph/list bodies keep their inline spans so
/// bold/italic can be rendered; headings and code blocks are single-style.
enum Block {
    Heading(u8, String),
    Paragraph(Vec<Span>),
    ListItem(Vec<Span>),
    Code(String),
}

fn flatten_spans(spans: &[Span]) -> String {
    spans.iter().map(|s| s.text.as_str()).collect()
}

fn trim_spans(mut spans: Vec<Span>) -> Vec<Span> {
    while spans.first().is_some_and(|s| s.text.trim().is_empty()) {
        spans.remove(0);
    }
    while spans.last().is_some_and(|s| s.text.trim().is_empty()) {
        spans.pop();
    }
    if let Some(first) = spans.first_mut() {
        first.text = first.text.trim_start().to_string();
    }
    if let Some(last) = spans.last_mut() {
        last.text = last.text.trim_end().to_string();
    }
    spans
}

fn push_span(spans: &mut Vec<Span>, text: &str, bold: bool, italic: bool) {
    if text.is_empty() {
        return;
    }
    if let Some(last) = spans.last_mut() {
        if last.bold == bold && last.italic == italic {
            last.text.push_str(text);
            return;
        }
    }
    spans.push(Span {
        text: text.to_string(),
        bold,
        italic,
    });
}

fn markdown_blocks(md: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut spans: Vec<Span> = Vec::new();
    // Active block kind: 0 none, 1 paragraph, 2 item, 3 code, 4 heading.
    let mut mode: u8 = 0;
    let mut heading_level: u8 = 1;
    let mut bold = 0u32;
    let mut italic = 0u32;

    let flush = |blocks: &mut Vec<Block>, spans: &mut Vec<Span>, mode: u8, hl: u8| {
        let taken = std::mem::take(spans);
        match mode {
            1 => {
                let s = trim_spans(taken);
                if !s.is_empty() {
                    blocks.push(Block::Paragraph(s));
                }
            }
            2 => {
                let s = trim_spans(taken);
                if !s.is_empty() {
                    blocks.push(Block::ListItem(s));
                }
            }
            3 => {
                let t = flatten_spans(&taken).trim().to_string();
                if !t.is_empty() {
                    blocks.push(Block::Code(t));
                }
            }
            4 => {
                let t = flatten_spans(&taken).trim().to_string();
                if !t.is_empty() {
                    blocks.push(Block::Heading(hl, t));
                }
            }
            _ => {}
        }
    };

    for ev in Parser::new(md) {
        match ev {
            Event::Start(Tag::Paragraph) => {
                flush(&mut blocks, &mut spans, mode, heading_level);
                mode = 1;
            }
            Event::Start(Tag::Item) => {
                flush(&mut blocks, &mut spans, mode, heading_level);
                mode = 2;
            }
            Event::Start(Tag::CodeBlock(_)) => {
                flush(&mut blocks, &mut spans, mode, heading_level);
                mode = 3;
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush(&mut blocks, &mut spans, mode, heading_level);
                mode = 4;
                heading_level = heading_md_level(level);
            }
            Event::Start(Tag::Strong) => bold += 1,
            Event::Start(Tag::Emphasis) => italic += 1,
            Event::End(TagEnd::Strong) => bold = bold.saturating_sub(1),
            Event::End(TagEnd::Emphasis) => italic = italic.saturating_sub(1),
            Event::End(TagEnd::Paragraph | TagEnd::Item | TagEnd::CodeBlock | TagEnd::Heading(_)) => {
                flush(&mut blocks, &mut spans, mode, heading_level);
                mode = 0;
            }
            // Inline code is rendered as regular text.
            Event::Text(t) | Event::Code(t) => push_span(&mut spans, &t, bold > 0, italic > 0),
            Event::SoftBreak => push_span(&mut spans, " ", bold > 0, italic > 0),
            Event::HardBreak => push_span(&mut spans, " ", bold > 0, italic > 0),
            _ => {}
        }
    }
    flush(&mut blocks, &mut spans, mode, heading_level);
    blocks
}

fn heading_md_level(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        _ => 3,
    }
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

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

    #[test]
    fn escape_typst_neutralizes_markup() {
        assert_eq!(escape_typst("a*b_c#d"), "a\\*b\\_c\\#d");
        assert_eq!(typst_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
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
                       wrapping across multiple lines so we exercise the layout \
                       engine thoroughly.\n\n- bullet one\n- bullet two"
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
        // Typst subsets the CJK font, so even a Chinese PDF should be small.
        assert!(bytes.len() > 1500, "PDF suspiciously small: {}", bytes.len());
        assert!(
            bytes.len() < 5_000_000,
            "CJK PDF should be subset-small, got {} bytes",
            bytes.len()
        );
        eprintln!("rendered {} bytes -> {}", bytes.len(), out.display());
    }

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
            body: "A short English-only document. It should render small.\n\n- one\n- two"
                .into(),
        }];
        let out = render_document(
            &cfg, &dir, "English Report", None, None, true, true, &sections,
        )
        .expect("render should succeed");
        let len = std::fs::read(&out).unwrap().len();
        eprintln!("english PDF: {} bytes -> {}", len, out.display());
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

    // Renders a Latin doc with bold/italic and checks it stays a valid PDF.
    // #[ignore] — needs a font.
    #[test]
    #[ignore]
    fn render_emphasis_smoke() {
        let cfg = BookConfig {
            enabled: true,
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("microclaw_render_emphasis");
        let _ = std::fs::create_dir_all(&dir);
        let sections = vec![Section {
            heading: "Styles".into(),
            level: 1,
            body: "This paragraph has **bold words**, *italic words*, and \
                   ***both at once***, plus inline `code`. It should wrap across \
                   a couple of lines with the emphasis preserved.\n\n\
                   - a **bold** bullet\n- an *italic* bullet"
                .into(),
        }];
        let out =
            render_document(&cfg, &dir, "Emphasis Test", None, None, true, true, &sections)
                .expect("render should succeed");
        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "not a PDF");
        assert!(
            (1500..8_000_000).contains(&bytes.len()),
            "unexpected size: {} bytes",
            bytes.len()
        );
        eprintln!("emphasis PDF: {} bytes -> {}", bytes.len(), out.display());
    }

    #[test]
    fn markdown_emphasis_produces_styled_spans() {
        let blocks = markdown_blocks("Plain **bold** and *italic* words.");
        assert_eq!(blocks.len(), 1);
        let Block::Paragraph(spans) = &blocks[0] else {
            panic!("expected a paragraph");
        };
        assert!(spans.iter().any(|s| s.bold && !s.italic && s.text.contains("bold")));
        assert!(spans.iter().any(|s| s.italic && !s.bold && s.text.contains("italic")));
        assert!(spans.iter().any(|s| !s.bold && !s.italic && s.text.contains("Plain")));
    }

    #[test]
    fn markdown_blocks_splits_paragraph_and_list() {
        let blocks = markdown_blocks("Hello world.\n\n- one\n- two");
        assert_eq!(blocks.len(), 3);
        assert!(matches!(blocks[0], Block::Paragraph(_)));
        assert!(matches!(blocks[1], Block::ListItem(_)));
        assert!(matches!(blocks[2], Block::ListItem(_)));
    }
}
