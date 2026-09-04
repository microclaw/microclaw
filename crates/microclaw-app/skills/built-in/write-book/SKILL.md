---
name: write-book
description: "Research a topic and produce a polished multi-chapter PDF book/report. Use when the user asks to write a book, booklet, report, brief, guide, ebook, whitepaper, or 'turn X into a PDF document'. Runs a research → outline → write → render pipeline and calls the render_pdf tool to produce a downloadable PDF. Triggers on mentions of write a book, make a PDF, booklet, report, brief, guide, ebook, whitepaper, 写一本书, 写本书, 生成PDF, 做一本电子书, 写一份报告, 小册子, 出一本书, 制作PDF."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Uses web_search/web_fetch (no API key) and the render_pdf tool (requires media.book.enabled). PDF rendering is pure-Rust and self-contained. Works on macOS, Linux, and Windows."
---

# Write a Book (PDF)

Turn a topic into a structured, well-researched PDF — a short book or report — and
deliver it to the user as a file. This mirrors a clarify → plan → research → write →
edit → render pipeline.

## When to use

The user wants a *document*, not a chat answer: "write me a book about…", "make a PDF
report on…", "出一本关于…的小册子". The deliverable is a PDF produced by the
`render_pdf` tool.

## Method

1. **Scope it.** If the topic is broad or ambiguous, ask 1–3 quick clarifying questions
   (depth, audience, language, how many chapters). If the user said "use your best
   judgment", skip and choose sensible defaults (6 chapters, ~800–1200 words each).
2. **Plan the outline.** Decide a title, optional subtitle, and an ordered list of
   chapters — each with a one-line intent and a rough word budget. Keep chapters in the
   user's language.
3. **Research** with `web_search` then `web_fetch` on the most credible hits. Cross-check
   key facts against a second source. If search yields little, fall back to your own
   knowledge but don't fabricate specifics (names, numbers, dates).
4. **Write chapter by chapter**, in order. Feed yourself the tail of the previous chapter
   so voice and terminology stay consistent. For a long book you may spawn a `sub_agent`
   per chapter to draft in parallel, then stitch. Write real prose with Markdown
   structure (`##` sub-headings, `-` lists, `` `code` ``) — the renderer understands it.
5. **Edit once** for a single consistent voice, terminology, and no repetition.
6. **Render** by calling `render_pdf` (see below). Then tell the user what you produced
   (title, chapter count) — the PDF is delivered as an attachment automatically.

## Calling render_pdf

Pass a `title` (+ optional `subtitle`, `author`) and an ordered `sections` array. Each
section is one chapter: a `heading` and a `body_markdown`.

```json
{
  "title": "A Short History of the Quartz Watch",
  "subtitle": "From lab curiosity to wrist ubiquity",
  "author": "MicroClaw",
  "sections": [
    {"heading": "1. The Mechanical World Before Quartz", "body_markdown": "In the 1960s...\n\n- point\n- point"},
    {"heading": "2. The Breakthrough", "body_markdown": "## The oscillator\n\nText..."}
  ]
}
```

- Put the chapter title in `heading`; do **not** repeat it as an `#` heading inside the body.
- `level` (1–3) controls heading size; default 1 for top-level chapters.
- A cover page and table of contents are generated automatically (`cover`/`toc` default true).

## Quality bar

- Aim for the page20 shape: ~6 chapters × ~1000 words for a full book; fewer/shorter for a
  quick brief. State the target you chose.
- Concrete and sourced beats vague and padded. Lead each chapter with its point.
- For CJK output, the operator may need to set `media.book.font_path` to a CJK font; if a
  render fails with "no usable font", relay that hint.
