---
name: translate
description: "Translate text between languages naturally, preserving meaning, tone, and formatting, with notes on nuance or ambiguity when it matters. Use when users ask to translate text, say something in another language, or localize a message. Triggers on mentions of translate, in English/Chinese/Spanish/Japanese/etc, how do you say, localize, 翻译, 译成, 用英文怎么说, 中译英, 英译中, 本地化."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Translate

Translate for meaning and natural phrasing, not word-for-word. A good translation reads as
if originally written in the target language.

## Approach

- **Convey meaning and intent**, not just words. Idioms become the target language's
  equivalent idiom, not a literal calque.
- **Preserve tone and register** — formal stays formal, casual stays casual, jokes stay jokes
  where possible.
- **Keep formatting** — line breaks, lists, placeholders like `{name}`, code, and markup intact.
- **Don't translate** proper nouns, brand names, code, or URLs unless asked.

## Output

- Give the translation directly. If the user asked for just the translation, don't pad it.
- Add a brief note only when it earns its place: an ambiguity, an untranslatable nuance, a
  formality choice (e.g. tu/vous, 你/您, です/だ), or a term with no clean equivalent.

## Guidance

- If the source is ambiguous, pick the most likely reading and note the assumption.
- For names/places, keep the common target-language spelling if one exists.
- Match the politeness level the situation needs; when unsure between formal/informal, default to
  polite and say so.
- For long documents, keep paragraph structure aligned so the user can map source to translation.
