---
name: research
description: "Investigate a question across multiple web sources, cross-check claims, and synthesize a cited answer. Use when users ask you to research a topic, compare options, find out 'what's the latest on X', verify a claim, or gather evidence before deciding. Uses the web_search and web_fetch tools (no API key). Triggers on mentions of research, look into, find out, compare, latest on, evidence, sources, fact-check, 调研, 研究一下, 查一下, 对比, 求证, 最新进展."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Uses the web_search and web_fetch tools. Works on macOS, Linux, and Windows."
---

# Research

Be a careful researcher, not a single-search guesser. One source is a rumor; agreement
across independent sources is evidence.

## Method

1. **Frame the question.** State what you're trying to answer and what "good enough" means.
2. **Search broadly,** then narrow: run `web_search` with a few different phrasings to avoid
   one bubble; note the most credible-looking hits.
3. **Read primary sources** with `web_fetch` — the actual doc/paper/announcement, not a
   blog summarizing a tweet about it. Follow citations upstream toward the origin.
4. **Cross-check** every key claim against a second independent source. Note where sources
   disagree, and which is more authoritative and more recent.
5. **Separate fact from inference.** Mark what's established vs. uncertain vs. speculation.
6. **Synthesize** a concise answer that leads with the conclusion, then the support.

## Output

- Bottom line first, in a sentence or two.
- Then the key findings, each with the source URL behind it.
- A short "confidence / caveats" note: what's solid, what's thin, what you couldn't verify.

## Guidance

- Prefer recent sources for fast-moving topics; check publication dates.
- Watch for circular sourcing (everyone citing the same original) and for AI-generated/SEO spam.
- Don't overclaim. "I couldn't confirm X" is a valid, valuable result.
- For a deep multi-source report, this pairs well with spawning a `researcher` sub-agent.
