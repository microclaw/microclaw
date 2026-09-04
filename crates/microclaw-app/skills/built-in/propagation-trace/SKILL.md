---
name: propagation-trace
description: "Trace the propagation chain of a new thing — a news story, rumor, meme, claim, product, or trending topic — by reconstructing where it originated, when it appeared, and how it spread across sources. Uses the `web_search` and `web_fetch` tools (no API key required). Use when users ask where something came from, who said it first, how it spread, the timeline of a story, the original source, or whether a claim is real. Triggers on mentions of source, origin, first reported, who started it, how it spread, propagation, timeline, trace, 出处, 来源, 最早, 谁先说的, 传播链, 溯源, 时间线."
compatibility: "Uses built-in web_search and web_fetch tools. Works on all platforms; no external CLI required."
---

# Propagation Trace

Reconstruct the propagation chain of a "new thing" (news, rumor, meme, claim, product launch, trending topic): **where it started, when it appeared, and how it spread**. This is an investigation method layered on the `web_search` and `web_fetch` tools — not a single command.

## Goal

Produce a chronological chain of nodes:

```
origin → early amplifiers → mainstream pickup → current state
```

Each node should carry: source name, URL, timestamp (as exact as available), and what that source added (original claim, quote, correction, debunk, etc.).

## Method

1. **Pin down the claim.** Restate the exact thing being traced in one sentence. If it's vague ("that AI thing everyone's talking about"), use `clarify` or ask the user for a distinguishing phrase, name, or quote before searching.

2. **Broad search for the canonical phrasing.** Run `web_search` with the most quotable, specific string (an exact quote, a unique name, a number). Distinctive phrases surface the origin faster than generic keywords.

3. **Walk backwards in time to the origin.** Re-search with date-narrowing terms and the earliest-looking sources. Add qualifiers like `"first reported"`, `"originally"`, `"según"`, `"最早"`, the year, or `before:<date>`-style phrasing. The earliest credible source that is not citing someone else is the candidate origin.

4. **Fetch and verify each candidate node.** Use `web_fetch` on the actual URLs — do not trust search snippets alone. Confirm:
   - the publish/post timestamp (look in the page text, not just the search result),
   - whether the source is **originating** the claim or **citing** another source (follow the citation upstream),
   - the exact wording, since claims mutate as they spread.

5. **Map the spread forward.** From the origin, identify who amplified it and in what order: secondary outlets, aggregators, social platforms, mainstream press. Note where the claim changed, got exaggerated, or was corrected/debunked.

6. **Assemble the chain.** Order nodes by timestamp. Mark gaps and uncertainty explicitly.

## Output format

Present a compact timeline, then a one-line assessment:

```
PROPAGATION CHAIN: <the thing>

1. [YYYY-MM-DD] Origin — <source>, <url>
   "<original claim/quote>"
2. [YYYY-MM-DD] <source>, <url> — <what changed / what it added>
3. ...

ASSESSMENT: <single origin or multiple? how confident? any mutation/debunk along the way?>
```

## Guidance

- **Distinguish origin from amplifier.** A high-traffic outlet is often *not* the origin — follow "according to" / "as first reported by" links upstream until you reach a source that isn't citing anyone.
- **Timestamps are the spine.** Prefer machine-readable dates from the page over fuzzy search-snippet dates. If a source has no reliable timestamp, say so rather than guessing its position in the chain.
- **Watch for mutation.** The wording at the origin and the wording now are frequently different. Quote both when they diverge.
- **Be honest about gaps.** Web search cannot see private/deleted posts or paywalled archives. State what you could not verify instead of inventing a clean chain.
- **Don't overclaim causation.** "Appeared earlier" is not proof of "caused the spread." Describe the observed order; flag inferences as inferences.
- **Stop when it converges.** Once multiple independent backward searches keep landing on the same earliest source, treat that as the origin and stop.
