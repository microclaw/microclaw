---
name: wikipedia
description: "Look up a quick factual summary of a topic, person, place, or thing from Wikipedia via its public REST API (no API key). Use when users want a concise overview, 'who/what is X', background, or a definition-level explanation of a named entity. Triggers on mentions of who is, what is, tell me about, overview of, background on, wikipedia, 是谁, 是什么, 介绍一下, 简介, 维基."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires curl. Works on macOS, Linux, and Windows."
---

# Wikipedia

Fast factual lookups for named entities. Good for background; verify anything contested
with the `research` skill.

## Summary of a topic

```bash
curl -s "https://en.wikipedia.org/api/rest_v1/page/summary/Alan_Turing" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('title')); print(d.get('extract'))"
```

## Search for the right title first (if unsure)

```bash
curl -s "https://en.wikipedia.org/w/api.php?action=opensearch&limit=5&format=json&search=turing" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[1])"
```

## Other languages

```bash
# Swap the subdomain: zh.wikipedia.org, ja.wikipedia.org, ...
curl -s "https://zh.wikipedia.org/api/rest_v1/page/summary/图灵" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('extract'))"
```

## Guidance

- Spaces in titles become underscores; URL-encode non-ASCII.
- If you get a disambiguation or "not found", use the opensearch step to pick the exact title.
- Wikipedia is a starting point, not a primary source — cite it as such, and verify claims
  that matter with the underlying references.
- Keep the answer to the asked scope; summarize the `extract`, don't dump it verbatim.
