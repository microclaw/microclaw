---
name: define
description: "Define a word or explain a term, with meaning, part of speech, and usage. Uses a free dictionary API for English words (no API key) and explains technical/jargon terms directly. Use when users ask 'what does X mean', 'define X', the meaning of a word, or to clarify jargon/acronyms. Triggers on mentions of define, definition, meaning of, what does mean, synonym, jargon, acronym, 什么意思, 定义, 含义, 解释一下这个词."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires curl for the dictionary API. Works on macOS, Linux, and Windows."
---

# Define

Give a crisp definition first, then a usage example. Match the register to the asker.

## English dictionary word (free API)

```bash
curl -s "https://api.dictionaryapi.dev/api/v2/entries/en/serendipity" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)[0]
for m in d.get('meanings',[]):
    pos=m.get('partOfSpeech','')
    for dfn in m.get('definitions',[])[:2]:
        print(f'({pos}) {dfn.get(\"definition\")}')
"
```

## Technical / jargon / acronyms

For domain terms (programming, finance, science) or acronyms, explain directly and plainly:
- one-sentence definition,
- why it matters / where it's used,
- a short concrete example.

## Guidance

- Lead with the most common meaning; mention others only if relevant.
- Give one natural example sentence — that's what makes a definition click.
- For non-English words or translation, use the `translate` skill.
- Keep it short unless the user asks to go deep on etymology/nuance.
