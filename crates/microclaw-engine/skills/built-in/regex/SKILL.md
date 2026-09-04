---
name: regex
description: "Write, explain, test, and debug regular expressions, and build them iteratively against real sample input. Use when users want a regex/pattern to match or extract text, ask why a pattern isn't matching, need to validate emails/URLs/dates/phone numbers, or want to do find-and-replace with capture groups. Triggers on mentions of regex, regular expression, pattern, match, extract, validate, find and replace, 正则, 正则表达式, 匹配, 提取, 替换."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3. Works on macOS, Linux, and Windows."
---

# Regex

Never hand-wave a regex — test it against real samples before handing it over. A pattern
that "looks right" but fails on the user's actual input is worse than no pattern.

## Test a pattern against samples

```bash
python3 - <<'PY'
import re
pat = r'\b\d{4}-\d{2}-\d{2}\b'
samples = ["due 2026-05-31 ok", "no date", "2026/05/31 wrong sep"]
for s in samples:
    print(repr(s), "->", re.findall(pat, s))
PY
```

## Extract with named groups

```bash
python3 - <<'PY'
import re
m = re.search(r'(?P<user>[\w.+-]+)@(?P<domain>[\w.-]+)', "ping alice.k+test@mail.example.com")
print(m.groupdict() if m else "no match")
PY
```

## Find-and-replace with backreferences

```bash
python3 - <<'PY'
import re
print(re.sub(r'(\d{4})-(\d{2})-(\d{2})', r'\3/\2/\1', "2026-05-31"))  # -> 31/05/2026
PY
```

## Common building blocks

- Anchors: `^` start, `$` end, `\b` word boundary.
- Classes: `\d` digit, `\w` word char, `\s` space; negate with uppercase `\D \W \S`.
- Quantifiers: `*` 0+, `+` 1+, `?` 0/1, `{m,n}`; add `?` for lazy (`.*?`).
- Groups: `(...)` capture, `(?:...)` non-capture, `(?P<name>...)` named.
- Lookaround: `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`.

## Guidance

- Always show what it matches AND what it deliberately rejects, using the user's samples.
- Prefer explicit, readable patterns over clever unreadable ones; add `re.VERBOSE` for
  complex patterns and comment them.
- Warn about catastrophic backtracking (nested quantifiers like `(a+)+`) on untrusted input.
- Note the regex flavor if it leaves Python (JS, PCRE, Go/RE2, grep) — escaping and
  lookbehind support differ.
