---
name: code-review
description: "Review code or a diff for correctness bugs, security issues, and clear simplifications. Use when users ask to review code, check a PR/diff, find bugs, audit a function, or ask 'is this code correct/safe', 'what's wrong with this'. Covers logic errors, edge cases, error handling, concurrency, injection/secrets, and readability. Triggers on mentions of review, code review, audit, find bugs, check this code, PR review, 代码审查, 评审, 查 bug, 看看这段代码."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Code Review

Review like a senior engineer who is kind but does not rubber-stamp. Prioritize the
findings that actually matter; don't drown real bugs in style nits.

## What to look for (in priority order)

1. **Correctness** — wrong logic, off-by-one, inverted conditions, bad null/empty/zero
   handling, wrong types, incorrect async/await, missing returns.
2. **Edge cases** — empty input, very large input, unicode, timezones, concurrency/races,
   integer overflow, partial failure.
3. **Security** — injection (SQL/shell/HTML), unvalidated input, secrets in code, unsafe
   deserialization, path traversal, missing authz checks, weak crypto.
4. **Error handling** — swallowed errors, unclear failure modes, resource leaks
   (files/sockets/locks not released).
5. **Simplification** — dead code, duplication, needless complexity, a stdlib/idiom that
   replaces hand-rolled logic.
6. **Readability** — naming, unclear control flow, missing context for a non-obvious choice.

## How to report

For each finding:
```
[severity: bug | security | nit]  file:line
  what: <the problem, one line>
  why:  <impact / failing case>
  fix:  <concrete suggestion or patch>
```
- Lead with the highest-severity items. If the code is solid, say so plainly and list only
  the few things worth changing.
- Distinguish "this is a bug" from "I'd prefer." Don't invent problems to look thorough.
- When unsure whether something is a bug, say "verify: …" rather than asserting.

## Guidance

- If a diff is available, review the diff in context, not the whole repo.
- Suggest a test for any non-trivial bug you find.
- Keep the review proportional: a 10-line snippet gets a few lines back, not an essay.
