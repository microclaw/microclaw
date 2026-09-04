---
name: decision-matrix
description: "Compare options against weighted criteria to make a defensible decision (a.k.a. weighted scoring / pros-cons-on-steroids). Use when users are choosing between alternatives — tools, vendors, designs, offers, places — and want a structured comparison or 'which should I pick'. Triggers on mentions of compare options, which should I choose, pros and cons, trade-offs, decide between, evaluate options, 怎么选, 选哪个, 对比方案, 利弊, 权衡."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Decision Matrix

Turn a fuzzy "which one?" into a transparent, weighted comparison the user can adjust.

## Steps

1. **List the options** (the real candidates, 2–5).
2. **List the criteria** that actually matter to this user, and **weight** them (must sum to
   100%, or use 1–5 importance). Make the user's priorities explicit.
3. **Score** each option on each criterion (e.g. 1–5).
4. **Compute** weighted totals.
5. **Sanity-check** the winner against gut feel — if it feels wrong, a weight is probably off;
   surface that rather than hiding it.

## Example

```bash
python3 - <<'PY'
weights = {"price":0.4, "ease":0.35, "support":0.25}
scores = {
  "Option A": {"price":5, "ease":3, "support":4},
  "Option B": {"price":3, "ease":5, "support":4},
}
for opt, s in scores.items():
    total = sum(s[c]*w for c,w in weights.items())
    print(f"{opt}: {total:.2f}")
PY
```

## Output

- A small table: options × criteria with scores, the weights, and the weighted totals.
- The recommendation in one line, plus the main trade-off ("A wins on price; pick B if ease matters most").
- Note any decisive dealbreaker that overrides the score (a hard constraint).

## Guidance

- Weights encode the user's values — ask or state your assumption, and invite them to retune.
- Don't false-precision it: scores are judgments. The value is the structure, not the decimals.
- Flag missing info that would change the answer ("if price is fixed, this collapses to ease").
