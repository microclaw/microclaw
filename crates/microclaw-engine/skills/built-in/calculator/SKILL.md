---
name: calculator
description: "Evaluate math expressions and do exact/precise calculations using Python. Use for arithmetic, percentages, exponents, roots, trigonometry, logarithms, big-number or high-precision math, financial math (interest, tips, splits), and unit-free numeric problems where a wrong digit matters. Triggers on mentions of calculate, compute, how much is, percent, square root, power, sum, average, 算, 计算, 百分之, 平方根, 多少."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3. Works on macOS, Linux, and Windows."
---

# Calculator

Do not do multi-step arithmetic in your head — run it. A single wrong digit erodes trust.
Use Python for any calculation beyond trivial one-step mental math.

## Quick evaluation

```bash
python3 -c "print(2**32 - 1)"
python3 -c "print(0.1 + 0.2)"
python3 -c "import math; print(math.sqrt(2), math.log(1000, 10))"
```

## Exact decimal / money (avoid float errors)

```bash
python3 -c "from decimal import Decimal as D; print(D('19.99')*D('3'))"
```

## Percentages, tips, splits

```bash
python3 -c "bill=128.50; tip=0.18; n=4; total=bill*(1+tip); print(f'total={total:.2f}, per_person={total/n:.2f}')"
```

## Stats over a list

```bash
python3 -c "import statistics as s; xs=[12,7,9,21,4]; print('mean',s.mean(xs),'median',s.median(xs),'stdev',round(s.pstdev(xs),3))"
```

## Compound interest

```bash
python3 -c "p=10000; r=0.05; n=12; t=3; print(round(p*(1+r/n)**(n*t),2))"
```

## Guidance

- Prefer `decimal.Decimal` for money; prefer `fractions.Fraction` for exact rational results.
- Show the user the result, not the code, unless they ask how.
- For symbolic algebra/calculus, use `sympy` if available (`python3 -c "import sympy"` to check first).
- State units explicitly in the answer when the problem has them.
