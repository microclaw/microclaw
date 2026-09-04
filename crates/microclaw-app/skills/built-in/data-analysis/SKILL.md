---
name: data-analysis
description: "Analyze a dataset end-to-end: load, clean, compute statistics, find patterns/correlations, and optionally plot — using pandas when available (stdlib fallback otherwise). Use when users hand over data (CSV/Excel/JSON) and want insights, trends, summaries, correlations, or charts, beyond a single quick query. Triggers on mentions of analyze data, analysis, statistics, correlation, trend, distribution, plot/chart the data, insights, 数据分析, 统计, 相关性, 趋势, 分布, 画图."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3; uses pandas/matplotlib when installed, with a stdlib fallback. Works on macOS, Linux, and Windows."
---

# Data Analysis

Compute, don't eyeball. Load the data, check it, then answer the actual question with numbers.
Check tooling first: `python3 -c "import pandas"` — if missing, fall back to the `csv`/`statistics` stdlib (see the `csv-tools` skill).

## Explore first (shape, types, missing)

```bash
python3 - <<'PY'
import pandas as pd
df = pd.read_csv("data.csv")          # or read_excel / read_json
print(df.shape)
print(df.dtypes)
print(df.isna().sum())                # missing values per column
print(df.describe(include="all"))     # summary stats
PY
```

## Aggregate, group, correlate

```bash
python3 - <<'PY'
import pandas as pd
df = pd.read_csv("data.csv")
print(df.groupby("category")["amount"].agg(["count","mean","sum"]))
print(df.select_dtypes("number").corr())   # correlation matrix
PY
```

## Plot (save, then send as attachment)

```bash
python3 - <<'PY'
import pandas as pd, matplotlib
matplotlib.use("Agg")                 # headless
import matplotlib.pyplot as plt
df = pd.read_csv("data.csv")
df.groupby("month")["sales"].sum().plot(kind="bar")
plt.tight_layout(); plt.savefig("tmp/chart.png", dpi=120)
print("wrote tmp/chart.png")
PY
```

## Workflow

1. Restate the question and what would answer it.
2. Load + sanity-check (shape, types, missing, obvious outliers).
3. Compute the specific metrics; don't dump everything.
4. Report the **findings** ("北区销量是南区的 2.3 倍，主要集中在 Q4"), with the numbers behind them.
5. Note caveats: small samples, missing data, correlation ≠ causation.

## Guidance

- Save charts under `tmp/` and send via `send_message` with `attachment_path`.
- Don't over-plot; one clear chart that answers the question beats five decorative ones.
- State assumptions (how you handled missing/dupes) so results are reproducible.
- If pandas isn't installed and the task is light, use `csv-tools`; if heavy, say what's needed.
