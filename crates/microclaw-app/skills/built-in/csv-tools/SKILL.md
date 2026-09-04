---
name: csv-tools
description: "Inspect, filter, aggregate, and clean CSV/TSV data with Python. Use when users hand over a .csv/.tsv file or paste tabular data and want a quick look, column stats, filtering, sorting, deduping, group-by sums/counts, or cleanup — without needing a full spreadsheet. Triggers on mentions of csv, tsv, columns, rows, filter, group by, aggregate, dedupe, clean data, 表格, 逗号分隔, 去重, 分组统计, 筛选."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3. Works on macOS, Linux, and Windows."
---

# CSV Tools

Use Python's stdlib `csv` (always available). Reach for `pandas` only if it's installed
and the task is heavy (`python3 -c "import pandas"` to check first).

## Peek: headers, row count, first rows

```bash
python3 - <<'PY'
import csv
with open('data.csv', newline='') as f:
    r = list(csv.reader(f))
print('cols:', r[0])
print('rows:', len(r)-1)
for row in r[1:4]: print(row)
PY
```

## Filter rows by a column

```bash
python3 - <<'PY'
import csv
with open('data.csv', newline='') as f:
    for row in csv.DictReader(f):
        if row['status'] == 'active':
            print(row['id'], row['name'])
PY
```

## Group-by aggregate (sum / count)

```bash
python3 - <<'PY'
import csv, collections
sums = collections.Counter()
with open('sales.csv', newline='') as f:
    for row in csv.DictReader(f):
        sums[row['region']] += float(row['amount'])
for k,v in sums.most_common():
    print(f'{k}: {v:.2f}')
PY
```

## Dedupe / clean

```bash
python3 - <<'PY'
import csv
seen=set(); out=[]
with open('data.csv', newline='') as f:
    rd=csv.reader(f); header=next(rd)
    for row in rd:
        key=tuple(c.strip() for c in row)
        if key not in seen:
            seen.add(key); out.append(row)
with open('clean.csv','w',newline='') as f:
    w=csv.writer(f); w.writerow(header); w.writerows(out)
print('wrote', len(out), 'unique rows')
PY
```

## Guidance

- Always check the delimiter (`,` vs `\t` vs `;`) and whether there's a header row.
- Watch for quoted fields containing commas/newlines — `csv` handles them; manual splitting won't.
- Report a short summary (rows in/out, columns, key numbers), not the whole file.
- If the deliverable is a polished spreadsheet with formatting/charts, use the `xlsx` skill instead.
