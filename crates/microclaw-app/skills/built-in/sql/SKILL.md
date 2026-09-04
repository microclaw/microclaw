---
name: sql
description: "Write, run, and explain SQL queries, and do quick local analysis of CSV/SQLite data with the sqlite3 CLI. Use when users want a SQL query written or fixed, want to query a .db/.sqlite file, or want to analyze a CSV with SQL (joins, group by, window functions). Triggers on mentions of SQL, query, SELECT, JOIN, GROUP BY, sqlite, database table, 查询, 数据库, 写个 sql, 联表, 分组."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires sqlite3 for execution (query writing works without it). Works on macOS, Linux, and Windows."
---

# SQL

Write standard, readable SQL; when a database is available, run it to verify rather than
guessing the result. Check `command -v sqlite3` before executing.

## Inspect a SQLite database

```bash
sqlite3 app.db ".tables"
sqlite3 app.db ".schema users"
sqlite3 -header -column app.db "SELECT * FROM users LIMIT 5;"
```

## Query CSV directly with SQL (no schema setup)

```bash
sqlite3 :memory: -cmd ".mode csv" -cmd ".import data.csv t" \
  "SELECT region, COUNT(*) n, ROUND(AVG(amount),2) avg FROM t GROUP BY region ORDER BY n DESC;"
```

## Common patterns

```sql
-- Join + aggregate
SELECT u.name, COUNT(o.id) AS orders, SUM(o.total) AS spent
FROM users u LEFT JOIN orders o ON o.user_id = u.id
GROUP BY u.id
HAVING orders > 0
ORDER BY spent DESC;

-- Window function: rank within group
SELECT name, dept, salary,
       RANK() OVER (PARTITION BY dept ORDER BY salary DESC) AS rank_in_dept
FROM employees;

-- Upsert (SQLite / Postgres)
INSERT INTO kv(k, v) VALUES('x', 1)
ON CONFLICT(k) DO UPDATE SET v = excluded.v;
```

## Guidance

- Prefer explicit column lists over `SELECT *` in anything reused.
- Use `LEFT JOIN` when you must keep unmatched rows; `WHERE` on a left-joined table silently turns it into an inner join.
- `GROUP BY` every non-aggregated selected column.
- Note the dialect if it's not SQLite (Postgres/MySQL differ on quoting, `LIMIT`/`TOP`, upsert).
- Always test destructive statements (`UPDATE`/`DELETE`) first with a matching `SELECT`.
