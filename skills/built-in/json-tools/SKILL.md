---
name: json-tools
description: "Query, filter, transform, and validate JSON using jq (or Python as a fallback). Use when users want to extract fields from a JSON blob/file/API response, reshape JSON, pretty-print, or check that JSON is valid. Triggers on mentions of json, jq, extract field, parse json, pretty print json, validate json, reshape, 解析 json, 提取字段, 格式化 json."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Prefers jq; falls back to python3. Works on macOS, Linux, and Windows."
---

# JSON Tools

Prefer `jq` for querying JSON; fall back to Python's `json` if `jq` isn't installed
(`command -v jq` to check).

## Pretty-print / validate

```bash
jq . data.json                 # pretty-print (errors if invalid)
python3 -m json.tool data.json # stdlib fallback
```

## Extract a field / path

```bash
jq -r '.user.name' data.json
jq -r '.items[].id' data.json          # one id per line
jq -r '.items[] | select(.active)' data.json
```

## Reshape into a new object / CSV

```bash
jq '{id: .id, who: .user.name}' data.json
jq -r '.rows[] | [.id, .name] | @csv' data.json
```

## Python fallback for the same tasks

```bash
python3 - <<'PY'
import json
d = json.load(open('data.json'))
print([it['id'] for it in d['items'] if it.get('active')])
PY
```

## Guidance

- `jq -r` strips quotes for raw string output; drop `-r` to keep valid JSON.
- For huge files, filter early (`jq '.items[] | select(...)'`) instead of loading all into memory in Python.
- When piping an API response, validate first — a truncated/HTML error page is not JSON.
- Show the extracted result, not the entire input.
