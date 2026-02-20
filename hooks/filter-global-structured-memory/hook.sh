#!/bin/sh
payload="$(cat)"

python3 - <<'PY' "$payload"
import json
import sys

payload = sys.argv[1]

try:
    data = json.loads(payload)
except Exception:
    print('{"action":"allow"}')
    raise SystemExit(0)

if data.get("tool_name") != "structured_memory_search":
    print('{"action":"allow"}')
    raise SystemExit(0)

result = data.get("result") or {}
if result.get("is_error"):
    print('{"action":"allow"}')
    raise SystemExit(0)

content = result.get("content")
if not isinstance(content, str):
    print('{"action":"allow"}')
    raise SystemExit(0)

lines = content.splitlines()
filtered = [line for line in lines if "[global]" not in line]
new_content = "\n".join(filtered).strip()

if not new_content:
    new_content = "No memories found matching that query."

patch = {
    "content": new_content,
    "status_code": result.get("status_code", 0),
    "is_error": False,
}

print(json.dumps({"action": "modify", "patch": patch}, ensure_ascii=True))
PY
