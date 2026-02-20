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

tool_name = data.get("tool_name")
tool_input = data.get("tool_input") or {}
scope = tool_input.get("scope")

if tool_name in ("read_memory", "write_memory") and scope == "global":
    print('{"action":"block","reason":"global memory is disabled by policy; use scope=chat"}')
else:
    print('{"action":"allow"}')
PY
