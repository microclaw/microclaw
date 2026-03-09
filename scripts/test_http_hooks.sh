#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/test_http_hooks.sh [--config <path>] --hooks-token <token> [--base-url <url>]

Examples:
  scripts/test_http_hooks.sh --hooks-token my-hooks-secret

  scripts/test_http_hooks.sh \
    --config api_test_microclaw.config.yaml \
    --hooks-token my-hooks-secret

Notes:
  - Default config path: microclaw.config.yaml
  - The script starts: cargo run -- start --config <path>
  - It validates HTTP hook endpoints:
    /hooks/agent, /api/hooks/agent, /hooks/wake
EOF
}

CONFIG_PATH="microclaw.config.yaml"
HOOKS_TOKEN=""
BASE_URL="http://127.0.0.1:10961"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --hooks-token)
      HOOKS_TOKEN="${2:-}"
      shift 2
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$HOOKS_TOKEN" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config file does not exist: $CONFIG_PATH" >&2
  exit 1
fi

extract_port_from_base_url() {
  local raw="$1"
  local no_scheme="${raw#*://}"
  local host_port="${no_scheme%%/*}"
  if [[ "$host_port" == *:* ]]; then
    echo "${host_port##*:}"
    return 0
  fi
  echo "80"
}

PORT="$(extract_port_from_base_url "$BASE_URL")"
if command -v lsof >/dev/null 2>&1; then
  existing_listener="$(lsof -tiTCP:"$PORT" -sTCP:LISTEN -n -P 2>/dev/null | head -n 1 || true)"
  if [[ -n "$existing_listener" ]]; then
    echo "Port $PORT is already in use by PID $existing_listener. Stop it and rerun." >&2
    exit 1
  fi
fi

LOG_FILE="$(mktemp -t microclaw-http-hooks-log.XXXXXX)"
cleanup() {
  if [[ -n "${MC_PID:-}" ]]; then
    kill "$MC_PID" >/dev/null 2>&1 || true
    wait "$MC_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$LOG_FILE"
}
trap cleanup EXIT

echo "[1/11] Starting MicroClaw with config: $CONFIG_PATH"
cargo run -- start --config "$CONFIG_PATH" >"$LOG_FILE" 2>&1 &
MC_PID=$!

echo "[2/11] Waiting for web server..."
ready=0
for _ in $(seq 1 90); do
  if ! kill -0 "$MC_PID" >/dev/null 2>&1; then
    echo "MicroClaw process exited before server became ready." >&2
    echo "---- last logs ----" >&2
    tail -n 100 "$LOG_FILE" >&2 || true
    exit 1
  fi
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/health" || true)"
  if [[ "$code" == "200" || "$code" == "401" ]]; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "Server did not become ready in time." >&2
  echo "---- last logs ----" >&2
  tail -n 100 "$LOG_FILE" >&2 || true
  exit 1
fi

extract_json_field() {
  local payload="$1"
  local field="$2"
  python3 - "$payload" "$field" <<'PY'
import json
import sys
raw = sys.argv[1]
field = sys.argv[2]
try:
    obj = json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)
value = obj.get(field)
if value is None:
    print("")
elif isinstance(value, bool):
    print("true" if value else "false")
else:
    print(str(value))
PY
}

RESP_BODY=""
RESP_CODE=""

post_json() {
  local auth_mode="$1"
  local url="$2"
  local payload="$3"
  local -a headers=("-H" "Content-Type: application/json")
  case "$auth_mode" in
    bearer)
      headers+=("-H" "Authorization: Bearer $HOOKS_TOKEN")
      ;;
    bad-bearer)
      headers+=("-H" "Authorization: Bearer ${HOOKS_TOKEN}-invalid")
      ;;
    openclaw)
      headers+=("-H" "x-openclaw-token: $HOOKS_TOKEN")
      ;;
    microclaw)
      headers+=("-H" "x-microclaw-hook-token: $HOOKS_TOKEN")
      ;;
    none)
      ;;
    *)
      echo "Unknown auth mode: $auth_mode" >&2
      exit 1
      ;;
  esac
  local resp
  resp="$(curl -sS -X POST "$url" "${headers[@]}" -d "$payload" -w $'\n%{http_code}')"
  RESP_CODE="${resp##*$'\n'}"
  RESP_BODY="${resp%$'\n'*}"
}

wait_for_run_id() {
  local auth_mode="$1"
  local url="$2"
  local payload="$3"
  local run_id=""
  for _ in $(seq 1 30); do
    post_json "$auth_mode" "$url" "$payload"
    run_id="$(extract_json_field "$RESP_BODY" "run_id")"
    if [[ -n "$run_id" ]]; then
      echo "$run_id"
      return 0
    fi
    if [[ "$RESP_BODY" == *"too many concurrent requests for session"* ]]; then
      sleep 1
      continue
    fi
    echo "Expected run_id from $url, got status=$RESP_CODE body=$RESP_BODY" >&2
    return 1
  done
  echo "Timed out waiting for run slot at $url" >&2
  return 1
}

echo "[3/11] Validating missing/invalid token are rejected"
post_json none "$BASE_URL/hooks/agent" '{"message":"ping"}'
if [[ "$RESP_CODE" != "401" ]]; then
  echo "Expected 401 for missing token, got: $RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi
post_json bad-bearer "$BASE_URL/hooks/agent" '{"message":"ping"}'
if [[ "$RESP_CODE" != "401" ]]; then
  echo "Expected 401 for invalid token, got: $RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi

echo "[4/11] Validating compatible token headers"
wait_for_run_id openclaw "$BASE_URL/hooks/agent" \
  '{"message":"header openclaw test","name":"api-test"}' >/dev/null
wait_for_run_id microclaw "$BASE_URL/hooks/agent" \
  '{"message":"header microclaw test","name":"api-test"}' >/dev/null

echo "[5/11] Validating /hooks/agent and /api/hooks/agent"
wait_for_run_id bearer "$BASE_URL/hooks/agent" \
  '{"message":"hook agent test","name":"api-test"}' >/dev/null
wait_for_run_id bearer "$BASE_URL/api/hooks/agent" \
  '{"message":"hook alias test","senderName":"api-test"}' >/dev/null

echo "[6/11] Validating /hooks/wake and /api/hooks/wake (mode=now)"
wait_for_run_id bearer "$BASE_URL/hooks/wake" \
  '{"text":"hook wake now test","mode":"now"}' >/dev/null
wait_for_run_id bearer "$BASE_URL/api/hooks/wake" \
  '{"text":"hook wake alias now test","mode":"now"}' >/dev/null

echo "[7/11] Validating wake queue mode"
post_json bearer "$BASE_URL/hooks/wake" \
  '{"text":"hook wake queue test","mode":"next-heartbeat"}'
queued="$(extract_json_field "$RESP_BODY" "queued")"
mode="$(extract_json_field "$RESP_BODY" "mode")"
queued_session_key="$(extract_json_field "$RESP_BODY" "session_key")"
if [[ "$RESP_CODE" != "200" || "$queued" != "true" || "$mode" != "next-heartbeat" ]]; then
  echo "Expected queued=true and mode=next-heartbeat, got status=$RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi
if [[ -z "$queued_session_key" ]]; then
  echo "Expected non-empty session_key in wake queue response, got: $RESP_BODY" >&2
  exit 1
fi

echo "[8/11] Validating wake invalid payloads"
post_json bearer "$BASE_URL/hooks/wake" '{"text":"   ","mode":"now"}'
if [[ "$RESP_CODE" != "400" ]]; then
  echo "Expected 400 for empty wake text, got status=$RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi
post_json bearer "$BASE_URL/hooks/wake" '{"text":"abc","mode":"later"}'
if [[ "$RESP_CODE" != "400" ]]; then
  echo "Expected 400 for invalid wake mode, got status=$RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi

echo "[9/11] Validating OpenClaw payload compatibility fields"
post_json bearer "$BASE_URL/hooks/agent" \
  '{"message":"compat test","sessionKey":"hook:compat:1","name":"from-name"}'
compat_with_session_run_id="$(extract_json_field "$RESP_BODY" "run_id")"
if [[ "$RESP_CODE" != "400" && ( "$RESP_CODE" != "200" || -z "$compat_with_session_run_id" ) ]]; then
  echo "Expected either 400 (override disabled) or run_id (override enabled), got status=$RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi
wait_for_run_id bearer "$BASE_URL/hooks/agent" \
  '{"message":"compat fallback","senderName":"from-sender","name":"from-name"}' >/dev/null

echo "[10/11] Validating sessionKey override policy (auto-detect)"
post_json bearer "$BASE_URL/hooks/agent" \
  '{"message":"override policy test","sessionKey":"hook:manual:1"}'
override_run_id="$(extract_json_field "$RESP_BODY" "run_id")"
if [[ "$RESP_CODE" == "400" ]]; then
  echo "sessionKey override policy: disabled (as expected in strict mode)"
elif [[ "$RESP_CODE" == "200" && -n "$override_run_id" ]]; then
  echo "sessionKey override policy: enabled"
  post_json bearer "$BASE_URL/hooks/agent" \
    '{"message":"prefix probe","sessionKey":"__deny_probe__:1"}'
  if [[ "$RESP_CODE" == "400" ]]; then
    echo "sessionKey prefix allowlist: active"
  else
    echo "sessionKey prefix allowlist: not configured"
  fi
else
  echo "Unexpected response for override policy probe: status=$RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi

echo "[11/11] Validating /api/hooks/wake queue alias"
post_json bearer "$BASE_URL/api/hooks/wake" \
  '{"text":"hook wake alias queue test","mode":"next-heartbeat"}'
queued_alias="$(extract_json_field "$RESP_BODY" "queued")"
mode_alias="$(extract_json_field "$RESP_BODY" "mode")"
if [[ "$RESP_CODE" != "200" || "$queued_alias" != "true" || "$mode_alias" != "next-heartbeat" ]]; then
  echo "Expected queued alias response, got status=$RESP_CODE body=$RESP_BODY" >&2
  exit 1
fi

echo "All HTTP hook checks passed."
