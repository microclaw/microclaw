#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${MATRIX_SMOKE_DIR:-/tmp/microclaw-matrix-smoke}"
PROJECT_NAME="${MATRIX_SMOKE_PROJECT:-microclaw-matrix-smoke}"
SYNAPSE_PORT="${MATRIX_SMOKE_PORT:-18008}"
KEEP_ENV="${MATRIX_SMOKE_KEEP:-0}"
TIMEOUT_SECS="${MATRIX_SMOKE_TIMEOUT_SECS:-45}"
NO_MENTION_WAIT_SECS="${MATRIX_SMOKE_NO_MENTION_WAIT_SECS:-8}"

COMPOSE_FILE="$WORK_DIR/docker-compose.yaml"
DATA_DIR="$WORK_DIR/data"
LOG_FILE="$WORK_DIR/microclaw.log"
CONFIG_FILE="$WORK_DIR/microclaw.matrix-smoke.yaml"
STATE_FILE="$WORK_DIR/state.env"
RUNTIME_ROOT="$WORK_DIR/microclaw.data"
DB_PATH="$RUNTIME_ROOT/runtime/microclaw.db"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

for cmd in docker curl jq cargo awk sed sqlite3; do
  require_cmd "$cmd"
done

docker compose version >/dev/null

mkdir -p "$WORK_DIR"

cleanup() {
  if [[ -n "${MICROCLAW_PID:-}" ]]; then
    kill "$MICROCLAW_PID" >/dev/null 2>&1 || true
    wait "$MICROCLAW_PID" >/dev/null 2>&1 || true
  fi

  if [[ "$KEEP_ENV" != "1" ]]; then
    docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_bot_count_gt() {
  local before="$1"
  local after="$before"
  local response=""
  for _ in $(seq 1 "$TIMEOUT_SECS"); do
    response="$(curl -sS "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/messages?dir=b&limit=100" -H "Authorization: Bearer $ALICE_TOKEN")"
    after="$(printf '%s' "$response" | jq '[.chunk[] | select(.type=="m.room.message" and .sender=="@bot:localhost")] | length')"
    if [[ "$after" -gt "$before" ]]; then
      LAST_BOT_BODY="$(printf '%s' "$response" | jq -r '.chunk[] | select(.type=="m.room.message" and .sender=="@bot:localhost") | .content.body' | head -n 1)"
      LAST_BOT_EVENT_ID="$(printf '%s' "$response" | jq -r '.chunk[] | select(.type=="m.room.message" and .sender=="@bot:localhost") | .event_id' | head -n 1)"
      BOT_COUNT_AFTER_WAIT="$after"
      return 0
    fi
    sleep 1
  done

  BOT_COUNT_AFTER_WAIT="$after"
  return 1
}

wait_for_db_pattern() {
  local pattern="$1"
  for _ in $(seq 1 "$TIMEOUT_SECS"); do
    if [[ -f "$DB_PATH" ]]; then
      if sqlite3 "$DB_PATH" "SELECT content FROM messages;" 2>/dev/null | grep -Fq "$pattern"; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

cat > "$COMPOSE_FILE" <<YAML
services:
  synapse:
    image: matrixdotorg/synapse:latest
    restart: unless-stopped
    ports:
      - "${SYNAPSE_PORT}:8008"
    volumes:
      - ./data:/data
    environment:
      - SYNAPSE_SERVER_NAME=localhost
      - SYNAPSE_REPORT_STATS=no
YAML

if [[ ! -f "$DATA_DIR/homeserver.yaml" ]]; then
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" run --rm synapse generate >/dev/null
fi

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d >/dev/null

CONTAINER_ID="$(docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" ps -q synapse)"
if [[ -z "$CONTAINER_ID" ]]; then
  echo "Failed to determine Synapse container id" >&2
  exit 1
fi

for _ in $(seq 1 60); do
  status="$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_ID" 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  sleep 1
done

BASE_URL="http://127.0.0.1:${SYNAPSE_PORT}"
curl -sS "$BASE_URL/_matrix/client/versions" >/dev/null

SECRET="$(awk -F': ' '/registration_shared_secret:/ {gsub(/"/,"",$2); print $2}' "$DATA_DIR/homeserver.yaml")"
if [[ -z "$SECRET" ]]; then
  echo "Failed to read registration_shared_secret from $DATA_DIR/homeserver.yaml" >&2
  exit 1
fi

register_user() {
  local user="$1"
  local pass="$2"
  docker exec "$CONTAINER_ID" register_new_matrix_user --exists-ok -u "$user" -p "$pass" -a -k="$SECRET" http://localhost:8008 >/dev/null
}

register_user bot botpass123
register_user alice alicepass123

BOT_TOKEN="$(curl -sS -X POST "$BASE_URL/_matrix/client/v3/login" -H 'Content-Type: application/json' -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"bot"},"password":"botpass123"}' | jq -r '.access_token')"
ALICE_TOKEN="$(curl -sS -X POST "$BASE_URL/_matrix/client/v3/login" -H 'Content-Type: application/json' -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"alicepass123"}' | jq -r '.access_token')"

if [[ "$BOT_TOKEN" == "null" || -z "$BOT_TOKEN" ]]; then
  echo "Failed to log in bot user" >&2
  exit 1
fi
if [[ "$ALICE_TOKEN" == "null" || -z "$ALICE_TOKEN" ]]; then
  echo "Failed to log in alice user" >&2
  exit 1
fi

ROOM_ID="$(curl -sS -X POST "$BASE_URL/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"microclaw-matrix-smoke","preset":"private_chat","invite":["@bot:localhost"]}' | jq -r '.room_id')"

if [[ "$ROOM_ID" == "null" || -z "$ROOM_ID" ]]; then
  echo "Failed to create room" >&2
  exit 1
fi

ROOM_ID_URI="$(jq -rn --arg x "$ROOM_ID" '$x|@uri')"

curl -sS -X POST "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/join" \
  -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{}' >/dev/null

cat > "$CONFIG_FILE" <<YAML
llm_provider: "ollama"
api_key: ""
data_dir: "${RUNTIME_ROOT}"
working_dir: "${WORK_DIR}/work"
web_enabled: false
channels:
  web:
    enabled: false
  matrix:
    enabled: true
    homeserver_url: "${BASE_URL}"
    access_token: "${BOT_TOKEN}"
    bot_user_id: "@bot:localhost"
    mention_required: true
    allowed_room_ids:
      - "${ROOM_ID}"
YAML

cat > "$STATE_FILE" <<STATE
BASE_URL='${BASE_URL}'
ROOM_ID='${ROOM_ID}'
ROOM_ID_URI='${ROOM_ID_URI}'
BOT_TOKEN='${BOT_TOKEN}'
ALICE_TOKEN='${ALICE_TOKEN}'
DB_PATH='${DB_PATH}'
STATE

pushd "$ROOT_DIR" >/dev/null
MICROCLAW_CONFIG="$CONFIG_FILE" cargo run -- start >"$LOG_FILE" 2>&1 &
MICROCLAW_PID=$!
popd >/dev/null

sleep 6

# 1) mention gating: plain text without mention should not trigger bot reply.
BASE_BOT_COUNT="$(curl -sS "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/messages?dir=b&limit=100" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  | jq '[.chunk[] | select(.type=="m.room.message" and .sender=="@bot:localhost")] | length')"

TXN_ID="$(cat /proc/sys/kernel/random/uuid)"
curl -sS -X PUT "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/send/m.room.message/$TXN_ID" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"hello without mention"}' >/dev/null

sleep "$NO_MENTION_WAIT_SECS"
AFTER_NO_MENTION="$(curl -sS "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/messages?dir=b&limit=100" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  | jq '[.chunk[] | select(.type=="m.room.message" and .sender=="@bot:localhost")] | length')"

if [[ "$AFTER_NO_MENTION" -ne "$BASE_BOT_COUNT" ]]; then
  echo "Matrix smoke test FAILED: bot replied to non-mentioned message with mention_required=true" >&2
  echo "before=$BASE_BOT_COUNT after=$AFTER_NO_MENTION" >&2
  echo "log_file=$LOG_FILE" >&2
  exit 1
fi

# 2) mention via Matrix metadata should trigger a bot reply.
TXN_ID="$(cat /proc/sys/kernel/random/uuid)"
MENTION_SEND_RESULT="$(curl -sS -X PUT "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/send/m.room.message/$TXN_ID" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"ping","m.mentions":{"user_ids":["@bot:localhost"]}}')"

LAST_BOT_BODY=""
LAST_BOT_EVENT_ID=""
BOT_COUNT_AFTER_WAIT="$AFTER_NO_MENTION"
wait_for_bot_count_gt "$AFTER_NO_MENTION" || true
AFTER_MENTION="$BOT_COUNT_AFTER_WAIT"
if [[ "$AFTER_MENTION" -le "$AFTER_NO_MENTION" ]]; then
  echo "Matrix smoke test FAILED: bot did not reply to mentioned message within ${TIMEOUT_SECS}s" >&2
  echo "mention_send_result=$MENTION_SEND_RESULT" >&2
  echo "log_file=$LOG_FILE" >&2
  exit 1
fi

# 3) reaction ingestion: add reaction from alice to the latest bot message and assert DB ingestion.
if [[ -z "$LAST_BOT_EVENT_ID" || "$LAST_BOT_EVENT_ID" == "null" ]]; then
  echo "Matrix smoke test FAILED: could not determine last bot event id" >&2
  exit 1
fi

REACTION_TXN_ID="$(cat /proc/sys/kernel/random/uuid)"
REACTION_SEND_RESULT="$(curl -sS -X PUT "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/send/m.reaction/$REACTION_TXN_ID" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"m.relates_to\":{\"rel_type\":\"m.annotation\",\"event_id\":\"$LAST_BOT_EVENT_ID\",\"key\":\"👍\"}}")"

if ! wait_for_db_pattern "[reaction] @alice:localhost reacted 👍"; then
  echo "Matrix smoke test FAILED: reaction event was not ingested into DB" >&2
  echo "reaction_send_result=$REACTION_SEND_RESULT" >&2
  echo "db_path=$DB_PATH" >&2
  echo "log_file=$LOG_FILE" >&2
  exit 1
fi

# 4) attachment ingestion: upload and send file from alice, assert DB contains normalized attachment line.
UPLOAD_JSON="$(printf 'matrix smoke attachment\n' | curl -sS -X POST "$BASE_URL/_matrix/media/v3/upload?filename=smoke.txt" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: text/plain' \
  --data-binary @-)"
CONTENT_URI="$(printf '%s' "$UPLOAD_JSON" | jq -r '.content_uri')"
if [[ "$CONTENT_URI" == "null" || -z "$CONTENT_URI" ]]; then
  echo "Matrix smoke test FAILED: upload did not return content_uri" >&2
  echo "upload_json=$UPLOAD_JSON" >&2
  exit 1
fi

ATTACH_TXN_ID="$(cat /proc/sys/kernel/random/uuid)"
ATTACH_SEND_RESULT="$(curl -sS -X PUT "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID_URI/send/m.room.message/$ATTACH_TXN_ID" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"msgtype\":\"m.file\",\"body\":\"smoke.txt\",\"filename\":\"smoke.txt\",\"url\":\"$CONTENT_URI\"}")"

if ! wait_for_db_pattern "[attachment:m.file] smoke.txt ($CONTENT_URI)"; then
  echo "Matrix smoke test FAILED: attachment event was not ingested into DB" >&2
  echo "attach_send_result=$ATTACH_SEND_RESULT" >&2
  echo "db_path=$DB_PATH" >&2
  echo "log_file=$LOG_FILE" >&2
  exit 1
fi

echo "Matrix smoke test PASSED"
echo "room_id=$ROOM_ID"
echo "mention_send_result=$MENTION_SEND_RESULT"
echo "reaction_send_result=$REACTION_SEND_RESULT"
echo "attachment_send_result=$ATTACH_SEND_RESULT"
echo "bot_reply=$LAST_BOT_BODY"
echo "db_path=$DB_PATH"
echo "microclaw_log=$LOG_FILE"

if [[ "$KEEP_ENV" == "1" ]]; then
  echo "Environment kept at $WORK_DIR"
fi
