#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--output-dir DIR]"
}

output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
release_version="$(
  sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)"/\1/p' Cargo.toml |
    head -n 1
)"
if [[ -z "$release_version" ]]; then
  echo "Unable to read the package version from Cargo.toml" >&2
  exit 1
fi
if [[ -z "$output_dir" ]]; then
  output_dir="target/reliability-scorecard/$timestamp"
fi
mkdir -p "$output_dir/logs"

json_path="$output_dir/scorecard.json"
markdown_path="$output_dir/scorecard.md"
rows_path="$output_dir/.rows"
: > "$rows_path"

run_case() {
  local id="$1"
  local category="$2"
  local description="$3"
  shift 3

  local log_path="$output_dir/logs/$id.log"
  local started finished duration_ms status
  started="$(date +%s)"
  echo "[reliability] $id: $description"
  if "$@" >"$log_path" 2>&1; then
    status="pass"
  else
    status="fail"
  fi
  finished="$(date +%s)"
  duration_ms="$(( (finished - started) * 1000 ))"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$category" "$status" "$duration_ms" "$description" "logs/$id.log" \
    >> "$rows_path"

  if [[ "$status" == "fail" ]]; then
    tail -80 "$log_path" >&2
  fi
}

run_case "process-restart" "recovery" \
  "A safe active-turn checkpoint survives a second recovery restart." \
  cargo test --quiet -p microclaw-engine test_active_turn_checkpoint_survives_recovery_restart_boundary
run_case "scheduler-reopen" "recovery" \
  "Scheduled work remains available after the database is reopened." \
  cargo test --quiet --test db_integration test_scheduled_task_persists_across_db_reopen
run_case "scheduler-dlq-replay" "recovery" \
  "A failed scheduled run can be replayed from the durable dead-letter queue." \
  cargo test --quiet test_replay_task_dlq_requeues_task_and_marks_replayed
run_case "delivery-idempotency" "delivery" \
  "Interrupted chunk delivery resumes without duplicating the logical message." \
  cargo test --quiet -p microclaw-engine test_chunked_delivery_resumes_and_stores_logical_message_once
run_case "payload-integrity" "delivery" \
  "Long messages preserve every byte across newline chunk boundaries." \
  cargo test --quiet -p microclaw-core split_text_preserves_every_byte_at_newline_boundaries
run_case "utf8-boundaries" "delivery" \
  "Long-message splitting never cuts through a UTF-8 code point." \
  cargo test --quiet -p microclaw-core split_text_respects_utf8_boundaries
run_case "rate-limit-recovery" "rate_limit" \
  "The request rate-limit window accepts work again after recovery." \
  cargo test --quiet test_rate_limit_window_recovers
run_case "delivery-rate-limit" "rate_limit" \
  "Common delivery rate-limit failures are classified as retryable." \
  cargo test --quiet test_is_retryable_delivery_rate_limit_recognizes_common_errors
run_case "tool-timeout" "timeout" \
  "A timed-out command is terminated and reported as a timeout." \
  cargo test --quiet test_bash_timeout
run_case "malformed-wrapper" "provider_boundary" \
  "Malformed provider wrappers are normalized without poisoning stored history." \
  cargo test --quiet test_extract_raw_tool_use_blocks_from_minimax_wrappers
run_case "output-sanitization" "provider_boundary" \
  "Private reasoning and fake tool traces are removed before delivery." \
  cargo test --quiet -p microclaw-core sanitizes_private_reasoning_and_fake_tool_calls
run_case "permission-matrix" "security" \
  "Cross-chat tool permissions remain fail-closed." \
  cargo test --quiet --test tool_permissions
run_case "sandbox-required" "security" \
  "A required sandbox fails closed when its runtime is unavailable." \
  cargo test --quiet -p microclaw-engine test_router_fails_closed_when_runtime_required_and_missing

total="$(wc -l < "$rows_path" | tr -d ' ')"
passed="$(awk -F '\t' '$3 == "pass" { count++ } END { print count+0 }' "$rows_path")"
failed="$((total - passed))"

{
  echo "{"
  echo "  \"schema_version\": 1,"
  echo "  \"generated_at\": \"$timestamp\","
  echo "  \"release\": \"$release_version\","
  echo "  \"summary\": {\"total\": $total, \"passed\": $passed, \"failed\": $failed},"
  echo "  \"cases\": ["
  first=1
  while IFS=$'\t' read -r id category status duration_ms description log; do
    if [[ $first -eq 0 ]]; then
      echo ","
    fi
    first=0
    printf '    {"id":"%s","category":"%s","status":"%s","duration_ms":%s,"description":"%s","evidence":"%s"}' \
      "$id" "$category" "$status" "$duration_ms" "$description" "$log"
  done < "$rows_path"
  echo
  echo "  ]"
  echo "}"
} > "$json_path"

{
  echo "# MicroClaw Reliability Scorecard"
  echo
  echo "- Generated: \`$timestamp\`"
  echo "- Release: \`$release_version\`"
  echo "- Result: **$passed/$total passed**"
  echo
  echo "| Scenario | Category | Result | Duration | Evidence |"
  echo "|---|---|---:|---:|---|"
  while IFS=$'\t' read -r id category status duration_ms description log; do
    echo "| $description | \`$category\` | **$status** | ${duration_ms} ms | [$id log]($log) |"
  done < "$rows_path"
  echo
  echo "This scorecard proves the in-repository MicroClaw baseline. It does not claim"
  echo "cross-project superiority; competitor adapters must run the same scenarios,"
  echo "payloads, retry windows, and release versions before comparison."
} > "$markdown_path"

echo "[reliability] scorecard: $markdown_path"
echo "[reliability] machine-readable: $json_path"

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
