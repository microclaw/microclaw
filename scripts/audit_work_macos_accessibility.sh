#!/usr/bin/env bash
set -euo pipefail

work_process_name="${1:-microclaw-work}"
work_tree="$({
  osascript - "$work_process_name" <<'APPLESCRIPT'
on run arguments
  set processName to item 1 of arguments
  tell application "System Events"
    tell process processName
      return entire contents of front window
    end tell
  end tell
end run
APPLESCRIPT
} 2>&1)" || {
  printf '%s\n' "$work_tree" >&2
  echo "Could not read the Work accessibility tree. Launch the app and grant Accessibility permission to the terminal." >&2
  exit 1
}

required_nodes=(
  "button +  New chat"
  "text field Search conversations"
  "button Settings"
  "text area Message MicroClaw Work"
  "button Send"
)

for node in "${required_nodes[@]}"; do
  if [[ "$work_tree" != *"$node"* ]]; then
    echo "Missing required accessibility node: $node" >&2
    exit 1
  fi
done

if [[ "$work_tree" =~ button\ [0-9]+\ of\ group\ 1 ]]; then
  echo "Found an unnamed button in the Work content group." >&2
  exit 1
fi

echo "MicroClaw Work accessibility tree passed"
