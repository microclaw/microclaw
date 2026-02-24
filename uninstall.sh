#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="microclaw"

log() {
  printf '%s\n' "$*"
}

err() {
  printf 'Error: %s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    *)
      err "Unsupported OS: $(uname -s)"
      exit 1
      ;;
  esac
}

resolve_targets() {
  local out=()

  if [ -n "${MICROCLAW_INSTALL_DIR:-}" ]; then
    out+=("${MICROCLAW_INSTALL_DIR%/}/$BIN_NAME")
  fi

  if need_cmd "$BIN_NAME"; then
    out+=("$(command -v "$BIN_NAME")")
  fi

  out+=("/usr/local/bin/$BIN_NAME")
  out+=("$HOME/.local/bin/$BIN_NAME")

  # De-duplicate while preserving order.
  local seen="|"
  local path
  for path in "${out[@]}"; do
    if [ -n "$path" ] && [[ "$seen" != *"|$path|"* ]]; then
      printf '%s\n' "$path"
      seen+="$path|"
    fi
  done
}

remove_file() {
  local target="$1"
  if [ ! -e "$target" ]; then
    return 1
  fi

  if [ -w "$target" ] || [ -w "$(dirname "$target")" ]; then
    rm -f "$target"
  else
    if need_cmd sudo; then
      sudo rm -f "$target"
    else
      err "No permission to remove $target and sudo is unavailable"
      return 2
    fi
  fi

  return 0
}

main() {
  local os removed=0 failed=0 target

  os="$(detect_os)"
  log "Uninstalling $BIN_NAME on $os..."

  while IFS= read -r target; do
    if [ -z "$target" ]; then
      continue
    fi
    if remove_file "$target"; then
      log "Removed: $target"
      removed=$((removed + 1))
    else
      rc=$?
      if [ "$rc" -eq 2 ]; then
        failed=1
      fi
    fi
  done < <(resolve_targets)

  if [ "$failed" -ne 0 ]; then
    exit 1
  fi

  if [ "$removed" -eq 0 ]; then
    log "$BIN_NAME binary not found. Nothing to uninstall."
    exit 0
  fi

  log ""
  log "$BIN_NAME has been removed."
  log "Optional cleanup (not removed automatically):"
  log "  rm -rf ~/.microclaw/runtime"
  log "  rm -f ./microclaw.config.yaml ./microclaw.config.yml"
}

main "$@"
