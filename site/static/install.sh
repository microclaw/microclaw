#!/usr/bin/env bash
set -euo pipefail

REPO="${MICROCLAW_REPO:-microclaw/microclaw}"
BIN_NAME="microclaw"
VARIANT="${MICROCLAW_VARIANT:-default}"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
SKIP_RUN="${MICROCLAW_INSTALL_SKIP_RUN:-0}"

log() {
  printf '%s\n' "$*"
}

err() {
  printf 'Error: %s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

print_help() {
  cat <<'EOF'
Usage: install.sh [--full] [--skip-run]

Options:
  --full       Install the full variant (includes Matrix channel + MCP support).
  --skip-run   Do not auto-run microclaw after install.

Environment variables:
  MICROCLAW_VARIANT   Set to "full" as an alternative to --full.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --full)
        VARIANT="full"
        ;;
      --skip-run)
        SKIP_RUN=1
        ;;
      -h|--help)
        print_help
        exit 0
        ;;
      *)
        err "Unknown argument: $1"
        print_help >&2
        exit 1
        ;;
    esac
    shift
  done
}

should_skip_run() {
  # Bash 3.2 (default on macOS) does not support `${var,,}`.
  local skip_run_normalized
  skip_run_normalized="$(printf '%s' "$SKIP_RUN" | tr '[:upper:]' '[:lower:]')"
  case "$skip_run_normalized" in
    1|true|yes)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *)
      err "Unsupported architecture: $(uname -m)"
      exit 1
      ;;
  esac
}

detect_install_dir() {
  if [ -n "${MICROCLAW_INSTALL_DIR:-}" ]; then
    echo "$MICROCLAW_INSTALL_DIR"
    return
  fi
  if [ -w "/usr/local/bin" ]; then
    echo "/usr/local/bin"
    return
  fi
  if [ -d "$HOME/.local/bin" ] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
    echo "$HOME/.local/bin"
    return
  fi
  echo "/usr/local/bin"
}

download_release_json() {
  if need_cmd curl; then
    curl -fsSL "$API_URL"
  elif need_cmd wget; then
    wget -qO- "$API_URL"
  else
    err "Neither curl nor wget is available"
    exit 1
  fi
}

extract_asset_url() {
  # Match assets like:
  #   microclaw-0.0.5-aarch64-apple-darwin.tar.gz
  #   microclaw-full-0.0.5-aarch64-apple-darwin.tar.gz
  local release_json="$1"
  local os="$2"
  local arch="$3"
  local variant="$4"
  local os_regex arch_regex asset_prefix

  if [ "$variant" = "full" ]; then
    asset_prefix="${BIN_NAME}-full"
  else
    asset_prefix="${BIN_NAME}"
  fi

  case "$os" in
    darwin) os_regex="apple-darwin|darwin" ;;
    linux) os_regex="linux-gnu|linux-musl|linux" ;;
    *)
      err "Unsupported OS for release matching: $os"
      return 1
      ;;
  esac

  case "$arch" in
    x86_64) arch_regex="x86_64|amd64" ;;
    aarch64) arch_regex="aarch64|arm64" ;;
    *)
      err "Unsupported architecture for release matching: $arch"
      return 1
      ;;
  esac

  printf '%s\n' "$release_json" \
    | grep -Eo 'https://[^"]+' \
    | grep '/releases/download/' \
    | grep -E "/${asset_prefix}-[0-9]+\.[0-9]+\.[0-9]+-.*(apple-darwin|linux-gnu|linux-musl|windows-msvc)\.(tar\.gz|zip)$" \
    | grep -Ei "(${arch_regex}).*(${os_regex})|(${os_regex}).*(${arch_regex})" \
    | head -n1
}

download_file() {
  local url="$1"
  local output="$2"
  if need_cmd curl; then
    curl -fL "$url" -o "$output"
  else
    wget -O "$output" "$url"
  fi
}

install_from_archive() {
  local archive="$1"
  local install_dir="$2"
  local tmpdir="$3"
  local extracted=0

  case "$archive" in
    *.tar.gz|*.tgz)
      tar -xzf "$archive" -C "$tmpdir"
      extracted=1
      ;;
    *.zip)
      if ! need_cmd unzip; then
        err "unzip is required to extract zip archives"
        return 1
      fi
      unzip -q "$archive" -d "$tmpdir"
      extracted=1
      ;;
  esac

  if [ "$extracted" -eq 0 ]; then
    # Fallback: detect by content if extension is missing/changed.
    if tar -tzf "$archive" >/dev/null 2>&1; then
      tar -xzf "$archive" -C "$tmpdir"
      extracted=1
    elif need_cmd unzip && unzip -tq "$archive" >/dev/null 2>&1; then
      unzip -q "$archive" -d "$tmpdir"
      extracted=1
    fi
  fi

  if [ "$extracted" -eq 0 ]; then
    err "Unknown archive format: $archive"
    return 1
  fi

  local bin_path
  # Full variant archives contain "microclaw-full" binary; fall back to "microclaw".
  bin_path="$(find "$tmpdir" -type f \( -name "${BIN_NAME}-full" -o -name "$BIN_NAME" \) | head -n1)"
  if [ -z "$bin_path" ]; then
    err "Could not find '$BIN_NAME' in archive"
    return 1
  fi

  chmod +x "$bin_path"
  local target_path tmp_target
  target_path="$install_dir/$BIN_NAME"
  tmp_target="$install_dir/.${BIN_NAME}.tmp.$$"
  if [ -w "$install_dir" ]; then
    cp "$bin_path" "$tmp_target"
    chmod +x "$tmp_target"
    mv -f "$tmp_target" "$target_path"
  else
    if need_cmd sudo; then
      sudo cp "$bin_path" "$tmp_target"
      sudo chmod +x "$tmp_target"
      sudo mv -f "$tmp_target" "$target_path"
    else
      err "No write permission for $install_dir and sudo not available"
      return 1
    fi
  fi
}

main() {
  local os arch install_dir release_json asset_url tmpdir archive asset_filename had_existing_bin

  parse_args "$@"

  os="$(detect_os)"
  arch="$(detect_arch)"
  install_dir="$(detect_install_dir)"
  had_existing_bin=0
  if need_cmd "${BIN_NAME}"; then
    had_existing_bin=1
  fi

  if [ "$VARIANT" = "full" ]; then
    log "Installing ${BIN_NAME} (full variant) for ${os}/${arch}..."
  else
    log "Installing ${BIN_NAME} for ${os}/${arch}..."
  fi
  release_json="$(download_release_json)"
  asset_url="$(extract_asset_url "$release_json" "$os" "$arch" "$VARIANT" || true)"
  if [ -z "$asset_url" ]; then
    err "No prebuilt binary found for ${os}/${arch} in the latest GitHub release."
    err "Use a separate install method instead:"
    err "  Homebrew (macOS): brew tap microclaw/tap && brew install microclaw"
    err "  Build from source: https://github.com/${REPO}"
    exit 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'if [ -n "${tmpdir:-}" ]; then rm -rf "$tmpdir"; fi' EXIT
  asset_filename="${asset_url##*/}"
  asset_filename="${asset_filename%%\?*}"
  if [ -z "$asset_filename" ] || [ "$asset_filename" = "$asset_url" ]; then
    asset_filename="${BIN_NAME}.archive"
  fi
  archive="$tmpdir/$asset_filename"
  log "Downloading: $asset_url"
  download_file "$asset_url" "$archive"
  install_from_archive "$archive" "$install_dir" "$tmpdir"

  log ""
  log "Installed ${BIN_NAME}."
  if [ "$install_dir" = "$HOME/.local/bin" ]; then
    log "Make sure '$HOME/.local/bin' is in PATH."
    log "Example: export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
  log "${BIN_NAME}"
  if should_skip_run; then
    log "Skipping auto-run (--skip-run)."
  elif [ "$had_existing_bin" -eq 1 ]; then
    log "Skipping auto-run (upgrade detected)."
  elif need_cmd "${BIN_NAME}"; then
    log "Running: ${BIN_NAME}"
    if ! "${BIN_NAME}"; then
      err "Auto-run failed. Try running: ${BIN_NAME}"
    fi
  else
    log "Could not find '${BIN_NAME}' in PATH."
    log "Add this directory to PATH: ${install_dir}"
    if [ "$install_dir" = "$HOME/.local/bin" ]; then
      log "Example: export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
    log "Then run: ${install_dir}/${BIN_NAME}"
  fi
}

main "$@"
