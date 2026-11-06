#!/usr/bin/env bash
# Install MicroClaw Code (mccode) from the latest GitHub release.
#
#   curl -fsSL https://microclaw.org/install-mccode.sh | bash
#
# The archive is verified against the release's SHA256SUMS.txt before the
# binary is installed.
set -euo pipefail

REPO="${MCCODE_REPO:-microclaw/microclaw}"
BIN_NAME="mccode"
API_URL="${MCCODE_RELEASE_API_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
VERSION="${MCCODE_VERSION:-}"

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
Usage: install-mccode.sh [--version <x.y.z>] [--dir <path>]

Installs MicroClaw Code (mccode) from a GitHub release.

Options:
  --version <x.y.z>  Install this release instead of the latest one.
  --dir <path>       Install into this directory.

Environment variables:
  MCCODE_VERSION       Same as --version.
  MCCODE_INSTALL_DIR   Same as --dir (default: /usr/local/bin when writable,
                       otherwise ~/.local/bin).
EOF
}

INSTALL_DIR="${MCCODE_INSTALL_DIR:-}"
WORK_DIR=""

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version)
        VERSION="${2:-}"
        shift
        ;;
      --dir)
        INSTALL_DIR="${2:-}"
        shift
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

detect_target() {
  local os arch
  case "$(uname -s)" in
    Darwin) os="apple-darwin" ;;
    Linux) os="linux-gnu" ;;
    *)
      err "Unsupported OS: $(uname -s). On Windows use install-mccode.ps1."
      exit 1
      ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *)
      err "Unsupported architecture: $(uname -m)"
      exit 1
      ;;
  esac
  if [ "$os" = "linux-gnu" ] && [ "$arch" = "aarch64" ]; then
    echo "aarch64-linux-gnu"
  elif [ "$os" = "linux-gnu" ]; then
    echo "x86_64-linux-gnu"
  else
    echo "${arch}-${os}"
  fi
}

detect_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR" 2>/dev/null || true
    echo "$INSTALL_DIR"
    return
  fi
  if [ -w "/usr/local/bin" ]; then
    echo "/usr/local/bin"
    return
  fi
  mkdir -p "$HOME/.local/bin" 2>/dev/null || true
  echo "$HOME/.local/bin"
}

fetch() {
  # fetch <url> [output]
  if need_cmd curl; then
    if [ "$#" -eq 2 ]; then curl -fsSL "$1" -o "$2"; else curl -fsSL "$1"; fi
  elif need_cmd wget; then
    if [ "$#" -eq 2 ]; then wget -qO "$2" "$1"; else wget -qO- "$1"; fi
  else
    err "Neither curl nor wget is available"
    exit 1
  fi
}

sha256_of() {
  if need_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif need_cmd shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    err "sha256sum or shasum is required to verify the download"
    exit 1
  fi
}

build_from_source_hint() {
  err "Build it from source instead (needs the Rust toolchain):"
  err "  cargo install --git https://github.com/${REPO} microclaw-code"
}

main() {
  parse_args "$@"
  local target install_dir tag version asset base tmpdir archive expected actual bin_path

  target="$(detect_target)"
  install_dir="$(detect_install_dir)"

  if [ -n "$VERSION" ]; then
    version="${VERSION#v}"
    tag="v${version}"
  else
    tag="$(fetch "$API_URL" | grep -Eo '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')"
    if [ -z "$tag" ]; then
      err "Could not find the latest release of ${REPO}."
      exit 1
    fi
    version="${tag#v}"
  fi

  asset="${BIN_NAME}-${version}-${target}.tar.gz"
  base="${MCCODE_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}/${tag}"
  tmpdir="$(mktemp -d)"
  WORK_DIR="$tmpdir"
  trap 'if [ -n "$WORK_DIR" ]; then rm -rf "$WORK_DIR"; fi' EXIT

  log "Installing ${BIN_NAME} ${version} for ${target}..."
  if ! fetch "${base}/SHA256SUMS.txt" "$tmpdir/SHA256SUMS.txt"; then
    err "Could not download SHA256SUMS.txt for ${tag}."
    build_from_source_hint
    exit 1
  fi
  expected="$(awk -v name="$asset" '{ file=$2; sub(/^\*/, "", file); if (file == name) print $1 }' "$tmpdir/SHA256SUMS.txt" | head -n1)"
  if [ -z "$expected" ]; then
    err "Release ${tag} has no ${asset}."
    build_from_source_hint
    exit 1
  fi

  archive="$tmpdir/$asset"
  log "Downloading ${base}/${asset}"
  fetch "${base}/${asset}" "$archive"
  actual="$(sha256_of "$archive")"
  if [ "$actual" != "$expected" ]; then
    err "Checksum mismatch for ${asset} (expected ${expected}, got ${actual}); not installing."
    exit 1
  fi
  log "Checksum verified."

  tar -xzf "$archive" -C "$tmpdir"
  bin_path="$(find "$tmpdir" -type f -name "$BIN_NAME" | head -n1)"
  if [ -z "$bin_path" ]; then
    err "${asset} does not contain ${BIN_NAME}"
    exit 1
  fi
  chmod +x "$bin_path"

  local target_path="$install_dir/$BIN_NAME"
  local staged="$install_dir/.${BIN_NAME}.tmp.$$"
  if [ -w "$install_dir" ]; then
    cp "$bin_path" "$staged" && mv -f "$staged" "$target_path"
  elif need_cmd sudo; then
    sudo cp "$bin_path" "$staged" && sudo mv -f "$staged" "$target_path"
  else
    err "No write permission for ${install_dir} and sudo is not available (use --dir)"
    exit 1
  fi

  log ""
  log "Installed ${BIN_NAME} ${version} to ${target_path}."
  case ":$PATH:" in
    *":$install_dir:"*) ;;
    *)
      log "Add ${install_dir} to PATH, for example:"
      log "  export PATH=\"${install_dir}:\$PATH\""
      ;;
  esac
  log ""
  log "Next steps:"
  log "  mccode setup        # choose a model provider and key"
  log "  cd your/repo && mccode"
  log "Update later with: mccode update"
}

main "$@"
