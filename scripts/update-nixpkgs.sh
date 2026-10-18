#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/update-nixpkgs.sh [options]

Default behavior (no options):
  - auto-detect version from Cargo.toml
  - clone <current-gh-user>/nixpkgs into /tmp with timestamp
  - if pkgs/by-name/mi/microclaw/package.nix is missing upstream ("init"
    case), seed it from nix/nixpkgs/package.nix in this repo
  - resolve src / cargo / npm hashes from nix-build output
  - build/verify
  - commit, push, and open or update the PR to NixOS/nixpkgs

Reusing an existing PR branch (what nixpkgs reviewers ask for):
  scripts/update-nixpkgs.sh --branch microclaw-init --base master --ready
  The branch is rebuilt on top of upstream/<base>, the maintainer-list entry
  from the old branch is carried over, the push is a --force-with-lease, and
  the open PR for that branch gets its title and body updated instead of a
  new PR.

Automation/AI policy (nixpkgs CONTRIBUTING.md#automationai-policy):
  Pass --assisted-by "<tool>:<model>" once per LLM tool/model that helped
  prepare the change; each becomes an "Assisted-by:" commit trailer and is
  listed in the PR's "AI disclosure" section. When it is omitted, Assisted-by
  trailers on the old branch's tip commit are carried over.
  An existing PR description is kept (only the version in release links and
  "init at" is bumped, and a missing AI disclosure section is added); a body
  that does not follow the nixpkgs PR template is rebuilt from it.

Options:
  --version <x.y.z>         Target microclaw version (default: from Cargo.toml)
  --microclaw-dir <path>    MicroClaw repo root (default: current repo root)
  --nixpkgs-dir <path>      Use an existing nixpkgs checkout instead of temp clone
  --fork-owner <owner>      GitHub owner of nixpkgs fork (default: current gh user)
  --branch <name>           Nixpkgs branch name (default: microclaw-<version>-<timestamp>)
  --base <branch>           Upstream base branch (default: master)
  --template <path>         package.nix used when the package is missing upstream
                            (default: <microclaw-dir>/nix/nixpkgs/package.nix)
  --draft                   Open PR as draft
  --ready                   Mark an existing draft PR as ready for review
  --assisted-by <tool:model>
                            Add an "Assisted-by: <tool>:<model>" commit trailer
                            and PR disclosure entry (repeatable)
  --no-push                 Do not push (the PR body is still rendered to
                            <nixpkgs-dir>/.git/microclaw-pr-body.md)
  --no-pr                   Do not open/update PR
  -h, --help                Show help

Example (what a release runs):
  scripts/update-nixpkgs.sh --branch microclaw-init --base master --ready \
    --assisted-by "Claude Code:claude-opus-5-5"
USAGE
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

set_version_fields() {
  local package_file="$1"
  local version="$2"
  perl -0777 -i -pe 's/version = "[^"]+";/version = "'"$version"'";/' "$package_file"
}

reset_hashes_to_placeholders() {
  # Distinct placeholders per field so a "specified: X / got: Y" pair in the
  # build log identifies which field it belongs to.
  local package_file="$1"
  perl -0777 -i -pe '
    s/(fetchFromGitHub \{.*?\bhash = )(?:lib\.fakeHash|"sha256-[^"]+");/$1"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";/s;
    s/(\bcargoHash = )(?:lib\.fakeHash|"sha256-[^"]+");/$1"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";/;
    s/(fetchNpmDeps \{.*?\bhash = )(?:lib\.fakeHash|"sha256-[^"]+");/$1"sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";/s;
  ' "$package_file"
}

run_nix_build() {
  local log_file="$1"
  set +e
  nix-build -A microclaw --keep-going >"$log_file" 2>&1
  local status=$?
  set -e
  return "$status"
}

# Replace every "specified: <hash>" that appears in the package file with the
# matching "got: <hash>" from the build log. Returns 1 when nothing changed.
apply_hash_fixes_from_log() {
  local log_file="$1"
  local package_file="$2"
  local changed=1
  local specified got
  while read -r specified got; do
    [ -n "$specified" ] && [ -n "$got" ] || continue
    if grep -qF "\"$specified\"" "$package_file"; then
      echo "Resolved hash: $specified -> $got"
      SPEC="$specified" GOT="$got" perl -i -pe 's{\Q$ENV{SPEC}\E}{$ENV{GOT}}g' "$package_file"
      changed=0
    fi
  done < <(
    grep -Eo '(specified|got):[[:space:]]+sha256-[A-Za-z0-9+/=]+' "$log_file" \
      | awk '
          /^specified:/ { spec = $2; next }
          /^got:/ && spec != "" { print spec, $2; spec = "" }
        '
  )
  return "$changed"
}

# Version in a PR title such as "microclaw: init at 1.2.3" or "microclaw: 1.2.2 -> 1.2.3".
version_from_title() {
  printf '%s\n' "$1" | sed -nE 's/.*(init at|->)[[:space:]]+([^[:space:]]+)[[:space:]]*$/\2/p'
}

write_ai_disclosure() {
  local entry
  echo "## AI disclosure"
  echo
  echo "Per the [automation/AI policy], these LLM-based tools were used to prepare this change:"
  echo
  for entry in "${ASSISTED_BY[@]}"; do
    echo "- \`${entry}\`"
  done
  echo
  echo "\`scripts/update-nixpkgs.sh\` from the MicroClaw repository sets the version, resolves the three hashes and builds the package. The commit carries matching \`Assisted-by:\` trailers. I reviewed the resulting \`package.nix\` and the build results below and can answer questions about any part of it."
}

# PR body from the nixpkgs PR template: summary, AI disclosure, then the
# template's "Things done" checklist with what this script verified ticked.
write_template_body() {
  local template
  if $INIT_MODE; then
    echo "Adds [MicroClaw](https://github.com/microclaw/microclaw), a self-hosted Rust chat agent that runs on Telegram, Discord, Slack, Feishu/Lark, Matrix and its own built-in web UI. It supports tool execution, scheduled tasks and persistent memory."
  else
    echo "Updates [MicroClaw](https://github.com/microclaw/microclaw) from ${OLD_VERSION} to ${VERSION}."
  fi
  echo
  echo "- Release: https://github.com/microclaw/microclaw/releases/tag/v${VERSION}"
  echo
  if [ "${#ASSISTED_BY[@]}" -gt 0 ]; then
    write_ai_disclosure
    echo
  fi
  if template="$(git show "upstream/${BASE_BRANCH}:.github/PULL_REQUEST_TEMPLATE.md" 2>/dev/null)"; then
    printf '%s\n' "$template" \
      | sed -n '/^## Things done/,$p' \
      | SYSTEM="$CURRENT_SYSTEM" perl -pe '
          s/^(\s*- )\[ \]( \Q$ENV{SYSTEM}\E)$/$1\[x\]$2/ if length $ENV{SYSTEM};
          s/^(\s*- )\[ \]( Basic functionality of all binary files)/$1\[x\]$2/;
        '
  else
    echo "WARNING: .github/PULL_REQUEST_TEMPLATE.md not found on upstream/${BASE_BRANCH}; PR body has no checklist." >&2
    echo "[automation/AI policy]: https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md#automationai-policy"
  fi
}

# Bring an existing PR description up to date without rewriting it.
update_existing_body() {
  local body_file="$1"
  local prev_version="$2"
  if ! grep -q '^## Things done' "$body_file"; then
    echo "Existing PR body does not follow the nixpkgs PR template; rebuilding it from the template."
    write_template_body >"$body_file"
    return
  fi
  if [ -n "$prev_version" ] && [ "$prev_version" != "$VERSION" ]; then
    PREV="$prev_version" NEW="$VERSION" perl -0777 -i -pe '
      s{(releases/tag/v)\Q$ENV{PREV}\E(?!\.?[0-9A-Za-z])}{$1$ENV{NEW}}g;
      s{(init at )\Q$ENV{PREV}\E(?!\.?[0-9A-Za-z])}{$1$ENV{NEW}}g;
    ' "$body_file"
  elif [ -z "$prev_version" ]; then
    echo "WARNING: could not read the old version from the PR title; check version references in the PR body." >&2
  fi
  if [ "${#ASSISTED_BY[@]}" -gt 0 ] && ! grep -qi '^## AI disclosure' "$body_file"; then
    local disclosure
    disclosure="$(mktemp)"
    write_ai_disclosure >"$disclosure"
    DISCLOSURE="$disclosure" perl -0777 -i -pe '
      BEGIN { local $/; open my $fh, "<", $ENV{DISCLOSURE} or die; $d = <$fh>; }
      s/^(?=## Things done)/$d\n/m;
    ' "$body_file"
    rm -f "$disclosure"
    echo "Added an AI disclosure section to the PR body."
  fi
}

TIMESTAMP="$(date +%Y%m%d%H%M%S)"
MICROCLAW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=""
BASE_BRANCH="master"
FORK_OWNER=""
NIXPKGS_DIR=""
BRANCH=""
TEMPLATE=""
DO_PUSH=true
DO_PR=true
DO_DRAFT=false
DO_READY=false
ASSISTED_BY=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --microclaw-dir) MICROCLAW_DIR="$2"; shift 2 ;;
    --nixpkgs-dir) NIXPKGS_DIR="$2"; shift 2 ;;
    --fork-owner) FORK_OWNER="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --base) BASE_BRANCH="$2"; shift 2 ;;
    --template) TEMPLATE="$2"; shift 2 ;;
    --draft) DO_DRAFT=true; shift ;;
    --ready) DO_READY=true; shift ;;
    --assisted-by)
      if [ "$#" -lt 2 ] || ! [[ "$2" =~ ^[^:]+:[^:]+$ ]]; then
        echo "--assisted-by expects \"<tool>:<model>\", e.g. \"Claude Code:claude-opus-5-5\"" >&2
        exit 1
      fi
      ASSISTED_BY+=("$2"); shift 2 ;;
    --no-push) DO_PUSH=false; shift ;;
    --no-pr) DO_PR=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd git
require_cmd perl
require_cmd nix-build
require_cmd gh

if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated. Run: gh auth login" >&2
  exit 1
fi

if [ -z "$VERSION" ]; then
  VERSION="$(grep '^version = "' "$MICROCLAW_DIR/Cargo.toml" | head -n1 | sed -E 's/version = "([^"]+)"/\1/')"
fi
if [ -z "$VERSION" ]; then
  echo "Failed to detect version from Cargo.toml. Pass --version explicitly." >&2
  exit 1
fi

if [ -z "$TEMPLATE" ]; then
  TEMPLATE="$MICROCLAW_DIR/nix/nixpkgs/package.nix"
fi

if [ -z "$FORK_OWNER" ]; then
  FORK_OWNER="$(gh api user --jq .login)"
fi

if [ -z "$NIXPKGS_DIR" ]; then
  NIXPKGS_DIR="/tmp/nixpkgs-${TIMESTAMP}"
  echo "Using temp nixpkgs dir: $NIXPKGS_DIR"
  if ! gh repo view "${FORK_OWNER}/nixpkgs" >/dev/null 2>&1; then
    echo "Fork ${FORK_OWNER}/nixpkgs not found, creating fork..."
    gh repo fork NixOS/nixpkgs --remote=false
  fi
  gh repo clone "${FORK_OWNER}/nixpkgs" "$NIXPKGS_DIR" -- --filter=blob:none
fi

if [ -z "$BRANCH" ]; then
  BRANCH="microclaw-${VERSION}-${TIMESTAMP}"
fi

cd "$NIXPKGS_DIR"
if ! git remote get-url upstream >/dev/null 2>&1; then
  git remote add upstream https://github.com/NixOS/nixpkgs.git
fi

git fetch upstream "$BASE_BRANCH"

# Does the branch already exist on the fork (an open PR we are updating)?
BRANCH_EXISTS_ON_FORK=false
if git fetch origin "$BRANCH" >/dev/null 2>&1; then
  BRANCH_EXISTS_ON_FORK=true
  git branch -f "refs/heads/__microclaw_old_${BRANCH}" FETCH_HEAD
  echo "Branch ${BRANCH} exists on ${FORK_OWNER}/nixpkgs; it will be rebuilt on upstream/${BASE_BRANCH}"
fi

git checkout -B "$BRANCH" "upstream/$BASE_BRANCH"

PACKAGE_DIR="$NIXPKGS_DIR/pkgs/by-name/mi/microclaw"
PACKAGE_FILE="$PACKAGE_DIR/package.nix"
MAINTAINER_LIST="$NIXPKGS_DIR/maintainers/maintainer-list.nix"
INIT_MODE=false
OLD_VERSION=""

if [ -f "$PACKAGE_FILE" ]; then
  OLD_VERSION="$(grep 'version = "' "$PACKAGE_FILE" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
  echo "Updating microclaw package: ${OLD_VERSION} -> ${VERSION}"
else
  INIT_MODE=true
  if [ ! -f "$TEMPLATE" ]; then
    echo "Package not in upstream ${BASE_BRANCH} and template not found: $TEMPLATE" >&2
    exit 1
  fi
  echo "microclaw is not packaged in upstream/${BASE_BRANCH}; seeding from template: $TEMPLATE"
  mkdir -p "$PACKAGE_DIR"
  cp "$TEMPLATE" "$PACKAGE_FILE"
  # Drop the template banner; nixpkgs files start at the argument set.
  perl -0777 -i -pe 's/\A(#[^\n]*\n)+//' "$PACKAGE_FILE"
fi

# Carry over the maintainer-list entry from the previous PR branch, if any.
if $BRANCH_EXISTS_ON_FORK; then
  OLD_REF="refs/heads/__microclaw_old_${BRANCH}"
  MERGE_BASE="$(git merge-base "upstream/$BASE_BRANCH" "$OLD_REF" || true)"
  if [ -n "$MERGE_BASE" ] && ! git diff --quiet "$MERGE_BASE" "$OLD_REF" -- maintainers/maintainer-list.nix; then
    if git diff "$MERGE_BASE" "$OLD_REF" -- maintainers/maintainer-list.nix | git apply -3 --index; then
      echo "Carried over maintainers/maintainer-list.nix changes from previous ${BRANCH}"
    else
      git checkout -- maintainers/maintainer-list.nix || true
      echo "WARNING: could not re-apply the maintainer-list entry from the old branch; re-add it by hand." >&2
    fi
  fi
fi

if [ "${#ASSISTED_BY[@]}" -eq 0 ] && $BRANCH_EXISTS_ON_FORK; then
  while IFS= read -r trailer; do
    [ -n "$trailer" ] && ASSISTED_BY+=("$trailer")
  done < <(git log -1 --format='%(trailers:key=Assisted-by,valueonly,unfold)' "refs/heads/__microclaw_old_${BRANCH}")
  if [ "${#ASSISTED_BY[@]}" -gt 0 ]; then
    echo "No --assisted-by given; carrying over Assisted-by trailers from the old ${BRANCH}: ${ASSISTED_BY[*]}"
  fi
fi
if [ "${#ASSISTED_BY[@]}" -eq 0 ]; then
  echo "WARNING: no --assisted-by given. The nixpkgs automation/AI policy requires an Assisted-by: trailer for LLM-assisted commits." >&2
fi

if $INIT_MODE && ! grep -q "^  ${FORK_OWNER} = {" "$MAINTAINER_LIST"; then
  echo "WARNING: no maintainer entry for '${FORK_OWNER}' in maintainers/maintainer-list.nix; nixpkgs requires one for meta.maintainers." >&2
fi

set_version_fields "$PACKAGE_FILE" "$VERSION"
reset_hashes_to_placeholders "$PACKAGE_FILE"

BUILD_LOG="$(mktemp)"
PR_BODY="$(mktemp)"
COMMIT_MSG="$(mktemp)"
trap 'rm -f "$BUILD_LOG" "$PR_BODY" "$COMMIT_MSG"' EXIT

# src, cargoHash and npmDeps.hash are all fixed-output derivations; each failed
# build reports one or more "specified/got" pairs. Iterate until it builds.
MAX_ROUNDS=6
round=0
while :; do
  round=$((round + 1))
  if run_nix_build "$BUILD_LOG"; then
    break
  fi
  if [ "$round" -ge "$MAX_ROUNDS" ]; then
    echo "nix-build still failing after ${MAX_ROUNDS} rounds." >&2
    tail -n 200 "$BUILD_LOG" >&2
    exit 1
  fi
  if ! apply_hash_fixes_from_log "$BUILD_LOG" "$PACKAGE_FILE"; then
    echo "nix-build failed for a reason other than a hash mismatch." >&2
    tail -n 200 "$BUILD_LOG" >&2
    exit 1
  fi
done

BUILD_PATH="$(tail -n1 "$BUILD_LOG" | tr -d '\r')"
if [ -x "$BUILD_PATH/bin/microclaw" ]; then
  "$BUILD_PATH/bin/microclaw" --help >/dev/null
else
  echo "Build finished but $BUILD_PATH/bin/microclaw is missing." >&2
  exit 1
fi

if command -v nixfmt >/dev/null 2>&1; then
  nixfmt "$PACKAGE_FILE"
fi

git add "$PACKAGE_FILE"
if git diff --cached --quiet; then
  echo "No changes detected after update."
  echo "nixpkgs dir: $NIXPKGS_DIR"
  exit 0
fi

if $INIT_MODE; then
  COMMIT_TITLE="microclaw: init at ${VERSION}"
else
  COMMIT_TITLE="microclaw: ${OLD_VERSION} -> ${VERSION}"
fi
TRAILER_ARGS=()
for entry in ${ASSISTED_BY[@]+"${ASSISTED_BY[@]}"}; do
  TRAILER_ARGS+=(--trailer "Assisted-by: ${entry}")
done
printf '%s\n\nRelease: https://github.com/microclaw/microclaw/releases/tag/v%s\n' "$COMMIT_TITLE" "$VERSION" \
  | git interpret-trailers --if-exists addIfDifferent ${TRAILER_ARGS[@]+"${TRAILER_ARGS[@]}"} >"$COMMIT_MSG"
git commit --cleanup=strip -F "$COMMIT_MSG"
echo "Committed on branch: $BRANCH"

if $DO_PUSH; then
  if $BRANCH_EXISTS_ON_FORK; then
    git push --force-with-lease -u origin "$BRANCH"
  else
    git push -u origin "$BRANCH"
  fi
  echo "Pushed: origin/$BRANCH"
else
  echo "Skip push due to --no-push"
fi

if $DO_PR; then
  CURRENT_SYSTEM="$(nix-instantiate --eval --expr builtins.currentSystem 2>/dev/null | tr -d '"' || true)"

  # `gh pr list --head` matches the branch name only; filter on the fork owner.
  EXISTING_PR="$(gh pr list --repo NixOS/nixpkgs --head "$BRANCH" --state open \
    --json number,headRepositoryOwner \
    --jq "map(select(.headRepositoryOwner.login == \"${FORK_OWNER}\")) | .[0].number // empty" 2>/dev/null || true)"

  if [ -n "$EXISTING_PR" ]; then
    gh pr view "$EXISTING_PR" --repo NixOS/nixpkgs --json body --jq .body >"$PR_BODY"
    OLD_TITLE="$(gh pr view "$EXISTING_PR" --repo NixOS/nixpkgs --json title --jq .title)"
    update_existing_body "$PR_BODY" "$(version_from_title "$OLD_TITLE")"
  else
    write_template_body >"$PR_BODY"
  fi

  if ! $DO_PUSH; then
    cp "$PR_BODY" "$NIXPKGS_DIR/.git/microclaw-pr-body.md"
    echo "Skip PR due to --no-push; PR body (title: ${COMMIT_TITLE}) rendered to $NIXPKGS_DIR/.git/microclaw-pr-body.md"
  elif [ -n "$EXISTING_PR" ]; then
    echo "Updating existing PR NixOS/nixpkgs#${EXISTING_PR}"
    gh pr edit "$EXISTING_PR" --repo NixOS/nixpkgs --title "$COMMIT_TITLE" --body-file "$PR_BODY"
    if $DO_READY; then
      gh pr ready "$EXISTING_PR" --repo NixOS/nixpkgs
    fi
  else
    PR_ARGS=(
      --repo NixOS/nixpkgs
      --base "$BASE_BRANCH"
      --head "${FORK_OWNER}:${BRANCH}"
      --title "$COMMIT_TITLE"
      --body-file "$PR_BODY"
    )
    if $DO_DRAFT; then
      PR_ARGS+=(--draft)
    fi
    gh pr create "${PR_ARGS[@]}"
    echo "Review the PR checklist (e.g. \"Follows the automation/AI policy\") before marking it ready."
  fi
else
  echo "Skip PR due to --no-pr"
fi

echo "Done. nixpkgs dir: $NIXPKGS_DIR"
