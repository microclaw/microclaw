---
id: installation
title: Installation
sidebar_position: 3
---

## System requirements

- Rust 1.70+ (2021 edition) — only required for building from source; the installer ships prebuilt binaries
- macOS, Linux, or Windows
- Internet access for chat + your selected LLM provider API
- **Minimum hardware: 1 vCPU / 1 GB RAM** — microclaw is a single Rust binary with embedded SQLite, so it runs comfortably on a $5/month VPS (DigitalOcean, Hetzner, Vultr, etc.). No Python interpreter, no separate vector DB, no service mesh.

### Linux: glibc and OpenSSL

The prebuilt Linux binaries are dynamically linked against **glibc 2.39** (the `ubuntu-latest` build toolchain) and **OpenSSL 3** (`libssl.so.3`). They run only on a distribution whose system glibc is **2.39 or newer**. On an older system you will see errors such as:

```
microclaw: error while loading shared libraries: libssl.so.3: cannot open shared object file
microclaw: /lib64/libc.so.6: version `GLIBC_2.39' not found (required by microclaw)
```

| Distribution                 | glibc       | Status      |
| ---------------------------- | ----------- | ----------- |
| Ubuntu 24.04 LTS+            | 2.39        | ✅ works      |
| Debian 13 (trixie)+         | 2.41        | ✅ works      |
| AlmaLinux / Rocky / RHEL 10+ | 2.39        | ✅ works      |
| Fedora 40+                  | 2.39        | ✅ works      |
| Debian 12 (bookworm)        | 2.36        | ❌ too old    |
| AlmaLinux / RHEL 8–9        | 2.28–2.34   | ❌ too old    |
| Ubuntu 22.04 / 20.04        | 2.35 / 2.31 | ❌ too old    |

Check your version with `ldd --version`. If you only hit the `libssl.so.3` error (glibc is new enough), just install the OpenSSL 3 runtime — `dnf install openssl3-libs` on RHEL-family, `apt install libssl3` on Debian/Ubuntu.

If glibc is too old, either run on a supported release (Ubuntu 24.04 / AlmaLinux 10), use a newer container base image, or [build from source](#build-from-source). A static build via the `x86_64-unknown-linux-musl` target removes both the glibc and OpenSSL system dependencies.

## One-line installer (recommended)

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

For the full variant (adds Matrix channel support):

```sh
curl -fsSL https://microclaw.org/install.sh | bash -s -- --full
```

The installer only installs prebuilt GitHub release binaries.
It does not fall back to Homebrew or Cargo automatically.


## Windows (PowerShell)

Install using PowerShell:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

For the full variant (adds Matrix channel):

```powershell
& ([scriptblock]::Create((iwr https://microclaw.org/install.ps1 -UseBasicParsing).Content)) -Full
```

What this script does:

- Downloads the latest matching Windows release (`microclaw.exe`)
- Installs into `%USERPROFILE%\.local\bin` by default
- Adds install dir to your **user PATH** if missing

Optional browser automation dependency (for `browser` tool):

```powershell
npm install -g agent-browser
agent-browser install
```

On Windows, MicroClaw will invoke `agent-browser.cmd` when available.

### Preflight diagnostics (all platforms)

Run diagnostics before first start, and include output in support tickets:

```sh
microclaw doctor
```

JSON output (for issue templates / copy-paste):

```sh
microclaw doctor --json
```

Unified check output format across macOS/Linux/Windows:

```text
[✅ PASS] <title> (<check_id>) <detail>
[⚠️ WARN] <title> (<check_id>) <detail>
[❌ FAIL] <title> (<check_id>) <detail>
Summary: pass=<n> warn=<n> fail=<n>
```

`doctor` checks:

- PATH/install dir visibility
- Shell runtime (`bash/sh` or `pwsh/powershell`)
- Node.js + npm + `agent-browser`
- PowerShell execution policy (Windows)
- MCP dependency commands from `~/.microclaw/mcp.json` and `~/.microclaw/mcp.d/*.json` (or your configured `data_dir`)

### PowerShell execution policy notes

If your environment blocks script execution, run PowerShell as your user and temporarily allow signed/local scripts:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

If your organization enforces policy via Group Policy, use local source build instead of remote script execution.

### Common Windows issues (native non-WSL flow)

Use this triage path when running in native Windows terminals (PowerShell / CMD, not WSL):

1. Confirm environment and run diagnostics:
   - `microclaw doctor`
   - If this fails, run with full path: `%USERPROFILE%\.local\bin\microclaw.exe doctor`
2. If `path.install_dir` is `WARN`:
   - add `%USERPROFILE%\.local\bin` to user PATH
   - restart terminal
3. If `powershell.policy` is `FAIL` (`Restricted`):
   - `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
4. If `deps.node` / `deps.npm` / `deps.agent_browser` is `WARN`:
   - install Node.js LTS
   - run `npm install -g agent-browser` and `agent-browser install`
5. If any `mcp.<name>.command` is `FAIL`:
   - install that command (or use absolute path in `~/.microclaw/mcp.json` or a file under `~/.microclaw/mcp.d/*.json`)
6. Re-run `microclaw doctor` until `fail=0`, then start:
   - `microclaw start`

Quick symptom map:

- `microclaw` command not found: PATH problem (`path.install_dir`)
- `browser` spawn failure: missing `agent-browser.cmd`
- script blocked by policy: `powershell.policy` failure
- MCP tool unavailable: `mcp.*` dependency failure

## Homebrew (macOS)

```sh
brew tap microclaw/tap
brew install microclaw
```

For the full variant (adds Matrix channel support):

```sh
brew install microclaw-full
```

## Docker image

Release tags publish an official container image to:

- `ghcr.io/microclaw/microclaw:latest`
- `ghcr.io/microclaw/microclaw:<version>`
- `docker.io/microclaw/microclaw:latest` when Docker Hub publishing credentials are configured for the repository

For first-time pulls from GHCR, you may need:

```sh
docker login ghcr.io
```

Use your GitHub username and a Personal Access Token with `read:packages`.

Quickest way to try it:

```sh
docker pull ghcr.io/microclaw/microclaw:latest
docker run --rm -it \
  -p 127.0.0.1:10961:10961 \
  ghcr.io/microclaw/microclaw:latest
```

Recommended for day-to-day use: mount config and persistent data from the host:

```sh
mkdir -p data tmp
chmod a+r microclaw.config.yaml
chmod -R a+rwX data tmp

docker run --rm -it \
  -p 127.0.0.1:10961:10961 \
  -v "$(pwd)/microclaw.config.yaml:/app/microclaw.config.yaml:ro" \
  -v "$(pwd)/data:/home/microclaw/.microclaw" \
  -v "$(pwd)/tmp:/app/tmp" \
  ghcr.io/microclaw/microclaw:latest
```

Why mount them:

- `microclaw.config.yaml`: keep configuration outside the container
- `data/`: persist sessions, memory, skills, database, and runtime state
- `tmp/`: provide a writable temp directory for container-side work

The image entrypoint is `microclaw`, so operational commands can be passed directly:

```sh
docker run --rm ghcr.io/microclaw/microclaw:latest doctor
docker run --rm ghcr.io/microclaw/microclaw:latest version
```

If startup fails with `Permission denied (os error 13)`, re-check the `chmod` commands above and confirm the mounted paths exist.

## Build from source

```sh
git clone https://github.com/microclaw/microclaw.git
cd microclaw
cargo build --release
```

Copy the binary somewhere on your PATH:

```sh
cp target/release/microclaw /usr/local/bin/
```

The default build includes all channels except Matrix (MCP is included by default). To add Matrix support:

```sh
cargo build --release --features full
```

`full` enables `channel-matrix`. See [Configuration](./configuration) for feature details.

## Run from source (dev)

Runtime boot behavior:
- starts scheduler
- starts configured adapters (Telegram/Discord/Slack/Feishu/IRC/Web)
- can run without Telegram when other channels are enabled

```sh
cargo run -- start
```

## Setup configuration

Recommended:

```sh
microclaw setup
```

Or manually create `microclaw.config.yaml`:

```
llm_provider: "anthropic"
api_key: "..."
model: "claude-sonnet-4-5-20250929"
data_dir: "~/.microclaw"
working_dir: "~/.microclaw/working_dir"
max_document_size_mb: 100

# Enable at least one channel:
channels:
  telegram:
    default_account: "main"
    accounts:
      main:
        bot_token: "..."
        bot_username: "..."
# Optional reusable provider profiles:
# provider_presets:
#   ops-openrouter:
#     provider: "openrouter"
#     api_key: "sk-or-..."
#     default_model: "openai/gpt-4o-mini"
# Optional additional channels:
# channels:
#   discord:
#     accounts:
#       main: { bot_token: "..." }
#   slack:
#     accounts:
#       main: { bot_token: "...", app_token: "..." }
#   feishu:
#     accounts:
#       main: { app_id: "...", app_secret: "..." }
#   irc:
#     server: "irc.example.com"
#     nick: "microclaw"
#     channels: "#general"
web_enabled: true
```

Use `microclaw help` (or `cargo run -- help`) for CLI usage.

For full Telegram / Discord / Slack / Feishu / Weixin / IRC onboarding (token provisioning, connection setup, verification), see [Channel Setup](./channel-setup).

The interactive setup wizard supports provider/model selection (including `ollama`) and uses sensible defaults with Enter-to-confirm prompts.

## Gateway persistent service

MicroClaw supports a persistent gateway service manager:

```sh
microclaw gateway install
microclaw gateway install --force
microclaw gateway status
microclaw gateway status --json --deep
microclaw gateway start
microclaw gateway stop
microclaw gateway restart
microclaw gateway logs 200
microclaw gateway uninstall
```

Platform behavior:
- macOS: `launchd` user agent
- Linux: `systemd --user` unit
- Logs: gateway service stdout/stderr in `~/.microclaw/runtime/logs/` as `microclaw-gateway.log` and `microclaw-gateway.error.log`
- Retention: files older than 30 days are auto-deleted

## Optional: browser automation

To enable the `browser` tool (headless browser automation), install [agent-browser](https://github.com/vercel-labs/agent-browser):

```sh
npm install -g agent-browser
agent-browser install
```

This lets MicroClaw interact with JavaScript-rendered pages, fill forms, click buttons, and navigate multi-step web flows. If `agent-browser` is not installed, the `browser` tool will return an error when called — all other tools work normally.

## Uninstall

Installer-script uninstall (recommended):

macOS/Linux:

```sh
curl -fsSL https://microclaw.org/uninstall.sh | bash
```

Windows PowerShell:

```powershell
iwr https://microclaw.org/uninstall.ps1 -UseBasicParsing | iex
```

Windows PATH cleanup (optional):

```powershell
iwr https://microclaw.org/uninstall.ps1 -UseBasicParsing | iex -CleanPath
```

If installed via Homebrew:

```sh
brew uninstall microclaw
brew untap microclaw/tap
```

Optional cleanup (remove local runtime data):

```sh
rm -rf ~/.microclaw/runtime
rm -rf ~/.microclaw
```
