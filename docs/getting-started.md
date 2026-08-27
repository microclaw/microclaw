# Getting Started

This guide covers installation, first-time configuration, startup, and the most common deployment choices. For a project overview, return to [README.md](../README.md).

> [!IMPORTANT]
> Use the [`stable`](https://github.com/microclaw/microclaw/tree/stable) branch for production. The `main` branch moves quickly.

## 1. Install

### macOS or Linux installer

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

Install the full build, which adds Matrix support:

```sh
curl -fsSL https://microclaw.org/install.sh | bash -s -- --full
```

The script downloads the matching prebuilt release asset. It does not fall back to Homebrew or Cargo.

### Windows PowerShell installer

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

Install the full build:

```powershell
& ([scriptblock]::Create((iwr https://microclaw.org/install.ps1 -UseBasicParsing).Content)) -Full
```

### Homebrew on macOS

Install the native MicroClaw Work desktop app on Apple Silicon macOS 13+:

```sh
brew tap microclaw/tap
brew install --cask microclaw-work
```

MicroClaw Work for Windows and Linux is coming soon. The Server remains
available on macOS, Linux, and Windows.

Install MicroClaw Server:

```sh
brew tap microclaw/tap
brew install microclaw
```

Use `brew install microclaw-full` when Matrix support is required.

Work releases are signed with Developer ID, notarized by Apple, stapled, and
verified before the Homebrew Cask is updated.

### Build from source

The repository pins its Rust toolchain in `rust-toolchain.toml`.

```sh
git clone https://github.com/microclaw/microclaw.git
cd microclaw
cargo build --release
```

Build optional variants when needed:

```sh
cargo build --release --features full
cargo build --release --features sqlite-vec
```

`full` currently enables Matrix. `sqlite-vec` enables semantic-memory vector indexing.

### Linux compatibility

Release binaries use the GNU Linux target and are built on GitHub's current `ubuntu-latest` runner. At the time this guide was updated, they require glibc 2.39 or newer and OpenSSL 3.

Check the local C library before installing:

```sh
ldd --version
```

Ubuntu 24.04+, Debian 13+, Fedora 40+, and RHEL-compatible 10+ releases meet the glibc requirement. Older distributions can build from source on the target host or run the container image. Treat the release workflow as authoritative if the runner image changes.

## 2. Run diagnostics

```sh
microclaw doctor
```

Useful focused checks:

```sh
microclaw doctor --json
microclaw doctor sandbox
microclaw doctor delivery
```

The general check covers the local runtime, configured MCP command dependencies, and common platform prerequisites. The JSON form is suitable for support tickets.

## 3. Configure

Start the interactive setup:

```sh
microclaw setup
```

The wizard selects a provider and model, collects optional channel credentials, creates required directories, and writes `microclaw.config.yaml` with a backup of the previous file.

You can also copy and edit the full example:

```sh
cp microclaw.config.example.yaml microclaw.config.yaml
```

Use these sources instead of copied config tables:

- [Generated configuration defaults](generated/config-defaults.md)
- [Full configuration example](../microclaw.config.example.yaml)
- [Generated provider matrix](generated/provider-matrix.md)

At least one interaction surface must be available. The Web UI is enabled by default, so a chat-platform credential is optional for a local first run.

## 4. Start

```sh
microclaw start
```

The default Web UI is [http://127.0.0.1:10961](http://127.0.0.1:10961). See [Local Web UI and gateway](operations/web-ui.md) for authentication and API entry points.

## 5. Run as a user service

After a valid configuration exists:

```sh
microclaw gateway install
microclaw gateway status
```

Lifecycle commands:

```sh
microclaw gateway start
microclaw gateway stop
microclaw gateway restart
microclaw gateway logs 200
microclaw gateway uninstall
```

MicroClaw uses a `launchd` user agent on macOS, `systemd --user` on Linux, and a native Windows service. Windows service setup requires an elevated terminal; see the [Windows service guide](operations/windows-service.md).

## Container deployment

Published images use these names:

- `ghcr.io/microclaw/microclaw:latest`
- `ghcr.io/microclaw/microclaw:<version>`

Try the image:

```sh
docker pull ghcr.io/microclaw/microclaw:latest
docker run --rm -it \
  -p 127.0.0.1:10961:10961 \
  ghcr.io/microclaw/microclaw:latest
```

For persistent use, mount a configuration file and data directories:

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

The `data` mount preserves sessions, memory, skills, SQLite state, and scheduled work.

## Upgrade or uninstall

Upgrade an installer-managed binary:

```sh
microclaw upgrade
```

Review the [upgrade guide](releases/upgrade-guide.md) and [changelog](../CHANGELOG.md) before production upgrades.

Uninstall on macOS or Linux:

```sh
curl -fsSL https://microclaw.org/uninstall.sh | bash
```

Uninstall on Windows PowerShell:

```powershell
iwr https://microclaw.org/uninstall.ps1 -UseBasicParsing | iex
```

## Next steps

- [Cookbook](cookbook.md) for common workflows
- [MCP integration](integrations/mcp.md) for external tools
- [Secure runtime](security/secure-runtime.md) before exposing a deployment
- [Operations runbook](operations/runbook.md) for backup, recovery, and troubleshooting
- [Documentation map](README.md) for the full guide set
