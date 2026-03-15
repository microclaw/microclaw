# Windows Service Wrapper

MicroClaw now supports Windows service management directly through `microclaw gateway`.
On Windows, the built-in gateway service flow uses WinSW under the hood.

## Requirements

- Run the command in an elevated terminal for `install`, `start`, `stop`, `restart`, and `uninstall`.
- Prepare a working directory that contains `microclaw.config.yaml`, or pass `-ConfigPath` explicitly.
- Prefer absolute paths in `microclaw.config.yaml`, especially for `data_dir`, because services do not run with your normal shell context.

## Install

Example:

```powershell
cd D:\microclaw-runtime
microclaw gateway install
```

Default behavior:

- service name: `MicroClawGateway`
- wrapper root: `%ProgramData%\MicroClaw\gateway`
- WinSW version: `v2.12.0`
- service executable: the current `microclaw.exe`
- install command starts the service automatically

## Manage

```powershell
microclaw gateway status
microclaw gateway start
microclaw gateway stop
microclaw gateway restart
microclaw gateway uninstall
```

## Notes

- Run service install/start/stop/restart/uninstall commands in an elevated terminal.
- `microclaw gateway install` requires a real config file. Run `microclaw setup` first, then install the service from that configured working directory, or set `MICROCLAW_CONFIG`.
- The wrapper stores WinSW logs under `%ProgramData%\MicroClaw\gateway\winsw-logs`.
- MicroClaw still writes its own runtime logs under `<data_dir>/runtime/logs`.
- If your provider auth depends on per-user home files such as `~/.codex/auth.json`, a Windows service may not behave like an interactive user session. In that case, prefer API-key based config or a Scheduled Task that runs under your user account.
