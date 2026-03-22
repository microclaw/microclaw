# Windows Gateway Service

MicroClaw can install the gateway as a native Windows Service directly from `microclaw.exe`.
No WinSW wrapper, `.cmd`, or extra helper script is required at runtime.

## Requirements

- Run `install`, `start`, `stop`, `restart`, and `uninstall` from an elevated terminal.
- Prepare a working directory that already contains `microclaw.config.yaml`, or pass `--config` explicitly.
- Prefer absolute paths in `microclaw.config.yaml`, especially for `data_dir`, because Windows services do not inherit your interactive shell context.

## Install

Example:

```powershell
cd D:\microclaw-runtime
microclaw gateway install
```

Default behavior:

- service name: `MicroClawGateway`
- display name: `MicroClaw Gateway`
- host binary: the current `microclaw.exe`
- service command line: `microclaw.exe --config <path> gateway service-run --working-dir <dir>`
- startup mode: automatic
- failure policy: restart after 5 seconds, then after 15 seconds
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

- `microclaw gateway install` requires a real config file. Run `microclaw setup` first, then install the service from that configured working directory, or set `MICROCLAW_CONFIG`.
- The native Windows service host starts `microclaw start` internally and uses the configured working directory for runtime startup.
- MicroClaw runtime logs are still written under `<data_dir>/runtime/logs`.
- If your provider auth depends on per-user home files such as `~/.codex/auth.json`, a Windows service running as `LocalSystem` may still behave differently from an interactive user session. In that case, prefer API-key based config or another launcher that runs under your own account.
