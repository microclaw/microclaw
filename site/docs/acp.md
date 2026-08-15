---
id: acp
title: ACP Stdio Mode
sidebar_position: 8
---

MicroClaw can run as an Agent Client Protocol (ACP) server over stdio.

Use this mode when you want a local tool or editor integration to talk to MicroClaw as a sessioned chat runtime without going through Telegram, Discord, Slack, or the Web UI.

This page covers the **ACP server** entry point. It is different from the ACP-backed **subagent runtime** used by `sessions_spawn(runtime="acp")`.

## Start ACP mode

```sh
microclaw acp
```

The process stays attached to stdio and serves ACP until the client disconnects or the process exits.

## What ACP mode gives you

- One shared MicroClaw runtime behind ACP stdio transport
- Sessioned chat behavior, including resumed context by session key
- The same tool loop used by normal chat surfaces
- Slash command support for `/stop` to cancel the current in-flight run

## Typical use cases

- local editor or IDE integrations
- terminal agents that want a stdio chat backend
- thin local wrappers around the MicroClaw runtime

## Runtime behavior

- ACP mode uses the normal MicroClaw config file and provider setup
- conversations are persisted like other channels
- each ACP session is mapped into MicroClaw chat/session storage
- cancellation is supported through `/stop`

## ACP-backed Subagents

MicroClaw can also use ACP as an **external worker runtime** for subagents. This is separate from `microclaw acp`.

Enable it in config:

```yaml
subagents:
  acp:
    enabled: true
    command: codex
    args: ["--model", "gpt-5.4"]
```

Then use `sessions_spawn` with `runtime="acp"` to run one background subagent through that external ACP agent process.

If you want multiple ACP workers, define named targets:

```yaml
subagents:
  acp:
    enabled: true
    default_target: "reviewer"
    targets:
      reviewer:
        enabled: true
        command: codex
        args: ["--model", "gpt-5.4"]
      fast-fix:
        enabled: true
        command: codex
        args: ["--model", "gpt-5.3-codex"]
        auto_approve: false
```

Selection rules:

- `runtime="acp"` uses `subagents.acp.default_target` when it is set
- otherwise it uses the inline `subagents.acp.command` worker when configured
- if neither exists and only one named target is enabled, that target is selected automatically
- if multiple named targets are enabled, pass `runtime_target`

Current behavior:

- the parent chat still uses the normal MicroClaw lifecycle (`sessions_spawn`, `subagents_list`, `subagents_info`, `subagents_kill`, `subagents_log`)
- each ACP run gets the chat working directory as its session workspace
- ACP file read/write and terminal methods are exposed to the external agent inside that workspace
- `subagents_send` inherits the runtime and `runtime_target` from the focused ACP run
- `subagents_log` records ACP permission, plan, tool-call, file, and terminal events
- ACP permission requests are target-configurable with `auto_approve`; treat enabled auto-approve as an explicit operator opt-in

## Quick verification

Before testing ACP, make sure your config is valid:

```sh
microclaw doctor
```

If the Web control plane is enabled, also check `GET /api/config/self_check`. It reports ACP warnings such as:

- invalid `subagents.acp.default_target`
- missing ACP worker commands on the host
- `auto_approve` being enabled on the selected target

Then start ACP:

```sh
microclaw acp
```

Recommended validation flow:

1. open a session from your ACP client
2. send a normal prompt and confirm you get a reply
3. send a second prompt in the same session and confirm context is preserved
4. start a long-running request, then issue `/stop`
5. reconnect and confirm the runtime still accepts new requests

For ACP-backed subagents, also validate:

1. run one `sessions_spawn` with `runtime="acp"`
2. if you use named workers, run one with `runtime_target`
3. inspect the run with `subagents_info` or `subagents_log`
4. focus the run, then continue it with `subagents_send` and confirm the target is preserved

## When not to use ACP mode

Use `microclaw start` instead if you want:

- Telegram / Discord / Slack / Feishu / IRC / Web adapters
- Web UI and Web operator APIs
- webhook-triggered automation endpoints

ACP mode is specifically the stdio server entry point.
