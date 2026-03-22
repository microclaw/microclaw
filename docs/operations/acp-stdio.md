# ACP Stdio Mode

MicroClaw can run as an Agent Client Protocol (ACP) server over stdio:

```sh
microclaw acp
```

## When to use it

Use ACP mode when another local tool wants to treat MicroClaw as a sessioned chat runtime over stdio instead of using a chat adapter or the Web API.

This document is about MicroClaw acting as an ACP **server**. It is separate from ACP-backed subagent execution via `sessions_spawn(runtime="acp")`, which can now also select named workers with `runtime_target`.

ACP-backed subagents are configured under `subagents.acp`. You can either:

- set one inline default worker with `subagents.acp.command` + `args`
- define multiple named workers under `subagents.acp.targets` and select them with `runtime_target`
- set `subagents.acp.default_target` so plain `runtime="acp"` resolves to a stable named worker

Typical cases:

- local editor or IDE integrations
- terminal wrappers that want ACP transport
- local automation that already speaks ACP

## Behavior

- uses the normal `microclaw.config.yaml`
- persists ACP conversations through the standard runtime storage
- supports `/stop` to cancel the active run for the ACP session
- keeps the normal tool loop and provider stack

## Verification

1. Run `microclaw doctor`.
2. If Web is enabled, also inspect `GET /api/config/self_check` for ACP warnings.
3. Start `microclaw acp`.
4. Connect with an ACP client.
5. Send one prompt and confirm a normal response.
6. Send a follow-up prompt in the same session and confirm context is preserved.
7. Trigger a long-running request, then send `/stop` and confirm cancellation works.

## Related docs

- `README.md`
- `website/docs/acp.md`
- `website/docs/testing.md`
