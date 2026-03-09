# HTTP Hook Trigger

This document describes the dedicated webhook-style HTTP trigger surface for MicroClaw automation.

## Scope

This feature is for external systems (webhooks, CI, cron scripts) that need to trigger agent runs without Web UI interaction.

## Endpoints

- `POST /hooks/agent`
- `POST /api/hooks/agent` (alias)
- `POST /hooks/wake`
- `POST /api/hooks/wake` (alias)

## Auth

`/hooks/*` endpoints use a dedicated token from `channels.web.hooks_token`.

Supported headers:

- `Authorization: Bearer <token>` (recommended)
- `x-openclaw-token: <token>`
- `x-microclaw-hook-token: <token>`

If `hooks_token` is missing, the endpoint returns `503`.

## Config

```yaml
channels:
  web:
    hooks_token: "replace-with-secret"
    hooks_default_session_key: "hook:ingress"
    hooks_allow_request_session_key: false
    hooks_allowed_session_key_prefixes: ["hook:"]
```

### Session key policy

- By default, request `sessionKey` is rejected (`hooks_allow_request_session_key: false`).
- If enabled, values can still be restricted by `hooks_allowed_session_key_prefixes`.
- When no request `sessionKey` is provided, `hooks_default_session_key` is used.

## `POST /hooks/agent`

OpenClaw-style payload compatibility:

```json
{
  "message": "Summarize inbox",
  "name": "Email",
  "sessionKey": "hook:email:msg-123"
}
```

Fields:

- `message` required.
- `name` optional (used as sender fallback).
- `sessionKey` optional; subject to session key policy.

Response:

- `200` with async run payload (`run_id`), then consume `/api/stream`.

## `POST /hooks/wake`

Payload:

```json
{
  "text": "New email received",
  "mode": "now"
}
```

Fields:

- `text` required.
- `mode` optional: `now` (default) or `next-heartbeat`.

Behavior:

- `now`: starts an async run immediately (returns `run_id`).
- `next-heartbeat`: only queues a system event message in the hook session and returns queue metadata.

## Examples

```sh
curl -sS http://127.0.0.1:10961/hooks/agent \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"Summarize inbox","name":"Email"}'
```

```sh
curl -sS http://127.0.0.1:10961/hooks/wake \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"New email received","mode":"next-heartbeat"}'
```

## Troubleshooting

- `401 unauthorized`: missing or invalid hook token.
- `400 sessionKey override is disabled`: request tried to set `sessionKey` while overrides are disabled.
- `400 sessionKey is not allowed by configured prefixes`: request `sessionKey` failed prefix policy.
- `503 hooks token is not configured`: set `channels.web.hooks_token` and restart.
