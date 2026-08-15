---
slug: /http-hook-trigger-for-automation
title: "New: HTTP Hook Trigger for Headless Automation"
authors: [microclaw]
tags: [release, web, runtime, channels]
---

MicroClaw now includes a dedicated HTTP hook trigger surface for external automation.

This closes a common integration gap: webhook systems and scripts can trigger agent runs directly, without relying on chat-native ingress or static scheduler-only flows.

<!-- truncate -->

## What shipped

MicroClaw now exposes:

- `POST /hooks/agent` (alias: `/api/hooks/agent`)
- `POST /hooks/wake` (alias: `/api/hooks/wake`)

`/hooks/agent` accepts an OpenClaw-style payload shape (`message`, optional `name`, optional `sessionKey`) and starts an async run.

`/hooks/wake` supports two modes:

- `now` (default): run immediately
- `next-heartbeat`: queue a system-event message only

## Security model

These endpoints are protected by a dedicated hook token:

```yaml
channels:
  web:
    hooks_token: "replace-with-secret"
```

Auth headers:

- `Authorization: Bearer <token>`
- `x-openclaw-token: <token>`
- `x-microclaw-hook-token: <token>`

This keeps webhook ingress auth separated from operator API key scopes.

## Session-key safety defaults

To reduce risky external routing, request `sessionKey` override is off by default:

```yaml
channels:
  web:
    hooks_default_session_key: "hook:ingress"
    hooks_allow_request_session_key: false
    hooks_allowed_session_key_prefixes: ["hook:"]
```

If you enable request overrides, prefix allowlists let you constrain where external traffic can route.

## Why this matters

Before this, MicroClaw already had Web send endpoints, but webhook-style trigger semantics were less explicit for automation clients.

Now the runtime has a first-class ingress path for:

- CI/CD checks and summary bots
- inbound SaaS events (monitoring, incident tools, ticketing)
- script-based orchestration and fan-out workflows

## Quick example

```bash
curl -sS http://127.0.0.1:10961/hooks/agent \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"Summarize inbox","name":"Email"}'
```

Then consume run events via:

```bash
curl -N "http://127.0.0.1:10961/api/stream?run_id=<RUN_ID>" \
  -H "Authorization: Bearer $MICROCLAW_OPERATOR_API_KEY"
```

## Docs

Full reference and troubleshooting:

- [HTTP Hook Trigger](/docs/http-hook-trigger)
- [Web Operator API](/docs/web-operator-api)
