---
id: architecture-channels
title: Architecture - Channels and Gateway
sidebar_position: 13
---

MicroClaw supports multiple channels with shared agent behavior and channel-specific ingress/egress.

## Current adapters

- Telegram
- Discord
- Slack (Socket Mode)
- Feishu / Lark (WebSocket long connection or webhook)
- IRC (plain TCP or TLS)
- Web UI

Each adapter handles platform specifics (message format, mention rules, send API), while reusing common agent/tool logic.

Current runtime boundary:
- `src/runtime.rs`: boots enabled adapters
- `crates/microclaw-channels/src/channel.rs`: channel routing + policy + dispatcher orchestration
- `crates/microclaw-channels/src/channel_adapter.rs`: adapter trait + channel registry
- `crates/microclaw-channels/src/delivery.rs`: delivery boundary notes (delivery now lives in adapter implementations)

## Gateway responsibilities (target model)

Gateway should own:

- message ingress normalization
- channel auth and identity mapping
- dispatch into agent runtime
- response fan-out and delivery

Gateway should not own:

- tool planning loop
- model provider internals
- skill resolution logic

## Multi-account direction

For enterprise shared deployments:

- account/tenant-scoped storage roots
- strict default isolation
- optional shared zones with explicit ACL
- consistent authorization checks in both tools and channel adapters

## Why this split helps

- add new IM channels without touching core planner
- test adapters independently from agent logic
- reduce regression risk when platform APIs change
