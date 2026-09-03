---
id: overview
title: Overview
sidebar_position: 1
---

# MicroClaw

MicroClaw is a self-hosted Rust agent platform with one embeddable Agent Engine,
two product surfaces, and a Rust SDK:

- **MicroClaw Server** is the always-on runtime for chat channels, the local
  Web console, APIs, schedules, background work, and agent protocols. It ships
  for macOS, Linux, and Windows.
- **MicroClaw Work** is a native GPUI desktop application for local
  conversations, project workspaces, approvals, checkpoints, and settings. It
  is officially supported on Apple Silicon macOS 13+; launch-smoked Linux and
  Windows portable previews are published with each release while native
  platform acceptance continues.
- **`microclaw-sdk`** lets another Rust application use the same Agent, Run,
  event, control, Skill, and Worker model without importing Server or UI code.

Both surfaces share the Agent Engine, provider abstraction, tool registry,
policy and approval path, memory, skills, MCP integration, checkpoints, and
runtime event protocol. Work is not a packaged copy of the Web console, and it
does not maintain a desktop-only agent loop.

The latest release is **v0.5.5**. Use the `stable` branch for conservative
production deployments; `main` is the active development branch.

## What makes it different

- One shared agent loop across Server channels, Web, protocols, and native Work
- A native Rust/GPUI desktop workspace without a bundled browser or duplicated runtime
- Humanlike chat surface: short-first / multi-bubble replies, mood-adaptive tone, group etiquette
- Bounded, observable **Subagents** with named tasks, cancellation, native or ACP workers, and colleague-style progress reports
- Long-lived memory backed by `AGENTS.md` files plus structured SQLite memory, with graph-augmented recall over a temporal knowledge graph
- Built-in scheduler for cron and one-time tasks
- Multi-chat permission model (`control_chat_ids`) for cross-chat tool authorization
- Skills, MCP tool federation, and a local web operator API
- Config self-check and observability surfaces for operational drift
- Customizable personality via `SOUL.md` files (global + per-chat)

## How it works

```
chat message
    |
    v
 Store in SQLite --> Load chat history + memory
                         |
                         v
                   LLM API (with tools)
                         |
                    stop_reason?
                   /            \
              end_turn        tool_use
                 |               |
                 v               v
           Send reply      Execute tool(s)
                              |
                              v
                        Feed results back
                        to LLM (loop)
```

MicroClaw enters an agentic loop for every message. LLM can call tools, inspect results, call more tools, and reason through multi-step tasks before responding. The same loop also powers resumed sessions, background subagents, and ACP-connected clients. The loop is capped by `max_tool_iterations` for safety.

## Core capabilities

- Agentic tool use (bash, file I/O, glob, grep)
- Humanlike chat: short-first / BLUF replies, multi-bubble sends, zero-cost mood detection (`<conversation_mood>`), group etiquette
- Bounded Subagents with named tasks (`label`), mid-run `report_progress`, cancellation, native or ACP workers, opt-in standup + fan-in summaries, and specialist-to-specialist `consult_specialist`
- 45 factory-ready built-in skills (compute, coding, research, planning, writing, diagrams, documents)
- Web search, fetch, and browser automation (with default-on SSRF guard against private/loopback/cloud-metadata IPs)
- Multimedia tools: image generation, vision, text-to-speech, speech-to-text
- Cross-channel voice: inbound transcription on Telegram/Discord/Slack/Feishu, opt-in TTS round-trip
- Cross-conversation recall via `session_search` (SQLite FTS5)
- Scheduling with cron expressions
- ACP stdio server mode plus ACP-backed external subagent workers
- Mid-conversation messaging for progress updates
- Persistent memory (global + per-chat)
- Per-chat user model (USER.md) — curated narrative of who the user is, distinct from volatile memories
- Structured memory with reflector extraction, dedupe, per-row TTL, recency decay, and observability
- Graph-augmented recall: bounded local expansion over the temporal knowledge graph injects connected facts during recall (default-on, no embeddings)
- Skill lifecycle: end-of-turn review with patch-existing support, activation tracking, auto-archive
- Tool result truncation + artifact stash with `fetch_artifact` for slicing oversized outputs
- Personality customization via SOUL.md
- Conversation archiving (automatic before compaction, manual via `/archive`)
- Typing indicator that stays active during tool use
- Local Web operator console with chat, session controls, task history, configuration, governance, usage, skills, and diagnostics
- Native MicroClaw Work desktop with durable conversations, project workspaces, inline approvals, checkpoints, model and SOUL settings, and light/dark themes

Continue with the Quickstart to get a bot running in minutes.
