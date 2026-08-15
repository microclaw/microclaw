---
id: overview
title: Overview
sidebar_position: 1
---

# MicroClaw

MicroClaw is a Rust multi-channel agent runtime for Telegram, Discord, Slack, Feishu/Lark, IRC, Web, and ACP-connected local clients. It combines one shared agent loop, one provider abstraction, persistent memory, background scheduling, and a local web control plane in a single binary.

## What makes it different

- Channel-agnostic agent loop instead of separate bot implementations per surface
- Humanlike chat surface: short-first / multi-bubble replies, mood-adaptive tone, group etiquette
- A concurrent **specialist sub-agent team** (mathematician, illustrator, researcher, coder, writer, analyst) with named tasks and colleague-style progress reports
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
- Concurrent specialist sub-agent team with named tasks (`label`), mid-run `report_progress`, opt-in standup + fan-in summaries, and specialist-to-specialist `consult_specialist`
- 42 factory-ready built-in skills (compute, coding, research, planning, writing, diagrams, documents)
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
- Local Web UI with session controls, config editing, and self-checks

Continue with the Quickstart to get a bot running in minutes.
