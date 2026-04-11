# MicroClaw Optimization Plan — Inspired by Hermes Agent

**Date**: 2026-04-11
**Reference**: [nousresearch/hermes-agent](https://github.com/nousresearch/hermes-agent)

## Background

Analysis of NousResearch's Hermes Agent revealed several design patterns worth adopting in MicroClaw. This document details each optimization, its motivation, and implementation approach.

## Already Implemented (Verified)

### Memory Frozen Snapshot (Prefix Cache Friendly)
- **Status**: Already implemented
- Memory context is built once before the agent loop (`agent_engine.rs:742-754`), system prompt constructed once (`agent_engine.rs:760`), reused throughout all iterations.

### Parallel Tool Execution
- **Status**: Already implemented
- `tool_executor.rs` partitions tool calls into waves (ReadOnly/SideEffect/Exclusive) and runs ReadOnly tools concurrently via `futures::join_all`. Configurable via `parallel_tool_max_concurrency`.

## Optimizations To Implement

### 1. [P0] User Profile (PROFILE) Priority Injection

**Problem**: PROFILE-category memories (user preferences, role, communication style) are mixed with KNOWLEDGE and EVENT memories in the context injection. They may be pushed out by the token budget or ranked lower by keyword relevance.

**Hermes approach**: Separates `USER.md` (user profile) from `MEMORY.md` (agent notes), ensuring the user model is always present.

**Implementation**:
- In `build_db_memory_context()` (`memory_service.rs`), partition memories into PROFILE vs non-PROFILE
- Always include all PROFILE memories first (up to a sub-budget), then fill remaining budget with KNOWLEDGE/EVENT
- This ensures the agent always "knows" the user regardless of query relevance scoring

### 2. [P1] Memory Capacity Management & Auto-Archive

**Problem**: No per-chat memory count limit. Over time, the `memories` table can grow unboundedly, leading to slower queries and wasted reflector effort on stale data.

**Hermes approach**: Hard character limits on MEMORY.md (2200 chars) and USER.md (1375 chars), forcing the agent to curate.

**Implementation**:
- Add `memory_max_entries_per_chat` config (default: 200)
- In reflector, after applying extractions, check if chat exceeds the limit
- Auto-archive lowest-confidence memories that haven't been seen recently
- Add `memory_max_global_entries` config (default: 500) for global memories

### 3. [P1] Iteration Budget Progressive Warnings

**Problem**: When the agent loop hits `max_tool_iterations`, it abruptly stops with a generic message. The agent gets no advance warning to wrap up gracefully.

**Hermes approach**: `IterationBudget` injects caution at 70% and urgent warning at 90%.

**Implementation**:
- In the agent loop (`agent_engine.rs`), at 70% and 90% of `max_tool_iterations`, inject a system-level hint into tool results
- 70%: "You've used {n}/{max} iterations. Start wrapping up."
- 90%: "URGENT: Only {remaining} iterations left. Provide your final answer now."

### 4. [P2] Prompt Injection Detection in Memory Content

**Problem**: Memory content from user "remember:" commands or reflector extractions is not scanned for prompt injection patterns. Malicious content could manipulate agent behavior in future sessions.

**Hermes approach**: Scans all memory content for invisible unicode, "ignore previous instructions" patterns, and exfiltration attempts.

**Implementation**:
- Add `scan_for_injection()` function in `memory_quality.rs`
- Check for: invisible unicode (zero-width chars, RTL overrides), instruction override patterns, data exfiltration patterns (curl/wget URLs)
- Call from `normalize_memory_content()` and `memory_quality_ok()`
- Log and reject injected content

### 5. [P2] Skill Management Tool (Agent Can Create/Edit/Delete Skills)

**Problem**: Skills are static files managed externally. The agent cannot learn from experience and create reusable procedural knowledge.

**Hermes approach**: `skill_manage` tool with create/edit/patch/delete actions. Agent autonomously creates skills after completing complex tasks.

**Implementation**:
- New `src/tools/skill_manage.rs` with `SkillManageTool`
- Actions: `create` (new SKILL.md), `edit` (full rewrite), `patch` (targeted update), `delete`
- Security: scan created content for injection, validate frontmatter, cap content size
- Skills are written to `{data_dir}/skills/` (runtime skills, distinct from bundled)
- Control chat restriction: only control chats can create/delete skills by default

### 6. [P3] Autonomous Skill Creation (Post-Task Review)

**Problem**: Even with a skill_manage tool, the agent won't proactively create skills unless prompted.

**Hermes approach**: Nudge system triggers background review every N tool-call iterations, spawning a review agent to decide if a skill should be created.

**Implementation**:
- Add `skill_review_interval` config (default: disabled/0, enable with e.g. 15)
- In reflector or post-agent-loop hook, check if the completed conversation involved 5+ tool calls
- If so, spawn a lightweight LLM call with the conversation summary + skill review prompt
- If the review finds a reusable approach, call skill_manage internally

## Priority Summary

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| P0 | PROFILE priority injection | Low | UX quality |
| P1 | Memory capacity management | Medium | Long-term stability |
| P1 | Iteration budget warnings | Low | Agent quality |
| P2 | Injection detection | Low | Security |
| P2 | Skill management tool | Medium | Differentiation |
| P3 | Autonomous skill creation | High | Self-improvement |
