# RFC 0003: Session Forking Model

- Status: Draft
- Owner: storage/web/agent
- Target Phase: Phase 3
- Last Updated: 2026-02-19

## Context

MicroClaw supports session resume and compaction but lacks first-class branching/forking for exploratory workflows.

## Goals

- Add DB-level parent-child relation for sessions.
- Add API for forking a session at optional message index.
- Define delete and listing semantics for fork trees.

## Non-Goals

- Full web UI tree rendering in this phase.
- Git worktree binding in this phase.

## Proposed Design

### Data Changes

Add columns to `sessions` table:

- `parent_session_key TEXT NULL`
- `fork_point INTEGER NULL`

Indexes:

- `idx_sessions_parent_session_key`

### API

- `POST /api/sessions/fork`
  - input: `{ key, at_message?, label? }`
  - output: `{ session_key }`

### Fork Semantics

- copy messages `[0..at_message]` when provided
- copy full transcript when omitted
- inherit model/provider/session settings

### Delete Semantics

- deleting parent does not cascade
- children become top-level (retain their own history)

### Listing Semantics

- existing list API remains flat in v1
- optional `include_parent=true` adds parent/fork metadata

## Compatibility

- existing sessions have null parent/fork fields
- no behavior change unless fork API invoked

## Testing Plan

- migration tests for old DB
- fork copy correctness (boundary and full copy)
- parent delete non-cascade behavior

## Rollback Plan

- additive schema only
- API can be disabled behind feature gate
