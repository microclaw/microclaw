---
id: memory
title: Memory System
sidebar_position: 7
---

MicroClaw memory has three layers of persistence:

- file memory in `AGENTS.md`
- structured memory in SQLite/MCP (`memories` table)
- temporal knowledge graph triples (`knowledge_graph` table)

Prompt injection uses the file memory plus a layered subset of structured memory. The knowledge graph is queried on-demand through dedicated tools, **and is also activated automatically during recall** to inject connected facts (see [Graph-augmented recall](#graph-augmented-recall)).

## File memory (AGENTS.md)

Manually written key-value style notes in `AGENTS.md` files. The LLM writes these via the `write_memory` tool.

```
~/.microclaw/runtime/groups/
    AGENTS.md                 # Global memory (shared across all chats)
    {channel}/
        AGENTS.md             # Bot/account memory for this channel
        {chat_id}/
            AGENTS.md         # Per-chat memory (namespaced by channel)
```

- LLM can read and write memory using `read_memory` and `write_memory`
- `scope` supports `global`, `bot`, and `chat`
- Memory is wrapped in `<global_memory>`, `<bot_memory>`, and `<chat_memory>` tags
- The memory files live under `DATA_DIR/runtime` (default `~/.microclaw/runtime`)
- `write_memory` to `scope: "global"` requires the caller chat to be in `control_chat_ids`
- `write_memory` to `scope: "chat"` updates the latest sender's `## Person: <name>` section when sender identity is available
- `write_memory` also persists a structured memory row into SQLite (`memories` table)
- Explicit commands like `remember ...` / `记住...` also use a deterministic fast path into structured memory

## Optional MCP memory backend

If MCP config contains a server that exposes both `memory_query` and `memory_upsert`, structured-memory operations switch to MCP-first mode.
Config is loaded from `<data_dir>/mcp.json` plus optional fragments in `<data_dir>/mcp.d/*.json`.

MCP-first coverage:

- structured-memory reads and searches used during prompt construction
- explicit `remember ...` fast-path writes
- Reflector insert/update/supersede/touch operations
- `structured_memory_search`, `structured_memory_update`, and `structured_memory_delete` tool operations

Fallback behavior:

- if MCP is not configured, unavailable, times out, or returns an invalid payload, MicroClaw transparently falls back to built-in SQLite memory for that operation
- file memory (`AGENTS.md`) remains local and unchanged

Minimal MCP config example (base file or fragment):

```json
{
  "defaultProtocolVersion": "2024-11-05",
  "mcpServers": {
    "memory": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:8090/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_ME"
      },
      "request_timeout_secs": 60
    }
  }
}
```

The `memory` server must expose MCP tools named exactly `memory_query` and `memory_upsert`.

## Chat identity mapping

SQLite stores chats with two identities:

- `chat_id`: internal primary key used by sessions/messages/tasks
- `channel + external_chat_id`: source identity from Telegram/Discord/Slack/Feishu/IRC/Web

This prevents cross-channel collisions when numeric IDs overlap. Existing databases are migrated automatically at startup. Structured memories also store `chat_channel` and `external_chat_id` for easier debugging.

## Reflector (structured memories + triples)

A background process that automatically extracts and persists structured memories from conversations — independently of the main chat loop.

As sessions grow longer, the model tends to deprioritize voluntary `write_memory` calls. The Reflector runs on a timer and extracts memories without relying on the model to remember to do so.

**How it works:**

1. Every `reflector_interval_mins` minutes (default 15), the Reflector scans recently-active chats
2. Per chat, it reads messages incrementally from a persisted cursor (`memory_reflector_state`) instead of rescanning full windows
3. It calls the LLM directly and extracts durable facts plus optional entity triples
4. Extracted memories are stored in SQLite (`memories`), and triples go to `knowledge_graph`
5. Dedup strategy:
   - with `sqlite-vec` feature + runtime embedding configured: semantic nearest-neighbor check (cosine distance)
   - otherwise: Jaccard overlap fallback
6. Quality gate:
   - low-signal / uncertain snippets are filtered before writing
7. Lifecycle:
   - rows track confidence + last-seen
   - stale low-confidence rows can be soft-archived

8. Capacity control:
   - if per-chat/global limits are exceeded, lowest-confidence and least-recently-seen rows are archived first
   - knowledge-graph triples also have per-chat capacity control

**Memory categories:**

| Category | Description |
|---|---|
| `PROFILE` | User attributes and preferences |
| `KNOWLEDGE` | Facts and areas of expertise |
| `EVENT` | Significant things that happened |

## Layered Structured-Memory Injection

Structured memories are injected with a 4-layer policy:

- L0 Identity: `PROFILE` memories first (always injected, fixed budget share)
- L1 Essential: highest-confidence durable facts
- L2 Relevance: query-matched memories filling the remaining budget
- L3 Deep Search: not injected; fetched only when tool calls are needed

This keeps identity and durable facts stable while preserving room for query-specific context.

**Injected in system prompt as:**

```
<structured_memories>
[PROFILE] [chat] User is a Rust developer based in Tokyo
[KNOWLEDGE] [chat] User prefers functional programming style
</structured_memories>
```

**Configuration:**

```yaml
reflector_enabled: true         # enable/disable background reflector
reflector_interval_mins: 15     # how often to run (minutes)
memory_token_budget: 1500       # total budget for L0+L1+L2 structured memories
memory_l0_identity_pct: 20      # L0 identity share of budget
memory_l1_essential_pct: 30     # L1 essential share of budget
memory_max_entries_per_chat: 200
memory_max_global_entries: 500
kg_max_triples_per_chat: 1000
skill_review_min_tool_calls: 0  # >0 enables post-reflector autonomous skill review

# optional semantic memory runtime config (requires --features sqlite-vec build)
# embedding_provider: "openai"  # openai | ollama
# embedding_api_key: "..."
# embedding_base_url: "..."
# embedding_model: "text-embedding-3-small"
# embedding_dim: 1536
```

Both can be changed via the setup wizard (`microclaw setup`) or the Web UI settings panel.

When `memory_token_budget` is exceeded during prompt construction, MicroClaw stops adding memories and appends `(+N memories omitted)`.

## Memory Security and Auditability

- Memory writes pass a prompt-injection scanner (invisible unicode, instruction-override patterns, exfiltration-like payloads, and risky HTML/script payloads).
- Structured-memory writes are audit-logged to:
  - `<data_dir>/runtime/wal/memory_writes.jsonl`
  - this helps diagnose memory poisoning and unexpected write spikes.

## Knowledge Graph Tools

- `knowledge_graph_query`: query by entity, timeline, or stats
- `knowledge_graph_add`: add triples and optionally invalidate stale ones

Use these when a request needs relationship or time-aware recall beyond the injected memory subset.

## Graph-augmented recall

Beyond on-demand tool queries, the temporal knowledge graph is also activated **during recall itself**, so relationship-aware facts surface automatically without the model having to ask for them.

After the flat L0–L2 structured-memory layers are assembled, recall:

1. Seeds the graph from entities mentioned in the current query (`kg_distinct_entities`).
2. Expands a **bounded 1–2 hop** neighborhood over the triple store (`kg_neighborhood`, a bounded BFS).
3. Injects the connected facts as a dedicated `# Connected` block in the prompt.

It is **local-only** — no embeddings and no extra LLM call — bounded by hops, triple count, and token budget, with a redundancy guard so it never repeats facts already injected by L0–L2. If you mention a project, recall can now surface the person who owns it and the deadline attached to it — relationships the flat layers wouldn't have ranked together.

**Configuration (default-on, no added cost):**

```yaml
memory_graph_recall_enabled: true   # activate KG expansion during recall
memory_graph_max_hops: 2            # bounded neighborhood radius
memory_graph_max_triples: 10        # cap on injected connected facts
```

## Semantic memory behavior

Two-level safety model:

- Compile-time: `sqlite-vec` feature is **off by default**
- Runtime: `embedding_provider` is **unset by default**

Runtime outcomes:

- `sqlite-vec` enabled + embedding configured: semantic KNN retrieval and semantic dedup
- `sqlite-vec` enabled + embedding not configured: vector table may exist but retrieval/dedup still falls back
- `sqlite-vec` disabled: keyword retrieval + Jaccard dedup (stable baseline)
- MCP memory backend enabled: retrieval order comes from MCP query results; local sqlite-vec KNN ranking is skipped

## Memory observability

MicroClaw records memory operations for diagnostics:

- `memory_reflector_runs`: per-run extracted/inserted/updated/skipped counts
- `memory_injection_logs`: candidate/selected/omitted counts during prompt injection

You can inspect these from:

- `/usage` output (text summary)
- Web UI → **Usage Panel** → **Memory Observability** cards

The panel highlights:

- memory pool health (active/archived/low-confidence)
- reflector throughput in last 24h
- injection coverage (`selected / candidates`) in last 24h

## Example

```
You: Remember that I prefer Rust examples
Bot: Noted. Saved memory #123: I prefer Rust examples.

[15 minutes later, automatically]
Reflector: extracted "User prefers Rust code examples" → memories table

[Next session after /reset]
Bot: [has both AGENTS.md + structured memories in context]
```
