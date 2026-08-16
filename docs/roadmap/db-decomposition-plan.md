# db.rs decomposition plan

Status: **delivered in 0.5.0** · Scope: `crates/microclaw-storage/src/db.rs`

> Executed 2026-08-16 on the v0.5.0 release branch, at the maintainer's
> direction, as a single scripted transformation instead of the six staged
> PRs below (the phasing was designed for incremental review; the release
> PR carried it in one commit, `b38cca6`, with the same per-phase gates
> applied at the end state). Integrity was machine-checked: 237/237 public
> methods, 59/59 structs, 71/71 CREATE TABLE statements, 43/43 migration
> blocks, identical test counts (124 / 125 with `sqlite-vec` / 1,509
> workspace), clippy and fmt clean. The rest of this document is kept as
> the design rationale.

## 1. Problem

`db.rs` is 17,178 lines: a 636 KB file holding ~60 public structs, the schema
init and all 43 versioned migrations, ~1,600 lines of free helper functions,
one `impl Database` block with **237 public methods** (~8,300 lines), and a
~4,400-line test module. Every schema change, every new query, and every
domain feature lands in the same file. No reviewer can hold it; `git blame`
and merge conflicts concentrate there; and the learning/experience domain
alone (55 methods plus most of the free helpers) is a subsystem trapped
inside a junk drawer.

## 2. Facts the plan builds on (measured, not assumed)

1. **Single choke point for connection access.** Every method goes through a
   private `lock_conn(&self) -> MutexGuard<Connection>` (242 call sites).
   Nothing else touches `self.conn`.
2. **Consumers import through one path.** 60 files across the workspace use
   `microclaw_storage::db::{Database, StoredMessage, ...}`. No consumer names
   a submodule.
3. **Tests exercise only the public API.** The embedded test module makes 495
   `db.…` calls through `Database` methods; nothing reaches into privates
   except via `super::*`.
4. **Method inventory clusters cleanly by domain** (counted from the impl
   block):

   | Domain | Methods | Extra weight |
   |---|---|---|
   | learning / experience / skills | 55 | + ~1,600 lines of free helpers, ~25 structs |
   | messages / chats | 34 | |
   | memory / KG / embeddings | 38 | |
   | subagent runs / announce | 25 | |
   | scheduled tasks + DLQ | 22 | |
   | sessions | 16 | |
   | auth (passwords, API keys) | 8 | |
   | outbox / delivery health | 8 | |
   | interrupted turns | 8 | |
   | tool cache / artifacts | 6 | |
   | runtime meta | 5 | |
   | audit chain | 4 | + hash helpers |
   | metrics / usage / observability | 7 | |
   | `new` + `lock_conn` | 2 | stays in the root |

5. **Rust allows multiple `impl Database` blocks across files in one crate.**
   That is the entire trick: domain modules each contribute an
   `impl Database { … }`, and the facade type, its construction, and every
   public signature stay byte-identical.

## 3. Chosen shape: same facade, multiple impl blocks

`db.rs` becomes a `db/` directory. The `Database` struct, `new()`,
`lock_conn()` (promoted to `pub(crate)`), and `call_blocking` live in
`db/mod.rs`, which also `pub use`s every type from the domain modules so the
existing `microclaw_storage::db::X` import path keeps working for all 60
consumer files — **zero changes outside the storage crate**.

```
crates/microclaw-storage/src/db/
  mod.rs          Database, new(), pub(crate) lock_conn(), call_blocking,
                  pub use re-exports of every domain type
  schema.rs       ensure_* fns + apply_schema_migrations (verbatim; see §5)
  chats.rs        chats/messages/catch-up            (34 methods + structs)
  sessions.rs     session persistence + settings     (16)
  tasks.rs        scheduled tasks + DLQ              (22)
  subagents.rs    subagent runs/announce/events      (25)
  memory.rs       memories, KG triples, embeddings,  (38)
                  reflector + injection logs
  learning.rs     experience runs, outcome envelopes,(55 + free helpers)
                  verifiers, shadow evals, skill
                  lifecycle/governance, journal
  usage.rs        LLM usage + token budget           (3)
  auth.rs         operator password + API keys       (8)
  audit.rs        audit chain + hash helpers         (4)
  outbox.rs       outbox + delivery health           (8)
  turns.rs        interrupted-turn recovery          (8)
  tool_cache.rs   tool cache + artifacts             (6)
  meta.rs         runtime meta + metrics history     (9)
  test_support.rs #[cfg(test)] shared test_db() helper
```

Each domain module holds, together: its structs, its free helper functions,
its `impl Database` block, and its `#[cfg(test)] mod tests`. Structs live
with the code that reads and writes them — `types.rs` grab-bags are
explicitly rejected.

Note `db/memory.rs` (`db::memory`) does not collide with the existing
crate-level `memory.rs` (`microclaw_storage::memory`, the file-memory
manager) — different module paths.

`learning.rs` will still be the largest (~4,500 lines with helpers and
tests). That is acceptable for this pass: it is one coherent subsystem, and
splitting it further (experience vs. skill-lifecycle) is a follow-up decision
for whoever next works in it, not a blocker.

### Alternatives rejected

- **Repository objects** (`db.sessions().get(…)`): a real API change touching
  all 60 consumer files and every call site — high churn, no correctness
  gain. Can be layered on later if ever wanted; this plan doesn't foreclose it.
- **Traits per domain**: indirection without a second implementor.
- **Splitting the SQLite database itself**: out of scope; single-file WAL
  SQLite is a product feature.

## 4. Execution: verbatim moves in review-sized PRs

Every phase is a **pure text move** — cut a coherent block from `db.rs`,
paste into its module, add the module's `use` header, `pub use` the types
from `mod.rs`. No signature edits, no query edits, no logic edits in any
phase. The one mechanical edit allowed is visibility (`fn` → `pub(crate) fn`
for `lock_conn` and any free helper crossed by a module boundary).

Gate for every phase, no exceptions: `cargo test --workspace` green with the
same 1,509+ test count, `cargo clippy --workspace --all-targets -D warnings`
clean, `cargo fmt --check` clean, and `git diff --stat` shows only the
storage crate.

- **PR 1 — scaffold + schema.** Convert to `db/` layout: `mod.rs` keeps
  everything initially; move `ensure_*` + `apply_schema_migrations` +
  `SCHEMA_VERSION_CURRENT` into `schema.rs`; move the shared `test_db()`
  into `test_support.rs`. Smallest possible diff that proves the layout,
  re-export mechanism, and test relocation all work.
- **PR 2 — leaf domains** (low coupling, small): `auth.rs`, `audit.rs`,
  `outbox.rs`, `turns.rs`, `tool_cache.rs`, `meta.rs`, `usage.rs`.
  Seven modules, ~45 methods total.
- **PR 3 — chats + sessions.** 50 methods, the hot request path; keep this
  PR free of anything else so review attention stays on it.
- **PR 4 — tasks + subagents.** 47 methods.
- **PR 5 — memory.** 38 methods including the `sqlite-vec` feature-gated
  embedding code; the feature flag is why this gets its own PR
  (`cargo test` must pass with the feature both on and off).
- **PR 6 — learning.** The 55-method block plus its ~1,600 lines of free
  helpers and the matching tests. Largest but purely mechanical by then;
  the pattern is proven five times over.

Each PR is independently landable and independently revertable. If the
effort stalls after any PR, the tree is strictly better than before.

## 5. Rules that protect correctness

1. **Migrations are frozen text.** `apply_schema_migrations` moves verbatim.
   Historical `if version < N` blocks are never reformatted, reordered, or
   "cleaned up" — the migration path from every deployed version must replay
   byte-identically. `schema.rs` gets a header comment saying exactly this.
2. **No drive-by fixes.** Anything ugly discovered during a move is filed,
   not fixed in the move PR. A move diff must be verifiable by eye as a move.
3. **Tests move with their domain, never rewritten.** The count may only go
   up (if a shared helper needs duplicating), never down.
4. **`lock_conn` stays `pub(crate)`.** No public access to the raw
   connection; the facade boundary is unchanged for consumers.
5. **One in-flight decomposition PR at a time**, rebased before merge —
   this refactor is the maximum-conflict-surface change possible in this
   crate, and the repo has active feature branches.
6. **Add the move commits to `.git-blame-ignore-revs`** (and document
   `git config blame.ignoreRevsFile .git-blame-ignore-revs` in
   `CONTRIBUTING.md`) so `git blame` keeps pointing at real authorship.

## 6. What this does not fix (deliberately)

- `learning.rs` internal complexity — the shadow-eval/lifecycle helpers keep
  their current shape; splitting or simplifying them is real refactoring, not
  moving, and needs its own review.
- The `Mutex<Connection>` single-writer model — fine at current scale;
  connection pooling is a separate conversation with actual measurements.
- `src/setup.rs` (11k lines) and `src/web.rs` (6.8k) — same disease, separate
  plans; do not batch them into this one.

## 7. Estimate

PR 1 is an afternoon. PRs 2–6 are each a half-day of careful moving plus the
gate run. Wall-clock spread over ~2 weeks at one PR at a time; total effort
~4 focused days. The payoff: no file in the storage crate over ~4,500 lines,
domain changes review in isolation, and the next schema migration lands in a
600-line `schema.rs` instead of a 17,000-line monolith.
