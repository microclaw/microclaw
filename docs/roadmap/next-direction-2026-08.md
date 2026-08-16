# Next direction — health review, 2026-08-15

A full-tree review of `main` at `6ebb0c0`. Scope: build, tests, lint, dependency
posture, structural debt, docs accuracy. This supersedes
[`v0.4.0-plan.md`](./v0.4.0-plan.md) as the active plan; v0.4.0 shipped on 2026-08-07
and its exit criteria are met.

## 1. Verdict

**The Rust code is in good shape. The build and release boundary is not.**

Quality gates, all run against this tree:

| Gate | Result |
|---|---|
| `cargo test --workspace` | **1509 passed, 0 failed**, 5 ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all --check` | clean |
| `cargo build --workspace --all-targets` | compiles with zero warnings |
| `node scripts/generate_docs_artifacts.mjs --check` | generated docs up to date |
| `.unwrap()` in production code (test modules excluded) | **5**, across 3 files |
| `TODO`/`FIXME`/`HACK` markers | 6, all of them intentional prompt text in `scheduler.rs` |

Five production `unwrap()` calls in ~144k lines of Rust, and near-zero debt markers,
is unusually disciplined. The problems found are almost entirely *outside* the Rust
source: in the build script, the packaging metadata, the local check script, and the
docs.

## 2. P0 — a clean clone did not build

Fixed in this change, but worth recording because CI could not see it.

`web/.npmrc` sets `engine-strict=true`, and `web/package.json` pinned
`"engines": { "node": "24.x" }`. `build.rs` unconditionally runs `npm ci`, so on any
Node other than exactly 24.x, `cargo build` aborted:

```
npm error notsup Required: {"node":"24.x"}
npm error notsup Actual:   {"node":"v22.22.2"}
thread 'main' panicked at build.rs:136:9:
failed to install web dependencies
```

Three things made this worse than a version warning:

1. **No escape hatch.** `MICROCLAW_SKIP_WEB_BUILD=1` also panics when `web/dist` is
   absent, which it is on a fresh clone. There was no way to build at all.
2. **The pin was artificial.** The web UI builds and bundles cleanly on Node 22 once
   the engine check is bypassed. Nothing in the toolchain actually needed Node 24.
3. **`snap/snapcraft.yaml` pulls `node/22/stable`**, then runs the Rust plugin, which
   runs `build.rs`. The snap package could not build either — a shipped artifact,
   broken by the same pin.

CI pins Node 24 in every job, so CI stayed green while a fresh clone, the snap build,
and any contributor on Node 22 LTS all failed.

**Fix applied:** `"node": ">=22"`. Verified by deleting `web/node_modules` and
`web/dist` and running `cargo build` with no bypass on Node 22 — clean success. This
also stops the pin from breaking again when Node 25 and 26 land, which `24.x` would
have.

**Follow-up applied:** the web/docs CI job now runs as a matrix over both supported
Node LTS majors (22 and 24). Pinning every job to one Node major is what hid this.

## 3. P0 — the local quality gate was a no-op

`check.sh` is the project's own pre-push gate. It was:

```sh
                                  # no shebang
cargo test -q
npm --prefix web run build
npm --prefix website run build    # ENOENT: the directory is site/
node scripts/generate_docs_artifacts.mjs --check
```

Two independent defects:

- **Stale path.** `4e283cb` moved the docs site from `website/` to `site/` and updated
  `.github/workflows/ci.yml` and `scripts/generate_docs_artifacts.mjs`, but not
  `check.sh`, `deploy.sh`, `TEST.md`, or the release checklists. `deploy.sh` still ran
  `cd website`, so the docs deploy step was broken too.
- **No error propagation.** With no `set -e`, the script ran every line regardless of
  failure and exited with the status of the *last* command. `check.sh` returned 0 even
  when `cargo test` failed. A gate that always passes is worse than no gate.

**Fix applied:** added `#!/bin/sh` and `set -eu`, corrected `website` → `site` in
`check.sh`, `deploy.sh`, `TEST.md`, and the five release-checklist docs that carried
the stale command. Verified `npm --prefix site run build` succeeds.

## 4. P1 — 10 features are shipped but unreleased

`Cargo.toml` still reads `0.4.0`, the `v0.4.0` tag is at `a19482d`, and `main` carries
**21 commits** past it — including ten user-facing features with no `Unreleased`
section in `CHANGELOG.md`:

- Plan mode (`/plan`, ACP `plan` session mode)
- Headless one-shot CLI (`microclaw run -p`)
- API-key pool rotation on auth and rate-limit errors
- Per-chat model and provider overrides (`/model here`, `/provider here`)
- Context-pressure auto-compaction and overflow-error recovery
- Interactive approve/always/deny buttons for high-risk approvals
- `AfterTurn` hook event and opt-in post-edit self-recheck
- Unified diff rendering, progress bar, sub-agent lifecycle events, pinned status panel
- Reply-quote context forwarding
- Group-concise soul preset

**This is the single highest-value next step: cut v0.5.0.** The work is done, tested,
and documented in `CLAUDE.md` — it is simply not in anyone's hands. Every week it sits
on `main` is a week of finished work delivering nothing.

Two release-hygiene notes found while checking this:

- The `v0.4.0` tag predates `981cab9` ("harden v0.4.0 approval/alerts/trust-tier
  flows"). The `v0.4-lts` branch points at the hardening commit, so **the LTS branch
  is ahead of the tag it supports** — released v0.4.0 binaries lack fixes the LTS
  branch has. Worth a `v0.4.1` from the LTS branch.
- `fdc9a0f` and `743db66` are duplicate "API-key pool rotation" commits, a rebase
  artifact. Harmless, but squash before tagging.

## 5. P1 — frontend supply chain and bundle

`npm audit` on `web/`: **3 high, 1 moderate**.

| Severity | Package | Issue |
|---|---|---|
| HIGH | `vite` | path traversal in optimized-deps `.map` handling |
| HIGH | `postcss` | XSS via unescaped `</style>` in stringify output |
| HIGH | `nanoid` | non-secure generator loops indefinitely on negative size |
| MODERATE | `esbuild` | dev server accepts any origin's requests |

All were build-time rather than runtime in the shipped binary — the binary embeds
static `dist/` output. That lowers severity but does not eliminate it: a compromised
build step compromises the artifact.

**All four are now closed.** `postcss` and `nanoid` took a plain `npm audit fix`; the
remaining two needed the vite major, so the web UI moved to **vite 8 (rolldown) and
React 19**. `npm audit` now reports 0 vulnerabilities, `tsc --noEmit` is clean, and the
built bundle was loaded in Chromium to confirm the app mounts and renders with no
runtime errors — not merely that it compiles.

Bundle output was one chunk: **957 kB JS, 782 kB CSS**, with vite's own chunk-size
warning firing. It is now split into `react`, `markdown`, and `vendor` chunks, so the
stable vendor code caches independently of app code. Note that rolldown requires the
function form of `manualChunks`; the object-map form throws.

`web/src/main.tsx` is **4,927 of 8,010** frontend lines — 61% of the web UI in one
file. Splitting it is a precondition for anyone but the author working on the web UI
comfortably, and is left open.

## 6. P2 — structural debt in the Rust tree

Not urgent, and explicitly *not* something to start before v0.5.0 ships. Recording it
so it is a decision rather than a drift.

| File | Lines | Note |
|---|---|---|
| `crates/microclaw-storage/src/db.rs` | **17,178** | 12.8k production + 4.4k tests, **237 public methods** in one file |
| `src/setup.rs` | 11,276 | interactive wizard |
| `src/web.rs` | 6,775 | route handlers + streaming |
| `src/agent_engine.rs` | 5,904 | the core loop; size is somewhat inherent |
| `src/config.rs` | 5,387 | mostly a large but flat config surface |
| `src/llm.rs` | 5,280 | provider implementations + format translation |

`db.rs` is the one that genuinely matters. 237 methods on one type means every schema
change touches a file no reviewer can hold in their head, and it is the file most
likely to collect a subtle bug that tests do not cover. The crate boundary
(`microclaw-storage`) is already correct — the work is splitting the *inside* into
domain modules (sessions, memory, tasks, sub-agent runs, governance, usage) behind the
existing `Database` facade, which is a mechanical, test-covered refactor rather than a
redesign.

`setup.rs` at 11k lines for a config wizard is the clearest candidate for actual
deletion rather than reorganization — much of it is likely per-field prompting that a
schema-driven loop could generate from the config type.

## 7. P2 — docs and branch hygiene

- **14 roadmap documents** live under `docs/roadmap/` and `docs/roadmaps/`, spanning
  2026-02 to 2026-08, with no index marking which is current. A reader cannot tell
  `v0.4.0-plan.md` (delivered) from `capability-deepening-2026-h2.md` (aspirational).
  Add a `docs/roadmap/README.md` with a status column, and archive the delivered ones
  under `docs/roadmap/archive/`.
- **`docs/IMPLEMENTED.md`** is titled "branch: humanlike-chat-analysis" — a
  branch-scoped snapshot of a branch that merged long ago, sitting at a path that
  reads like an authoritative feature list.
- **79 remote branches**, mostly merged `claude/*` and `codex/*` work. Prune the
  merged ones; they make the branch list useless for finding live work.
- **14 RUSTSEC advisories** are suppressed in `deny.toml`. Unusually, each one *is*
  documented with a rationale and a removal condition — that is good practice and
  should be preserved. The task is a periodic sweep to retire the ones whose upstreams
  have since fixed, not to justify them.

## 8. Recommended order

Status reflects what landed in the change that added this document.

| # | Item | Status |
|---|---|---|
| 1 | Node LTS matrix in CI, so the §2 class of break cannot recur invisibly | **Done** |
| 2 | Frontend advisories: `postcss`, `nanoid`, then vite and esbuild | **Done** — 5 advisories to 0 |
| 3 | vite 5 → 8 and React 18 → 19 | **Done** — typecheck, build, and runtime verified |
| 4 | Chunk the embedded web bundle | **Done** — one 957 kB chunk to `react`/`markdown`/`vendor` |
| 5 | Docs-site contrast (see §10) | **Done** |
| 6 | Roadmap index; correct the misleading `IMPLEMENTED.md` scope | **Done** |
| 7 | `CHANGELOG` entry for the unreleased work | **Done** — finalized as `0.5.0 - 2026-08-16` |
| 8 | **Cut the release**: version bumped to 0.5.0 on the PR branch; tagging `v0.5.0` after merge is the maintainer's step | **Prepared** |
| 9 | **Cut v0.4.1** from `v0.4-lts` so released v0.4.x carries the hardening fixes | **Open — maintainer call** |
| 10 | Split `web/src/main.tsx` (4,927 lines) | **Done** — 2,373 lines, tabs and libs extracted, E2E-verified |
| 11 | Prune the 79 remote branches | Open |
| 12 | Decompose `db.rs` into domain modules behind the existing facade | **Delivered in 0.5.0** — see [`db-decomposition-plan.md`](./db-decomposition-plan.md) |

Items 8 and 9 are deliberately left open: choosing a version number and creating a
tag is a release decision, not a cleanup. The `CHANGELOG` is written and the tree is
green, so both are a short step whenever the maintainer wants them.

Item 12 is the one that needs a plan of its own before anyone starts typing.

## 10. Docs-site contrast

The public site defaulted to dark mode, and the dark palette was the source of a
"flat grey" impression. Three measurable causes, all fixed:

1. **No lightness ladder.** Page `#1a1b26`, alternating band `#202231`, and card
   `#24283b` sat within roughly 5% lightness of each other, so sections and cards
   melted into one field. They now step deliberately: `#0f1017` → `#161823` →
   `#212640`.
2. **No depth cues.** Every card carried `box-shadow: none` in dark mode. Cards now
   get a drop shadow *and* an inset top highlight, which is what actually reads as an
   edge against a near-black page — a drop shadow alone is nearly invisible there.
3. **Washed text and a haze overlay.** Body text was `#c0caf5` with secondary text at
   78% opacity, and the hero carried a grid overlay at `0.42` opacity. Text is now
   `#dce2f5` with secondary at 84%, and the grid sits at `0.24`.

The site's default color mode is now `light`; an explicit OS preference still wins, so
this only changes what a visitor with no preference sees first.

Verified by rendering the built site in Chromium at 1440×1000 in both themes, before
and after.

## 9. What this review did not find

Worth stating explicitly, because the absence is the story:

- No failing tests, no clippy suppressions hiding warnings, no formatting drift.
- No panic-happy production code — 5 `unwrap()`s total, none in a request path.
- No undocumented audit suppressions.
- No generated-docs drift.
- No `await_holding_lock` in production code; all five suppressions are in tests
  guarding environment variables.

The engineering discipline inside the Rust tree is high. The gap is that the machinery
*around* it — the build script's Node assumption, the local gate, the release cut —
was not held to the same standard, and CI's uniform Node pin hid the largest
consequence.
