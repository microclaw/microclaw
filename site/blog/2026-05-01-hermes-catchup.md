---
slug: /hermes-catchup
title: "Hermes Catch-up: User Model, Skill Lifecycle, Multimedia, Defensive Defaults — and Round 2 (Prompt Cache, Fuzzy Edit, Checkpoints, @-Refs)"
authors: [microclaw]
tags: [release, runtime, skills, memory, multimedia, security, performance, cost, checkpoints]
description: "Two consecutive Hermes-inspired releases. Round 1: per-chat user model, end-to-end skill lifecycle, cross-channel voice, multimedia tools, cross-conversation search, defensive-by-default web fetch. Round 2 (PR #342): Anthropic prompt caching, fuzzy edit_file matching, per-turn tool-loop guardrails, filesystem checkpoints + /rewind, @-prefix context references, and lazy subdirectory AGENTS.md hints."
---

The Hermes Catch-up release is MicroClaw's largest single-branch update so far: 37 commits, 8400 lines, 53 files. The headline number is misleading, though — what matters is which layers of the agent runtime got filled in.

The inspiration is [hermes-agent](https://github.com/nousresearch/hermes-agent) v0.10.0. Hermes runs on Python; several of its design decisions land more naturally on a Rust + SQLite stack: FTS5 ships with bundled SQLite, `cargo audit` / `cargo deny` lock dependency posture at compile time, and the artifact pattern (large tool result on disk, fetch slices by id) costs almost nothing in a single-binary deploy.

So this isn't a port — it's a re-application of patterns hermes already validated, drawn against MicroClaw's engineering boundaries.

<!-- truncate -->

## Per-chat user model (USER.md)

Memory in MicroClaw used to be one-dimensional: AGENTS.md plus structured rows, all retrieved on demand. But "who this user is" and "what this user is doing this week" should be different layers.

This release splits them:

- **per-chat USER.md** — a curated narrative of the user in this chat, written to `runtime/groups/{chat_id}/USER.md`, injected into the system prompt under a dedicated `<user_model>` block.
- **Reflector owns curation** — the agent doesn't write USER.md directly. The reflector runs an LLM call each tick that folds new signal into the existing narrative, returning `null` when nothing warrants rewriting.
- **`/user` command** — show the current narrative, or `/user clear` to reset.

USER.md has a hard cap (default 1500 chars, hermes uses 1375) so the curator is forced to summarize rather than append.

The split matters because user identity is high-reuse, low-update; specific memories are high-frequency and fragmentary. Mixing them either bloats the prompt or makes it hard to reliably recall the durable constraints. With the split, the user model lives at the top of the prompt; memories stay retrieval-on-demand.

Memory itself also gained:

- **Per-row TTL** — set an expiration on a memory; it stops surfacing after that. "Meeting on Sunday" shouldn't keep coming back two months later.
- **Recency decay** (default half-life 30 days) — older memories get down-ranked at retrieval time so newer signal naturally surfaces.

Both USER.md writes and memory writes go through a PII redact module first — emails, phone numbers, API key shapes, and card numbers are masked before persistence.

## Skill lifecycle

Skills used to be: agent activates, SKILL.md gets loaded into the prompt. End of story. This release pushes it into a real lifecycle:

- **agentskills.io spec compatibility** — SKILL.md frontmatter aligns to the [agentskills.io](https://agentskills.io) spec; legacy field names emit warnings.
- **Review at end of turn** — instead of waiting for the reflector tick, every turn triggers a review pass that decides whether the conversation produced a reusable skill.
- **Patch existing skills, not just create** — review can recognize that a solution overlaps with an existing skill and emit an edit instead of a duplicate.
- **Success-signal filter** — review only fires when the turn actually completed something, so we don't burn LLM calls on failed attempts.
- **Structured tool trajectory** — the review LLM reads a structured `(tool_name, input shape, success/fail)` trace, not the chat log. Signal density is much higher.
- **Activation tracking + auto-archive** — every activation is logged; skills idle for 30 days (default, configurable) auto-archive.
- **Retrieval-gated catalog** — the prompt-side catalog only includes the top-K best matches for the current query (default 3) instead of the full list.
- **Autonomous review default on** — previously opt-in.

The end-to-end loop is: user asks → agent solves with tools → end-of-turn review checks if it's worth a new skill or a patch → catalog retrieval surfaces the right skill next time → unused skills age out. What used to be ad-hoc decisions scattered across the codebase is now a single pipeline.

## Multimedia: hear, see, speak, draw

A complete multimedia tool suite:

| Tool | Purpose |
|---|---|
| `generate_image` | Text-to-image via OpenAI-compat `/images` |
| `describe_image` | Vision via vision-capable model |
| `text_to_speech` | TTS via OpenAI-compat `/audio/speech` |
| `transcribe_audio` | STT via OpenAI-compat `/audio/transcriptions` |

More important: voice goes all the way to channel ingress and egress.

- **Cross-channel inbound voice transcription** — Telegram, Discord, Slack, and Feishu adapters all transcribe inbound voice and feed the text into the agent loop as a normal user message. Mobile users get parity with text users.
- **Outbound TTS round-trip** (opt-in) — when the inbound was voice, the agent's reply gets synthesized to audio and shipped back through the same channel (Telegram uses native `send_voice` bubbles; Discord/Slack attach the file).

Round-trip is opt-in because each turn burns one extra TTS call.

A new `media.allowed_read_dirs` allowlist gates every media tool's local-file reads — preventing flows where the agent gets coaxed into feeding `~/.ssh` to a vision model.

## Cross-conversation recall + structured clarification

Two new tools, complementary:

- **`session_search`** — SQLite FTS5 full-text search over stored messages. The agent can find a project name or error string the user mentioned weeks ago. Schema migration adds the `messages_fts` virtual table plus INSERT/UPDATE/DELETE triggers, and backfills existing rows. Default scope is the caller's chat; cross-chat search requires explicit control.
- **`clarify`** — when a request is ambiguous, the agent asks a structured question: up to four predefined choices plus an automatic "Other". The question goes through the channel and the turn ends — the next user message is the answer. More controllable than free-form "do you mean A or B" because the channel can render it as buttons later.

`session_search` is exposed to subagents (read-only); `clarify` is main-agent only because it touches channel UI.

## Defensive-by-default

Several defaults shifted toward safer-out-of-the-box. Operators upgrading should review these:

- **`web_fetch.block_private_ips: true`** — refuses loopback / RFC1918 / CGNAT / link-local / ULA / cloud-metadata (169.254.169.254). Intranet deploys must add hosts to `allowlist_hosts` or set this `false`.
- **Redirect hook re-validates SSRF on every hop** — the initial URL isn't enough; every 302/307 is re-checked, defeating "public domain redirects to internal address" attacks.
- **robots.txt consultation** — `web_fetch` consults the target site's robots.txt before fetching.
- **`bash_dangerous_patterns`** — seven default regexes guard against `sudo`, `rm -rf /`, pipe-to-shell installers, `mkfs`, forkbombs, raw `dd if=`, and recursive root chmod/chown.
- **PII redact** — emails, phones, API key shapes, and card numbers are masked before USER.md / memory writes.
- **Bash command-content gate** — high-risk commands now show their literal contents in the approval preview, not an abstract risk classifier.

## Performance and cost control

- **Tool result cache** (schema v22) — keyed on `SHA256(tool_name + normalized input)`, opt-in per tool (e.g. `osv_check`). LRU + TTL.
- **Oversized result truncation + `fetch_artifact`** — when a tool returns more than 4000 chars (default), head and tail are kept inline and the full payload goes to `tool_result_artifacts` with a TTL. The agent calls `fetch_artifact` to slice into it. No more 100 MB grep results filling the context window.
- **Per-tool duplicate-call circuit breaker** — same tool with same input more than three times in a 10-step window is rejected. Breaks death loops.
- **Autonomous session titles** — a background LLM call titles each session after the first few user messages. Web UI history isn't a wall of "Untitled" anymore.

## Other new tools

- **`osv_check`** — queries [osv.dev](https://osv.dev) for advisories across npm / PyPI / crates.io / RubyGems / Maven / NuGet / Packagist / Hex / Pub / Go. MAL-* malware advisories are flagged separately.
- **`insights`** — usage summary over a trailing window: top tools, skill activations, token cost distribution.
- **`fetch_artifact`** — pairs with the truncation feature above.

## Operator quality of life

- **`doctor` diagnostics expanded** — now checks context cap, USER.md cap, and bash dangerous patterns config sanity, not just "the YAML parses".
- **Project-level context files** — drop any `.md` into `data_dir/runtime/groups/{channel}/{chat_id}/` and it gets concatenated into the system prompt (capped by `context_max_chars`, default 8000). A first-class home for "things this chat should always know".
- **New provider preset: Xiaomi MiMo** — five models (`mimo-v2.5-pro`, `mimo-v2.5`, `mimo-v2-pro`, `mimo-v2-flash`, `mimo-v2-omni`), OpenAI-compat protocol.

## Update — 2026-05-02: round 2 (PR #342)

Round 1 closed the biggest gaps in memory, skills, and multimedia. Round 2 goes back into hermes-agent and pulls six more patterns that earn their keep on a single-binary Rust runtime: cost control, recovery, and just-in-time context. Six new modules, fifty new tests, all opt-in or non-disruptive by default.

### Anthropic prompt caching (default on, free)

Anthropic's API accepts up to four `cache_control` breakpoints per request. MicroClaw now places one on the system prompt and one each on the last three messages, so the second turn re-uses the prefix from the first, the third re-uses the second's prefix, etc. On a multi-turn chat, the recurring input cost drops about 75%.

The implementation is JSON-mutation right before send: serialize `MessagesRequest` to a `serde_json::Value`, walk system + last 3 non-system messages, attach `cache_control: {"type": "ephemeral"}` to the last block of each. The typed `Message` / `ContentBlock` shapes stay clean, and the OpenAI-compatible path is untouched.

Two new config flags: `anthropic_prompt_cache_enabled` (default `true`) and `anthropic_prompt_cache_ttl` (`"5m"` default or `"1h"` if your key has extended-cache opt-in).

### Fuzzy `edit_file` matching

LLMs frequently hand `edit_file` an `old_string` that is "morally" right but byte-wrong: pasted with a different indent, copied through a tool transport that stripped trailing whitespace, smart-quoted by a doc renderer, or with `\n` written as the literal two characters instead of a newline. Each failed exact match wasted iterations.

The tool now retries through eight strategies in order and tells the model which one matched:

1. exact
2. line-trimmed (per-line `trim()`)
3. whitespace-normalized (collapse runs of spaces/tabs)
4. indentation-flexible (per-line `lstrip()`)
5. escape-normalized (`\n`/`\t`/`\r` → real chars)
6. trimmed-boundary (only first and last line trimmed)
7. unicode-normalized (smart quotes, em/en-dash, ellipsis, NBSP)
8. block-anchor (first/last line + middle similarity)

When a non-exact strategy matches, the implementation also runs an escape-drift check: if `new_string` contains literal `\'` or `\"` sequences and the matched region of the file does not, the patch is refused — that pattern is almost always a tool-call serialization artifact that would corrupt the source if written verbatim.

The strategy chain is borrowed from [hermes-agent's `tools/fuzzy_match.py`](https://github.com/nousresearch/hermes-agent/blob/main/tools/fuzzy_match.py), which itself adopted it from OpenCode.

### Per-turn tool-loop guardrails

The duplicate-call circuit breaker (`tool_repeat_window` + `tool_repeat_limit`) already short-circuits identical `(tool, args)` repeats. Round 2 adds two finer-grained signals as warnings (the result still goes back to the model, just with a hint appended):

- **Idempotent no-progress** — when a read-only tool (`read_file`, `grep`, `web_fetch`, `web_search`, `session_search`, …) returns the same result hash twice for the same arguments, the result gets a "this won't change, use what you have" suffix.
- **Same-tool failure streak** — when any tool fails three times in a turn, even with different arguments, the result gets a "change approach instead of retrying" suffix.

The new `IDEMPOTENT_TOOLS` constant in `src/tools/mod.rs` classifies thirteen read-only tools. The controller is reset per turn — guardrails are about *this turn*'s loop, not lifetime behavior.

### Filesystem checkpoints + `/rewind`

Once per agent turn, MicroClaw can run `git add -A && git commit` against a *shadow* git repo whose `GIT_DIR` lives outside the user's working tree (under `<data_dir>/checkpoints/<sha256(abs_path)[:16]>/`). The shadow repo isolates from `~/.gitconfig` (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`), so it never triggers signing prompts, hooks, or credential helpers — even if the user has aggressive global git config.

Two new chat commands:

- `/rewind` — list the most recent 20 snapshots for the current chat, newest first.
- `/rewind <commit>` — restore the chat's working dir to that snapshot. Hashes are validated as 4–64 hex chars to defeat git argument injection (e.g. `--patch` would otherwise be interpreted as a flag).

This is **off by default** (`checkpoints_enabled: false`) because it requires `git` on PATH and is most useful for code-editing chats. Once on, the agent never sees this — it's transparent infrastructure.

The pattern is borrowed from [hermes-agent's `tools/checkpoint_manager.py`](https://github.com/nousresearch/hermes-agent/blob/main/tools/checkpoint_manager.py).

### `@`-prefix context references

User messages can now include short references that get expanded server-side, before the LLM sees the message:

- `@file:src/main.rs` — full file contents.
- `@file:src/llm.rs:920-997` — line range.
- `@folder:src/tools` — one-level directory listing.
- `@diff` / `@staged` — output of `git diff` or `git diff --cached` against the chat's working dir.
- `@url:https://example.com/page` — fetched and HTML-stripped, capped at 64 KB.

The runtime rewrites the user message into `(stripped text) + --- Attached Context ---`, attaches the resolved blocks below, and passes the result to the agent. URL fetches reuse the SSRF guard from PR #335 (loopback, link-local, private, CGNAT, ULA, cloud-metadata all blocked, every redirect hop validated). File and folder references are gated by a sensitive-path block list — `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.azure`, plus dotfiles like `~/.bashrc`, `~/.netrc`, `~/.npmrc`, `~/.pgpass`. The block list walks `Path::components()` so it works on Windows too (an early Windows-CI failure surfaced this).

The pattern saves a `read_file` / `web_fetch` round-trip when the user clearly intends to give the agent a specific artifact. It's especially useful in the Web UI and Discord, where typing a path is faster than telling the agent to go look it up.

### Lazy subdirectory `AGENTS.md` hints

The system prompt loads the project root's `AGENTS.md` once at session start. But subdirectory-specific guidance (`backend/AGENTS.md`, `frontend/CLAUDE.md`, `infra/.cursorrules`) only mattered if the user mentioned it.

Now: when a tool call touches a subdirectory (via `path` / `file_path` / `workdir` / `cwd` arguments, or path-shaped tokens in a `bash` command), MicroClaw walks up to five ancestor directories looking for `AGENTS.md`, `CLAUDE.md`, or `.cursorrules`. The first hit (capped at 8 KB) is appended to that tool's result. Each directory is emitted at most once per turn, and the chat root is excluded — its hint is already in the system prompt.

The pattern is from hermes-agent's `agent/subdirectory_hints.py`, originally inspired by Block/goose's `SubdirectoryHintTracker`.

### Where this leaves us

Round 2 is mostly about the boring qualities of a long-running runtime: cost (prompt cache), reliability (fuzzy edit, guardrails, checkpoints), and just-in-time context (@-refs, subdir hints). None of them are headline features. All of them turn into "we kept it in production for another quarter" — exactly the layer that MicroClaw needs to keep filling in.

The full PR is [#342](https://github.com/microclaw/microclaw/pull/342) — 2,842 lines added, 56 lines deleted, six new modules, fifty new unit tests, and a single static Rust binary that still runs on a $5 VPS.

## Upgrade notes

A few things to check before merging into your deployment:

1. **DB schema advances irreversibly to v25** (migrations 21–25 are forward-only, from round 1). On first start, v21 backfills the FTS5 index — large message tables can take a few minutes. **Back up `data_dir/`'s SQLite file before upgrade.**
2. **If you use `web_fetch` against intranet services**, add hosts to `web_fetch_url_validation.allowlist_hosts` or set `block_private_ips: false`.
3. **If you have bash workflows that use `sudo` or `rm -rf`**, either change the workflow or set `bash_dangerous_patterns: []`.
4. **Autonomous skill review is on by default** — each turn now incurs an extra LLM call at the end. To disable, set `autonomous_skill_review: false` or `reflector_enabled: false`.
5. **Anthropic prompt caching is on by default** (round 2). If your provider proxy cannot accept `cache_control` markers in messages, set `anthropic_prompt_cache_enabled: false`. Real Anthropic and most compatible proxies (LiteLLM, OpenRouter Anthropic passthrough, Cloudflare AI Gateway) handle them transparently.
6. **`/rewind` and per-turn checkpoints are off by default** (round 2). If you want the safety net, set `checkpoints_enabled: true` and make sure `git` is on PATH inside whatever environment runs MicroClaw (containers included).

Existing `microclaw.config.yaml` files do not need changes — every new field has `#[serde(default)]` and the defaults match the descriptions above.

## How to think about this release

It isn't "we added N tools". It's MicroClaw moving from "a runtime that can call tools" toward "a runtime with a user model, a skill lifecycle, cross-conversation memory, multimedia ingress, explicit safety defaults — and now prompt-cache economics, edit-tolerance, loop guardrails, filesystem time-travel, and just-in-time context."

A lot of these look like quality-of-life polish (auto-titled sessions, voice ingress, the user model, the prompt cache, the checkpoint shadow repo). On long-running bots, they accumulate into the reason an operator is willing to keep MicroClaw in production — on a $5 VPS, no less.

Source: [microclaw/microclaw](https://github.com/microclaw/microclaw) · Round 1 PR [#335](https://github.com/microclaw/microclaw/pull/335) · Round 2 PR [#342](https://github.com/microclaw/microclaw/pull/342)
