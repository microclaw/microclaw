---
slug: /being-more-human-specialist-team
title: "Being More Human — and a Specialist Team Behind It: Chat Realism, Concurrent Specialists, 42 Built-in Skills, Graph-Augmented Recall"
authors: [microclaw]
tags: [release, runtime, skills, memory, agents, reliability]
description: "MicroClaw 0.2.x makes the bot feel human on the surface (short replies, multi-bubble, mood-adaptive tone, group etiquette) while a concurrent specialist sub-agent team does the hard work underneath — named tasks, mid-run progress reports, standup and fan-in summaries, specialist-to-specialist consults. Plus 30 new factory-ready built-in skills (42 total) and graph-augmented memory recall over the temporal knowledge graph. Outward-facing behaviors are gated and default-off."
---

The previous release ([Hermes Catch-up](/blog/hermes-catchup)) filled in the runtime's plumbing: a user model, a skill lifecycle, prompt-cache economics, checkpoints. This one is about something harder to measure and easier to feel — making MicroClaw behave like a *person*, and specifically like **a very capable person who happens to have a team behind them.**

The thesis, lifted from the design docs that drove this release: "being human" is two layers, and the magic is in the **contrast** between them.

> On the surface they chat with you casually, lightly, in short replies. But the moment you need something real, they quietly pull in a mathematician, an illustrator, a researcher — several lines running at once — and come back with "done, here's the answer."

MicroClaw used to be robotic on *both* layers: it dumped long answers up top, and although it could run sub-agents concurrently, it worked in silence until everything was finished. This release reworks both — and gates every outward-facing, proactive behavior behind a default-off switch.

<!-- truncate -->

## Surface layer: chatting like a human

The most impactful change is also the cheapest: **default to short.** Real chat is 90% one-or-two-sentence replies; long-form is the exception, unlocked only when you explicitly ask for "details / a plan / a tutorial."

- **Short-first, BLUF (bottom-line-up-front)** — written into `SOUL.md`'s chat-style section and a `Conversational style` block in the system prompt. Answer first, offer to expand.
- **Multi-bubble replies** — instead of one wall of text, the agent sends 2–3 short messages ("hang on" → "let me look" → "found it 👇"), reusing the existing `send_message` mid-conversation channel. The mechanism already existed; what was missing was telling the model to use it.
- **Mood-adaptive tone** — a new zero-cost heuristic layer (`src/mood.rs`, bilingual EN/中文, conservatively triggered) detects `frustrated / urgent / sad / confused / grateful / excited / playful` and injects a `<conversation_mood>` hint. **Personality stays stable (SOUL); tone flows with the moment (mood).** The two are deliberately separated.
- **Group etiquette** — in group chats the prompt injects "when to speak / when to stay silent": answer when @-mentioned, stay short, don't talk over people.
- **One question at a time, no filler.**

None of this changes *who* the bot is. It changes how relaxed it sounds.

## Deep layer: a concurrent specialist team

A capable professional isn't strong because they personally know everything — they're strong because they **route the right problem to the right expertise and keep several lines in flight.** That maps directly onto MicroClaw's sub-agent system, which this release upgrades from "one generic temp worker" into **a team of named experts.**

### Specialist profiles

Every sub-agent used to share one hardcoded system prompt and one restricted toolset. Now there's a small, extensible roster of **specialist profiles** (`src/tools/specialists.rs`), each a preset persona + tool subset:

| Specialist | Persona focus | Extra tools |
|---|---|---|
| 🧮 mathematician | step-by-step derivation, verify with code, show work | code exec |
| 🎨 illustrator | understand the visual brief, iterate on the prompt | `generate_image`, `describe_image` |
| 🔍 researcher | multi-source retrieval, cross-check, cite sources | `web_search`, `web_fetch` |
| 💻 coder | read/write code, run tests, minimal diffs | file tools, `bash` |
| ✍️ writer | structured writing, controls tone and length | memory/context |
| 📊 analyst | classify data, statistics, charts | code exec, file tools |
| 🧰 generalist | default catch-all | restricted set |

The main agent stays light and human in the foreground; when a sub-problem needs real horsepower, it **quietly** dispatches the right specialist (`sessions_spawn(specialist="mathematician", label="prove convergence", task=…)`), keeps chatting with you, and serves the conclusion in one line when it's done.

**Extensibility is the design goal:** adding a new specialist is one record in the roster — no change to the core loop. Music, translation, legal, slides… all become config later.

### Specialist-to-specialist consults

A specialist used to be on its own. New in this release ([#394](https://github.com/microclaw/microclaw/pull/394)): a bounded **`consult_specialist`** tool lets a sub-agent get an inline expert opinion from a *different* specialist — a single LLM round, no tools, no recursion, no chat side effects — instead of faking expertise it doesn't have. A researcher can ask the writer "how would you phrase this finding?" without spawning a whole new run. It works at any spawn depth and reuses the existing roster.

### Concurrent tasks with progress reporting

The concurrency itself was already production-grade (background `sessions_spawn`, a global semaphore, per-chat quotas, reliable completion-announce relay). What was missing was the *colleague-like* layer:

- **Named tasks** — `sessions_spawn` takes a human `label`; `subagents_list / info / kill / focus / send` all accept the label in place of a UUID. Now you can say "kill the competitor-pricing task" instead of pasting `subrun-7f3a…`.
- **Mid-run progress** — a sub-agent-only `report_progress` tool emits `📊 [label] (60%): …` at milestones, throttled by `subagents.progress_min_interval_secs` (45s) so it never spams. A toggle, `subagents.progress_reports` (default on), lets operators silence the chat-side relay while still recording to the timeline.
- **Standup** — an opt-in low-frequency loop that, for long-running tasks, posts a merged `🛰️ Still on it — N tasks running` digest per chat, with a rough **ETA** derived from the historical average run duration. Stalled tasks (past 2× the interval with no recent progress) get flagged `⚠️ no recent progress`.
- **Fan-in summary** — when every child of a parent run finishes, an opt-in `🧩` summary lands in one message.

Both standup and fan-in are **default-off**, because they're the bot speaking unprompted — and unprompted messages must earn their keep.

### What it looks like

```
You: check if this integral converges, sketch me a diagram, and see if our
     pricing holds up against competitors

Bot: on it — splitting this up 👀                         ← short, acknowledge
Bot: running convergence + the diagram in parallel, checking competitors now
     (quietly: sessions_spawn mathematician / illustrator / researcher)

     …(main agent keeps chatting, not blocked)…

Bot: 📊 [competitor-pricing] 3/5 checked — we're low at $29, B is $49     ← throttled progress
Bot: 🧮 [convergence] converges (ratio test), full steps sent your way    ← specialist done
Bot: 🎨 [diagram] here 👇 [image]                                          ← specialist done
Bot: pricing's still running, 2 left. BLUF: you've got room to raise.      ← short, BLUF
```

## 30 new factory-ready built-in skills (42 total)

A fresh install should already be a one-stop assistant — calculation, coding, research, planning, writing, diagrams, doc handling — without the user wiring anything up. This release adds **30 original built-in skills** on top of the existing 12, for **42 total**, across six batches:

- **Compute & data** — calculator, unit-converter, datetime, csv-tools, json-tools, sql, data-analysis
- **Coding** — code-review, regex, debugging, shell-scripting, api-design, testing, git
- **Research** — research, wikipedia, define (propagation-trace already shipped)
- **Planning** — planning, brainstorming, decision-matrix, meeting-notes, goal-setting
- **Creative & diagrams** — mermaid, color-tools, algorithmic-art, qrcode
- **Writing & productivity** — writing-editor, summarize, email-drafting, translate

Every skill is an **original `SKILL.md`** (the value of a skill is in its instructions, not borrowed code), embedded at compile time via `include_dir!` and auto-installed at runtime by compatibility. Skills that need an external command (git/jq/curl) carry fallback logic in their body, so nothing is silently skipped. Adding a skill remains a "drop a folder in `skills/built-in/`" operation — pure increment, no Rust changes, zero regression risk.

## Graph-augmented memory recall

MicroClaw has carried a temporal knowledge graph for a while, but it was only queried on demand through tools. This release ([#395](https://github.com/microclaw/microclaw/pull/395)) **activates it during recall itself.**

After the flat L0–L2 memory layers are assembled, recall seeds the KG from entities the query mentions, expands a **bounded 1–2 hops**, and injects the connected facts as a dedicated `# Connected` block in the prompt. It's **local-only** — no embeddings, no extra LLM call — bounded by hops / triple count / token budget, with a redundancy guard so it never repeats what L0–L2 already injected.

The mechanism: two new storage primitives, `kg_distinct_entities` and `kg_neighborhood` (a bounded BFS over the triple store), plus three default-on config knobs:

```yaml
memory_graph_recall_enabled: true   # activate KG expansion during recall
memory_graph_max_hops: 2            # bounded neighborhood radius
memory_graph_max_triples: 10        # cap injected connected facts
```

So if you mention a project, the recall can now surface the person who owns it and the deadline attached to it — relationships the flat memory layers wouldn't have ranked together.

## The honest parts: humanlike follow-ups, and what's still on the road

A couple of features close the gap between "scripted" and "lived-in":

- **Relationship familiarity** — derived from message history, the prompt gets a `# Relationship` hint: welcoming for brand-new chats, casual for long-running ones. (No hint in the middle — only the extremes are distinctive.)
- **Per-user adaptive growth** — the reflector now distills "how to work well with *this* person (what lands, what to avoid)" into the per-chat `USER.md`. It grows *toward each person*, without rewriting the stable personality.
- **Read-the-room humor timing** — a prompt-level principle tied to the mood signal: a dry joke is fine when things are relaxed and there's rapport; never when the user is frustrated, anxious, rushed, or the topic is serious.
- **Group interjection (default-off, throttled)** — an Inner-Thoughts-style loop that, in group chats where the bot wasn't @-mentioned, evaluates "is there something genuinely worth saying?" and either says one thing or returns SKIP. It captures the spirit of speaking up unprompted, while staying bounded and silent by default.

We wrote an essay about the line between done and not-done — ["How to Be a Human"](https://github.com/microclaw/microclaw/blob/main/docs/how-to-be-a-human.md) — and were deliberate about what we *didn't* simulate: forgetting, procrastination, sulking, faking competence. Reliability wins; those "human" traits we don't want.

## Upgrade notes

- **DB schema advances to v26** via additive `table_has_column` migrations (label / progress columns on `subagent_runs`). Forward-only; back up `data_dir/`'s SQLite file before upgrading, as always.
- **Every proactive / outward-facing behavior is default-off**: `subagents.standup.enabled`, `subagents.fan_in_summary`, `idle_checkin.enabled`, and `interjection` all default to `false`. Turn them on deliberately.
- **Graph-augmented recall is default-on** but local-only and bounded — no new cost. Set `memory_graph_recall_enabled: false` to opt out.
- **Mid-run progress reports are default-on** (`subagents.progress_reports: true`) but throttled; set to `false` to keep progress in the timeline without relaying to chat.
- Existing `microclaw.config.yaml` files need no changes — every new field has a `#[serde(default)]` and the defaults match the descriptions above.

## How to think about this release

It isn't "we added N features." It's MicroClaw learning to **relax on the surface and get deep underneath** — short, multi-bubble, mood-aware chat in front; a concurrent, named, self-reporting specialist team behind; a memory that now recalls relationships, not just facts. The contrast between those two layers is the whole point — it's what a very capable person actually feels like to talk to.

Source: [microclaw/microclaw](https://github.com/microclaw/microclaw) · Specialist team & skills [#391](https://github.com/microclaw/microclaw/pull/391) · Humanlike follow-ups [#392](https://github.com/microclaw/microclaw/pull/392) · Bounded research-hard traits [#393](https://github.com/microclaw/microclaw/pull/393) · `consult_specialist` [#394](https://github.com/microclaw/microclaw/pull/394) · Graph-augmented recall [#395](https://github.com/microclaw/microclaw/pull/395)
