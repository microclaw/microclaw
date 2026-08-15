---
slug: /microclaw-february-2026-updates
title: "MicroClaw Feb 19: What Changed in the Past Week"
authors: [microclaw]
tags: [architecture, agents, rust, chat]
---

MicroClaw has moved quickly in February, with significant updates across ClawHub integration, voice handling, path compatibility, modularization, web/auth hardening, and release automation.

This post summarizes the direction and outcomes based on the **50 most recent commits** on `main`.

<!-- truncate -->

## Scope and Time Window

This update covers the most recent 50 commits up to **February 19, 2026**.

At a high level, the work clusters into six tracks:

- ClawHub and skills lifecycle
- provider/runtime compatibility
- config/path compatibility and migration safety
- web/auth/ops hardening
- modular crate boundaries and codebase cleanup
- release and deployment reliability

## 1) ClawHub: From Initial Integration to Production-Friendly Flow

The registry path is now substantially more practical.

Key outcomes from this cycle:

- `microclaw skill` command set is usable for search/install/list/inspect workflows
- async runtime panic scenarios were removed in CLI/tool execution paths
- transient failures now have retry behavior in key flows
- `/reload-skills` support was added in multiple channels to reduce restart dependency
- follow-up fixes corrected install result semantics and endpoint behavior

Operationally, this means less friction for skill discovery and activation, and fewer false-positive install states.

## 2) Voice Transcription: Cloud + Local Execution Modes

Voice handling now supports both hosted and local execution paths.

Highlights:

- OpenAI remains the default provider path
- local command-based transcription is now configurable
- failure-path cleanup was tightened to avoid temp-file leaks

This gives teams more flexibility in privacy/performance/cost tradeoffs while preserving a simple default for most users.

## 3) Path and Data Compatibility: Hardening After Real-World Merge Pressure

A major focus in the follow-up work was preventing path regressions.

Important corrections included:

- restoring dynamic `data_dir` behavior for skills/lockfile defaults
- aligning assertions and cross-platform path expectations
- clarifying skills source layout (`skills/built-in`) vs runtime state layout

Net effect: upgrades are safer for existing deployments that already depend on custom data roots.

## 4) Runtime and Provider Compatibility

The runtime also received compatibility-focused cleanup:

- DeepSeek/tool-call behavior fixes
- replacement of brittle model-name checks with provider capability flags
- improved LLM/provider conventions in docs to reduce future drift

This lowers maintenance risk as provider APIs evolve.

## 5) Web/Auth/Ops and Modularity Progress

Beyond feature work, a lot of value in this batch is structural:

- auth/metrics and config self-check hardening
- web handler refactors and module split cleanup
- continued modular extraction into workspace crates (`core/storage/tools/channels/app`)
- removal of temporary wrappers/shims after migration milestones

These changes improve long-term maintainability and make feature iteration less risky.

## 6) Release and Delivery Cadence

This period also included active release execution work:

- version bumps through `0.0.83`, `0.0.85`, `0.0.86`
- release/build script refinements
- Homebrew tap updates and release packaging flow maintenance

The direction is clear: keep shipping while steadily tightening quality gates and deployment repeatability.

## What to Expect Next

Given this trajectory, near-term priorities are likely to continue around:

- ClawHub reliability and skill lifecycle UX
- cross-channel consistency in runtime behavior
- deployment smoothness and fewer manual release interventions
- further simplification after modularization milestones

---

## Appendix: 50 Recent Commits Covered

- `1a67c37` chore: trigger CI for release 0.0.86 finalize
- `4b8f7b1` bump version to 0.0.86
- `d6a030e` Merge pull request #45 from microclaw/fix/pr44-followup
- `7d2aba1` fix ignore
- `30e00f4` mv skill dir
- `94dcfe9` docs: regenerate config defaults artifact
- `8c30d3d` fix: follow up PR44 path and clawhub install regressions
- `0ab79bc` Merge pull request #44 from klampatech/feature/clawhub-integration-fixes
- `45e1ddf` chore: remove test artifacts from PR
- `039c11f` bump version to 0.0.85
- `60fb947` docs: add llm provider capability-based conventions
- `c09a3bc` Merge origin/main into feature branch and resolve conflicts
- `10ae7b6` refactor(llm): replace DeepSeek model-name checks with provider capability flags
- `a933732` Merge pull request #43 from mission-deny-the-mission/fix/deepseek-reasoning
- `bf4fb7e` feat(clawhub): integrate ClawHub skills and add local voice transcription
- `d49b1a3` Merge pull request #42 from microclaw/feature/ops-hardening-feb19
- `40516fd` Fix windows path assertions and document path compatibility
- `98e67c9` Improve skill availability diagnostics and filtering
- `3606842` Move built-in skill sources to skills/built-in
- `9715f8a` Update working_dir default to home-based path
- `5597f39` Simplify data/skills path logic without env overrides
- `5068792` fix deepseek reasoning/tool-call compatibility
- `65567cd` Default data_dir to ~/.microclaw when not configured
- `82351af` Add configurable skills_dir override
- `216dac9` Harden web metrics/auth flow and adopt ~/.microclaw skills home
- `7456f0c` Merge pull request #41 from microclaw/codex/fix-clawhub-pr39
- `7053399` refactor clawhub config, test templates, and gateway adapter
- `bf6d7b7` extract clawhub core into microclaw-clawhub crate
- `d85f226` update generated config defaults and include clawhub fixes
- `5852ffa` fix clawhub merge fallout and restore lint clean
- `3d95bec` Merge pull request #39 from klampatech/feat/clawhub-integration
- `e58a244` Merge branch 'feature/clawhub-init-v0' into feat/clawhub-integration
- `432e2aa` bump version to 0.0.83
- `6185b81` Merge pull request #40 from microclaw/feature/auth-feature
- `d80571e` Fix legacy sessions schema index init ordering
- `5fd4314` Add merge notes and rollback steps to upgrade guide
- `4f278a8` Use platform hook scripts in hook block test
- `c8a3a8e` Fix Windows hook block test command quoting
- `450c77c` Add config self-check UI and split web config/stream modules
- `b2df265` Refactor web handlers and harden config/OTLP checks
- `1215d2a` lots of features
- `f5ca180` bump version to 0.0.82
- `faa2ad6` chore: trigger CI on main
- `8e11fba` feat(clawhub): complete ClawHub integration v1
- `3d59af4` bump version to 0.0.81
- `4083f56` docs: align architecture and runtime docs with crate layout
- `e33288f` Merge pull request #38 from microclaw/pr/final-cleanup-remove-usage-wrapper
- `eb96f48` refactor(storage): remove usage wrapper module and use storage usage API directly
- `e07bf93` Merge pull request #37 from microclaw/pr/finalize-modularity-boundaries
- `5780822` refactor(modularity): finalize crate imports and remove legacy shim modules
