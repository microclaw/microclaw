---
id: sdk-skills
title: Skills in embedded apps
description: Discover, validate, and select MicroClaw Skills through the Rust SDK.
---

# Skills in embedded apps

Skills are instruction packages discovered when the full runtime starts. The
SDK exposes a UI-neutral catalog so a host can list them, explain unavailable
entries, and attach selected Skills to an Agent.

## Choose where Skills live

By default, the full runtime follows MicroClaw's configured data directory. An
embedded application can point to its own managed directory:

```rust
let microclaw = MicroClaw::configure(config)
    .data_dir("./app-data")
    .skills_dir("./app-data/skills")
    .build()
    .await?;
```

Each Skill directory contains a `SKILL.md`. Keep the selected directory inside
the application's intended data boundary and apply the same review policy you
would use for executable extensions.

## Build a Skill picker

```rust
for skill in microclaw.skills().all() {
    println!(
        "{} | available={} | {}",
        skill.name,
        skill.available,
        skill.unavailable_reason.as_deref().unwrap_or("ready"),
    );
}
```

The catalog is a snapshot created during runtime initialization. Show
`description`, `source`, and `version` where available. Disable unavailable
Skills in the UI and surface `unavailable_reason` instead of letting a run fail
later.

## Select Skills for an Agent

```rust
let reviewer = microclaw
    .agent("reviewer")
    .system_prompt("Review changes and explain concrete risks.")
    .skill("code-review")
    .build()?;
```

Agent construction validates every selected Skill. An unknown or unavailable
Skill returns `SdkError::SkillUnavailable` before execution begins.

## Product guidance

- Let users select Skills per Agent, not per individual event.
- Preserve Skill IDs in application state; treat display descriptions as copy.
- Rebuild the runtime after installing or removing Skills so the catalog is
  refreshed predictably.
- Keep import, review, activation, and selection as distinct actions.
- Apply MicroClaw's existing audit and policy gates rather than inventing a
  second trust model in the host UI.

For the package format and governance model, read [Skills](./skills),
[Skill architecture](./architecture-skills), and [ClawHub](./clawhub).
