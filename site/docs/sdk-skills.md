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

The catalog is refreshed on demand. Show
`description`, `source`, and `version` where available. Disable unavailable
Skills in the UI and surface `unavailable_reason` instead of letting a run fail
later.

## Manage Skills without restarting

```rust
let installed = microclaw.install_skill("owner/repository/skill").await?;
let catalog = microclaw.set_skill_enabled("code-review", false)?;
let catalog = microclaw.reload_skills()?;
let removed = microclaw.remove_skill("old-skill")?;
println!("Archived at {}", removed.archived_at.display());
```

Use `install_local_skill(path)` for a local directory. Local imports are staged,
reject symbolic links, and pass injection scanning before replacing an existing
package. Removal is recoverable: the package moves under `.archived/`.

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
- Refresh the catalog after external filesystem changes; SDK lifecycle methods
  refresh it automatically.
- Keep import, review, activation, and selection as distinct actions.
- Apply MicroClaw's existing audit and policy gates rather than inventing a
  second trust model in the host UI.

For the package format and governance model, read [Skills](./skills),
[Skill architecture](./architecture-skills), and [ClawHub](./clawhub).
