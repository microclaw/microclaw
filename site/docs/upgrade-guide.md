---
id: upgrade-guide
title: Upgrade Guide
sidebar_position: 24
---

Use this guide for rolling upgrades that may include schema, authentication,
hooks, session, or metrics changes. See also the
[PR and Release Checklist](./release-checklist).

## Before upgrading

1. Back up `microclaw.db`.
2. Save the current `microclaw.config.yaml`.
3. Record the running binary or image version and commit SHA.
4. Confirm that `sh` is available if hooks are enabled.

## Upgrading to v0.3.4

v0.3.4 advances the SQLite schema to v43. The migration adds Learning Foundry
tracks, epochs, immutable skill candidates, paired candidate evaluations, and
per-scenario trial records.

Existing chats, memories, skills, and scheduler records are preserved. No
configuration changes or manual SQL steps are required. Older binaries cannot
reverse these forward-applied tables, so restore the database backup if a
rollback is necessary.

Learn how the new governed learning pipeline works in
[Learning Foundry](./learning-foundry).

## Post-upgrade validation

1. Check `GET /api/health`.
2. Check `GET /api/auth/status`.
3. Check `GET /api/sessions/tree`.
4. Check `GET /api/metrics`.
5. Check `GET /api/config/self_check` and resolve unaccepted `high` warnings.
6. Start a long-running chat request, send `/stop`, and verify it is aborted.
7. Verify `/reset` still clears session context and chat history.

## Rollback

1. Stop the new process.
2. Restore the previous binary or image.
3. Restore the pre-upgrade `microclaw.db` backup.
4. Restore the previous configuration.
5. Start the old version and verify health, authentication, and sessions.

Do not partially reverse migration SQL by hand.
