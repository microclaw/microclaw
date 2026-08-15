---
id: scheduler
title: Scheduler
sidebar_position: 8
---

MicroClaw includes a background scheduler that runs every 60 seconds and executes due tasks.

## Task types

- Recurring tasks via cron expressions
- One-time tasks at a specific timestamp

## Cron format

MicroClaw uses 6-field cron expressions:

```
sec min hour dom month dow
```

Example: every 5 minutes

```
0 */5 * * * *
```

## How it runs

1. Poll `scheduled_tasks` where `status = 'active'` and `next_run <= now`
2. For each due task, call the agent loop with the stored prompt
3. Send the response to the original chat
4. Update `next_run` (cron) or mark as `completed` (one-time)

`next_run` is normalized and stored as UTC RFC3339 timestamps for both cron and one-time tasks.

## Manage tasks

```
"List my scheduled tasks"
"Pause task #3"
"Resume task #3"
"Cancel task #3"
```
