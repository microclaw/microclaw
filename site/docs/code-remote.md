---
id: code-remote
title: Run tasks on a MicroClaw Server
sidebar_label: Remote Server
---

# Run tasks on a MicroClaw Server

`mccode` can send a task to a MicroClaw Server instead of running it locally.
The task then runs on the Server's machine, in its working directory, with its
tools, model and approval policy; `mccode` streams the result back. This is
useful when the code, credentials or hardware live on another machine.

## Pair once

1. On the Server, open the web console, go to **Access** and create a pairing
   code.
2. On your machine:

   ```sh
   mccode remote pair https://server.example.com <code>
   mccode remote status     # shows the paired Server
   ```

Pairing trades the single-use code for a device token. The token is stored in
`~/.mccode/remote.json` (readable only by you) and can be revoked from
the Server's Access tab. `mccode remote forget` deletes it locally.

## Run a task

```sh
mccode -p "run the nightly data check and summarise failures" --remote
mccode -p "…" --remote --json            # runtime events as JSON Lines
```

The output and exit codes are the same as for a local `-p` run; Ctrl+C
cancels the run on the Server. Runs from the same folder share one Server
session (`mccode-<folder name>`), so a follow-up task sees the earlier
conversation. Pick another one with `--session <key>`; `-p -` reads the task
from stdin.

## Approvals

When the Server's policy needs a person for a command, the run stops with exit
code `2` and prints the session key. Answer it with:

```sh
mccode -p 1 --remote --session <key>     # approve once
mccode -p 3 --remote --session <key>     # deny
```

The Server's own approval rules apply; local permission modes, allow rules
and the local sandbox do not.
