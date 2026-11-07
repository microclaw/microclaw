# ACP Registry entry

[The ACP Registry](https://github.com/agentclientprotocol/registry) is how Zed
(and JetBrains and other ACP clients) install external agents. MicroClaw Code
is listed as `mccode`, distributed as the release's `mccode` archives and run
as `mccode acp`; its sign-in is terminal auth (`mccode setup`).

After a release, generate the entry and open a pull request against a fork
of the registry:

```sh
scripts/acp_registry_entry.py 0.27.0 /path/to/registry-fork/mccode
```

The script reads the release's `SHA256SUMS.txt`, so run it once the release
assets are published. Once listed, the registry picks up new GitHub releases
by itself every hour; a manual pull request is only needed to change the
description, platforms or icon. `icon.svg` follows the registry rules
(16×16, monochrome `currentColor`).
