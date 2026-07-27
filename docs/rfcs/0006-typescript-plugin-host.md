# RFC 0006: TypeScript Plugin Host

- Status: Draft
- Owner: runtime/plugins/security
- Created: 2026-07-26
- Related: [#463](https://github.com/microclaw/microclaw/issues/463)

## Decision Summary

MicroClaw should let plugin authors write ordinary TypeScript, but it should
not embed a JavaScript engine into the Rust process and should not treat a
language runtime's permission flags as a security boundary.

The proposed architecture is:

1. Authors write and type-check TypeScript against a versioned
   `@microclaw/plugin-sdk`.
2. Installation produces a locked, hashed JavaScript bundle; production does
   not resolve packages or run lifecycle scripts on startup.
3. A supervised, out-of-process plugin host communicates with MicroClaw over
   newline-delimited JSON-RPC on stdio.
4. Each plugin runs as principal `plugin:<plugin_id>` and receives explicit
   capabilities. Filesystem, network, secrets, subprocesses, and MicroClaw
   tools are default-deny.
5. Untrusted plugins require the existing container sandbox. Runtime
   permission flags are defense in depth, not the isolation boundary.

This preserves the current channel-neutral agent loop: TypeScript plugins
register tools, commands, and context providers at the same runtime boundaries
as manifest plugins.

## Why TypeScript

- It has a large library ecosystem and a familiar authoring experience.
- The same SDK can provide schema inference, generated JSON Schema, testing
  helpers, and editor completion.
- Plugins remain portable across MicroClaw installations because the Rust
  runtime sees a stable protocol rather than JavaScript implementation details.
- An out-of-process host contains crashes, memory leaks, event-loop stalls, and
  runtime upgrades without risking the core agent process.

## Current Baseline

MicroClaw currently loads YAML/JSON plugin manifests from
`<data_dir>/plugins`. A manifest can define:

- slash commands;
- dynamic tools;
- per-turn prompt/document context providers;
- command execution with host-only, sandbox-only, or dual policy.

The TypeScript design extends this surface. Existing manifests remain
supported and require no migration.

## Runtime Research

### Node.js

Node can execute TypeScript with erasable syntax directly, and type stripping
is stable in current releases. It does not read `tsconfig.json`, does not
type-check, and full TypeScript features still need a build step. Its stable
permission model can restrict filesystem, network, subprocess, workers,
native addons, WASI, FFI, and the inspector.

Node's own documentation is explicit that this is a "seat belt" for trusted
code, not protection from malicious code. Existing file descriptors and OS
process capabilities also matter. Therefore Node permissions are useful
defense in depth but cannot replace a container or OS sandbox.

References:

- [Node.js TypeScript modules](https://nodejs.org/api/typescript.html)
- [Node.js permission model](https://nodejs.org/api/permissions.html)

### Deno

Deno runs TypeScript directly and denies filesystem, network, environment, and
subprocess access by default. Permissions can be scoped to a path, host, or
environment variable, which closely matches the desired capability model.
Deno also warns that granting subprocess execution can escape the permission
model by launching a new unrestricted runtime.

Deno is a strong optional host adapter. It is not the initial mandatory
runtime because requiring a second runtime would complicate MicroClaw's small
deployment footprint and some npm packages still assume Node behavior.

References:

- [Deno security and permissions](https://docs.deno.com/runtime/fundamentals/security/)
- [Deno permission reference](https://docs.deno.com/runtime/reference/permissions/)
- [Deno compile and frozen lockfiles](https://docs.deno.com/runtime/reference/cli/compile/)

### Bun

Bun offers fast startup and direct TypeScript execution. Its default package
resolution can install missing packages automatically, which is unsuitable for
a deterministic production plugin host unless `--no-install` and a locked
artifact are enforced. It also does not currently provide the granular
default-deny runtime permission model required here.

Reference:

- [Bun runtime](https://bun.sh/docs/runtime)

### Protocol precedent

MCP demonstrates a practical local extension shape: the client launches a
subprocess, exchanges UTF-8 JSON-RPC messages over stdin/stdout, and keeps logs
on stderr. MicroClaw's plugin protocol can use the same transport conventions
without making every plugin a general MCP server.

Reference:

- [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## Proposed Package

```text
my-plugin/
  microclaw-plugin.json
  package.json
  package-lock.json
  tsconfig.json
  src/
    index.ts
  test/
    index.test.ts
```

Example manifest:

```json
{
  "apiVersion": "microclaw.dev/plugin/v1alpha1",
  "id": "com.example.release-notes",
  "version": "0.1.0",
  "entry": "src/index.ts",
  "permissions": {
    "microclawTools": ["read_file", "grep"],
    "fsRead": ["workspace"],
    "fsWrite": [],
    "net": ["api.example.com"],
    "secrets": ["EXAMPLE_API_TOKEN"],
    "subprocess": false
  }
}
```

Example authoring API:

```ts
import { definePlugin, z } from "@microclaw/plugin-sdk";

export default definePlugin({
  tools: {
    summarizeRelease: {
      description: "Summarize release notes from the current workspace",
      input: z.object({ path: z.string() }),
      async execute(input, context) {
        const text = await context.files.readText(input.path);
        return { content: summarize(text) };
      },
    },
  },
});
```

The SDK exposes mediated `context.files`, `context.fetch`,
`context.secrets.get`, and `context.tools.call` APIs. It does not hand plugins
the core database, channel registry, raw credentials, or an in-process Rust
handle.

## Wire Protocol

Transport is newline-delimited JSON-RPC 2.0 over stdio. Stdout is protocol
only; diagnostics go to stderr. Every request has bounded size and a deadline.

Initial methods:

- `initialize`: negotiate protocol version, SDK version, plugin identity, and
  granted capabilities;
- `plugin/list`: return tool, command, and context-provider definitions;
- `tool/call`: execute one registered plugin tool;
- `command/call`: execute one registered slash command;
- `context/provide`: produce bounded per-turn context;
- `host/fetch`, `host/files/*`, `host/secrets/get`, `host/tools/call`: request
  a capability through the Rust host;
- `health`, `shutdown`: supervision lifecycle.

Every call carries a request id, chat/channel identity, principal, deadline,
and cancellation token. Responses use typed error codes and never mix logs
with protocol output.

## Security Model

### Principal and grants

Each plugin is a distinct principal: `plugin:<id>`. Calls into the shared tool
registry use the existing per-chat/per-principal grant evaluator. A plugin
grant cannot weaken a global tool-policy block.

### Filesystem

- No arbitrary host filesystem access.
- Plugin bundle is mounted read-only.
- A per-plugin temporary directory may be writable.
- Workspace reads/writes are mediated and checked by MicroClaw's path guards,
  chat isolation, and declared manifest capability.

### Network

- The plugin process starts without direct network access.
- `context.fetch` asks the Rust host to perform a request.
- The host evaluates `egress_policy`, resolves DNS, checks every redirect,
  applies size/time limits, and records an audit event.
- Direct network access is only an explicit operator escape hatch and requires
  a sandbox profile that can enforce the declared network policy.

### Secrets

- The child process inherits a minimal environment.
- Plugin manifests name secret references, never secret values.
- `context.secrets.get` returns only explicitly granted values and is audited.
- Secrets are redacted from logs, protocol traces, crash reports, and cached
  results.
- The existing sandbox credential allowlist remains a compatibility escape
  hatch for command-style plugins, not the preferred TypeScript API.

### Subprocesses and native code

- Child processes, native addons, FFI, WASI, workers, and the inspector are
  denied by default.
- A subprocess grant is high risk and requires a container plus explicit
  operator approval.
- Node permission flags are applied, but container/OS isolation remains the
  security boundary.

### Resource and lifecycle limits

- Per-call timeout and cancellation;
- process memory, CPU, PID, and output limits;
- restart budget with exponential backoff;
- health checks and circuit breaking;
- bounded concurrent calls per plugin;
- protocol and stderr truncation with artifact retention for diagnostics.

## Supply Chain and Build

Installation is a separate, reviewable phase:

1. Require `package-lock.json`.
2. Run a frozen install (`npm ci`) with lifecycle scripts disabled by default.
3. Type-check against the supported SDK.
4. Bundle production code and exclude undeclared native modules.
5. Produce a manifest containing bundle hash, lockfile hash, SDK/protocol
   versions, requested capabilities, and source provenance.
6. Run static injection/secret scans and the plugin test suite.
7. Store the immutable artifact under the plugin cache and require an explicit
   activation step.

The current npm CLI supports frozen installs and explicit lifecycle-script
policy. Package provenance/signature verification can be added without
changing the runtime protocol.

References:

- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/)

Production startup never runs `npm install`, downloads dependencies, rewrites
the lockfile, or executes package lifecycle hooks.

## Why Not WASM

This RFC deliberately does not use WASM:

- the user requirement is a native TypeScript authoring experience;
- npm/Node interoperability matters for the intended plugin ecosystem;
- a process boundary already provides crash containment and runtime
  replaceability;
- capability mediation and container isolation address the security boundary
  without forcing authors through a WASM toolchain.

WASM could remain useful for a future narrow compute extension, but it is not
the TypeScript plugin architecture.

## Delivery Plan

### Phase 1: SDK and deterministic build

- Publish versioned SDK types and JSON Schema.
- Add `microclaw plugin create|build|validate|inspect`.
- Require lockfile, disable install scripts by default, type-check, bundle, and
  hash artifacts.
- Add golden protocol and compatibility fixtures.

### Phase 2: supervised plugin host

- Add host process lifecycle, stdio JSON-RPC, deadlines, cancellation, crash
  backoff, and health reporting.
- Register TypeScript tools/commands/context providers through current shared
  registries.
- Run each plugin as `plugin:<id>`.

### Phase 3: mediated capabilities

- Add host filesystem, fetch, secret, and tool-call services.
- Enforce path, egress, grant, approval, redaction, and audit policies.
- Require sandbox isolation for untrusted plugins.

### Phase 4: distribution and ecosystem

- Add immutable plugin packages, provenance/signature verification, update and
  rollback lifecycle, compatibility checks, and ClawHub integration.
- Add templates, test harness, local development watch mode, and diagnostics.

## Compatibility and Migration

- Existing YAML/JSON manifest plugins continue to work unchanged.
- TypeScript plugins use a new manifest `apiVersion` and cannot be silently
  interpreted as command manifests.
- Operators can disable the TypeScript host globally.
- Protocol negotiation rejects incompatible hosts before loading definitions.
- An immutable prior artifact remains available for rollback.

## Testing and Acceptance

Before declaring TypeScript plugins production-ready:

1. Golden JSON-RPC tests cover every method, error, cancellation, and version
   mismatch.
2. Crash-loop tests prove the Rust runtime stays responsive and disables an
   unhealthy plugin.
3. Security tests prove default denial of host files, network, env/secrets,
   subprocess, native addons, and cross-chat tool access.
4. Egress tests cover DNS rebinding-resistant resolution and every redirect.
5. Supply-chain tests reject missing/drifted lockfiles, lifecycle scripts,
   mutable artifacts, and hash mismatches.
6. Compatibility tests run supported Node releases on Linux, macOS, and
   Windows.
7. Benchmarks report cold start, steady-state call latency, memory per plugin,
   and 100-plugin catalog behavior.

## Open Questions

1. Ship a small Node host with MicroClaw releases or require an operator
   installed Node LTS?
2. One process per plugin for strongest isolation, or a reviewed process pool
   for lower idle memory?
3. Should Deno become a first-class host adapter in Phase 2 or after the Node
   protocol is stable?
4. Which package registry/provenance format should ClawHub require?
5. Should direct-network escape hatches be prohibited entirely for marketplace
   plugins?
