# RFC 0007: Plugin Host Runtime Decision — wasmtime Spike

- Status: Proposed
- Owner: runtime/plugins/security
- Created: 2026-08-07
- Related: [RFC 0006](./0006-typescript-plugin-host.md),
  [`../roadmap/v0.4.0-plan.md`](../roadmap/v0.4.0-plan.md) (WS-D)

## Decision Summary

**Hold the RFC 0006 course**: the TypeScript plugin architecture remains a supervised
out-of-process Node host over stdio JSON-RPC, with container/OS isolation as the security
boundary. A wasmtime component-model host is **not** adopted for TypeScript plugins, but is
**reserved as the designated architecture for a future narrow "compute skill" extension
point** (pure functions over bytes, no ambient I/O), and this RFC defines the trigger
conditions that would reopen the decision.

This document exists because ZeroClaw v0.8.3 shipped a wasmtime component-model plugin host
in a Rust runtime comparable to ours, which invalidated the "nobody does this in practice"
shortcut and obligated an explicit comparison before RFC 0006 Phase 1 starts.

## What the comparison covered

Assessed dimensions, with the honest evidence level for each:

| Dimension | Node stdio host (RFC 0006) | wasmtime component host | Evidence |
|---|---|---|---|
| TypeScript authoring | Native: tsc + npm, any library | Via `componentize-js`/`jco`: StarlingMonkey JS engine compiled to a component; subset of Node APIs, no native addons, npm compatibility partial | documented toolchains |
| Capability mediation | Host-mediated JSON-RPC (`host/fetch`, `host/files/*`, …); language runtime flags are defense-in-depth only | WASI preview-2 capabilities are *structurally* default-deny: no ambient filesystem/network exists unless a host import is provided | documented; wasmtime's model is genuinely stronger here |
| Security boundary | Process + container; kernel attack surface applies | In-process sandbox with a small, auditable import surface; no kernel syscall surface exposed to guest | documented |
| Crash containment | Process exit; supervisor restarts | Trap unwinds into host `Result`; store poisoned, instance dropped | documented |
| Cold start | Node process spawn + require graph: ~50–200 ms typical | Precompiled module instantiation: sub-ms to low-ms | documented ranges — **must be re-measured in Phase 1 benchmarks on our workloads** |
| Idle memory per plugin | One Node process each (tens of MB) unless pooled | One store per instance (small); engine shared | documented — same caveat |
| Build determinism | `npm ci` + frozen lockfile + bundle hash (RFC 0006 supply chain) | Compiled `.wasm` artifact is inherently a single hashable immutable object | wasm slightly simpler, both adequate |
| Ecosystem reach | Full npm (the stated user requirement in RFC 0006) | Excludes native addons, most of Node's stdlib surface, many popular packages | decisive |
| Windows/macOS/Linux | Node LTS everywhere | wasmtime everywhere; toolchain (jco) needs Node anyway for JS plugins | neutral |
| Maintenance cost | JSON-RPC protocol + supervisor (moderate, all in our control) | wasmtime + component tooling churn (WASI preview evolution) | wasm ecosystem still moving |

No in-repo code spike was run for the wasm path in this pass; the numbers above are from
the projects' own documentation and are directionally consistent across sources. The
Phase-1 benchmark suite in RFC 0006 ("cold start, steady-state call latency, memory per
plugin, 100-plugin catalog") is hereby extended to record the same metrics for a minimal
wasmtime harness, so the next revisit argues from our numbers, not vendors'.

## Why the process host still wins for TypeScript plugins

1. **The requirement is npm-ecosystem TypeScript, and the wasm JS story cannot deliver it.**
   `componentize-js` embeds a non-Node JS engine; the moment a plugin author `npm install`s
   a package with native bindings, Node API internals, or worker threads, it breaks. RFC
   0006's whole premise is "authors write ordinary TypeScript" — a host that works for a
   curated subset of npm silently converts every incompatibility into our support burden.
2. **Our security boundary does not get weaker by staying out-of-process.** WASI's
   structural default-deny is elegant, but MicroClaw's threat model already refuses to
   treat the language runtime as the boundary: capabilities are mediated by the Rust host
   over the protocol, and untrusted plugins require the container sandbox. The marginal
   security win of wasm is real but small *given our architecture*; the ecosystem loss is
   large.
3. **ZeroClaw's host proves feasibility, not fit.** Their plugin surface is
   Rust/WIT-centric with JS as a guest option; their ecosystem bet is different. An
   existence proof that wasmtime hosting works in Rust was never in doubt — the open
   question was the npm story, and it remains the blocker.

## What wasm is reserved for

A future **compute skill** extension point — deterministic, CPU-bound transforms
(parsers, converters, scoring functions) delivered as `.wasm` components with no I/O
imports — is a better fit for wasmtime than for a Node process: single-file immutable
artifact, sub-ms instantiation, structurally no ambient authority, trivially safe to run
from ClawHub with only a hash check. This is deliberately out of scope for v0.4.0; it
becomes worth building the first time a real skill needs sandboxed compute that the
manifest-plugin `command` surface can't express safely.

## Revisit triggers

Reopen this decision if any of the following becomes true:

- The Phase-1 benchmark shows the Node host cannot meet targets (cold start >500 ms p95 or
  per-plugin idle memory that makes a 20-plugin catalog exceed ~1 GB) *and* pooling doesn't
  fix it.
- `jco`/StarlingMonkey reaches practical parity for mainstream npm packages (no native
  addons required by the top plugin use cases).
- A marketplace-driven requirement appears for running *fully untrusted* plugins without a
  container runtime available (the $5-VPS-no-Docker case) — wasm's in-process sandbox is
  the only credible answer there.
- WASI preview 2+ stabilizes threads/sockets in a way that materially changes the
  capability story.

## Consequences

- RFC 0006 Phase 1 (SDK + deterministic build) can start without architectural risk.
- The RFC 0006 open question #2 (process per plugin vs pool) inherits the benchmark
  obligation defined here.
- ClawHub artifact format work should keep the manifest generic enough to describe a
  `.wasm` compute-skill artifact later (`artifact_kind` field), which costs nothing now.
