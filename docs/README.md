# MicroClaw Documentation

This page is the map for MicroClaw's technical documentation. Start with the shortest path that matches your goal; generated references remain the source of truth for facts that change with the code.

## Start here

| Goal | Read this |
|---|---|
| Install and launch MicroClaw | [Getting started](getting-started.md) |
| Learn by example | [Cookbook](cookbook.md) |
| Diagnose a running deployment | [Operations runbook](operations/runbook.md) |
| Upgrade an existing deployment | [Upgrade guide](releases/upgrade-guide.md) |
| Contribute code | [Development guide](../DEVELOP.md) and [contribution guide](../CONTRIBUTING.md) |

## Reference

These pages are generated from source. Do not hand-edit them.

- [Built-in tools](generated/tools.md)
- [Provider matrix](generated/provider-matrix.md)
- [Configuration defaults](generated/config-defaults.md)
- [Full configuration example](../microclaw.config.example.yaml)

## Interfaces and integrations

- [Local Web UI and gateway](operations/web-ui.md)
- [HTTP and webhook triggers](operations/http-hook-trigger.md)
- [MCP](integrations/mcp.md)
- [ClawHub](clawhub/overview.md)
- [Plugins](plugins/overview.md)
- [Hooks](hooks/HOOK.md)
- [A2A](a2a.md)
- [ACP over stdio](operations/acp-stdio.md)
- [Weixin](operations/weixin.md)
- [HAPI bridge](operations/hapi-bridge.md)

## Runtime behavior

- [Concurrency and responsiveness](operations/concurrency-and-responsiveness.md)
- [Scheduled task lifecycle](scheduled-task-lifecycle.md)
- [Completion contracts](completion-contracts.md)
- [Durable coworker recovery](operations/durable-coworker.md)
- [Long-horizon learning](long-horizon-learning.md)
- [Learning Foundry](learning-foundry.md)
- [Built-in skill roster](builtin-skills-roster.md)
- [LLM provider conventions](llm-provider-conventions.md)

## Security

- [Execution model](security/execution-model.md)
- [Secure runtime](security/secure-runtime.md)
- [OWASP agentic self-assessment](security/owasp-agentic-self-assessment-2026-08.md)
- [Web UI and ClawHub audit](security/audit-2026-07-web-ui-clawhub.md)
- [Vulnerability reporting](../SECURITY.md)

## Observability

- [Architecture](observability/architecture.md)
- [Metrics](observability/metrics.md)
- [Langfuse setup](observability/langfuse.md)

## Releases and operations

- [Operations runbook](operations/runbook.md)
- [Status surface and webhook alerts](operations/status-and-alerts.md)
- [Reliability scorecard](reports/reliability/README.md)
- [Tokens-per-task benchmark method](reports/benchmarks/tokens-per-task.md)
- [Windows service](operations/windows-service.md)
- [Release policy](releases/release-policy.md)
- [Release checklist](releases/pr-release-checklist.md)
- [Upgrade guide](releases/upgrade-guide.md)
- [Changelog](../CHANGELOG.md)

## Design records and project status

- [RFC index](rfcs/README.md)
- [Humanlike-chat workstream implementation inventory](IMPLEMENTED.md) (scoped to that workstream, not a project-wide feature list)
- [Roadmaps](roadmap/)
- [Point-in-time reports](reports/)

Roadmaps and reports describe a dated plan or assessment; they are not configuration references. Prefer generated references and current operations guides for present behavior.

## Languages

The project overview and quick start are available in 10 widely used languages. See the [translation index and maintenance policy](i18n/README.md).

Technical documentation is maintained in English as the canonical source. This avoids copying commands, configuration keys, and security guidance across translations where they could drift silently.

## Documentation maintenance

- Put installation and feature orientation in the root README files.
- Put task-focused guidance under `docs/` and link to it instead of copying it.
- Put current config and provider facts in source-backed generated pages.
- Mark dated plans and reports clearly; do not let them read like current setup instructions.
- Keep English and Chinese README behaviorally aligned.
- Check generated-document drift with:

```sh
node scripts/generate_docs_artifacts.mjs --check --no-website
```
