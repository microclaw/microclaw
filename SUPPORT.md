# Support Policy

## Release Channels

MicroClaw uses three practical support states:

- `main`: active development, expected to stay releasable
- latest tagged release: primary supported release line
- previous tagged release: limited overlap support during upgrade windows

Older versions are upgrade-only unless a maintainer explicitly announces an exception.

## Compatibility Targets

- Database schema upgrades must be forward-migrated by the current release.
- Config compatibility should be preserved when feasible; breaking config changes require upgrade notes.
- Web API contract changes should be documented before release.

## Issue Routing

- Bug reports: GitHub Issues
- Feature requests: GitHub Discussions or Issues
- Security reports: `SECURITY.md`
- Operational regressions after release: open an issue and include `microclaw doctor --json` output when possible

## Maintainer Response Expectations

- Reproducible regressions on the latest release: prioritized
- Regressions on unsupported older releases: may require upgrading first
- Questions without reproduction details: best effort

## What To Include In Support Requests

- MicroClaw version or commit SHA
- OS and install method
- provider/channel configuration involved
- exact command or API route used
- logs, screenshots, or failing payloads if available
