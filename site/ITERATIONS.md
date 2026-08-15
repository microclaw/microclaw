# Website Iterations (v1 -> v5)

Date: 2026-02-15
Scope: `site/` homepage and global visual system
Reference baseline: `https://moltis.org/` and current `https://microclaw.org/`

## Summary

This iteration series improves conversion clarity, information hierarchy, visual identity, and onboarding flow while preserving MicroClaw's own style.

## v1 - Information Architecture Reset

Changes:
- Reframed hero from generic introduction to explicit value proposition:
  - "Build one agent core. Deploy it to every chat surface."
- Pulled key runtime differentiation into above-the-fold copy.
- Added immediate CTA pair with clear intent:
  - `Start in 5 Minutes`
  - `View GitHub`

Why:
- Existing page was clear but too flat in prioritization.
- New structure reduces cognitive load and accelerates first-click intent.

## v2 - Install Experience Upgrade

Changes:
- Replaced single command with tabbed install switcher:
  - Install Script / Homebrew / Cargo / Doctor Check
- Added install hint text per method.
- Added copy interaction for the active command.

Why:
- The previous one-liner was useful but not role-aware.
- Different user segments need different entry paths.

## v3 - Proof Layer and Architecture Clarity

Changes:
- Added proof strip with four concrete dimensions:
  - Architecture / Memory / Execution / Extensibility
- Added architecture section with embedded system diagram and step-by-step runtime flow.
- Expanded capability grid with operational language (not only feature labels).

Why:
- Trust is built by architecture clarity and operational details, not slogans.

## v4 - Visual Language Rework

Changes:
- New color direction with warm-cool gradients and high-contrast terminal panel.
- Refined card depth, border rhythm, and spacing scale.
- Added subtle motion signal (`pulseDot`) without noisy micro-animation.
- Improved navbar legibility with translucent blur treatment.

Why:
- Prior design was good but too close to typical Docusaurus aesthetic.
- New treatment gives distinct product personality while staying readable.

## v5 - Conversion and Use-Case Completion

Changes:
- Added real workload use-case cards:
  - Personal Infra Agent / Team Operations Bot / Product Prototyping Runtime
- Added final CTA block with three terminal actions:
  - Quickstart / Architecture Docs / Generated Tools Reference
- Improved mobile behavior for command panel, grids, and hero actions.

Why:
- Users need a clear path from "looks promising" to "I can implement this now."

## Files Updated

- `site/src/pages/index.js`
- `site/src/pages/index.module.css`
- `site/src/css/custom.css`
- `site/ITERATIONS.md`

## Validation Checklist

- [x] Home builds successfully in Docusaurus
- [x] Hero actions visible and clickable on desktop/mobile
- [x] Install tabs switch command text correctly
- [x] Copy button works for active command
- [x] No horizontal overflow on mobile breakpoints
