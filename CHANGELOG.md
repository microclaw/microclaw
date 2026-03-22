# Changelog

All notable changes to this project should be recorded in this file.

The format is loosely based on Keep a Changelog. Dates use UTC.

## Unreleased

### Added

- governance documents for security reporting, contribution expectations, and operator support
- CI coverage and dependency-audit gates
- release packaging coverage for macOS artifacts and checksum publication
- stronger config self-check coverage for risky execution settings
- official container image release automation for GHCR, with optional Docker Hub mirroring when repository credentials are configured

### Changed

- CI now builds the website docs alongside the web UI
- release process documentation now points to explicit support and release-policy artifacts
- Docker builds now compile embedded web assets inside the image build and default the runtime image to `microclaw start`

## 0.1.12

- Current release baseline before the maturity-hardening PR
