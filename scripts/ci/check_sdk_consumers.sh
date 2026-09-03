#!/usr/bin/env bash
set -euo pipefail

manifest="tests/sdk-consumer/Cargo.toml"
cargo check --manifest-path "${manifest}" --no-default-features --features minimal
cargo check --manifest-path "${manifest}" --no-default-features --features standard
cargo check --manifest-path "${manifest}" --no-default-features --features full
cargo run --quiet --manifest-path "${manifest}" --no-default-features --features minimal
