#!/bin/sh
set -eu

cargo test -q
npm --prefix web run build
npm --prefix site run build
node scripts/generate_docs_artifacts.mjs --check
