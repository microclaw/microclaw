
cargo test -q
npm --prefix web run build
npm --prefix website run build
node scripts/generate_docs_artifacts.mjs --check
