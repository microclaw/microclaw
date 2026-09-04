#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi

consumer_dir="$(mktemp -d)"
trap 'rm -rf "$consumer_dir"' EXIT

cargo init --quiet --bin --name microclaw-registry-consumer "$consumer_dir"

cat >"$consumer_dir/Cargo.toml" <<EOF
[package]
name = "microclaw-registry-consumer"
version = "0.0.0"
edition = "2021"
publish = false

[features]
default = []
minimal = ["microclaw-sdk/minimal"]
standard = ["microclaw-sdk/standard", "dep:async-trait", "dep:tokio"]
full = ["microclaw-sdk/full", "dep:async-trait", "dep:tokio"]

[dependencies]
async-trait = { version = "0.1", optional = true }
microclaw-sdk = { version = "=${version}", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"], optional = true }
EOF

cat >"$consumer_dir/src/main.rs" <<'EOF'
#[cfg(feature = "minimal")]
fn main() {
    let request = microclaw_sdk::RunRequest::new("registry smoke test");
    assert_eq!(request.prompt, "registry smoke test");
    assert!(microclaw_sdk::WORKER_PROTOCOL_VERSION > 0);
}

#[cfg(any(feature = "standard", feature = "full"))]
mod runtime_consumer {
    use async_trait::async_trait;
    use microclaw_sdk::{
        AgentProfile, ExecutionContext, ExecutionResult, MicroClaw, RunExecutor, RunRequest,
        Runtime, RuntimeError,
    };

    struct Echo;

    #[async_trait]
    impl RunExecutor for Echo {
        async fn execute(
            &self,
            _profile: AgentProfile,
            request: RunRequest,
            _context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            Ok(ExecutionResult::new("registry", request.prompt))
        }
    }

    #[tokio::main]
    pub async fn run() {
        let runtime = Runtime::builder().executor(Echo).build().unwrap();
        let sdk = MicroClaw::from_runtime(runtime.clone());
        let result = sdk.agent("consumer").build().unwrap().run("ok").result().await.unwrap();
        assert_eq!(result.final_text, "ok");
        runtime.shutdown().await;
    }
}

#[cfg(any(feature = "standard", feature = "full"))]
fn main() {
    runtime_consumer::run();
}
EOF

cargo run --quiet --manifest-path "$consumer_dir/Cargo.toml" --features minimal
cargo run --quiet --manifest-path "$consumer_dir/Cargo.toml" --features standard
cargo check --quiet --manifest-path "$consumer_dir/Cargo.toml" --features full

echo "Verified microclaw-sdk ${version} from crates.io with minimal, standard, and full presets."
