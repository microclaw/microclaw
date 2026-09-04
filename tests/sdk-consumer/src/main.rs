#[cfg(any(feature = "standard", feature = "full"))]
use async_trait::async_trait;
#[cfg(any(feature = "standard", feature = "full"))]
use microclaw_sdk::{
    AgentProfile, ExecutionContext, ExecutionResult, MicroClaw, RunExecutor, RunRequest, Runtime,
    RuntimeError,
};

#[cfg(any(feature = "standard", feature = "full"))]
struct ConsumerExecutor;

#[cfg(any(feature = "standard", feature = "full"))]
#[async_trait]
impl RunExecutor for ConsumerExecutor {
    async fn execute(
        &self,
        _profile: AgentProfile,
        request: RunRequest,
        _context: ExecutionContext,
    ) -> Result<ExecutionResult, RuntimeError> {
        Ok(ExecutionResult::new("consumer-session", request.prompt))
    }
}

#[cfg(feature = "minimal")]
fn main() {
    let request = microclaw_sdk::RunRequest::new("hello");
    assert_eq!(request.prompt, "hello");
    assert!(microclaw_sdk::WORKER_PROTOCOL_VERSION > 0);
}

#[cfg(any(feature = "standard", feature = "full"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::builder().executor(ConsumerExecutor).build()?;
    let microclaw = MicroClaw::from_runtime(runtime);
    let result = microclaw
        .agent("consumer")
        .build()?
        .run("hello")
        .result()
        .await?;
    assert_eq!(result.final_text, "hello");

    #[cfg(feature = "full")]
    {
        let _config = microclaw_sdk::FullRuntimeConfig::new("anthropic", "model", "key")
            .base_url("https://example.com");
        let _transport = microclaw_sdk::WebSocketWorkerTransport::new("wss://example.com/worker")
            .bearer_token("token");
    }
    Ok(())
}
