use async_trait::async_trait;
use microclaw_sdk::{
    AgentProfile, ExecutionContext, ExecutionResult, MicroClaw, RunExecutor, RunRequest, Runtime,
    RuntimeError,
};

struct ConsumerExecutor;

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
