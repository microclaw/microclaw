use async_trait::async_trait;
use microclaw_sdk::{
    AgentProfile, ExecutionContext, ExecutionResult, RunExecutor, RunRequest, Runtime,
    RuntimeError, RuntimeEvent,
};

struct AppExecutor;

#[async_trait]
impl RunExecutor for AppExecutor {
    async fn execute(
        &self,
        _profile: AgentProfile,
        request: RunRequest,
        context: ExecutionContext,
    ) -> Result<ExecutionResult, RuntimeError> {
        context.emit(RuntimeEvent::TextDelta {
            delta: "working...".into(),
        })?;
        Ok(ExecutionResult::new("example-session", request.prompt))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::builder().executor(AppExecutor).build()?;
    let agent = runtime.agent(AgentProfile {
        name: "embedded-agent".into(),
        ..AgentProfile::default()
    });
    let mut run = agent.run(RunRequest::new("Hello from an embedded app"));

    while let Some(event) = run.next_event().await {
        println!("event {}: {:?}", event.sequence, event.event);
    }
    println!("result: {}", run.result().await?.final_text);
    Ok(())
}
