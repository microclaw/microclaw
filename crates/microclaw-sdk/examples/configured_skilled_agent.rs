use microclaw_sdk::engine::{config::Config, headless::HeadlessRuntime};
use microclaw_sdk::{AgentProfile, RunRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "microclaw.config.yaml".into());
    let config = Config::load_from_path_for_headless(config_path.as_ref())?;
    let runtime = HeadlessRuntime::load(config)
        .await?
        .into_embedded_runtime("embedded-app", 2)?;
    let agent = runtime.agent(AgentProfile {
        name: "repository-reviewer".into(),
        system_prompt: Some("Review carefully and report evidence.".into()),
        skills: vec!["code-review".into()],
        ..AgentProfile::default()
    });
    let mut run = agent.run(RunRequest::new("Review this repository"));
    while let Some(event) = run.next_event().await {
        println!("{}: {:?}", event.sequence, event.event);
    }
    println!("{}", run.result().await?.final_text);
    Ok(())
}
