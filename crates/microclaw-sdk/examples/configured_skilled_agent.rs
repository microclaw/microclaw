use microclaw_sdk::MicroClaw;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "microclaw.config.yaml".into());
    let microclaw = MicroClaw::builder(config_path)
        .caller_channel("embedded-app")
        .max_concurrent_runs(2)
        .build()
        .await?;
    let agent = microclaw
        .agent("repository-reviewer")
        .system_prompt("Review carefully and report evidence.")
        .skill("code-review")
        .build()?;
    let mut run = agent.run("Review this repository");
    while let Some(event) = run.next_event().await {
        println!("{}: {:?}", event.sequence, event.event);
    }
    println!("{}", run.result().await?.final_text);
    Ok(())
}
