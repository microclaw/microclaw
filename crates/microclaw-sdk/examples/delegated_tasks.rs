use microclaw_sdk::MicroClaw;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "microclaw.config.yaml".into());
    let microclaw = MicroClaw::builder(config_path).build().await?;
    let session = std::env::args().nth(2).unwrap_or_else(|| "default".into());

    for task in microclaw.delegated_tasks(session, 100)? {
        println!(
            "{} [{}] {}",
            task.label.as_deref().unwrap_or(&task.run_id),
            task.status.as_str(),
            task.progress.as_deref().unwrap_or(&task.task),
        );
    }
    Ok(())
}
