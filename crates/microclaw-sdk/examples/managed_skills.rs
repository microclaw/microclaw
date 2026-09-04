use microclaw_sdk::MicroClaw;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "microclaw.config.yaml".into());
    let microclaw = MicroClaw::builder(config_path).build().await?;

    if let Some(source) = std::env::args().nth(2) {
        let result = microclaw.install_skill(source).await?;
        println!("{}", result.message);
    }
    for skill in microclaw.skills().all() {
        println!(
            "{} enabled={} available={}",
            skill.name, skill.enabled, skill.available
        );
    }
    Ok(())
}
