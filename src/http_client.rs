/// Returns the User-Agent string used for outbound LLM HTTP calls.
///
/// Set `MICROCLAW_LLM_USER_AGENT` to override the default value.
pub fn llm_user_agent() -> String {
    if let Ok(override_ua) = std::env::var("MICROCLAW_LLM_USER_AGENT") {
        let trimmed = override_ua.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    format!(
        "MicroClaw/{} (+https://github.com/microclaw/microclaw)",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::llm_user_agent;
    use crate::test_support::env_lock;

    #[test]
    fn test_llm_user_agent_default() {
        let _guard = env_lock();
        std::env::remove_var("MICROCLAW_LLM_USER_AGENT");
        let ua = llm_user_agent();
        assert!(ua.starts_with("MicroClaw/"));
        assert!(ua.contains("github.com/microclaw/microclaw"));
    }

    #[test]
    fn test_llm_user_agent_override() {
        let _guard = env_lock();
        std::env::set_var("MICROCLAW_LLM_USER_AGENT", "OpenClaw/0.1.0");
        assert_eq!(llm_user_agent(), "OpenClaw/0.1.0");
        std::env::remove_var("MICROCLAW_LLM_USER_AGENT");
    }
}
