pub fn default_llm_user_agent() -> String {
    format!("MicroClaw/{}", env!("CARGO_PKG_VERSION"))
}

/// Returns the User-Agent string used for outbound LLM HTTP calls.
pub fn llm_user_agent(configured: &str) -> String {
    let trimmed = configured.trim();
    if trimmed.is_empty() {
        default_llm_user_agent()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{default_llm_user_agent, llm_user_agent};

    #[test]
    fn test_llm_user_agent_default() {
        let ua = default_llm_user_agent();
        assert!(ua.starts_with("MicroClaw/"));
    }

    #[test]
    fn test_llm_user_agent_uses_configured_value() {
        assert_eq!(llm_user_agent("OpenClaw/0.1.0"), "OpenClaw/0.1.0");
    }

    #[test]
    fn test_llm_user_agent_empty_uses_default() {
        assert_eq!(llm_user_agent("  "), default_llm_user_agent());
    }
}
