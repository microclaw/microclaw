use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum MicroClawError {
    #[error("LLM API error: {0}")]
    LlmApi(String),

    #[error("Rate limited, retry after backoff")]
    RateLimited,

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Tool execution error: {0}")]
    ToolExecution(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Max tool iterations reached ({0})")]
    MaxIterations(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        let e = MicroClawError::LlmApi("bad request".into());
        assert_eq!(e.to_string(), "LLM API error: bad request");

        let e = MicroClawError::RateLimited;
        assert_eq!(e.to_string(), "Rate limited, retry after backoff");

        let e = MicroClawError::ToolExecution("tool failed".into());
        assert_eq!(e.to_string(), "Tool execution error: tool failed");

        let e = MicroClawError::Config("missing key".into());
        assert_eq!(e.to_string(), "Config error: missing key");

        let e = MicroClawError::MaxIterations(25);
        assert_eq!(e.to_string(), "Max tool iterations reached (25)");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let e: MicroClawError = io_err.into();
        assert!(e.to_string().contains("not found"));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{invalid").unwrap_err();
        let e: MicroClawError = json_err.into();
        assert!(e.to_string().contains("JSON error"));
    }

    #[test]
    fn test_error_debug() {
        let e = MicroClawError::RateLimited;
        let debug = format!("{:?}", e);
        assert!(debug.contains("RateLimited"));
    }
}
