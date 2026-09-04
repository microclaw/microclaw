pub mod agentops;
pub mod langfuse;

#[derive(Default)]
pub struct TraceTargetConfig {
    pub endpoint: Option<String>,
    pub headers: Vec<(String, String)>,
}
