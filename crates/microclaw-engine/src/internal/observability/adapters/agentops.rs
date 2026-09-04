use serde_yaml::{Mapping, Value};

use super::TraceTargetConfig;

fn get_trimmed<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

pub fn apply(map: &Mapping, target: &mut TraceTargetConfig) {
    let Some(api_key) = get_trimmed(map, "agentops_api_key") else {
        return;
    };
    if target.endpoint.is_none() {
        target.endpoint = get_trimmed(map, "agentops_otlp_endpoint").map(ToOwned::to_owned);
    }
    if !target
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
    {
        target
            .headers
            .push(("Authorization".to_string(), format!("Bearer {api_key}")));
    }
}
