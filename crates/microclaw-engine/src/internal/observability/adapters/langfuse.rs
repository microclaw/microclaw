use base64::prelude::*;
use serde_yaml::{Mapping, Value};
use tracing::warn;

use super::TraceTargetConfig;

fn get_trimmed<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

pub fn apply(map: &Mapping, target: &mut TraceTargetConfig) {
    let Some(pk) = get_trimmed(map, "langfuse_public_key") else {
        return;
    };
    let Some(sk) = get_trimmed(map, "langfuse_secret_key") else {
        return;
    };
    let host = normalize_langfuse_host(
        get_trimmed(map, "langfuse_host").unwrap_or("https://cloud.langfuse.com"),
    );

    if target.endpoint.is_none() {
        target.endpoint = Some(format!(
            "{}/api/public/otel/v1/traces",
            host.trim_end_matches('/')
        ));
    }

    let auth = BASE64_STANDARD.encode(format!("{pk}:{sk}"));
    if !target
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
    {
        target
            .headers
            .push(("Authorization".to_string(), format!("Basic {auth}")));
    }
}

fn normalize_langfuse_host(raw: &str) -> String {
    let mut host = raw.trim().trim_end_matches('/').to_string();
    if let Some((prefix, _)) = host.split_once("/project/") {
        warn!(
            langfuse_host = %raw,
            "langfuse_host appears to be a UI project URL; using host root instead"
        );
        host = prefix.to_string();
    }
    if host.ends_with("/api/public/otel/v1/traces") {
        host = host
            .trim_end_matches("/api/public/otel/v1/traces")
            .to_string();
    } else if host.ends_with("/api/public/otel") {
        host = host.trim_end_matches("/api/public/otel").to_string();
    }
    host
}
