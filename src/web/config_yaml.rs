use super::*;

/// Convert a serde_json::Value to a serde_yaml::Value for channel config merging.
pub(crate) fn json_to_yaml_value(v: &serde_json::Value) -> serde_yaml::Value {
    match v {
        serde_json::Value::Null => serde_yaml::Value::Null,
        serde_json::Value::Bool(b) => serde_yaml::Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_yaml::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_yaml::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_yaml::Value::Number(serde_yaml::Number::from(f))
            } else {
                serde_yaml::Value::Null
            }
        }
        serde_json::Value::String(s) => serde_yaml::Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            serde_yaml::Value::Sequence(arr.iter().map(json_to_yaml_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut map = serde_yaml::Mapping::new();
            for (k, v) in obj {
                map.insert(serde_yaml::Value::String(k.clone()), json_to_yaml_value(v));
            }
            serde_yaml::Value::Mapping(map)
        }
    }
}

pub(crate) fn yaml_key_to_json_field(key: &serde_yaml::Value) -> String {
    match key {
        serde_yaml::Value::Null => "null".to_string(),
        serde_yaml::Value::Bool(value) => value.to_string(),
        serde_yaml::Value::Number(value) => value.to_string(),
        serde_yaml::Value::String(value) => value.clone(),
        other => serde_yaml::to_string(other)
            .map(|raw| raw.trim().to_string())
            .unwrap_or_else(|_| "<non-string-key>".to_string()),
    }
}

pub(crate) fn yaml_to_json_value(value: &serde_yaml::Value) -> serde_json::Value {
    match value {
        serde_yaml::Value::Null => serde_json::Value::Null,
        serde_yaml::Value::Bool(value) => serde_json::Value::Bool(*value),
        serde_yaml::Value::Number(value) => {
            if let Some(i) = value.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = value.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = value.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml::Value::String(value) => serde_json::Value::String(value.clone()),
        serde_yaml::Value::Sequence(items) => {
            serde_json::Value::Array(items.iter().map(yaml_to_json_value).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let mut json_map = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                json_map.insert(yaml_key_to_json_field(key), yaml_to_json_value(value));
            }
            serde_json::Value::Object(json_map)
        }
        serde_yaml::Value::Tagged(tagged) => yaml_to_json_value(&tagged.value),
    }
}

pub(crate) fn config_path_for_save() -> Result<PathBuf, (StatusCode, String)> {
    match Config::resolve_config_path() {
        Ok(Some(path)) => Ok(path),
        Ok(None) => Ok(PathBuf::from("./microclaw.config.yaml")),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

pub(crate) fn is_sensitive_config_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    if k.is_empty() {
        return false;
    }
    let exact = [
        "api_key",
        "openai_api_key",
        "embedding_api_key",
        "shared_tokens",
        "telegram_bot_token",
        "discord_bot_token",
        "bot_token",
        "app_token",
        "token",
        "secret",
        "password",
        "app_secret",
        "clawhub_token",
    ];
    if exact.contains(&k.as_str()) {
        return true;
    }
    k.ends_with("_token")
        || k.ends_with("_secret")
        || k.ends_with("_password")
        || k.ends_with("_api_key")
}

pub(crate) fn redact_json_secrets(value: &mut serde_json::Value, parent_key: Option<&str>) {
    if parent_key.is_some_and(is_sensitive_config_key) {
        match value {
            serde_json::Value::Array(items) => {
                for item in items {
                    *item = serde_json::Value::String("***".to_string());
                }
            }
            _ => {
                *value = serde_json::Value::String("***".to_string());
            }
        }
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                redact_json_secrets(v, Some(k.as_str()));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_secrets(item, parent_key);
            }
        }
        _ => {}
    }
}

pub(crate) fn redact_config(config: &Config) -> serde_json::Value {
    let mut value = serde_yaml::to_value(config)
        .map(|yaml| yaml_to_json_value(&yaml))
        .unwrap_or_else(|_| json!({}));
    redact_json_secrets(&mut value, None);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::web::test_prelude::*;

    #[test]
    fn test_redact_config_recursively_masks_nested_and_flattened_secrets() {
        let mut cfg = test_config_template();
        cfg.clawhub.token = Some("clawhub-secret".to_string());
        cfg.a2a.shared_tokens = vec!["a2a-secret".to_string()];
        cfg.channels.insert(
            "discord".to_string(),
            serde_yaml::to_value(json!({
                "accounts": {
                    "main": {
                        "bot_token": "discord-secret-token"
                    }
                }
            }))
            .unwrap(),
        );
        let redacted = redact_config(&cfg);
        assert_eq!(
            redacted.get("clawhub_token").and_then(|v| v.as_str()),
            Some("***")
        );
        assert_eq!(
            redacted
                .pointer("/channels/discord/accounts/main/bot_token")
                .and_then(|v| v.as_str()),
            Some("***")
        );
        assert_eq!(
            redacted
                .pointer("/a2a/shared_tokens/0")
                .and_then(|v| v.as_str()),
            Some("***")
        );
        assert_eq!(
            redacted.get("max_tokens").and_then(|v| v.as_u64()),
            Some(cfg.max_tokens as u64)
        );
    }

    #[test]
    fn test_redact_config_handles_non_string_yaml_mapping_keys() {
        let mut cfg = test_config_template();
        let mut inner = serde_yaml::Mapping::new();
        inner.insert(
            serde_yaml::Value::String("bot_token".to_string()),
            serde_yaml::Value::String("discord-secret-token".to_string()),
        );

        let mut outer = serde_yaml::Mapping::new();
        outer.insert(
            serde_yaml::Value::Number(42_i64.into()),
            serde_yaml::Value::Mapping(inner),
        );

        cfg.channels
            .insert("discord".to_string(), serde_yaml::Value::Mapping(outer));

        let redacted = redact_config(&cfg);
        assert_eq!(
            redacted
                .pointer("/channels/discord/42/bot_token")
                .and_then(|v| v.as_str()),
            Some("***")
        );
    }
}
