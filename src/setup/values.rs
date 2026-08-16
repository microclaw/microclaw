use super::*;

pub(crate) fn dynamic_channel_uses_minimal_setup(channel: &str) -> bool {
    channel == "weixin"
}

pub(crate) fn effective_dynamic_slot_field_value<F>(
    channel: &str,
    slot: usize,
    field: &ChannelFieldDef,
    get: F,
) -> String
where
    F: Fn(&str) -> String,
{
    let slot_key = dynamic_slot_field_key(channel, slot, field.yaml_key);
    let slot_value = get(&slot_key);
    let slot_value = slot_value.trim();
    if !slot_value.is_empty() {
        return slot_value.to_string();
    }

    let channel_key = dynamic_field_key(channel, field.yaml_key);
    let channel_value = get(&channel_key);
    let channel_value = channel_value.trim();
    if !channel_value.is_empty() {
        return channel_value.to_string();
    }

    field.default.trim().to_string()
}

pub(crate) fn default_account_id() -> &'static str {
    "main"
}

pub(crate) fn account_id_from_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        default_account_id().to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn is_valid_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn resolve_channel_default_account_id(
    channel_cfg: &serde_yaml::Value,
) -> Option<String> {
    let explicit = channel_cfg
        .get("default_account")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);
    if explicit.is_some() {
        return explicit;
    }

    let accounts = channel_cfg.get("accounts").and_then(|v| v.as_mapping())?;
    if accounts.contains_key(serde_yaml::Value::String("default".to_string())) {
        return Some("default".to_string());
    }
    let mut ids: Vec<String> = accounts
        .keys()
        .filter_map(|k| k.as_str().map(ToOwned::to_owned))
        .collect();
    ids.sort();
    ids.first().cloned()
}

pub(crate) fn channel_account_str_value(
    channel_cfg: &serde_yaml::Value,
    account_id: &str,
    key: &str,
) -> Option<String> {
    channel_cfg
        .get("accounts")
        .and_then(|v| v.get(account_id))
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn channel_default_account_str_value(
    channel_cfg: &serde_yaml::Value,
    key: &str,
) -> Option<String> {
    let account_id = resolve_channel_default_account_id(channel_cfg)?;
    channel_account_str_value(channel_cfg, &account_id, key)
}

pub(crate) fn compact_json_string(value: &serde_yaml::Value) -> Option<String> {
    let json_value = serde_json::to_value(value).ok()?;
    serde_json::to_string(&json_value).ok()
}

pub(crate) fn parse_accounts_json_value(
    raw: &str,
    field_key: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, MicroClawError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
        MicroClawError::Config(format!("{field_key} must be valid JSON object: {e}"))
    })?;
    let obj = if let Some(map_obj) = parsed.as_object() {
        map_obj.clone()
    } else if let Some(items) = parsed.as_array() {
        let mut out = serde_json::Map::new();
        for (idx, item) in items.iter().enumerate() {
            let Some(entry) = item.as_object() else {
                return Err(MicroClawError::Config(format!(
                    "{field_key}[{idx}] must be an object with at least 'id'"
                )));
            };
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    MicroClawError::Config(format!(
                        "{field_key}[{idx}] is missing required string field 'id'"
                    ))
                })?;
            if !is_valid_account_id(id) {
                return Err(MicroClawError::Config(format!(
                    "{field_key}[{idx}] has invalid id '{id}' (allowed: letters, numbers, '_' or '-')"
                )));
            }
            let mut account = entry.clone();
            account.remove("id");
            out.insert(id.to_string(), serde_json::Value::Object(account));
        }
        out
    } else {
        return Err(MicroClawError::Config(format!(
            "{field_key} must be a JSON object {{id: config}} or JSON array [{{id, ...config}}]"
        )));
    };
    for account_id in obj.keys() {
        if !is_valid_account_id(account_id) {
            return Err(MicroClawError::Config(format!(
                "{field_key} contains invalid account id '{account_id}' (allowed: letters, numbers, '_' or '-')"
            )));
        }
    }
    Ok(Some(obj))
}

pub(crate) fn parse_provider_presets_json_value(
    raw: &str,
    field_key: &str,
) -> Result<HashMap<String, LlmProviderProfile>, MicroClawError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let mut presets: HashMap<String, LlmProviderProfile> =
        serde_json::from_str(trimmed).map_err(|e| {
            MicroClawError::Config(format!(
                "{field_key} must be a valid JSON object {{preset_id: {{provider,...}}}}: {e}"
            ))
        })?;
    let mut normalized = HashMap::new();
    for (preset_id, profile) in presets.drain() {
        let preset_id = preset_id.trim().to_ascii_lowercase();
        if preset_id.is_empty() {
            return Err(MicroClawError::Config(format!(
                "{field_key} contains an empty preset id"
            )));
        }
        if preset_id == "main" {
            return Err(MicroClawError::Config(format!(
                "{field_key} preset id 'main' is reserved for the global default"
            )));
        }
        if !is_valid_account_id(&preset_id) {
            return Err(MicroClawError::Config(format!(
                "{field_key} contains invalid preset id '{preset_id}' (allowed: letters, numbers, '_' or '-')"
            )));
        }
        normalized.insert(preset_id, profile);
    }
    Ok(normalized)
}

pub(crate) fn append_yaml_value(yaml: &mut String, indent: usize, value: &serde_yaml::Value) {
    if let Ok(rendered) = serde_yaml::to_string(value) {
        let prefix = " ".repeat(indent);
        for line in rendered.lines() {
            if line == "---" || line.trim().is_empty() {
                continue;
            }
            yaml.push_str(&prefix);
            yaml.push_str(line);
            yaml.push('\n');
        }
    }
}

pub(crate) fn yaml_double_quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub(crate) fn parse_boolish(value: &str, default_if_empty: bool) -> Result<bool, MicroClawError> {
    let raw = value.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Ok(default_if_empty);
    }
    match raw.as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(MicroClawError::Config(format!(
            "invalid bool value '{value}', expected true/false"
        ))),
    }
}

pub(crate) fn dynamic_field_is_bool(channel: &str, yaml_key: &str) -> bool {
    matches!(
        (channel, yaml_key),
        ("feishu", "topic_mode" | "show_progress") | ("slack", "capture_unmentioned_images")
    )
}

pub(crate) fn dynamic_field_is_u64(channel: &str, yaml_key: &str) -> bool {
    matches!((channel, yaml_key), ("slack", "inbound_image_max_mb"))
}

pub(crate) fn parse_bot_count(value: &str, field_key: &str) -> Result<usize, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(1);
    }
    let parsed = trimmed.parse::<usize>().map_err(|_| {
        MicroClawError::Config(format!(
            "{field_key} must be an integer between 1 and {MAX_BOT_SLOTS}"
        ))
    })?;
    if !(1..=MAX_BOT_SLOTS).contains(&parsed) {
        return Err(MicroClawError::Config(format!(
            "{field_key} must be between 1 and {MAX_BOT_SLOTS}"
        )));
    }
    Ok(parsed)
}

pub(crate) fn parse_u64_field(value: &str, field_key: &str) -> Result<u64, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MicroClawError::Config(format!(
            "{field_key} must be a positive integer"
        )));
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| MicroClawError::Config(format!("{field_key} must be a positive integer")))
}

pub(crate) fn parse_i64_list_field(
    value: &str,
    field_key: &str,
) -> Result<Vec<i64>, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let parse_item = |raw: &str| -> Result<i64, MicroClawError> {
        raw.trim().parse::<i64>().map_err(|_| {
            MicroClawError::Config(format!(
                "{field_key} must contain integer IDs (csv like '123,456' or JSON array like '[123,456]')"
            ))
        })
    };

    if trimmed.starts_with('[') {
        let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            MicroClawError::Config(format!(
                "{field_key} must be a valid JSON array when using [] syntax: {e}"
            ))
        })?;
        let arr = parsed.as_array().ok_or_else(|| {
            MicroClawError::Config(format!(
                "{field_key} must be a JSON array when using [] syntax"
            ))
        })?;
        let mut out = Vec::new();
        for item in arr {
            match item {
                serde_json::Value::Number(n) => {
                    let id = n.as_i64().ok_or_else(|| {
                        MicroClawError::Config(format!("{field_key} contains non-integer number"))
                    })?;
                    out.push(id);
                }
                serde_json::Value::String(s) => out.push(parse_item(s)?),
                _ => {
                    return Err(MicroClawError::Config(format!(
                        "{field_key} supports only integer values"
                    )));
                }
            }
        }
        return Ok(out);
    }

    trimmed
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(parse_item)
        .collect()
}

pub(crate) fn parse_string_list_field(value: &str) -> Result<Vec<String>, MicroClawError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            MicroClawError::Config(format!("invalid string list JSON array syntax: {e}"))
        })?;
        let arr = parsed.as_array().ok_or_else(|| {
            MicroClawError::Config("string list must be a JSON array when using [] syntax".into())
        })?;
        let mut out = Vec::new();
        for item in arr {
            let s = item
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    MicroClawError::Config(
                        "string list supports only non-empty string values".into(),
                    )
                })?;
            out.push(s.to_string());
        }
        return Ok(out);
    }
    Ok(trimmed
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub(crate) fn normalize_soul_path_input(raw: &str, souls_dir: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return trimmed.to_string();
    }
    let base = souls_dir.trim().trim_end_matches(['/', '\\']);
    let prefix = if base.is_empty() { "souls" } else { base };
    if trimmed.to_ascii_lowercase().ends_with(".md") {
        return format!("{prefix}/{trimmed}");
    }
    format!("{prefix}/{trimmed}.md")
}

pub(crate) fn soul_picker_file_names(
    data_dir: Option<&str>,
    souls_dir: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut roots = Vec::new();

    if let Some(dir) = souls_dir {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            roots.push(Path::new(trimmed).to_path_buf());
            if let Some(data) = data_dir {
                let data_trimmed = data.trim();
                if !data_trimmed.is_empty() {
                    roots.push(Path::new(data_trimmed).join(trimmed));
                }
            }
        }
    }
    roots.push(Path::new("souls").to_path_buf());
    if let Some(dir) = data_dir {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            roots.push(Path::new(trimmed).join("souls"));
        }
    }

    for root in roots {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let is_md = path
                    .extension()
                    .and_then(|v| v.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("md"))
                    .unwrap_or(false);
                if !is_md {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|v| v.to_str()) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn default_data_dir_for_setup() -> String {
    if std::env::var("SNAP").is_ok() {
        if let Ok(snap_user_common) = std::env::var("SNAP_USER_COMMON") {
            return snap_user_common;
        }
    }
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .map(|p| p.join(".microclaw"))
        .unwrap_or_else(|| std::path::PathBuf::from(".microclaw"))
        .to_string_lossy()
        .to_string()
}

pub(crate) fn default_working_dir_for_setup() -> String {
    Path::new(&default_data_dir_for_setup())
        .join("working_dir")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn default_souls_dir_for_setup() -> String {
    Path::new(&default_data_dir_for_setup())
        .join("souls")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn parse_bool_like(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" | "" => Some(false),
        _ => None,
    }
}
