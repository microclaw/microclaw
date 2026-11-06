//! `/configure <request>`: the model turns a plain-language request ("use a
//! light theme and ask before git push") into settings changes, which are
//! shown and applied only after the user confirms.

use microclaw_code_core::settings::{self, CodeSettings};

/// One proposed settings change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub layer: String,
    pub key: String,
    /// `None` removes the key.
    pub value: Option<String>,
}

impl Change {
    pub fn describe(&self) -> String {
        match &self.value {
            Some(v) => format!("{} · {} = {}", self.layer, self.key, v),
            None => format!("{} · remove {}", self.layer, self.key),
        }
    }
}

/// The prompt for the model.
pub fn prompt(request: &str, current: &CodeSettings) -> String {
    let current = serde_yaml::to_string(current).unwrap_or_default();
    format!(
        "You configure MicroClaw Code (mccode). Turn the user's request into settings changes.\n\n\
         The settings file format, with comments:\n```yaml\n{template}\n```\n\n\
         The effective settings now:\n```yaml\n{current}```\n\n\
         Reply with a short explanation, then exactly one fenced block tagged `mccode-config` \
         containing one change per line:\n\
         - `set <layer> <dotted.key> <value>` (value in YAML: a scalar, or a flow list like [a, b])\n\
         - `add <layer> <dotted.key> <item>` to append one item to a list (permission rules, domains)\n\
         - `unset <layer> <dotted.key>`\n\
         Layers: `user` (personal, all projects), `project` (shared with the repository), \
         `local` (this project, not committed). Prefer `user` for UI preferences and `local` \
         for permission rules unless the user asks to share them. Never put API keys in \
         project layers. Do not read or change any files.\n\n\
         The request: {request}",
        template = settings::template(),
    )
}

/// Parse the `mccode-config` block of a reply.
pub fn parse(reply: &str) -> Vec<Change> {
    let mut in_block = false;
    let mut out = Vec::new();
    for line in reply.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_block {
                break;
            }
            in_block = trimmed.trim_start_matches('`').trim() == "mccode-config";
            continue;
        }
        if !in_block || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(4, ' ');
        let verb = parts.next().unwrap_or("");
        let layer = parts.next().unwrap_or("").to_string();
        let key = parts.next().unwrap_or("").to_string();
        let rest = parts.next().map(|v| v.trim().to_string());
        if settings::SettingsLayer::parse(&layer).is_none() || key.is_empty() {
            continue;
        }
        match (verb, rest) {
            ("set", Some(v)) => out.push(Change {
                layer,
                key,
                value: Some(v),
            }),
            ("add", Some(v)) => out.push(Change {
                layer,
                key: format!("{key}[+]"),
                value: Some(v),
            }),
            ("unset", _) => out.push(Change {
                layer,
                key,
                value: None,
            }),
            _ => {}
        }
    }
    out
}

/// The explanation text before the block.
pub fn explanation(reply: &str) -> String {
    reply.split("```").next().unwrap_or("").trim().to_string()
}

/// Apply changes; returns one line per change.
pub fn apply(root: &std::path::Path, changes: &[Change]) -> Vec<Result<String, String>> {
    changes
        .iter()
        .map(|c| {
            let layer = settings::SettingsLayer::parse(&c.layer)
                .ok_or_else(|| format!("unknown layer {}", c.layer))?;
            let path = layer.path(root);
            let result = match (&c.value, c.key.strip_suffix("[+]")) {
                (Some(item), Some(list)) => settings::append_in_file(&path, list, item).map(|_| ()),
                (Some(v), None) => settings::set_in_file(&path, &c.key, v),
                (None, _) => settings::unset_in_file(&path, &c.key).map(|_| ()),
            };
            result
                .map(|_| c.describe())
                .map_err(|e| format!("{}: {e}", c.describe()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_block() {
        let reply = "Switching to a light theme and asking before pushes.\n\n```mccode-config\nset user tui.theme github-light\nadd local permissions.ask bash(git push *)\nunset user tui.sidebar\nset nowhere x y\n```\n";
        let changes = parse(reply);
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].value.as_deref(), Some("github-light"));
        assert_eq!(changes[1].key, "permissions.ask[+]");
        assert_eq!(changes[2].value, None);
        assert!(explanation(reply).starts_with("Switching"));
    }

    #[test]
    fn applies_to_a_layer() {
        let dir = tempfile::tempdir().unwrap();
        let changes = vec![
            Change {
                layer: "local".into(),
                key: "permissions.ask[+]".into(),
                value: Some("bash(git push *)".into()),
            },
            Change {
                layer: "local".into(),
                key: "tui.diff".into(),
                value: Some("split".into()),
            },
        ];
        let results = apply(dir.path(), &changes);
        assert!(results.iter().all(|r| r.is_ok()), "{results:?}");
        let text =
            std::fs::read_to_string(dir.path().join(".microclaw/settings.local.yaml")).unwrap();
        assert!(
            text.contains("git push") && text.contains("split"),
            "{text}"
        );
    }
}
