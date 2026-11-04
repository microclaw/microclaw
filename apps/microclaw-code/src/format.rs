//! Formatting shared by the TUI and the line printer.

use serde_json::Value;

/// Collapse whitespace and cut `text` to `max` characters.
pub fn truncate(text: &str, max: usize) -> String {
    let single_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() <= max {
        single_line
    } else {
        let cut: String = single_line.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// One-line summary of a tool call's input.
pub fn tool_summary(name: &str, input: &Value) -> String {
    let field = |key: &str| input.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let summary = match name {
        "bash" => {
            let mut s = field("command").to_string();
            if input.get("run_in_background").and_then(|v| v.as_bool()) == Some(true) {
                s.push_str("  (background)");
            }
            s
        }
        "read_file" | "write_file" | "edit_file" => {
            let mut s = field("path").to_string();
            if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
                s.push_str(&format!("  ({} edits)", edits.len()));
            }
            s
        }
        "grep" => {
            let path = field("path");
            if path.is_empty() {
                format!("/{}/", field("pattern"))
            } else {
                format!("/{}/ in {path}", field("pattern"))
            }
        }
        "glob" => field("pattern").to_string(),
        "apply_patch" => {
            let files: Vec<&str> = field("patch")
                .lines()
                .filter_map(|l| {
                    ["*** Add File: ", "*** Update File: ", "*** Delete File: "]
                        .iter()
                        .find_map(|p| l.strip_prefix(p))
                })
                .map(str::trim)
                .collect();
            match files.len() {
                0 => String::new(),
                1..=3 => files.join(", "),
                n => format!("{}, … ({n} files)", files[..2].join(", ")),
            }
        }
        "bash_output" | "bash_kill" => field("id").to_string(),
        "web_fetch" => field("url").to_string(),
        "web_search" => field("query").to_string(),
        "sub_agent" | "sessions_spawn" => field("task").to_string(),
        _ => String::new(),
    };
    truncate(&summary, 110)
}

/// Human label for an elapsed duration.
pub fn elapsed(duration: std::time::Duration) -> String {
    let secs = duration.as_secs_f32();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!(
            "{}m{:02}s",
            duration.as_secs() / 60,
            duration.as_secs() % 60
        )
    }
}

/// Compact token count: 950, 12.3k, 4.1M.
pub fn tokens(n: i64) -> String {
    match n {
        n if n >= 1_000_000 => format!("{:.1}M", n as f64 / 1_000_000.0),
        n if n >= 1_000 => format!("{:.1}k", n as f64 / 1_000.0),
        n => n.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summarizes_common_tools() {
        assert_eq!(
            tool_summary("bash", &json!({"command": "cargo   test\n-q"})),
            "cargo test -q"
        );
        assert_eq!(
            tool_summary("edit_file", &json!({"path": "a.rs", "edits": [{}, {}]})),
            "a.rs (2 edits)"
        );
        assert_eq!(
            tool_summary("grep", &json!({"pattern": "fn main"})),
            "/fn main/"
        );
        assert!(tool_summary("bash", &json!({"command": "x".repeat(300)})).ends_with('…'));
    }

    #[test]
    fn formats_elapsed_time() {
        assert_eq!(elapsed(std::time::Duration::from_millis(1500)), "1.5s");
        assert_eq!(elapsed(std::time::Duration::from_secs(125)), "2m05s");
    }
}
