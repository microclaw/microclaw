pub fn normalize_memory_content(input: &str, max_chars: usize) -> Option<String> {
    let cleaned = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut content = cleaned.trim().to_string();
    if content.is_empty() {
        return None;
    }
    if content.len() > max_chars {
        let cutoff = content
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max_chars)
            .last()
            .unwrap_or(max_chars);
        content.truncate(cutoff);
    }
    Some(content)
}

pub fn memory_quality_reason(content: &str) -> Result<(), &'static str> {
    let lower = content.to_ascii_lowercase();
    let trimmed = lower.trim();
    if trimmed.len() < 8 {
        return Err("too short");
    }
    let low_signal_starts = [
        "hi",
        "hello",
        "thanks",
        "thank you",
        "ok",
        "okay",
        "lol",
        "haha",
    ];
    if low_signal_starts.contains(&trimmed) {
        return Err("small talk");
    }
    if trimmed.contains("maybe")
        || trimmed.contains("i think")
        || trimmed.contains("not sure")
        || trimmed.contains("guess")
    {
        return Err("uncertain statement");
    }
    if !trimmed.chars().any(|c| c.is_alphanumeric()) {
        return Err("no signal");
    }
    Ok(())
}

pub fn memory_quality_ok(content: &str) -> bool {
    memory_quality_reason(content).is_ok()
}

pub fn extract_explicit_memory_command(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let lower = t.to_ascii_lowercase();

    // High-confidence prefixes that are clearly memory commands
    let strong_prefixes = [
        "remember this:",
        "remember this ",
        "remember that ",
        "remember:",
        "memo:",
    ];
    for p in strong_prefixes {
        if let Some(raw_with_prefix) = lower.strip_prefix(p) {
            let raw = t[t.len() - raw_with_prefix.len()..].trim();
            return normalize_memory_content(raw, 180);
        }
    }

    // "remember <anything>" without a strong prefix — let the model handle it.
    // The model can call write_memory via proper tool use if it decides to save.

    let zh_prefixes = ["记住：", "记住:", "请记住", "记一下：", "记一下:"];
    for p in zh_prefixes {
        if let Some(raw) = t.strip_prefix(p) {
            let raw = raw.trim();
            return normalize_memory_content(raw, 180);
        }
    }
    None
}

pub fn memory_topic_key(content: &str) -> String {
    let lower = content.to_ascii_lowercase();
    if lower.contains("port") && (lower.contains("db") || lower.contains("database")) {
        return "db_port".to_string();
    }
    if lower.contains("deadline") || lower.contains("due date") {
        return "deadline".to_string();
    }
    if lower.contains("timezone") || lower.contains("time zone") {
        return "timezone".to_string();
    }
    if lower.contains("server ip") || lower.contains("ip address") {
        return "server_ip".to_string();
    }
    lower
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
        })
        .filter(|w| !w.is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .join("_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_explicit_memory_command() {
        // Strong prefixes — always save
        assert_eq!(
            extract_explicit_memory_command("Remember that prod db is on 5433"),
            Some("prod db is on 5433".to_string())
        );
        assert_eq!(
            extract_explicit_memory_command("Remember this: always use bun"),
            Some("always use bun".to_string())
        );
        assert_eq!(
            extract_explicit_memory_command("Remember: deploy on Fridays"),
            Some("deploy on Fridays".to_string())
        );
        assert_eq!(
            extract_explicit_memory_command("记住：下周三发布"),
            Some("下周三发布".to_string())
        );
        // Weak "remember " without strong prefix — NOT auto-saved (model handles via tool use)
        assert!(extract_explicit_memory_command("Remember prod db port is 5433").is_none());
        assert!(extract_explicit_memory_command("Remember I'm on windows").is_none());
        assert!(extract_explicit_memory_command("Remember, we need to fix that").is_none());
        assert!(extract_explicit_memory_command("Remember when we talked about this?").is_none());
        assert!(extract_explicit_memory_command("hello there").is_none());
    }

    #[test]
    fn test_memory_quality_reason() {
        assert!(memory_quality_ok("User prefers Rust and PostgreSQL."));
        assert!(!memory_quality_ok("hello"));
        assert!(!memory_quality_ok("maybe user likes tea"));
    }

    #[test]
    fn test_memory_topic_key() {
        assert_eq!(
            memory_topic_key("Production database port is 5433"),
            "db_port".to_string()
        );
        assert_eq!(
            memory_topic_key("Release deadline is Friday"),
            "deadline".to_string()
        );
    }

    #[test]
    fn test_memory_quality_eval_regression_set() {
        let dataset = vec![
            ("User's production DB port is 5433", true),
            ("User prefers concise bullet-point replies", true),
            ("Release deadline is 2026-03-01", true),
            ("Team uses Discord for on-call handoff", true),
            ("Hello", false),
            ("Thanks!", false),
            ("ok", false),
            ("maybe switch to postgres later", false),
            ("not sure but perhaps use rust", false),
            ("haha", false),
        ];
        let mut tp = 0usize;
        let mut fp = 0usize;
        let mut fnn = 0usize;
        for (text, expected) in dataset {
            let got = memory_quality_ok(text);
            if got && expected {
                tp += 1;
            } else if got && !expected {
                fp += 1;
            } else if !got && expected {
                fnn += 1;
            }
        }
        let precision = tp as f64 / (tp + fp).max(1) as f64;
        let recall = tp as f64 / (tp + fnn).max(1) as f64;
        assert!(
            precision >= 0.80,
            "precision regression: expected >= 0.80, got {precision:.2}"
        );
        assert!(
            recall >= 0.80,
            "recall regression: expected >= 0.80, got {recall:.2}"
        );
    }
}
