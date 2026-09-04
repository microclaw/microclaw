//! Dotenv file parsing utilities for skill environment injection.

use std::collections::HashMap;

/// Parse a dotenv-format string into a key-value map.
///
/// Supports:
/// - `KEY=value`
/// - `export KEY=value`
/// - Quoted values (`"value"` or `'value'`)
/// - Comments (`# ...`) and blank lines
pub fn parse_dotenv(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            if key.is_empty() {
                continue;
            }
            let actual_key = key.strip_prefix("export ").map(str::trim).unwrap_or(key);
            if actual_key.is_empty() {
                continue;
            }
            let val = unquote_env_value(trimmed[eq_pos + 1..].trim());
            map.insert(actual_key.to_string(), val);
        }
    }
    map
}

fn unquote_env_value(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv_basic() {
        let content = "KEY1=value1\nKEY2=value2\n# comment\n\nKEY3=\"quoted value\"";
        let map = parse_dotenv(content);
        assert_eq!(map.get("KEY1").unwrap(), "value1");
        assert_eq!(map.get("KEY2").unwrap(), "value2");
        assert_eq!(map.get("KEY3").unwrap(), "quoted value");
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn test_parse_dotenv_export_prefix() {
        let content = "export API_KEY=secret123\nexport BASE_URL='https://example.com'";
        let map = parse_dotenv(content);
        assert_eq!(map.get("API_KEY").unwrap(), "secret123");
        assert_eq!(map.get("BASE_URL").unwrap(), "https://example.com");
    }

    #[test]
    fn test_parse_dotenv_empty_and_comments() {
        let content = "# full comment\n\n  \n";
        let map = parse_dotenv(content);
        assert!(map.is_empty());
    }
}
