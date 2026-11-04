//! Per-project command allow rules ("always allow `cargo test` here").
//!
//! A rule is a command prefix of whole words. A shell command matches when it
//! starts with the prefix at a word boundary and is a single simple command:
//! anything with shell operators (`;`, `&&`, `|`, redirections, command
//! substitution, newlines) never matches, so `cargo test && rm -rf ~` is not
//! covered by a `cargo test` rule. Rules are stored in the Code home, never in
//! the repository, and the destructive-command list (`always_ask`) still wins.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Characters that make a command more than one simple command.
const SHELL_OPERATORS: &[&str] = &[";", "&", "|", ">", "<", "`", "$(", "\n", "\r", "${", "\\"];

/// Leading words that take a sub-command worth keeping in the prefix
/// (`npm run lint`, `cargo run --bin x` → `cargo run`).
const SUBCOMMAND_RUNNERS: &[&str] = &["run", "exec", "x"];

/// Programs that can run anything, escalate privileges or destroy data;
/// no rule may start with them.
const NEVER_ALLOW: &[&str] = &[
    "sh", "bash", "zsh", "fish", "env", "sudo", "su", "doas", "eval", "exec", "xargs", "python",
    "python3", "node", "perl", "ruby", "deno", "bun", "npx", "rm", "curl", "wget", "ssh", "scp",
    "find", "dd", "chmod", "chown", "nohup", "time", "watch", "command", "builtin", "source", ".",
];

/// Whether `command` is a single simple command an allow rule may cover.
pub fn is_simple_command(command: &str) -> bool {
    let command = command.trim();
    // Approval previews longer than 400 characters arrive truncated with
    // "..."; never match a command we cannot see in full.
    let truncated = command.chars().count() > 400 && command.ends_with("...");
    let compound = SHELL_OPERATORS.iter().any(|op| command.contains(op));
    !(command.is_empty() || truncated || compound)
}

fn words(text: &str) -> Vec<&str> {
    text.split_whitespace().collect()
}

/// Normalize a prefix: whole words, single spaces.
pub fn normalize(prefix: &str) -> String {
    words(prefix).join(" ")
}

/// Whether `prefix` can be used as a rule (non-empty, simple, not a bare
/// interpreter or privileged command).
pub fn is_allowable_prefix(prefix: &str) -> bool {
    let words = words(prefix);
    let Some(first) = words.first() else {
        return false;
    };
    is_simple_command(prefix) && !NEVER_ALLOW.contains(first)
}

/// Suggest a rule for `command`: the program and its sub-command
/// (`cargo test`, `npm run lint`, `go test`), stopping at the first flag,
/// path, assignment or quoted word. `None` when the command cannot be
/// covered by a rule.
pub fn suggest_prefix(command: &str) -> Option<String> {
    if !is_simple_command(command) {
        return None;
    }
    let plain = |w: &str| {
        !w.starts_with('-')
            && !w.contains(['/', '=', '"', '\'', '*', '?', '~', '$'])
            && !w.is_empty()
    };
    let all = words(command);
    let first = *all.first()?;
    if !plain(first) {
        return None;
    }
    let mut prefix = vec![first];
    if let Some(second) = all.get(1).filter(|w| plain(w)) {
        prefix.push(second);
        if SUBCOMMAND_RUNNERS.contains(second)
            && let Some(third) = all.get(2).filter(|w| plain(w))
        {
            prefix.push(third);
        }
    }
    let prefix = prefix.join(" ");
    is_allowable_prefix(&prefix).then_some(prefix)
}

/// Whether `command` is covered by `prefix`.
pub fn matches(prefix: &str, command: &str) -> bool {
    if !is_simple_command(command) {
        return false;
    }
    let rule = words(prefix);
    let cmd = words(command);
    !rule.is_empty() && cmd.len() >= rule.len() && cmd[..rule.len()] == rule[..]
}

/// Allow rules keyed by canonical project root.
#[derive(Debug, Clone)]
pub struct AllowRules {
    path: PathBuf,
    rules: BTreeMap<String, Vec<String>>,
}

impl AllowRules {
    /// Default location inside the Code home.
    pub fn default_path() -> PathBuf {
        crate::home::code_home().join("allow-rules.json")
    }

    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let rules = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self { path, rules }
    }

    fn key(root: &Path) -> String {
        std::fs::canonicalize(root)
            .unwrap_or_else(|_| root.to_path_buf())
            .to_string_lossy()
            .into_owned()
    }

    pub fn for_project(&self, root: &Path) -> &[String] {
        self.rules
            .get(&Self::key(root))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The rule covering `command` in `root`, if any.
    pub fn matching(&self, root: &Path, command: &str) -> Option<&str> {
        self.for_project(root)
            .iter()
            .find(|rule| matches(rule, command))
            .map(String::as_str)
    }

    /// Add a rule. Returns `Ok(false)` when it already existed.
    pub fn add(&mut self, root: &Path, prefix: &str) -> std::io::Result<bool> {
        let prefix = normalize(prefix);
        if !is_allowable_prefix(&prefix) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "`{prefix}` cannot be an allow rule (use a specific command such as `cargo test`)"
                ),
            ));
        }
        let rules = self.rules.entry(Self::key(root)).or_default();
        if rules.contains(&prefix) {
            return Ok(false);
        }
        rules.push(prefix);
        rules.sort();
        self.save()?;
        Ok(true)
    }

    /// Remove a rule. Returns `Ok(false)` when there was none.
    pub fn remove(&mut self, root: &Path, prefix: &str) -> std::io::Result<bool> {
        let prefix = normalize(prefix);
        let key = Self::key(root);
        let Some(rules) = self.rules.get_mut(&key) else {
            return Ok(false);
        };
        let before = rules.len();
        rules.retain(|r| *r != prefix);
        let removed = rules.len() != before;
        if rules.is_empty() {
            self.rules.remove(&key);
        }
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.rules).map_err(std::io::Error::other)?;
        std::fs::write(&self.path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_program_and_subcommand() {
        assert_eq!(
            suggest_prefix("cargo test -p foo").as_deref(),
            Some("cargo test")
        );
        assert_eq!(
            suggest_prefix("npm run lint -- --fix").as_deref(),
            Some("npm run lint")
        );
        assert_eq!(suggest_prefix("go test ./...").as_deref(), Some("go test"));
        assert_eq!(suggest_prefix("make").as_deref(), Some("make"));
        assert_eq!(suggest_prefix("ls -la").as_deref(), Some("ls"));
        assert_eq!(suggest_prefix("cargo test && rm -rf x"), None);
        assert_eq!(suggest_prefix("FOO=1 cargo test"), None);
        assert_eq!(suggest_prefix("./run.sh"), None);
        assert_eq!(suggest_prefix("bash -c 'x'"), None);
        assert_eq!(suggest_prefix("sudo make install"), None);
        assert_eq!(suggest_prefix("python3 -m pytest"), None);
        assert_eq!(suggest_prefix("rm foo"), None);
    }

    #[test]
    fn matching_requires_whole_words_and_a_simple_command() {
        assert!(matches("cargo test", "cargo test"));
        assert!(matches("cargo test", "cargo  test -p x"));
        assert!(!matches("cargo test", "cargo testing"));
        assert!(!matches("cargo test", "cargo build"));
        assert!(!matches("cargo test", "cargo test; rm -rf ~"));
        assert!(!matches("cargo test", "cargo test && git push"));
        assert!(!matches("cargo test", "cargo test | sh"));
        assert!(!matches("cargo test", "cargo test $(curl x)"));
        assert!(!matches("cargo test", "cargo test > /etc/passwd"));
        assert!(!matches("cargo test", "cargo test\nrm -rf ~"));
    }

    #[test]
    fn rules_persist_per_project() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let path = dir.path().join("allow.json");
        let mut rules = AllowRules::load(&path);
        assert!(rules.add(&a, " cargo   test ").unwrap());
        assert!(!rules.add(&a, "cargo test").unwrap());
        assert!(rules.add(&a, "bash").is_err());
        let reloaded = AllowRules::load(&path);
        assert_eq!(reloaded.for_project(&a), ["cargo test"]);
        assert_eq!(reloaded.matching(&a, "cargo test -q"), Some("cargo test"));
        assert_eq!(reloaded.matching(&b, "cargo test -q"), None);
        let mut rules = reloaded;
        assert!(rules.remove(&a, "cargo test").unwrap());
        assert!(!rules.remove(&a, "cargo test").unwrap());
        assert!(AllowRules::load(&path).for_project(&a).is_empty());
    }
}
