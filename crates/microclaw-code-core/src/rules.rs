//! Permission rules: `allow` / `ask` / `deny` per tool, path, command, domain.
//!
//! A rule is `<kind>(<pattern>)`:
//!
//! | kind    | subject                                   | pattern                         |
//! |---------|-------------------------------------------|---------------------------------|
//! | `bash`  | each simple command of a shell command    | words, `*` wildcard, prefix     |
//! | `read`  | `read_file` / `glob` / `grep` path        | glob (`src/**`, `**/.env`, `~/x`, `/abs`) |
//! | `edit`  | every path `write_file` / `edit_file` / `apply_patch` touches | glob |
//! | `net`   | host of a `web_fetch` URL                 | domain, `*.example.com`, `*`    |
//! | `mcp`   | MCP tool `server.tool`                    | glob (`github.delete_*`)        |
//! | `agent` | `explore` agent / `sessions_spawn` specialist | glob                        |
//! | `tool`  | raw tool name                             | glob                            |
//!
//! Claude Code spellings are accepted too: `Bash(npm test:*)`, `Read(...)`,
//! `Edit(...)`, `Write(...)` (= edit), `WebFetch(domain:x)` (= net),
//! `mcp__server__tool` (= `mcp(server.tool)`), `Task(x)` (= agent) and bare
//! tool names (`Bash`, `WebFetch`, `WebSearch`).
//!
//! Precedence: deny > ask > allow. For a shell command split into several
//! simple commands (`&&`, `||`, `;`, `|`, `&`, newlines, and the contents of
//! `$(…)` / backticks), deny and ask trigger when ANY part matches, allow
//! needs ALL parts to match. `apply_patch` works the same way over the files
//! it touches. Writing outside the project root asks (implicit rule) unless an
//! allow rule covers the path.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobMatcher};
use regex::Regex;
use serde_json::Value;

use crate::settings::PermissionsConfig;

/// What a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleKind {
    Bash,
    Read,
    Edit,
    Net,
    Mcp,
    Agent,
    Tool,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Read => "read",
            Self::Edit => "edit",
            Self::Net => "net",
            Self::Mcp => "mcp",
            Self::Agent => "agent",
            Self::Tool => "tool",
        }
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Effect {
    Allow,
    Ask,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// One parsed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub kind: RuleKind,
    pub pattern: String,
    pub effect: Effect,
    /// The rule as written in the settings file.
    pub source: String,
}

impl Rule {
    /// The rule in MicroClaw syntax (`bash(git push)`).
    pub fn canonical(&self) -> String {
        format!("{}({})", self.kind.as_str(), self.pattern)
    }
}

/// A rule that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub rule: String,
    pub message: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid permission rule `{}`: {}",
            self.rule, self.message
        )
    }
}

impl std::error::Error for RuleError {}

/// Parse `kind(pattern)` (or a Claude Code spelling) with the given effect.
pub fn parse_rule(text: &str, effect: Effect) -> Result<Rule, RuleError> {
    let source = text.trim().to_string();
    let err = |message: &str| RuleError {
        rule: source.clone(),
        message: message.to_string(),
    };
    if source.is_empty() {
        return Err(err("empty rule"));
    }
    let (kind_text, pattern) = match source.find('(') {
        Some(open) => {
            let Some(inner) = source[open + 1..].strip_suffix(')') else {
                return Err(err("missing closing `)`"));
            };
            (source[..open].trim(), Some(inner.trim()))
        }
        None => (source.as_str(), None),
    };
    if kind_text.is_empty() {
        return Err(err("missing rule kind"));
    }
    // Claude MCP names: mcp__server, mcp__server__tool, mcp__server__*.
    if let Some(rest) = kind_text.strip_prefix("mcp__") {
        if pattern.is_some() {
            return Err(err("`mcp__…` rules take no pattern"));
        }
        let pattern = match rest.split_once("__") {
            Some((server, tool)) if !tool.is_empty() => format!("{server}.{tool}"),
            Some((server, _)) => format!("{server}.*"),
            None => format!("{rest}.*"),
        };
        return Ok(Rule {
            kind: RuleKind::Mcp,
            pattern,
            effect,
            source,
        });
    }
    let lower = kind_text.to_ascii_lowercase();
    let (kind, default_pattern) = match lower.as_str() {
        "bash" | "shell" => (RuleKind::Bash, "*"),
        "read" => (RuleKind::Read, "**"),
        "edit" | "write" | "multiedit" | "notebookedit" => (RuleKind::Edit, "**"),
        "net" | "webfetch" | "web_fetch" | "domain" => (RuleKind::Net, "*"),
        "mcp" => (RuleKind::Mcp, "*"),
        "agent" | "task" | "subagent" | "sub_agent" => (RuleKind::Agent, "*"),
        "tool" => (RuleKind::Tool, "*"),
        _ if pattern.is_none() => {
            // Bare tool name (`web_search`, Claude `WebSearch`, `Glob`).
            let name = ours_from_claude_tool(kind_text);
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '*' | '?' | '.'))
            {
                return Err(err("unknown rule kind"));
            }
            return Ok(Rule {
                kind: RuleKind::Tool,
                pattern: name,
                effect,
                source,
            });
        }
        _ => {
            return Err(err(
                "unknown rule kind (use bash, read, edit, net, mcp, agent or tool)",
            ));
        }
    };
    let mut pattern = pattern.unwrap_or(default_pattern).to_string();
    if pattern.is_empty() {
        return Err(err("empty pattern"));
    }
    match kind {
        RuleKind::Bash => {
            // Claude `npm run test:*` = prefix `npm run test`.
            if let Some(prefix) = pattern.strip_suffix(":*") {
                pattern = format!("{} *", prefix.trim_end());
            }
            pattern = normalize_ws(&pattern);
        }
        RuleKind::Net => {
            if let Some(domain) = pattern.strip_prefix("domain:") {
                pattern = domain.trim().to_string();
            }
            pattern = normalize_domain_pattern(&pattern);
            if pattern.is_empty() {
                return Err(err("empty domain"));
            }
        }
        RuleKind::Read | RuleKind::Edit => {
            // Claude `//abs/path` = absolute.
            if pattern.starts_with("//") {
                pattern = pattern[1..].to_string();
            }
            if let Some(rest) = pattern.strip_prefix("./") {
                pattern = rest.to_string();
            }
            if Glob::new(&pattern).is_err() {
                return Err(err("invalid glob"));
            }
        }
        RuleKind::Mcp => {
            if let Some(rest) = pattern.strip_prefix("mcp__") {
                pattern = match rest.split_once("__") {
                    Some((s, t)) => format!("{s}.{t}"),
                    None => format!("{rest}.*"),
                };
            }
        }
        RuleKind::Agent | RuleKind::Tool => {}
    }
    Ok(Rule {
        kind,
        pattern,
        effect,
        source,
    })
}

/// Our tool name for a Claude Code tool name (identity for unknown names).
pub fn ours_from_claude_tool(name: &str) -> String {
    match name {
        "Bash" => "bash",
        "Read" => "read_file",
        "Write" => "write_file",
        "Edit" | "MultiEdit" => "edit_file",
        "Glob" => "glob",
        "Grep" => "grep",
        "WebFetch" => "web_fetch",
        "WebSearch" => "web_search",
        "Task" => "sessions_spawn",
        "TodoWrite" => "todo_write",
        other => other,
    }
    .to_string()
}

fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_domain_pattern(pattern: &str) -> String {
    let p = pattern.trim();
    let p = p
        .strip_prefix("https://")
        .or_else(|| p.strip_prefix("http://"))
        .unwrap_or(p);
    let p = p.split('/').next().unwrap_or_default();
    p.trim_end_matches('.').to_ascii_lowercase()
}

/// A rule that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub effect: Effect,
    /// The rule as written, or a description of an implicit rule.
    pub rule_source: String,
    /// Why, for implicit rules (`outside the project: /x`).
    pub reason: Option<String>,
}

/// Rule source of the implicit "writes outside the project ask" rule.
pub const OUTSIDE_PROJECT: &str = "outside the project";

#[derive(Debug)]
enum Compiled {
    Bash(Regex),
    Path(Vec<PathPattern>),
    Domain(String),
    Name(GlobMatcher),
}

#[derive(Debug)]
enum PathPattern {
    /// Matched against the path relative to the project root; for `**/…`
    /// patterns also against the absolute path.
    Relative(GlobMatcher, bool),
    Absolute(GlobMatcher),
}

#[derive(Debug)]
struct CompiledRule {
    rule: Rule,
    matcher: Compiled,
}

/// The effective rule set of one project.
#[derive(Debug, Default)]
pub struct PermissionRules {
    rules: Vec<CompiledRule>,
    root: PathBuf,
    canonical_root: Option<PathBuf>,
    warnings: Vec<String>,
    /// Effect for web requests no `net(...)` rule matched
    /// (`sandbox.network: ask` → Ask, `off` → Deny).
    network_default: Option<Effect>,
}

fn glob(pattern: &str) -> Option<GlobMatcher> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
}

fn name_glob(pattern: &str) -> Option<GlobMatcher> {
    Glob::new(pattern).ok().map(|g| g.compile_matcher())
}

fn has_glob_meta(text: &str) -> bool {
    text.contains(['*', '?', '[', '{'])
}

fn bash_regex(pattern: &str) -> Option<Regex> {
    if pattern == "*" {
        return Regex::new("(?s)^.*$").ok();
    }
    let (base, optional_tail) = match pattern.strip_suffix(" *") {
        Some(base) => (base, true),
        None => (pattern, !pattern.contains('*')),
    };
    let body = base
        .split('*')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(".*");
    let tail = if optional_tail { "(?: .*)?" } else { "" };
    Regex::new(&format!("(?s)^{body}{tail}$")).ok()
}

fn compile_path(pattern: &str, home: Option<&Path>) -> Option<Vec<PathPattern>> {
    let (text, absolute) = if let Some(rest) = pattern.strip_prefix("~/") {
        let home = home?;
        (
            format!(
                "{}/{rest}",
                globset::escape(home.to_string_lossy().trim_end_matches('/'))
            ),
            true,
        )
    } else if pattern == "~" {
        (globset::escape(&home?.to_string_lossy()), true)
    } else {
        (pattern.to_string(), Path::new(pattern).is_absolute())
    };
    let mut variants = vec![text.clone()];
    // A plain directory also covers what is below it.
    if !has_glob_meta(pattern) {
        variants.push(format!("{}/**", text.trim_end_matches('/')));
    }
    let any_depth = pattern.starts_with("**");
    variants
        .iter()
        .map(|v| {
            let m = glob(v)?;
            Some(if absolute {
                PathPattern::Absolute(m)
            } else {
                PathPattern::Relative(m, any_depth)
            })
        })
        .collect()
}

/// Resolve `.` and `..` without touching the file system.
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The absolute path a tool argument refers to (relative to `root`).
pub fn resolve_path(root: &Path, raw: &str) -> PathBuf {
    let raw = raw.trim();
    let path = if let Some(rest) = raw.strip_prefix("~/") {
        dirs::home_dir().unwrap_or_default().join(rest)
    } else {
        PathBuf::from(raw)
    };
    if path.is_absolute() {
        normalize_path(&path)
    } else {
        normalize_path(&root.join(path))
    }
}

/// Paths in an `apply_patch` envelope (added, updated, deleted, move targets).
pub fn patch_paths(patch: &str) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    patch
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            MARKERS
                .iter()
                .find_map(|m| line.strip_prefix(m))
                .map(|p| p.trim().to_string())
        })
        .filter(|p| !p.is_empty())
        .collect()
}

/// Tools that change files, and the paths a call would touch (absolute).
pub fn edited_paths(tool: &str, input: &Value, root: &Path) -> Option<Vec<PathBuf>> {
    let str_field = |k: &str| input.get(k).and_then(Value::as_str);
    match tool {
        "write_file" | "edit_file" => Some(
            str_field("path")
                .or_else(|| str_field("file_path"))
                .map(|p| vec![resolve_path(root, p)])
                .unwrap_or_default(),
        ),
        "apply_patch" => Some(
            patch_paths(
                str_field("patch")
                    .or_else(|| str_field("input"))
                    .unwrap_or(""),
            )
            .iter()
            .map(|p| resolve_path(root, p))
            .collect(),
        ),
        _ => None,
    }
}

/// Whether `tool` writes files (`write_file`, `edit_file`, `apply_patch`).
pub fn is_edit_tool(tool: &str) -> bool {
    matches!(tool, "write_file" | "edit_file" | "apply_patch")
}

fn read_paths(tool: &str, input: &Value, root: &Path) -> Option<Vec<PathBuf>> {
    let path = input
        .get("path")
        .or_else(|| input.get("file_path"))
        .and_then(Value::as_str);
    match tool {
        "read_file" => Some(
            path.map(|p| vec![resolve_path(root, p)])
                .unwrap_or_default(),
        ),
        "glob" | "grep" => Some(vec![resolve_path(root, path.unwrap_or("."))]),
        _ => None,
    }
}

/// Host of a URL, lowercased.
fn url_host(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn domain_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(base) = pattern.strip_prefix("*.") {
        return host == base || host.ends_with(&format!(".{base}"));
    }
    pattern == host
}

/// Split a shell command into simple commands: on `&&`, `||`, `;`, `|`, `&`
/// and newlines outside quotes; the contents of `$(…)`, `<(…)` and backticks
/// become extra parts. Leading/trailing whitespace is trimmed and empty parts
/// dropped.
pub fn split_commands(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    split_into(command, &mut parts, 0);
    parts
}

fn split_into(command: &str, parts: &mut Vec<String>, depth: usize) {
    let chars: Vec<char> = command.chars().collect();
    let mut current = String::new();
    let mut i = 0;
    let (mut single, mut double) = (false, false);
    let flush = |current: &mut String, parts: &mut Vec<String>| {
        let part = normalize_ws(current);
        if !part.is_empty() {
            parts.push(part);
        }
        current.clear();
    };
    while i < chars.len() {
        let c = chars[i];
        if single {
            current.push(c);
            if c == '\'' {
                single = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\\' if i + 1 < chars.len() => {
                current.push(c);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            '\'' if !double => single = true,
            '"' => double = !double,
            '`' => {
                // Backtick substitution: extract until the closing backtick.
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '`' {
                    j += if chars[j] == '\\' { 2 } else { 1 };
                }
                let inner: String = chars[i + 1..j.min(chars.len())].iter().collect();
                if depth < 8 {
                    split_into(&inner, parts, depth + 1);
                }
                current.extend(&chars[i..(j + 1).min(chars.len())]);
                i = j + 1;
                continue;
            }
            '$' | '<' | '>' if chars.get(i + 1) == Some(&'(') => {
                // $(…), <(…), >(…): find the matching parenthesis.
                let mut level = 0usize;
                let mut j = i + 1;
                let (mut sq, mut dq) = (false, false);
                while j < chars.len() {
                    let d = chars[j];
                    if sq {
                        sq = d != '\'';
                    } else if d == '\\' {
                        j += 1;
                    } else if d == '\'' && !dq {
                        sq = true;
                    } else if d == '"' {
                        dq = !dq;
                    } else if d == '(' && !dq {
                        level += 1;
                    } else if d == ')' && !dq {
                        level -= 1;
                        if level == 0 {
                            break;
                        }
                    }
                    j += 1;
                }
                let inner: String = chars[i + 2..j.min(chars.len())].iter().collect();
                if depth < 8 {
                    split_into(&inner, parts, depth + 1);
                }
                current.extend(&chars[i..(j + 1).min(chars.len())]);
                i = j + 1;
                continue;
            }
            _ if double => {}
            ';' | '\n' | '\r' => {
                flush(&mut current, parts);
                i += 1;
                continue;
            }
            '&' | '|' => {
                // `2>&1` / `>&2` / `&>` are redirections, not separators.
                let prev = current.chars().last();
                let redirect = c == '&'
                    && (prev == Some('>') || prev == Some('<') || chars.get(i + 1) == Some(&'>'));
                if !redirect {
                    flush(&mut current, parts);
                    while i + 1 < chars.len() && chars[i + 1] == c {
                        i += 1;
                    }
                    i += 1;
                    continue;
                }
            }
            _ => {}
        }
        current.push(c);
        i += 1;
    }
    flush(&mut current, parts);
}

/// `FOO=1 BAR=2 cmd args` → `cmd args`.
fn strip_assignments(part: &str) -> &str {
    let mut rest = part;
    loop {
        let word_end = rest.find(' ').unwrap_or(rest.len());
        let word = &rest[..word_end];
        let is_assignment = word.find('=').is_some_and(|eq| {
            eq > 0
                && word[..eq]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        if !is_assignment || word_end == rest.len() {
            return rest;
        }
        rest = rest[word_end..].trim_start();
    }
}

/// Whether a simple command writes through a redirection to a real file
/// (`> x`, `>> x`); `/dev/null` and fd duplications are harmless.
fn has_file_redirect(part: &str) -> bool {
    let chars: Vec<char> = part.chars().collect();
    let (mut single, mut double) = (false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => i += 1,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '>' if !single && !double => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j] == '>' || chars[j] == '|') {
                    j += 1;
                }
                if chars.get(j) == Some(&'&') {
                    i = j + 1;
                    continue;
                }
                while j < chars.len() && chars[j] == ' ' {
                    j += 1;
                }
                let target: String = chars[j..]
                    .iter()
                    .take_while(|c| !c.is_whitespace())
                    .collect();
                if target != "/dev/null" {
                    return true;
                }
                i = j;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

impl PermissionRules {
    /// No rules.
    /// Apply `sandbox.allow_domains` (allow rules) and the network mode's
    /// default for other domains.
    pub fn with_network(mut self, default: Option<Effect>, allow_domains: &[String]) -> Self {
        self.network_default = default;
        if !allow_domains.is_empty() {
            let root = self.root.clone();
            let mut extra: Vec<Rule> = Vec::new();
            for d in allow_domains {
                if let Ok(rule) = parse_rule(&format!("net({d})"), Effect::Allow) {
                    extra.push(rule);
                }
            }
            let mut more = Self::from_rules(extra, &root);
            self.rules.append(&mut more.rules);
            self.warnings.append(&mut more.warnings);
        }
        self
    }

    pub fn empty(project_root: &Path) -> Self {
        Self::from_rules(Vec::new(), project_root)
    }

    /// Rules from a merged settings `permissions` section. Unparsable rules
    /// are skipped and reported by [`PermissionRules::warnings`].
    pub fn from_config(config: &PermissionsConfig, project_root: &Path) -> Self {
        let mut rules = Vec::new();
        let mut warnings = Vec::new();
        for (list, effect) in [
            (&config.deny, Effect::Deny),
            (&config.ask, Effect::Ask),
            (&config.allow, Effect::Allow),
        ] {
            for text in list {
                match parse_rule(text, effect) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => warnings.push(e.to_string()),
                }
            }
        }
        let mut out = Self::from_rules(rules, project_root);
        out.warnings.extend(warnings);
        out
    }

    /// Rules already parsed.
    pub fn from_rules(rules: Vec<Rule>, project_root: &Path) -> Self {
        Self::build(rules, project_root, dirs::home_dir().as_deref())
    }

    fn build(rules: Vec<Rule>, project_root: &Path, home: Option<&Path>) -> Self {
        let root = normalize_path(project_root);
        let canonical_root = std::fs::canonicalize(&root).ok().filter(|c| *c != root);
        let mut warnings = Vec::new();
        let mut compiled = Vec::new();
        for rule in rules {
            let matcher = match rule.kind {
                RuleKind::Bash => bash_regex(&rule.pattern).map(Compiled::Bash),
                RuleKind::Read | RuleKind::Edit => {
                    compile_path(&rule.pattern, home).map(Compiled::Path)
                }
                RuleKind::Net => Some(Compiled::Domain(rule.pattern.clone())),
                RuleKind::Mcp => {
                    let p = &rule.pattern;
                    let name = if p.starts_with("mcp_") {
                        p.clone()
                    } else {
                        match p.split_once('.') {
                            Some((server, tool)) => format!("mcp_{server}_{tool}"),
                            None => format!("mcp_{p}_*"),
                        }
                    };
                    name_glob(&name).map(Compiled::Name)
                }
                RuleKind::Agent | RuleKind::Tool => name_glob(&rule.pattern).map(Compiled::Name),
            };
            match matcher {
                Some(matcher) => compiled.push(CompiledRule { rule, matcher }),
                None => warnings.push(format!(
                    "invalid permission rule `{}`: bad pattern",
                    rule.source
                )),
            }
        }
        Self {
            rules: compiled,
            root,
            canonical_root,
            warnings,
            network_default: None,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(|c| &c.rule)
    }

    fn relative<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        path.strip_prefix(&self.root).ok().or_else(|| {
            self.canonical_root
                .as_ref()
                .and_then(|c| path.strip_prefix(c).ok())
        })
    }

    /// Whether `path` (absolute) is inside the project root.
    pub fn is_inside(&self, path: &Path) -> bool {
        self.relative(path).is_some()
    }

    fn path_matches(&self, patterns: &[PathPattern], path: &Path) -> bool {
        let rel = self.relative(path);
        patterns.iter().any(|p| match p {
            PathPattern::Absolute(m) => m.is_match(path),
            PathPattern::Relative(m, any_depth) => {
                rel.is_some_and(|r| m.is_match(r)) || (*any_depth && m.is_match(path))
            }
        })
    }

    fn first(
        &self,
        kind: RuleKind,
        effect: Effect,
        mut pred: impl FnMut(&Compiled) -> bool,
    ) -> Option<&Rule> {
        self.rules
            .iter()
            .filter(|c| c.rule.kind == kind && c.rule.effect == effect)
            .find(|c| pred(&c.matcher))
            .map(|c| &c.rule)
    }

    fn bash_part_matches(matcher: &Compiled, part: &str, for_allow: bool) -> bool {
        let Compiled::Bash(re) = matcher else {
            return false;
        };
        if for_allow {
            // Allow needs the command as written (assignments such as
            // LD_PRELOAD=… must be part of the rule) and no file redirection
            // unless the rule spells one out.
            re.is_match(part) && (!has_file_redirect(part) || re.as_str().contains('>'))
        } else {
            re.is_match(part) || re.is_match(strip_assignments(part))
        }
    }

    /// Match a shell command against the bash rules.
    pub fn evaluate_command(&self, command: &str) -> Option<Match> {
        let parts = split_commands(command);
        if parts.is_empty() {
            return None;
        }
        for effect in [Effect::Deny, Effect::Ask] {
            for part in &parts {
                if let Some(rule) = self.first(RuleKind::Bash, effect, |m| {
                    Self::bash_part_matches(m, part, false)
                }) {
                    return Some(found(rule));
                }
            }
        }
        let mut first_rule = None;
        for part in &parts {
            let rule = self.first(RuleKind::Bash, Effect::Allow, |m| {
                Self::bash_part_matches(m, part, true)
            })?;
            first_rule.get_or_insert(rule);
        }
        first_rule.map(found)
    }

    /// The allow rule covering every part of `command`, when no deny or ask
    /// rule matches it (for the driver's bash auto-approval).
    pub fn allows_command(&self, command: &str) -> Option<&str> {
        let m = self.evaluate_command(command)?;
        if m.effect != Effect::Allow {
            return None;
        }
        self.rules
            .iter()
            .map(|c| &c.rule)
            .find(|r| r.source == m.rule_source && r.effect == Effect::Allow)
            .map(|r| r.source.as_str())
    }

    fn evaluate_paths(&self, kind: RuleKind, paths: &[PathBuf]) -> Option<Match> {
        if paths.is_empty() {
            return None;
        }
        for effect in [Effect::Deny, Effect::Ask] {
            for path in paths {
                if let Some(rule) = self.first(kind, effect, |m| match m {
                    Compiled::Path(p) => self.path_matches(p, path),
                    _ => false,
                }) {
                    return Some(found(rule));
                }
            }
        }
        let mut first_rule = None;
        let mut all = true;
        for path in paths {
            match self.first(kind, Effect::Allow, |m| match m {
                Compiled::Path(p) => self.path_matches(p, path),
                _ => false,
            }) {
                Some(rule) => {
                    first_rule.get_or_insert(rule);
                }
                None => all = false,
            }
        }
        if kind == RuleKind::Edit
            && !all
            && let Some(outside) = paths.iter().find(|p| !self.is_inside(p))
        {
            return Some(Match {
                effect: Effect::Ask,
                rule_source: OUTSIDE_PROJECT.into(),
                reason: Some(format!("{OUTSIDE_PROJECT}: {}", outside.display())),
            });
        }
        if all { first_rule.map(found) } else { None }
    }

    fn evaluate_names(&self, kind: RuleKind, names: &[String]) -> Option<Match> {
        [Effect::Deny, Effect::Ask, Effect::Allow]
            .into_iter()
            .find_map(|effect| {
                self.first(kind, effect, |m| match m {
                    Compiled::Name(g) => names.iter().any(|n| g.is_match(n)),
                    _ => false,
                })
            })
            .map(found)
    }

    fn evaluate_domain(&self, host: &str) -> Option<Match> {
        [Effect::Deny, Effect::Ask, Effect::Allow]
            .into_iter()
            .find_map(|effect| {
                self.first(RuleKind::Net, effect, |m| match m {
                    Compiled::Domain(d) => domain_matches(d, host),
                    _ => false,
                })
            })
            .map(found)
    }

    /// Decide on one tool call. `None` when no rule applies (the normal
    /// approval rules decide).
    pub fn evaluate_call(&self, tool: &str, input: &Value) -> Option<Match> {
        let mut matches = Vec::new();
        let str_field = |k: &str| input.get(k).and_then(Value::as_str);
        if tool == "bash" {
            matches.extend(str_field("command").and_then(|c| self.evaluate_command(c)));
        }
        if let Some(paths) = read_paths(tool, input, &self.root) {
            matches.extend(self.evaluate_paths(RuleKind::Read, &paths));
        }
        if let Some(paths) = edited_paths(tool, input, &self.root) {
            matches.extend(self.evaluate_paths(RuleKind::Edit, &paths));
        }
        if tool == "web_fetch"
            && let Some(host) = str_field("url").and_then(url_host)
        {
            match self.evaluate_domain(&host) {
                Some(m) => matches.push(m),
                None => {
                    if let Some(effect) = self.network_default {
                        matches.push(Match {
                            effect,
                            rule_source: format!(
                                "sandbox.network ({host} is not in allow_domains)"
                            ),
                            reason: None,
                        });
                    }
                }
            }
        }
        if tool.starts_with("mcp_") {
            matches.extend(self.evaluate_names(RuleKind::Mcp, &[tool.to_string()]));
        }
        if let Some(names) = agent_names(tool, input) {
            matches.extend(self.evaluate_names(RuleKind::Agent, &names));
        }
        // `tool(...)` last: among equally strong matches the more specific
        // rule is reported.
        matches.extend(self.evaluate_names(RuleKind::Tool, &[tool.to_string()]));
        // Strongest effect wins; among equals, the first found.
        let best = matches.iter().map(|m| m.effect).max()?;
        matches.into_iter().find(|m| m.effect == best)
    }
}

fn found(rule: &Rule) -> Match {
    Match {
        effect: rule.effect,
        rule_source: rule.source.clone(),
        reason: None,
    }
}

/// Agent names a delegation call uses: `explore` (or its project `agent`),
/// `sessions_spawn` / `sub_agent` (its `specialist` / `agent`, default
/// `generalist`).
fn agent_names(tool: &str, input: &Value) -> Option<Vec<String>> {
    let field = |k: &str| {
        input
            .get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    match tool {
        "explore" => Some(vec![field("agent").unwrap_or_else(|| "explore".into())]),
        "sessions_spawn" | "sub_agent" => Some(vec![
            field("specialist")
                .or_else(|| field("agent"))
                .unwrap_or_else(|| "generalist".into()),
        ]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules(allow: &[&str], ask: &[&str], deny: &[&str]) -> PermissionRules {
        let config = PermissionsConfig {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ask: ask.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let parsed: Vec<Rule> = [
            (&config.deny, Effect::Deny),
            (&config.ask, Effect::Ask),
            (&config.allow, Effect::Allow),
        ]
        .into_iter()
        .flat_map(|(list, e)| list.iter().map(move |t| parse_rule(t, e).unwrap()))
        .collect();
        PermissionRules::build(parsed, Path::new("/repo"), Some(Path::new("/home/u")))
    }

    fn effect(r: &PermissionRules, tool: &str, input: Value) -> Option<Effect> {
        r.evaluate_call(tool, &input).map(|m| m.effect)
    }

    #[test]
    fn parses_ours_and_claude_spellings() {
        let p = |t| parse_rule(t, Effect::Allow).unwrap();
        assert_eq!(p("bash(git push)").kind, RuleKind::Bash);
        assert_eq!(p("Bash(npm run test:*)").pattern, "npm run test *");
        assert_eq!(p("BASH(  git   status )").pattern, "git status");
        assert_eq!(p("Write(src/**)").kind, RuleKind::Edit);
        assert_eq!(p("Edit(./src/**)").pattern, "src/**");
        assert_eq!(p("Read(//etc/hosts)").pattern, "/etc/hosts");
        let net = p("WebFetch(domain:Docs.RS)");
        assert_eq!((net.kind, net.pattern.as_str()), (RuleKind::Net, "docs.rs"));
        let mcp = p("mcp__github__delete_repo");
        assert_eq!(
            (mcp.kind, mcp.pattern.as_str()),
            (RuleKind::Mcp, "github.delete_repo")
        );
        assert_eq!(p("mcp__github").pattern, "github.*");
        assert_eq!(p("Task(reviewer)").kind, RuleKind::Agent);
        let bare = p("WebSearch");
        assert_eq!(
            (bare.kind, bare.pattern.as_str()),
            (RuleKind::Tool, "web_search")
        );
        assert_eq!(p("Bash").pattern, "*");
        assert_eq!(p("bash(x)").canonical(), "bash(x)");
        assert_eq!(p("bash(x)").source, "bash(x)");
        assert!(parse_rule("bash(x", Effect::Allow).is_err());
        assert!(parse_rule("frob(x)", Effect::Allow).is_err());
        assert!(parse_rule("bash()", Effect::Allow).is_err());
        assert!(parse_rule("", Effect::Allow).is_err());
    }

    #[test]
    fn from_config_reports_bad_rules() {
        let config = PermissionsConfig {
            allow: vec!["bash(cargo test)".into(), "nope(x)".into()],
            ..Default::default()
        };
        let r = PermissionRules::from_config(&config, Path::new("/repo"));
        assert_eq!(r.rules().count(), 1);
        assert_eq!(r.warnings().len(), 1);
        assert!(r.warnings()[0].contains("nope(x)"));
    }

    #[test]
    fn splits_compound_commands() {
        assert_eq!(
            split_commands("cargo test && git push origin || echo 'a && b'; ls | wc -l"),
            vec![
                "cargo test",
                "git push origin",
                "echo 'a && b'",
                "ls",
                "wc -l"
            ]
        );
        assert_eq!(split_commands("a\nb & c"), vec!["a", "b", "c"]);
        assert_eq!(split_commands("make 2>&1"), vec!["make 2>&1"]);
        let parts = split_commands("echo $(rm -rf /) `curl x`");
        assert!(parts.contains(&"rm -rf /".to_string()));
        assert!(parts.contains(&"curl x".to_string()));
        assert_eq!(split_commands("echo \"x; y\""), vec!["echo \"x; y\""]);
    }

    #[test]
    fn bash_prefix_and_wildcards() {
        let r = rules(
            &["bash(cargo test)", "bash(git status)"],
            &["bash(git push *)"],
            &["bash(rm -rf *)"],
        );
        let m = |c: &str| r.evaluate_command(c).map(|m| m.effect);
        assert_eq!(m("cargo test -p x"), Some(Effect::Allow));
        assert_eq!(m("cargo testing"), None);
        assert_eq!(m("git push"), Some(Effect::Ask));
        assert_eq!(m("git push origin main"), Some(Effect::Ask));
        assert_eq!(m("cargo test && git push"), Some(Effect::Ask));
        assert_eq!(m("cargo test && rm -rf target"), Some(Effect::Deny));
        assert_eq!(m("FOO=1 rm -rf /"), Some(Effect::Deny));
        assert_eq!(m("echo $(rm -rf /)"), Some(Effect::Deny));
        // Allow needs every part.
        assert_eq!(m("cargo test && git status"), Some(Effect::Allow));
        assert_eq!(m("cargo test && ls"), None);
        assert_eq!(m("cargo test > /etc/passwd"), None);
        assert_eq!(m("cargo test 2>&1 > /dev/null"), Some(Effect::Allow));
        assert_eq!(m("LD_PRELOAD=x cargo test"), None);
        assert_eq!(r.allows_command("cargo test -q"), Some("bash(cargo test)"));
        assert_eq!(r.allows_command("git push"), None);
        let star = rules(&["bash(npm run *:check)"], &[], &[]);
        assert!(star.allows_command("npm run lint:check").is_some());
        assert!(star.allows_command("npm run lint").is_none());
    }

    #[test]
    fn read_and_edit_globs() {
        let r = rules(
            &["edit(src/**)", "edit(~/notes/**)"],
            &[],
            &["read(**/.env)", "read(/etc/**)", "edit(Cargo.lock)"],
        );
        assert_eq!(
            effect(&r, "read_file", json!({"path": ".env"})),
            Some(Effect::Deny)
        );
        assert_eq!(
            effect(&r, "read_file", json!({"path": "a/b/.env"})),
            Some(Effect::Deny)
        );
        assert_eq!(
            effect(&r, "read_file", json!({"path": "/other/.env"})),
            Some(Effect::Deny)
        );
        assert_eq!(
            effect(&r, "read_file", json!({"path": "/etc/hosts"})),
            Some(Effect::Deny)
        );
        assert_eq!(effect(&r, "read_file", json!({"path": "src/x.rs"})), None);
        assert_eq!(
            effect(&r, "edit_file", json!({"path": "src/a/b.rs"})),
            Some(Effect::Allow)
        );
        assert_eq!(
            effect(&r, "write_file", json!({"path": "./src/../src/c.rs"})),
            Some(Effect::Allow)
        );
        assert_eq!(
            effect(&r, "write_file", json!({"path": "/home/u/notes/a.md"})),
            Some(Effect::Allow)
        );
        assert_eq!(effect(&r, "write_file", json!({"path": "README.md"})), None);
        assert_eq!(
            effect(&r, "write_file", json!({"path": "Cargo.lock"})),
            Some(Effect::Deny)
        );
        // Outside the project: implicit ask.
        let out = r
            .evaluate_call("write_file", &json!({"path": "/tmp/x"}))
            .unwrap();
        assert_eq!(out.effect, Effect::Ask);
        assert_eq!(out.rule_source, OUTSIDE_PROJECT);
        assert_eq!(
            effect(&r, "write_file", json!({"path": "../x"})),
            Some(Effect::Ask)
        );
        // apply_patch: every path.
        let patch = "*** Begin Patch\n*** Add File: src/new.rs\n+x\n*** Update File: src/lib.rs\n*** Move to: src/core.rs\n*** End Patch";
        assert_eq!(
            effect(&r, "apply_patch", json!({"patch": patch})),
            Some(Effect::Allow)
        );
        let patch2 =
            "*** Begin Patch\n*** Add File: src/new.rs\n*** Delete File: Cargo.lock\n*** End Patch";
        assert_eq!(
            effect(&r, "apply_patch", json!({"patch": patch2})),
            Some(Effect::Deny)
        );
        let patch3 =
            "*** Begin Patch\n*** Add File: src/new.rs\n*** Add File: docs/x.md\n*** End Patch";
        assert_eq!(effect(&r, "apply_patch", json!({"patch": patch3})), None);
        // Directories cover what is below them.
        let d = rules(&["edit(docs)"], &[], &[]);
        assert_eq!(
            effect(&d, "write_file", json!({"path": "docs/a/b.md"})),
            Some(Effect::Allow)
        );
    }

    #[test]
    fn net_mcp_agent_tool() {
        let r = rules(
            &["net(*.crates.io)", "mcp(github.*)", "agent(reviewer)"],
            &["net(*)", "tool(web_search)"],
            &["mcp(github.delete_*)", "net(evil.com)", "agent(generalist)"],
        );
        assert_eq!(
            effect(
                &r,
                "web_fetch",
                json!({"url": "https://static.crates.io/x"})
            ),
            Some(Effect::Ask)
        );
        let only = rules(&["net(*.crates.io)"], &[], &["net(evil.com)"]);
        assert_eq!(
            effect(&only, "web_fetch", json!({"url": "https://crates.io/"})),
            Some(Effect::Allow)
        );
        assert_eq!(
            effect(
                &only,
                "web_fetch",
                json!({"url": "https://static.crates.io:443/a"})
            ),
            Some(Effect::Allow)
        );
        assert_eq!(
            effect(&only, "web_fetch", json!({"url": "http://user@EVIL.com/a"})),
            Some(Effect::Deny)
        );
        assert_eq!(
            effect(&only, "web_fetch", json!({"url": "https://notcrates.io/"})),
            None
        );
        assert_eq!(
            effect(&r, "mcp_github_delete_repo", json!({})),
            Some(Effect::Deny)
        );
        assert_eq!(
            effect(&r, "mcp_github_list_issues", json!({})),
            Some(Effect::Allow)
        );
        assert_eq!(effect(&r, "mcp_gitlab_x", json!({})), None);
        assert_eq!(effect(&r, "web_search", json!({})), Some(Effect::Ask));
        assert_eq!(
            effect(&r, "explore", json!({"agent": "reviewer"})),
            Some(Effect::Allow)
        );
        assert_eq!(
            effect(&r, "sessions_spawn", json!({"task": "x"})),
            Some(Effect::Deny)
        );
        let bash = rules(&[], &[], &["tool(bash)"]);
        assert_eq!(
            effect(&bash, "bash", json!({"command": "ls"})),
            Some(Effect::Deny)
        );
    }

    #[test]
    fn deny_beats_allow_across_kinds() {
        let r = rules(&["tool(bash)"], &[], &["bash(git push *)"]);
        assert_eq!(
            effect(&r, "bash", json!({"command": "git push"})),
            Some(Effect::Deny)
        );
        assert_eq!(
            effect(&r, "bash", json!({"command": "ls"})),
            Some(Effect::Allow)
        );
    }
}
