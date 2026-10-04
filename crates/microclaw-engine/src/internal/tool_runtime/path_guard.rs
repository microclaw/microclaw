use std::path::{Component, Path, PathBuf};

/// Directory components that are always blocked.
const BLOCKED_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube"];

/// Blocked subpath (checked as consecutive components).
const BLOCKED_SUBPATHS: &[&[&str]] = &[&[".config", "gcloud"]];

/// File names that are always blocked (exact component match).
const BLOCKED_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "credentials",
    "credentials.json",
    "token.json",
    "secrets.yaml",
    "secrets.json",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_dsa",
    "id_dsa.pub",
    ".netrc",
    ".npmrc",
];

/// Absolute paths that are always blocked.
const BLOCKED_ABSOLUTE: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];

fn default_path_allowlist_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))?;
    Some(home.join(".microclaw/sandbox-path-allowlist.txt"))
}

/// The path allowlist file in effect (`MICROCLAW_PATH_ALLOWLIST` or the
/// default under `~/.microclaw`), whether or not it exists.
pub fn path_allowlist_file() -> Option<PathBuf> {
    std::env::var_os("MICROCLAW_PATH_ALLOWLIST")
        .map(PathBuf::from)
        .or_else(default_path_allowlist_path)
}

/// File names that make up the agent's own prompt-injected governance layer
/// (memory, personality, user model) when they live in the data directory.
const GOVERNANCE_FILE_NAMES: &[&str] = &["AGENTS.md", "SOUL.md", "USER.md"];

/// Write guard for MicroClaw's own governance files: the config file, the
/// AGENTS.md / SOUL.md / USER.md files under the data directory, soul and
/// project-context directories, and the path allowlist. These are injected
/// into other chats' prompts or define access policy, so the generic file
/// tools must not rewrite them; scoped tools (`write_memory`) keep their own
/// permission checks. An empty guard allows everything.
#[derive(Clone, Debug, Default)]
pub struct GovernanceGuard {
    protected_files: Vec<PathBuf>,
    protected_dirs: Vec<PathBuf>,
    /// Roots under which governance file names are protected by name.
    data_roots: Vec<PathBuf>,
    /// Roots exempt from the by-name rule (the agent's working directory,
    /// where a project may legitimately carry its own AGENTS.md).
    exempt_roots: Vec<PathBuf>,
}

impl GovernanceGuard {
    pub fn protect_file(mut self, path: impl AsRef<Path>) -> Self {
        self.protected_files
            .push(resolve_for_compare(path.as_ref()));
        self
    }

    pub fn protect_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.protected_dirs.push(resolve_for_compare(path.as_ref()));
        self
    }

    pub fn protect_data_root(mut self, path: impl AsRef<Path>) -> Self {
        self.data_roots.push(resolve_for_compare(path.as_ref()));
        self
    }

    pub fn exempt(mut self, path: impl AsRef<Path>) -> Self {
        self.exempt_roots.push(resolve_for_compare(path.as_ref()));
        self
    }

    /// Returns Err(message) when `path` is a protected governance path.
    pub fn check_write(&self, path: &Path) -> Result<(), String> {
        let target = resolve_for_compare(path);
        if self.is_protected(&target) {
            Err(format!(
                "Access denied: '{}' is a MicroClaw governance file (config, memory, soul or \
                 context) and cannot be modified with file tools. Use write_memory for memory; \
                 the operator manages the rest.",
                path.display()
            ))
        } else {
            Ok(())
        }
    }

    fn is_protected(&self, target: &Path) -> bool {
        if self.protected_files.iter().any(|f| paths_equal(target, f)) {
            return true;
        }
        if self
            .protected_dirs
            .iter()
            .any(|d| path_starts_with(target, d))
        {
            return true;
        }
        if self
            .exempt_roots
            .iter()
            .any(|r| path_starts_with(target, r))
        {
            return false;
        }
        let Some(root) = self
            .data_roots
            .iter()
            .find(|root| path_starts_with(target, root))
        else {
            return false;
        };
        let file_name = target
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if GOVERNANCE_FILE_NAMES
            .iter()
            .any(|name| file_name.eq_ignore_ascii_case(name))
        {
            return true;
        }
        // Chat-scoped project context: <data>/.../groups/<channel>/<chat>/context/**
        let relative: Vec<String> = target
            .strip_prefix(root)
            .map(|rel| {
                rel.components()
                    .filter_map(|c| match c {
                        Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        relative
            .iter()
            .position(|c| c == "groups")
            .is_some_and(|i| relative[i + 1..].iter().any(|c| c == "context"))
    }
}

/// Resolve a path for comparison: canonicalize the longest existing ancestor
/// (so `/var` vs `/private/var` and `..` tricks cannot slip past) and append
/// the not-yet-existing remainder.
fn resolve_for_compare(path: &Path) -> PathBuf {
    let abs = if path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    let abs = normalize_path(&abs);
    let mut existing = abs.as_path();
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(existing) {
            let mut out = canonical;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                existing = parent;
            }
            _ => return abs,
        }
    }
}

fn case_insensitive_fs() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    if case_insensitive_fs() {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

fn path_starts_with(path: &Path, root: &Path) -> bool {
    if case_insensitive_fs() {
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(path).starts_with(lower(root))
    } else {
        path.starts_with(root)
    }
}

/// Check if a path is blocked. Returns Err(message) if blocked.
pub fn check_path(path: &str) -> Result<(), String> {
    let candidate = Path::new(path);
    if let Err(err) = validate_symlink_safety(candidate) {
        return Err(format!(
            "Access denied: '{path}' symlink validation failed: {err}"
        ));
    }
    if let Err(err) = validate_allowlist(candidate) {
        return Err(format!("Access denied: {err}"));
    }
    if is_blocked(candidate) {
        Err(format!(
            "Access denied: '{}' is a sensitive path and cannot be accessed.",
            path
        ))
    } else {
        Ok(())
    }
}

/// Logically normalize a path by resolving `.` and `..` components without
/// requiring the path to exist on the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
    let mut parts: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Pop the last Normal component if possible
                if matches!(parts.last(), Some(Component::Normal(_))) {
                    parts.pop();
                } else if matches!(parts.last(), Some(Component::RootDir)) {
                    // Already at root; `..` above root stays at root
                } else {
                    parts.push(component);
                }
            }
            _ => parts.push(component),
        }
    }
    parts.iter().collect()
}

/// Check if a file path should be blocked.
pub fn is_blocked(path: &Path) -> bool {
    // Try to resolve symlinks; if the file doesn't exist, fall back to
    // logical normalization so that `..` components are still resolved.
    // For relative paths, prepend the working directory first so `..`
    // at the start can be resolved against the absolute prefix.
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| {
        let abs = if path.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                cwd.join(path)
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        };
        normalize_path(&abs)
    });

    // Check against blocked absolute paths (both original and resolved)
    let original_str = path.to_string_lossy();
    let resolved_str = resolved.to_string_lossy();
    for blocked in BLOCKED_ABSOLUTE {
        if original_str == *blocked || resolved_str == *blocked {
            return true;
        }
    }

    // Collect components as strings for checking
    let components: Vec<String> = resolved
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    // Check each component against blocked dirs and files
    for component in &components {
        if BLOCKED_DIRS.contains(&component.as_str()) {
            return true;
        }
        if BLOCKED_FILES.contains(&component.as_str()) {
            return true;
        }
    }

    // Check blocked subpaths (consecutive components)
    for subpath in BLOCKED_SUBPATHS {
        if subpath.len() <= components.len() {
            for window in components.windows(subpath.len()) {
                let matches = window
                    .iter()
                    .zip(subpath.iter())
                    .all(|(a, b)| a.as_str() == *b);
                if matches {
                    return true;
                }
            }
        }
    }

    false
}

fn validate_symlink_safety(path: &Path) -> Result<(), String> {
    let mut cur = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                cur.push(Path::new("/"));
            }
            Component::Prefix(prefix) => {
                cur.push(prefix.as_os_str());
            }
            Component::Normal(part) => {
                cur.push(part);
                if !cur.exists() {
                    continue;
                }
                let meta = std::fs::symlink_metadata(&cur).map_err(|e| {
                    format!("failed to inspect path component '{}': {e}", cur.display())
                })?;
                if meta.file_type().is_symlink() {
                    if cur == Path::new("/tmp") || cur == Path::new("/var") {
                        continue;
                    }
                    return Err(format!("symlink component detected at '{}'", cur.display()));
                }
            }
            Component::CurDir | Component::ParentDir => {}
        }
    }
    Ok(())
}

fn validate_allowlist(path: &Path) -> Result<(), String> {
    if cfg!(test) {
        let _ = path;
        return Ok(());
    }
    let Some(allowlist) = path_allowlist_file() else {
        return Ok(());
    };
    if !allowlist.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&allowlist)
        .map_err(|e| format!("failed reading allowlist '{}': {e}", allowlist.display()))?;
    let canonical_target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut allowed_roots = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = Path::new(line);
        let canonical =
            std::fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
        allowed_roots.push(canonical);
    }
    if allowed_roots.is_empty() {
        // Keep compatibility: treat empty allowlist as disabled.
        return Ok(());
    }
    if allowed_roots
        .iter()
        .any(|root| canonical_target.starts_with(root))
    {
        Ok(())
    } else {
        Err(format!(
            "'{}' is outside configured allowlist '{}'",
            canonical_target.display(),
            allowlist.display()
        ))
    }
}

/// Filter a list of paths, removing blocked ones. For glob results.
pub fn filter_paths(paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| !is_blocked(Path::new(p)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governance_fixture() -> (tempfile::TempDir, GovernanceGuard) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("working_dir")).unwrap();
        std::fs::create_dir_all(root.join("runtime/groups/telegram/42")).unwrap();
        std::fs::write(root.join("microclaw.config.yaml"), "x").unwrap();
        let guard = GovernanceGuard::default()
            .protect_data_root(root)
            .exempt(root.join("working_dir"))
            .exempt(root.join("skills"))
            .protect_dir(root.join("souls"))
            .protect_dir(root.join("context"))
            .protect_file(root.join("microclaw.config.yaml"));
        (dir, guard)
    }

    #[test]
    fn governance_guard_blocks_memory_soul_and_user_files() {
        let (dir, guard) = governance_fixture();
        let root = dir.path();
        for rel in [
            "runtime/groups/AGENTS.md",
            "runtime/groups/telegram/AGENTS.md",
            "runtime/groups/telegram/42/AGENTS.md",
            "runtime/groups/telegram/42/USER.md",
            "runtime/groups/42/SOUL.md",
            "SOUL.md",
            "runtime/groups/telegram/42/context/notes.md",
            "souls/house.md",
            "context/project.md",
            "microclaw.config.yaml",
        ] {
            assert!(
                guard.check_write(&root.join(rel)).is_err(),
                "{rel} should be protected"
            );
        }
    }

    #[test]
    fn governance_guard_resolves_dot_dot_and_case() {
        let (dir, guard) = governance_fixture();
        let sneaky = dir
            .path()
            .join("working_dir/../runtime/groups/telegram/42/AGENTS.md");
        assert!(guard.check_write(&sneaky).is_err());
        let lower = dir.path().join("runtime/groups/agents.md");
        assert!(guard.check_write(&lower).is_err());
    }

    #[test]
    fn governance_guard_allows_working_dir_and_skills() {
        let (dir, guard) = governance_fixture();
        let root = dir.path();
        for rel in [
            "working_dir/repo/AGENTS.md",
            "working_dir/notes.txt",
            "skills/foo/SKILL.md",
            "runtime/exports/report.md",
        ] {
            assert!(guard.check_write(&root.join(rel)).is_ok(), "{rel}");
        }
        assert!(GovernanceGuard::default()
            .check_write(&root.join("SOUL.md"))
            .is_ok());
    }

    #[test]
    fn test_blocks_ssh_directory() {
        assert!(is_blocked(Path::new("/home/user/.ssh/id_rsa")));
        assert!(is_blocked(Path::new("/home/user/.ssh/config")));
    }

    #[test]
    fn test_blocks_aws_directory() {
        assert!(is_blocked(Path::new("/home/user/.aws/credentials")));
    }

    #[test]
    fn test_blocks_gnupg_directory() {
        assert!(is_blocked(Path::new("/home/user/.gnupg/private-keys-v1.d")));
    }

    #[test]
    fn test_blocks_kube_directory() {
        assert!(is_blocked(Path::new("/home/user/.kube/config")));
    }

    #[test]
    fn test_blocks_gcloud_config() {
        assert!(is_blocked(Path::new(
            "/home/user/.config/gcloud/credentials.db"
        )));
    }

    #[test]
    fn test_blocks_env_files() {
        assert!(is_blocked(Path::new("/project/.env")));
        assert!(is_blocked(Path::new("/project/.env.local")));
        assert!(is_blocked(Path::new("/project/.env.production")));
        assert!(is_blocked(Path::new("/project/.env.development")));
    }

    #[test]
    fn test_blocks_credential_files() {
        assert!(is_blocked(Path::new("/project/credentials.json")));
        assert!(is_blocked(Path::new("/project/token.json")));
        assert!(is_blocked(Path::new("/project/secrets.yaml")));
        assert!(is_blocked(Path::new("/project/secrets.json")));
    }

    #[test]
    fn test_blocks_ssh_keys() {
        assert!(is_blocked(Path::new("/home/user/id_rsa")));
        assert!(is_blocked(Path::new("/home/user/id_rsa.pub")));
        assert!(is_blocked(Path::new("/home/user/id_ed25519")));
        assert!(is_blocked(Path::new("/home/user/id_ed25519.pub")));
    }

    #[test]
    fn test_blocks_netrc_npmrc() {
        assert!(is_blocked(Path::new("/home/user/.netrc")));
        assert!(is_blocked(Path::new("/home/user/.npmrc")));
    }

    #[test]
    fn test_blocks_etc_shadow() {
        assert!(is_blocked(Path::new("/etc/shadow")));
        assert!(is_blocked(Path::new("/etc/gshadow")));
        assert!(is_blocked(Path::new("/etc/sudoers")));
    }

    #[test]
    fn test_allows_normal_files() {
        assert!(!is_blocked(Path::new("/home/user/project/main.rs")));
        assert!(!is_blocked(Path::new("/tmp/test.txt")));
        assert!(!is_blocked(Path::new("src/config.rs")));
    }

    #[test]
    fn test_check_path_ok() {
        assert!(check_path("src/main.rs").is_ok());
    }

    #[test]
    fn test_check_path_blocked() {
        let result = check_path("/home/user/.ssh/id_rsa");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Access denied"));
    }

    #[test]
    fn test_blocks_traversal_via_parent_dir() {
        // Paths using .. to reach blocked locations should still be caught
        #[cfg(not(target_os = "windows"))]
        {
            assert!(is_blocked(Path::new("/tmp/../etc/shadow")));
            assert!(is_blocked(Path::new(
                "/home/user/project/../../.ssh/id_rsa"
            )));
            assert!(is_blocked(Path::new("/foo/bar/../../../etc/sudoers")));
            assert!(is_blocked(Path::new("/tmp/../home/user/.aws/credentials")));
        }

        #[cfg(target_os = "windows")]
        {
            assert!(is_blocked(Path::new(r"C:\temp\..\Users\user\.ssh\id_rsa")));
            assert!(is_blocked(Path::new(
                r"C:\project\src\..\..\.aws\credentials"
            )));
        }
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            normalize_path(Path::new("/tmp/../etc/shadow")),
            PathBuf::from("/etc/shadow")
        );
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            normalize_path(Path::new("/a/./b/./c")),
            PathBuf::from("/a/b/c")
        );
        assert_eq!(normalize_path(Path::new("a/b/../c")), PathBuf::from("a/c"));
    }

    #[test]
    fn test_filter_paths() {
        let paths = vec![
            "src/main.rs".to_string(),
            "/home/user/.ssh/id_rsa".to_string(),
            "README.md".to_string(),
            "/project/.env".to_string(),
        ];
        let filtered = filter_paths(paths);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0], "src/main.rs");
        assert_eq!(filtered[1], "README.md");
    }

    #[test]
    fn test_symlink_rejected() {
        let dir = std::env::temp_dir().join(format!("mc_pg_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.txt");
        std::fs::write(&target, "ok").unwrap();
        let link = dir.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_file(&target, &link) {
            // Creating symlinks on Windows requires Developer Mode or the
            // SeCreateSymbolicLink privilege. The behavior is covered when
            // the host permits constructing the fixture.
            if error.raw_os_error() == Some(1314) {
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            panic!("failed to create test symlink: {error}");
        }
        let err = check_path(link.to_string_lossy().as_ref()).unwrap_err();
        assert!(err.contains("symlink"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
