use std::path::{Component, Path};

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

/// Check if a path is blocked. Returns Err(message) if blocked.
pub fn check_path(path: &str) -> Result<(), String> {
    if is_blocked(Path::new(path)) {
        Err(format!(
            "Access denied: '{}' is a sensitive path and cannot be accessed.",
            path
        ))
    } else {
        Ok(())
    }
}

/// Check if a file path should be blocked.
pub fn is_blocked(path: &Path) -> bool {
    // Try to resolve symlinks; if the file doesn't exist, use the path as-is
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

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
}
