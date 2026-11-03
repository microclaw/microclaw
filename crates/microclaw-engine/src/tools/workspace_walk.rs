//! Gitignore-aware directory traversal shared by the `grep` and `glob` tools.
//!
//! Coding sessions point the file tools at real repositories, where walking
//! `target/`, `node_modules/`, build outputs and other ignored trees wastes
//! tokens and time. The walker honours `.gitignore`, `.git/info/exclude` and
//! `.ignore` files (also outside a git checkout), skips hidden entries, and
//! keeps the historical `node_modules` / `target` exclusion as a fallback.

use std::path::{Path, PathBuf};

/// Directories skipped even when no ignore file mentions them.
const ALWAYS_SKIPPED_DIRS: &[&str] = &["node_modules", "target"];

/// Upper bound on visited files so one search cannot stall the agent loop.
pub const MAX_WALKED_FILES: usize = 10_000;

/// Options controlling one walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkOptions {
    /// When true, ignore files are not consulted (hidden entries and the
    /// always-skipped directories are still excluded).
    pub include_ignored: bool,
    /// Yield directories as well as files.
    pub include_dirs: bool,
}

/// Walk `root` and return the visited paths (files, plus directories when
/// requested), excluding the root itself and path-guard blocked entries.
pub fn walk(root: &Path, options: WalkOptions) -> Vec<PathBuf> {
    let respect_ignore = !options.include_ignored;
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(true)
        .parents(respect_ignore)
        .ignore(respect_ignore)
        .git_ignore(respect_ignore)
        .git_exclude(respect_ignore)
        .git_global(false)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_path(|a, b| a.cmp(b))
        .filter_entry(|entry| {
            let is_dir = entry.file_type().is_some_and(|ft| ft.is_dir());
            if entry.depth() > 0 && is_dir {
                let name = entry.file_name().to_string_lossy();
                if ALWAYS_SKIPPED_DIRS.contains(&name.as_ref()) {
                    return false;
                }
            }
            true
        });

    let mut out = Vec::new();
    let mut files = 0usize;
    for entry in builder.build().flatten() {
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.path();
        let is_dir = entry.file_type().is_some_and(|ft| ft.is_dir());
        if is_dir {
            if options.include_dirs {
                out.push(path.to_path_buf());
            }
            continue;
        }
        if crate::internal::tool_runtime::path_guard::is_blocked(path) {
            continue;
        }
        files += 1;
        if files > MAX_WALKED_FILES {
            break;
        }
        out.push(path.to_path_buf());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(root: &Path, paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn honours_gitignore_without_a_git_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".gitignore"), "dist/\n*.log\n").unwrap();
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("dist/bundle.js"), "x").unwrap();
        std::fs::write(root.join("debug.log"), "x").unwrap();
        std::fs::write(root.join("src/main.rs"), "x").unwrap();

        let found = names(root, &walk(root, WalkOptions::default()));
        assert_eq!(found, vec!["src/main.rs"]);

        let all = names(
            root,
            &walk(
                root,
                WalkOptions {
                    include_ignored: true,
                    include_dirs: false,
                },
            ),
        );
        assert!(all.contains(&"dist/bundle.js".to_string()));
        assert!(all.contains(&"debug.log".to_string()));
    }

    #[test]
    fn skips_hidden_and_build_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for sub in [".hidden", "node_modules/pkg", "target/debug", "lib"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(root.join(".hidden/a.txt"), "x").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), "x").unwrap();
        std::fs::write(root.join("target/debug/out"), "x").unwrap();
        std::fs::write(root.join("lib/ok.txt"), "x").unwrap();

        let found = names(
            root,
            &walk(
                root,
                WalkOptions {
                    include_ignored: true,
                    include_dirs: true,
                },
            ),
        );
        assert_eq!(found, vec!["lib", "lib/ok.txt"]);
    }
}
