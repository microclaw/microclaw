//! Local OS sandbox for shell commands (`sandbox.backend: local`).
//!
//! Commands run on the host, confined by the operating system instead of a
//! container:
//!
//! - **Linux**: [bubblewrap](https://github.com/containers/bubblewrap)
//!   (`bwrap`). The whole filesystem is mounted read-only, the workspace,
//!   the temp directory and the writable roots are bound read-write,
//!   credential directories are replaced by empty tmpfs mounts, and the
//!   network namespace is unshared when network access is off.
//! - **macOS**: Seatbelt (`sandbox-exec`) with a generated profile: reads
//!   are allowed except for credential directories; writes only under the
//!   workspace, the temp directories and the writable roots; network access
//!   is denied when off.
//!
//! The process keeps the caller's user, environment and toolchains, so
//! builds and tests behave as they do outside the sandbox. What it cannot do
//! is change files outside the allowed roots, read SSH/cloud credentials, or
//! (when network is off) reach the network.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::internal::tool_runtime::command_runner::CommandSpec;

/// The OS mechanism a [`LocalPolicy`] is enforced with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSandboxKind {
    Bubblewrap,
    Seatbelt,
    /// Linux fallback without bubblewrap: write confinement (and TCP
    /// blocking on newer kernels) through Landlock; cannot hide directories.
    Landlock,
}

impl LocalSandboxKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bubblewrap",
            Self::Seatbelt => "seatbelt",
            Self::Landlock => "landlock",
        }
    }

    /// Whether this mechanism hides the credential directories.
    pub fn hides_credentials(self) -> bool {
        !matches!(self, Self::Landlock)
    }
}

const SEATBELT: &str = "/usr/bin/sandbox-exec";

/// Home-relative directories a sandboxed command can never read.
const HIDDEN_HOME_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".netrc",
    ".git-credentials",
    ".microclaw",
    ".mccode",
];

/// Home-relative tool caches commands may write (package downloads, build
/// caches), so builds and tests keep working.
const DEFAULT_WRITABLE_HOME_DIRS: &[&str] = &[
    ".cache",
    ".cargo",
    ".rustup",
    ".npm",
    ".pnpm-store",
    ".yarn",
    ".bun",
    ".gradle",
    ".m2",
    "go",
    "Library/Caches",
];

/// Which mechanism is available on this machine, probed once. On Linux the
/// probe runs `bwrap` for real, because user namespaces can be disabled
/// (some containers, hardened kernels); without it, Landlock is used when the
/// kernel supports it. `MICROCLAW_LOCAL_SANDBOX=bubblewrap|landlock|none`
/// overrides the choice.
pub fn detect() -> Option<LocalSandboxKind> {
    static DETECTED: OnceLock<Option<LocalSandboxKind>> = OnceLock::new();
    *DETECTED.get_or_init(|| {
        let forced = std::env::var("MICROCLAW_LOCAL_SANDBOX").ok();
        match forced.as_deref().map(str::trim) {
            Some("none") | Some("off") => return None,
            Some("landlock") => {
                return crate::internal::tool_runtime::landlock::abi()
                    .map(|_| LocalSandboxKind::Landlock)
            }
            _ => {}
        }
        if cfg!(target_os = "macos") {
            Path::new(SEATBELT)
                .exists()
                .then_some(LocalSandboxKind::Seatbelt)
        } else if cfg!(target_os = "linux") {
            let works = std::process::Command::new("bwrap")
                .args([
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--unshare-net",
                    "--die-with-parent",
                    "--",
                    "true",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if works {
                Some(LocalSandboxKind::Bubblewrap)
            } else {
                crate::internal::tool_runtime::landlock::abi().map(|_| LocalSandboxKind::Landlock)
            }
        } else {
            None
        }
    })
}

/// What a sandboxed command may touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPolicy {
    /// Writable (the repository / chat working directory).
    pub workspace: PathBuf,
    /// Additional writable directories (existing ones only are applied).
    pub writable_roots: Vec<PathBuf>,
    /// Allow network access.
    pub network: bool,
    /// Directories that are hidden (unreadable).
    pub hidden: Vec<PathBuf>,
}

fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

impl LocalPolicy {
    /// The default policy for a workspace: write the workspace, the temp
    /// directory and the usual tool caches; hide credential directories.
    pub fn for_workspace(workspace: &Path, extra_writable: &[PathBuf], network: bool) -> Self {
        let home = home_dir();
        let mut writable_roots = vec![std::env::temp_dir()];
        if cfg!(target_os = "macos") {
            writable_roots.push(PathBuf::from("/private/tmp"));
            writable_roots.push(PathBuf::from("/private/var/folders"));
        } else {
            writable_roots.push(PathBuf::from("/tmp"));
        }
        if let Some(home) = &home {
            writable_roots.extend(DEFAULT_WRITABLE_HOME_DIRS.iter().map(|d| home.join(d)));
        }
        writable_roots.extend(extra_writable.iter().cloned());
        let hidden = home
            .map(|home| HIDDEN_HOME_DIRS.iter().map(|d| home.join(d)).collect())
            .unwrap_or_default();
        Self {
            workspace: workspace.to_path_buf(),
            writable_roots,
            network,
            hidden,
        }
    }

    /// Canonical workspace and existing writable roots, deduplicated; hidden
    /// paths that exist and do not contain the workspace.
    fn resolved(&self) -> (PathBuf, Vec<PathBuf>, Vec<PathBuf>) {
        let workspace = canonical(&self.workspace).unwrap_or_else(|| self.workspace.clone());
        let mut writable: Vec<PathBuf> = Vec::new();
        for root in &self.writable_roots {
            let Some(root) = canonical(root) else {
                continue;
            };
            if root == Path::new("/")
                || writable.iter().any(|w| root.starts_with(w))
                || root.starts_with(&workspace)
            {
                continue;
            }
            writable.retain(|w| !w.starts_with(&root));
            writable.push(root);
        }
        let hidden = self
            .hidden
            .iter()
            .filter_map(|p| canonical(p))
            .filter(|p| !workspace.starts_with(p))
            .collect();
        (workspace, writable, hidden)
    }
}

/// Wrap `spec` so it runs under `kind` with `policy`, starting in `cwd`.
pub fn wrap(
    kind: LocalSandboxKind,
    policy: &LocalPolicy,
    spec: &CommandSpec,
    cwd: &Path,
) -> CommandSpec {
    match kind {
        LocalSandboxKind::Bubblewrap => bubblewrap(policy, spec, cwd),
        LocalSandboxKind::Seatbelt => seatbelt(policy, spec),
        LocalSandboxKind::Landlock => landlock(policy, spec),
    }
}

fn landlock(policy: &LocalPolicy, spec: &CommandSpec) -> CommandSpec {
    let (workspace, writable, _) = policy.resolved();
    let mut roots = writable;
    roots.push(workspace);
    match crate::internal::tool_runtime::landlock::Ruleset::new(&roots, policy.network) {
        Ok(rules) => CommandSpec {
            program: spec.program.clone(),
            args: spec.args.clone(),
            landlock: Some(std::sync::Arc::new(rules)),
        },
        // Never run unconfined when the sandbox was requested.
        Err(e) => CommandSpec {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "echo 'microclaw: could not set up the Landlock sandbox: {e}' >&2; exit 126"
                ),
            ],
            landlock: None,
        },
    }
}

fn bubblewrap(policy: &LocalPolicy, spec: &CommandSpec, cwd: &Path) -> CommandSpec {
    let (workspace, writable, hidden) = policy.resolved();
    let path = |p: &Path| p.to_string_lossy().into_owned();
    let mut args: Vec<String> = vec![
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
    ];
    for root in writable.iter().chain(std::iter::once(&workspace)) {
        args.extend(["--bind".into(), path(root), path(root)]);
    }
    for dir in &hidden {
        if dir.is_dir() {
            args.extend(["--tmpfs".into(), path(dir)]);
        } else {
            args.extend(["--ro-bind".into(), "/dev/null".into(), path(dir)]);
        }
    }
    if !policy.network {
        args.push("--unshare-net".into());
    }
    args.extend([
        "--die-with-parent".into(),
        "--new-session".into(),
        "--chdir".into(),
        path(cwd),
        "--".into(),
        spec.program.clone(),
    ]);
    args.extend(spec.args.iter().cloned());
    CommandSpec {
        program: "bwrap".into(),
        args,
        landlock: None,
    }
}

/// Quote a path for a Seatbelt profile string literal.
fn sbpl_string(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for c in raw.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The Seatbelt profile for `policy` (later rules win in SBPL).
pub fn seatbelt_profile(policy: &LocalPolicy) -> String {
    let (workspace, writable, hidden) = policy.resolved();
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec)\n\
         (allow process-fork)\n\
         (allow process-info*)\n\
         (allow signal (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow mach-lookup)\n\
         (allow ipc-posix-shm*)\n\
         (allow ipc-posix-sem)\n\
         (allow iokit-open)\n\
         (allow pseudo-tty)\n\
         (allow file-ioctl)\n\
         (allow file-read*)\n\
         (allow file-write-data (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\") (regex #\"^/dev/tty\") (regex #\"^/dev/fd/\"))\n",
    );
    profile.push_str("(allow file-write*");
    for root in writable.iter().chain(std::iter::once(&workspace)) {
        profile.push_str(&format!(" (subpath {})", sbpl_string(root)));
    }
    profile.push_str(")\n");
    if !hidden.is_empty() {
        profile.push_str("(deny file-read* file-write*");
        for dir in &hidden {
            profile.push_str(&format!(" (subpath {})", sbpl_string(dir)));
        }
        profile.push_str(")\n");
    }
    if policy.network {
        profile.push_str("(allow network*)\n(allow system-socket)\n");
    } else {
        profile.push_str("(allow network* (local unix))\n");
    }
    profile
}

fn seatbelt(policy: &LocalPolicy, spec: &CommandSpec) -> CommandSpec {
    let mut args = vec![
        "-p".to_string(),
        seatbelt_profile(policy),
        spec.program.clone(),
    ];
    args.extend(spec.args.iter().cloned());
    CommandSpec {
        program: SEATBELT.into(),
        args,
        landlock: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::tool_runtime::command_runner::{build_command, shell_command};

    fn policy(workspace: &Path, network: bool) -> LocalPolicy {
        LocalPolicy {
            workspace: workspace.to_path_buf(),
            writable_roots: vec![std::env::temp_dir()],
            network,
            hidden: Vec::new(),
        }
    }

    #[test]
    fn bubblewrap_arguments_bind_the_workspace_and_drop_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        let secret = dir.path().join("secret");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        let mut p = policy(&ws, false);
        p.hidden = vec![secret.clone(), dir.path().join("missing")];
        let spec = bubblewrap(&p, &shell_command("ls"), &ws);
        let args = spec.args.join(" ");
        let ws = std::fs::canonicalize(&ws).unwrap();
        let secret = std::fs::canonicalize(&secret).unwrap();
        assert_eq!(spec.program, "bwrap");
        assert!(args.starts_with("--ro-bind / /"), "{args}");
        assert!(args.contains(&format!("--bind {} {}", ws.display(), ws.display())));
        assert!(args.contains(&format!("--tmpfs {}", secret.display())));
        assert!(!args.contains("missing"));
        assert!(args.contains("--unshare-net"));
        assert!(!bubblewrap(&policy(&ws, true), &shell_command("ls"), &ws)
            .args
            .contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn seatbelt_profile_limits_writes_and_hides_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws \"q\"");
        std::fs::create_dir_all(&ws).unwrap();
        let secret = dir.path().join(".ssh");
        std::fs::create_dir_all(&secret).unwrap();
        let mut p = policy(&ws, false);
        p.hidden = vec![secret];
        let profile = seatbelt_profile(&p);
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-write* "));
        assert!(profile.contains("ws \\\"q\\\""), "{profile}");
        assert!(profile.contains("(deny file-read* file-write* (subpath"));
        assert!(profile.contains("(allow network* (local unix))"));
        assert!(seatbelt_profile(&policy(&ws, true)).contains("(allow network*)\n"));
    }

    #[test]
    fn hidden_paths_that_contain_the_workspace_are_kept_visible() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("a/ws");
        std::fs::create_dir_all(&ws).unwrap();
        let mut p = policy(&ws, true);
        p.hidden = vec![dir.path().join("a")];
        let (_, _, hidden) = p.resolved();
        assert!(hidden.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn landlock_wrapping_confines_writes() {
        if crate::internal::tool_runtime::landlock::abi().is_none() {
            eprintln!("Landlock unavailable; skipping");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let ws = base.path().join("ws");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let p = LocalPolicy {
            workspace: ws.clone(),
            writable_roots: Vec::new(),
            network: true,
            hidden: Vec::new(),
        };
        let script = format!(
            "echo in > inside.txt; echo out > '{}/x.txt'; echo done",
            outside.display()
        );
        let spec = wrap(LocalSandboxKind::Landlock, &p, &shell_command(&script), &ws);
        let output = build_command(&spec, Some(&ws)).output().await.unwrap();
        assert!(ws.join("inside.txt").exists());
        assert!(!outside.join("x.txt").exists());
        assert!(String::from_utf8_lossy(&output.stdout).contains("done"));
    }

    /// Runs only where the OS sandbox actually works (bwrap with user
    /// namespaces, or macOS).
    #[tokio::test]
    async fn sandboxed_commands_can_write_the_workspace_only() {
        let Some(kind) = detect() else {
            eprintln!("no local sandbox on this machine; skipping");
            return;
        };
        let base = tempfile::tempdir().unwrap();
        let ws = base.path().join("ws");
        let outside = base.path().join("outside");
        let secret = base.path().join("secret");
        for d in [&ws, &outside, &secret] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(secret.join("key"), "hunter2").unwrap();
        let p = LocalPolicy {
            workspace: ws.clone(),
            writable_roots: Vec::new(),
            network: false,
            hidden: vec![secret.clone()],
        };
        let run = |script: &str| {
            let spec = wrap(kind, &p, &shell_command(script), &ws);
            let mut cmd = build_command(&spec, Some(&ws));
            async move { cmd.output().await.unwrap() }
        };
        let ok = run("echo inside > inside.txt && cat inside.txt").await;
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "inside");
        assert!(ws.join("inside.txt").exists());

        let denied = run(&format!("echo x > '{}/escape.txt'", outside.display())).await;
        assert!(!denied.status.success());
        assert!(!outside.join("escape.txt").exists());

        let hidden = run(&format!("cat '{}/key'", secret.display())).await;
        assert!(!String::from_utf8_lossy(&hidden.stdout).contains("hunter2"));
    }
}
