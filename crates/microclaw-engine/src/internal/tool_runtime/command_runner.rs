use std::path::Path;

pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    /// Landlock rules applied to the child before `exec` (local sandbox
    /// fallback on Linux without bubblewrap).
    pub landlock: Option<std::sync::Arc<crate::internal::tool_runtime::landlock::Ruleset>>,
}

pub fn shell_command(command: &str) -> CommandSpec {
    if cfg!(target_os = "windows") {
        CommandSpec {
            program: "powershell".to_string(),
            args: vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                command.to_string(),
            ],
            landlock: None,
        }
    } else {
        CommandSpec {
            program: unix_shell().to_string(),
            args: vec!["-c".to_string(), command.to_string()],
            landlock: None,
        }
    }
}

/// The shell that runs commands on Unix.
///
/// The tool promises bash and models write bash, so bash is used whenever it
/// is installed. The user's `$SHELL` is not used unless it is bash: zsh (the
/// macOS default) aborts on an unmatched glob such as `--include=*.rs` and
/// splits words differently. Without bash, `$SHELL` or `/bin/sh` is used.
fn unix_shell() -> &'static str {
    static SHELL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SHELL.get_or_init(|| {
        let user_shell = std::env::var("SHELL").ok().filter(|s| !s.trim().is_empty());
        pick_unix_shell(
            user_shell.as_deref(),
            std::env::var_os("PATH").as_deref(),
            |p| p.is_file(),
        )
    })
}

fn pick_unix_shell(
    user_shell: Option<&str>,
    path: Option<&std::ffi::OsStr>,
    exists: impl Fn(&Path) -> bool,
) -> String {
    let user_bash = user_shell.filter(|shell| {
        Path::new(shell).file_name().and_then(|n| n.to_str()) == Some("bash")
            && exists(Path::new(shell))
    });
    if let Some(shell) = user_bash {
        return shell.to_string();
    }
    for candidate in ["/bin/bash", "/usr/bin/bash"] {
        if exists(Path::new(candidate)) {
            return candidate.to_string();
        }
    }
    if let Some(path) = path {
        for dir in std::env::split_paths(path) {
            let candidate = dir.join("bash");
            if exists(&candidate) {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    user_shell.unwrap_or("/bin/sh").to_string()
}

pub fn agent_browser_program() -> String {
    if cfg!(target_os = "windows") {
        "agent-browser.cmd".to_string()
    } else {
        "agent-browser".to_string()
    }
}

pub fn build_command(spec: &CommandSpec, working_dir: Option<&Path>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args);
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }
    #[cfg(target_os = "linux")]
    if let Some(rules) = spec.landlock.clone() {
        // SAFETY: restrict_self only issues prctl/landlock system calls,
        // which are async-signal-safe between fork and exec.
        unsafe {
            cmd.pre_exec(move || rules.restrict_self());
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_command_shape() {
        let spec = shell_command("echo hello");
        assert!(!spec.program.is_empty());
        assert!(!spec.args.is_empty());
    }

    #[test]
    fn test_pick_unix_shell_prefers_bash() {
        let only = |paths: &'static [&'static str]| {
            move |p: &Path| paths.iter().any(|x| Path::new(x) == p)
        };
        // zsh as the login shell still runs commands in bash.
        assert_eq!(
            pick_unix_shell(Some("/bin/zsh"), None, only(&["/bin/zsh", "/bin/bash"])),
            "/bin/bash"
        );
        // A bash login shell (e.g. a newer Homebrew bash) is kept.
        assert_eq!(
            pick_unix_shell(
                Some("/opt/homebrew/bin/bash"),
                None,
                only(&["/opt/homebrew/bin/bash", "/bin/bash"])
            ),
            "/opt/homebrew/bin/bash"
        );
        // NixOS-style: no /bin/bash, bash on PATH.
        let path = std::ffi::OsString::from("/run/current-system/sw/bin:/usr/bin");
        assert_eq!(
            pick_unix_shell(
                Some("/bin/zsh"),
                Some(&path),
                only(&["/run/current-system/sw/bin/bash"])
            ),
            "/run/current-system/sw/bin/bash"
        );
        // No bash at all: the login shell, then /bin/sh.
        assert_eq!(
            pick_unix_shell(Some("/bin/zsh"), None, only(&[])),
            "/bin/zsh"
        );
        assert_eq!(pick_unix_shell(None, None, only(&[])), "/bin/sh");
    }

    #[test]
    fn test_agent_browser_program_not_empty() {
        let p = agent_browser_program();
        assert!(!p.trim().is_empty());
    }
}
