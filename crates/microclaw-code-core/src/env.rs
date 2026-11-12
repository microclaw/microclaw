//! The process environment of a MicroClaw Code front end, set up before any
//! thread starts.
//!
//! - [`isolate_engine_env`]: the Agent Engine reads a few `MICROCLAW_*`
//!   variables meant for the MicroClaw Server. Code is a separate product, so
//!   they are replaced with Code's own `MCCODE_*` values (or cleared).
//! - [`import_login_shell_env`]: an app started from Finder gets a bare
//!   `PATH` without `cargo`, `npm` or `brew`; the user's login shell is asked
//!   once for its environment so checks, LSP and shell commands find them.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

/// Engine variables and the value each gets in a Code process (`None`:
/// removed).
pub fn engine_env_overrides(
    get: impl Fn(&str) -> Option<OsString>,
    code_home: &Path,
) -> Vec<(&'static str, Option<OsString>)> {
    let get = |var: &str| get(var).filter(|v| !v.is_empty());
    vec![
        ("MICROCLAW_CONFIG", None),
        ("MICROCLAW_SKILLS_DIR", None),
        ("MICROCLAW_OPENAI_API_KEY", None),
        ("MICROCLAW_SANDBOX_MOUNT_ALLOWLIST", None),
        (
            "MICROCLAW_PATH_ALLOWLIST",
            Some(
                get("MCCODE_PATH_ALLOWLIST")
                    .unwrap_or_else(|| code_home.join("sandbox-path-allowlist.txt").into()),
            ),
        ),
        ("MICROCLAW_LOCAL_SANDBOX", get("MCCODE_LOCAL_SANDBOX")),
    ]
}

/// Apply [`engine_env_overrides`] to this process.
///
/// # Safety
/// Must run before any other thread is started.
pub unsafe fn isolate_engine_env(code_home: &Path) {
    for (var, value) in engine_env_overrides(|v| std::env::var_os(v), code_home) {
        // SAFETY: the caller guarantees the process is single-threaded.
        unsafe {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
    }
}

/// Printed before `env -0` so shell start-up chatter is skipped.
const MARKER: &str = "__MCCODE_LOGIN_ENV__";

/// Variables never copied from the login shell.
const SKIP: &[&str] = &[
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "PS1",
    "PS2",
    "TERM_SESSION_ID",
];

/// Parse `MARKER\0` followed by `env -0` output.
pub fn parse_env_output(bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(bytes);
    let Some(start) = text.find(&format!("{MARKER}\0")) else {
        return Vec::new();
    };
    text[start + MARKER.len() + 1..]
        .split('\0')
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            let key = key.trim_start_matches('\n');
            (!key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                .then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

/// `current` with the entries of `login` it lacks appended.
pub fn merge_path(current: &str, login: &str) -> String {
    let mut parts: Vec<&str> = current.split(':').filter(|p| !p.is_empty()).collect();
    for part in login.split(':').filter(|p| !p.is_empty()) {
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    parts.join(":")
}

/// The login shell's environment (`$SHELL -ilc`), or why it could not be read.
pub fn login_shell_env(timeout: Duration) -> Result<Vec<(String, String)>, String> {
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/zsh".into());
    // Output goes to a file: reading a pipe would need a second thread, and
    // this runs before the process may start one.
    let path = std::env::temp_dir().join(format!("mccode-login-env-{}", std::process::id()));
    let file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(&shell)
        .args(["-ilc", &format!("printf '%s\\0' {MARKER}; env -0")])
        .stdin(std::process::Stdio::null())
        .stdout(file)
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("{shell}: {e}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("{shell} did not finish in {}s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => break Err(e.to_string()),
        }
    };
    let bytes = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    status?;
    let vars = parse_env_output(&bytes);
    if vars.is_empty() {
        return Err(format!("{shell} printed no environment"));
    }
    Ok(vars)
}

/// What [`import_login_shell_env`] did, for a doctor view.
#[derive(Debug, Clone, Default)]
pub struct LoginEnvReport {
    pub imported: usize,
    pub path: String,
    pub error: Option<String>,
}

/// Merge the login shell's environment into this process: `PATH` gains the
/// login shell's entries, other variables are added only when unset.
///
/// # Safety
/// Must run before any other thread is started.
pub unsafe fn import_login_shell_env(timeout: Duration) -> LoginEnvReport {
    let mut report = LoginEnvReport::default();
    match login_shell_env(timeout) {
        Ok(vars) => {
            for (key, value) in vars {
                if SKIP.contains(&key.as_str()) {
                    continue;
                }
                if key == "PATH" {
                    let current = std::env::var("PATH").unwrap_or_default();
                    // SAFETY: the caller guarantees the process is single-threaded.
                    unsafe { std::env::set_var("PATH", merge_path(&current, &value)) };
                    report.imported += 1;
                } else if std::env::var_os(&key).is_none() {
                    // SAFETY: as above.
                    unsafe { std::env::set_var(&key, value) };
                    report.imported += 1;
                }
            }
        }
        Err(e) => report.error = Some(e),
    }
    report.path = std::env::var("PATH").unwrap_or_default();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_variables_are_replaced_or_cleared() {
        let home = Path::new("/home/u/.mccode");
        let env = |var: &str| match var {
            "MCCODE_LOCAL_SANDBOX" => Some(OsString::from("off")),
            _ => None,
        };
        let overrides = engine_env_overrides(env, home);
        let get = |name: &str| {
            overrides
                .iter()
                .find(|(v, _)| *v == name)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(get("MICROCLAW_CONFIG"), None);
        assert_eq!(get("MICROCLAW_LOCAL_SANDBOX"), Some(OsString::from("off")));
        assert_eq!(
            get("MICROCLAW_PATH_ALLOWLIST"),
            Some(OsString::from("/home/u/.mccode/sandbox-path-allowlist.txt"))
        );
    }

    #[test]
    fn env_output_after_the_marker_is_parsed() {
        let mut out = b"Last login: today\nwelcome\n".to_vec();
        out.extend_from_slice(format!("{MARKER}\0").as_bytes());
        out.extend_from_slice(b"PATH=/opt/homebrew/bin:/usr/bin\0MULTI=a\nb\0=bad\0EMPTY=\0");
        let vars = parse_env_output(&out);
        assert_eq!(
            vars,
            vec![
                ("PATH".into(), "/opt/homebrew/bin:/usr/bin".into()),
                ("MULTI".into(), "a\nb".into()),
                ("EMPTY".into(), String::new()),
            ]
        );
        assert!(parse_env_output(b"no marker here").is_empty());
    }

    #[test]
    fn path_keeps_current_order_and_adds_login_entries() {
        assert_eq!(
            merge_path(
                "/usr/bin:/bin",
                "/opt/homebrew/bin:/usr/bin:/Users/u/.cargo/bin"
            ),
            "/usr/bin:/bin:/opt/homebrew/bin:/Users/u/.cargo/bin"
        );
        assert_eq!(merge_path("", "/a"), "/a");
    }
}
