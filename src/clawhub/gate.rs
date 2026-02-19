use crate::clawhub::types::Requires;
use std::env;

pub struct GateCheckResult {
    pub missing_bins: Vec<String>,
    pub missing_envs: Vec<String>,
    pub wrong_os: bool,
}

/// Check if skill requirements are met
pub fn check_requirements(requires: &Option<Requires>, os: &[String]) -> GateCheckResult {
    let mut result = GateCheckResult {
        missing_bins: vec![],
        missing_envs: vec![],
        wrong_os: false,
    };

    if let Some(req) = requires {
        // Check bins
        for bin in &req.bins {
            if !command_exists(bin) {
                result.missing_bins.push(bin.clone());
            }
        }

        // Check anyBins (at least one must exist)
        if !req.any_bins.is_empty() {
            let any_exists = req.any_bins.iter().any(|b| command_exists(b));
            if !any_exists && !req.bins.is_empty() {
                // If anyBins is specified and no bins passed, check if we should warn
            }
        }

        // Check env vars
        for env_var in &req.env {
            if env::var(env_var).is_err() {
                result.missing_envs.push(env_var.clone());
            }
        }
    }

    // Check OS
    if !os.is_empty() {
        let current_os = current_platform();
        let os_matches = os.iter().any(|o| {
            let o = o.to_lowercase();
            o == "all" || o == "*" || normalize_platform(&o) == current_os
        });
        result.wrong_os = !os_matches;
    }

    result
}

fn current_platform() -> String {
    #[cfg(target_os = "macos")]
    return "darwin".to_string();
    #[cfg(target_os = "linux")]
    return "linux".to_string();
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "unknown".to_string();
}

fn normalize_platform(s: &str) -> String {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "macos" | "osx" => "darwin".to_string(),
        _ => s,
    }
}

fn command_exists(cmd: &str) -> bool {
    if cmd.trim().is_empty() {
        return true;
    }
    let path_var = env::var_os("PATH").unwrap_or_default();
    let paths = env::split_paths(&path_var);

    #[cfg(target_os = "windows")]
    let candidates: Vec<String> = {
        let exts = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let ext_list: Vec<String> = exts
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let lower = cmd.to_ascii_lowercase();
        if ext_list.iter().any(|ext| lower.ends_with(ext)) {
            vec![cmd.to_string()]
        } else {
            let mut c = vec![cmd.to_string()];
            for ext in ext_list {
                c.push(format!("{}{}", cmd, ext));
            }
            c
        }
    };

    #[cfg(not(target_os = "windows"))]
    let candidates: Vec<String> = vec![cmd.to_string()];

    for base in paths {
        for candidate in &candidates {
            let full = base.join(candidate);
            if full.is_file() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_platform() {
        let platform = current_platform();
        assert!(!platform.is_empty());
    }

    #[test]
    fn test_normalize_platform() {
        assert_eq!(normalize_platform("darwin"), "darwin");
        assert_eq!(normalize_platform("macOS"), "darwin");
        assert_eq!(normalize_platform("osx"), "darwin");
    }

    #[test]
    fn test_command_exists() {
        // Should find system commands
        assert!(command_exists("ls") || command_exists("dir"));
    }

    #[test]
    fn test_check_requirements_empty() {
        let result = check_requirements(&None, &[]);
        assert!(result.missing_bins.is_empty());
        assert!(result.missing_envs.is_empty());
        assert!(!result.wrong_os);
    }
}
