use std::path::Path;

pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
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
        }
    } else {
        let shell = std::env::var("SHELL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".to_string());
        CommandSpec {
            program: shell,
            args: vec!["-c".to_string(), command.to_string()],
        }
    }
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
    fn test_agent_browser_program_not_empty() {
        let p = agent_browser_program();
        assert!(!p.trim().is_empty());
    }
}
