//! System prompt for the MicroClaw Code agent profile.

use crate::project::{Mode, Project};

const CODE_GUIDE: &str = "You are MicroClaw Code, a coding agent working directly in the user's repository on their own machine. \
The working directory for every file and shell tool is the repository root shown below.

How to work:
- Explore before changing anything: use glob and grep (they respect .gitignore) and read_file to understand the relevant code and its conventions. Read a file before editing it.
- Make focused changes that match the surrounding style. Prefer edit_file with small, unique old_string matches; use its `edits` array for several changes to one file and `replace_all` for renames inside a file. Only use write_file for new files or full rewrites.
- If edit_file reports the file changed on disk, read it again: the user may be editing alongside you.
- Run the project's build/test commands with bash to confirm your change. Use run_in_background for dev servers or watchers, read them with bash_output and stop them with bash_kill when done.
- Never delete, skip or weaken tests or checks to make them pass. If something fails for reasons unrelated to your change, say so.
- Do not commit, push, or rewrite git history unless the user asks. Do not touch files outside the repository.
- For larger tasks keep a short plan with todo_write and update it as you go.
- Finish with a brief summary of what changed and how it was verified. Keep chat output concise; the user sees your tool calls and diffs.";

const PLAN_SUFFIX: &str = "You are in PLAN mode: research with read-only tools only and do not modify files or run commands. \
End your reply with a numbered implementation plan (files to change, approach, how to verify). The user will approve it before you execute.";

pub fn system_prompt(project: &Project, mode: Mode, git: Option<&str>) -> String {
    let mut prompt = String::from(CODE_GUIDE);
    prompt.push_str(&format!("\n\n# Repository\n\nroot: {}\n", project.root.display()));
    if !project.kinds.is_empty() {
        prompt.push_str(&format!("project types: {}\n", project.kinds.join(", ")));
    }
    if let Some(git) = git {
        prompt.push_str(git);
        prompt.push('\n');
    }
    if !project.checks.is_empty() {
        prompt.push_str("\n# Project checks\n\n");
        for check in &project.checks {
            let when = if check.auto {
                " (run automatically after you edit files)"
            } else {
                ""
            };
            prompt.push_str(&format!("- {}: `{}`{when}\n", check.name, check.run));
        }
    }
    if let Some(extra) = project
        .config
        .instructions
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        prompt.push_str("\n# Project instructions\n\n");
        prompt.push_str(extra.trim());
        prompt.push('\n');
    }
    if mode == Mode::Plan {
        prompt.push_str("\n# Mode\n\n");
        prompt.push_str(PLAN_SUFFIX);
        prompt.push('\n');
    }
    prompt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_checks_instructions_and_plan_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        std::fs::create_dir_all(dir.path().join(".microclaw")).unwrap();
        std::fs::write(
            dir.path().join(".microclaw/code.yaml"),
            "instructions: Always run fmt.\n",
        )
        .unwrap();
        let project = Project::discover(dir.path()).unwrap();
        let prompt = system_prompt(&project, Mode::Plan, Some("branch: main"));
        assert!(prompt.contains("cargo check --all-targets` (run automatically"));
        assert!(prompt.contains("Always run fmt."));
        assert!(prompt.contains("branch: main"));
        assert!(prompt.contains("PLAN mode"));
        assert!(!system_prompt(&project, Mode::Ask, None).contains("PLAN mode"));
    }
}
