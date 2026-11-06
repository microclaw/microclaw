//! Custom slash commands: Markdown prompt templates.
//!
//! `~/.mccode/commands/<name>.md` (personal) and, in trusted
//! projects, `.microclaw/commands/<name>.md` (shared with the repository)
//! define `/name`. The file body is the prompt; `$ARGUMENTS` is replaced by
//! what follows the command (or the arguments are appended when the body has
//! no placeholder). Optional front matter: `description: …`. Project
//! commands win over personal ones with the same name.

use std::path::Path;

use crate::project::Project;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomCommand {
    pub name: String,
    pub description: String,
    pub body: String,
    /// `project` or `personal`.
    pub scope: &'static str,
}

impl CustomCommand {
    /// The prompt for `/name args`.
    pub fn expand(&self, args: &str) -> String {
        let args = args.trim();
        if self.body.contains("$ARGUMENTS") {
            self.body.replace("$ARGUMENTS", args)
        } else if args.is_empty() {
            self.body.clone()
        } else {
            format!("{}\n\n{args}", self.body)
        }
    }
}

fn load_dir(dir: &Path, scope: &'static str) -> Vec<CustomCommand> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .filter_map(|path| {
            let name = path.file_stem()?.to_str()?.to_string();
            if name.is_empty() || name.contains(char::is_whitespace) {
                return None;
            }
            let text = std::fs::read_to_string(&path).ok()?;
            let (description, body) = split_front_matter(&text);
            let body = body.trim().to_string();
            if body.is_empty() {
                return None;
            }
            let description = description.unwrap_or_else(|| {
                body.lines()
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(60)
                    .collect()
            });
            Some(CustomCommand {
                name,
                description,
                body,
                scope,
            })
        })
        .collect()
}

fn split_front_matter(text: &str) -> (Option<String>, &str) {
    if let Some(rest) = text.strip_prefix("---")
        && let Some(end) = rest.find("\n---")
    {
        let description = rest[..end].lines().find_map(|line| {
            line.strip_prefix("description:")
                .map(|v| v.trim().trim_matches('"').to_string())
        });
        return (
            description,
            rest[end + 4..].trim_start_matches(['\r', '\n']),
        );
    }
    (None, text)
}

/// Commands available in `project`: personal ones from `personal_dir`, then
/// project ones (trusted projects only), sorted by name.
pub fn load(project: &Project, personal_dir: &Path) -> Vec<CustomCommand> {
    let mut commands = load_dir(personal_dir, "personal");
    if project.trusted {
        for command in load_dir(&project.root.join(".microclaw").join("commands"), "project") {
            commands.retain(|c| c.name != command.name);
            commands.push(command);
        }
    }
    commands.sort_by(|a, b| a.name.cmp(&b.name));
    commands
}

/// Personal commands directory under the Code home.
pub fn personal_dir() -> std::path::PathBuf {
    crate::home::code_home().join("commands")
}

/// Expand `input` when it starts with a custom `/command`.
pub fn expand(commands: &[CustomCommand], input: &str) -> Option<String> {
    let rest = input.trim_start().strip_prefix('/')?;
    let (name, args) = match rest.split_once(char::is_whitespace) {
        Some((name, args)) => (name, args),
        None => (rest, ""),
    };
    commands
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.expand(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn expands_arguments_and_appends_when_no_placeholder() {
        let c = CustomCommand {
            name: "fix".into(),
            description: String::new(),
            body: "Fix issue $ARGUMENTS and add a test.".into(),
            scope: "project",
        };
        assert_eq!(c.expand(" 42 "), "Fix issue 42 and add a test.");
        let plain = CustomCommand {
            body: "Review the diff.".into(),
            ..c
        };
        assert_eq!(plain.expand(""), "Review the diff.");
        assert_eq!(
            plain.expand("focus on errors"),
            "Review the diff.\n\nfocus on errors"
        );
    }

    #[test]
    fn project_commands_need_trust_and_win_over_personal_ones() {
        let repo = tempfile::tempdir().unwrap();
        let personal = tempfile::tempdir().unwrap();
        write(personal.path(), "deploy.md", "personal deploy");
        write(
            personal.path(),
            "notes.md",
            "---\ndescription: Take notes\n---\nWrite notes",
        );
        let commands_dir = repo.path().join(".microclaw").join("commands");
        write(&commands_dir, "deploy.md", "project deploy $ARGUMENTS");
        write(&commands_dir, "empty.md", "---\ndescription: x\n---\n");

        let trusted = Project::discover(repo.path(), |_, _| true).unwrap();
        let commands = load(&trusted, personal.path());
        let names: Vec<_> = commands
            .iter()
            .map(|c| (c.name.as_str(), c.scope))
            .collect();
        assert_eq!(names, vec![("deploy", "project"), ("notes", "personal")]);
        assert_eq!(commands[1].description, "Take notes");
        assert_eq!(
            expand(&commands, "/deploy prod").as_deref(),
            Some("project deploy prod")
        );
        assert_eq!(expand(&commands, "/unknown x"), None);
        assert_eq!(expand(&commands, "plain text"), None);

        let untrusted = Project::discover(repo.path(), |_, _| false).unwrap();
        let commands = load(&untrusted, personal.path());
        assert_eq!(
            commands.iter().find(|c| c.name == "deploy").unwrap().scope,
            "personal"
        );
    }
}
