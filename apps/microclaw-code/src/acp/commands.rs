//! Slash commands offered to ACP clients (`available_commands_update`).
//!
//! Built-in commands are handled by the agent; custom commands
//! (`~/.mccode/commands`, `.microclaw/commands` in trusted projects) expand
//! to prompts.

use agent_client_protocol_schema::v1::{
    AvailableCommand, AvailableCommandInput, UnstructuredCommandInput,
};
use microclaw_code_core::commands::CustomCommand;

/// A built-in command the agent runs itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    Review,
    Compact,
    Undo,
    Cost,
    Context,
    Help,
}

const BUILTINS: &[(Builtin, &str, &str, Option<&str>)] = &[
    (
        Builtin::Review,
        "review",
        "Review the uncommitted changes (read-only)",
        Some("what to focus on (optional)"),
    ),
    (
        Builtin::Compact,
        "compact",
        "Summarize older messages to free context",
        Some("what the summary must keep (optional)"),
    ),
    (
        Builtin::Undo,
        "undo",
        "Undo the last turn's file changes",
        None,
    ),
    (
        Builtin::Cost,
        "cost",
        "Tokens and estimated cost of this session",
        None,
    ),
    (
        Builtin::Context,
        "context",
        "How full the context window is",
        None,
    ),
    (Builtin::Help, "help", "List the commands", None),
];

/// What a prompt asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Builtin(Builtin, String),
    /// A custom command, expanded.
    Prompt(String),
    Plain,
}

pub fn parse(text: &str, custom: &[CustomCommand]) -> Parsed {
    let Some(rest) = text.trim_start().strip_prefix('/') else {
        return Parsed::Plain;
    };
    let (name, args) = match rest.split_once(char::is_whitespace) {
        Some((name, args)) => (name, args.trim().to_string()),
        None => (rest.trim(), String::new()),
    };
    if let Some((builtin, ..)) = BUILTINS.iter().find(|(_, n, ..)| *n == name) {
        return Parsed::Builtin(*builtin, args);
    }
    match microclaw_code_core::commands::expand(custom, text) {
        Some(prompt) => Parsed::Prompt(prompt),
        None => Parsed::Plain,
    }
}

pub fn available(custom: &[CustomCommand]) -> Vec<AvailableCommand> {
    let mut out: Vec<AvailableCommand> = BUILTINS
        .iter()
        .map(|(_, name, description, hint)| {
            let command = AvailableCommand::new(*name, *description);
            match hint {
                Some(hint) => command.input(AvailableCommandInput::Unstructured(
                    UnstructuredCommandInput::new(*hint),
                )),
                None => command,
            }
        })
        .collect();
    for command in custom {
        if BUILTINS.iter().any(|(_, n, ..)| *n == command.name) {
            continue;
        }
        let description = if command.description.is_empty() {
            format!("{} command", command.scope)
        } else {
            command.description.clone()
        };
        out.push(
            AvailableCommand::new(command.name.clone(), description).input(
                AvailableCommandInput::Unstructured(UnstructuredCommandInput::new("arguments")),
            ),
        );
    }
    out
}

pub fn help(custom: &[CustomCommand]) -> String {
    let mut text = String::from("Commands:\n");
    for (_, name, description, _) in BUILTINS {
        text.push_str(&format!("- `/{name}`: {description}\n"));
    }
    for command in custom {
        text.push_str(&format!("- `/{}`: {}\n", command.name, command.description));
    }
    text.push_str("\nModes (plan / ask / auto) and the model are in the session's settings menu.");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_builtins_custom_commands_and_plain_text() {
        let custom = vec![CustomCommand {
            name: "fix".into(),
            description: "Fix an issue".into(),
            body: "Fix issue $ARGUMENTS".into(),
            scope: "project",
        }];
        assert_eq!(
            parse("/review security", &custom),
            Parsed::Builtin(Builtin::Review, "security".into())
        );
        assert_eq!(
            parse("/undo", &custom),
            Parsed::Builtin(Builtin::Undo, String::new())
        );
        assert_eq!(
            parse("/fix 42", &custom),
            Parsed::Prompt("Fix issue 42".into())
        );
        assert_eq!(parse("/unknown", &custom), Parsed::Plain);
        assert_eq!(parse("fix the bug", &custom), Parsed::Plain);
        let names: Vec<_> = available(&custom).into_iter().map(|c| c.name).collect();
        assert!(names.contains(&"review".to_string()) && names.contains(&"fix".to_string()));
    }
}
