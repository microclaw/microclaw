//! `explore`: a synchronous, read-only sub-agent for wide searches.
//!
//! The calling agent hands over a question ("where is the retry policy
//! configured and who calls it?"); a fresh loop with only read/search tools
//! answers it and returns a short report. The main conversation receives the
//! conclusion instead of every file it took to get there, which keeps its
//! context small. The tool is read-only, so several `explore` calls in one
//! reply run in parallel.
//!
//! Project agents: a trusted workspace can define focused helpers in
//! `.microclaw/agents/<name>.md` (front matter `description`, optional
//! `model`; the body is the system prompt), selected with `agent`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolRegistry, ToolResult};
use crate::config::Config;
use crate::internal::storage::db::Database;
use crate::internal::tool_runtime::runtime::{
    auth_context_from_input, tool_concurrency_class, ToolAuthContext, ToolConcurrencyClass,
};
use microclaw_core::llm_types::{
    ContentBlock, Message, MessageContent, ResponseContentBlock, ToolDefinition,
};

const MAX_ITERATIONS: usize = 30;
const MAX_REPORT_CHARS: usize = 16_000;
/// Tool output kept per call inside the explore loop.
const MAX_TOOL_OUTPUT_CHARS: usize = 24_000;

const DEFAULT_PROMPT: &str = "You are an exploration helper working for another agent. Answer its question by reading and searching the workspace (read_file, grep, glob, and web tools when the question needs them). You cannot change anything. Be efficient: search before reading, read only what you need. Finish with a concise report: the answer, the exact file paths and line numbers that support it, and anything uncertain. No preamble.";

/// A project-defined helper agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectAgent {
    pub name: String,
    pub description: String,
    pub model: Option<String>,
    pub prompt: String,
}

/// Agents defined in `dir` (`<name>.md` with optional front matter).
pub fn load_project_agents(dir: &Path) -> Vec<ProjectAgent> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut agents: Vec<ProjectAgent> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .filter_map(|path| {
            let name = path.file_stem()?.to_str()?.to_string();
            let text = std::fs::read_to_string(&path).ok()?;
            Some(parse_agent(&name, &text))
        })
        .filter(|agent| !agent.prompt.trim().is_empty())
        .collect();
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    agents
}

fn parse_agent(name: &str, text: &str) -> ProjectAgent {
    let mut description = String::new();
    let mut model = None;
    let mut body = text;
    if let Some(rest) = text.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            for line in rest[..end].lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let value = value.trim().trim_matches('"').to_string();
                    match key.trim() {
                        "description" => description = value,
                        "model" if !value.is_empty() => model = Some(value),
                        _ => {}
                    }
                }
            }
            body = rest[end + 4..].trim_start_matches(['\r', '\n']);
        }
    }
    ProjectAgent {
        name: name.to_string(),
        description,
        model,
        prompt: body.trim().to_string(),
    }
}

pub struct ExploreTool {
    config: Config,
    db: Arc<Database>,
    agents: Vec<ProjectAgent>,
}

impl ExploreTool {
    pub fn new(config: &Config, db: Arc<Database>) -> Self {
        let agents = config
            .project_agents_dir
            .as_deref()
            .map(|dir| load_project_agents(&PathBuf::from(dir)))
            .unwrap_or_default();
        Self {
            config: config.clone(),
            db,
            agents,
        }
    }
}

fn truncate(text: &str, max: usize) -> String {
    crate::context_window::truncate_chars(text, max)
}

#[async_trait]
impl Tool for ExploreTool {
    fn name(&self) -> &str {
        "explore"
    }

    fn definition(&self) -> ToolDefinition {
        let mut description = String::from(
            "Delegate a read-only investigation to a helper with its own context: finding where something is defined or used, understanding a subsystem, surveying many files. Returns a short report with file paths and line numbers, so your own context only gets the conclusion. Several explore calls in one reply run in parallel. The helper cannot edit files or run commands. Give it a precise question.",
        );
        if !self.agents.is_empty() {
            description.push_str(" Project agents (pass as `agent`): ");
            let list: Vec<String> = self
                .agents
                .iter()
                .map(|a| {
                    if a.description.is_empty() {
                        a.name.clone()
                    } else {
                        format!("{} ({})", a.name, a.description)
                    }
                })
                .collect();
            description.push_str(&list.join("; "));
            description.push('.');
        }
        let mut properties = json!({
            "task": {
                "type": "string",
                "description": "The question to answer, with any paths or names you already know"
            }
        });
        if !self.agents.is_empty() {
            properties["agent"] = json!({
                "type": "string",
                "enum": self.agents.iter().map(|a| a.name.clone()).collect::<Vec<_>>(),
                "description": "Project agent to use instead of the default explorer"
            });
        }
        ToolDefinition {
            name: "explore".into(),
            description,
            input_schema: schema_object(properties, &["task"]),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let Some(task) = input
            .get("task")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return ToolResult::error("explore: `task` is required".into());
        };
        let agent = match input.get("agent").and_then(|v| v.as_str()) {
            Some(name) => match self.agents.iter().find(|a| a.name == name) {
                Some(agent) => Some(agent.clone()),
                None => return ToolResult::error(format!("explore: unknown agent `{name}`")),
            },
            None => None,
        };
        let parent = auth_context_from_input(&input);
        let auth = ToolAuthContext {
            caller_channel: parent
                .as_ref()
                .map(|a| a.caller_channel.clone())
                .unwrap_or_else(|| "code".into()),
            caller_chat_id: parent.as_ref().map(|a| a.caller_chat_id).unwrap_or(0),
            principal: "subagent:explore".into(),
            control_chat_ids: Vec::new(),
            env_files: Vec::new(),
        };
        match run_explore(&self.config, self.db.clone(), &auth, task, agent.as_ref()).await {
            Ok(report) => ToolResult::success(report),
            Err(e) => ToolResult::error(format!("explore failed: {e}")),
        }
    }
}

/// Read-only tools the explorer may use.
fn explorer_tool(name: &str) -> bool {
    tool_concurrency_class(name) == ToolConcurrencyClass::ReadOnly
        && matches!(
            name,
            "read_file" | "grep" | "glob" | "web_fetch" | "web_search" | "fetch_artifact"
        )
}

async fn run_explore(
    config: &Config,
    db: Arc<Database>,
    auth: &ToolAuthContext,
    task: &str,
    agent: Option<&ProjectAgent>,
) -> anyhow::Result<String> {
    let tools = ToolRegistry::new_sub_agent(config, db.clone(), None, false);
    let tool_defs: Vec<ToolDefinition> = tools
        .definitions_for(auth)
        .into_iter()
        .filter(|d| explorer_tool(&d.name))
        .collect();
    let llm = crate::llm::create_provider(config);
    let model = agent
        .and_then(|a| a.model.clone())
        .unwrap_or_else(|| config.model.clone());
    let system = match agent {
        Some(agent) => format!(
            "{}\n\nYou are working for another agent and cannot change anything; only read and search. End with a concise report including file paths and line numbers.",
            agent.prompt
        ),
        None => DEFAULT_PROMPT.to_string(),
    };
    let mut messages = vec![Message {
        role: "user".into(),
        content: MessageContent::Text(task.to_string()),
    }];
    let mut files_read = 0usize;
    for _ in 0..MAX_ITERATIONS {
        let response = llm
            .send_message_with_model(
                &system,
                messages.clone(),
                Some(tool_defs.clone()),
                Some(&model),
            )
            .await?;
        if let Some(usage) = &response.usage {
            let (channel, provider, model_name) = (
                auth.caller_channel.clone(),
                config.llm_provider.clone(),
                model.clone(),
            );
            let (chat_id, input_tokens, output_tokens) = (
                auth.caller_chat_id,
                i64::from(usage.input_tokens),
                i64::from(usage.output_tokens),
            );
            let _ = crate::internal::storage::db::call_blocking(db.clone(), move |db| {
                db.log_llm_usage(
                    chat_id,
                    &channel,
                    &provider,
                    &model_name,
                    input_tokens,
                    output_tokens,
                    "explore",
                )
                .map(|_| ())
            })
            .await;
        }
        let mut text = String::new();
        let mut calls = Vec::new();
        for block in &response.content {
            match block {
                ResponseContentBlock::Text { text: t } => text.push_str(t),
                ResponseContentBlock::ToolUse {
                    id, name, input, ..
                } => calls.push((id.clone(), name.clone(), input.clone())),
                _ => {}
            }
        }
        if calls.is_empty() {
            let report = if text.trim().is_empty() {
                "(the explorer found nothing to report)".to_string()
            } else {
                truncate(text.trim(), MAX_REPORT_CHARS)
            };
            return Ok(format!("{report}\n\n[explore: {files_read} tool calls]"));
        }
        let mut assistant_blocks = Vec::new();
        if !text.trim().is_empty() {
            assistant_blocks.push(ContentBlock::Text { text: text.clone() });
        }
        for (id, name, input) in &calls {
            assistant_blocks.push(ContentBlock::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input: input.clone(),
                thought_signature: None,
            });
        }
        messages.push(Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(assistant_blocks),
        });
        let results = futures_util::future::join_all(calls.iter().map(|(_, name, input)| {
            let name = name.clone();
            let input = input.clone();
            let tools = &tools;
            async move {
                if !explorer_tool(&name) {
                    return ToolResult::error(format!(
                        "`{name}` is not available to the explorer (read-only tools only)"
                    ));
                }
                tools.execute_with_auth(&name, input, auth).await
            }
        }))
        .await;
        files_read += calls.len();
        let result_blocks = calls
            .iter()
            .zip(results)
            .map(|((id, _, _), result)| ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: truncate(&result.content, MAX_TOOL_OUTPUT_CHARS),
                is_error: result.is_error.then_some(true),
            })
            .collect();
        messages.push(Message {
            role: "user".into(),
            content: MessageContent::Blocks(result_blocks),
        });
    }
    anyhow::bail!("no report after {MAX_ITERATIONS} steps; ask a narrower question")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agent_front_matter() {
        let agent = parse_agent(
            "db-expert",
            "---\ndescription: Knows the storage layer\nmodel: small-model\n---\nYou explain the database code.\n",
        );
        assert_eq!(agent.description, "Knows the storage layer");
        assert_eq!(agent.model.as_deref(), Some("small-model"));
        assert_eq!(agent.prompt, "You explain the database code.");
        let plain = parse_agent("plain", "Just a prompt.");
        assert_eq!(plain.prompt, "Just a prompt.");
        assert!(plain.description.is_empty());
    }

    #[test]
    fn loads_agents_from_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.md"),
            "---\ndescription: A\n---\nPrompt A",
        )
        .unwrap();
        std::fs::write(dir.path().join("empty.md"), "---\ndescription: none\n---\n").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        let agents = load_project_agents(dir.path());
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "a");
    }

    #[test]
    fn explorer_tools_are_read_only() {
        assert!(explorer_tool("read_file"));
        assert!(explorer_tool("grep"));
        assert!(!explorer_tool("bash"));
        assert!(!explorer_tool("write_file"));
        assert!(!explorer_tool("explore"));
    }
}
