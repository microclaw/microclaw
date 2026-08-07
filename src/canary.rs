//! Model-swap canary: probe a candidate `model:` value with live calls
//! before an operator switches config, and show the result next to the
//! currently configured model.
//!
//! Two probes per model, both cheap:
//! 1. **responds** — a one-word health prompt returns non-empty text;
//! 2. **tool calls** — given a trivial `ping` tool and an instruction to
//!    call it, the response contains a tool_use block (agentic tool-calling
//!    is the capability MicroClaw actually depends on; plenty of models can
//!    chat but fumble tool calls).
//!
//! The probe clones the runtime config and swaps only the model, so the
//! candidate runs through the exact provider path (base URL, auth, user
//! agent) the runtime would use. The fallback model is pinned to the probed
//! model so `ResilientProvider` cannot silently mask a broken candidate by
//! routing to the fallback.

use std::time::Instant;

use serde_json::json;

use crate::config::Config;
use microclaw_core::llm_types::{
    Message, MessageContent, ResponseContentBlock, ToolDefinition,
};

#[derive(Debug, serde::Serialize)]
pub struct ModelProbe {
    pub model: String,
    pub responds: bool,
    pub tool_calls: bool,
    pub latency_ms: u128,
    pub error: Option<String>,
}

impl ModelProbe {
    pub fn passed(&self) -> bool {
        self.responds && self.tool_calls
    }
}

fn ping_tool() -> ToolDefinition {
    ToolDefinition {
        name: "ping".into(),
        description: "Health-check tool. Call it with the value you were given.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {"value": {"type": "integer", "description": "Echo value"}},
            "required": ["value"]
        }),
    }
}

async fn probe_model(base: &Config, model: &str) -> ModelProbe {
    let mut cfg = base.clone();
    cfg.model = model.to_string();
    cfg.fallback_model = Some(model.to_string());
    let provider = crate::llm::create_provider(&cfg);
    let started = Instant::now();

    let text_result = provider
        .send_message(
            "You are a health probe. Reply with the single word OK.",
            vec![Message {
                role: "user".into(),
                content: MessageContent::Text("ping".into()),
            }],
            None,
        )
        .await;
    let (responds, mut error) = match &text_result {
        Ok(resp) => (
            resp.content.iter().any(|block| {
                matches!(block, ResponseContentBlock::Text { text } if !text.trim().is_empty())
            }),
            None,
        ),
        Err(e) => (false, Some(e.to_string())),
    };

    let tool_calls = if responds {
        match provider
            .send_message(
                "You are a health probe. You MUST call the ping tool; do not answer in text.",
                vec![Message {
                    role: "user".into(),
                    content: MessageContent::Text("Call the ping tool with value 42.".into()),
                }],
                Some(vec![ping_tool()]),
            )
            .await
        {
            Ok(resp) => resp
                .content
                .iter()
                .any(|block| matches!(block, ResponseContentBlock::ToolUse { .. })),
            Err(e) => {
                error = Some(e.to_string());
                false
            }
        }
    } else {
        false
    };

    ModelProbe {
        model: model.to_string(),
        responds,
        tool_calls,
        latency_ms: started.elapsed().as_millis(),
        error,
    }
}

fn render(probe: &ModelProbe, label: &str) -> String {
    let verdict = if probe.passed() {
        "PASS"
    } else {
        "FAIL"
    };
    let mut line = format!(
        "{verdict} {label} {} — responds: {}, tool calls: {}, {} ms",
        probe.model,
        if probe.responds { "yes" } else { "NO" },
        if probe.tool_calls { "yes" } else { "NO" },
        probe.latency_ms
    );
    if let Some(err) = &probe.error {
        line.push_str(&format!("\n     error: {err}"));
    }
    line
}

/// Probe `candidate` (and, unless skipped, the currently configured model as
/// a baseline) and print a comparison. Exit code 0 when the candidate passes
/// both probes, 1 otherwise.
pub async fn run_canary(
    config: &Config,
    candidate: &str,
    skip_baseline: bool,
    json_output: bool,
) -> i32 {
    let baseline = if skip_baseline || config.model == candidate {
        None
    } else {
        Some(probe_model(config, &config.model).await)
    };
    let candidate_probe = probe_model(config, candidate).await;

    if json_output {
        let payload = json!({
            "baseline": baseline,
            "candidate": candidate_probe,
            "candidate_passed": candidate_probe.passed(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
        );
    } else {
        if let Some(b) = &baseline {
            println!("{}", render(b, "baseline "));
            if !b.passed() {
                println!(
                    "     note: the CURRENT model fails its own probes — fix credentials/config \
                     before judging the candidate."
                );
            }
        }
        println!("{}", render(&candidate_probe, "candidate"));
        if candidate_probe.passed() {
            println!(
                "\nCandidate looks usable. Switch with `model: {candidate}` in the config, and \
                 keep the old value handy for rollback."
            );
        } else {
            println!("\nCandidate FAILED — do not switch `model:` yet.");
        }
    }
    if candidate_probe.passed() {
        0
    } else {
        1
    }
}
