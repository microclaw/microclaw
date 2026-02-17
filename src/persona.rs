//! Persona system: per-chat identity that selects which session and message history to use.
//! Operations (list, switch, new, delete, model) are internal; use the HTTP API or this module.
//! Chat flow only resolves persona_id via db.get_or_create_default_persona(chat_id).

use std::sync::Arc;

use crate::config::Config;
use crate::db::{call_blocking, Database};

/// Handle a persona command payload (e.g. from API or internal call).
/// `text` is the full message; the first token is typically "/persona" or "/personas", rest are subcommand and args.
/// When creating or updating a persona with a model, pass `config` so the model is tested first; if `config` is None, the test is skipped.
/// Returns a response string to show the user (or API client).
pub async fn handle_persona_command(
    db: Arc<Database>,
    chat_id: i64,
    text: &str,
    config: Option<&Config>,
) -> String {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let sub = parts.get(1).map(|s| *s).unwrap_or("");

    if sub.is_empty() || sub == "list" {
        // List personas
        let personas = match call_blocking(db.clone(), move |d| d.list_personas(chat_id)).await {
            Ok(p) => p,
            Err(e) => return format!("Error: {e}"),
        };
        let active_id = match call_blocking(db.clone(), move |d| d.get_active_persona_id(chat_id)).await {
            Ok(Some(id)) => id,
            _ => 0,
        };
        if personas.is_empty() {
            let _ = call_blocking(db.clone(), move |d| d.get_or_create_default_persona(chat_id)).await;
            return "Personas: default (active). Use /persona switch <name> to switch.".into();
        }
        let names: Vec<String> = personas
            .iter()
            .map(|p| {
                let suffix = if Some(p.id) == active_id.into() { " (active)" } else { "" };
                format!("{}{}", p.name, suffix)
            })
            .collect();
        format!("Personas: {}. Use /persona switch <name> to switch.", names.join(", "))
    } else if sub == "switch" {
        let name: String = parts.get(2).map(|s| (*s).to_string()).unwrap_or_default();
        if name.is_empty() {
            return "Usage: /persona switch <name>".into();
        }
        let name_for_fmt = name.clone();
        match call_blocking(db.clone(), move |d| d.get_persona_by_name(chat_id, &name)).await {
            Ok(Some(persona)) => {
                if let Ok(true) = call_blocking(db.clone(), move |d| d.set_active_persona(chat_id, persona.id)).await {
                    format!("Switched to {}.", name_for_fmt)
                } else {
                    "Failed to switch.".into()
                }
            }
            Ok(None) => format!("Persona '{}' not found. Use /persona new {} to create.", name_for_fmt, name_for_fmt),
            Err(e) => format!("Error: {e}"),
        }
    } else if sub == "new" {
        let name = parts.get(2).map(|s| (*s).to_string()).unwrap_or_default();
        if name.is_empty() {
            return "Usage: /persona new <name> [model]".into();
        }
        let model: Option<String> = parts.get(3).map(|s| (*s).to_string());
        let model_note = model.as_ref().map(|m| format!(" using model {}", m)).unwrap_or_default();
        let name_for_fmt = name.clone();
        // When a model is specified, test it before creating the persona (if config available)
        let model_ok_note = if let Some(ref model_str) = model {
            if let Some(cfg) = config {
                match crate::llm::test_model(cfg, model_str).await {
                    Ok(()) => "Model OK. ",
                    Err(e) => return format!("Model test failed: {e}. Persona not created."),
                }
            } else {
                ""
            }
        } else {
            ""
        };
        match call_blocking(db.clone(), move |d| d.create_persona(chat_id, &name, model.as_deref())).await {
            Ok(new_id) => {
                let _ = call_blocking(db.clone(), move |d| d.set_active_persona(chat_id, new_id)).await;
                format!("{}Created persona {}{} and switched to it.", model_ok_note, name_for_fmt, model_note)
            }
            Err(e) => format!("Error: {e}"),
        }
    } else if sub == "delete" {
        let name = parts.get(2).map(|s| (*s).to_string()).unwrap_or_default();
        if name.is_empty() {
            return "Usage: /persona delete <name>".into();
        }
        let name_for_fmt = name.clone();
        match call_blocking(db.clone(), move |d| d.get_persona_by_name(chat_id, &name)).await {
            Ok(Some(persona)) => match call_blocking(db.clone(), move |d| d.delete_persona(chat_id, persona.id)).await {
                Ok(true) => format!("Deleted persona {}.", name_for_fmt),
                Ok(false) => "Failed to delete.".into(),
                Err(e) => format!("Error: {e}"),
            },
            Ok(None) => format!("Persona '{}' not found.", name_for_fmt),
            Err(e) => format!("Error: {e}"),
        }
    } else if sub == "model" {
        let name = parts.get(2).map(|s| (*s).to_string()).unwrap_or_default();
        let model: Option<String> = parts.get(3).map(|s| (*s).to_string());
        if name.is_empty() {
            return "Usage: /persona model <name> <model>".into();
        }
        let model_str = match &model {
            Some(m) => m.as_str(),
            None => return "Usage: /persona model <name> <model>".into(),
        };
        // Test the model before updating (if config available)
        let model_ok_note = if let Some(cfg) = config {
            match crate::llm::test_model(cfg, model_str).await {
                Ok(()) => "Model OK. ",
                Err(e) => return format!("Model test failed: {e}. Persona model not updated."),
            }
        } else {
            ""
        };
        let name_for_fmt = name.clone();
        match call_blocking(db.clone(), move |d| d.get_persona_by_name(chat_id, &name)).await {
            Ok(Some(persona)) => {
                let persona_id = persona.id;
                let model_display = model.clone();
                if let Ok(true) = call_blocking(db.clone(), move |d| d.update_persona_model(chat_id, persona_id, model.as_deref())).await {
                    format!("{}Set model for {} to {:?}.", model_ok_note, name_for_fmt, model_display)
                } else {
                    "Failed to update.".into()
                }
            }
            Ok(None) => format!("Persona '{}' not found.", name_for_fmt),
            Err(e) => format!("Error: {e}"),
        }
    } else {
        "Usage: /persona [list|switch|new|delete|model]".into()
    }
}
