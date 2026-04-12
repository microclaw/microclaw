use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::{call_blocking, Database};

use super::{schema_object, Tool, ToolResult};

pub struct KnowledgeGraphQueryTool {
    db: Arc<Database>,
}

impl KnowledgeGraphQueryTool {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Tool for KnowledgeGraphQueryTool {
    fn name(&self) -> &str {
        "knowledge_graph_query"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "knowledge_graph_query".into(),
            description: "Query the temporal knowledge graph for entity relationships. Returns triples (subject-predicate-object) with temporal validity. Use 'as_of' for point-in-time queries. Use 'timeline' mode to see how facts changed over time.".into(),
            input_schema: schema_object(
                json!({
                    "entity": {
                        "type": "string",
                        "description": "The entity (subject or object) to query"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["subject", "object", "timeline", "stats"],
                        "description": "Query mode: 'subject' (find facts about entity), 'object' (reverse lookup), 'timeline' (all historical facts), 'stats' (graph statistics)"
                    },
                    "as_of": {
                        "type": "string",
                        "description": "Optional ISO 8601 timestamp for point-in-time query (only for subject mode)"
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Optional chat_id to scope the query"
                    }
                }),
                &["entity", "mode"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let entity = match input.get("entity").and_then(|v| v.as_str()) {
            Some(e) if !e.trim().is_empty() => e.trim().to_string(),
            _ => return ToolResult::error("Missing required parameter: entity".into()),
        };
        let mode = input
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("subject");
        let chat_id = input.get("chat_id").and_then(|v| v.as_i64());
        let as_of = input
            .get("as_of")
            .and_then(|v| v.as_str())
            .map(String::from);

        let db = self.db.clone();
        match mode {
            "subject" => {
                let entity_clone = entity.clone();
                let as_of_clone = as_of.clone();
                let triples = call_blocking(db, move |db| {
                    db.kg_query_subject(&entity_clone, chat_id, as_of_clone.as_deref())
                })
                .await
                .map_err(|e| e.to_string());
                match triples {
                    Ok(rows) if rows.is_empty() => {
                        ToolResult::success(format!("No facts found for entity '{entity}'."))
                    }
                    Ok(rows) => {
                        let mut out = format!("Facts about '{entity}'");
                        if let Some(ts) = &as_of {
                            out.push_str(&format!(" (as of {ts})"));
                        }
                        out.push_str(":\n");
                        for t in &rows {
                            out.push_str(&format!(
                                "  [{}] {} -> {} (since {}, confidence: {:.2})\n",
                                t.predicate, t.subject, t.object, t.valid_from, t.confidence
                            ));
                        }
                        ToolResult::success(out)
                    }
                    Err(e) => ToolResult::error(format!("Query failed: {e}")),
                }
            }
            "object" => {
                let entity_clone = entity.clone();
                let triples =
                    call_blocking(db, move |db| db.kg_query_object(&entity_clone, chat_id))
                        .await
                        .map_err(|e| e.to_string());
                match triples {
                    Ok(rows) if rows.is_empty() => ToolResult::success(format!(
                        "No relationships found pointing to '{entity}'."
                    )),
                    Ok(rows) => {
                        let mut out =
                            format!("Entities related to '{entity}' (as object):\n");
                        for t in &rows {
                            out.push_str(&format!(
                                "  {} -[{}]-> {} (since {})\n",
                                t.subject, t.predicate, t.object, t.valid_from
                            ));
                        }
                        ToolResult::success(out)
                    }
                    Err(e) => ToolResult::error(format!("Query failed: {e}")),
                }
            }
            "timeline" => {
                let entity_clone = entity.clone();
                let triples =
                    call_blocking(db, move |db| db.kg_timeline(&entity_clone, chat_id))
                        .await
                        .map_err(|e| e.to_string());
                match triples {
                    Ok(rows) if rows.is_empty() => ToolResult::success(format!(
                        "No historical facts found for entity '{entity}'."
                    )),
                    Ok(rows) => {
                        let mut out = format!("Timeline for '{entity}':\n");
                        for t in &rows {
                            let status = if t.valid_to.is_some() {
                                format!("invalidated at {}", t.valid_to.as_deref().unwrap_or("?"))
                            } else {
                                "current".to_string()
                            };
                            out.push_str(&format!(
                                "  {} | {} -> {} [{}] ({})\n",
                                t.valid_from, t.subject, t.object, t.predicate, status
                            ));
                        }
                        ToolResult::success(out)
                    }
                    Err(e) => ToolResult::error(format!("Query failed: {e}")),
                }
            }
            "stats" => {
                let stats = call_blocking(db, move |db| db.kg_stats(chat_id))
                    .await
                    .map_err(|e| e.to_string());
                match stats {
                    Ok((total, active, invalidated)) => ToolResult::success(format!(
                        "Knowledge graph stats: {total} total triples, {active} active, {invalidated} invalidated"
                    )),
                    Err(e) => ToolResult::error(format!("Stats failed: {e}")),
                }
            }
            _ => ToolResult::error(format!(
                "Unknown mode: {mode}. Use subject, object, timeline, or stats."
            )),
        }
    }
}

pub struct KnowledgeGraphAddTool {
    db: Arc<Database>,
}

impl KnowledgeGraphAddTool {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Tool for KnowledgeGraphAddTool {
    fn name(&self) -> &str {
        "knowledge_graph_add"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "knowledge_graph_add".into(),
            description: "Add a fact (triple) to the temporal knowledge graph. Facts are subject-predicate-object with a valid_from timestamp. Use this to record structured relationships between entities discovered during conversation.".into(),
            input_schema: schema_object(
                json!({
                    "subject": {
                        "type": "string",
                        "description": "The subject entity (e.g., 'User', 'ProjectX', 'production-db')"
                    },
                    "predicate": {
                        "type": "string",
                        "description": "The relationship (e.g., 'uses', 'prefers', 'located_at', 'version_is')"
                    },
                    "object": {
                        "type": "string",
                        "description": "The object entity or value (e.g., 'Rust', 'PostgreSQL 16', 'us-east-1')"
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Chat ID to scope this fact to (default: current chat)"
                    },
                    "invalidates_id": {
                        "type": "integer",
                        "description": "Optional: ID of a previous triple this fact supersedes (will set its valid_to)"
                    }
                }),
                &["subject", "predicate", "object"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let subject = match input.get("subject").and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => return ToolResult::error("Missing required parameter: subject".into()),
        };
        let predicate = match input.get("predicate").and_then(|v| v.as_str()) {
            Some(p) if !p.trim().is_empty() => p.trim().to_string(),
            _ => return ToolResult::error("Missing required parameter: predicate".into()),
        };
        let object = match input.get("object").and_then(|v| v.as_str()) {
            Some(o) if !o.trim().is_empty() => o.trim().to_string(),
            _ => return ToolResult::error("Missing required parameter: object".into()),
        };
        let chat_id = input.get("chat_id").and_then(|v| v.as_i64());
        let invalidates_id = input.get("invalidates_id").and_then(|v| v.as_i64());

        let now = chrono::Utc::now().to_rfc3339();

        // Invalidate the old triple if specified
        if let Some(old_id) = invalidates_id {
            let db = self.db.clone();
            let now_clone = now.clone();
            let _ = call_blocking(db, move |db| db.kg_invalidate_triple(old_id, &now_clone)).await;
        }

        let db = self.db.clone();
        let now_clone = now.clone();
        let subject_clone = subject.clone();
        let predicate_clone = predicate.clone();
        let object_clone = object.clone();
        match call_blocking(db, move |db| {
            db.kg_insert_triple(
                &subject_clone,
                &predicate_clone,
                &object_clone,
                chat_id,
                &now_clone,
                0.80,
                "agent",
                None,
            )
        })
        .await
        {
            Ok(id) => {
                info!(
                    "KG: added triple #{} ({} -> {} -> {})",
                    id, subject, predicate, object
                );
                let mut msg = format!("Added to knowledge graph: {subject} -[{predicate}]-> {object} (id={id})");
                if let Some(old_id) = invalidates_id {
                    msg.push_str(&format!(", invalidated previous triple #{old_id}"));
                }
                ToolResult::success(msg)
            }
            Err(e) => ToolResult::error(format!("Failed to add triple: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("microclaw_kg_test_{}", uuid::Uuid::new_v4()));
        let db = Database::new(dir.to_str().unwrap()).unwrap();
        (Arc::new(db), dir)
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_kg_add_and_query() {
        let (db, dir) = test_db();
        let add_tool = KnowledgeGraphAddTool::new(db.clone());
        let query_tool = KnowledgeGraphQueryTool::new(db.clone());

        // Add a triple
        let result = add_tool
            .execute(json!({
                "subject": "User",
                "predicate": "prefers",
                "object": "Rust"
            }))
            .await;
        assert!(!result.is_error, "Error: {}", result.content);
        assert!(result.content.contains("Added to knowledge graph"));

        // Query it
        let result = query_tool
            .execute(json!({
                "entity": "User",
                "mode": "subject"
            }))
            .await;
        assert!(!result.is_error, "Error: {}", result.content);
        assert!(result.content.contains("prefers"));
        assert!(result.content.contains("Rust"));

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_kg_invalidate_and_timeline() {
        let (db, dir) = test_db();

        // Insert first triple directly with a fixed timestamp to avoid timing races
        let id1 = microclaw_storage::db::call_blocking(db.clone(), |db| {
            db.kg_insert_triple(
                "db-port",
                "is",
                "5432",
                None,
                "2026-01-01T00:00:00Z",
                0.80,
                "test",
                None,
            )
        })
        .await
        .unwrap();

        // Invalidate the first and add the second
        let now = "2026-01-02T00:00:00Z";
        let _ = microclaw_storage::db::call_blocking(db.clone(), {
            let now = now.to_string();
            move |db| db.kg_invalidate_triple(id1, &now)
        })
        .await;

        let _ = microclaw_storage::db::call_blocking(db.clone(), {
            let now = now.to_string();
            move |db| {
                db.kg_insert_triple(
                    "db-port",
                    "is",
                    "5433",
                    None,
                    &now,
                    0.80,
                    "test",
                    None,
                )
            }
        })
        .await
        .unwrap();

        let query_tool = KnowledgeGraphQueryTool::new(db.clone());

        // Current query should only show 5433 (5432 is invalidated)
        let current = query_tool
            .execute(json!({
                "entity": "db-port",
                "mode": "subject"
            }))
            .await;
        assert!(
            current.content.contains("5433"),
            "Expected 5433 in current: {}",
            current.content
        );
        assert!(
            !current.content.contains("5432"),
            "Expected no 5432 in current: {}",
            current.content
        );

        // Timeline should show both
        let timeline = query_tool
            .execute(json!({
                "entity": "db-port",
                "mode": "timeline"
            }))
            .await;
        assert!(timeline.content.contains("5432"));
        assert!(timeline.content.contains("5433"));
        assert!(timeline.content.contains("invalidated"));
        assert!(timeline.content.contains("current"));

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_kg_stats() {
        let (db, dir) = test_db();
        let add_tool = KnowledgeGraphAddTool::new(db.clone());
        let query_tool = KnowledgeGraphQueryTool::new(db.clone());

        add_tool
            .execute(json!({"subject": "A", "predicate": "knows", "object": "B"}))
            .await;
        add_tool
            .execute(json!({"subject": "C", "predicate": "knows", "object": "D"}))
            .await;

        let result = query_tool
            .execute(json!({"entity": "_", "mode": "stats"}))
            .await;
        assert!(result.content.contains("2 total"));
        assert!(result.content.contains("2 active"));

        cleanup(&dir);
    }
}
