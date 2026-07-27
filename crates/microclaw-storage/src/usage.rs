use std::sync::Arc;

use chrono::SecondsFormat;

use crate::db::{
    call_blocking, Database, ExperienceSummary, LlmModelUsageSummary, LlmUsageSummary,
    MemoryObservabilitySummary, SkillLearningSummary,
};

fn fmt_int(v: i64) -> String {
    let neg = v < 0;
    let mut n = v.unsigned_abs();
    let mut parts = Vec::new();
    while n >= 1000 {
        parts.push(format!("{:03}", n % 1000));
        n /= 1000;
    }
    let mut out = n.to_string();
    while let Some(p) = parts.pop() {
        out.push(',');
        out.push_str(&p);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

fn fmt_summary_line(name: &str, s: &LlmUsageSummary) -> String {
    format!(
        "{name:<8} req={:>4}  tok={} (in {} / out {})",
        fmt_int(s.requests),
        fmt_int(s.total_tokens),
        fmt_int(s.input_tokens),
        fmt_int(s.output_tokens)
    )
}

fn format_model_rows(rows: &[LlmModelUsageSummary], max_rows: usize) -> Vec<String> {
    if rows.is_empty() {
        return vec!["    - (no data)".to_string()];
    }

    rows.iter()
        .take(max_rows)
        .enumerate()
        .map(|(idx, row)| {
            format!(
                "    {}. {}  tok={}  req={}  in {} / out {}",
                idx + 1,
                row.model,
                fmt_int(row.total_tokens),
                fmt_int(row.requests),
                fmt_int(row.input_tokens),
                fmt_int(row.output_tokens)
            )
        })
        .collect()
}

fn block_lines(
    title: &str,
    all: &LlmUsageSummary,
    d24: &LlmUsageSummary,
    d7: &LlmUsageSummary,
    models_24h: &[LlmModelUsageSummary],
    models_7d: &[LlmModelUsageSummary],
) -> Vec<String> {
    let mut lines = vec![
        title.to_string(),
        "".to_string(),
        format!("  🧮 {}", fmt_summary_line("All-time", all)),
        format!("  🕓 {}", fmt_summary_line("Last 24h", d24)),
        format!("  📆 {}", fmt_summary_line("Last 7d", d7)),
        "".to_string(),
        "  🤖 Top models (24h)".to_string(),
    ];
    lines.extend(format_model_rows(models_24h, 4));
    lines.push("".to_string());
    lines.push("  🤖 Top models (7d)".to_string());
    lines.extend(format_model_rows(models_7d, 4));

    lines
}

async fn query_summary(
    db: Arc<Database>,
    chat_id: Option<i64>,
    since: Option<String>,
) -> Result<LlmUsageSummary, String> {
    call_blocking(db, move |d| {
        d.get_llm_usage_summary_since(chat_id, since.as_deref())
    })
    .await
    .map_err(|e| e.to_string())
}

async fn query_by_model(
    db: Arc<Database>,
    chat_id: Option<i64>,
    since: Option<String>,
) -> Result<Vec<LlmModelUsageSummary>, String> {
    call_blocking(db, move |d| {
        d.get_llm_usage_by_model(chat_id, since.as_deref(), None)
    })
    .await
    .map_err(|e| e.to_string())
}

async fn query_memory_summary(
    db: Arc<Database>,
    chat_id: Option<i64>,
) -> Result<MemoryObservabilitySummary, String> {
    call_blocking(db, move |d| d.get_memory_observability_summary(chat_id))
        .await
        .map_err(|e| e.to_string())
}

async fn query_learning_summary(
    db: Arc<Database>,
    chat_id: Option<i64>,
) -> Result<ExperienceSummary, String> {
    call_blocking(db, move |d| d.get_experience_summary(chat_id))
        .await
        .map_err(|e| e.to_string())
}

async fn query_skill_learning(db: Arc<Database>) -> Result<Vec<SkillLearningSummary>, String> {
    call_blocking(db, move |d| d.get_skill_learning_summaries())
        .await
        .map_err(|e| e.to_string())
}

pub async fn build_usage_report(db: Arc<Database>, chat_id: i64) -> Result<String, String> {
    let now = chrono::Utc::now();
    let since_24h = (now - chrono::Duration::hours(24)).to_rfc3339();
    let since_7d = (now - chrono::Duration::days(7)).to_rfc3339();

    let chat_all = query_summary(db.clone(), Some(chat_id), None).await?;
    let chat_24h = query_summary(db.clone(), Some(chat_id), Some(since_24h.clone())).await?;
    let chat_7d = query_summary(db.clone(), Some(chat_id), Some(since_7d.clone())).await?;
    let chat_models_24h = query_by_model(db.clone(), Some(chat_id), Some(since_24h)).await?;
    let chat_models_7d = query_by_model(db.clone(), Some(chat_id), Some(since_7d)).await?;

    let global_all = query_summary(db.clone(), None, None).await?;
    let global_24h = query_summary(
        db.clone(),
        None,
        Some((now - chrono::Duration::hours(24)).to_rfc3339()),
    )
    .await?;
    let global_7d = query_summary(
        db.clone(),
        None,
        Some((now - chrono::Duration::days(7)).to_rfc3339()),
    )
    .await?;
    let global_models_24h = query_by_model(
        db.clone(),
        None,
        Some((now - chrono::Duration::hours(24)).to_rfc3339()),
    )
    .await?;
    let global_models_7d = query_by_model(
        db.clone(),
        None,
        Some((now - chrono::Duration::days(7)).to_rfc3339()),
    )
    .await?;
    let chat_mem = query_memory_summary(db.clone(), Some(chat_id)).await?;
    let global_mem = query_memory_summary(db.clone(), None).await?;
    let chat_learning = query_learning_summary(db.clone(), Some(chat_id)).await?;
    let global_learning = query_learning_summary(db.clone(), None).await?;
    let skill_learning = query_skill_learning(db).await?;

    let mut lines = vec![
        "📊 Token Usage".to_string(),
        format!(
            "🕒 Updated: {}",
            now.to_rfc3339_opts(SecondsFormat::Secs, true)
        ),
        "".to_string(),
    ];

    lines.extend(block_lines(
        "🔹 This chat",
        &chat_all,
        &chat_24h,
        &chat_7d,
        &chat_models_24h,
        &chat_models_7d,
    ));

    lines.push("".to_string());

    lines.extend(block_lines(
        "🌍 Global",
        &global_all,
        &global_24h,
        &global_7d,
        &global_models_24h,
        &global_models_7d,
    ));

    lines.push("".to_string());
    lines.push("🧠 Memory Observability".to_string());
    lines.push("".to_string());
    lines.push(format!(
        "  This chat: total={} active={} archived={} avg_conf={:.2} low_conf={}",
        fmt_int(chat_mem.total),
        fmt_int(chat_mem.active),
        fmt_int(chat_mem.archived),
        chat_mem.avg_confidence,
        fmt_int(chat_mem.low_confidence)
    ));
    lines.push(format!(
        "  Reflector 24h: runs={} +{} ~{} -{}",
        fmt_int(chat_mem.reflector_runs_24h),
        fmt_int(chat_mem.reflector_inserted_24h),
        fmt_int(chat_mem.reflector_updated_24h),
        fmt_int(chat_mem.reflector_skipped_24h)
    ));
    lines.push(format!(
        "  Injection 24h: events={} selected/candidates={}/{}",
        fmt_int(chat_mem.injection_events_24h),
        fmt_int(chat_mem.injection_selected_24h),
        fmt_int(chat_mem.injection_candidates_24h)
    ));
    lines.push("".to_string());
    lines.push(format!(
        "  Global: total={} active={} archived={} avg_conf={:.2} low_conf={}",
        fmt_int(global_mem.total),
        fmt_int(global_mem.active),
        fmt_int(global_mem.archived),
        global_mem.avg_confidence,
        fmt_int(global_mem.low_confidence)
    ));
    lines.push(format!(
        "  Global reflector 24h: runs={} +{} ~{} -{}",
        fmt_int(global_mem.reflector_runs_24h),
        fmt_int(global_mem.reflector_inserted_24h),
        fmt_int(global_mem.reflector_updated_24h),
        fmt_int(global_mem.reflector_skipped_24h)
    ));
    lines.push(format!(
        "  Global injection 24h: events={} selected/candidates={}/{}",
        fmt_int(global_mem.injection_events_24h),
        fmt_int(global_mem.injection_selected_24h),
        fmt_int(global_mem.injection_candidates_24h)
    ));
    lines.push("".to_string());
    lines.push("Long-Horizon Learning".to_string());
    lines.push("".to_string());
    lines.push(format!(
        "  This chat: runs={} completed={} failed/cancelled={} with_evidence={} tokens={}/{} tools={}/{} cost=${:.4}",
        fmt_int(chat_learning.total_runs),
        fmt_int(chat_learning.completed_runs),
        fmt_int(chat_learning.failed_runs),
        fmt_int(chat_learning.verified_runs),
        fmt_int(chat_learning.input_tokens),
        fmt_int(chat_learning.output_tokens),
        fmt_int(chat_learning.tool_calls),
        fmt_int(chat_learning.tool_errors),
        chat_learning.estimated_cost_usd
    ));
    lines.push(format!(
        "  Global: runs={} completed={} failed/cancelled={} with_evidence={} tokens={}/{} tools={}/{} cost=${:.4}",
        fmt_int(global_learning.total_runs),
        fmt_int(global_learning.completed_runs),
        fmt_int(global_learning.failed_runs),
        fmt_int(global_learning.verified_runs),
        fmt_int(global_learning.input_tokens),
        fmt_int(global_learning.output_tokens),
        fmt_int(global_learning.tool_calls),
        fmt_int(global_learning.tool_errors),
        global_learning.estimated_cost_usd
    ));
    if skill_learning.is_empty() {
        lines.push("  Skills: no governed versions yet".to_string());
    } else {
        lines.push("  Governed skills:".to_string());
        for skill in skill_learning.iter().take(8) {
            lines.push(format!(
                "    - {} v{} [{}] outcomes={} pass_rate={:.0}%",
                skill.skill_name,
                skill.active_version,
                skill.state,
                fmt_int(skill.total_outcomes),
                skill.success_rate * 100.0
            ));
        }
    }

    Ok(lines.join("\n"))
}
