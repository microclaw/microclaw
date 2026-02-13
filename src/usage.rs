use std::sync::Arc;

use chrono::SecondsFormat;

use crate::config::Config;
use crate::db::{call_blocking, Database, LlmModelUsageSummary, LlmUsageSummary};

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

pub async fn build_usage_report(
    db: Arc<Database>,
    _config: &Config,
    chat_id: i64,
) -> Result<String, String> {
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
        db,
        None,
        Some((now - chrono::Duration::days(7)).to_rfc3339()),
    )
    .await?;

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

    Ok(lines.join("\n"))
}
