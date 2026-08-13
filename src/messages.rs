//! Bilingual (en/zh) catalog for user-facing runtime messages.
//!
//! Refusals, approval prompts, and recovery notices are product surface,
//! not log lines — they should read like a person wrote them, in the
//! operator's language. `user_message_language` selects `en` (default,
//! preserves historical output), `zh`, or `bilingual` (both blocks).
//! Approval reply keywords are always recognized in both languages
//! regardless of the render language.

use crate::config::UserMessageLanguage;

/// Structured approval prompt: what is waiting, an optional command
/// preview, an optional advisory verdict from the aux reviewer, and the
/// numbered option card.
pub fn approval_prompt(
    lang: UserMessageLanguage,
    tool_name: &str,
    preview: Option<&str>,
    advisory: Option<&str>,
) -> String {
    let preview_block = preview
        .map(|p| format!("\n\n```\n{p}\n```"))
        .unwrap_or_default();
    let advisory_en = advisory
        .map(|a| format!("\nRisk reviewer (advisory only): {a}"))
        .unwrap_or_default();
    let advisory_zh = advisory
        .map(|a| format!("\n风险复核（仅供参考）：{a}"))
        .unwrap_or_default();
    let en = format!(
        "High-risk tool '{tool_name}' is waiting for your confirmation.{preview_block}{advisory_en}\n\n\
         1. Approve once (reply \"1\" or \"approve\" / \"批准\")\n\
         2. Always allow '{tool_name}' in this chat (reply \"2\" or \"always\")\n\
         3. Deny (reply \"3\", \"deny\", or any other instruction)"
    );
    let zh = format!(
        "高风险工具 '{tool_name}' 正在等待你的确认。{preview_block}{advisory_zh}\n\n\
         1. 批准本次（回复 \"1\" 或 \"批准\"）\n\
         2. 本聊天始终允许 '{tool_name}'（回复 \"2\" 或 \"总是\"）\n\
         3. 拒绝（回复 \"3\"、\"拒绝\"，或发送其他指令）"
    );
    match lang {
        UserMessageLanguage::En => en,
        UserMessageLanguage::Zh => zh,
        UserMessageLanguage::Bilingual => format!("{en}\n\n{zh}"),
    }
}

/// Labels for the interactive approval buttons (approve once / always
/// allow / deny), matching the numbered option card in [`approval_prompt`].
pub fn approval_button_labels(lang: UserMessageLanguage) -> [String; 3] {
    match lang {
        UserMessageLanguage::Zh => [
            "✅ 批准本次".into(),
            "🔁 始终允许".into(),
            "❌ 拒绝".into(),
        ],
        _ => [
            "✅ Approve once".into(),
            "🔁 Always allow".into(),
            "❌ Deny".into(),
        ],
    }
}

/// Short prompt line shown on the interactive approval button message.
pub fn approval_buttons_hint(lang: UserMessageLanguage) -> &'static str {
    match lang {
        UserMessageLanguage::Zh => "请选择：",
        UserMessageLanguage::Bilingual => "Choose an option / 请选择：",
        UserMessageLanguage::En => "Choose an option:",
    }
}

/// Confirmation line the approval button message is edited to after a
/// choice is made.
pub fn approval_choice_ack(lang: UserMessageLanguage, label: &str) -> String {
    match lang {
        UserMessageLanguage::Zh => format!("已选择：{label}"),
        _ => format!("Selected: {label}"),
    }
}

/// Suffix appended after the (stable, test-guarded) budget refusal prefix.
pub fn budget_refusal_body(
    lang: UserMessageLanguage,
    used: i64,
    budget: i64,
) -> String {
    let en = format!(
        " for this chat ({used} of {budget} tokens in the last 24h). I'll be available again \
         once usage rolls out of the window. An operator can raise \
         `token_budget.daily_per_chat` in the config."
    );
    let zh = format!(
        "本聊天已用 {used} / {budget} tokens（近 24 小时）。用量滚出窗口后我会恢复可用；\
         管理员可在配置中调高 `token_budget.daily_per_chat`。"
    );
    match lang {
        UserMessageLanguage::En => en,
        UserMessageLanguage::Zh => format!(" — {zh}"),
        UserMessageLanguage::Bilingual => format!("{en}\n{zh}"),
    }
}

/// Notice sent when a restart interrupted a turn at an uncertain tool
/// boundary and the run was deliberately not replayed.
pub fn interruption_notice(
    lang: UserMessageLanguage,
    progress: Option<&str>,
    tool_summary: Option<&str>,
) -> String {
    let tool_summary = tool_summary.filter(|value| !value.trim().is_empty());
    let progress = progress.filter(|value| !value.trim().is_empty());

    let en = {
        let mut notice = "⚠️ I restarted while a tool operation was in progress. I did not \
                          replay it because the external side effect may already have happened."
            .to_string();
        if let Some(summary) = tool_summary {
            notice.push_str("\n\nOperation at the uncertain boundary: ");
            notice.push_str(summary);
            notice.push('.');
        }
        if let Some(progress) = progress {
            notice.push_str("\nLast durable progress: ");
            notice.push_str(progress);
            notice.push('.');
        }
        notice.push_str(
            "\n\nPlease verify the external state, then tell me to continue. This run was \
             stopped deliberately to avoid duplicating a write, message, command, or other \
             side effect.",
        );
        notice
    };
    let zh = {
        let mut notice = "⚠️ 我在一次工具操作进行中重启了。因为外部副作用可能已经发生，我没有重放这次操作。"
            .to_string();
        if let Some(summary) = tool_summary {
            notice.push_str("\n\n不确定边界上的操作：");
            notice.push_str(summary);
            notice.push('。');
        }
        if let Some(progress) = progress {
            notice.push_str("\n最后一次持久进度：");
            notice.push_str(progress);
            notice.push('。');
        }
        notice.push_str(
            "\n\n请先核实外部状态，然后告诉我继续。这次运行是有意停下的，以避免重复写入、发消息、执行命令等副作用。",
        );
        notice
    };
    match lang {
        UserMessageLanguage::En => en,
        UserMessageLanguage::Zh => zh,
        UserMessageLanguage::Bilingual => format!("{en}\n\n{zh}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_prompt_renders_options_in_each_language() {
        let en = approval_prompt(UserMessageLanguage::En, "bash", Some("rm -rf /tmp/x"), None);
        assert!(en.contains("1. Approve once"));
        assert!(en.contains("rm -rf /tmp/x"));
        assert!(en.contains("批准")); // zh keyword stays discoverable in en

        let zh = approval_prompt(UserMessageLanguage::Zh, "bash", None, Some("looks safe"));
        assert!(zh.contains("批准本次"));
        assert!(zh.contains("风险复核"));

        let both = approval_prompt(UserMessageLanguage::Bilingual, "bash", None, None);
        assert!(both.contains("Approve once") && both.contains("批准本次"));
    }

    #[test]
    fn budget_refusal_en_matches_historical_wording() {
        let body = budget_refusal_body(UserMessageLanguage::En, 10, 5);
        assert!(body.starts_with(" for this chat (10 of 5 tokens"));
    }
}
