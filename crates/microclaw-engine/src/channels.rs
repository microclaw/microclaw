const FEISHU_REACTION_PROTOCOL_PROMPT: &str = r#"
# Feishu Reaction Protocol

- To react to the user's current Feishu message, put `reaction-only: EMOJI_TYPE` on the final line.
- Use a Feishu emoji type such as `THUMBSUP`, `OK`, `DONE`, `SMILE`, `APPLAUSE`, or `MUSCLE`.
- The channel removes this control line before delivery and applies the reaction to the source message.
- For normal Feishu replies/reactions, do not call `send_message`; return final assistant text directly.
- Call `send_message` only when an attachment must be delivered.
"#;

pub fn system_prompt_extension(caller_channel: &str) -> Option<&'static str> {
    if caller_channel.starts_with("feishu") || caller_channel.starts_with("lark") {
        Some(FEISHU_REACTION_PROTOCOL_PROMPT)
    } else {
        None
    }
}
