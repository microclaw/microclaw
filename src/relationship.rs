//! Relationship familiarity: a light, prompt-level sense of how well the bot
//! "knows" the person it's talking to, derived from how much history they share
//! (the stored message count). People treat a stranger and an old friend
//! differently; this nudges tone the same way.
//!
//! Conservative by design: only the extremes (brand-new vs. long-time) inject
//! anything. The broad middle stays silent so we don't over-prompt.

/// Threshold (messages) below which a chat is treated as brand-new.
const NEW_MAX: i64 = 6;
/// Threshold (messages) at/above which a chat is treated as long-running.
const FAMILIAR_MIN: i64 = 200;

/// One-line familiarity guidance for the system prompt, or `None` for the
/// broad middle where no nudge is warranted.
pub fn familiarity_hint(message_count: i64) -> Option<&'static str> {
    if message_count < NEW_MAX {
        Some(
            "This looks like one of your first conversations with this person. Be welcoming and a \
touch more explicit — you don't share much history yet, so don't assume prior context.",
        )
    } else if message_count >= FAMILIAR_MIN {
        Some(
            "You and this person go back a long way. You can be relaxed and familiar, and lean on \
the history and context you already share.",
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_chats_get_a_welcoming_nudge() {
        assert!(familiarity_hint(0).unwrap().contains("first conversations"));
        assert!(familiarity_hint(5).is_some());
    }

    #[test]
    fn the_middle_stays_silent() {
        assert!(familiarity_hint(6).is_none());
        assert!(familiarity_hint(50).is_none());
        assert!(familiarity_hint(199).is_none());
    }

    #[test]
    fn long_running_chats_get_a_familiar_nudge() {
        assert!(familiarity_hint(200).unwrap().contains("go back a long way"));
        assert!(familiarity_hint(5000).is_some());
    }
}
