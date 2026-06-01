//! Lightweight, zero-cost conversational mood detection.
//!
//! `SOUL.md` defines the bot's *stable* personality; this adds the *fluid*
//! layer — a coarse read of the user's current emotional state from their
//! latest message — so the bot can adapt tone (empathize when they're
//! frustrated, be crisp when they're in a hurry) without any extra LLM call.
//!
//! Detection is deliberately conservative: it only fires on clear signals and
//! otherwise returns `None` (no injection), since a wrong mood read is worse
//! than none. Cues cover both English and Chinese.

/// A coarse read of the user's current emotional tone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    Frustrated,
    Urgent,
    Sad,
    Confused,
    Grateful,
    Excited,
    Playful,
}

impl Mood {
    /// Short label shown inside the `<conversation_mood>` block.
    fn label(self) -> &'static str {
        match self {
            Mood::Frustrated => "frustrated",
            Mood::Urgent => "in a hurry",
            Mood::Sad => "down",
            Mood::Confused => "confused",
            Mood::Grateful => "appreciative",
            Mood::Excited => "excited",
            Mood::Playful => "playful",
        }
    }

    /// One-line tone guidance for the model.
    fn guidance(self) -> &'static str {
        match self {
            Mood::Frustrated => {
                "Acknowledge the frustration briefly, skip the cheer, and get straight to fixing the problem."
            }
            Mood::Urgent => {
                "Be fast and direct — give the answer first and trim everything optional."
            }
            Mood::Sad => {
                "Lead with a little genuine warmth before the practical part; don't be chirpy."
            }
            Mood::Confused => {
                "Slow down, use plainer words, and give one clear step at a time."
            }
            Mood::Grateful => {
                "A brief, warm acknowledgement is enough — don't overdo it."
            }
            Mood::Excited => "Match their energy a little, then keep things moving.",
            Mood::Playful => {
                "A light, casual tone fits here, and a touch of humor is welcome."
            }
        }
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Detect a coarse mood from the user's latest message. Returns `None` when the
/// signal is weak or neutral. Negative states are checked first since handling
/// them well matters most.
pub fn detect_mood(text: &str) -> Option<Mood> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let lower = t.to_lowercase();

    // Frustrated / angry.
    let strong_punct = t.contains("?!") || t.contains("!!!") || t.contains("？！");
    if contains_any(
        &lower,
        &[
            "frustrat",
            "annoying",
            "annoyed",
            "this is ridiculous",
            "not working",
            "still broken",
            "still not working",
            "doesn't work",
            "doesnt work",
            "wtf",
            " ugh",
            "ugh ",
            "useless",
            "i hate",
            "so stupid",
            "again?!",
        ],
    ) || contains_any(
        t,
        &[
            "烦",
            "崩溃",
            "无语",
            "搞什么",
            "又不行",
            "还是不行",
            "气死",
            "什么破",
            "废物",
            "垃圾",
            "受不了",
            "服了",
        ],
    ) || (strong_punct && contains_any(&lower, &["why", "still", "again"])
        || strong_punct && contains_any(t, &["为什么", "怎么", "又"]))
    {
        return Some(Mood::Frustrated);
    }

    // Urgent.
    if contains_any(
        &lower,
        &[
            "asap",
            "urgent",
            "right now",
            "immediately",
            "hurry",
            "deadline",
            "emergency",
            "as fast as",
            "quickly please",
            "need it now",
        ],
    ) || contains_any(
        t,
        &[
            "很急",
            "急",
            "马上",
            "立刻",
            "赶紧",
            "尽快",
            "快点",
            "现在就要",
            "等不及",
        ],
    ) {
        return Some(Mood::Urgent);
    }

    // Sad / down / overwhelmed.
    if contains_any(
        &lower,
        &[
            "depressed",
            "burned out",
            "burnt out",
            "overwhelmed",
            "exhausted",
            "feeling down",
            "so tired",
            "i'm sad",
            "im sad",
            "can't cope",
            "cant cope",
        ],
    ) || contains_any(
        t,
        &[
            "难过",
            "伤心",
            "好累",
            "累了",
            "压力好大",
            "撑不住",
            "焦虑",
            "心累",
            "失落",
        ],
    ) {
        return Some(Mood::Sad);
    }

    // Confused.
    if contains_any(
        &lower,
        &[
            "i'm confused",
            "im confused",
            "i don't understand",
            "i dont understand",
            "doesn't make sense",
            "what do you mean",
            "i'm lost",
            "im lost",
            "no idea what",
        ],
    ) || contains_any(
        t,
        &[
            "看不懂",
            "不明白",
            "搞不懂",
            "什么意思",
            "没看懂",
            "懵",
            "不懂",
        ],
    ) {
        return Some(Mood::Confused);
    }

    // Grateful.
    if contains_any(
        &lower,
        &[
            "thank you",
            "thanks",
            "appreciate it",
            "you're the best",
            "lifesaver",
            "much appreciated",
        ],
    ) || contains_any(t, &["谢谢", "感谢", "太感谢", "辛苦了", "多谢", "感激"])
    {
        return Some(Mood::Grateful);
    }

    // Excited.
    if contains_any(
        &lower,
        &[
            "awesome",
            "amazing",
            "let's go",
            "lets go",
            "can't wait",
            "cant wait",
            "so excited",
            "this is great",
            "love it",
            "incredible",
            "🎉",
            "🚀",
            "🔥",
        ],
    ) || contains_any(
        t,
        &[
            "太棒",
            "太好了",
            "厉害",
            "牛",
            "期待",
            "激动",
            "爱了",
            "yyds",
        ],
    ) {
        return Some(Mood::Excited);
    }

    // Playful.
    if contains_any(&lower, &["lol", "lmao", "rofl", "😂", "🤣", "😜", "haha"])
        || contains_any(t, &["哈哈", "嘻嘻", "2333", "doge"])
    {
        return Some(Mood::Playful);
    }

    None
}

/// Build the `<conversation_mood>` body for the latest user message, or `None`.
pub fn mood_hint(text: &str) -> Option<String> {
    detect_mood(text).map(|m| format!("The user sounds {}. {}", m.label(), m.guidance()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_text_yields_no_mood() {
        assert_eq!(detect_mood("what's the capital of France?"), None);
        assert_eq!(detect_mood(""), None);
        assert!(mood_hint("please summarize this file").is_none());
    }

    #[test]
    fn detects_frustration_en_and_zh() {
        assert_eq!(
            detect_mood("this is still not working, ugh"),
            Some(Mood::Frustrated)
        );
        assert_eq!(detect_mood("又不行，气死了"), Some(Mood::Frustrated));
    }

    #[test]
    fn detects_urgency_and_sadness() {
        assert_eq!(detect_mood("I need this ASAP"), Some(Mood::Urgent));
        assert_eq!(detect_mood("赶紧帮我看下"), Some(Mood::Urgent));
        assert_eq!(
            detect_mood("I'm so exhausted and overwhelmed"),
            Some(Mood::Sad)
        );
    }

    #[test]
    fn gratitude_and_excitement_and_hint_text() {
        assert_eq!(detect_mood("thank you so much!"), Some(Mood::Grateful));
        assert_eq!(detect_mood("太棒了，厉害"), Some(Mood::Excited));
        let hint = mood_hint("this is still broken, wtf").unwrap();
        assert!(hint.contains("frustrated"));
    }
}
