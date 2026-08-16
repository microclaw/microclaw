use super::*;

pub(crate) fn default_sleep_time_idle_hours() -> u64 {
    6
}

pub(crate) fn default_sleep_time_min_interval_hours() -> u64 {
    24
}

pub(crate) fn default_sleep_time_similarity_threshold() -> f64 {
    0.82
}

pub(crate) fn default_sleep_time_max_archived_per_pass() -> usize {
    20
}

/// "Sleep-time" memory consolidation: when a chat has been idle for a while, run a
/// background, deterministic (no-LLM) pass that archives near-duplicate memories so
/// the store stops accumulating redundancy between reflector runs. PROFILE memories
/// are never touched, archiving is reversible, and the pass is capped and throttled.
/// OFF by default. First slice of the v0.3.0 "Self-Improving Runtime" sleep-time
/// consolidation (Pillar 1c).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SleepTimeConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Only consolidate a chat after this many hours with no messages.
    #[serde(default = "default_sleep_time_idle_hours")]
    pub idle_hours: u64,
    /// At most one consolidation pass per chat per this many hours.
    #[serde(default = "default_sleep_time_min_interval_hours")]
    pub min_interval_hours: u64,
    /// Jaccard similarity at/above which two same-category memories are treated as
    /// duplicates (the lower-confidence one is archived). Clamped to [0.5, 1.0].
    #[serde(default = "default_sleep_time_similarity_threshold")]
    pub similarity_threshold: f64,
    /// Safety cap on how many memories a single pass may archive per chat.
    #[serde(default = "default_sleep_time_max_archived_per_pass")]
    pub max_archived_per_pass: usize,
}

impl Default for SleepTimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_hours: default_sleep_time_idle_hours(),
            min_interval_hours: default_sleep_time_min_interval_hours(),
            similarity_threshold: default_sleep_time_similarity_threshold(),
            max_archived_per_pass: default_sleep_time_max_archived_per_pass(),
        }
    }
}

pub(crate) fn default_heartbeat_interval_mins() -> u64 {
    30
}

pub(crate) fn default_heartbeat_max_chars() -> usize {
    8000
}

/// OpenClaw-style proactive heartbeat. When enabled, every `interval_mins`
/// the bot reads each chat's `runtime/groups/<chat_id>/HEARTBEAT.md` checklist
/// and runs an agent turn over it; the agent messages the chat only when
/// something on the list genuinely needs attention, otherwise stays silent.
/// OFF by default — and chats without a HEARTBEAT.md file are never touched.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Minutes between heartbeat sweeps. Default: 30.
    #[serde(default = "default_heartbeat_interval_mins")]
    pub interval_mins: u64,
    /// Max characters of HEARTBEAT.md injected into the prompt. Default: 8000.
    #[serde(default = "default_heartbeat_max_chars")]
    pub max_chars: usize,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_mins: default_heartbeat_interval_mins(),
            max_chars: default_heartbeat_max_chars(),
        }
    }
}

pub(crate) fn default_idle_checkin_idle_hours() -> u64 {
    24
}

pub(crate) fn default_idle_checkin_min_interval_hours() -> u64 {
    24
}

/// Proactive "long-silence" check-in: after a chat has been quiet for a while,
/// optionally let the bot reach out IF it has something genuinely useful to say
/// (a pending follow-up, a due reminder). OFF by default — it is outward-facing
/// and uses an LLM call per idle chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdleCheckinConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Only consider a chat idle after this many hours with no messages.
    #[serde(default = "default_idle_checkin_idle_hours")]
    pub idle_hours: u64,
    /// At most one check-in per chat per this many hours.
    #[serde(default = "default_idle_checkin_min_interval_hours")]
    pub min_interval_hours: u64,
}

impl Default for IdleCheckinConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_hours: default_idle_checkin_idle_hours(),
            min_interval_hours: default_idle_checkin_min_interval_hours(),
        }
    }
}

pub(crate) fn default_interjection_min_interval_secs() -> u64 {
    900
}

pub(crate) fn default_interjection_lookback_mins() -> u64 {
    10
}

/// "Inner thoughts" interjection: in an active group chat where the bot was NOT
/// addressed, occasionally evaluate whether it has a genuinely valuable thing to
/// say and, if so, chime in once. OFF by default — it speaks unprompted in
/// group conversations and uses an LLM call per evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterjectionConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Minimum seconds between unprompted interjections per chat.
    #[serde(default = "default_interjection_min_interval_secs")]
    pub min_interval_secs: u64,
    /// Only consider chats with non-bot messages in the last this-many minutes.
    #[serde(default = "default_interjection_lookback_mins")]
    pub lookback_mins: u64,
}

impl Default for InterjectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_secs: default_interjection_min_interval_secs(),
            lookback_mins: default_interjection_lookback_mins(),
        }
    }
}
