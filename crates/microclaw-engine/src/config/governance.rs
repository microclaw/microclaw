use super::*;

/// Opt-in post-edit self-recheck (one review pass after file-modifying
/// turns, before the reply finalizes).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SelfRecheckConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Custom prompt template; `{{USER}}` and `{{RESULT}}` placeholders are
    /// replaced with the original request and the draft reply.
    #[serde(default)]
    pub prompt: Option<String>,
}

pub(crate) fn default_token_budget_exempt_control_chats() -> bool {
    true
}

/// Per-chat token spend cap. Counters Hermes-style "week-3 bill" drift:
/// once a chat's rolling-24h total (input+output, all request kinds) hits
/// `daily_per_chat`, new turns are refused with a notice until usage rolls
/// out of the window. 0 (default) = unlimited; control chats exempt by
/// default so operators can always reach the bot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBudgetConfig {
    /// Total tokens (input+output) allowed per chat per rolling 24h. 0 = off.
    #[serde(default)]
    pub daily_per_chat: i64,
    #[serde(default = "default_token_budget_exempt_control_chats")]
    pub exempt_control_chats: bool,
}

impl Default for TokenBudgetConfig {
    fn default() -> Self {
        Self {
            daily_per_chat: 0,
            exempt_control_chats: default_token_budget_exempt_control_chats(),
        }
    }
}

impl TokenBudgetConfig {
    /// True when a chat that has already spent `used` tokens in the window
    /// must be refused a new turn.
    pub fn blocks(&self, is_control_chat: bool, used: i64) -> bool {
        if self.daily_per_chat <= 0 {
            return false;
        }
        if self.exempt_control_chats && is_control_chat {
            return false;
        }
        used >= self.daily_per_chat
    }
}

pub(crate) fn default_alerts_interval_secs() -> u64 {
    60
}

pub(crate) fn default_alerts_cooldown_secs() -> u64 {
    900
}

pub(crate) fn default_alerts_restart_storm_threshold() -> u64 {
    5
}

/// Opt-in operational webhook alerts. When enabled, a supervised loop
/// polls runtime health every `interval_secs` and POSTs a JSON alert to
/// `webhook_url` when a condition trips: scheduler DLQ growth, provider
/// down (circuit breaker open / repeated failures), token-budget
/// exhaustion, or a supervised-loop restart storm. OFF by default; the
/// webhook URL participates in the configured-endpoint egress policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Webhook that receives alert POSTs (JSON body: class, message,
    /// generated_at).
    #[serde(default)]
    pub webhook_url: String,
    /// Seconds between health polls. Default: 60 (min 10).
    #[serde(default = "default_alerts_interval_secs")]
    pub interval_secs: u64,
    /// Minimum seconds between two alerts of the same class. Default: 900.
    #[serde(default = "default_alerts_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Supervised-loop restarts within one poll interval that count as a
    /// storm. Default: 5.
    #[serde(default = "default_alerts_restart_storm_threshold")]
    pub restart_storm_threshold: u64,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            interval_secs: default_alerts_interval_secs(),
            cooldown_secs: default_alerts_cooldown_secs(),
            restart_storm_threshold: default_alerts_restart_storm_threshold(),
        }
    }
}

pub(crate) fn default_trust_report_interval_days() -> u64 {
    7
}

/// Opt-in periodic "trust report": a digest of what the agent actually did
/// — task runs, contract verdicts, token spend, guardrail interventions,
/// delivery/recovery health — delivered to every control chat. OFF by
/// default. Built entirely from data MicroClaw already records (usage
/// ledger, contract events, tamper-evident audit chain), so enabling it
/// costs no extra LLM calls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustReportConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Days between reports. Default: 7.
    #[serde(default = "default_trust_report_interval_days")]
    pub interval_days: u64,
}

impl Default for TrustReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_days: default_trust_report_interval_days(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::test_prelude::*;

    #[test]
    fn token_budget_disabled_never_blocks() {
        let cfg = TokenBudgetConfig::default();
        assert!(!cfg.blocks(false, i64::MAX));
        assert!(!cfg.blocks(true, i64::MAX));
    }

    #[test]
    fn token_budget_blocks_at_cap_but_exempts_control_chats() {
        let cfg = TokenBudgetConfig {
            daily_per_chat: 1000,
            exempt_control_chats: true,
        };
        assert!(!cfg.blocks(false, 999));
        assert!(cfg.blocks(false, 1000));
        assert!(cfg.blocks(false, 5000));
        // Control chat exempt by default
        assert!(!cfg.blocks(true, 5000));
        // ...unless exemption is turned off
        let strict = TokenBudgetConfig {
            daily_per_chat: 1000,
            exempt_control_chats: false,
        };
        assert!(strict.blocks(true, 1000));
    }
}
