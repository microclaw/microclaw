use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing::info;

static CHANNEL_START_MS: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
static CHANNEL_RECENT_MESSAGE_IDS: OnceLock<Mutex<HashMap<String, HashMap<String, i64>>>> =
    OnceLock::new();
const RECENT_DUPLICATE_TTL_MS: i64 = 10 * 60 * 1000;
const RECENT_DUPLICATE_MAX_IDS_PER_CHANNEL: usize = 20_000;

fn registry() -> &'static Mutex<HashMap<String, i64>> {
    CHANNEL_START_MS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn recent_message_registry() -> &'static Mutex<HashMap<String, HashMap<String, i64>>> {
    CHANNEL_RECENT_MESSAGE_IDS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn mark_channel_started(channel_name: &str) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Ok(mut map) = registry().lock() {
        map.insert(channel_name.to_string(), now_ms);
    }
}

pub fn should_drop_pre_start_message(
    channel_name: &str,
    message_id: &str,
    message_time_ms: Option<i64>,
) -> bool {
    let Some(msg_ms) = message_time_ms else {
        return false;
    };
    let start_ms = registry()
        .lock()
        .ok()
        .and_then(|map| map.get(channel_name).copied());
    let Some(start_ms) = start_ms else {
        return false;
    };
    if msg_ms < start_ms {
        info!(
            "Channel startup guard: dropping pre-start message channel={} message_id={} message_ms={} startup_ms={}",
            channel_name, message_id, msg_ms, start_ms
        );
        return true;
    }
    false
}

pub fn should_drop_recent_duplicate_message(channel_name: &str, message_id: &str) -> bool {
    let message_id = message_id.trim();
    if message_id.is_empty() {
        return false;
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let Ok(mut guard) = recent_message_registry().lock() else {
        return false;
    };
    let ids = guard.entry(channel_name.to_string()).or_default();

    if let Some(last_seen_ms) = ids.get(message_id).copied() {
        if now_ms.saturating_sub(last_seen_ms) <= RECENT_DUPLICATE_TTL_MS {
            info!(
                "Channel duplicate guard: dropping duplicate message channel={} message_id={} last_seen_ms={} now_ms={}",
                channel_name, message_id, last_seen_ms, now_ms
            );
            return true;
        }
    }

    ids.insert(message_id.to_string(), now_ms);

    // Keep memory bounded for long-running processes.
    if ids.len() > RECENT_DUPLICATE_MAX_IDS_PER_CHANNEL {
        ids.retain(|_, seen_ms| now_ms.saturating_sub(*seen_ms) <= RECENT_DUPLICATE_TTL_MS);
    }

    false
}

pub fn parse_epoch_ms_from_str(raw: &str) -> Option<i64> {
    raw.trim().parse::<i64>().ok()
}

pub fn parse_epoch_ms_from_seconds_str(raw: &str) -> Option<i64> {
    parse_epoch_ms_from_str(raw).map(|secs| secs.saturating_mul(1000))
}

pub fn parse_epoch_ms_from_seconds_fraction(raw: &str) -> Option<i64> {
    let secs = raw.trim().parse::<f64>().ok()?;
    Some((secs * 1000.0) as i64)
}

#[cfg(test)]
mod tests {
    use super::should_drop_recent_duplicate_message;

    #[test]
    fn test_recent_duplicate_message_guard() {
        let channel = "test.startup_guard.dup";
        let message = "mid_123";
        assert!(!should_drop_recent_duplicate_message(channel, message));
        assert!(should_drop_recent_duplicate_message(channel, message));
    }
}
