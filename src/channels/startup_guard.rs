use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing::info;

static CHANNEL_START_MS: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, i64>> {
    CHANNEL_START_MS.get_or_init(|| Mutex::new(HashMap::new()))
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
