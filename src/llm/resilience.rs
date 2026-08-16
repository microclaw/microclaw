use super::*;

/// Number of consecutive primary-model failures before the breaker opens.
pub(crate) const BREAKER_FAILURE_THRESHOLD: u32 = 4;

/// How long the breaker stays open (routing straight to the fallback) before it
/// lets a primary probe through again.
pub(crate) const BREAKER_COOLDOWN_SECS: u64 = 30;

/// A simple consecutive-failure circuit breaker for the primary model. When the
/// primary fails `threshold` times in a row the breaker opens for `cooldown`,
/// during which calls skip the primary and go straight to the fallback; after
/// the cooldown a single primary probe is allowed through (closing the breaker
/// on success, reopening on failure).
/// Process-wide provider failover stats, aggregated across every
/// `ResilientProvider` instance (main + aux slots). Powers `/status`,
/// the governance snapshot, and the "provider down" alert class.
pub(crate) static FAILOVER_TOTAL: AtomicU64 = AtomicU64::new(0);

pub(crate) static FAILURES_CONSECUTIVE: AtomicU64 = AtomicU64::new(0);

pub(crate) static BREAKER_OPEN_UNTIL_EPOCH_MS: AtomicU64 = AtomicU64::new(0);

pub(crate) static LAST_FAILURE_EPOCH_MS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderFailoverSnapshot {
    /// Calls that were served by the fallback model since process start.
    pub total_fallbacks: u64,
    /// Provider failures since the last success (approximate: shared across
    /// provider instances, reset by a success on any of them).
    pub consecutive_failures: u64,
    /// True while any circuit breaker's cooldown window is still open. The
    /// window expires on its own and is NOT cleared by a success on a
    /// different provider instance (an aux-slot success must not mask a
    /// down primary), so this can briefly over-report a breaker that
    /// recovered early — a conservative, fail-safe bias.
    pub breaker_open: bool,
    pub last_failure_epoch_ms: Option<u64>,
}

pub fn provider_failover_snapshot() -> ProviderFailoverSnapshot {
    let last = LAST_FAILURE_EPOCH_MS.load(Ordering::Relaxed);
    ProviderFailoverSnapshot {
        total_fallbacks: FAILOVER_TOTAL.load(Ordering::Relaxed),
        consecutive_failures: FAILURES_CONSECUTIVE.load(Ordering::Relaxed),
        breaker_open: BREAKER_OPEN_UNTIL_EPOCH_MS.load(Ordering::Relaxed) > epoch_ms(),
        last_failure_epoch_ms: if last == 0 { None } else { Some(last) },
    }
}

pub(crate) fn note_fallback_used() {
    FAILOVER_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub(crate) struct CircuitBreaker {
    failures: AtomicU32,
    open_until: Mutex<Option<Instant>>,
    threshold: u32,
    cooldown: Duration,
}

impl CircuitBreaker {
    pub(crate) fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            open_until: Mutex::new(None),
            threshold,
            cooldown,
        }
    }

    pub(crate) fn is_open(&self, now: Instant) -> bool {
        match *self.open_until.lock().unwrap_or_else(|p| p.into_inner()) {
            Some(until) => now < until,
            None => false,
        }
    }

    pub(crate) fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.open_until.lock() {
            *guard = None;
        }
        // Reset only this instance's contribution to the shared consecutive
        // counter. The global breaker-open window is deliberately NOT
        // cleared here: a success on this (possibly aux) instance must not
        // mask a different instance's still-open primary breaker; the window
        // expires on its own timeline.
        FAILURES_CONSECUTIVE.store(0, Ordering::Relaxed);
    }

    pub(crate) fn record_failure(&self, now: Instant) {
        let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        FAILURES_CONSECUTIVE.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_EPOCH_MS.store(epoch_ms(), Ordering::Relaxed);
        if n >= self.threshold {
            if let Ok(mut guard) = self.open_until.lock() {
                *guard = Some(now + self.cooldown);
            }
            // Extend the shared window to the furthest-out cooldown rather
            // than overwriting, so concurrent breakers can't shorten it.
            BREAKER_OPEN_UNTIL_EPOCH_MS.fetch_max(
                epoch_ms() + self.cooldown.as_millis() as u64,
                Ordering::Relaxed,
            );
        }
    }
}

/// Decorator that adds a circuit breaker + model fallback around any
/// `LlmProvider`. Non-streaming calls fall back to the configured model after a
/// primary failure (or immediately while the breaker is open); streaming calls
/// route to the fallback while the breaker is open but do not retry mid-stream
/// (which would risk duplicating already-emitted output).
pub struct ResilientProvider {
    inner: Box<dyn LlmProvider>,
    fallback_model: String,
    breaker: CircuitBreaker,
}

impl ResilientProvider {
    pub(crate) fn new(inner: Box<dyn LlmProvider>, fallback_model: String) -> Self {
        Self {
            inner,
            fallback_model,
            breaker: CircuitBreaker::new(
                BREAKER_FAILURE_THRESHOLD,
                Duration::from_secs(BREAKER_COOLDOWN_SECS),
            ),
        }
    }

    async fn call(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let now = Instant::now();
        // Breaker open and the caller didn't pin a model → fail fast to fallback.
        if model_override.is_none() && self.breaker.is_open(now) {
            warn!(
                "LLM circuit breaker open; routing to fallback model {}",
                self.fallback_model
            );
            note_fallback_used();
            return self
                .inner
                .send_message_with_model(system, messages, tools, Some(&self.fallback_model))
                .await;
        }
        match self
            .inner
            .send_message_with_model(system, messages.clone(), tools.clone(), model_override)
            .await
        {
            Ok(r) => {
                self.breaker.record_success();
                Ok(r)
            }
            Err(e) => {
                self.breaker.record_failure(now);
                // Try the fallback once, unless the caller already asked for it.
                if model_override != Some(self.fallback_model.as_str()) {
                    warn!(
                        "primary LLM call failed ({e}); retrying with fallback model {}",
                        self.fallback_model
                    );
                    note_fallback_used();
                    match self
                        .inner
                        .send_message_with_model(
                            system,
                            messages,
                            tools,
                            Some(&self.fallback_model),
                        )
                        .await
                    {
                        Ok(r) => Ok(r),
                        Err(e2) => {
                            warn!("fallback model also failed: {e2}");
                            Err(e)
                        }
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn call_stream(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
        model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let now = Instant::now();
        if model_override.is_none() && self.breaker.is_open(now) {
            warn!(
                "LLM circuit breaker open; streaming via fallback model {}",
                self.fallback_model
            );
            note_fallback_used();
            return self
                .inner
                .send_message_stream_with_model(
                    system,
                    messages,
                    tools,
                    text_tx,
                    Some(&self.fallback_model),
                )
                .await;
        }
        match self
            .inner
            .send_message_stream_with_model(system, messages, tools, text_tx, model_override)
            .await
        {
            Ok(r) => {
                self.breaker.record_success();
                Ok(r)
            }
            Err(e) => {
                // No mid-stream fallback: deltas may already have been emitted,
                // so re-streaming would duplicate output. The next call will
                // route to the fallback once the breaker opens.
                self.breaker.record_failure(now);
                Err(e)
            }
        }
    }
}

#[async_trait]
impl LlmProvider for ResilientProvider {
    async fn send_message(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        self.call(system, messages, tools, None).await
    }

    async fn send_message_with_model(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        self.call(system, messages, tools, model_override).await
    }

    async fn send_message_stream(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        self.call_stream(system, messages, tools, text_tx, None)
            .await
    }

    async fn send_message_stream_with_model(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
        model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        self.call_stream(system, messages, tools, text_tx, model_override)
            .await
    }
}

// ---------------------------------------------------------------------------
// Anthropic provider
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

    #[test]
    pub(crate) fn test_circuit_breaker_opens_and_recovers() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(!cb.is_open(t0));
        cb.record_failure(t0);
        assert!(!cb.is_open(t0), "one failure below threshold must not open");
        cb.record_failure(t0);
        assert!(cb.is_open(t0), "threshold failures must open the breaker");
        assert!(
            cb.is_open(t0 + Duration::from_secs(59)),
            "open during cooldown"
        );
        assert!(
            !cb.is_open(t0 + Duration::from_secs(61)),
            "closed (half-open probe) after cooldown"
        );
        // A success fully resets the breaker.
        cb.record_success();
        assert!(!cb.is_open(t0));
    }
}
