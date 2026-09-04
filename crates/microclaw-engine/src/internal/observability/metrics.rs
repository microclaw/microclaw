use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry::metrics::{Counter, MeterProvider, UpDownCounter};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::runtime;
use serde_yaml::Value;
use tracing::{debug, info, warn};

use crate::internal::observability::sdk::{
    get_bool, get_trimmed, get_u64, parse_headers, OTelSdkContext,
};

#[derive(Debug, Clone)]
pub struct OtlpMetricSnapshot {
    pub timestamp_unix_nano: u64,
    pub http_requests: i64,
    pub llm_completions: i64,
    pub llm_input_tokens: i64,
    pub llm_output_tokens: i64,
    pub tool_executions: i64,
    pub mcp_calls: i64,
    pub mcp_rate_limited_rejections: i64,
    pub mcp_bulkhead_rejections: i64,
    pub mcp_circuit_open_rejections: i64,
    pub active_sessions: i64,
}

#[derive(Clone)]
pub struct OtlpMetricExporter {
    inner: Arc<OtlpMetricsInner>,
}

struct OtlpMetricsInner {
    provider: SdkMeterProvider,
    instruments: MetricInstruments,
    previous: Mutex<Option<OtlpMetricSnapshot>>,
}

#[derive(Clone)]
struct MetricInstruments {
    http_requests: Counter<u64>,
    llm_completions: Counter<u64>,
    llm_input_tokens: Counter<u64>,
    llm_output_tokens: Counter<u64>,
    tool_executions: Counter<u64>,
    mcp_calls: Counter<u64>,
    mcp_rate_limited_rejections: Counter<u64>,
    mcp_bulkhead_rejections: Counter<u64>,
    mcp_circuit_open_rejections: Counter<u64>,
    active_sessions: UpDownCounter<i64>,
}

impl OtlpMetricExporter {
    pub fn from_observability(observability: Option<&Value>) -> Option<Arc<Self>> {
        let map = observability?.as_mapping()?;
        let enabled = get_bool(map, "otlp_enabled").unwrap_or(false);
        if !enabled {
            debug!("otlp metric exporter disabled by config");
            return None;
        }
        let endpoint = get_trimmed(map, "otlp_endpoint")?.to_string();
        let sdk = OTelSdkContext::from_observability(map);
        let interval_secs = get_u64(map, "otlp_export_interval_seconds")
            .map(|v| v.clamp(1, 300))
            .unwrap_or(15);
        let headers = parse_headers(map);

        let mut exporter_builder = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_http_client(reqwest::Client::new())
            .with_endpoint(endpoint.clone());
        if !headers.is_empty() {
            exporter_builder =
                exporter_builder.with_headers(headers.into_iter().collect::<HashMap<_, _>>());
        }
        let exporter = match exporter_builder.build() {
            Ok(exporter) => exporter,
            Err(err) => {
                warn!(
                    endpoint = %endpoint,
                    "failed to build otlp metric exporter: {}",
                    err
                );
                return None;
            }
        };

        let reader = PeriodicReader::builder(exporter, runtime::Tokio)
            .with_interval(Duration::from_secs(interval_secs))
            .build();
        let provider = SdkMeterProvider::builder()
            .with_resource(sdk.resource)
            .with_reader(reader)
            .build();
        let meter = provider.meter("microclaw.observability.metrics");
        let instruments = MetricInstruments {
            http_requests: meter.u64_counter("microclaw_http_requests").build(),
            llm_completions: meter.u64_counter("microclaw_llm_completions").build(),
            llm_input_tokens: meter.u64_counter("microclaw_llm_input_tokens").build(),
            llm_output_tokens: meter.u64_counter("microclaw_llm_output_tokens").build(),
            tool_executions: meter.u64_counter("microclaw_tool_executions").build(),
            mcp_calls: meter.u64_counter("microclaw_mcp_calls").build(),
            mcp_rate_limited_rejections: meter
                .u64_counter("microclaw_mcp_rate_limited_rejections")
                .build(),
            mcp_bulkhead_rejections: meter
                .u64_counter("microclaw_mcp_bulkhead_rejections")
                .build(),
            mcp_circuit_open_rejections: meter
                .u64_counter("microclaw_mcp_circuit_open_rejections")
                .build(),
            active_sessions: meter
                .i64_up_down_counter("microclaw_active_sessions")
                .build(),
        };
        info!(
            endpoint = %endpoint,
            export_interval_secs = interval_secs,
            service_name = %sdk.service_name,
            "otlp metric exporter initialized"
        );

        Some(Arc::new(Self {
            inner: Arc::new(OtlpMetricsInner {
                provider,
                instruments,
                previous: Mutex::new(None),
            }),
        }))
    }

    pub fn enqueue_metrics(&self, snapshot: OtlpMetricSnapshot) -> Result<(), String> {
        let mut previous = self.inner.previous.lock().map_err(|_| {
            warn!("failed to enqueue metrics snapshot: metrics state lock poisoned");
            "metrics state lock poisoned".to_string()
        })?;

        let delta = if let Some(prev) = previous.as_ref() {
            OtlpMetricSnapshot {
                timestamp_unix_nano: snapshot.timestamp_unix_nano,
                http_requests: (snapshot.http_requests - prev.http_requests).max(0),
                llm_completions: (snapshot.llm_completions - prev.llm_completions).max(0),
                llm_input_tokens: (snapshot.llm_input_tokens - prev.llm_input_tokens).max(0),
                llm_output_tokens: (snapshot.llm_output_tokens - prev.llm_output_tokens).max(0),
                tool_executions: (snapshot.tool_executions - prev.tool_executions).max(0),
                mcp_calls: (snapshot.mcp_calls - prev.mcp_calls).max(0),
                mcp_rate_limited_rejections: (snapshot.mcp_rate_limited_rejections
                    - prev.mcp_rate_limited_rejections)
                    .max(0),
                mcp_bulkhead_rejections: (snapshot.mcp_bulkhead_rejections
                    - prev.mcp_bulkhead_rejections)
                    .max(0),
                mcp_circuit_open_rejections: (snapshot.mcp_circuit_open_rejections
                    - prev.mcp_circuit_open_rejections)
                    .max(0),
                active_sessions: snapshot.active_sessions - prev.active_sessions,
            }
        } else {
            OtlpMetricSnapshot {
                timestamp_unix_nano: snapshot.timestamp_unix_nano,
                http_requests: snapshot.http_requests.max(0),
                llm_completions: snapshot.llm_completions.max(0),
                llm_input_tokens: snapshot.llm_input_tokens.max(0),
                llm_output_tokens: snapshot.llm_output_tokens.max(0),
                tool_executions: snapshot.tool_executions.max(0),
                mcp_calls: snapshot.mcp_calls.max(0),
                mcp_rate_limited_rejections: snapshot.mcp_rate_limited_rejections.max(0),
                mcp_bulkhead_rejections: snapshot.mcp_bulkhead_rejections.max(0),
                mcp_circuit_open_rejections: snapshot.mcp_circuit_open_rejections.max(0),
                active_sessions: snapshot.active_sessions,
            }
        };

        self.inner
            .instruments
            .http_requests
            .add(delta.http_requests as u64, &[]);
        self.inner
            .instruments
            .llm_completions
            .add(delta.llm_completions as u64, &[]);
        self.inner
            .instruments
            .llm_input_tokens
            .add(delta.llm_input_tokens as u64, &[]);
        self.inner
            .instruments
            .llm_output_tokens
            .add(delta.llm_output_tokens as u64, &[]);
        self.inner
            .instruments
            .tool_executions
            .add(delta.tool_executions as u64, &[]);
        self.inner
            .instruments
            .mcp_calls
            .add(delta.mcp_calls as u64, &[]);
        self.inner
            .instruments
            .mcp_rate_limited_rejections
            .add(delta.mcp_rate_limited_rejections as u64, &[]);
        self.inner
            .instruments
            .mcp_bulkhead_rejections
            .add(delta.mcp_bulkhead_rejections as u64, &[]);
        self.inner
            .instruments
            .mcp_circuit_open_rejections
            .add(delta.mcp_circuit_open_rejections as u64, &[]);
        self.inner
            .instruments
            .active_sessions
            .add(delta.active_sessions, &[]);
        debug!(
            timestamp_unix_nano = snapshot.timestamp_unix_nano,
            "otlp metric snapshot recorded"
        );

        *previous = Some(snapshot);
        Ok(())
    }
}

impl Drop for OtlpMetricsInner {
    fn drop(&mut self) {
        if let Err(err) = self.provider.force_flush() {
            warn!("otlp metric exporter force_flush failed: {}", err);
        } else {
            debug!("otlp metric exporter force_flush succeeded");
        }
        if let Err(err) = self.provider.shutdown() {
            warn!("otlp metric exporter shutdown failed: {}", err);
        } else {
            debug!("otlp metric exporter shutdown succeeded");
        }
    }
}
