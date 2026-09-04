use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry::trace::{
    Span as _, SpanContext, SpanId, SpanKind, Status as OtelStatus, TraceContextExt, TraceFlags,
    TraceId, TraceState, Tracer, TracerProvider,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_proto::tonic::trace::v1::Status;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
use opentelemetry_sdk::trace::{BatchConfigBuilder, SdkTracerProvider, Tracer as SdkTracer};
use serde_yaml::Value as YamlValue;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::internal::observability::adapters;
use crate::internal::observability::sdk::{
    get_bool, get_trimmed, get_u64, parse_headers, OTelSdkContext,
};

#[derive(Debug, Clone)]
pub struct SpanData {
    pub trace_id: Vec<u8>,
    pub span_id: Vec<u8>,
    pub parent_span_id: Vec<u8>,
    pub name: String,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: Vec<KeyValue>,
    pub status: Option<Status>,
    pub kind: i32,
}

#[derive(Clone)]
pub struct OtlpTraceExporter {
    tracer: SdkTracer,
    provider: Arc<SdkTracerProvider>,
}

pub fn new_trace_id() -> Vec<u8> {
    Uuid::new_v4().as_bytes().to_vec()
}

pub fn new_span_id() -> Vec<u8> {
    Uuid::new_v4().as_bytes()[0..8].to_vec()
}

pub fn now_unix_nano() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue::new(key.to_string(), value.to_string())
}

pub fn kv_int(key: &str, value: i64) -> KeyValue {
    KeyValue::new(key.to_string(), value)
}

impl OtlpTraceExporter {
    pub fn from_observability(observability: Option<&YamlValue>) -> Option<Arc<Self>> {
        let map = observability?.as_mapping()?;
        let mut target = adapters::TraceTargetConfig {
            endpoint: get_trimmed(map, "otlp_tracing_endpoint").map(ToOwned::to_owned),
            headers: parse_headers(map),
        };

        adapters::langfuse::apply(map, &mut target);
        adapters::agentops::apply(map, &mut target);

        let enabled = get_bool(map, "otlp_tracing_enabled").unwrap_or(target.endpoint.is_some());
        if !enabled {
            debug!("otlp trace exporter disabled by config");
            return None;
        }

        let endpoint = target.endpoint?;
        let sdk = OTelSdkContext::from_observability(map);
        let max_queue_size = get_u64(map, "otlp_tracing_max_queue_size")
            .map(|v| v.clamp(512, 65536))
            .unwrap_or(8192) as usize;
        let max_export_batch_size = get_u64(map, "otlp_tracing_max_export_batch_size")
            .map(|v| v.clamp(64, max_queue_size as u64))
            .unwrap_or(512) as usize;
        let scheduled_delay_ms = get_u64(map, "otlp_tracing_scheduled_delay_ms")
            .map(|v| v.clamp(100, 10000))
            .unwrap_or(5000);

        let mut exporter_builder = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_http_client(reqwest::Client::new())
            .with_endpoint(endpoint.clone());
        if !target.headers.is_empty() {
            exporter_builder = exporter_builder
                .with_headers(target.headers.into_iter().collect::<HashMap<_, _>>());
        }
        let exporter = match exporter_builder.build() {
            Ok(exporter) => exporter,
            Err(err) => {
                warn!(
                    endpoint = %endpoint,
                    "failed to build otlp trace exporter: {}",
                    err
                );
                return None;
            }
        };

        let batch_config = BatchConfigBuilder::default()
            .with_max_queue_size(max_queue_size)
            .with_max_export_batch_size(max_export_batch_size)
            .with_scheduled_delay(Duration::from_millis(scheduled_delay_ms))
            .build();
        let batch_processor = BatchSpanProcessor::builder(exporter, runtime::Tokio)
            .with_batch_config(batch_config)
            .build();
        let provider = SdkTracerProvider::builder()
            .with_resource(sdk.resource)
            .with_span_processor(batch_processor)
            .build();
        let tracer = provider.tracer("microclaw.observability.traces");
        info!(
            endpoint = %endpoint,
            service_name = %sdk.service_name,
            max_queue_size,
            max_export_batch_size,
            scheduled_delay_ms,
            "otlp trace exporter initialized"
        );

        Some(Arc::new(Self {
            tracer,
            provider: Arc::new(provider),
        }))
    }

    pub fn send_span(&self, span: SpanData) {
        let parent = build_parent_context(&span);
        let SpanData {
            trace_id,
            span_id,
            name,
            kind,
            start_time_unix_nano,
            end_time_unix_nano,
            attributes,
            status,
            ..
        } = span;
        let mut builder = self
            .tracer
            .span_builder(name)
            .with_kind(to_span_kind(kind))
            .with_start_time(unix_nano_to_time(start_time_unix_nano))
            .with_attributes(attributes);
        if trace_id.len() == 16 {
            if let Ok(bytes) = trace_id.as_slice().try_into() {
                builder = builder.with_trace_id(TraceId::from_bytes(bytes));
            }
        } else {
            warn!(
                trace_id_len = trace_id.len(),
                "invalid trace_id length, expected 16 bytes"
            );
        }
        if span_id.len() == 8 {
            if let Ok(bytes) = span_id.as_slice().try_into() {
                builder = builder.with_span_id(SpanId::from_bytes(bytes));
            }
        } else {
            warn!(
                span_id_len = span_id.len(),
                "invalid span_id length, expected 8 bytes"
            );
        }

        let mut sdk_span = if let Some(parent) = parent {
            builder.start_with_context(&self.tracer, &parent)
        } else {
            builder.start(&self.tracer)
        };

        if let Some(status) = status {
            if status.code == 2 {
                sdk_span.set_status(OtelStatus::error(status.message));
            } else if status.code == 1 {
                sdk_span.set_status(OtelStatus::Ok);
            }
        }

        sdk_span.end_with_timestamp(unix_nano_to_time(end_time_unix_nano));
        debug!("trace span submitted to otel sdk");
    }
}

impl Drop for OtlpTraceExporter {
    fn drop(&mut self) {
        if let Err(err) = self.provider.force_flush() {
            warn!("otlp trace exporter force_flush failed: {}", err);
        } else {
            debug!("otlp trace exporter force_flush succeeded");
        }
    }
}

fn to_span_kind(kind: i32) -> SpanKind {
    match kind {
        2 => SpanKind::Server,
        3 => SpanKind::Client,
        4 => SpanKind::Producer,
        5 => SpanKind::Consumer,
        _ => SpanKind::Internal,
    }
}

fn unix_nano_to_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(value)
}

fn build_parent_context(span: &SpanData) -> Option<Context> {
    if span.trace_id.len() != 16 || span.parent_span_id.len() != 8 {
        return None;
    }
    let trace_id = TraceId::from_bytes(span.trace_id.as_slice().try_into().ok()?);
    let span_id = SpanId::from_bytes(span.parent_span_id.as_slice().try_into().ok()?);
    let span_context = SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    );
    Some(Context::new().with_remote_span_context(span_context))
}
