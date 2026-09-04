use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry::logs::{
    AnyValue as OtelAnyValue, LogRecord, Logger, LoggerProvider, Severity as OtelSeverity,
};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
use opentelemetry_sdk::logs::log_processor_with_async_runtime::BatchLogProcessor;
use opentelemetry_sdk::logs::{BatchConfigBuilder, SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::runtime;
use serde_yaml::Value;
use tracing::{debug, info, warn};

use crate::internal::observability::sdk::{get_bool, get_trimmed, parse_headers, OTelSdkContext};

#[derive(Debug, Clone)]
pub struct OtlpLogRecord {
    pub timestamp_unix_nano: u64,
    pub severity_number: SeverityNumber,
    pub severity_text: String,
    pub body: String,
    pub attributes: Vec<KeyValue>,
}

#[derive(Clone)]
pub struct OtlpLogExporter {
    logger: Arc<SdkLogger>,
    provider: Arc<SdkLoggerProvider>,
}

impl OtlpLogExporter {
    pub fn from_observability(observability: Option<&Value>) -> Option<Arc<Self>> {
        let map = observability?.as_mapping()?;
        let enabled = get_bool(map, "otlp_logs_enabled").unwrap_or(false);
        if !enabled {
            debug!("otlp log exporter disabled by config");
            return None;
        }
        let endpoint = get_trimmed(map, "otlp_logs_endpoint")?.to_string();
        let sdk = OTelSdkContext::from_observability(map);
        let headers = parse_headers(map);

        let mut exporter_builder = opentelemetry_otlp::LogExporter::builder()
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
                    "failed to build otlp log exporter: {}",
                    err
                );
                return None;
            }
        };
        let batch_config = BatchConfigBuilder::default()
            .with_max_queue_size(8192)
            .with_max_export_batch_size(512)
            .with_scheduled_delay(Duration::from_millis(1000))
            .build();
        let processor = BatchLogProcessor::builder(exporter, runtime::Tokio)
            .with_batch_config(batch_config)
            .build();
        let provider = SdkLoggerProvider::builder()
            .with_resource(sdk.resource)
            .with_log_processor(processor)
            .build();
        let logger = provider.logger("microclaw.observability.logs");
        info!(
            endpoint = %endpoint,
            service_name = %sdk.service_name,
            "otlp log exporter initialized"
        );

        Some(Arc::new(Self {
            logger: Arc::new(logger),
            provider: Arc::new(provider),
        }))
    }

    pub fn send_log(&self, record: OtlpLogRecord) {
        let mut log_record = self.logger.create_log_record();
        log_record.set_timestamp(unix_nano_to_time(record.timestamp_unix_nano));
        log_record.set_observed_timestamp(SystemTime::now());
        log_record.set_severity_number(to_otel_severity(record.severity_number));
        log_record.set_body(OtelAnyValue::from(record.body));
        if !record.severity_text.is_empty() {
            log_record.add_attribute("severity.text", record.severity_text);
        }
        for kv in record.attributes {
            log_record.add_attribute(kv.key, kv.value.to_string());
        }
        self.logger.emit(log_record);
        debug!("log record submitted to otel sdk");
    }

    pub fn logger_provider(&self) -> Arc<SdkLoggerProvider> {
        self.provider.clone()
    }
}

impl Drop for OtlpLogExporter {
    fn drop(&mut self) {
        if let Err(err) = self.provider.force_flush() {
            warn!("otlp log exporter force_flush failed: {}", err);
        } else {
            debug!("otlp log exporter force_flush succeeded");
        }
    }
}

fn to_otel_severity(severity: SeverityNumber) -> OtelSeverity {
    match severity as i32 {
        1..=4 => OtelSeverity::Trace,
        5..=8 => OtelSeverity::Debug,
        9..=12 => OtelSeverity::Info,
        13..=16 => OtelSeverity::Warn,
        17..=20 => OtelSeverity::Error,
        21..=24 => OtelSeverity::Fatal,
        _ => OtelSeverity::Info,
    }
}

fn unix_nano_to_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(value)
}
