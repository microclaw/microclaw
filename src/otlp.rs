use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{
    metric, number_data_point, AggregationTemporality, Gauge, Metric, NumberDataPoint, Sum,
};
use opentelemetry_proto::tonic::metrics::v1::{ResourceMetrics, ScopeMetrics};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use tokio::sync::mpsc;

use crate::config::Config;

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
pub struct OtlpExporter {
    tx: mpsc::Sender<OtlpMetricSnapshot>,
}

struct OtlpWorkerConfig {
    endpoint: String,
    headers: Vec<(String, String)>,
    service_name: String,
    batch_size: usize,
    batch_max_delay: Duration,
    retry_max_attempts: usize,
    retry_base_ms: u64,
    retry_max_ms: u64,
}

impl OtlpExporter {
    pub fn from_config(config: &Config) -> Option<Arc<Self>> {
        let map = config.channels.get("observability")?.as_mapping()?;
        let enabled = map
            .get(serde_yaml::Value::String("otlp_enabled".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let endpoint = map
            .get(serde_yaml::Value::String("otlp_endpoint".to_string()))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())?
            .to_string();
        let service_name = map
            .get(serde_yaml::Value::String("service_name".to_string()))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "microclaw".to_string());
        let queue_capacity = map
            .get(serde_yaml::Value::String("otlp_queue_capacity".to_string()))
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(8, 100_000) as usize)
            .unwrap_or(256);
        let retry_max_attempts = map
            .get(serde_yaml::Value::String(
                "otlp_retry_max_attempts".to_string(),
            ))
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 10) as usize)
            .unwrap_or(3);
        let batch_size = map
            .get(serde_yaml::Value::String("otlp_batch_size".to_string()))
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 1024) as usize)
            .unwrap_or(32);
        let batch_max_delay = map
            .get(serde_yaml::Value::String(
                "otlp_batch_max_delay_ms".to_string(),
            ))
            .and_then(|v| v.as_u64())
            .map(|n| Duration::from_millis(n.clamp(20, 30_000)))
            .unwrap_or_else(|| Duration::from_millis(1000));
        let retry_base_ms = map
            .get(serde_yaml::Value::String("otlp_retry_base_ms".to_string()))
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(50, 60_000))
            .unwrap_or(500);
        let retry_max_ms_raw = map
            .get(serde_yaml::Value::String("otlp_retry_max_ms".to_string()))
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(100, 600_000))
            .unwrap_or(8_000);
        let (retry_base_ms, retry_max_ms) = normalize_retry_window(retry_base_ms, retry_max_ms_raw);

        let mut headers = Vec::new();
        if let Some(hmap) = map
            .get(serde_yaml::Value::String("otlp_headers".to_string()))
            .and_then(|v| v.as_mapping())
        {
            for (k, v) in hmap {
                let Some(key) = k.as_str() else {
                    continue;
                };
                let Some(val) = v.as_str() else {
                    continue;
                };
                headers.push((key.to_string(), val.to_string()));
            }
        }

        let (tx, rx) = mpsc::channel::<OtlpMetricSnapshot>(queue_capacity);
        let client = reqwest::Client::new();
        let worker_cfg = OtlpWorkerConfig {
            endpoint,
            headers,
            service_name,
            batch_size,
            batch_max_delay,
            retry_max_attempts,
            retry_base_ms,
            retry_max_ms,
        };
        tokio::spawn(async move { run_worker(rx, client, worker_cfg).await });
        Some(Arc::new(Self { tx }))
    }

    pub fn enqueue_metrics(&self, snapshot: OtlpMetricSnapshot) -> Result<(), String> {
        self.tx
            .try_send(snapshot)
            .map_err(|e| format!("otlp queue full or closed: {e}"))
    }
}

fn normalize_retry_window(retry_base_ms: u64, retry_max_ms: u64) -> (u64, u64) {
    let normalized_max = retry_max_ms.max(retry_base_ms);
    (retry_base_ms, normalized_max)
}

async fn run_worker(
    mut rx: mpsc::Receiver<OtlpMetricSnapshot>,
    client: reqwest::Client,
    cfg: OtlpWorkerConfig,
) {
    while let Some(snapshot) = rx.recv().await {
        let mut batch = Vec::with_capacity(cfg.batch_size);
        batch.push(snapshot);
        let window_start = tokio::time::Instant::now();
        while batch.len() < cfg.batch_size {
            let Some(remaining) = cfg.batch_max_delay.checked_sub(window_start.elapsed()) else {
                break;
            };
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(item)) => batch.push(item),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        let mut attempt = 0usize;
        let mut backoff = cfg.retry_base_ms;
        loop {
            attempt += 1;
            let result = send_once(
                &client,
                &cfg.endpoint,
                &cfg.headers,
                &cfg.service_name,
                &batch,
            )
            .await;
            match result {
                Ok(_) => break,
                Err(err) => {
                    if attempt >= cfg.retry_max_attempts {
                        tracing::warn!("otlp export dropped after retries: {}", err);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    backoff = (backoff.saturating_mul(2)).min(cfg.retry_max_ms);
                }
            }
        }
    }
}

async fn send_once(
    client: &reqwest::Client,
    endpoint: &str,
    headers: &[(String, String)],
    service_name: &str,
    batch: &[OtlpMetricSnapshot],
) -> Result<(), String> {
    let payload = build_metrics_payload(service_name, batch).encode_to_vec();
    let mut req = client
        .post(endpoint)
        .header("content-type", "application/x-protobuf")
        .body(payload);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("otlp export failed: {}", resp.status()));
    }
    Ok(())
}

fn build_metrics_payload(
    service_name: &str,
    snapshots: &[OtlpMetricSnapshot],
) -> ExportMetricsServiceRequest {
    let points = if snapshots.is_empty() {
        vec![OtlpMetricSnapshot {
            timestamp_unix_nano: 0,
            http_requests: 0,
            llm_completions: 0,
            llm_input_tokens: 0,
            llm_output_tokens: 0,
            tool_executions: 0,
            mcp_calls: 0,
            mcp_rate_limited_rejections: 0,
            mcp_bulkhead_rejections: 0,
            mcp_circuit_open_rejections: 0,
            active_sessions: 0,
        }]
    } else {
        snapshots.to_vec()
    };
    let start_ts = points
        .first()
        .map(|p| p.timestamp_unix_nano)
        .unwrap_or_default();
    let resource = Resource {
        attributes: vec![KeyValue {
            key: "service.name".to_string(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(service_name.to_string())),
            }),
        }],
        dropped_attributes_count: 0,
    };
    let metrics = vec![
        sum_metric(
            "http_requests",
            "Total HTTP requests",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.http_requests))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "llm_completions",
            "Total LLM completions",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.llm_completions))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "llm_input_tokens",
            "Total input tokens",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.llm_input_tokens))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "llm_output_tokens",
            "Total output tokens",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.llm_output_tokens))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "tool_executions",
            "Total tool executions",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.tool_executions))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "mcp_calls",
            "Total MCP calls",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.mcp_calls))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "mcp_rate_limited_rejections",
            "Total MCP rate-limited rejections",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.mcp_rate_limited_rejections))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "mcp_bulkhead_rejections",
            "Total MCP bulkhead rejections",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.mcp_bulkhead_rejections))
                .collect(),
            start_ts,
        ),
        sum_metric(
            "mcp_circuit_open_rejections",
            "Total MCP circuit-open rejections",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.mcp_circuit_open_rejections))
                .collect(),
            start_ts,
        ),
        gauge_metric(
            "active_sessions",
            "Current active sessions",
            points
                .iter()
                .map(|p| (p.timestamp_unix_nano, p.active_sessions))
                .collect(),
            start_ts,
        ),
    ];
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(resource),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "microclaw.web".to_string(),
                    version: "1".to_string(),
                    attributes: Vec::new(),
                    dropped_attributes_count: 0,
                }),
                metrics,
                schema_url: "".to_string(),
            }],
            schema_url: "".to_string(),
        }],
    }
}

fn sum_metric(name: &str, desc: &str, values: Vec<(u64, i64)>, start_ts: u64) -> Metric {
    Metric {
        name: format!("microclaw_{}", name),
        description: desc.to_string(),
        unit: "1".to_string(),
        metadata: Vec::new(),
        data: Some(metric::Data::Sum(Sum {
            data_points: values
                .into_iter()
                .map(|(ts, value)| NumberDataPoint {
                    attributes: Vec::new(),
                    start_time_unix_nano: start_ts,
                    time_unix_nano: ts,
                    exemplars: Vec::new(),
                    flags: 0,
                    value: Some(number_data_point::Value::AsInt(value.max(0))),
                })
                .collect(),
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        })),
    }
}

fn gauge_metric(name: &str, desc: &str, values: Vec<(u64, i64)>, start_ts: u64) -> Metric {
    Metric {
        name: format!("microclaw_{}", name),
        description: desc.to_string(),
        unit: "1".to_string(),
        metadata: Vec::new(),
        data: Some(metric::Data::Gauge(Gauge {
            data_points: values
                .into_iter()
                .map(|(ts, value)| NumberDataPoint {
                    attributes: Vec::new(),
                    start_time_unix_nano: start_ts,
                    time_unix_nano: ts,
                    exemplars: Vec::new(),
                    flags: 0,
                    value: Some(number_data_point::Value::AsInt(value.max(0))),
                })
                .collect(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_otlp_payload() {
        let payload = build_metrics_payload(
            "microclaw-test",
            &[OtlpMetricSnapshot {
                timestamp_unix_nano: 1_700_000_000_000_000_000,
                http_requests: 10,
                llm_completions: 5,
                llm_input_tokens: 100,
                llm_output_tokens: 40,
                tool_executions: 3,
                mcp_calls: 1,
                mcp_rate_limited_rejections: 2,
                mcp_bulkhead_rejections: 1,
                mcp_circuit_open_rejections: 0,
                active_sessions: 2,
            }],
        );
        assert_eq!(payload.resource_metrics.len(), 1);
        let metrics = &payload.resource_metrics[0].scope_metrics[0].metrics;
        assert!(!metrics.is_empty());
        assert!(metrics.iter().any(|m| m.name == "microclaw_http_requests"));
        assert!(metrics
            .iter()
            .any(|m| m.name == "microclaw_mcp_rate_limited_rejections"));
        assert!(metrics
            .iter()
            .any(|m| m.name == "microclaw_mcp_bulkhead_rejections"));
        assert!(metrics
            .iter()
            .any(|m| m.name == "microclaw_mcp_circuit_open_rejections"));
    }

    #[test]
    fn test_normalize_retry_window_keeps_valid_range() {
        let (base, max) = normalize_retry_window(500, 8_000);
        assert_eq!(base, 500);
        assert_eq!(max, 8_000);
    }

    #[test]
    fn test_normalize_retry_window_raises_max_when_needed() {
        let (base, max) = normalize_retry_window(30_000, 100);
        assert_eq!(base, 30_000);
        assert_eq!(max, 30_000);
    }
}
