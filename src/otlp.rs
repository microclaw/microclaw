use std::sync::Arc;

use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{
    metric, number_data_point, AggregationTemporality, Gauge, Metric, NumberDataPoint, Sum,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::metrics::v1::{ResourceMetrics, ScopeMetrics};
use prost::Message;

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
    pub active_sessions: i64,
}

#[derive(Clone)]
pub struct OtlpExporter {
    endpoint: String,
    headers: Vec<(String, String)>,
    service_name: String,
    client: reqwest::Client,
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
        Some(Arc::new(Self {
            endpoint,
            headers,
            service_name,
            client: reqwest::Client::new(),
        }))
    }

    pub async fn export_metrics(&self, snapshot: OtlpMetricSnapshot) -> Result<(), String> {
        let payload = build_metrics_payload(&self.service_name, snapshot)
            .encode_to_vec();
        let mut req = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/x-protobuf")
            .body(payload);
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("otlp export failed: {}", resp.status()));
        }
        Ok(())
    }
}

fn build_metrics_payload(service_name: &str, s: OtlpMetricSnapshot) -> ExportMetricsServiceRequest {
    let ts = s.timestamp_unix_nano;
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
        sum_metric("http_requests", "Total HTTP requests", s.http_requests, ts),
        sum_metric("llm_completions", "Total LLM completions", s.llm_completions, ts),
        sum_metric("llm_input_tokens", "Total input tokens", s.llm_input_tokens, ts),
        sum_metric("llm_output_tokens", "Total output tokens", s.llm_output_tokens, ts),
        sum_metric("tool_executions", "Total tool executions", s.tool_executions, ts),
        sum_metric("mcp_calls", "Total MCP calls", s.mcp_calls, ts),
        gauge_metric("active_sessions", "Current active sessions", s.active_sessions, ts),
    ];
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: resource.attributes,
                dropped_attributes_count: 0,
            }),
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

fn sum_metric(name: &str, desc: &str, value: i64, ts: u64) -> Metric {
    Metric {
        name: format!("microclaw_{}", name),
        description: desc.to_string(),
        unit: "1".to_string(),
        metadata: Vec::new(),
        data: Some(metric::Data::Sum(Sum {
            data_points: vec![NumberDataPoint {
                attributes: Vec::new(),
                start_time_unix_nano: ts,
                time_unix_nano: ts,
                exemplars: Vec::new(),
                flags: 0,
                value: Some(number_data_point::Value::AsInt(value.max(0))),
            }],
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        })),
    }
}

fn gauge_metric(name: &str, desc: &str, value: i64, ts: u64) -> Metric {
    Metric {
        name: format!("microclaw_{}", name),
        description: desc.to_string(),
        unit: "1".to_string(),
        metadata: Vec::new(),
        data: Some(metric::Data::Gauge(Gauge {
            data_points: vec![NumberDataPoint {
                attributes: Vec::new(),
                start_time_unix_nano: ts,
                time_unix_nano: ts,
                exemplars: Vec::new(),
                flags: 0,
                value: Some(number_data_point::Value::AsInt(value.max(0))),
            }],
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
            OtlpMetricSnapshot {
                timestamp_unix_nano: 1_700_000_000_000_000_000,
                http_requests: 10,
                llm_completions: 5,
                llm_input_tokens: 100,
                llm_output_tokens: 40,
                tool_executions: 3,
                mcp_calls: 1,
                active_sessions: 2,
            },
        );
        assert_eq!(payload.resource_metrics.len(), 1);
        let metrics = &payload.resource_metrics[0].scope_metrics[0].metrics;
        assert!(!metrics.is_empty());
        assert!(metrics.iter().any(|m| m.name == "microclaw_http_requests"));
    }
}
