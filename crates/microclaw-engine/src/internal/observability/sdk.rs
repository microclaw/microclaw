use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;
use serde_yaml::{Mapping, Value};

#[derive(Clone)]
pub struct OTelSdkContext {
    pub resource: Resource,
    pub service_name: String,
}

impl OTelSdkContext {
    pub fn from_observability(map: &Mapping) -> Self {
        let service_name = get_trimmed(map, "service_name")
            .unwrap_or("microclaw")
            .to_string();
        let resource = Resource::builder_empty()
            .with_attributes([KeyValue::new("service.name", service_name.clone())])
            .build();
        Self {
            resource,
            service_name,
        }
    }
}

pub fn get_trimmed<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

pub fn get_u64(map: &Mapping, key: &str) -> Option<u64> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_u64)
}

pub fn get_bool(map: &Mapping, key: &str) -> Option<bool> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_bool)
}

pub fn parse_headers(map: &Mapping) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(hmap) = map
        .get(Value::String("otlp_headers".to_string()))
        .and_then(Value::as_mapping)
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
    headers
}
