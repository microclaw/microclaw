#![allow(unused_imports)]

use super::*;

pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::test_support::env_lock()
}

pub fn test_config() -> Config {
    Config::test_defaults()
}

pub(crate) fn mapping_of(yaml: &str) -> serde_yaml::Mapping {
    serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .unwrap()
        .as_mapping()
        .unwrap()
        .clone()
}
