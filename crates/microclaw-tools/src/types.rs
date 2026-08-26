use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingDirIsolation {
    Direct,
    Shared,
    Chat,
}

impl<'de> Deserialize<'de> for WorkingDirIsolation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum IsolationValue {
            Bool(bool),
            Str(String),
        }

        match IsolationValue::deserialize(deserializer)? {
            IsolationValue::Bool(v) => Ok(if v {
                WorkingDirIsolation::Chat
            } else {
                WorkingDirIsolation::Shared
            }),
            IsolationValue::Str(v) => match v.trim().to_ascii_lowercase().as_str() {
                "direct" | "root" => Ok(WorkingDirIsolation::Direct),
                "chat" | "isolated" | "true" => Ok(WorkingDirIsolation::Chat),
                "shared" | "false" => Ok(WorkingDirIsolation::Shared),
                other => Err(de::Error::custom(format!(
                    "invalid working_dir_isolation '{other}', expected direct/shared/chat or true/false"
                ))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WorkingDirIsolation;

    #[test]
    fn test_deserialize_bool_true_as_chat() {
        let v: WorkingDirIsolation = serde_json::from_str("true").unwrap();
        assert!(matches!(v, WorkingDirIsolation::Chat));
    }

    #[test]
    fn test_deserialize_bool_false_as_shared() {
        let v: WorkingDirIsolation = serde_json::from_str("false").unwrap();
        assert!(matches!(v, WorkingDirIsolation::Shared));
    }

    #[test]
    fn test_deserialize_chat_string() {
        let v: WorkingDirIsolation = serde_json::from_str("\"chat\"").unwrap();
        assert!(matches!(v, WorkingDirIsolation::Chat));
    }

    #[test]
    fn test_deserialize_direct_string() {
        let v: WorkingDirIsolation = serde_json::from_str("\"direct\"").unwrap();
        assert!(matches!(v, WorkingDirIsolation::Direct));
    }
}
