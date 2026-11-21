//! Shared alert/metrics types for SysSpectogram guard control-plane.

pub mod auth;
pub mod flow;
pub mod metrics;
pub mod render;
pub mod response;
pub mod risk;
pub mod rules;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const SCHEMA_VERSION: &str = "1";

/// Perimeter-style alert envelope (JSON lines / golden fixtures).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub schema_version: String,
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub extras: HashMap<String, serde_json::Value>,
    pub ts: f64,
}

impl Alert {
    pub fn new(
        rule_id: impl Into<String>,
        severity: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            rule_id: rule_id.into(),
            severity: severity.into(),
            message: message.into(),
            ip: None,
            port: None,
            extras: HashMap::new(),
            ts: json_now_ts(),
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// Generic event record using the same field layout as [`Alert`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub schema_version: String,
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub extras: HashMap<String, serde_json::Value>,
    pub ts: f64,
}

impl From<Alert> for Event {
    fn from(a: Alert) -> Self {
        Self {
            schema_version: a.schema_version,
            rule_id: a.rule_id,
            severity: a.severity,
            message: a.message,
            ip: a.ip,
            port: a.port,
            extras: a.extras,
            ts: a.ts,
        }
    }
}

fn json_now_ts() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_json_contains_schema_version() {
        let a = Alert::new("bruteforce_ssh", "critical", "SSH brute-force");
        let j = a.to_json().expect("serialize");
        assert!(j.contains("\"schema_version\":\"1\"") || j.contains(r#""schema_version": "1""#));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v.get("schema_version").and_then(|x| x.as_str()), Some("1"));
    }

    #[test]
    fn alert_json_roundtrip() {
        let mut a = Alert::new("scan", "warn", "port scan");
        a.ip = Some("203.0.113.1".into());
        a.port = Some(22);
        a.extras
            .insert("fails".into(), serde_json::json!(9));
        a.ts = 1_700_000_000.5;

        let j = a.to_json().unwrap();
        let back = Alert::from_json(&j).unwrap();
        assert_eq!(a, back);
    }
}