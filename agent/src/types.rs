//! Shared event / alert types (JSON contract with Python guard).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAlert {
    pub schema: String,
    pub kind: String,
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub host_id: String,
    pub ts: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Value>,
}

impl AgentAlert {
    pub fn new(
        rule_id: &str,
        severity: &str,
        message: impl Into<String>,
        host_id: &str,
    ) -> Self {
        Self {
            schema: "sysspectogram.agent.v1".into(),
            kind: "agent".into(),
            rule_id: rule_id.into(),
            severity: severity.into(),
            message: message.into(),
            host_id: host_id.into(),
            ts: now_unix(),
            pid: None,
            ppid: None,
            comm: None,
            path: None,
            extras: None,
        }
    }
}

pub fn now_unix() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub kind: EventKind,
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Exec,
    OpenSensitive,
    ConnectBurst,
}
