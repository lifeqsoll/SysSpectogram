//! Read-only views of the JSONL reports the guard and CLI write.

use std::fs;
use std::path::Path;

use serde_json::Value;

/// Reports the Control Center may show. Anything else is refused.
pub const LOG_WHITELIST: &[&str] = &[
    "alerts.jsonl",
    "agent.jsonl",
    "perimeter.jsonl",
    "incidents.jsonl",
];

pub fn read_jsonl(path: &Path, limit: usize) -> Result<Vec<Value>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut rows: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect();
    if rows.len() > limit {
        rows.drain(..rows.len() - limit);
    }
    Ok(rows)
}

pub fn safe_log_name(name: &str) -> Option<&'static str> {
    LOG_WHITELIST.iter().copied().find(|n| *n == name)
}
