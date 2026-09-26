//! HMAC-SHA256 for critical agent alerts (shared secret with guard).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub fn load_secret(path: &Path) -> Option<String> {
    if let Ok(v) = std::env::var("SYSSPECTOGRAM_AGENT_HMAC") {
        let t = v.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    let text = fs::read_to_string(path).ok()?;
    let t = text.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub fn canonical(
    rule_id: &str,
    severity: &str,
    ts: f64,
    pid: Option<u32>,
    path: &str,
    message: &str,
) -> String {
    let pid_s = pid.map(|p| p.to_string()).unwrap_or_default();
    let path = path.chars().take(256).collect::<String>();
    let message = message.chars().take(256).collect::<String>();
    format!("v1|{rule_id}|{severity}|{ts:.3}|{pid_s}|{path}|{message}")
}

pub fn sign_hex(secret: &str, canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(canonical.as_bytes());
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
