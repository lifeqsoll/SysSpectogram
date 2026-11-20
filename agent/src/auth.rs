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

/// Constant-time check of a hex HMAC-SHA256 over `canonical`.
///
/// Wrong length, non-hex digits, and a bad tag all return false.
pub fn verify_hex(secret: &str, canonical: &str, hex_mac: &str) -> bool {
    let Some(tag) = decode_hex(hex_mac) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(canonical.as_bytes());
    mac.verify_slice(&tag).is_ok()
}

fn decode_hex(hex_mac: &str) -> Option<[u8; 32]> {
    if hex_mac.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex_mac.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_hex_accepts_sign_hex_and_rejects_a_flipped_tag() {
        let secret = "test-secret";
        let canon = "v1|stop|1700000000|42";
        let good = sign_hex(secret, canon);
        assert!(verify_hex(secret, canon, &good));
        let mut flipped = good.clone().into_bytes();
        flipped[0] = if flipped[0] == b'0' { b'1' } else { b'0' };
        let flipped = String::from_utf8(flipped).unwrap();
        assert!(!verify_hex(secret, canon, &flipped));
        assert!(!verify_hex(secret, canon, "abcd"));
        assert!(!verify_hex("other", canon, &good));
    }
}
