//! Ban orchestration via sysspectogram-helper Unix socket (same protocol as Python).

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn default_helper_sock() -> PathBuf {
    std::env::var_os("SYSSPECTOGRAM_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/sysspectogram/helper.sock"))
}

pub fn helper_available(path: Option<&Path>) -> bool {
    let p = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_helper_sock);
    p.exists()
}

fn call_helper(path: &Path, op: &str, args: Value, timeout_ms: u64) -> Result<Value, String> {
    let mut stream = UnixStream::connect(path).map_err(|e| format!("helper connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    let req = json!({"op": op, "args": args});
    let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("helper write: {e}"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Err(e) => return Err(format!("helper read: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first = text.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        return Err("empty helper reply".into());
    }
    serde_json::from_str(first).map_err(|e| format!("helper json: {e}"))
}

/// Request `ban.add` through the helper. Dry-run never contacts the socket.
pub fn ban_via_helper(
    ip: &str,
    ttl_sec: i64,
    dry_run: bool,
    socket: Option<&Path>,
) -> String {
    if dry_run {
        return format!("dry-run ban {ip} ttl={ttl_sec} backend=helper");
    }
    let path = socket
        .map(Path::to_path_buf)
        .unwrap_or_else(default_helper_sock);
    if !path.exists() {
        return "nft failed: no privileges (install helper and join group sysspectogram)".into();
    }
    match call_helper(
        &path,
        "ban.add",
        json!({"ip": ip, "ttl_sec": ttl_sec, "reason": "guard-core"}),
        5000,
    ) {
        Ok(reply) if reply.get("ok").and_then(|v| v.as_bool()) == Some(true) => {
            let data = reply.get("data").cloned().unwrap_or(json!({}));
            let ttl = data
                .get("ttl_sec")
                .and_then(|v| v.as_i64())
                .unwrap_or(ttl_sec);
            format!("banned {ip} ttl={ttl} backend=helper")
        }
        Ok(reply) => format!(
            "nft failed: {}",
            reply
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("helper error")
        ),
        Err(e) => format!("nft failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_ban_message() {
        let msg = ban_via_helper("203.0.113.9", 60, true, None);
        assert!(msg.contains("dry-run"));
        assert!(msg.contains("203.0.113.9"));
    }
}
