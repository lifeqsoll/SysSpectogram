//! Direct Telegram notify via `curl` (no extra crate). Root-only env file.

use std::fs;
use std::path::Path;
use std::process::Command;

pub fn load_kv_env(path: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(path).ok()?;
    let mut token = None;
    let mut chat = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match k.trim() {
            "TELEGRAM_BOT_TOKEN" | "BOT_TOKEN" => token = Some(v),
            "TELEGRAM_CHAT_ID" | "CHAT_ID" => chat = Some(v),
            _ => {}
        }
    }
    match (token, chat) {
        (Some(t), Some(c)) if !t.is_empty() && !c.is_empty() => Some((t, c)),
        _ => None,
    }
}

/// Fire-and-forget critical message. Returns Ok(true) if curl ran.
pub fn send_critical(text: &str, env_path: &Path) -> Result<bool, String> {
    let Some((token, chat)) = load_kv_env(env_path) else {
        return Ok(false);
    };
    if Command::new("curl").arg("--version").output().is_err() {
        return Err("curl not found".into());
    }
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let payload = serde_json::json!({ "chat_id": chat, "text": text });
    let body = payload.to_string();
    let st = Command::new("curl")
        .args([
            "-sS",
            "-m",
            "8",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &url,
        ])
        .status()
        .map_err(|e| e.to_string())?;
    Ok(st.success())
}
