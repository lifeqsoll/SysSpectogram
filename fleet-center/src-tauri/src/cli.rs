//! Bridge to `python -m sysspectogram ...`. Arguments are passed as an array, never
//! through a shell. Output is plain JSON.

use std::process::Command;

use serde_json::Value;

use crate::paths;

fn base_command() -> Command {
    let root = paths::root();
    let mut cmd = Command::new(paths::python());
    cmd.arg("-m")
        .arg("sysspectogram")
        .current_dir(&root)
        .env("SYSSPECTOGRAM_HOME", &root);
    cmd
}

/// Run a CLI command and parse its stdout as JSON.
pub fn run_json(args: &[&str]) -> Result<Value, String> {
    run_json_env(args, &[])
}

/// Like `run_json`, with extra process env (e.g. SYSSPECTOGRAM_DEVICE_TOKEN).
pub fn run_json_env(args: &[&str], extra_env: &[(&str, &str)]) -> Result<Value, String> {
    let mut cmd = base_command();
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let output = cmd
        .args(args)
        .output()
        .map_err(|e| format!("cannot start python: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let detail = stderr.trim();
        let detail = if detail.is_empty() {
            stdout.trim()
        } else {
            detail
        };
        return Err(format!(
            "sysspectogram {} failed: {}",
            args.join(" "),
            detail
        ));
    }
    if let Ok(v) = serde_json::from_str::<Value>(stdout.trim()) {
        return Ok(v);
    }
    if let Some(start) = stdout.rfind('{') {
        if let Ok(v) = serde_json::from_str::<Value>(stdout[start..].trim()) {
            return Ok(v);
        }
    }
    Err(format!(
        "bad JSON from CLI: {} (stdout head: {:?})",
        serde_json::from_str::<Value>(stdout.trim())
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "empty".into()),
        stdout.chars().take(180).collect::<String>()
    ))
}
