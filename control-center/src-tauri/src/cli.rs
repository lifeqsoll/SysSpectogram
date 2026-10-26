//! Bridge to `python -m sysspectogram ...`. Arguments are passed as an array, never
//! through a shell. Output is plain JSON or line-streamed text.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;

use serde_json::Value;

use crate::paths;

fn base_command() -> Command {
    let root = paths::root();
    let mut cmd = Command::new(paths::python());
    // The CLI must see the same state directory as the guard it talks to.
    cmd.arg("-m")
        .arg("sysspectogram")
        .current_dir(&root)
        .env("SYSSPECTOGRAM_HOME", &root);
    cmd
}

/// Run a CLI command and parse its stdout as JSON.
pub fn run_json(args: &[&str]) -> Result<Value, String> {
    let output = base_command()
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
    // Prefer whole stdout; if pip/noise leaked, take the last JSON object.
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

/// Run a CLI command and return its stdout as text.
pub fn run_text(args: &[&str]) -> Result<String, String> {
    let output = base_command()
        .args(args)
        .output()
        .map_err(|e| format!("cannot start python: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Run a CLI command and forward each stdout/stderr line to `on_line(line, is_stderr)`.
/// Returns the exit code (-1 when killed by a signal).
pub fn run_streaming<F>(args: &[String], on_line: F) -> Result<i32, String>
where
    F: Fn(String, bool) + Send + Sync + 'static,
{
    let mut child = base_command()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start python: {e}"))?;

    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let on_line = Arc::new(on_line);

    let out_cb = Arc::clone(&on_line);
    let out_thread = thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            out_cb(line, false);
        }
    });
    let err_cb = Arc::clone(&on_line);
    let err_thread = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            err_cb(line, true);
        }
    });

    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    let _ = out_thread.join();
    let _ = err_thread.join();
    Ok(status.code().unwrap_or(-1))
}
