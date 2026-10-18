//! One-button start of the local stack.
//!
//! - The privileged helper is a systemd unit (installed once by scripts/install-helper.sh).
//!   It is started through `pkexec`, so polkit shows the password prompt. The app never
//!   holds root.
//! - The guard runs as a child of this app with `--dry-run`: it observes and never
//!   blocks. It stops when the app exits. Model path: `state/model.path` or
//!   `artifacts/live` when present; otherwise notorch (metrics + perimeter only).

use std::fs::{self, OpenOptions};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{helper, paths};

const HELPER_UNIT: &str = "sysspectogram-helper.service";
const HELPER_WAIT: Duration = Duration::from_secs(10);

#[derive(Default, Clone)]
pub struct Stack {
    guard: Arc<Mutex<Option<Child>>>,
}

fn step(ok: bool, message: impl Into<String>) -> Value {
    json!({ "ok": ok, "message": message.into() })
}

fn resolve_model(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let marker = root.join("state").join("model.path");
    if let Ok(raw) = fs::read_to_string(&marker) {
        let p = std::path::PathBuf::from(raw.trim());
        if p.is_dir() {
            return Some(p);
        }
        let rel = root.join(raw.trim());
        if rel.is_dir() {
            return Some(rel);
        }
    }
    let live = root.join("artifacts").join("live");
    if live.is_dir() && (live.join("cnn.onnx").is_file() || live.join("cnn.pt").is_file()) {
        return Some(live);
    }
    None
}

impl Stack {
    /// Returns the guard pid if our child is still alive. A dead child is forgotten.
    fn guard_pid(&self) -> Option<u32> {
        let mut slot = self.guard.lock().ok()?;
        let alive = match slot.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        };
        if alive {
            slot.as_ref().map(Child::id)
        } else {
            *slot = None;
            None
        }
    }

    pub fn status(&self) -> Value {
        let pid = self.guard_pid();
        json!({ "guard_running": pid.is_some(), "guard_pid": pid })
    }

    pub fn stop_guard(&self) {
        let Ok(mut slot) = self.guard.lock() else {
            return;
        };
        let Some(mut child) = slot.take() else {
            return;
        };
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
        let _ = fs::remove_file(paths::root().join("state").join("guard.pid"));
    }

    fn start_helper(&self) -> Value {
        if helper::request("status", json!({})).is_ok() {
            return step(true, "helper already running");
        }
        let out = Command::new("pkexec")
            .args(["systemctl", "start", HELPER_UNIT])
            .output();
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                return step(false, format!("cannot run pkexec (install polkit): {e}"));
            }
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return step(
                false,
                format!(
                    "helper did not start: {err}. If the unit is missing, run once: sudo scripts/install-helper.sh"
                ),
            );
        }
        let deadline = Instant::now() + HELPER_WAIT;
        while Instant::now() < deadline {
            if helper::request("status", json!({})).is_ok() {
                return step(true, "helper started");
            }
            thread::sleep(Duration::from_millis(300));
        }
        step(
            false,
            "helper started but not reachable: this session does not have the sysspectogram group yet. In the terminal run `newgrp sysspectogram`, then start the app from that same terminal (or log out and back in once)",
        )
    }

    fn start_guard(&self) -> Value {
        if let Some(pid) = self.guard_pid() {
            return step(true, format!("guard already running (pid {pid})"));
        }
        let root = paths::root();
        let log_path = root.join("state").join("guard-app.log");
        let log_open = fs::create_dir_all(root.join("state")).and_then(|_| {
            OpenOptions::new().create(true).append(true).open(&log_path)
        });
        let log = match log_open {
            Ok(f) => f,
            Err(e) => return step(false, format!("cannot open {}: {e}", log_path.display())),
        };
        let log_err = match log.try_clone() {
            Ok(f) => f,
            Err(e) => return step(false, format!("cannot clone log handle: {e}")),
        };
        let mut args: Vec<String> = vec![
            "-m".into(),
            "sysspectogram".into(),
            "guard".into(),
            "--dry-run".into(),
            "--telegram".into(),
        ];
        if let Some(model) = resolve_model(&root) {
            args.push("--model".into());
            args.push(model.display().to_string());
        }
        let mut path_env = std::env::var("PATH").unwrap_or_default();
        let home_bin = root.join("bin");
        if home_bin.is_dir() {
            path_env = format!("{}:{path_env}", home_bin.display());
        }
        let spawned = Command::new(paths::python())
            .args(&args)
            .current_dir(&root)
            .env("SYSSPECTOGRAM_HOME", &root)
            .env("PATH", &path_env)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn();
        match spawned {
            Ok(mut child) => {
                let pid = child.id();
                // Catch immediate crashes (import errors, missing unlock write, …).
                thread::sleep(Duration::from_millis(900));
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let tail = fs::read_to_string(&log_path)
                            .unwrap_or_default()
                            .lines()
                            .rev()
                            .take(12)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<Vec<_>>()
                            .join("\n");
                        return step(
                            false,
                            format!(
                                "guard exited immediately ({status}). Last log lines:\n{tail}"
                            ),
                        );
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return step(false, format!("cannot check guard pid {pid}: {e}"));
                    }
                }
                if let Ok(mut slot) = self.guard.lock() {
                    *slot = Some(child);
                }
                let model_note = resolve_model(&root)
                    .map(|p| format!("model={}", p.display()))
                    .unwrap_or_else(|| "model=notorch".into());
                step(
                    true,
                    format!(
                        "guard started (pid {pid}), dry-run, {model_note}; log: {}",
                        log_path.display()
                    ),
                )
            }
            Err(e) => step(false, format!("cannot start guard: {e}")),
        }
    }

    pub fn start_all(&self) -> Value {
        let helper_step = self.start_helper();
        let guard_step = self.start_guard();
        json!({ "helper": helper_step, "guard": guard_step })
    }
}
