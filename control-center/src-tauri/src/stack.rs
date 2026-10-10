//! One-button start of the local stack.
//!
//! - The privileged helper is a systemd unit (installed once by scripts/install-helper.sh).
//!   It is started through `pkexec`, so polkit shows the password prompt. The app never
//!   holds root.
//! - The guard runs as a child of this app with `--dry-run`: it observes and never
//!   blocks. It stops when the app exits.

use std::fs::{self, OpenOptions};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{helper, paths};

/// Model directory for the app-started guard, relative to the project root.
const GUARD_MODEL: &str = "artifacts/real_v3";
const HELPER_UNIT: &str = "sysspectogram-helper.service";
const HELPER_WAIT: Duration = Duration::from_secs(10);

#[derive(Default, Clone)]
pub struct Stack {
    guard: Arc<Mutex<Option<Child>>>,
}

fn step(ok: bool, message: impl Into<String>) -> Value {
    json!({ "ok": ok, "message": message.into() })
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

    /// Stop the guard child, if we started one. Called on app exit and by `stop_guard`.
    ///
    /// SIGTERM first, so the guard runs its clean shutdown and removes `state/guard.pid`;
    /// SIGKILL only if it does not exit in time. Because this stop is deliberate, the
    /// pidfile is dropped here too, so the agent does not report `agent_kirk_guard_down`.
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
        // pkexec asks for the password through the desktop's polkit agent.
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
        if !root.join(GUARD_MODEL).exists() {
            return step(
                false,
                format!("model not found: {}", root.join(GUARD_MODEL).display()),
            );
        }
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
        let spawned = Command::new(paths::python())
            // --telegram: the bot/alerts only start when TELEGRAM_* in .env is set;
            // without it the guard just logs "telegram requested but ... missing".
            .args([
                "-m",
                "sysspectogram",
                "guard",
                "--model",
                GUARD_MODEL,
                "--dry-run",
                "--telegram",
            ])
            .current_dir(&root)
            .env("SYSSPECTOGRAM_HOME", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn();
        match spawned {
            Ok(child) => {
                let pid = child.id();
                if let Ok(mut slot) = self.guard.lock() {
                    *slot = Some(child);
                }
                step(
                    true,
                    format!("guard started (pid {pid}), dry-run; log: {}", log_path.display()),
                )
            }
            Err(e) => step(false, format!("cannot start guard: {e}")),
        }
    }

    /// Start everything the app needs. Each step reports on its own; a failed helper
    /// step does not stop the guard step.
    pub fn start_all(&self) -> Value {
        let helper_step = self.start_helper();
        let guard_step = self.start_guard();
        json!({ "helper": helper_step, "guard": guard_step })
    }
}
