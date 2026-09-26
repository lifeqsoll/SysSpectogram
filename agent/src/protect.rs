//! Agent self-protect helpers: install path checks + CLEAN_SHUTDOWN.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::emit::Emitter;
use crate::types::AgentAlert;

/// Preferred production install location (root-writable only).
pub const PREFERRED_BIN: &str = "/usr/local/sbin/sysspectogram-agent";

#[derive(Debug, Clone)]
pub struct InstallCheck {
    pub path: PathBuf,
    pub ok: bool,
    pub warnings: Vec<String>,
}

/// Check that the running binary is not world-writable and prefer root ownership.
pub fn check_install(exe: &Path) -> InstallCheck {
    let mut warnings = Vec::new();
    let mut ok = true;
    let path = exe.to_path_buf();
    match fs::metadata(exe) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o002 != 0 {
                ok = false;
                warnings.push(format!("binary world-writable (mode={mode:o})"));
            }
            if meta.uid() != 0 {
                warnings.push(format!(
                    "binary uid={} (prefer root-owned under {PREFERRED_BIN})",
                    meta.uid()
                ));
            }
            if !exe.starts_with("/usr/local/sbin") && !exe.starts_with("/usr/sbin") {
                warnings.push(format!(
                    "path {} — production recommend {PREFERRED_BIN}",
                    exe.display()
                ));
            }
        }
        Err(e) => {
            ok = false;
            warnings.push(format!("cannot stat exe: {e}"));
        }
    }
    InstallCheck { path, ok, warnings }
}

pub fn resolve_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("sysspectogram-agent"))
}

pub fn check_unit_file(path: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    if !path.exists() {
        return warnings;
    }
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o002 != 0 {
                warnings.push(format!("unit {} world-writable", path.display()));
            }
            if meta.uid() != 0 {
                warnings.push(format!("unit {} not root-owned", path.display()));
            }
        }
        Err(e) => warnings.push(format!("unit stat failed: {e}")),
    }
    warnings
}

/// Emit CLEAN_SHUTDOWN so guard does not treat systemd stop as Dead-man.
pub fn emit_clean_shutdown(emitter: &Emitter, host_id: &str) -> io::Result<()> {
    let alert = AgentAlert::new(
        "agent_kirk_clean_shutdown",
        "info",
        "CLEAN_SHUTDOWN (SIGTERM) — intentional stop, not Dead-man",
        host_id,
    );
    emitter.emit_alert(&alert)
}
