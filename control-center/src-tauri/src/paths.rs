//! Where things live. Everything can be overridden with environment variables,
//! which the tests and the lab use.
//!
//! Resolution order for the project root:
//! 1. SYSSPECTOGRAM_HOME
//! 2. the source checkout this binary was built in (if it sits inside one)
//! 3. the installed state directory

use std::path::{Path, PathBuf};

const INSTALLED_ROOT: &str = "/var/lib/sysspectogram"; // WorkingDirectory of the guard unit
const INSTALLED_PYTHON: &str = "/opt/sysspectogram/venv/bin/python";
const HELPER_SOCKET: &str = "/run/sysspectogram/helper.sock";

/// A source checkout contains both the default config and the Python package.
fn is_checkout(dir: &Path) -> bool {
    dir.join("configs").join("default.yaml").is_file()
        && dir.join("sysspectogram").join("__init__.py").is_file()
}

/// Walk up from the running binary to find the checkout it was built from.
fn dev_checkout() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.ancestors().skip(1).find(|dir| is_checkout(dir)).map(Path::to_path_buf)
}

/// Project root: env override, else the source checkout, else the installed state dir.
pub fn root() -> PathBuf {
    if let Some(home) = std::env::var_os("SYSSPECTOGRAM_HOME") {
        return PathBuf::from(home);
    }
    dev_checkout().unwrap_or_else(|| PathBuf::from(INSTALLED_ROOT))
}

/// Python for the CLI and the app-started guard: env override, the checkout's .venv,
/// the installed venv, then whatever `python3` is on PATH.
pub fn python() -> PathBuf {
    if let Some(p) = std::env::var_os("SYSSPECTOGRAM_PYTHON") {
        return PathBuf::from(p);
    }
    let checkout_venv = root().join(".venv").join("bin").join("python");
    if checkout_venv.exists() {
        return checkout_venv;
    }
    let installed = PathBuf::from(INSTALLED_PYTHON);
    if installed.exists() {
        installed
    } else {
        PathBuf::from("python3")
    }
}

pub fn helper_socket() -> PathBuf {
    std::env::var_os("SYSSPECTOGRAM_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(HELPER_SOCKET))
}

pub fn timeseries_db() -> PathBuf {
    root().join("state").join("timeseries.sqlite")
}

pub fn reports_dir() -> PathBuf {
    root().join("reports")
}
