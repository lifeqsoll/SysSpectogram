//! Where things live. Everything can be overridden with environment variables.
//!
//! Resolution order for the project root:
//! 1. SYSSPECTOGRAM_HOME
//! 2. the source checkout this binary was built in (if it sits inside one)
//! 3. user data dir (~/.local/share/sysspectogram)
//! 4. the system-installed state directory (/var/lib/sysspectogram)

use std::path::{Path, PathBuf};

const INSTALLED_ROOT: &str = "/var/lib/sysspectogram";
const INSTALLED_PYTHON: &str = "/opt/sysspectogram/venv/bin/python";

/// A source checkout contains both the default config and the Python package.
pub fn is_checkout(dir: &Path) -> bool {
    dir.join("configs").join("default.yaml").is_file()
        && dir.join("sysspectogram").join("__init__.py").is_file()
}

/// Walk up from the running binary to find the checkout it was built from.
fn dev_checkout() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.ancestors()
        .skip(1)
        .find(|dir| is_checkout(dir))
        .map(Path::to_path_buf)
}

/// Writable home for packaged installs.
pub fn user_data_root() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("sysspectogram");
    }
    dirs_next_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
        .join("sysspectogram")
}

fn dirs_next_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Project root: env override, else the source checkout, else user data, else system dir.
pub fn root() -> PathBuf {
    if let Some(home) = std::env::var_os("SYSSPECTOGRAM_HOME") {
        return PathBuf::from(home);
    }
    if let Some(checkout) = dev_checkout() {
        return checkout;
    }
    let user = user_data_root();
    if user.join(".venv").join("bin").join("python").is_file()
        || user.join("configs").join("default.yaml").is_file()
    {
        return user;
    }
    let system = PathBuf::from(INSTALLED_ROOT);
    if system.join("configs").join("default.yaml").is_file()
        || Path::new(INSTALLED_PYTHON).is_file()
    {
        return system;
    }
    user
}

/// Python for the CLI.
pub fn python() -> PathBuf {
    if let Some(p) = std::env::var_os("SYSSPECTOGRAM_PYTHON") {
        return PathBuf::from(p);
    }
    let home_venv = root().join(".venv").join("bin").join("python");
    if home_venv.exists() {
        return home_venv;
    }
    let installed = PathBuf::from(INSTALLED_PYTHON);
    if installed.exists() {
        installed
    } else {
        PathBuf::from("python3")
    }
}

/// Whether the Python package is importable with our resolved interpreter.
pub fn stack_ready() -> bool {
    let py = python();
    let status = std::process::Command::new(&py)
        .args(["-c", "import sysspectogram"])
        .env("SYSSPECTOGRAM_HOME", root())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    matches!(status, Ok(s) if s.success())
}
