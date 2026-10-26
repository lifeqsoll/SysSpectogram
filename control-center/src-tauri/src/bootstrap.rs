//! First-run install for AppImage / deb: download signed release assets from GitHub,
//! create a user venv, install the wheel and musl agent. No git clone (ADR 0005).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::paths;

/// Default GitHub repo for release assets.
const DEFAULT_REPO: &str = "lifeqsoll/SysSpectogram";

pub fn github_repo() -> String {
    std::env::var("SYSSPECTOGRAM_GITHUB_REPO").unwrap_or_else(|_| DEFAULT_REPO.into())
}

fn cache_dir(root: &Path) -> PathBuf {
    root.join("state").join("bootstrap-cache")
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let resp = ureq::get(url)
        .set("User-Agent", "SysSpectogram-ControlCenter/1.1")
        .call()
        .map_err(|e| format!("download {url}: {e}"))?;
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {url}: {e}"))?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = File::create(dest).map_err(|e| e.to_string())?;
    f.write_all(&buf).map_err(|e| e.to_string())?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_sha256(path: &Path, expected_line: &str) -> Result<(), String> {
    let got = sha256_file(path)?;
    let exp = expected_line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if got != exp {
        return Err(format!(
            "sha256 mismatch for {}: got {got}, expected {exp}",
            path.display()
        ));
    }
    Ok(())
}

fn try_minisign(pub_key: &Path, file: &Path, sig: &Path) -> Result<(), String> {
    let status = Command::new("minisign")
        .args([
            "-Vm",
            file.to_str().unwrap_or(""),
            "-p",
            pub_key.to_str().unwrap_or(""),
            "-x",
            sig.to_str().unwrap_or(""),
        ])
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("minisign verify failed ({s})")),
        Err(e) => Err(format!(
            "minisign not available ({e}); install minisign or rely on sha256 only"
        )),
    }
}

fn release_json(tag: &str) -> Result<Value, String> {
    let repo = github_repo();
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    let resp = ureq::get(&url)
        .set("User-Agent", "SysSpectogram-ControlCenter/1.1")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GitHub release {tag}: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("GitHub body: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("GitHub JSON: {e}"))
}

fn asset_url(release: &Value, name_substr: &str) -> Result<String, String> {
    let assets = release
        .get("assets")
        .and_then(Value::as_array)
        .ok_or("release has no assets")?;
    for a in assets {
        let name = a.get("name").and_then(Value::as_str).unwrap_or("");
        if name.contains(name_substr) {
            return a
                .get("browser_download_url")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("no url for {name}"));
        }
    }
    Err(format!("no release asset matching {name_substr:?}"))
}

/// Download and install the Python wheel + musl agent for `tag` (e.g. v1.1.0).
pub fn install_stack(tag: &str) -> Result<Value, String> {
    let root = paths::user_data_root();
    fs::create_dir_all(&root).map_err(|e| format!("mkdir {}: {e}", root.display()))?;
    // Point subsequent CLI/guard at this home.
    std::env::set_var("SYSSPECTOGRAM_HOME", &root);

    let cache = cache_dir(&root);
    fs::create_dir_all(&cache).map_err(|e| e.to_string())?;

    let steps: Vec<Value> = Vec::new();
    let mut log = steps;

    let release = release_json(tag)?;
    log.push(json!({"step": "release", "ok": true, "tag": tag}));

    // Prefer a wheel; fall back to sdist name patterns from python -m build.
    let wheel_url = asset_url(&release, ".whl")
        .or_else(|_| asset_url(&release, "sysspectogram-"))
        .map_err(|e| format!("{e}. Publish a wheel on the GitHub release."))?;
    let wheel_name = wheel_url
        .rsplit('/')
        .next()
        .unwrap_or("package.whl")
        .to_string();
    let wheel_path = cache.join(&wheel_name);
    download(&wheel_url, &wheel_path)?;
    log.push(json!({"step": "download_wheel", "ok": true, "file": wheel_name}));

    // Require SHA256SUMS + matching wheel line (hard-fail).
    let sums_url = asset_url(&release, "SHA256SUMS")
        .map_err(|_| "release missing SHA256SUMS (required)".to_string())?;
    let sums_path = cache.join("SHA256SUMS");
    download(&sums_url, &sums_path)?;
    let sums_text = fs::read_to_string(&sums_path).map_err(|e| e.to_string())?;
    let mut wheel_hashed = false;
    for line in sums_text.lines() {
        if line.contains(&wheel_name) {
            verify_sha256(&wheel_path, line)?;
            log.push(json!({"step": "sha256_wheel", "ok": true}));
            wheel_hashed = true;
            break;
        }
    }
    if !wheel_hashed {
        return Err(format!("SHA256SUMS has no entry for {wheel_name}"));
    }

    // Agent musl binary
    let agent_url = asset_url(&release, "sysspectogram-agent-x86_64-linux-musl")?;
    let agent_path = cache.join("sysspectogram-agent-x86_64-linux-musl");
    download(&agent_url, &agent_path)?;
    log.push(json!({"step": "download_agent", "ok": true}));

    let sum_url = asset_url(&release, "sysspectogram-agent-x86_64-linux-musl.sha256")
        .map_err(|_| "release missing agent .sha256 (required)".to_string())?;
    let sum_path = cache.join("agent.sha256");
    download(&sum_url, &sum_path)?;
    let line = fs::read_to_string(&sum_path).unwrap_or_default();
    verify_sha256(&agent_path, &line)?;
    log.push(json!({"step": "sha256_agent", "ok": true}));

    // Embedded minisign pubkey (ADR 0005); never trust a key from the release alone.
    let pub_path = cache.join("SysSpectogram.minisign.pub");
    fs::write(
        &pub_path,
        include_str!("../keys/SysSpectogram.minisign.pub"),
    )
    .map_err(|e| e.to_string())?;
    // If .minisig is published, verification is mandatory (install minisign if needed).
    if let Ok(sig_url) = asset_url(&release, "sysspectogram-agent-x86_64-linux-musl.minisig") {
        let sig_path = cache.join("agent.minisig");
        download(&sig_url, &sig_path)?;
        try_minisign(&pub_path, &agent_path, &sig_path)?;
        log.push(json!({"step": "minisign_agent", "ok": true}));
    }
    let wheel_sig_name = format!("{wheel_name}.minisig");
    if let Ok(sig_url) = asset_url(&release, &wheel_sig_name) {
        let sig_path = cache.join("wheel.minisig");
        download(&sig_url, &sig_path)?;
        try_minisign(&pub_path, &wheel_path, &sig_path)?;
        log.push(json!({"step": "minisign_wheel", "ok": true}));
    }

    // venv + pip install wheel (no heavy torch)
    let venv = root.join(".venv");
    if !venv.join("bin").join("python").is_file() {
        let st = Command::new("python3")
            .args(["-m", "venv", venv.to_str().unwrap_or("")])
            .status()
            .map_err(|e| format!("python3 -m venv: {e}"))?;
        if !st.success() {
            return Err(format!("venv failed: {st}"));
        }
        log.push(json!({"step": "venv", "ok": true}));
    }
    // Prefer `python -m pip` — venv/bin/pip shebang breaks if the tree was moved.
    let py = venv.join("bin").join("python");
    let st = Command::new(&py)
        .args([
            "-m",
            "pip",
            "install",
            "--upgrade",
            "pip",
            "wheel",
            wheel_path.to_str().unwrap_or(""),
        ])
        .status()
        .map_err(|e| format!("pip install: {e}"))?;
    if !st.success() {
        return Err(format!("pip install failed: {st}"));
    }
    log.push(json!({"step": "pip_install", "ok": true}));

    // Do not pull unsigned configs from raw.githubusercontent (supply-chain).
    // Wheel / package data must ship defaults; friend can copy from the release tarball.
    let cfg = root.join("configs");
    fs::create_dir_all(&cfg).ok();
    if !cfg.join("default.yaml").is_file() {
        log.push(json!({
            "step": "config_default.yaml",
            "ok": false,
            "detail": "missing configs/default.yaml after wheel install; unpack from release .tar.gz"
        }));
    }

    // Install agent binary into home bin/
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
    let agent_dest = bin_dir.join("sysspectogram-agent");
    fs::copy(&agent_path, &agent_dest).map_err(|e| format!("copy agent: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&agent_dest, fs::Permissions::from_mode(0o755)).ok();
    }
    log.push(json!({"step": "agent_bin", "ok": true, "path": agent_dest.display().to_string()}));

    // Write model/agent hint for guard
    let marker = root.join("state");
    fs::create_dir_all(&marker).ok();

    Ok(json!({
        "ok": true,
        "home": root.display().to_string(),
        "tag": tag,
        "stack_ready": paths::stack_ready(),
        "steps": log,
        "hint": "Next: Start protection. Helper (polkit) is optional — Install helper from Settings if you need system overlays.",
    }))
}

pub fn status() -> Value {
    let root = paths::root();
    let ready = paths::stack_ready();
    let helper_ok = crate::helper::request("status", json!({})).is_ok();
    json!({
        "ok": true,
        "dev_checkout": paths::is_dev_checkout(),
        "home": root.display().to_string(),
        "python": paths::python().display().to_string(),
        "stack_ready": ready,
        "helper_ok": helper_ok,
        "github_repo": github_repo(),
        "app_version": env!("CARGO_PKG_VERSION"),
    })
}
