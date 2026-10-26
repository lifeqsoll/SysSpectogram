//! SysSpectogram Control Center backend.
//!
//! The UI never touches root directly. It calls these commands, which read SQLite and
//! JSONL read-only, run the Python CLI with argument arrays, or talk to
//! sysspectogram-helper over its Unix socket (which applies polkit and an allowlist).

mod bootstrap;
mod cli;
mod files;
mod helper;
mod paths;
mod stack;
mod timeseries;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use stack::Stack;

const LIVE_METRICS: &[&str] = &[
    "host_risk",
    "host_score",
    "agent_score",
    "cpu_percent",
    "mem_percent",
    "net_bytes_recv_per_s",
    "net_bytes_sent_per_s",
];

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[tauri::command]
fn app_info() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "root": paths::root().display().to_string(),
        "helper_socket": paths::helper_socket().display().to_string(),
        "dev_checkout": paths::is_dev_checkout(),
        "stack_ready": paths::stack_ready(),
    })
}

#[tauri::command]
fn bootstrap_status() -> Value {
    bootstrap::status()
}

#[tauri::command]
fn bootstrap_install(tag: Option<String>) -> Result<Value, String> {
    let ver = env!("CARGO_PKG_VERSION");
    let tag = tag.unwrap_or_else(|| format!("v{ver}"));
    bootstrap::install_stack(&tag)
}

#[tauri::command]
fn helper_status() -> Result<Value, String> {
    helper::request("status", json!({}))
}

#[tauri::command]
fn guard_service(action: String) -> Result<Value, String> {
    if !matches!(action.as_str(), "start" | "stop" | "restart") {
        return Err(format!("bad service action {action:?}"));
    }
    helper::request("service", json!({ "action": action }))
}

#[tauri::command]
fn protect_status() -> Result<Value, String> {
    cli::run_json(&["protect", "status"])
}

#[tauri::command]
async fn protect_enable(stack: tauri::State<'_, Stack>) -> Result<Value, String> {
    // Hand off to systemd --user; stop the app-owned child to avoid dual guards.
    let stack = stack.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        stack.stop_guard();
        cli::run_json(&["protect", "enable"])
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn protect_disable() -> Result<Value, String> {
    cli::run_json(&["protect", "disable"])
}

#[tauri::command]
fn home_update(tag: Option<String>) -> Result<Value, String> {
    let t = tag.unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    cli::run_json(&["home", "update", "--tag", &t])
}

#[tauri::command]
fn home_seed_role(role: String) -> Result<Value, String> {
    cli::run_json(&["home", "seed-role", "--role", &role])
}

#[tauri::command]
fn home_seed_never_ban() -> Result<Value, String> {
    cli::run_json(&["home", "seed-never-ban"])
}

/// Fetch public IPv4 via ifconfig.me (fallbacks). For never-ban wizard.
#[tauri::command]
fn detect_public_ip() -> Result<Value, String> {
    const URLS: &[&str] = &[
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "https://icanhazip.com",
    ];
    let mut last = String::from("no response");
    for url in URLS {
        match ureq::get(url)
            .set("User-Agent", "SysSpectogram-CC/1.1")
            .timeout(std::time::Duration::from_secs(8))
            .call()
        {
            Ok(resp) => match resp.into_string() {
                Ok(body) => {
                    let ip = body.trim().to_string();
                    if ip.parse::<std::net::Ipv4Addr>().is_ok()
                        || ip.parse::<std::net::Ipv6Addr>().is_ok()
                    {
                        return Ok(json!({ "ok": true, "ip": ip, "source": url }));
                    }
                    last = format!("bad body from {url}: {ip}");
                }
                Err(e) => last = format!("{url}: {e}"),
            },
            Err(e) => last = format!("{url}: {e}"),
        }
    }
    Err(format!("detect public IP failed: {last}"))
}

/// Download signed `install-helper-from-release.sh`, verify minisign with the
/// embedded release pubkey, then feed the verified bytes to `pkexec … bash -s`
/// on stdin (never a user-writable path in pkexec argv — closes TOCTOU).
#[tauri::command]
fn install_helper_release(tag: Option<String>) -> Result<Value, String> {
    use std::fs;
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let t = tag.unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    let t = if t.starts_with('v') {
        t
    } else {
        format!("v{t}")
    };
    let repo = crate::bootstrap::github_repo();
    let api = format!("https://api.github.com/repos/{repo}/releases/tags/{t}");
    let release_text = ureq::get(&api)
        .set("User-Agent", "SysSpectogram-CC/1.1")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GitHub release {t}: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let release: Value =
        serde_json::from_str(&release_text).map_err(|e| format!("GitHub JSON: {e}"))?;
    let assets = release
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| "release has no assets".to_string())?;
    let mut script_url: Option<String> = None;
    let mut sig_url: Option<String> = None;
    for a in assets {
        let name = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let url = a
            .get("browser_download_url")
            .and_then(|x| x.as_str())
            .map(str::to_string);
        if name == "install-helper-from-release.sh" {
            script_url = url.clone();
        }
        if name == "install-helper-from-release.sh.minisig" {
            sig_url = url;
        }
    }
    let script_url = script_url
        .ok_or_else(|| "release missing install-helper-from-release.sh".to_string())?;
    let sig_url = sig_url.ok_or_else(|| {
        "release missing install-helper-from-release.sh.minisig (minisign required)".to_string()
    })?;

    let download = |url: &str| -> Result<Vec<u8>, String> {
        let mut reader = ureq::get(url)
            .set("User-Agent", "SysSpectogram-CC/1.1")
            .call()
            .map_err(|e| format!("download {url}: {e}"))?
            .into_reader();
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        Ok(buf)
    };
    let script_bytes = download(&script_url)?;
    let sig_bytes = download(&sig_url)?;

    // Staging under system temp (not $HOME): only used for minisign -Vm; pkexec never sees these paths.
    let stage = std::env::temp_dir().join(format!(
        "ss-helper-install-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let script_path = stage.join("install-helper-from-release.sh");
    let sig_path = stage.join("install-helper-from-release.sh.minisig");
    let pub_path = stage.join("SysSpectogram.minisign.pub");
    let cleanup = |dir: &std::path::Path| {
        let _ = fs::remove_dir_all(dir);
    };
    if let Err(e) = (|| -> Result<(), String> {
        fs::write(&script_path, &script_bytes).map_err(|e| e.to_string())?;
        fs::write(&sig_path, &sig_bytes).map_err(|e| e.to_string())?;
        fs::write(
            &pub_path,
            include_str!("../keys/SysSpectogram.minisign.pub"),
        )
        .map_err(|e| e.to_string())?;
        // Absolute path only — never PATH (same-UID fake minisign, H-02).
        let minisign = if std::path::Path::new("/usr/bin/minisign").is_file() {
            "/usr/bin/minisign"
        } else if std::path::Path::new("/usr/local/bin/minisign").is_file() {
            "/usr/local/bin/minisign"
        } else {
            return Err(
                "minisign not found at /usr/bin/minisign (or /usr/local/bin)".into(),
            );
        };
        let status = Command::new(minisign)
            .args([
                "-Vm",
                script_path.to_str().unwrap_or(""),
                "-p",
                pub_path.to_str().unwrap_or(""),
                "-x",
                sig_path.to_str().unwrap_or(""),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()
            .map_err(|e| {
                format!(
                    "minisign not available ({e}); install minisign to verify helper install script"
                )
            })?;
        if !status.success() {
            return Err("minisign verify failed for install-helper-from-release.sh".into());
        }
        Ok(())
    })() {
        cleanup(&stage);
        return Err(e);
    }
    cleanup(&stage);

    // GUI path: only pkexec (graphical polkit). Feed verified script on stdin
    // (`bash -s`) so a same-UID TOCTOU on any cache path cannot swap the payload.
    let pkexec = std::path::Path::new("/usr/bin/pkexec");
    let term_hint = format!(
        "Open a normal terminal (not this window) and run:\n  \
         curl -fsSL -o /tmp/ss-helper-install.sh https://github.com/{repo}/releases/download/{t}/install-helper-from-release.sh && \\\n  \
         curl -fsSL -o /tmp/ss-helper-install.sh.minisig https://github.com/{repo}/releases/download/{t}/install-helper-from-release.sh.minisig && \\\n  \
         minisign -Vm /tmp/ss-helper-install.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F' && \\\n  \
         sudo bash /tmp/ss-helper-install.sh {t}\n\
         Then log out/in so group sysspectogram applies."
    );
    if !pkexec.is_file() {
        return Err(format!("pkexec not found (install polkit). {term_hint}"));
    }
    let mut env_args: Vec<String> = vec!["env".into()];
    for key in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
    ] {
        if let Ok(v) = std::env::var(key) {
            env_args.push(format!("{key}={v}"));
        }
    }
    env_args.push("bash".into());
    env_args.push("-s".into());
    env_args.push("--".into());
    env_args.push(t.clone());

    // Refuse if any pkexec arg looks like a home/XDG path (defense in depth).
    let home = std::env::var("HOME").unwrap_or_default();
    for a in &env_args {
        if !home.is_empty() && a.starts_with(&home) {
            return Err("refusing pkexec argv under $HOME".into());
        }
        if a.contains("/.local/") || a.contains("/bootstrap-cache/") {
            return Err("refusing pkexec argv under user cache".into());
        }
    }

    let mut child = Command::new(pkexec)
        .args(&env_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("run helper install: {e}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "pkexec stdin unavailable".to_string())?;
        stdin
            .write_all(&script_bytes)
            .map_err(|e| format!("write install script to pkexec: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("run helper install: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        let blob = format!("{stderr}\n{stdout}");
        if blob.contains("/dev/tty")
            || blob.contains("authentication agent")
            || blob.contains("No such device")
            || (blob.contains("polkit") && blob.contains("not authorized"))
        {
            return Err(format!(
                "Cannot ask for admin password from this window (no polkit agent / TTY).\n{term_hint}"
            ));
        }
        return Err(format!("helper install failed: {blob}"));
    }
    Ok(json!({
        "ok": true,
        "tag": t,
        "detail": if stdout.is_empty() { stderr } else { stdout },
    }))
}

#[tauri::command]
fn bootstrap_preflight() -> Result<Value, String> {
    // Lightweight checks the UI can show before Install stack.
    use std::process::Command;
    let mut checks = Vec::new();
    let py3 = Command::new("python3")
        .args(["-c", "import sys; print(sys.version.split()[0])"])
        .output();
    match py3 {
        Ok(o) if o.status.success() => checks.push(json!({
            "id": "python3", "ok": true,
            "detail": String::from_utf8_lossy(&o.stdout).trim()
        })),
        _ => checks.push(json!({"id": "python3", "ok": false, "detail": "python3 missing"})),
    }
    let venv = Command::new("python3")
        .args(["-c", "import venv"])
        .status();
    checks.push(json!({
        "id": "venv",
        "ok": matches!(venv, Ok(s) if s.success()),
        "detail": "python3 -m venv"
    }));
    let minisign = Command::new("minisign").arg("-h").status();
    checks.push(json!({
        "id": "minisign",
        "ok": matches!(minisign, Ok(s) if s.success()),
        "detail": "optional for signature verify"
    }));
    let ready = checks.iter().all(|c| {
        c.get("id").and_then(|v| v.as_str()) == Some("minisign")
            || c.get("ok").and_then(|v| v.as_bool()) == Some(true)
    });
    Ok(json!({
        "ok": true,
        "ready": ready,
        "checks": checks,
        "hints": {
            "debian": "sudo apt install python3 python3-venv minisign",
            "arch": "sudo pacman -S python python-virtualenv minisign",
            "fedora": "sudo dnf install python3 python3-virtualenv minisign"
        }
    }))
}

#[tauri::command]
async fn start_all(stack: tauri::State<'_, Stack>) -> Result<Value, String> {
    let stack = stack.inner().clone();
    tauri::async_runtime::spawn_blocking(move || stack.start_all())
        .await
        .map_err(|e| format!("start task failed: {e}"))
}

#[tauri::command]
async fn stop_guard(stack: tauri::State<'_, Stack>) -> Result<(), String> {
    // Waiting for a clean guard shutdown can take a few seconds; keep the UI responsive.
    let stack = stack.inner().clone();
    tauri::async_runtime::spawn_blocking(move || stack.stop_guard())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn stack_status(stack: tauri::State<'_, Stack>) -> Value {
    stack.status()
}

#[tauri::command]
fn settings_export() -> Result<Value, String> {
    cli::run_json(&["settings", "export"])
}

#[tauri::command]
fn settings_apply(changes: Value) -> Result<Value, String> {
    // Always persist the home overlay first so Day-0 / old helpers cannot block onboarding.
    let raw = serde_json::to_string(&changes).unwrap_or_else(|_| "{}".into());
    let home = cli::run_json(&["home", "settings", "--changes", raw.as_str()]);

    // Old helpers only accept observe/enforce — remap newer modes for the socket call.
    let mut helper_changes = changes.clone();
    if let Some(obj) = helper_changes.as_object_mut() {
        if let Some(mode) = obj.get("response.mode").and_then(Value::as_str) {
            if matches!(mode, "shield" | "aggressive" | "isolate") {
                obj.insert("response.mode".into(), json!("enforce"));
            }
        }
    }

    match helper::request("settings.apply", json!({ "changes": helper_changes })) {
        Ok(v) => Ok(json!({
            "ok": true,
            "via": "helper",
            "helper": v,
            "home": home.ok(),
        })),
        Err(helper_err) => match home {
            Ok(v) => Ok(json!({
                "ok": true,
                "via": "user-settings",
                "helper_error": helper_err,
                "result": v,
            })),
            Err(home_err) => Err(format!("{helper_err}; home fallback: {home_err}")),
        },
    }
}

#[tauri::command]
fn settings_rollback() -> Result<Value, String> {
    helper::request("settings.rollback", json!({}))
}

#[tauri::command]
fn install_bundle(version: String, source: String) -> Result<Value, String> {
    helper::request(
        "bundle.install",
        json!({ "version": version, "source": source }),
    )
}

#[tauri::command]
fn timeseries_query(metric: String, range: String) -> Result<Vec<timeseries::Point>, String> {
    timeseries::query(&paths::timeseries_db(), &metric, &range, now_secs())
}

#[tauri::command]
fn timeseries_metrics() -> Result<Vec<String>, String> {
    timeseries::metrics(&paths::timeseries_db())
}

#[tauri::command]
fn incidents_list(limit: Option<usize>) -> Result<Vec<Value>, String> {
    files::read_jsonl(
        &paths::reports_dir().join("incidents.jsonl"),
        limit.unwrap_or(500),
    )
}

/// Re-correlate the alert/agent/perimeter logs into incidents, then return them.
/// Incidents are only written by `sysspectogram incidents list`, so the UI triggers it.
#[tauri::command]
async fn incidents_refresh(limit: Option<usize>) -> Result<Vec<Value>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        cli::run_text(&["incidents", "list"])?;
        files::read_jsonl(
            &paths::reports_dir().join("incidents.jsonl"),
            limit.unwrap_or(500),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Spectrogram PNG for one incident, rendered on demand from the timeseries store.
#[tauri::command]
async fn incident_spectrogram(id: String) -> Result<tauri::ipc::Response, String> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("incident id has unexpected characters".into());
    }
    tauri::async_runtime::spawn_blocking(move || -> Result<tauri::ipc::Response, String> {
        let out = paths::reports_dir().join(format!("spectro-{id}.png"));
        let out_str = out.display().to_string();
        cli::run_text(&["spectro", "--incident", id.as_str(), "--out", out_str.as_str()])?;
        let bytes = std::fs::read(&out).map_err(|e| format!("cannot read {out_str}: {e}"))?;
        Ok(tauri::ipc::Response::new(bytes))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The Telegram pairing code, only while the guard is waiting for it (state/unlock.code).
/// The file is 0600 and removed on successful pairing and on clean guard stop.
#[tauri::command]
fn unlock_code() -> Result<Option<String>, String> {
    let path = paths::root().join("state").join("unlock.code");
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let code = raw.trim().to_string();
            // Steam-like alphabet: A-Z2-9 without 0/O/1/I/L (DEFAULT_CODE_LEN=10).
            const ALPH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            let valid = code.len() == 10
                && code
                    .bytes()
                    .all(|b| ALPH.contains(&b.to_ascii_uppercase()));
            Ok(if valid {
                Some(code.to_ascii_uppercase())
            } else {
                None
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read unlock code: {e}")),
    }
}

#[tauri::command]
fn incident_report(id: String, format: String) -> Result<String, String> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("incident id has unexpected characters".into());
    }
    let fmt: &'static str = match format.as_str() {
        "html" => "html",
        "md" => "md",
        other => return Err(format!("bad format {other:?}")),
    };
    let out = paths::reports_dir().join(format!("incident-{id}.{fmt}"));
    let out_str = out.display().to_string();
    cli::run_text(&[
        "incidents",
        "report",
        id.as_str(),
        "--format",
        fmt,
        "--out",
        out_str.as_str(),
    ])?;
    Ok(out_str)
}

#[tauri::command]
fn log_tail(name: String, limit: Option<usize>) -> Result<Vec<Value>, String> {
    let safe = files::safe_log_name(&name).ok_or_else(|| format!("log {name:?} is not allowed"))?;
    files::read_jsonl(&paths::reports_dir().join(safe), limit.unwrap_or(200))
}

#[tauri::command]
fn lab_list() -> Result<Value, String> {
    cli::run_json(&["lab", "list", "--json"])
}

#[tauri::command]
fn lab_run(app: AppHandle, id: String) -> Result<(), String> {
    // Validated by the CLI (unknown ids exit 2). Output streams as lab-output events.
    std::thread::spawn(move || {
        let args = vec!["lab".to_string(), "run".to_string(), id.clone()];
        let handle = app.clone();
        let id_for_lines = id.clone();
        let code = cli::run_streaming(&args, move |line, is_err| {
            let _ = handle.emit(
                "lab-output",
                json!({ "id": id_for_lines, "line": line, "stderr": is_err }),
            );
        })
        .unwrap_or(-1);
        let _ = app.emit("lab-done", json!({ "id": id, "code": code }));
    });
    Ok(())
}

#[tauri::command]
fn control_status() -> Result<Value, String> {
    cli::run_json(&["control", "status"])
}

#[tauri::command]
fn fleet_list() -> Result<Value, String> {
    cli::run_json(&["fleet", "list"])
}

#[tauri::command]
fn fleet_graph() -> Result<Value, String> {
    cli::run_json(&["fleet", "graph"])
}

#[tauri::command]
fn fleet_warmup(scope: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    cli::run_json(&["fleet", "warmup", "--scope", s.as_str()])
}

#[tauri::command]
fn fleet_pair_start(
    ssh: String,
    home: Option<String>,
    label: Option<String>,
    identity: Option<String>,
    host_key_line: Option<String>,
) -> Result<Value, String> {
    let mut args = vec![
        "fleet".into(),
        "pair-start".into(),
        "--ssh".into(),
        ssh,
    ];
    if let Some(h) = home.filter(|x| !x.is_empty()) {
        args.extend(["--home".into(), h]);
    }
    if let Some(l) = label.filter(|x| !x.is_empty()) {
        args.extend(["--label".into(), l]);
    }
    if let Some(i) = identity.filter(|x| !x.is_empty()) {
        args.extend(["--identity".into(), i]);
    }
    if let Some(k) = host_key_line.filter(|x| !x.is_empty()) {
        args.extend(["--host-key-line".into(), k]);
    }
    let owned: Vec<String> = args;
    let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
    cli::run_json(&refs)
}

#[tauri::command]
fn fleet_pair_finish(
    ssh: String,
    home: Option<String>,
    code: String,
    id: String,
    label: Option<String>,
    role: Option<String>,
    identity: Option<String>,
    host_key_line: Option<String>,
) -> Result<Value, String> {
    let mut owned: Vec<String> = vec![
        "fleet".into(),
        "pair-finish".into(),
        "--ssh".into(),
        ssh,
        "--code".into(),
        code,
        "--id".into(),
        id,
    ];
    if let Some(h) = home.filter(|x| !x.is_empty()) {
        owned.extend(["--home".into(), h]);
    }
    if let Some(l) = label.filter(|x| !x.is_empty()) {
        owned.extend(["--label".into(), l]);
    }
    if let Some(r) = role.filter(|x| !x.is_empty()) {
        owned.extend(["--role".into(), r]);
    }
    if let Some(i) = identity.filter(|x| !x.is_empty()) {
        owned.extend(["--identity".into(), i]);
    }
    if let Some(k) = host_key_line.filter(|x| !x.is_empty()) {
        owned.extend(["--host-key-line".into(), k]);
    }
    let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
    cli::run_json(&refs)
}

#[tauri::command]
fn fleet_keyscan(ssh: String) -> Result<Value, String> {
    cli::run_json(&["fleet", "keyscan", "--ssh", ssh.as_str()])
}

#[tauri::command]
fn fleet_profile_apply(id: String, scope: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    cli::run_json(&[
        "fleet",
        "profile-apply",
        "--id",
        id.as_str(),
        "--scope",
        s.as_str(),
        "--yes",
    ])
}

#[tauri::command]
fn fleet_status(scope: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    cli::run_json(&["fleet", "status", "--scope", s.as_str()])
}

#[tauri::command]
fn fleet_unlock_locked(scope: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    cli::run_json(&["fleet", "unlock-locked", "--scope", s.as_str(), "--yes"])
}

#[tauri::command]
fn fleet_attack(scope: String, level: Option<String>, deps: Option<bool>) -> Result<Value, String> {
    let lv = level.unwrap_or_else(|| "L2".into());
    if deps.unwrap_or(false) {
        return cli::run_json(&[
            "fleet",
            "attack",
            "--scope",
            scope.as_str(),
            "--level",
            lv.as_str(),
            "--deps",
            "--yes",
        ]);
    }
    cli::run_json(&[
        "fleet",
        "attack",
        "--scope",
        scope.as_str(),
        "--level",
        lv.as_str(),
        "--yes",
    ])
}

#[tauri::command]
fn fleet_release(scope: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    cli::run_json(&["fleet", "release", "--scope", s.as_str(), "--yes"])
}

#[tauri::command]
fn fleet_incidents(scope: Option<String>, limit: Option<i64>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    let lim = limit.unwrap_or(40).to_string();
    cli::run_json(&[
        "fleet",
        "incidents",
        "--scope",
        s.as_str(),
        "--limit",
        lim.as_str(),
    ])
}

#[tauri::command]
fn fleet_mark_fp(scope: Option<String>, label: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "all".into());
    let lab = label.unwrap_or_else(|| "host_fp".into());
    cli::run_json(&[
        "fleet",
        "mark-fp",
        "--scope",
        s.as_str(),
        "--label",
        lab.as_str(),
    ])
}

#[tauri::command]
fn edge_status(lang: Option<String>) -> Result<Value, String> {
    let l = lang.unwrap_or_else(|| "en".into());
    cli::run_json(&["edge", "status", "--lang", &l])
}

#[tauri::command]
fn edge_under_attack() -> Result<Value, String> {
    cli::run_json(&["edge", "under-attack", "--yes"])
}

#[tauri::command]
fn edge_clear(level: Option<String>) -> Result<Value, String> {
    let lv = level.unwrap_or_else(|| "high".into());
    cli::run_json(&["edge", "clear", "--level", &lv, "--yes"])
}

#[tauri::command]
fn edge_playbook(lang: Option<String>) -> Result<Value, String> {
    let l = lang.unwrap_or_else(|| "en".into());
    cli::run_json(&["edge", "playbook", "--lang", &l, "--json"])
}

#[tauri::command]
fn fleet_ban(scope: String, ip: String, ttl: Option<f64>) -> Result<Value, String> {
    let t = ttl.unwrap_or(3600.0).to_string();
    cli::run_json(&[
        "fleet",
        "ban",
        "--scope",
        scope.as_str(),
        "--ip",
        ip.as_str(),
        "--ttl",
        t.as_str(),
        "--yes",
    ])
}

#[tauri::command]
fn control_action(name: String, payload: Value) -> Result<Value, String> {
    let safe = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.is_empty()
        && name.len() <= 32;
    if !safe {
        return Err("bad action name".into());
    }
    let raw = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
    cli::run_json(&["control", "action", name.as_str(), "--payload", raw.as_str()])
}

#[tauri::command]
fn home_import_model(source: String) -> Result<Value, String> {
    if source.is_empty() || source.contains('\0') {
        return Err("bad source path".into());
    }
    cli::run_json(&["home", "import-model", source.as_str()])
}

#[tauri::command]
fn home_write_env(bot_token: Option<String>, chat_id: Option<String>) -> Result<Value, String> {
    // Secrets on stdin — never argv (/proc cmdline).
    let payload = json!({
        "bot_token": bot_token.filter(|s| !s.is_empty()),
        "chat_id": chat_id.filter(|s| !s.is_empty()),
    });
    cli::run_json_stdin(&["home", "env", "--from-stdin"], &payload.to_string())
}

#[tauri::command]
fn onboarding_status() -> Result<Value, String> {
    cli::run_json(&["home", "onboarding", "status"])
}

#[tauri::command]
fn onboarding_done() -> Result<Value, String> {
    cli::run_json(&["home", "onboarding", "done"])
}

#[tauri::command]
fn home_health(ping: Option<bool>) -> Result<Value, String> {
    let mut args = vec!["home", "health"];
    if ping.unwrap_or(false) {
        args.push("--ping");
    }
    cli::run_json(&args)
}

#[tauri::command]
fn home_digest(hours: Option<f64>, lang: Option<String>) -> Result<Value, String> {
    let hours_s = hours.unwrap_or(24.0).to_string();
    let lang_s = lang.unwrap_or_else(|| "en".into());
    cli::run_json(&[
        "home",
        "digest",
        "--hours",
        hours_s.as_str(),
        "--lang",
        lang_s.as_str(),
    ])
}

#[tauri::command]
fn home_checklist() -> Result<Value, String> {
    cli::run_json(&["home", "checklist"])
}

#[tauri::command]
fn home_mute_rule(rule_id: String, hours: Option<f64>) -> Result<Value, String> {
    if rule_id.is_empty() || rule_id.len() > 128 {
        return Err("bad rule_id".into());
    }
    let hours_s = hours.unwrap_or(24.0).to_string();
    cli::run_json(&[
        "home",
        "mute-rule",
        "--rule-id",
        rule_id.as_str(),
        "--hours",
        hours_s.as_str(),
    ])
}

/// Background loop: pushes the latest sample of each live metric to the UI every 2 s.
/// Ignores stale SQLite rows (retention leaves old samples that would paint a flat fake line).
fn live_loop(app: AppHandle) {
    const FRESH_SEC: f64 = 90.0;
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let now = now_secs();
        if let Ok(latest) = timeseries::latest(&paths::timeseries_db(), LIVE_METRICS) {
            let fresh: Vec<_> = latest
                .into_iter()
                .filter(|row| now - row.ts <= FRESH_SEC)
                .collect();
            if fresh.is_empty() {
                continue;
            }
            let sample_at = fresh
                .iter()
                .map(|row| row.ts)
                .fold(0.0_f64, f64::max);
            let _ = app.emit(
                "live",
                json!({ "at": sample_at.max(now - FRESH_SEC), "latest": fresh }),
            );
        }
    }
}

pub fn run() {
    let app = tauri::Builder::default()
        .manage(Stack::default())
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || live_loop(handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            helper_status,
            guard_service,
            start_all,
            stop_guard,
            stack_status,
            settings_export,
            settings_apply,
            settings_rollback,
            install_bundle,
            timeseries_query,
            timeseries_metrics,
            incidents_list,
            incidents_refresh,
            incident_report,
            incident_spectrogram,
            unlock_code,
            log_tail,
            lab_list,
            lab_run,
            control_status,
            control_action,
            fleet_list,
            fleet_graph,
            fleet_warmup,
            fleet_profile_apply,
            fleet_status,
            fleet_unlock_locked,
            fleet_attack,
            fleet_release,
            fleet_incidents,
            fleet_mark_fp,
            fleet_ban,
            fleet_pair_start,
            fleet_pair_finish,
            fleet_keyscan,
            edge_status,
            edge_under_attack,
            edge_clear,
            edge_playbook,
            home_import_model,
            home_write_env,
            onboarding_status,
            onboarding_done,
            home_health,
            home_digest,
            home_checklist,
            home_mute_rule,
            bootstrap_status,
            bootstrap_install,
            bootstrap_preflight,
            protect_status,
            protect_enable,
            protect_disable,
            home_update,
            home_seed_role,
            home_seed_never_ban,
            detect_public_ip,
            install_helper_release,
        ])
        .build(tauri::generate_context!())
        .expect("error while building SysSpectogram Control Center");
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            // If user systemd protect is active, leave it running (friend path).
            let keep = cli::run_json(&["protect", "status"])
                .ok()
                .and_then(|v| v.get("active").and_then(|x| x.as_bool()))
                .unwrap_or(false);
            if !keep {
                handle.state::<Stack>().stop_guard();
            }
        }
    });
}
