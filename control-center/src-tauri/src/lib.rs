//! SysSpectogram Control Center backend.
//!
//! The UI never touches root directly. It calls these commands, which read SQLite and
//! JSONL read-only, run the Python CLI with argument arrays, or talk to
//! sysspectogram-helper over its Unix socket (which applies polkit and an allowlist).

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
    })
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
    helper::request("settings.apply", json!({ "changes": changes }))
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
            let valid = code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit());
            Ok(if valid { Some(code) } else { None })
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

/// Background loop: pushes the latest sample of each live metric to the UI every 2 s.
fn live_loop(app: AppHandle) {
    loop {
        std::thread::sleep(Duration::from_secs(2));
        if let Ok(latest) = timeseries::latest(&paths::timeseries_db(), LIVE_METRICS) {
            let _ = app.emit("live", json!({ "at": now_secs(), "latest": latest }));
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
        ])
        .build(tauri::generate_context!())
        .expect("error while building SysSpectogram Control Center");
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            handle.state::<Stack>().stop_guard();
        }
    });
}
