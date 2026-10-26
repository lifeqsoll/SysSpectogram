//! SysSpectogram Fleet Hub backend.
//!
//! Thin bridge: UI invokes these commands, which run `python -m sysspectogram`
//! fleet / edge / home with argument arrays. No helper, polkit, or protect.

mod cli;
mod paths;

use serde_json::{json, Value};

#[tauri::command]
fn app_info() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "root": paths::root().display().to_string(),
        "stack_ready": paths::stack_ready(),
        "app": "fleet-hub",
    })
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
fn fleet_add(
    id: String,
    label: Option<String>,
    ssh: Option<String>,
    home: Option<String>,
    device_id: Option<String>,
    device_token: Option<String>,
    role: Option<String>,
) -> Result<Value, String> {
    let mut owned: Vec<String> = vec!["fleet".into(), "add".into(), "--id".into(), id];
    if let Some(v) = label.filter(|s| !s.is_empty()) {
        owned.push("--label".into());
        owned.push(v);
    }
    if let Some(v) = ssh.filter(|s| !s.is_empty()) {
        owned.push("--ssh".into());
        owned.push(v);
    }
    if let Some(v) = home.filter(|s| !s.is_empty()) {
        owned.push("--home".into());
        owned.push(v);
    }
    if let Some(v) = device_id.filter(|s| !s.is_empty()) {
        owned.push("--device-id".into());
        owned.push(v);
    }
    if let Some(v) = role.filter(|s| !s.is_empty()) {
        owned.push("--role".into());
        owned.push(v);
    }
    // Prefer env over argv so device_token is not visible in `ps`.
    let token = device_token.filter(|s| !s.is_empty());
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    match token {
        Some(t) => cli::run_json_env(&refs, &[("SYSSPECTOGRAM_DEVICE_TOKEN", t.as_str())]),
        None => cli::run_json(&refs),
    }
}

#[tauri::command]
fn fleet_pin_host(id: String, host_key_line: String) -> Result<Value, String> {
    cli::run_json(&[
        "fleet",
        "pin-host",
        "--id",
        id.as_str(),
        "--host-key-line",
        host_key_line.as_str(),
    ])
}

#[tauri::command]
fn fleet_warmup(scope: Option<String>) -> Result<Value, String> {
    let s = scope.unwrap_or_else(|| "local".into());
    cli::run_json(&["fleet", "warmup", "--scope", s.as_str()])
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
fn fleet_pair_start(
    ssh: String,
    home: Option<String>,
    label: Option<String>,
    identity: Option<String>,
    host_key_line: Option<String>,
) -> Result<Value, String> {
    let mut owned: Vec<String> = vec!["fleet".into(), "pair-start".into(), "--ssh".into(), ssh];
    if let Some(h) = home.filter(|x| !x.is_empty()) {
        owned.extend(["--home".into(), h]);
    }
    if let Some(l) = label.filter(|x| !x.is_empty()) {
        owned.extend(["--label".into(), l]);
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
fn home_pair_remote(label: Option<String>) -> Result<Value, String> {
    let lab = label.unwrap_or_else(|| "device".into());
    cli::run_json(&["home", "pair-remote", "--label", lab.as_str()])
}

#[tauri::command]
fn home_pair_complete(code: String, label: Option<String>) -> Result<Value, String> {
    if let Some(lab) = label.filter(|s| !s.is_empty()) {
        return cli::run_json(&[
            "home",
            "pair-complete",
            code.as_str(),
            "--label",
            lab.as_str(),
        ]);
    }
    cli::run_json(&["home", "pair-complete", code.as_str()])
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_info,
            fleet_list,
            fleet_graph,
            fleet_add,
            fleet_pin_host,
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
            home_pair_remote,
            home_pair_complete,
        ])
        .run(tauri::generate_context!())
        .expect("error while building SysSpectogram Fleet Hub");
}
