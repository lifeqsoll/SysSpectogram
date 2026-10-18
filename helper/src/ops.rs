//! Allowlisted root operations. No shell strings: every external command is started
//! with a fixed program path and an argument array.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{authorize, Caller};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MINISIGN: &str = "/usr/bin/minisign";
const PUBKEY: &str = "/usr/share/sysspectogram/minisign.pub";
const GUARD_UNIT: &str = "sysspectogram-guard.service";
const RELEASES_ROOT: &str = "/opt/sysspectogram/releases";
const CURRENT_LINK: &str = "/opt/sysspectogram/current";
const AGENT_BIN: &str = "/usr/local/sbin/sysspectogram-agent";
const SETTINGS_FILE: &str = "/etc/sysspectogram/settings.json";
const STAGING_ROOT: &str = "/var/lib/sysspectogram/staging";
const MANIFEST: &str = "MANIFEST.sha256";
const MANIFEST_SIG: &str = "MANIFEST.sha256.minisig";
const AGENT_NAME: &str = "sysspectogram-agent";
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CHANGES: usize = 64;

const ACTION_SERVICE: &str = "org.sysspectogram.helper.service";
const ACTION_BUNDLE: &str = "org.sysspectogram.helper.bundle-install";
const ACTION_SETTINGS: &str = "org.sysspectogram.helper.settings";

pub fn dispatch(op: &str, args: &Value, caller: Caller) -> Value {
    let result = match op {
        "status" => status(),
        "service" => service(args, caller),
        "bundle.install" => bundle_install(args, caller),
        "settings.apply" => settings_apply(args, caller),
        "settings.rollback" => settings_rollback(caller),
        other => Err(format!("unknown operation {other:?}")),
    };
    match result {
        Ok(data) => json!({"ok": true, "data": data}),
        Err(message) => json!({"ok": false, "message": message}),
    }
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

// ---------------------------------------------------------------- status / service

fn status() -> Result<Value, String> {
    let out = Command::new(SYSTEMCTL)
        .args(["is-active", GUARD_UNIT])
        .output()
        .map_err(|e| format!("systemctl: {e}"))?;
    let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(json!({"guard": state}))
}

fn service(args: &Value, caller: Caller) -> Result<Value, String> {
    let action = args
        .get("action")
        .and_then(Value::as_str)
        .ok_or("missing action")?;
    let verb = match action {
        "start" => "start",
        "stop" => "stop",
        "restart" => "restart",
        other => return Err(format!("bad service action {other:?}")),
    };
    authorize(ACTION_SERVICE, caller)?;
    run(SYSTEMCTL, &[verb, GUARD_UNIT])?;
    Ok(json!({"unit": GUARD_UNIT, "action": verb}))
}

// ---------------------------------------------------------------- bundle install

pub fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 4 && p.bytes().all(|b| b.is_ascii_digit()))
}

pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Parse a `sha256sum`-style manifest: `<64 hex>  <file name>` per line.
pub fn parse_manifest(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (hash, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("bad manifest line {line:?}"))?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("bad hash in manifest for {name:?}"));
        }
        if !valid_file_name(name) || name == MANIFEST || name == MANIFEST_SIG {
            return Err(format!("bad file name in manifest: {name:?}"));
        }
        if !seen.insert(name.to_string()) {
            return Err(format!("duplicate entry in manifest: {name:?}"));
        }
        out.push((hash.to_ascii_lowercase(), name.to_string()));
        if out.len() > MAX_FILES {
            return Err("manifest lists too many files".into());
        }
    }
    if out.is_empty() {
        return Err("manifest is empty".into());
    }
    if !out.iter().any(|(_, n)| n == AGENT_NAME) {
        return Err(format!("manifest does not list {AGENT_NAME}"));
    }
    Ok(out)
}

fn check_source(source: &str, uid: u32) -> Result<PathBuf, String> {
    let path = PathBuf::from(source);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("source must be an absolute path without '..'".into());
    }
    let meta = fs::symlink_metadata(&path).map_err(|e| format!("source: {e}"))?;
    if !meta.is_dir() {
        return Err("source must be a real directory".into());
    }
    if meta.uid() != uid {
        return Err("source directory is not owned by the caller".into());
    }
    Ok(path)
}

/// Root-owned, unpredictable staging directory. Removed on drop.
struct Staging {
    path: PathBuf,
}

impl Staging {
    fn create(version: &str) -> Result<Self, String> {
        fs::create_dir_all(STAGING_ROOT).map_err(|e| format!("staging root: {e}"))?;
        fs::set_permissions(STAGING_ROOT, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("staging root perms: {e}"))?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = PathBuf::from(STAGING_ROOT).join(format!("{version}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).map_err(|e| format!("staging dir: {e}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("staging perms: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_regular(src: &Path, dst: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(src).map_err(|e| format!("{}: {e}", src.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", src.display()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("{} is too large", src.display()));
    }
    fs::copy(src, dst).map_err(|e| format!("copy {}: {e}", src.display()))?;
    Ok(())
}

fn path_str(p: &Path) -> Result<&str, String> {
    p.to_str().ok_or_else(|| "non-UTF-8 path".to_string())
}

fn verify_signature(staging: &Path) -> Result<(), String> {
    let manifest = staging.join(MANIFEST);
    let sig = staging.join(MANIFEST_SIG);
    run(
        MINISIGN,
        &["-Vm", path_str(&manifest)?, "-p", PUBKEY, "-x", path_str(&sig)?],
    )
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn verify_hashes(staging: &Path, entries: &[(String, String)]) -> Result<(), String> {
    for (expected, name) in entries {
        let actual = sha256_file(&staging.join(name))?;
        if &actual != expected {
            return Err(format!("hash mismatch for {name}"));
        }
    }
    Ok(())
}

fn install_agent(src: &Path) -> Result<(), String> {
    let dir = Path::new(AGENT_BIN)
        .parent()
        .ok_or("agent path has no parent")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = PathBuf::from(format!("{AGENT_BIN}.new"));
    fs::copy(src, &tmp).map_err(|e| format!("agent copy: {e}"))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("agent perms: {e}"))?;
    fs::rename(&tmp, AGENT_BIN).map_err(|e| format!("agent install: {e}"))?;
    Ok(())
}

fn install_release(staging: &Path, version: &str, names: &[String]) -> Result<(), String> {
    fs::create_dir_all(RELEASES_ROOT).map_err(|e| format!("releases root: {e}"))?;
    let final_dir = PathBuf::from(RELEASES_ROOT).join(version);
    let tmp_dir = PathBuf::from(RELEASES_ROOT).join(format!(".{version}.tmp"));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir(&tmp_dir).map_err(|e| format!("release tmp: {e}"))?;

    let mut all: Vec<&str> = names.iter().map(String::as_str).collect();
    all.push(MANIFEST);
    all.push(MANIFEST_SIG);
    for name in all {
        let mode = if name == AGENT_NAME { 0o755 } else { 0o644 };
        fs::copy(staging.join(name), tmp_dir.join(name)).map_err(|e| format!("release copy: {e}"))?;
        fs::set_permissions(tmp_dir.join(name), fs::Permissions::from_mode(mode))
            .map_err(|e| format!("release perms: {e}"))?;
    }
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir).map_err(|e| format!("replace release: {e}"))?;
    }
    fs::rename(&tmp_dir, &final_dir).map_err(|e| format!("release rename: {e}"))?;

    install_agent(&final_dir.join(AGENT_NAME))?;

    // Atomic switch of `current`: create the new link beside it, then rename over it.
    let link_tmp = PathBuf::from(format!("{CURRENT_LINK}.tmp"));
    let _ = fs::remove_file(&link_tmp);
    std::os::unix::fs::symlink(&final_dir, &link_tmp).map_err(|e| format!("symlink: {e}"))?;
    fs::rename(&link_tmp, CURRENT_LINK).map_err(|e| format!("switch current: {e}"))?;
    Ok(())
}

fn bundle_install(args: &Value, caller: Caller) -> Result<Value, String> {
    let version = args
        .get("version")
        .and_then(Value::as_str)
        .ok_or("missing version")?;
    let source = args
        .get("source")
        .and_then(Value::as_str)
        .ok_or("missing source")?;
    if !valid_version(version) {
        return Err(format!("bad version {version:?}"));
    }
    authorize(ACTION_BUNDLE, caller)?;
    let source = check_source(source, caller.uid)?;

    let staging = Staging::create(version)?;
    let dir = staging.path.as_path();

    // 1. Copy the manifest and signature into root-owned staging, then verify the signature.
    copy_regular(&source.join(MANIFEST), &dir.join(MANIFEST))?;
    copy_regular(&source.join(MANIFEST_SIG), &dir.join(MANIFEST_SIG))?;
    verify_signature(dir)?;

    // 2. Only now trust the manifest. Copy each listed file and check its hash.
    let text = fs::read_to_string(dir.join(MANIFEST)).map_err(|e| format!("manifest: {e}"))?;
    let entries = parse_manifest(&text)?;
    for (_, name) in &entries {
        copy_regular(&source.join(name), &dir.join(name))?;
    }
    verify_hashes(dir, &entries)?;

    // 3. Install from the verified copies.
    let names: Vec<String> = entries.iter().map(|(_, n)| n.clone()).collect();
    install_release(dir, version, &names)?;
    Ok(json!({"version": version, "files": names.len()}))
}

// ---------------------------------------------------------------- settings overlay

#[derive(Clone, Copy)]
enum Kind {
    Bool,
    Int(i64, i64),
    Float(f64, f64),
    Enum(&'static [&'static str]),
    /// Free-form string (CIDR lists, paths). Max length enforced in validate_change.
    String,
}

/// Keys the Control Center may change. Must match configs/schema.yaml.
const SETTINGS_RULES: &[(&str, Kind)] = &[
    ("agent.enabled", Kind::Bool),
    ("agent.mode", Kind::Enum(&["userspace", "ebpf"])),
    ("agent.score_half_life_sec", Kind::Float(1.0, 3600.0)),
    ("agent.spectrogram", Kind::Bool),
    ("alerts.strict_secrets", Kind::Bool),
    ("ensemble.host_weight", Kind::Float(0.0, 1.0)),
    ("ensemble.agent_weight", Kind::Float(0.0, 1.0)),
    ("ensemble.risk_threshold", Kind::Float(0.0, 1.0)),
    ("kirk.vmi", Kind::Bool),
    ("kirk.vmi_backend", Kind::Enum(&["mock", "libvmi"])),
    ("kirk.vmi_trust", Kind::Enum(&["lab", "out-of-band"])),
    ("kirk.vmi_confirm", Kind::Int(1, 10)),
    ("monitor.interval_sec", Kind::Int(1, 3600)),
    ("response.mode", Kind::Enum(&["observe", "shield", "aggressive", "isolate"])),
    ("response.never_ban_cidrs", Kind::String),
    ("telegram.enabled", Kind::Bool),
    ("telegram.require_console_unlock", Kind::Bool),
    ("timeseries.enabled", Kind::Bool),
    ("ui.lang", Kind::Enum(&["en", "ru"])),
    ("web.enabled", Kind::Bool),
];

pub fn validate_change(key: &str, value: &Value) -> Result<(), String> {
    let kind = SETTINGS_RULES
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, kind)| *kind)
        .ok_or_else(|| format!("{key} is not a setting the helper may change"))?;
    match (kind, value) {
        (Kind::Bool, Value::Bool(_)) => Ok(()),
        (Kind::Int(lo, hi), Value::Number(n)) => {
            let v = n.as_i64().ok_or_else(|| format!("{key}: expected an integer"))?;
            if v >= lo && v <= hi {
                Ok(())
            } else {
                Err(format!("{key}: must be between {lo} and {hi}"))
            }
        }
        (Kind::Float(lo, hi), Value::Number(n)) => {
            let v = n.as_f64().ok_or_else(|| format!("{key}: expected a number"))?;
            if v >= lo && v <= hi {
                Ok(())
            } else {
                Err(format!("{key}: must be between {lo} and {hi}"))
            }
        }
        (Kind::Enum(choices), Value::String(s)) => {
            if choices.contains(&s.as_str()) {
                Ok(())
            } else {
                Err(format!("{key}: must be one of {choices:?}"))
            }
        }
        (Kind::String, Value::String(s)) => {
            if s.len() > 2048 {
                Err(format!("{key}: string too long (max 2048)"))
            } else {
                Ok(())
            }
        }
        // never_ban: allow a JSON array of IP/CIDR strings as well as one comma-separated string
        (Kind::String, Value::Array(items)) if key == "response.never_ban_cidrs" => {
            let mut total = 0usize;
            for item in items {
                let Some(s) = item.as_str() else {
                    return Err(format!("{key}: list entries must be strings"));
                };
                total = total.saturating_add(s.len());
                if total > 2048 {
                    return Err(format!("{key}: string too long (max 2048)"));
                }
            }
            Ok(())
        }
        _ => Err(format!("{key}: wrong value type")),
    }
}

fn backup_path() -> PathBuf {
    PathBuf::from(format!("{SETTINGS_FILE}.bak"))
}

fn read_overlay(path: &Path) -> Result<Map<String, Value>, String> {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(map)) => Ok(map),
            Ok(_) => Err(format!("{} is not a JSON object", path.display())),
            Err(e) => Err(format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_overlay(path: &Path, map: &Map<String, Value>) -> Result<(), String> {
    let dir = path.parent().ok_or("settings path has no parent")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let body = serde_json::to_string_pretty(&Value::Object(map.clone()))
        .map_err(|e| format!("encode settings: {e}"))?;
    {
        let mut file = fs::File::create(&tmp).map_err(|e| format!("create settings tmp: {e}"))?;
        file.write_all(body.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("write settings tmp: {e}"))?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("settings perms: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("replace settings: {e}"))?;
    Ok(())
}

fn settings_apply(args: &Value, caller: Caller) -> Result<Value, String> {
    let changes = args
        .get("changes")
        .and_then(Value::as_object)
        .ok_or("missing changes object")?;
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        return Err(format!("changes must hold 1..={MAX_CHANGES} keys"));
    }
    for (key, value) in changes {
        validate_change(key, value)?;
    }
    authorize(ACTION_SETTINGS, caller)?;

    let settings = Path::new(SETTINGS_FILE);
    let current = read_overlay(settings)?;
    let mut next = current.clone();
    for (key, value) in changes {
        next.insert(key.clone(), value.clone());
    }
    // Keep the previous state for one-step rollback, then write the new overlay.
    write_overlay(&backup_path(), &current)?;
    write_overlay(settings, &next)?;
    Ok(json!({"applied": changes.keys().collect::<Vec<_>>()}))
}

fn settings_rollback(caller: Caller) -> Result<Value, String> {
    authorize(ACTION_SETTINGS, caller)?;
    let settings = Path::new(SETTINGS_FILE);
    let bak = backup_path();
    if !bak.exists() {
        return Err("no previous settings to roll back to".into());
    }
    let previous = read_overlay(&bak)?;
    let current = read_overlay(settings)?;
    // Swap: the restored state becomes live, the replaced state becomes the new backup.
    write_overlay(settings, &previous)?;
    write_overlay(&bak, &current)?;
    Ok(json!({"keys": previous.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_rules() {
        assert!(valid_version("1.0.0"));
        assert!(!valid_version("1.0"));
        assert!(!valid_version("../1.0.0"));
        assert!(!valid_version("1.0.0-rc1"));
    }

    #[test]
    fn file_name_rules() {
        assert!(valid_file_name("sysspectogram-agent"));
        assert!(!valid_file_name("../x"));
        assert!(!valid_file_name("a/b"));
        assert!(!valid_file_name(".."));
    }

    #[test]
    fn manifest_parses_and_rejects_bad_lines() {
        let h = "a".repeat(64);
        let good = format!("{h}  sysspectogram-agent\n");
        assert_eq!(parse_manifest(&good).unwrap().len(), 1);
        assert!(parse_manifest(&format!("{h}  other\n")).is_err());
        assert!(parse_manifest(&format!("{h}  sysspectogram-agent\n{h}  sysspectogram-agent\n")).is_err());
        assert!(parse_manifest(&format!("{h}  ../sysspectogram-agent\n")).is_err());
        assert!(parse_manifest("zz  sysspectogram-agent\n").is_err());
    }

    #[test]
    fn settings_values_are_checked() {
        assert!(validate_change("kirk.vmi", &json!(true)).is_ok());
        assert!(validate_change("kirk.vmi", &json!("yes")).is_err());
        assert!(validate_change("response.mode", &json!("shield")).is_ok());
        assert!(validate_change("response.mode", &json!("nuke")).is_err());
        assert!(validate_change(
            "response.never_ban_cidrs",
            &json!("203.0.113.10, 198.51.100.20/32")
        )
        .is_ok());
        assert!(validate_change(
            "response.never_ban_cidrs",
            &json!(["203.0.113.10/32", "198.51.100.20/32"])
        )
        .is_ok());
        assert!(validate_change("response.never_ban_cidrs", &json!([1, 2])).is_err());
        assert!(validate_change("ui.lang", &json!("ru")).is_ok());
        assert!(validate_change("web.enabled", &json!(true)).is_ok());
        assert!(validate_change("telegram.enabled", &json!(true)).is_ok());
        assert!(validate_change("monitor.interval_sec", &json!(0)).is_err());
        assert!(validate_change("ensemble.risk_threshold", &json!(0.7)).is_ok());
        assert!(validate_change("ensemble.risk_threshold", &json!(1.5)).is_err());
        assert!(validate_change("ssh.PermitRootLogin", &json!("yes")).is_err());
    }
}
