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
        // Ban path (F-02): group sysspectogram, no polkit — headless guard cannot answer pkcheck.
        "ban.add" => ban_add(args, caller),
        "ban.del" => ban_del(args, caller),
        "ban.list" => ban_list(caller),
        "ban.selftest" => ban_selftest(caller),
        "auth.tail" => auth_tail(args, caller),
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
    // Re-check type via open(O_NOFOLLOW|O_NONBLOCK) so a TOCTOU symlink→FIFO swap
    // cannot hang root (FIFO open without O_NONBLOCK blocks until a writer).
    use std::os::unix::fs::OpenOptionsExt;
    let meta = fs::symlink_metadata(src).map_err(|e| format!("{}: {e}", src.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink", src.display()));
    }
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", src.display()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("{} is too large", src.display()));
    }
    let mut infile = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(src)
        .map_err(|e| format!("open {}: {e}", src.display()))?;
    let meta2 = infile
        .metadata()
        .map_err(|e| format!("fstat {}: {e}", src.display()))?;
    if !meta2.is_file() || meta2.file_type().is_symlink() {
        return Err(format!("{} changed type during copy", src.display()));
    }
    if meta2.len() > MAX_FILE_BYTES {
        return Err(format!("{} is too large", src.display()));
    }
    let mut outfile = fs::File::create(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    std::io::copy(&mut infile, &mut outfile).map_err(|e| format!("copy {}: {e}", src.display()))?;
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
    ("kirk.allow_ssh_cidrs", Kind::String),
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
        (Kind::String, Value::String(s)) if key == "response.never_ban_cidrs" => {
            if s.len() > 2048 {
                return Err(format!("{key}: string too long (max 2048)"));
            }
            validate_never_ban_list(s)
        }
        (Kind::String, Value::String(s)) if key == "kirk.allow_ssh_cidrs" => {
            if s.len() > 2048 {
                return Err(format!("{key}: string too long (max 2048)"));
            }
            validate_allow_ssh_list(s)
        }
        (Kind::String, Value::String(s)) => {
            if s.len() > 2048 {
                Err(format!("{key}: string too long (max 2048)"))
            } else {
                Ok(())
            }
        }
        // never_ban / allow_ssh: JSON array of IP/CIDR strings or one comma-separated string
        (Kind::String, Value::Array(items))
            if key == "response.never_ban_cidrs" || key == "kirk.allow_ssh_cidrs" =>
        {
            let mut total = 0usize;
            let mut parts: Vec<&str> = Vec::new();
            for item in items {
                let Some(s) = item.as_str() else {
                    return Err(format!("{key}: list entries must be strings"));
                };
                total = total.saturating_add(s.len());
                if total > 2048 {
                    return Err(format!("{key}: string too long (max 2048)"));
                }
                parts.push(s);
            }
            let joined = parts.join(",");
            if key == "kirk.allow_ssh_cidrs" {
                validate_allow_ssh_list(&joined)
            } else {
                validate_never_ban_list(&joined)
            }
        }
        _ => Err(format!("{key}: wrong value type")),
    }
}

/// Mirror Python `validate_never_ban_cidr`: host or /24+ (v4) / /64+ (v6);
/// reject unspecified/loopback/0.0.0.0/8 (parsed, not string-compared).
fn validate_never_ban_cidr(raw: &str) -> Result<(), String> {
    use std::net::IpAddr;

    let token = raw.trim();
    if token.is_empty() {
        return Err("empty".into());
    }
    let (addr_s, prefix_opt) = match token.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (token, None),
    };
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|_| format!("invalid_ip in {token}"))?;
    let (max_wide, host_pref) = match addr {
        IpAddr::V4(v4) => {
            // 0.0.0.0/8 + 127.0.0.0/8 + Class E/reserved 240/4 + broadcast (Python is_reserved).
            let o = v4.octets();
            let o0 = o[0];
            if v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || o0 == 0
                || o0 == 127
                || o0 >= 240
            {
                return Err("special_address".into());
            }
            (24u8, 32u8)
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                return Err("special_address".into());
            }
            // Match Python: reject IPv4-mapped (::ffff:a.b.c.d).
            if v6.to_ipv4_mapped().is_some() {
                return Err("special_address".into());
            }
            (64u8, 128u8)
        }
    };
    let prefix: u8 = match prefix_opt {
        None => host_pref,
        Some(p) => p
            .parse()
            .map_err(|_| format!("bad prefix in {token}"))?,
    };
    if prefix > host_pref {
        return Err("invalid_ip".into());
    }
    if prefix < max_wide {
        return Err("too_wide".into());
    }
    Ok(())
}

fn validate_never_ban_list(raw: &str) -> Result<(), String> {
    let text = raw.trim();
    if text.is_empty() {
        return Ok(());
    }
    for part in text.split([',', ';', ' ']) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        validate_never_ban_cidr(p).map_err(|e| format!("response.never_ban_cidrs: {e}"))?;
    }
    Ok(())
}

/// Looser than never_ban (admin SSH allow may be /8+), but still reject junk /0 / mapped.
fn validate_allow_ssh_cidr(raw: &str) -> Result<(), String> {
    use std::net::IpAddr;

    let token = raw.trim();
    if token.is_empty() {
        return Err("empty".into());
    }
    let (addr_s, prefix_opt) = match token.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (token, None),
    };
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|_| format!("invalid_ip in {token}"))?;
    let (min_pref, host_pref) = match addr {
        IpAddr::V4(_) => (8u8, 32u8),
        IpAddr::V6(v6) => {
            if v6.to_ipv4_mapped().is_some() {
                return Err("special_address".into());
            }
            (32u8, 128u8)
        }
    };
    let prefix: u8 = match prefix_opt {
        None => host_pref,
        Some(p) => p
            .parse()
            .map_err(|_| format!("bad prefix in {token}"))?,
    };
    if prefix > host_pref {
        return Err("invalid_ip".into());
    }
    if prefix < min_pref {
        return Err("too_wide".into());
    }
    Ok(())
}

fn validate_allow_ssh_list(raw: &str) -> Result<(), String> {
    let text = raw.trim();
    if text.is_empty() {
        return Ok(());
    }
    for part in text.split([',', ';', ' ']) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        validate_allow_ssh_cidr(p).map_err(|e| format!("kirk.allow_ssh_cidrs: {e}"))?;
    }
    Ok(())
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

// ---------------------------------------------------------------- ban (nft sets via helper, F-02)

const NFT: &str = "/usr/sbin/nft";
const NFT_ALT: &str = "/usr/bin/nft";
const NEVER_BAN_FILE: &str = "/etc/sysspectogram/never_ban";
const GUARD_UIDS_FILE: &str = "/etc/sysspectogram/guard-uids";
const BAN_GROUP: &str = "sysspectogram";
const MAX_BAN_TTL_SEC: u64 = 7 * 24 * 3600;
const MIN_BAN_TTL_SEC: u64 = 60;
const MAX_BAN_ELEMENTS: usize = 50_000;
const SELFTEST_IP: &str = "192.0.2.1";

fn nft_bin() -> &'static str {
    if Path::new(NFT).is_file() {
        NFT
    } else {
        NFT_ALT
    }
}

/// Authorize ban.* by membership in group `sysspectogram` (or root / guard-uids), not polkit.
fn authorize_ban_group(caller: Caller) -> Result<(), String> {
    if caller.uid == 0 {
        return Ok(());
    }
    if guard_uids_allows(caller.uid) {
        return Ok(());
    }
    if uid_in_group(caller.uid, BAN_GROUP)? {
        return Ok(());
    }
    Err(format!(
        "not authorized: not in group {BAN_GROUP} (and not listed in {GUARD_UIDS_FILE})"
    ))
}

fn guard_uids_allows(uid: u32) -> bool {
    let Ok(text) = fs::read_to_string(GUARD_UIDS_FILE) else {
        return false;
    };
    text.lines().any(|l| {
        let t = l.split('#').next().unwrap_or("").trim();
        t.parse::<u32>().ok() == Some(uid)
    })
}

fn uid_in_group(uid: u32, group_name: &str) -> Result<bool, String> {
    // SAFETY: getgrnam / getpwuid return static libc buffers; we only read them.
    unsafe {
        let grp = libc::getgrnam(std::ffi::CString::new(group_name).unwrap().as_ptr());
        if grp.is_null() {
            return Err(format!("group {group_name} not found"));
        }
        let gid = (*grp).gr_gid;
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return Err(format!("uid {uid} has no passwd entry"));
        }
        let mut groups: Vec<libc::gid_t> = vec![0; 64];
        let mut ngroups: libc::c_int = groups.len() as libc::c_int;
        let rc = libc::getgrouplist((*pw).pw_name, (*pw).pw_gid, groups.as_mut_ptr(), &mut ngroups);
        if rc < 0 {
            groups.resize(ngroups as usize, 0);
            let rc2 = libc::getgrouplist((*pw).pw_name, (*pw).pw_gid, groups.as_mut_ptr(), &mut ngroups);
            if rc2 < 0 {
                return Err("getgrouplist failed".into());
            }
        }
        Ok(groups[..ngroups as usize].iter().any(|g| *g == gid))
    }
}

/// Single-host IP only; reject CIDR, specials, junk (mirrors Python parse_ban_ip).
pub fn parse_helper_ban_ip(raw: &str) -> Result<std::net::IpAddr, String> {
    let token = raw.trim();
    if token.is_empty() || token.contains('/') || token.contains('%') {
        return Err(format!("invalid ban ip: {token:?}"));
    }
    if token.bytes().any(|b| {
        matches!(
            b,
            b';' | b'|' | b'&' | b'`' | b'$' | b'(' | b')' | b'{' | b'}' | b'[' | b']'
                | b'<' | b'>' | b'\\' | b'"' | b'\'' | b' ' | b'\t' | b'\n' | b'\r'
        )
    }) {
        return Err(format!("invalid ban ip: {token:?}"));
    }
    let addr: std::net::IpAddr = token
        .parse()
        .map_err(|_| format!("invalid ban ip: {token:?}"))?;
    match addr {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() || v4.is_link_local() => {
            Err(format!("refusing ban of special address: {addr}"))
        }
        std::net::IpAddr::V6(v6)
            if v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local() =>
        {
            Err(format!("refusing ban of special address: {addr}"))
        }
        _ => Ok(addr),
    }
}

fn clamp_ttl(raw: Option<u64>) -> Result<u64, String> {
    let ttl = raw.unwrap_or(3600);
    if ttl < MIN_BAN_TTL_SEC {
        return Err(format!("ttl_sec must be >= {MIN_BAN_TTL_SEC}"));
    }
    if ttl > MAX_BAN_TTL_SEC {
        return Err(format!("ttl_sec must be <= {MAX_BAN_TTL_SEC}"));
    }
    Ok(ttl)
}

fn set_for(addr: std::net::IpAddr) -> &'static str {
    match addr {
        std::net::IpAddr::V4(_) => "ban4",
        std::net::IpAddr::V6(_) => "ban6",
    }
}

fn ensure_nft_table() -> Result<(), String> {
    let nft = nft_bin();
    let _ = run(nft, &["create", "table", "inet", "sysspectogram"]);
    let _ = run(
        nft,
        &[
            "create",
            "set",
            "inet",
            "sysspectogram",
            "ban4",
            "{",
            "type",
            "ipv4_addr",
            ";",
            "flags",
            "timeout",
            ";",
            "}",
        ],
    );
    let _ = run(
        nft,
        &[
            "create",
            "set",
            "inet",
            "sysspectogram",
            "ban6",
            "{",
            "type",
            "ipv6_addr",
            ";",
            "flags",
            "timeout",
            ";",
            "}",
        ],
    );
    let _ = run(
        nft,
        &[
            "create",
            "chain",
            "inet",
            "sysspectogram",
            "input",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-10",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
    );
    let list = Command::new(nft)
        .args(["list", "chain", "inet", "sysspectogram", "input"])
        .output()
        .map_err(|e| format!("nft list: {e}"))?;
    let out = String::from_utf8_lossy(&list.stdout);
    if !out.contains("@ban4") {
        let _ = run(
            nft,
            &[
                "add",
                "rule",
                "inet",
                "sysspectogram",
                "input",
                "ip",
                "saddr",
                "@ban4",
                "drop",
            ],
        );
    }
    if !out.contains("@ban6") {
        let _ = run(
            nft,
            &[
                "add",
                "rule",
                "inet",
                "sysspectogram",
                "input",
                "ip6",
                "saddr",
                "@ban6",
                "drop",
            ],
        );
    }
    Ok(())
}

fn load_never_ban_cidrs() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = fs::read_to_string(NEVER_BAN_FILE) {
        for part in text.split(|c: char| c == ',' || c == '\n' || c == ' ') {
            let t = part.trim();
            if !t.is_empty() && !t.starts_with('#') {
                out.push(t.to_string());
            }
        }
    }
    if let Ok(overlay) = read_overlay(Path::new(SETTINGS_FILE)) {
        if let Some(v) = overlay.get("response.never_ban_cidrs") {
            match v {
                Value::String(s) => {
                    for part in s.split(|c: char| c == ',' || c == ' ') {
                        let t = part.trim();
                        if !t.is_empty() {
                            out.push(t.to_string());
                        }
                    }
                }
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let t = s.trim();
                            if !t.is_empty() {
                                out.push(t.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn ip_in_never_ban(addr: std::net::IpAddr, cidrs: &[String]) -> bool {
    for raw in cidrs {
        if let Ok(one) = raw.parse::<std::net::IpAddr>() {
            if one == addr {
                return true;
            }
            continue;
        }
        if let Some((base, bits)) = raw.split_once('/') {
            let Ok(base_ip) = base.parse::<std::net::IpAddr>() else {
                continue;
            };
            let Ok(prefix) = bits.parse::<u8>() else {
                continue;
            };
            if ip_prefix_contains(base_ip, prefix, addr) {
                return true;
            }
        }
    }
    false
}

fn ip_prefix_contains(base: std::net::IpAddr, prefix: u8, addr: std::net::IpAddr) -> bool {
    match (base, addr) {
        (std::net::IpAddr::V4(b), std::net::IpAddr::V4(a)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(b) & mask) == (u32::from(a) & mask)
        }
        (std::net::IpAddr::V6(b), std::net::IpAddr::V6(a)) => {
            if prefix > 128 {
                return false;
            }
            let b = u128::from(b);
            let a = u128::from(a);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (b & mask) == (a & mask)
        }
        _ => false,
    }
}

fn host_owns_address(addr: std::net::IpAddr) -> bool {
    // Best-effort: parse `ip -j addr` if present.
    let out = Command::new("/sbin/ip")
        .args(["-j", "addr"])
        .output()
        .or_else(|_| Command::new("/usr/bin/ip").args(["-j", "addr"]).output());
    let Ok(out) = out else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) else {
        return false;
    };
    let Some(arr) = v.as_array() else {
        return false;
    };
    for iface in arr {
        let Some(addrs) = iface.get("addr_info").and_then(|a| a.as_array()) else {
            continue;
        };
        for ai in addrs {
            if let Some(local) = ai.get("local").and_then(|x| x.as_str()) {
                if local.parse::<std::net::IpAddr>().ok() == Some(addr) {
                    return true;
                }
            }
        }
    }
    false
}

fn count_set_elements(set_name: &str) -> Result<usize, String> {
    let out = Command::new(nft_bin())
        .args(["-j", "list", "set", "inet", "sysspectogram", set_name])
        .output()
        .map_err(|e| format!("nft list set: {e}"))?;
    if !out.status.success() {
        return Ok(0);
    }
    let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) else {
        return Ok(0);
    };
    let mut n = 0usize;
    if let Some(arr) = v.as_array() {
        for item in arr {
            if let Some(elems) = item.pointer("/set/elem").and_then(|e| e.as_array()) {
                n += elems.len();
            }
        }
    }
    Ok(n)
}

fn ban_add(args: &Value, caller: Caller) -> Result<Value, String> {
    authorize_ban_group(caller)?;
    let ip_raw = args
        .get("ip")
        .and_then(Value::as_str)
        .ok_or("missing ip")?;
    let addr = parse_helper_ban_ip(ip_raw)?;
    let ttl = clamp_ttl(args.get("ttl_sec").and_then(Value::as_u64))?;
    let reason = args
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("guard")
        .chars()
        .take(64)
        .collect::<String>();
    if host_owns_address(addr) {
        return Err("refusing ban of host own address".into());
    }
    let never = load_never_ban_cidrs();
    if ip_in_never_ban(addr, &never) {
        return Err("never_ban skip".into());
    }
    ensure_nft_table()?;
    let set_name = set_for(addr);
    let n = count_set_elements(set_name)?;
    if n >= MAX_BAN_ELEMENTS {
        return Err(format!("ban set full ({MAX_BAN_ELEMENTS})"));
    }
    let ip_s = addr.to_string();
    let ttl_s = format!("{ttl}s");
    let nft = nft_bin();
    // delete+add for refresh timeout
    let _ = run(
        nft,
        &[
            "delete",
            "element",
            "inet",
            "sysspectogram",
            set_name,
            "{",
            &ip_s,
            "}",
        ],
    );
    run(
        nft,
        &[
            "add",
            "element",
            "inet",
            "sysspectogram",
            set_name,
            "{",
            &ip_s,
            "timeout",
            &ttl_s,
            "}",
        ],
    )?;
    eprintln!(
        "sysspectogram-helper ban.add uid={} ip={} ttl={} reason={}",
        caller.uid, ip_s, ttl, reason
    );
    Ok(json!({"ip": ip_s, "ttl_sec": ttl, "set": set_name, "backend": "nft"}))
}

fn ban_del(args: &Value, caller: Caller) -> Result<Value, String> {
    authorize_ban_group(caller)?;
    let ip_raw = args
        .get("ip")
        .and_then(Value::as_str)
        .ok_or("missing ip")?;
    let addr = parse_helper_ban_ip(ip_raw)?;
    let ip_s = addr.to_string();
    let set_name = set_for(addr);
    let nft = nft_bin();
    match run(
        nft,
        &[
            "delete",
            "element",
            "inet",
            "sysspectogram",
            set_name,
            "{",
            &ip_s,
            "}",
        ],
    ) {
        Ok(()) => {}
        Err(e) if e.contains("No such file") || e.to_lowercase().contains("not found") => {}
        Err(e) => return Err(e),
    }
    eprintln!(
        "sysspectogram-helper ban.del uid={} ip={}",
        caller.uid, ip_s
    );
    Ok(json!({"ip": ip_s, "set": set_name}))
}

fn ban_list(caller: Caller) -> Result<Value, String> {
    authorize_ban_group(caller)?;
    ensure_nft_table()?;
    let mut ips = Vec::new();
    for set_name in ["ban4", "ban6"] {
        let out = Command::new(nft_bin())
            .args(["list", "set", "inet", "sysspectogram", set_name])
            .output()
            .map_err(|e| format!("nft list: {e}"))?;
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for token in text.split_whitespace() {
            if let Ok(addr) = token.trim_matches(|c| c == ',' || c == '{' || c == '}').parse::<std::net::IpAddr>()
            {
                ips.push(addr.to_string());
            }
        }
    }
    Ok(json!({"ips": ips}))
}

const JOURNALCTL: &str = "/usr/bin/journalctl";
const JOURNALCTL_ALT: &str = "/bin/journalctl";
const MAX_AUTH_TAIL: u64 = 2000;

fn journalctl_bin() -> &'static str {
    if Path::new(JOURNALCTL).is_file() {
        JOURNALCTL
    } else {
        JOURNALCTL_ALT
    }
}

fn auth_tail(args: &Value, caller: Caller) -> Result<Value, String> {
    authorize_ban_group(caller)?;
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(200);
    if limit == 0 || limit > MAX_AUTH_TAIL {
        return Err(format!("limit must be 1..={MAX_AUTH_TAIL}"));
    }
    let cursor = args
        .get("cursor")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let limit_s = limit.to_string();
    let specs: &[&[&str]] = &[
        &["-u", "sshd"],
        &["-u", "sshd-session"],
        &["-u", "ssh"],
        &["_COMM=sshd-session"],
        &["_COMM=sshd"],
    ];
    let j = journalctl_bin();
    for spec in specs {
        let mut argv: Vec<&str> = Vec::with_capacity(spec.len() + 8);
        argv.extend_from_slice(spec);
        if let Some(c) = cursor {
            argv.push("--cursor");
            argv.push(c);
        }
        argv.push("-n");
        argv.push(&limit_s);
        argv.push("-o");
        argv.push("cat");
        argv.push("--no-pager");
        argv.push("--show-cursor");
        let out = Command::new(j)
            .args(&argv)
            .output()
            .map_err(|e| format!("journalctl: {e}"))?;
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines: Vec<String> = Vec::new();
        let mut next_cursor: Option<String> = None;
        for line in text.lines() {
            if line.starts_with("-- cursor:") {
                next_cursor = Some(line.trim_start_matches("-- cursor:").trim().to_string());
                continue;
            }
            if !line.trim().is_empty() {
                lines.push(line.to_string());
            }
        }
        if !lines.is_empty() {
            let mut data = Map::new();
            data.insert("lines".into(), json!(lines));
            if let Some(c) = next_cursor {
                data.insert("cursor".into(), json!(c));
            }
            return Ok(Value::Object(data));
        }
    }
    Ok(json!({"lines": [], "cursor": null}))
}

fn ban_selftest(caller: Caller) -> Result<Value, String> {
    authorize_ban_group(caller)?;
    ensure_nft_table()?;
    let nft = nft_bin();
    let _ = run(
        nft,
        &[
            "delete",
            "element",
            "inet",
            "sysspectogram",
            "ban4",
            "{",
            SELFTEST_IP,
            "}",
        ],
    );
    run(
        nft,
        &[
            "add",
            "element",
            "inet",
            "sysspectogram",
            "ban4",
            "{",
            SELFTEST_IP,
            "timeout",
            "1s",
            "}",
        ],
    )?;
    let _ = run(
        nft,
        &[
            "delete",
            "element",
            "inet",
            "sysspectogram",
            "ban4",
            "{",
            SELFTEST_IP,
            "}",
        ],
    );
    Ok(json!({"ok": true, "detail": "nft via helper ok"}))
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
    fn helper_ban_ip_rules() {
        assert!(parse_helper_ban_ip("198.51.100.7").is_ok());
        assert!(parse_helper_ban_ip("2001:db8::1").is_ok());
        assert!(parse_helper_ban_ip("0.0.0.0/0").is_err());
        assert!(parse_helper_ban_ip("127.0.0.1").is_err());
        assert!(parse_helper_ban_ip("1.2.3.4; flush").is_err());
        assert!(parse_helper_ban_ip("::1").is_err());
    }

    #[test]
    fn never_ban_prefix_match() {
        let addr: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert!(ip_in_never_ban(addr, &["198.51.100.0/24".into()]));
        assert!(!ip_in_never_ban(addr, &["203.0.113.0/24".into()]));
        assert!(ip_in_never_ban(addr, &["198.51.100.7".into()]));
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
        assert!(validate_change("response.never_ban_cidrs", &json!("0.0.0.0/0")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!("127.0.0.1/32")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!("127.0.0.0/24")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!("0.0.0.1/32")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!("000.0.0.0/32")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!("240.0.0.1/32")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!("255.255.255.255/32")).is_err());
        assert!(validate_change("response.never_ban_cidrs", &json!([1, 2])).is_err());
        assert!(validate_never_ban_cidr("203.0.113.10/32").is_ok());
        assert!(validate_never_ban_cidr("240.0.0.0/24").is_err());
        assert!(validate_change("ui.lang", &json!("ru")).is_ok());
        assert!(validate_change("web.enabled", &json!(true)).is_ok());
        assert!(validate_change("telegram.enabled", &json!(true)).is_ok());
        assert!(validate_change("monitor.interval_sec", &json!(0)).is_err());
        assert!(validate_change("ensemble.risk_threshold", &json!(0.7)).is_ok());
        assert!(validate_change("ensemble.risk_threshold", &json!(1.5)).is_err());
        assert!(validate_change("ssh.PermitRootLogin", &json!("yes")).is_err());
    }
}
