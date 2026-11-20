//! Phoenix twin: mutual watchdog (agent ↔ watchdog process).
//!
//! Primary outer shell remains systemd Restart=. This twin stops dumb `kill -9`
//! of a single process when both run under the same service or supervisor.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Write our pid for the peer / guard.
pub fn write_pidfile(path: &Path, pid: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    writeln!(f, "{pid}")?;
    Ok(())
}

pub fn read_pidfile(path: &Path) -> Option<u32> {
    let t = fs::read_to_string(path).ok()?;
    t.trim().parse().ok()
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Spawn watchdog child that respawns agent if it dies unexpectedly.
#[allow(clippy::too_many_arguments)] // CLI surface mirrors systemd ExecStart flags
pub fn spawn_watchdog(
    exe: &Path,
    agent_args: &[String],
    pidfile_agent: &Path,
    pidfile_watch: &Path,
    jsonl: Option<&Path>,
    host_id: &str,
    clean_marker: &Path,
    hmac_secret: &Path,
) -> io::Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.arg("--role")
        .arg("watchdog")
        .arg("--watch-pidfile")
        .arg(pidfile_agent)
        .arg("--pidfile")
        .arg(pidfile_watch)
        .arg("--respawn-exe")
        .arg(exe)
        .arg("--host-id")
        .arg(host_id)
        .arg("--clean-marker")
        .arg(clean_marker)
        .arg("--hmac-secret")
        .arg(hmac_secret);
    if let Some(path) = jsonl {
        cmd.arg("--jsonl").arg(path);
    }
    for a in agent_args {
        cmd.arg("--respawn-arg").arg(a);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

/// Legacy unsigned body (`clean`). Not a phoenix retirement signal.
///
/// Refuses a symlink at the final path. Writes a temp file in the same
/// directory (mode `0o600`, `O_NOFOLLOW`) and renames it into place.
/// Kept for unit tests that prove unsigned markers never retire the watchdog.
#[allow(dead_code)]
pub fn write_clean_marker(path: &Path) -> io::Result<()> {
    write_owner_only(path, "clean\n")
}

/// HMAC-signed stop marker. Two lines, owner-only, same write rules as
/// [`write_clean_marker`]. The MAC covers the canonical line only.
pub fn write_signed_stop_marker(path: &Path, secret: &str, agent_pid: u32) -> io::Result<()> {
    if secret.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hmac secret missing",
        ));
    }
    let canon = format!("v1|stop|{}|{agent_pid}", unix_secs());
    let mac = crate::auth::sign_hex(secret.trim(), &canon);
    write_owner_only(path, &format!("{canon}\nhmac={mac}\n"))
}

fn write_owner_only(path: &Path, body: &str) -> io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "clean marker path is a symlink",
            ));
        }
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => {
            fs::create_dir_all(p)?;
            p.to_path_buf()
        }
        _ => PathBuf::from("."),
    };
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("clean"));
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = parent.join(tmp_name);
    let _ = fs::remove_file(&tmp);
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let mut f = opts.open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// True when `path` is a non-symlink owner-only file owned by the right uid.
///
/// Root (euid 0) requires owner uid 0. Any other euid requires the owner to
/// be that euid, so unit tests can run without root.
pub fn clean_marker_trusted(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => owner_only_meta(&meta),
        Err(_) => false,
    }
}

/// Clean shutdown is true only when a verified HMAC stop marker is already present.
///
/// `si_pid`, `si_code` (including `SI_QUEUE` / `SI_USER` / `SI_KERNEL`), and
/// trusted-tree membership are ignored. A forged `si_pid=1` is not a clean stop.
pub fn decide_clean_shutdown(
    signal: i32,
    si_pid: u32,
    si_code: i32,
    trusted: bool,
    signature_present: bool,
) -> bool {
    let _ = (signal, si_pid, si_code, trusted);
    signature_present
}

const STOP_MARKER_MAX_AGE_SEC: i64 = 120;
const STOP_MARKER_MAX_FUTURE_SEC: i64 = 30;
const STOP_MARKER_MAX_BYTES: u64 = 512;

/// Owner-only file mode plus a fresh HMAC stop marker for `expected_agent_pid`.
///
/// Missing secret, unsigned `clean`, wide mode, symlink, bad MAC, skew, or a
/// pid mismatch are all unclean.
pub fn clean_marker_hmac_ok(path: &Path, secret: Option<&str>, expected_agent_pid: u32) -> bool {
    stop_marker_valid(path, secret, expected_agent_pid)
}

/// True when `path` is an owner-only HMAC stop marker for `expected_agent_pid`.
pub fn stop_marker_valid(path: &Path, secret: Option<&str>, expected_agent_pid: u32) -> bool {
    let Some(secret) = secret.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if expected_agent_pid == 0 {
        return false;
    }
    let Some((meta, text)) = read_marker_nofollow(path) else {
        return false;
    };
    if !owner_only_meta(&meta) {
        return false;
    }
    let Some((canon, mac_hex)) = split_stop_marker(&text) else {
        return false;
    };
    if !crate::auth::verify_hex(secret, canon, mac_hex) {
        return false;
    }
    let Some((ts, pid)) = parse_stop_canon(canon) else {
        return false;
    };
    pid == expected_agent_pid && ts_in_window(ts, unix_secs())
}

fn owner_only_meta(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return false;
    }
    if meta.mode() & 0o077 != 0 {
        return false;
    }
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        meta.uid() == 0
    } else {
        meta.uid() == euid
    }
}

fn read_marker_nofollow(path: &Path) -> Option<(fs::Metadata, String)> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return None;
        }
        if meta.len() > STOP_MARKER_MAX_BYTES {
            return None;
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let f = opts.open(path).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > STOP_MARKER_MAX_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    f.take(STOP_MARKER_MAX_BYTES).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8(buf).ok()?;
    Some((meta, text))
}

fn split_stop_marker(text: &str) -> Option<(&str, &str)> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let (canon, hmac_line) = text.split_once('\n')?;
    if canon.is_empty() || hmac_line.is_empty() || hmac_line.contains('\n') {
        return None;
    }
    let mac = hmac_line.strip_prefix("hmac=")?;
    if mac.len() != 64 {
        return None;
    }
    Some((canon, mac))
}

fn parse_stop_canon(canon: &str) -> Option<(i64, u32)> {
    let mut parts = canon.split('|');
    let ver = parts.next()?;
    let kind = parts.next()?;
    let ts = parts.next()?;
    let pid = parts.next()?;
    if parts.next().is_some() || ver != "v1" || kind != "stop" {
        return None;
    }
    if !canonical_uint(ts) || !canonical_uint(pid) {
        return None;
    }
    Some((ts.parse().ok()?, pid.parse().ok()?))
}

fn canonical_uint(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s.len() == 1 || !s.starts_with('0'))
}

fn ts_in_window(ts: i64, now: i64) -> bool {
    ts >= now.saturating_sub(STOP_MARKER_MAX_AGE_SEC)
        && ts <= now.saturating_add(STOP_MARKER_MAX_FUTURE_SEC)
}

fn unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Watchdog main loop: HMAC stop marker exits; anything else respawns.
#[allow(clippy::too_many_arguments)] // mirrors spawn_watchdog / CLI flags
pub fn run_watchdog_loop(
    watch_pidfile: &Path,
    clean_marker: &Path,
    respawn_exe: &Path,
    respawn_args: &[String],
    running: &std::sync::atomic::AtomicBool,
    jsonl: Option<&Path>,
    host_id: &str,
    hmac_secret: Option<&str>,
) {
    use std::sync::atomic::Ordering;
    let mut last_respawn = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now);
    let mut child: Option<Child> = None;
    let mut noted_exit: Option<ExitStatus> = None;

    // Variant A: the surviving agent witnesses kills aimed at the watchdog or
    // the guard. Do not attach a second sys_enter_kill probe in this process.
    // Variant B: death of the agent itself is `agent_respawned` below.
    while running.load(Ordering::SeqCst) {
        // Prefer tracking spawned child; else pidfile
        let alive = if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    noted_exit = Some(status);
                    child = None;
                    false
                }
                Err(_) => false,
            }
        } else if let Some(pid) = read_pidfile(watch_pidfile) {
            pid_alive(pid)
        } else {
            false
        };

        if !alive {
            let expected_pid = read_pidfile(watch_pidfile).unwrap_or(0);
            if clean_marker_hmac_ok(clean_marker, hmac_secret, expected_pid) {
                let _ = fs::remove_file(clean_marker);
                eprintln!("[sysspectogram-watch] signed CLEAN_SHUTDOWN seen — exit");
                break;
            }
            // Unsigned, forged, wide-mode, or symlink markers are deleted and
            // treated as an unclean death (respawn, do not leave the loop).
            if fs::symlink_metadata(clean_marker).is_ok() {
                let _ = fs::remove_file(clean_marker);
            }
            if last_respawn.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            eprintln!("[sysspectogram-watch] peer dead — respawning agent");
            append_respawn_alert(jsonl, host_id, noted_exit.as_ref());
            noted_exit = None;
            // Loud marker for operators / log shippers (guard Dead-man also fires).
            let _ = fs::write(
                "state/watchdog_last_respawn.txt",
                format!(
                    "ts_unix={}\nreason=unexpected_peer_death\n",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                ),
            );
            last_respawn = Instant::now();
            match Command::new(respawn_exe)
                .args(respawn_args)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
            {
                Ok(c) => child = Some(c),
                Err(e) => eprintln!("[sysspectogram-watch] respawn failed: {e}"),
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn append_respawn_alert(jsonl: Option<&Path>, host_id: &str, status: Option<&ExitStatus>) {
    let Some(path) = jsonl else {
        return;
    };
    let message = match status {
        Some(st) => format!("unexpected peer death status={st}"),
        None => "unexpected peer death".to_string(),
    };
    let alert = crate::types::AgentAlert::new("agent_respawned", "high", message, host_id);
    if let Err(e) = crate::emit::append_jsonl(path, &alert) {
        eprintln!("[sysspectogram-watch] agent_respawned: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    fn euid() -> u32 {
        let text = fs::read_to_string("/proc/self/status").unwrap();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let effective = rest.split_whitespace().nth(1).unwrap();
                return effective.parse().unwrap();
            }
        }
        panic!("no Uid in /proc/self/status");
    }

    fn write_mode(path: &Path, mode: u32) {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(mode);
        opts.open(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn clean_marker_rejects_wide_mode_and_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "ssx-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();

        let wide = dir.join("wide");
        write_mode(&wide, 0o644);
        assert!(
            !clean_marker_trusted(&wide),
            "0o644 must not count as a trusted clean marker"
        );

        let tight = dir.join("tight");
        write_mode(&tight, 0o600);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&tight, &link).unwrap();
        assert!(
            !clean_marker_trusted(&link),
            "symlink must not count as a trusted clean marker"
        );

        if euid() != 0 {
            assert!(
                clean_marker_trusted(&tight),
                "0o600 owned by the current user is trusted when not root"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_clean_marker_is_owner_only_and_refuses_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "ssx-marker-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("agent.clean_shutdown");
        write_clean_marker(&marker).unwrap();
        let meta = fs::symlink_metadata(&marker).unwrap();
        assert!(!meta.file_type().is_symlink());
        assert_eq!(meta.mode() & 0o077, 0);
        if euid() != 0 {
            assert!(clean_marker_trusted(&marker));
        }

        let link = dir.join("linked");
        std::os::unix::fs::symlink(&marker, &link).unwrap();
        assert!(write_clean_marker(&link).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    fn marker_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ssx-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_body(path: &Path, body: &str, mode: u32) {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(mode);
        let mut f = opts.open(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn signed_body(secret: &str, ts: i64, pid: u32) -> String {
        let canon = format!("v1|stop|{ts}|{pid}");
        let mac = crate::auth::sign_hex(secret, &canon);
        format!("{canon}\nhmac={mac}\n")
    }

    #[test]
    fn forged_si_queue_from_pid_one_is_not_clean_without_signature() {
        // Linux SI_USER=0, SI_QUEUE=-1, SI_KERNEL=0x80. si_pid=1 and a trusted
        // tree must not authorize CLEAN_SHUTDOWN.
        assert!(!decide_clean_shutdown(libc::SIGTERM, 1, -1, true, false));
        assert!(!decide_clean_shutdown(libc::SIGTERM, 1, 0, true, false));
        assert!(!decide_clean_shutdown(libc::SIGTERM, 1, 0x80, true, false));
        assert!(!decide_clean_shutdown(libc::SIGINT, 1, -1, false, false));
        assert!(decide_clean_shutdown(libc::SIGTERM, 1, -1, true, true));
    }

    #[test]
    fn signed_stop_marker_valid_until_tampered_or_unsigned() {
        let dir = marker_dir("stop-ok");
        let marker = dir.join("agent.clean_shutdown");
        let secret = "unit-secret";
        let pid = 4242u32;
        write_signed_stop_marker(&marker, secret, pid).unwrap();
        let text = fs::read_to_string(&marker).unwrap();
        let mut lines = text.lines();
        let canon = lines.next().unwrap();
        let hmac_line = lines.next().unwrap();
        assert!(lines.next().is_none());
        assert!(canon.starts_with("v1|stop|"));
        assert!(canon.ends_with(&format!("|{pid}")));
        assert_eq!(hmac_line.len(), "hmac=".len() + 64);
        assert!(stop_marker_valid(&marker, Some(secret), pid));
        assert!(clean_marker_hmac_ok(&marker, Some(secret), pid));
        let no_final_nl = text.trim_end_matches('\n');
        write_body(&marker, no_final_nl, 0o600);
        assert!(
            stop_marker_valid(&marker, Some(secret), pid),
            "trailing newline after hmac= is optional"
        );
        write_body(&marker, &text, 0o600);
        assert!(!stop_marker_valid(&marker, None, pid));
        assert!(!stop_marker_valid(&marker, Some(""), pid));
        assert!(!stop_marker_valid(&marker, Some("other-secret"), pid));
        assert!(!stop_marker_valid(&marker, Some(secret), pid + 1));
        assert!(!stop_marker_valid(&marker, Some(secret), 0));

        let mut raw = text.into_bytes();
        let pos = raw.windows(5).position(|w| w == b"hmac=").unwrap() + 5;
        raw[pos] = if raw[pos] == b'0' { b'1' } else { b'0' };
        write_body(&marker, &String::from_utf8(raw).unwrap(), 0o600);
        assert!(!stop_marker_valid(&marker, Some(secret), pid));

        write_body(&marker, "clean\n", 0o600);
        assert!(
            !stop_marker_valid(&marker, Some(secret), pid),
            "legacy unsigned clean marker is not a signed stop"
        );
        assert!(!clean_marker_hmac_ok(&marker, Some(secret), pid));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stop_marker_rejects_skew_wide_mode_and_symlink() {
        let dir = marker_dir("stop-skew");
        let marker = dir.join("agent.clean_shutdown");
        let secret = "unit-secret";
        let pid = 77u32;
        let now = unix_secs();
        write_body(&marker, &signed_body(secret, now - 10, pid), 0o600);
        assert!(stop_marker_valid(&marker, Some(secret), pid));
        write_body(&marker, &signed_body(secret, now - 200, pid), 0o600);
        assert!(!stop_marker_valid(&marker, Some(secret), pid));
        write_body(&marker, &signed_body(secret, now + 60, pid), 0o600);
        assert!(!stop_marker_valid(&marker, Some(secret), pid));

        write_body(&marker, &signed_body(secret, now, pid), 0o644);
        assert!(!stop_marker_valid(&marker, Some(secret), pid));

        let tight = dir.join("tight");
        write_body(&tight, &signed_body(secret, now, pid), 0o600);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&tight, &link).unwrap();
        assert!(!stop_marker_valid(&link, Some(secret), pid));
        assert!(write_signed_stop_marker(&link, secret, pid).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
