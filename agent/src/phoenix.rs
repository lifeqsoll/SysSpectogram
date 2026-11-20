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
pub fn spawn_watchdog(
    exe: &Path,
    agent_args: &[String],
    pidfile_agent: &Path,
    pidfile_watch: &Path,
    jsonl: Option<&Path>,
    host_id: &str,
    clean_marker: &Path,
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
        .arg(clean_marker);
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

/// Owner-only marker written on a trusted clean shutdown.
///
/// Refuses a symlink at the final path. Writes a temp file in the same
/// directory (mode `0o600`, `O_NOFOLLOW`) and renames it into place.
pub fn write_clean_marker(path: &Path) -> io::Result<()> {
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
        writeln!(f, "clean")?;
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
    use std::os::unix::fs::MetadataExt;
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
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

/// Watchdog main loop: trusted clean marker exits; anything else respawns.
pub fn run_watchdog_loop(
    watch_pidfile: &Path,
    clean_marker: &Path,
    respawn_exe: &Path,
    respawn_args: &[String],
    running: &std::sync::atomic::AtomicBool,
    jsonl: Option<&Path>,
    host_id: &str,
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
            if clean_marker_trusted(clean_marker) {
                let _ = fs::remove_file(clean_marker);
                eprintln!("[sysspectogram-watch] CLEAN_SHUTDOWN seen — exit");
                break;
            }
            // A marker that fails the owner/mode check is deleted and treated
            // as an unclean death (respawn, do not leave the loop).
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
}
