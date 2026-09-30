//! Phoenix twin: mutual watchdog (agent ↔ watchdog process).
//!
//! Primary outer shell remains systemd Restart=. This twin stops dumb `kill -9`
//! of a single process when both run under the same service or supervisor.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
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
) -> io::Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.arg("--role")
        .arg("watchdog")
        .arg("--watch-pidfile")
        .arg(pidfile_agent)
        .arg("--pidfile")
        .arg(pidfile_watch)
        .arg("--respawn-exe")
        .arg(exe);
    for a in agent_args {
        cmd.arg("--respawn-arg").arg(a);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

/// Watchdog main loop: if watched pid dies without clean marker, respawn.
pub fn run_watchdog_loop(
    watch_pidfile: &Path,
    clean_marker: &Path,
    respawn_exe: &Path,
    respawn_args: &[String],
    running: &std::sync::atomic::AtomicBool,
) {
    use std::sync::atomic::Ordering;
    let mut last_respawn = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now);
    let mut child: Option<Child> = None;

    while running.load(Ordering::SeqCst) {
        // Prefer tracking spawned child; else pidfile
        let alive = if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(None) => true,
                Ok(Some(_)) => {
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
            if clean_marker.exists() {
                let _ = fs::remove_file(clean_marker);
                eprintln!("[sysspectogram-watch] CLEAN_SHUTDOWN seen — exit");
                break;
            }
            if last_respawn.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            eprintln!("[sysspectogram-watch] peer dead — respawning agent");
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
