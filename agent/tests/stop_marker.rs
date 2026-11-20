//! Stop-marker trust is HMAC, not file mode and not signal si_pid.
//!
//! Forging `si_pid=1` / `SI_QUEUE` with `rt_sigqueueinfo` needs root and is not
//! run here. `phoenix::decide_clean_shutdown` unit tests cover that decision:
//! signature absent → unclean, even when si_pid is 1 and the sender is "trusted".

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "forging si_pid via rt_sigqueueinfo requires root; unit test forged_si_queue_from_pid_one_is_not_clean_without_signature"]
fn forged_si_pid_clean_shutdown_requires_root() {
    // Live reproduction: root queues SIGTERM with si_code=SI_QUEUE and si_pid=1.
    // Without an HMAC stop marker the agent must not set clean_exit, must emit
    // agent_kirk_agent_kill_attempt, and the watchdog must respawn.
    eprintln!("live si_pid forge is not automated; it needs root");
}

#[test]
fn unsigned_clean_marker_does_not_retire_watchdog() {
    let bin = agent_bin();
    let root = std::env::temp_dir().join(format!(
        "ssx-stop-marker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("state")).unwrap();
    let mut cleanup = Cleanup {
        root: root.clone(),
        child: None,
    };

    let jsonl = root.join("alerts.jsonl");
    let marker = root.join("state/agent.clean_shutdown");
    let secret_path = root.join("state/agent_hmac.secret");
    let watch_pidfile = root.join("state/agent.pid");
    let watch_pidfile_self = root.join("state/watchdog.pid");
    let stderr_path = root.join("watch.stderr");

    fs::write(&secret_path, "stop-marker-test-secret\n").unwrap();
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
    // Owner-only legacy body. Mode alone used to retire the watchdog.
    let mut marker_file = File::create(&marker).unwrap();
    marker_file.write_all(b"clean\n").unwrap();
    drop(marker_file);
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();

    let dead = unused_pid();
    fs::write(&watch_pidfile, format!("{dead}\n")).unwrap();

    let stderr = File::create(&stderr_path).unwrap();
    let mut cmd = Command::new(&bin);
    cmd.process_group(0)
        .current_dir(&root)
        .env_remove("SYSSPECTOGRAM_AGENT_HMAC")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .arg("--role")
        .arg("watchdog")
        .arg("--watch-pidfile")
        .arg(&watch_pidfile)
        .arg("--pidfile")
        .arg(&watch_pidfile_self)
        .arg("--clean-marker")
        .arg(&marker)
        .arg("--hmac-secret")
        .arg(&secret_path)
        .arg("--respawn-exe")
        .arg(root.join("no-such-respawn-exe"))
        .arg("--jsonl")
        .arg(&jsonl)
        .arg("--host-id")
        .arg("stop-marker-test");
    let child = cmd.spawn().expect("spawn watchdog");
    let child_pid = child.id();
    cleanup.child = Some(child);

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = fs::read_to_string(&jsonl).unwrap_or_default();
        if text.contains("\"rule_id\":\"agent_respawned\"") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let alive = Path::new(&format!("/proc/{child_pid}")).exists();
    let err = fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        !err.contains("HMAC secret missing"),
        "test secret was not loaded, so a retire skip would be vacuous: {err}"
    );
    assert!(
        text.contains("\"rule_id\":\"agent_respawned\""),
        "unsigned owner-only `clean` marker must not retire the watchdog: jsonl={text} stderr={err}"
    );
    assert!(
        alive,
        "watchdog exited on an unsigned marker (that used to look like CLEAN_SHUTDOWN)"
    );
    assert!(
        !marker.exists(),
        "unclean marker should be deleted before respawn"
    );
    drop(cleanup);
}

fn unused_pid() -> u32 {
    for pid in (100_000u32..100_200).rev() {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return pid;
        }
    }
    2_000_000_000
}

fn agent_bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_sysspectogram_agent") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("sysspectogram-agent")
}

struct Cleanup {
    root: PathBuf,
    child: Option<std::process::Child>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
