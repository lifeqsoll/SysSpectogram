//! Ignored live witness: an untrusted SIGINT must not look like a clean shutdown.
//!
//! `cargo test` compiles this binary and does not run it. Run explicitly with
//! `cargo test --test kill_witness -- --ignored` only on a machine that can
//! spare a short-lived agent process.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn untrusted_sigint_is_witnessed_not_clean() {
    let bin = agent_bin();
    let root = std::env::temp_dir().join(format!(
        "ssx-kill-witness-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("state")).unwrap();
    let cleanup = Cleanup {
        root: root.clone(),
        pgid: None,
    };

    let jsonl = root.join("alerts.jsonl");
    let socket = root.join("agent.sock");
    let pidfile = root.join("state/agent.pid");
    let watch_pidfile = root.join("state/watchdog.pid");
    let marker = root.join("state/agent.clean_shutdown");

    let mut cmd = Command::new(bin);
    cmd.process_group(0)
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("--phoenix")
        .arg("--mode")
        .arg("userspace")
        .arg("--jsonl")
        .arg(&jsonl)
        .arg("--socket")
        .arg(&socket)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--clean-marker")
        .arg(&marker)
        .arg("--host-id")
        .arg("witness-test")
        .arg("--no-root-watch")
        .arg("--metrics-ms")
        .arg("0")
        .arg("--poll-ms")
        .arg("200")
        .arg("--crossview=false")
        .arg("--kirk-baseline-poll=false");
    let agent = cmd.spawn().expect("spawn agent");
    let mut cleanup = cleanup;
    cleanup.pgid = Some(agent.id());
    let _cleanup = cleanup;
    let _agent = agent;

    let agent_pid = wait_pid(&pidfile, Duration::from_secs(10));
    let _watch_pid = wait_pid(&watch_pidfile, Duration::from_secs(10));

    // Child of this test, not of the agent, so it is outside the trusted tree.
    let kill_status = Command::new("kill")
        .args(["-s", "INT", &agent_pid.to_string()])
        .status()
        .expect("kill");
    assert!(kill_status.success(), "SIGINT from untrusted child failed");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = fs::read_to_string(&jsonl).unwrap_or_default();
        if witnessed(&text) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        witnessed(&text),
        "jsonl missing agent_kirk_agent_kill_attempt or agent_respawned at high/critical: {text}"
    );
    assert!(
        !trusted_clean_marker(&marker),
        "a trusted clean marker must not be what stopped the watchdog"
    );
    let watch_alive = fs::read_to_string(&watch_pidfile)
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
        .map(|pid| Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let respawned = text.contains("\"rule_id\":\"agent_respawned\"");
    assert!(
        watch_alive || respawned,
        "watchdog exited without agent_respawned; a trusted marker would do that"
    );
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

fn witnessed(text: &str) -> bool {
    text.lines().any(|line| {
        let rule = line.contains("\"rule_id\":\"agent_kirk_agent_kill_attempt\"")
            || line.contains("\"rule_id\":\"agent_respawned\"");
        let sev = line.contains("\"severity\":\"critical\"")
            || line.contains("\"severity\":\"high\"");
        rule && sev
    })
}

fn trusted_clean_marker(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return false;
    }
    meta.mode() & 0o077 == 0
}

fn wait_pid(path: &Path, limit: Duration) -> u32 {
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                if Path::new(&format!("/proc/{pid}")).exists() {
                    return pid;
                }
            }
        }
        if start.elapsed() > limit {
            panic!("pidfile {} not live within {limit:?}", path.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Cleanup {
    root: PathBuf,
    pgid: Option<u32>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid {
            let _ = Command::new("kill")
                .args(["-9", &format!("-{pgid}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
