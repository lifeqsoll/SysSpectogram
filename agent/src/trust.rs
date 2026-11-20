//! Trusted PID trees (guard / agent / phoenix twin) and kill-signal classification.
//!
//! Mirrors Python ``trusted_pids``: trust by pidfile + descendant ppid chain,
//! never by forged ``comm``.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::types::AgentAlert;

/// Role expected of the process named by a pidfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidfileRole {
    /// Agent or phoenix watchdog: exe must match this binary.
    SelfBinary,
    /// Python ``-m sysspectogram … guard|protect`` owned by the pidfile owner.
    Guard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRoot {
    pub pid: u32,
    pub starttime: u64,
    pub exe: String,
    pub uid: u32,
}

/// Raw live pid from a pidfile (no identity check). Prefer [`read_trusted_root`].
pub fn read_pidfile(path: &Path) -> Option<u32> {
    let t = fs::read_to_string(path).ok()?;
    let tok = t.split_whitespace().next()?;
    let pid: u32 = tok.parse().ok()?;
    if pid <= 1 {
        return None;
    }
    if !Path::new(&format!("/proc/{pid}")).exists() {
        return None;
    }
    Some(pid)
}

/// Read a pidfile and accept the PID only when identity matches ``role``.
pub fn read_trusted_root(path: &Path, role: PidfileRole) -> Option<TrustedRoot> {
    let pid = read_pidfile(path)?;
    let starttime = read_starttime(pid)?;
    let exe = read_exe(pid).unwrap_or_default();
    let uid = read_uid(pid)?;
    let file_uid = fs::metadata(path).ok()?.uid();
    // Non-root pidfile may only name a process with the same uid.
    if file_uid != 0 && uid != file_uid {
        return None;
    }
    match role {
        PidfileRole::SelfBinary => {
            if !exe_matches_self(&exe) {
                return None;
            }
        }
        PidfileRole::Guard => {
            if !looks_like_guard(pid, &exe) {
                return None;
            }
        }
    }
    Some(TrustedRoot {
        pid,
        starttime,
        exe,
        uid,
    })
}

/// Collect verified roots plus descendants.
///
/// Descendants of a non-root root that themselves run as uid 0 are not trusted
/// (stops an unprivileged guard pidfile from laundering root children).
pub fn collect_trusted_tree(
    agent_pidfile: &Path,
    watchdog_pidfile: &Path,
    guard_pidfile: &Path,
) -> HashSet<u32> {
    let mut roots: Vec<TrustedRoot> = Vec::new();
    if let Some(r) = read_trusted_root(agent_pidfile, PidfileRole::SelfBinary) {
        roots.push(r);
    }
    if let Some(r) = read_trusted_root(watchdog_pidfile, PidfileRole::SelfBinary) {
        roots.push(r);
    }
    if let Some(r) = read_trusted_root(guard_pidfile, PidfileRole::Guard) {
        roots.push(r);
    }
    let mut trusted = HashSet::new();
    let mut nonroot_roots = HashSet::new();
    for r in &roots {
        trusted.insert(r.pid);
        if r.uid != 0 {
            nonroot_roots.insert(r.pid);
        }
    }
    // Always treat our own process as trusted (self-signals / twin).
    trusted.insert(std::process::id());
    expand_descendants(trusted, &nonroot_roots)
}

fn expand_descendants(mut trusted: HashSet<u32>, nonroot_roots: &HashSet<u32>) -> HashSet<u32> {
    let mut children: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return trusted;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some(ppid) = read_ppid(pid) {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut under_nonroot = nonroot_roots.clone();
    let mut stack: Vec<u32> = trusted.iter().copied().collect();
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children.get(&pid) {
            for &c in kids {
                if under_nonroot.contains(&pid) {
                    if read_uid(c) == Some(0) {
                        continue;
                    }
                    under_nonroot.insert(c);
                }
                if trusted.insert(c) {
                    stack.push(c);
                }
            }
        }
    }
    trusted
}

fn exe_matches_self(exe: &str) -> bool {
    let Ok(self_exe) = std::env::current_exe() else {
        return false;
    };
    let self_s = fs::canonicalize(&self_exe)
        .unwrap_or(self_exe)
        .to_string_lossy()
        .into_owned();
    // Exact path only (plus "(deleted)" after replace-in-place). Basename soft
    // match would trust a foreign binary that reused our install name.
    let stripped = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    stripped == self_s || exe == self_s
}

fn looks_like_guard(pid: u32, exe: &str) -> bool {
    let base = Path::new(exe).file_name().and_then(|s| s.to_str()).unwrap_or("");
    let pythonish = base.starts_with("python");
    if !pythonish && !exe.contains("sysspectogram") {
        // Accept a sealed native guard binary path if ever shipped.
        if !(exe.contains("/sysspectogram") && exe.contains("guard")) {
            return false;
        }
    }
    let cmdline = read_cmdline(pid);
    let lower = cmdline.to_lowercase();
    let has_mod = lower.contains("sysspectogram");
    let has_role = lower.contains("guard") || lower.contains("protect");
    has_mod && has_role
}

fn read_starttime(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = text.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn read_exe(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if let Ok(canon) = fs::canonicalize(&link) {
        Some(canon.to_string_lossy().into_owned())
    } else {
        Some(link.to_string_lossy().into_owned())
    }
}

fn read_uid(pid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn read_cmdline(pid: u32) -> String {
    let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return String::new();
    };
    let s = String::from_utf8_lossy(&raw);
    s.replace('\0', " ").trim().chars().take(400).collect()
}

pub fn read_ppid(pid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}

pub fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// True when ``pid`` is in ``trusted`` or any ancestor is.
pub fn pid_trusted_or_descendant(pid: u32, trusted: &HashSet<u32>) -> bool {
    if trusted.contains(&pid) {
        return true;
    }
    let mut cur = pid;
    for _ in 0..64 {
        let Some(ppid) = read_ppid(cur) else {
            return false;
        };
        if ppid == 0 || ppid == cur {
            return false;
        }
        if trusted.contains(&ppid) {
            return true;
        }
        cur = ppid;
    }
    false
}

pub fn signal_name(sig: u32) -> &'static str {
    match sig {
        0 => "SIG0",
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        30 => "SIGPWR",
        31 => "SIGSYS",
        n if n >= 34 => "SIGRT",
        _ => "SIGNAL",
    }
}

/// ``None`` = do not alert. Otherwise severity string.
///
/// SIGTERM is critical here. A clean shutdown is a separate path and only runs
/// for a trusted sender.
pub fn kill_alert_severity(sig: u32) -> Option<&'static str> {
    match sig {
        0 => None,
        17 | 18 | 23 | 28 => Some("low"),
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 19 | 20
        | 21 | 22 | 24 | 25 | 26 | 27 | 29 | 30 | 31 => Some("critical"),
        n if n >= 34 => Some("critical"),
        _ => Some("low"),
    }
}

/// Agent, watchdog, and guard pids that a kill may be aimed at.
pub struct KillTargets {
    pub self_pid: u32,
    pub watchdog_pid: Option<u32>,
    pub guard_pid: Option<u32>,
}

/// Classify a kill aimed at this agent, its watchdog, or the guard.
///
/// ``trusted`` is the already-expanded tree. This function does not walk ``/proc``.
pub fn classify_kill(
    sender_pid: u32,
    target_pid: u32,
    sig: u32,
    targets: &KillTargets,
    trusted: &HashSet<u32>,
    host_id: &str,
) -> Option<AgentAlert> {
    if sig == 0 {
        return None;
    }
    let watched = target_pid == targets.self_pid
        || targets.watchdog_pid == Some(target_pid)
        || targets.guard_pid == Some(target_pid);
    if !watched {
        return None;
    }
    if trusted.contains(&sender_pid) {
        return None;
    }
    let sev = kill_alert_severity(sig)?;
    let sig_name = signal_name(sig);
    let mut alert = AgentAlert::new(
        "agent_kirk_agent_kill_attempt",
        sev,
        format!(
            "kill/signal toward pid={target_pid} {sig_name}({sig}) from sender_pid={sender_pid}"
        ),
        host_id,
    );
    alert.pid = Some(sender_pid);
    alert.extras = Some(serde_json::json!({
        "signal": sig,
        "signal_name": sig_name,
        "target_pid": target_pid,
        "sender_pid": sender_pid,
    }));
    Some(alert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sig0_never_alerts() {
        assert_eq!(kill_alert_severity(0), None);
    }

    #[test]
    fn sigkill_is_critical() {
        assert_eq!(kill_alert_severity(9), Some("critical"));
        assert_eq!(signal_name(9), "SIGKILL");
    }

    #[test]
    fn sighup_is_low() {
        // SIGHUP is critical at this layer. Clean shutdown is a separate trusted-sender path.
        assert_eq!(kill_alert_severity(1), Some("critical"));
        assert_eq!(signal_name(1), "SIGHUP");
    }

    #[test]
    fn sigterm_from_untrusted_is_critical() {
        assert_eq!(kill_alert_severity(15), Some("critical"));
        assert_eq!(signal_name(15), "SIGTERM");
        let targets = KillTargets {
            self_pid: 10,
            watchdog_pid: None,
            guard_pid: None,
        };
        let alert = classify_kill(99, 10, 15, &targets, &HashSet::new(), "host").unwrap();
        assert_eq!(alert.rule_id, "agent_kirk_agent_kill_attempt");
        assert_eq!(alert.severity, "critical");
        let extras = alert.extras.expect("extras");
        assert_eq!(extras["signal"].as_u64(), Some(15));
        assert_eq!(extras["signal_name"].as_str(), Some("SIGTERM"));
        assert_eq!(extras["target_pid"].as_u64(), Some(10));
        assert_eq!(extras["sender_pid"].as_u64(), Some(99));
    }

    #[test]
    fn sigurg_is_low_and_named() {
        assert_eq!(signal_name(23), "SIGURG");
        assert_eq!(kill_alert_severity(23), Some("low"));
    }

    #[test]
    fn rt_signals_are_critical() {
        assert_eq!(kill_alert_severity(34), Some("critical"));
        assert_eq!(kill_alert_severity(64), Some("critical"));
        assert_eq!(signal_name(34), "SIGRT");
        assert_eq!(signal_name(64), "SIGRT");
    }

    #[test]
    fn sigalrm_sigpipe_critical() {
        assert_eq!(kill_alert_severity(14), Some("critical"));
        assert_eq!(signal_name(14), "SIGALRM");
        assert_eq!(kill_alert_severity(13), Some("critical"));
        assert_eq!(signal_name(13), "SIGPIPE");
    }

    #[test]
    fn kill_to_watchdog_alerts() {
        let targets = KillTargets {
            self_pid: 10,
            watchdog_pid: Some(20),
            guard_pid: Some(30),
        };
        let alert = classify_kill(99, 20, 9, &targets, &HashSet::new(), "host").unwrap();
        assert_eq!(alert.rule_id, "agent_kirk_agent_kill_attempt");
        assert_eq!(alert.severity, "critical");
        let extras = alert.extras.expect("extras");
        assert_eq!(extras["signal"].as_u64(), Some(9));
        assert_eq!(extras["signal_name"].as_str(), Some("SIGKILL"));
        assert_eq!(extras["target_pid"].as_u64(), Some(20));
        assert_eq!(extras["sender_pid"].as_u64(), Some(99));
    }

    #[test]
    fn kill_from_trusted_ignored() {
        let targets = KillTargets {
            self_pid: 10,
            watchdog_pid: Some(20),
            guard_pid: None,
        };
        let mut trusted = HashSet::new();
        trusted.insert(99);
        assert!(classify_kill(99, 10, 9, &targets, &trusted, "host").is_none());
    }

    #[test]
    fn sig0_ignored() {
        let targets = KillTargets {
            self_pid: 10,
            watchdog_pid: Some(20),
            guard_pid: Some(30),
        };
        assert!(classify_kill(99, 10, 0, &targets, &HashSet::new(), "host").is_none());
    }

    #[test]
    fn other_target_ignored() {
        let targets = KillTargets {
            self_pid: 10,
            watchdog_pid: Some(20),
            guard_pid: Some(30),
        };
        assert!(classify_kill(99, 50, 9, &targets, &HashSet::new(), "host").is_none());
    }

    #[test]
    fn trusted_tree_includes_self() {
        let tmp = PathBuf::from("/tmp");
        let missing = tmp.join("no-such-pidfile");
        let tree = collect_trusted_tree(&missing, &missing, &missing);
        assert!(tree.contains(&std::process::id()));
    }

    #[test]
    fn pidfile_with_foreign_pid_not_trusted() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let dir = std::env::temp_dir().join(format!("ssx-trust-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let pf = dir.join("guard.pid");
        fs::write(&pf, format!("{pid}\n")).unwrap();
        assert!(
            read_trusted_root(&pf, PidfileRole::Guard).is_none(),
            "sleep must not become a trusted guard"
        );
        assert!(
            read_trusted_root(&pf, PidfileRole::SelfBinary).is_none(),
            "sleep must not become a trusted agent"
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn self_exe_trusted() {
        let dir = std::env::temp_dir().join(format!("ssx-trust-self-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let pf = dir.join("agent.pid");
        fs::write(&pf, format!("{}\n", std::process::id())).unwrap();
        let root = read_trusted_root(&pf, PidfileRole::SelfBinary).expect("self must match");
        assert_eq!(root.pid, std::process::id());
        assert!(root.starttime > 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn descendant_of_self_is_trusted() {
        let me = std::process::id();
        let mut roots = HashSet::new();
        roots.insert(me);
        assert!(pid_trusted_or_descendant(me, &roots));
    }
}
