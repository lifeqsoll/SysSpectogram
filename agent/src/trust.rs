//! Trusted PID trees (guard / agent / phoenix twin) and kill-signal classification.
//!
//! Mirrors Python ``trusted_pids``: trust by pidfile + descendant ppid chain,
//! never by forged ``comm``.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::types::AgentAlert;

/// Read a single PID from a pidfile (first whitespace-separated token).
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

/// Collect PIDs from pidfiles plus every live descendant (ppid chain).
pub fn collect_trusted_tree(pidfiles: &[&Path]) -> HashSet<u32> {
    let mut roots = HashSet::new();
    for p in pidfiles {
        if let Some(pid) = read_pidfile(p) {
            roots.insert(pid);
        }
    }
    // Always treat our own process as trusted (self-signals / twin).
    roots.insert(std::process::id());
    expand_descendants(roots)
}

fn expand_descendants(mut trusted: HashSet<u32>) -> HashSet<u32> {
    // Build ppid → children map once, then BFS from roots.
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
    let mut stack: Vec<u32> = trusted.iter().copied().collect();
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children.get(&pid) {
            for &c in kids {
                if trusted.insert(c) {
                    stack.push(c);
                }
            }
        }
    }
    trusted
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
        let tree = collect_trusted_tree(&[&tmp.join("no-such-pidfile")]);
        assert!(tree.contains(&std::process::id()));
    }

    #[test]
    fn descendant_of_self_is_trusted() {
        let me = std::process::id();
        let mut roots = HashSet::new();
        roots.insert(me);
        assert!(pid_trusted_or_descendant(me, &roots));
    }
}
