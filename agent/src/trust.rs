//! Trusted PID trees (guard / agent / phoenix twin) and kill-signal classification.
//!
//! Mirrors Python ``trusted_pids``: trust by pidfile + descendant ppid chain,
//! never by forged ``comm``.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

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
        6 => "SIGABRT",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        12 => "SIGUSR2",
        15 => "SIGTERM",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        23 => "SIGSTOP",
        _ => "SIGNAL",
    }
}

/// ``None`` = do not alert. Otherwise severity string.
pub fn kill_alert_severity(sig: u32) -> Option<&'static str> {
    match sig {
        0 => None, // existence probe — never alert
        15 => None, // clean shutdown / systemd stop — handled elsewhere
        1 | 10 | 12 => Some("low"), // HUP / USR*
        2 | 3 | 6 | 9 | 19 | 20 | 23 => Some("critical"),
        // Other terminating / stop-ish signals
        4 | 5 | 7 | 8 | 11 | 16 | 31 => Some("critical"),
        _ => Some("low"),
    }
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
        assert_eq!(kill_alert_severity(1), Some("low"));
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
