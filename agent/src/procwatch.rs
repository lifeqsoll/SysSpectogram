use crate::types::{AgentAlert, EventKind, RawEvent};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// Soft-allow root daemons (comm prefix or exact). Learned quietly after baseline.
const DEFAULT_ALLOW_COMMS: &[&str] = &[
    "systemd",
    "kthreadd",
    "rcu_sched",
    "migration",
    "ksoftirqd",
    "kworker",
    "sshd",
    "systemd-journal",
    "systemd-udevd",
    "systemd-logind",
    "cron",
    "crond",
    "dbus-daemon",
    "NetworkManager",
    "nftables",
    "sysspectogram-a",
    "sysspectogram-agent",
];

pub struct ProcWatcher {
    known_pids: HashSet<u32>,
    bootstrapped: bool,
    modules: HashSet<String>,
    modules_bootstrapped: bool,
    prev_tcp_remotes: usize,
    prev_unique_remotes: usize,
    /// Root watch (same /proc walk).
    root_enabled: bool,
    root_learn_until: Instant,
    root_baseline: HashSet<u32>,
    root_alerted: HashSet<u32>,
    pending_root: Vec<RootHit>,
}

#[derive(Debug, Clone)]
struct RootHit {
    pid: u32,
    comm: String,
    path: Option<String>,
    cmdline: String,
}

impl ProcWatcher {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_root(true, 300)
    }

    pub fn with_root(enabled: bool, learn_sec: u64) -> Self {
        Self {
            known_pids: HashSet::new(),
            bootstrapped: false,
            modules: HashSet::new(),
            modules_bootstrapped: false,
            prev_tcp_remotes: 0,
            prev_unique_remotes: 0,
            root_enabled: enabled,
            root_learn_until: Instant::now() + Duration::from_secs(learn_sec.max(1)),
            root_baseline: HashSet::new(),
            root_alerted: HashSet::new(),
            pending_root: Vec::new(),
        }
    }

    pub fn poll(&mut self) -> io::Result<Vec<RawEvent>> {
        let mut events = Vec::new();
        let mut current = HashSet::new();
        let mut root_now = HashSet::new();
        let learning = Instant::now() < self.root_learn_until;

        let proc = Path::new("/proc");
        for ent in fs::read_dir(proc)? {
            let ent = ent?;
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            current.insert(pid);

            let status = read_status(pid);
            if self.root_enabled {
                if let Some(ref st) = status {
                    if st.ruid == 0 || st.euid == 0 {
                        root_now.insert(pid);
                        if learning {
                            self.root_baseline.insert(pid);
                        }
                    }
                }
            }

            if !self.bootstrapped {
                continue;
            }
            if self.known_pids.contains(&pid) {
                if let Some(ev) = self.sample_sensitive_fds(pid) {
                    events.extend(ev);
                }
                continue;
            }

            let (ppid, comm) = status
                .as_ref()
                .map(|s| (s.ppid, s.comm.clone()))
                .unwrap_or((0, format!("pid-{pid}")));
            events.push(RawEvent {
                kind: EventKind::Exec,
                pid,
                ppid,
                comm: comm.clone(),
                path: read_exe(pid),
            });
            if let Some(ev) = self.sample_sensitive_fds(pid) {
                events.extend(ev);
            }
        }

        if self.root_enabled && !learning {
            for pid in &root_now {
                if self.root_baseline.contains(pid) || self.root_alerted.contains(pid) {
                    continue;
                }
                let st = read_status(*pid);
                let comm = st
                    .as_ref()
                    .map(|s| s.comm.clone())
                    .unwrap_or_else(|| "?".into());
                let exe = read_exe(*pid);
                if exe.is_none() && !comm.is_empty() {
                    // kernel thread
                    self.root_baseline.insert(*pid);
                    continue;
                }
                if soft_allow(&comm) {
                    self.root_baseline.insert(*pid);
                    continue;
                }
                self.root_alerted.insert(*pid);
                self.pending_root.push(RootHit {
                    pid: *pid,
                    comm,
                    path: exe,
                    cmdline: read_cmdline(*pid),
                });
            }
        }

        if !self.bootstrapped {
            self.known_pids = current;
            self.bootstrapped = true;
            self.prev_tcp_remotes = count_external_tcp().0;
            self.prev_unique_remotes = count_external_tcp().1;
            return Ok(vec![]);
        }

        self.known_pids = current;

        let (now_tcp, now_uniq) = count_external_tcp();
        let delta = now_tcp > self.prev_tcp_remotes.saturating_add(40);
        let uniq_jump = now_uniq > self.prev_unique_remotes.saturating_add(25);
        if delta || uniq_jump {
            events.push(RawEvent {
                kind: EventKind::ConnectBurst,
                pid: 0,
                ppid: 0,
                comm: "net".into(),
                path: None,
            });
        }
        self.prev_tcp_remotes = now_tcp;
        self.prev_unique_remotes = now_uniq;

        Ok(events)
    }

    /// Drain unexpected-root alerts collected during poll (same /proc walk).
    pub fn drain_root_alerts(&mut self, host_id: &str) -> Vec<AgentAlert> {
        let hits = std::mem::take(&mut self.pending_root);
        hits.into_iter()
            .map(|h| {
                let path = h.path.clone().unwrap_or_else(|| "?".into());
                let mut a = AgentAlert::new(
                    "agent_unexpected_root",
                    "critical",
                    format!(
                        "New root process pid={} comm={} exe={}",
                        h.pid, h.comm, path
                    ),
                    host_id,
                );
                a.pid = Some(h.pid);
                a.comm = Some(h.comm);
                a.path = h.path;
                a.extras = Some(serde_json::json!({
                    "cmdline": h.cmdline,
                    "source": "procwatch",
                }));
                a
            })
            .collect()
    }

    fn sample_sensitive_fds(&self, pid: u32) -> Option<Vec<RawEvent>> {
        let fd_dir = Path::new("/proc").join(pid.to_string()).join("fd");
        let rd = fs::read_dir(&fd_dir).ok()?;
        let (ppid, comm) = read_status(pid)
            .map(|s| (s.ppid, s.comm))
            .unwrap_or((0, "?".into()));
        let mut out = Vec::new();
        for ent in rd.flatten().take(64) {
            let link = fs::read_link(ent.path()).ok()?;
            let s = link.to_string_lossy();
            if s.contains("/.ssh/")
                || s.starts_with("/etc/shadow")
                || s.starts_with("/etc/sudoers")
                || s.contains("/cron")
                || s.contains("/systemd/system")
            {
                if s.contains(".wants")
                    || s.contains("/.ssh/agent")
                    || s.ends_with("known_hosts")
                    || s.ends_with("known_hosts.old")
                {
                    continue;
                }
                out.push(RawEvent {
                    kind: EventKind::OpenSensitive,
                    pid,
                    ppid,
                    comm: comm.clone(),
                    path: Some(s.into_owned()),
                });
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    pub fn module_alerts(&mut self, host_id: &str) -> Vec<AgentAlert> {
        let mut out = Vec::new();
        let Ok(text) = fs::read_to_string("/proc/modules") else {
            return out;
        };
        let mut now = HashSet::new();
        for line in text.lines() {
            if let Some(name) = line.split_whitespace().next() {
                now.insert(name.to_string());
            }
        }
        if !self.modules_bootstrapped {
            self.modules = now;
            self.modules_bootstrapped = true;
            return out;
        }
        for name in now.difference(&self.modules) {
            let mut a = AgentAlert::new(
                "agent_kirk_module_load",
                "high",
                format!("new kernel module appeared: {name}"),
                host_id,
            );
            a.path = Some(name.clone());
            out.push(a);
        }
        self.modules = now;
        out
    }
}

struct StatusInfo {
    ppid: u32,
    comm: String,
    ruid: u32,
    euid: u32,
}

fn soft_allow(comm: &str) -> bool {
    DEFAULT_ALLOW_COMMS
        .iter()
        .any(|a| comm == *a || comm.starts_with(a))
}

fn read_status(pid: u32) -> Option<StatusInfo> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut ppid = 0u32;
    let mut comm = String::new();
    let mut ruid = u32::MAX;
    let mut euid = u32::MAX;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Name:\t") {
            comm = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("PPid:\t") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Uid:\t") {
            // Uid: real effective saved fs
            let mut parts = rest.split_whitespace();
            ruid = parts.next().and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
            euid = parts.next().and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
        }
    }
    Some(StatusInfo {
        ppid,
        comm,
        ruid,
        euid,
    })
}

fn read_exe(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_cmdline(pid: u32) -> String {
    let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return String::new();
    };
    let s = String::from_utf8_lossy(&raw);
    s.replace('\0', " ").trim().chars().take(200).collect()
}

fn count_external_tcp() -> (usize, usize) {
    let mut n = 0usize;
    let mut remotes = HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let rem = parts[2];
            if let Some((iphex, porthex)) = rem.split_once(':') {
                if iphex.chars().all(|c| c == '0') {
                    continue;
                }
                n += 1;
                remotes.insert(format!("{iphex}:{porthex}"));
            }
        }
    }
    (n, remotes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_allow_matches_prefixes() {
        assert!(soft_allow("sshd"));
        assert!(soft_allow("kworker/0:1"));
        assert!(soft_allow("sysspectogram-agent"));
        assert!(!soft_allow("evil-rootkit"));
    }

    #[test]
    fn root_watch_disabled_emits_nothing() {
        let mut w = ProcWatcher::with_root(false, 1);
        let _ = w.poll();
        assert!(w.drain_root_alerts("t").is_empty());
    }
}
