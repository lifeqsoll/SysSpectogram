use crate::trust::{collect_trusted_tree, pid_trusted_or_descendant, read_comm};
use crate::types::{AgentAlert, EventKind, RawEvent};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Soft-allow root daemons (comm prefix/exact or known system exe basenames).
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
    // Safe system utilities (comm); exe path also checked when present.
    "journalctl",
    "systemctl",
    "nft",
    "ip",
    "ss",
    "pacman",
    "sudo", // only the sudo process itself — children still checked
    "logrotate",
    "man-db",
    "mandb",
    "updatedb",
    "fstrim",
];

/// Absolute exe prefixes / basenames that are soft-allowed when they match.
const DEFAULT_ALLOW_EXES: &[&str] = &[
    "/usr/bin/journalctl",
    "/usr/bin/systemctl",
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/usr/sbin/ip",
    "/usr/bin/ip",
    "/usr/bin/ss",
    "/usr/bin/pacman",
    "/usr/bin/sudo",
    "/usr/sbin/logrotate",
    "/usr/bin/logrotate",
    "/usr/bin/mandb",
    "/usr/bin/updatedb",
    "/usr/sbin/fstrim",
    "/usr/bin/fstrim",
    "/usr/local/sbin/sysspectogram-agent",
    "/usr/sbin/sysspectogram-agent",
];

const ROOT_DEDUP_SEC: u64 = 600;

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
    /// Dedup identical (comm, exe) unexpected-root alerts.
    root_dedup: HashMap<(String, String), Instant>,
    extra_allows: Vec<String>,
    guard_pidfile: PathBuf,
    agent_pidfile: PathBuf,
    watchdog_pidfile: PathBuf,
    trusted_cache: HashSet<u32>,
    trusted_refresh: Instant,
}

#[derive(Debug, Clone)]
struct RootHit {
    pid: u32,
    comm: String,
    path: Option<String>,
    cmdline: String,
    severity: String,
    parent_comm: String,
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
            root_dedup: HashMap::new(),
            extra_allows: Vec::new(),
            guard_pidfile: PathBuf::from("state/guard.pid"),
            agent_pidfile: PathBuf::from("state/agent.pid"),
            watchdog_pidfile: PathBuf::from("state/watchdog.pid"),
            trusted_cache: HashSet::new(),
            trusted_refresh: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(Instant::now),
        }
    }

    pub fn set_trust_pidfiles(
        &mut self,
        guard: PathBuf,
        agent: PathBuf,
        watchdog: PathBuf,
    ) {
        self.guard_pidfile = guard;
        self.agent_pidfile = agent;
        self.watchdog_pidfile = watchdog;
        self.refresh_trusted();
    }

    pub fn set_extra_allows(&mut self, allows: Vec<String>) {
        self.extra_allows = allows;
    }

    fn refresh_trusted(&mut self) {
        self.trusted_cache = collect_trusted_tree(&[
            self.guard_pidfile.as_path(),
            self.agent_pidfile.as_path(),
            self.watchdog_pidfile.as_path(),
        ]);
        self.trusted_refresh = Instant::now();
    }

    pub fn poll(&mut self) -> io::Result<Vec<RawEvent>> {
        let mut events = Vec::new();
        let mut current = HashSet::new();
        let mut root_now = HashSet::new();
        let learning = Instant::now() < self.root_learn_until;

        if self.trusted_refresh.elapsed() >= Duration::from_secs(2) {
            self.refresh_trusted();
        }

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
            let now = Instant::now();
            self.root_dedup
                .retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(ROOT_DEDUP_SEC));
            for pid in &root_now {
                if self.root_baseline.contains(pid) || self.root_alerted.contains(pid) {
                    continue;
                }
                // Spawned by guard / agent / phoenix — not unexpected.
                if pid_trusted_or_descendant(*pid, &self.trusted_cache) {
                    self.root_baseline.insert(*pid);
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
                if soft_allow(&comm, exe.as_deref(), &self.extra_allows) {
                    self.root_baseline.insert(*pid);
                    continue;
                }
                let parent_comm = st
                    .as_ref()
                    .and_then(|s| read_comm(s.ppid))
                    .unwrap_or_else(|| "?".into());
                let severity = root_severity(exe.as_deref(), &parent_comm);
                let dedup_key = (
                    comm.clone(),
                    exe.clone().unwrap_or_else(|| "?".into()),
                );
                if let Some(prev) = self.root_dedup.get(&dedup_key) {
                    if now.duration_since(*prev) < Duration::from_secs(ROOT_DEDUP_SEC) {
                        self.root_alerted.insert(*pid);
                        continue;
                    }
                }
                self.root_dedup.insert(dedup_key, now);
                self.root_alerted.insert(*pid);
                self.pending_root.push(RootHit {
                    pid: *pid,
                    comm,
                    path: exe,
                    cmdline: read_cmdline(*pid),
                    severity: severity.to_string(),
                    parent_comm,
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
                    &h.severity,
                    format!(
                        "New root process pid={} comm={} exe={} parent={}",
                        h.pid, h.comm, path, h.parent_comm
                    ),
                    host_id,
                );
                a.pid = Some(h.pid);
                a.comm = Some(h.comm);
                a.path = h.path;
                a.extras = Some(serde_json::json!({
                    "cmdline": h.cmdline,
                    "source": "procwatch",
                    "parent_comm": h.parent_comm,
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

fn soft_allow(comm: &str, exe: Option<&str>, extra: &[String]) -> bool {
    if DEFAULT_ALLOW_COMMS
        .iter()
        .any(|a| comm == *a || comm.starts_with(a))
    {
        // Prefer exe confirmation when we have a path for utility names.
        if let Some(path) = exe {
            if is_utility_comm(comm) && !exe_allowed(path, extra) {
                // comm forged — refuse soft-allow without matching exe
                return false;
            }
        }
        return true;
    }
    if let Some(path) = exe {
        if exe_allowed(path, extra) {
            return true;
        }
    }
    for a in extra {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        if a.starts_with('/') {
            if let Some(path) = exe {
                if path == a || path.ends_with(a) {
                    return true;
                }
            }
        } else if comm == a || comm.starts_with(a) {
            return true;
        }
    }
    false
}

fn is_utility_comm(comm: &str) -> bool {
    matches!(
        comm,
        "journalctl"
            | "systemctl"
            | "nft"
            | "ip"
            | "ss"
            | "pacman"
            | "sudo"
            | "logrotate"
            | "man-db"
            | "mandb"
            | "updatedb"
            | "fstrim"
    )
}

fn exe_allowed(path: &str, extra: &[String]) -> bool {
    if DEFAULT_ALLOW_EXES.iter().any(|p| path == *p) {
        return true;
    }
    // basename match under standard bin dirs
    let base = path.rsplit('/').next().unwrap_or("");
    if DEFAULT_ALLOW_COMMS.iter().any(|c| *c == base)
        && (path.starts_with("/usr/bin/")
            || path.starts_with("/usr/sbin/")
            || path.starts_with("/bin/")
            || path.starts_with("/sbin/"))
    {
        return true;
    }
    for a in extra {
        let a = a.trim();
        if a.starts_with('/') && (path == a || Path::new(path).ends_with(a.trim_start_matches('/')))
        {
            return true;
        }
    }
    false
}

/// cron/systemd timer children → medium; unknown /tmp binaries stay critical.
fn root_severity(exe: Option<&str>, parent_comm: &str) -> &'static str {
    let timerish = parent_comm == "systemd"
        || parent_comm.starts_with("systemd")
        || parent_comm == "cron"
        || parent_comm == "crond"
        || parent_comm.starts_with("cron");
    if let Some(path) = exe {
        if path.starts_with("/tmp/")
            || path.starts_with("/dev/shm/")
            || path.starts_with("/var/tmp/")
        {
            return "critical";
        }
    }
    if timerish {
        return "medium";
    }
    "critical"
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
        assert!(soft_allow("sshd", Some("/usr/sbin/sshd"), &[]));
        assert!(soft_allow("kworker/0:1", None, &[]));
        assert!(soft_allow(
            "sysspectogram-agent",
            Some("/usr/local/sbin/sysspectogram-agent"),
            &[]
        ));
        assert!(!soft_allow("evil-rootkit", Some("/tmp/evil"), &[]));
    }

    #[test]
    fn soft_allow_utilities_need_real_exe() {
        assert!(soft_allow("journalctl", Some("/usr/bin/journalctl"), &[]));
        // forged comm without matching exe
        assert!(!soft_allow("journalctl", Some("/tmp/journalctl"), &[]));
        assert!(soft_allow("sudo", Some("/usr/bin/sudo"), &[]));
    }

    #[test]
    fn soft_allow_extra_from_config() {
        assert!(soft_allow(
            "mydaemon",
            Some("/opt/mydaemon"),
            &["/opt/mydaemon".into()]
        ));
        assert!(soft_allow("customd", None, &["customd".into()]));
    }

    #[test]
    fn tmp_binary_stays_critical() {
        assert_eq!(root_severity(Some("/tmp/evil"), "systemd"), "critical");
        assert_eq!(root_severity(Some("/usr/bin/something"), "cron"), "medium");
        assert_eq!(root_severity(Some("/usr/bin/something"), "bash"), "critical");
    }

    #[test]
    fn root_watch_disabled_emits_nothing() {
        let mut w = ProcWatcher::with_root(false, 1);
        let _ = w.poll();
        assert!(w.drain_root_alerts("t").is_empty());
    }

    #[test]
    fn trusted_descendant_skipped() {
        let mut w = ProcWatcher::with_root(true, 1);
        // Force end of learn
        w.root_learn_until = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        w.refresh_trusted();
        let me = std::process::id();
        assert!(pid_trusted_or_descendant(me, &w.trusted_cache));
    }
}
