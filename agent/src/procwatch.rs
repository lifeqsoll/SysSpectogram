use crate::trust::{collect_trusted_tree, pid_trusted_or_descendant, read_comm};
use crate::types::{AgentAlert, EventKind, RawEvent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Exact executable paths. Comm is not part of this allowlist.
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
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/sbin/cron",
    "/usr/bin/cron",
    "/usr/sbin/crond",
    "/usr/bin/crond",
    "/usr/bin/dbus-daemon",
    "/usr/sbin/NetworkManager",
    "/usr/bin/NetworkManager",
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-udevd",
    "/usr/lib/systemd/systemd-logind",
    "/usr/lib/systemd/systemd-networkd",
    "/usr/lib/systemd/systemd-resolved",
    "/usr/lib/systemd/systemd-timesyncd",
    "/usr/sbin/logrotate",
    "/usr/bin/logrotate",
    "/usr/bin/mandb",
    "/usr/bin/updatedb",
    "/usr/sbin/fstrim",
    "/usr/bin/fstrim",
    "/usr/local/sbin/sysspectogram-agent",
    "/usr/sbin/sysspectogram-agent",
];

const KTHREAD_PREFIXES: &[&str] = &["kworker/", "ksoftirqd/", "migration/", "rcu_", "kthreadd"];

const ROOT_DEDUP_SEC: u64 = 600;
const ROOT_BASELINE_MAX_AGE_SEC: u64 = 900;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootBaselineEntry {
    pid: u32,
    starttime: u64,
    exe: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RootBaselineFile {
    boot_id: String,
    saved_at: u64,
    entries: Vec<RootBaselineEntry>,
}

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
    root_learn_sec: u64,
    root_baseline: HashMap<(u32, u64), String>,
    root_baseline_path: PathBuf,
    last_baseline_save: Instant,
    root_alerted: HashMap<u32, u64>,
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
        let learn_sec = learn_sec.max(1);
        Self {
            known_pids: HashSet::new(),
            bootstrapped: false,
            modules: HashSet::new(),
            modules_bootstrapped: false,
            prev_tcp_remotes: 0,
            prev_unique_remotes: 0,
            root_enabled: enabled,
            root_learn_until: Instant::now() + Duration::from_secs(learn_sec),
            root_learn_sec: learn_sec,
            root_baseline: HashMap::new(),
            root_baseline_path: PathBuf::from("state/root_baseline.json"),
            last_baseline_save: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(Instant::now),
            root_alerted: HashMap::new(),
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
        let baseline_path = agent
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(|parent| parent.join("root_baseline.json"));
        self.guard_pidfile = guard;
        self.agent_pidfile = agent;
        self.watchdog_pidfile = watchdog;
        if let Some(path) = baseline_path {
            self.root_baseline_path = path;
        }
        self.refresh_trusted();
        if self.root_enabled {
            self.root_learn_until = Instant::now() + Duration::from_secs(self.root_learn_sec);
            self.root_baseline.clear();
            self.load_root_baseline();
        }
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
        let learning = self.is_learning();

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
                            if let Some((starttime, exe)) = read_root_identity(pid) {
                                self.root_baseline.insert((pid, starttime), exe);
                            }
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
                let Some((starttime, exe_owned)) = read_root_identity(*pid) else {
                    continue;
                };
                if self.root_already_known(*pid, starttime)
                    || self.root_alerted.get(pid) == Some(&starttime)
                {
                    continue;
                }
                // Spawned by guard / agent / phoenix — not unexpected.
                if pid_trusted_or_descendant(*pid, &self.trusted_cache) {
                    self.root_baseline.insert((*pid, starttime), exe_owned);
                    continue;
                }
                let st = read_status(*pid);
                let comm = st
                    .as_ref()
                    .map(|s| s.comm.clone())
                    .unwrap_or_else(|| "?".into());
                let exe = if exe_owned.is_empty() {
                    None
                } else {
                    Some(exe_owned.clone())
                };
                if exe.is_none() && !comm.is_empty() {
                    // kernel thread
                    self.root_baseline.insert((*pid, starttime), exe_owned);
                    continue;
                }
                if soft_allow(&comm, exe.as_deref(), &self.extra_allows) {
                    self.root_baseline.insert((*pid, starttime), exe_owned);
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
                        self.root_alerted.insert(*pid, starttime);
                        continue;
                    }
                }
                self.root_dedup.insert(dedup_key, now);
                self.root_alerted.insert(*pid, starttime);
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
            self.maybe_save_root_baseline();
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

        self.maybe_save_root_baseline();
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

    pub fn is_learning(&self) -> bool {
        Instant::now() < self.root_learn_until
    }

    fn root_already_known(&self, pid: u32, starttime: u64) -> bool {
        self.root_baseline.contains_key(&(pid, starttime))
    }

    /// Trust this file only when it is owner-only, for this boot, and newer than 15 minutes.
    fn load_root_baseline(&mut self) {
        if !crate::phoenix::clean_marker_trusted(&self.root_baseline_path) {
            return;
        }
        let text = match fs::read_to_string(&self.root_baseline_path) {
            Ok(text) => text,
            Err(_) => return,
        };
        let parsed: RootBaselineFile = match serde_json::from_str(&text) {
            Ok(parsed) => parsed,
            Err(_) => return,
        };
        let Some(boot_id) = read_boot_id() else {
            return;
        };
        if parsed.boot_id != boot_id {
            return;
        }
        let now = unix_now();
        if parsed.saved_at < now.saturating_sub(ROOT_BASELINE_MAX_AGE_SEC) {
            return;
        }
        self.root_baseline = parsed
            .entries
            .into_iter()
            .map(|entry| ((entry.pid, entry.starttime), entry.exe))
            .collect();
        self.root_learn_until = Instant::now();
    }

    pub fn save_root_baseline(&self) -> io::Result<()> {
        if let Ok(meta) = fs::symlink_metadata(&self.root_baseline_path) {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "root baseline path is a symlink",
                ));
            }
        }
        let boot_id = read_boot_id().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "boot_id unavailable")
        })?;
        let payload = RootBaselineFile {
            boot_id,
            saved_at: unix_now(),
            entries: self
                .root_baseline
                .iter()
                .map(|((pid, starttime), exe)| RootBaselineEntry {
                    pid: *pid,
                    starttime: *starttime,
                    exe: exe.clone(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let parent = match self.root_baseline_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                fs::create_dir_all(parent)?;
                parent.to_path_buf()
            }
            _ => PathBuf::from("."),
        };
        let mut tmp_name = self
            .root_baseline_path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("root_baseline.json"));
        tmp_name.push(format!(".{}.tmp", std::process::id()));
        let tmp = parent.join(tmp_name);
        let _ = fs::remove_file(&tmp);
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW);
            let mut file = opts.open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        if let Ok(meta) = fs::symlink_metadata(&self.root_baseline_path) {
            if meta.file_type().is_symlink() {
                let _ = fs::remove_file(&tmp);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "root baseline path is a symlink",
                ));
            }
        }
        if let Err(err) = fs::rename(&tmp, &self.root_baseline_path) {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        Ok(())
    }

    fn maybe_save_root_baseline(&mut self) {
        if !self.root_enabled {
            return;
        }
        if self.last_baseline_save.elapsed() < Duration::from_secs(30) {
            return;
        }
        self.last_baseline_save = Instant::now();
        if let Err(err) = self.save_root_baseline() {
            eprintln!("[sysspectogram-agent] root baseline: {err}");
        }
    }
}

struct StatusInfo {
    ppid: u32,
    comm: String,
    ruid: u32,
    euid: u32,
}

fn exe_denied(path: &str) -> bool {
    path.ends_with(" (deleted)")
        || path.starts_with("/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/run/user/")
        || path.starts_with("/home/")
        || path.starts_with("/root/")
        || path.starts_with("memfd:")
}

/// Canonical path when it exists; otherwise the given string (tests use missing paths).
fn canonical_or_given(path: &str) -> String {
    fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Built-in exes compared after canonicalize. Missing entries stay as written.
fn builtin_allow_exes() -> &'static HashSet<String> {
    static CACHE: OnceLock<HashSet<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        DEFAULT_ALLOW_EXES
            .iter()
            .map(|entry| canonical_or_given(entry))
            .collect()
    })
}

fn is_kthread_comm(comm: &str) -> bool {
    KTHREAD_PREFIXES.iter().any(|prefix| comm.starts_with(prefix))
}

fn system_exe_prefix(path: &str) -> bool {
    path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/libexec/")
}

fn soft_allow(comm: &str, exe: Option<&str>, extra: &[String]) -> bool {
    let Some(raw) = exe.filter(|path| !path.is_empty()) else {
        return is_kthread_comm(comm);
    };
    if exe_denied(raw) {
        return false;
    }
    let path = canonical_or_given(raw);
    if exe_denied(&path) {
        return false;
    }
    if builtin_allow_exes().contains(path.as_str()) {
        return true;
    }
    for entry in extra {
        let item = entry.trim();
        if item.is_empty() {
            continue;
        }
        if item.contains('/') {
            if path == canonical_or_given(item) {
                return true;
            }
        } else if comm == item && system_exe_prefix(&path) {
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

fn read_starttime(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 22 is starttime. Parse after the last ')' because comm can contain
    // spaces and parentheses.
    let (_, rest) = text.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn read_root_identity(pid: u32) -> Option<(u64, String)> {
    let starttime = read_starttime(pid)?;
    Some((starttime, read_exe(pid).unwrap_or_default()))
}

fn read_boot_id() -> Option<String> {
    let text = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot_id = text.trim();
    if boot_id.is_empty() {
        None
    } else {
        Some(boot_id.to_string())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn read_exe(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if let Ok(canon) = fs::canonicalize(&link) {
        Some(canon.to_string_lossy().into_owned())
    } else {
        // Keep the readlink text, including a " (deleted)" suffix.
        Some(link.to_string_lossy().into_owned())
    }
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
        // No exe and not a kthread: bare config name is not enough.
        assert!(!soft_allow("customd", None, &["customd".into()]));
    }

    #[test]
    fn soft_allow_rejects_comm_prefix_from_tmp() {
        let cases = [
            ("ipwn", "/tmp/ipwn"),
            ("ss-x", "/tmp/ss-x"),
            ("sshd", "/tmp/sshd"),
            ("systemd-x", "/tmp/systemd-x"),
            ("sudoer", "/dev/shm/sudoer"),
            ("nftx", "/tmp/nftx"),
            ("cron", "/root/.c/cron"),
            ("sshd-x", "/usr/sbin/sshd-x"),
        ];
        for (comm, exe) in cases {
            assert!(
                !soft_allow(comm, Some(exe), &[]),
                "{comm} {exe} must not be soft-allowed"
            );
        }
    }

    #[test]
    fn soft_allow_extra_exact_path_only() {
        let extra = ["/opt/mydaemon".to_string()];
        assert!(!soft_allow("zz", Some("/tmp/opt/mydaemon"), &extra));
        assert!(!soft_allow("zz", Some("/var/opt/mydaemon"), &extra));
        assert!(soft_allow("zz", Some("/opt/mydaemon"), &extra));
        assert!(!soft_allow(
            "zz",
            Some("/tmp/evil"),
            &["/tmp/evil".to_string()]
        ));
    }

    #[test]
    fn soft_allow_kthread_without_exe() {
        assert!(soft_allow("kworker/0:1", None, &[]));
        assert!(!soft_allow("kworker/0:1", Some("/tmp/x"), &[]));
    }

    #[test]
    fn soft_allow_deleted_exe_never() {
        assert!(!soft_allow(
            "sudo",
            Some("/usr/bin/sudo (deleted)"),
            &[]
        ));
        // Non-utility comm: prefix match used to allow this deleted path.
        assert!(!soft_allow(
            "sshd",
            Some("/usr/sbin/sshd (deleted)"),
            &[]
        ));
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

    #[test]
    fn soft_allow_builtin_exe_after_canonicalize() {
        let udevd = "/usr/lib/systemd/systemd-udevd";
        if Path::new(udevd).exists() {
            // Comm is not part of the built-in match; the canonical exe is.
            assert!(soft_allow("not-systemd-udevd", Some(udevd), &[]));
        }
        assert!(!soft_allow(
            "systemd-udevd",
            Some("/tmp/systemd-udevd"),
            &[]
        ));
    }

    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ssx-rootbase-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn write_baseline_file(path: &Path, saved_at: u64, entries: &[(u32, u64, &str)]) {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .to_string();
        let entries_json: Vec<_> = entries
            .iter()
            .map(|(pid, starttime, exe)| {
                serde_json::json!({
                    "pid": pid,
                    "starttime": starttime,
                    "exe": exe,
                })
            })
            .collect();
        let body = serde_json::to_vec(&serde_json::json!({
            "boot_id": boot,
            "saved_at": saved_at,
            "entries": entries_json,
        }))
        .unwrap();
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut file = opts.open(path).unwrap();
        file.write_all(&body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn watch_in(dir: &Path) -> ProcWatcher {
        let mut watcher = ProcWatcher::with_root(true, 300);
        watcher.set_trust_pidfiles(
            dir.join("guard.pid"),
            dir.join("agent.pid"),
            dir.join("watchdog.pid"),
        );
        watcher
    }

    #[test]
    fn baseline_roundtrip_skips_learning() {
        let dir = scratch_dir("roundtrip");
        let mut writer = watch_in(&dir);
        writer
            .root_baseline
            .insert((1u32, 123u64), "/usr/sbin/sshd".to_string());
        writer.save_root_baseline().unwrap();

        let loaded = watch_in(&dir);
        assert!(
            !loaded.is_learning(),
            "a fresh baseline for this boot must skip the learn window"
        );
        assert!(
            loaded.root_already_known(1, 123),
            "saved (pid, starttime) must already be known"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_baseline_triggers_learn() {
        let dir = scratch_dir("stale");
        write_baseline_file(
            &dir.join("root_baseline.json"),
            unix_now().saturating_sub(901),
            &[(1, 123, "/usr/sbin/sshd")],
        );
        let loaded = watch_in(&dir);
        assert!(
            loaded.is_learning(),
            "baseline older than 15 minutes must keep the learn window"
        );
        assert!(
            !loaded.root_already_known(1, 123),
            "stale entries must not be treated as known"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_rejects_symlink() {
        let dir = scratch_dir("symlink");
        let real = dir.join("real.json");
        write_baseline_file(&real, unix_now(), &[(1, 2, "/usr/sbin/sshd")]);
        let link = dir.join("root_baseline.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let before = fs::read(&real).unwrap();

        let loaded = watch_in(&dir);
        assert!(
            loaded.is_learning(),
            "a symlink baseline must not be trusted"
        );
        assert!(!loaded.root_already_known(1, 2));
        assert!(
            loaded.save_root_baseline().is_err(),
            "save must refuse to write through a symlink"
        );
        assert_eq!(fs::read(&real).unwrap(), before);
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_pid_after_restart_is_not_known() {
        let dir = scratch_dir("newpid");
        write_baseline_file(
            &dir.join("root_baseline.json"),
            unix_now(),
            &[(7, 50, "/usr/sbin/sshd")],
        );
        let loaded = watch_in(&dir);
        assert!(
            loaded.root_already_known(7, 50),
            "loaded (pid, starttime) is known"
        );
        assert!(
            !loaded.root_already_known(7, 51),
            "same pid with a new starttime is not the saved process"
        );
        assert!(
            !loaded.root_already_known(8, 50),
            "pid absent from the loaded set is not known"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
