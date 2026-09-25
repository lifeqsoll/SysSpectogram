use crate::types::{AgentAlert, EventKind, RawEvent};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

pub struct ProcWatcher {
    known_pids: HashSet<u32>,
    bootstrapped: bool,
    modules: HashSet<String>,
    modules_bootstrapped: bool,
    prev_tcp_remotes: usize,
    prev_unique_remotes: usize,
}

impl ProcWatcher {
    pub fn new() -> Self {
        Self {
            known_pids: HashSet::new(),
            bootstrapped: false,
            modules: HashSet::new(),
            modules_bootstrapped: false,
            prev_tcp_remotes: 0,
            prev_unique_remotes: 0,
        }
    }

    pub fn poll(&mut self) -> io::Result<Vec<RawEvent>> {
        let mut events = Vec::new();
        let mut current = HashSet::new();

        let proc = Path::new("/proc");
        for ent in fs::read_dir(proc)? {
            let ent = ent?;
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            current.insert(pid);

            if !self.bootstrapped {
                continue;
            }
            if self.known_pids.contains(&pid) {
                // sample fds occasionally for known pids that look risky
                if let Some(ev) = self.sample_sensitive_fds(pid) {
                    events.extend(ev);
                }
                continue;
            }

            // new pid → exec-like event
            let (ppid, comm) = read_status(pid).unwrap_or((0, format!("pid-{pid}")));
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

        if !self.bootstrapped {
            self.known_pids = current;
            self.bootstrapped = true;
            // baseline tcp
            self.prev_tcp_remotes = count_external_tcp().0;
            self.prev_unique_remotes = count_external_tcp().1;
            return Ok(vec![]);
        }

        // dropped pids
        self.known_pids = current;

        // connect burst: jump in remotes OR unique remote endpoints (scan-like)
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

    fn sample_sensitive_fds(&self, pid: u32) -> Option<Vec<RawEvent>> {
        let fd_dir = Path::new("/proc").join(pid.to_string()).join("fd");
        let rd = fs::read_dir(&fd_dir).ok()?;
        let (ppid, comm) = read_status(pid).unwrap_or((0, "?".into()));
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

fn read_status(pid: u32) -> Option<(u32, String)> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut ppid = 0u32;
    let mut comm = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Name:\t") {
            comm = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("PPid:\t") {
            ppid = rest.trim().parse().unwrap_or(0);
        }
    }
    Some((ppid, comm))
}

fn read_exe(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
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
