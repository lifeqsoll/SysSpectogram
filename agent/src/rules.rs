use crate::aggregate::{alert_from_snapshot, PidSnapshot};
use crate::types::AgentAlert;

pub struct RuleEngine {
    sensitive_prefixes: Vec<String>,
    /// Interpreters / shells that touching secrets is especially noisy.
    risky_comms: Vec<String>,
}

impl RuleEngine {
    pub fn default_sensitive() -> Self {
        Self {
            sensitive_prefixes: vec![
                "/root/.ssh".into(),
                "/home/".into(), // narrowed in eval to */.ssh/*
                "/etc/shadow".into(),
                "/etc/sudoers".into(),
                "/etc/crontab".into(),
                "/var/spool/cron".into(),
                "/etc/systemd/system".into(),
                "/usr/lib/systemd/system".into(),
            ],
            risky_comms: vec![
                "bash".into(),
                "sh".into(),
                "zsh".into(),
                "python".into(),
                "python3".into(),
                "perl".into(),
                "ruby".into(),
                "node".into(),
                "curl".into(),
                "wget".into(),
                "nc".into(),
                "ncat".into(),
                "socat".into(),
            ],
        }
    }

    pub fn eval(&self, snap: &PidSnapshot) -> Vec<AgentAlert> {
        let mut out = Vec::new();
        let host = ""; // filled by caller

        for path in &snap.sensitive_opens {
            if !self.path_interesting(path) {
                continue;
            }
            let risky = self
                .risky_comms
                .iter()
                .any(|c| snap.comm == *c || snap.comm.starts_with(c));
            // inotify has no PID — informational, never "high", skip if no real process
            if snap.comm == "inotify" || snap.pid == 0 {
                // only emit when path is a clear secret file (already filtered), severity low
                let msg = format!("filesystem watch: sensitive path changed/created {}", path);
                let mut a = alert_from_snapshot(
                    snap,
                    "agent_path_watch",
                    "low",
                    msg,
                    host,
                    Some(path.clone()),
                );
                a.extras = Some(serde_json::json!({ "source": "inotify" }));
                out.push(a);
                continue;
            }
            let severity = if risky { "high" } else { "medium" };
            let msg = format!(
                "process {} (pid {}, ppid {}) touched sensitive path {}",
                snap.comm, snap.pid, snap.ppid, path
            );
            let mut a = alert_from_snapshot(
                snap,
                "agent_open_sensitive",
                severity,
                msg,
                host,
                Some(path.clone()),
            );
            a.extras = Some(serde_json::json!({ "risky_comm": risky }));
            out.push(a);
        }

        // Rapid interpreter spawn storm in one window
        if snap.execs >= 8
            && self
                .risky_comms
                .iter()
                .any(|c| snap.comm == *c || snap.comm.starts_with(c))
        {
            let msg = format!(
                "rapid exec burst: {} x{} (pid {})",
                snap.comm, snap.execs, snap.pid
            );
            out.push(alert_from_snapshot(
                snap,
                "agent_exec_burst",
                "medium",
                msg,
                host,
                None,
            ));
        }

        if snap.connect_hints >= 1 {
            let msg = format!(
                "outbound connect burst hint for {} (pid {})",
                snap.comm, snap.pid
            );
            out.push(alert_from_snapshot(
                snap,
                "agent_connect_burst",
                "medium",
                msg,
                host,
                None,
            ));
        }

        out
    }

    fn path_interesting(&self, path: &str) -> bool {
        // shared denylist with inotify (systemd .wants noise, ssh agent dir, known_hosts churn)
        if path.contains(".wants")
            || path.contains("/.ssh/agent")
            || path.ends_with("known_hosts")
            || path.ends_with("known_hosts.old")
        {
            return false;
        }
        if path.contains("/.ssh/") || path.ends_with("/.ssh") {
            let name = path.rsplit('/').next().unwrap_or("");
            return name.starts_with("id_")
                || name == "authorized_keys"
                || name == "authorized_keys2"
                || name == "config"
                || path.contains("/root/.ssh");
        }
        self.sensitive_prefixes.iter().any(|p| {
            if p == "/home/" {
                return false;
            }
            if p.as_str() == "/etc/systemd/system" || p.as_str() == "/usr/lib/systemd/system" {
                return path.starts_with(p.as_str())
                    && (path.ends_with(".service")
                        || path.ends_with(".timer")
                        || path.ends_with(".socket"));
            }
            path.starts_with(p.as_str())
        })
    }
}