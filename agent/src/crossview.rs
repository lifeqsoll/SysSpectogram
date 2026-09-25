//! Cross-view: /proc vs /sys (modules) — best-effort hide detection.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::types::AgentAlert;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewDiff {
    pub kernel_only: Vec<String>,
    pub proc_only: Vec<String>,
}

pub fn diff_sets(a: &HashSet<String>, b: &HashSet<String>) -> ViewDiff {
    let mut kernel_only: Vec<String> = a.difference(b).cloned().collect();
    let mut proc_only: Vec<String> = b.difference(a).cloned().collect();
    kernel_only.sort();
    proc_only.sort();
    ViewDiff {
        kernel_only,
        proc_only,
    }
}

pub fn is_hide_signal(diff: &ViewDiff) -> bool {
    !diff.kernel_only.is_empty() || !diff.proc_only.is_empty()
}

pub fn scan_proc_modules() -> HashSet<String> {
    let Ok(text) = fs::read_to_string("/proc/modules") else {
        return HashSet::new();
    };
    text.lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

/// sysfs module list — often harder for simple LKM hide tricks that only patch /proc.
pub fn scan_sysfs_modules() -> HashSet<String> {
    let Ok(rd) = fs::read_dir("/sys/module") else {
        return HashSet::new();
    };
    rd.filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .collect()
}

pub fn scan_proc_pids() -> HashSet<String> {
    let Ok(rd) = fs::read_dir("/proc") else {
        return HashSet::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.chars().all(|c| c.is_ascii_digit()) {
                Some(s.into_owned())
            } else {
                None
            }
        })
        .collect()
}

pub struct CrossViewMonitor {
    confirm: u32,
    need: u32,
    last_module_streak: u32,
    last_pid_count: usize,
}

impl CrossViewMonitor {
    pub fn new(confirm: u32) -> Self {
        Self {
            confirm: 0,
            need: confirm.max(1),
            last_module_streak: 0,
            last_pid_count: 0,
        }
    }

    /// Compare /sys/module vs /proc/modules. Require `need` consecutive mismatches.
    pub fn poll_modules(&mut self, host_id: &str) -> Option<AgentAlert> {
        let sysfs = scan_sysfs_modules();
        let proc = scan_proc_modules();
        if sysfs.is_empty() || proc.is_empty() {
            self.last_module_streak = 0;
            return None;
        }
        // Ignore noisy virtual modules sometimes only in one view
        let ignore = |n: &str| {
            n.starts_with("module_")
                || n == "firmware_class"
                || n.contains("rfkill")
        };
        let sysfs: HashSet<_> = sysfs.into_iter().filter(|n| !ignore(n)).collect();
        let proc: HashSet<_> = proc.into_iter().filter(|n| !ignore(n)).collect();
        let diff = diff_sets(&sysfs, &proc);
        if !is_hide_signal(&diff) {
            self.last_module_streak = 0;
            return None;
        }
        self.last_module_streak = self.last_module_streak.saturating_add(1);
        if self.last_module_streak < self.need {
            return None;
        }
        self.last_module_streak = 0;
        let msg = format!(
            "module cross-view mismatch sysfs_only={:?} proc_only={:?}",
            &diff.kernel_only[..diff.kernel_only.len().min(8)],
            &diff.proc_only[..diff.proc_only.len().min(8)]
        );
        let mut a = AgentAlert::new("agent_kirk_module_hide", "critical", msg, host_id);
        a.extras = Some(serde_json::json!({
            "kirk_evidence": {
                "sysfs_only": diff.kernel_only,
                "proc_only": diff.proc_only,
            }
        }));
        Some(a)
    }

    /// Soft signal: sudden large drop in visible PID count (possible mass hide). Confirm streak.
    pub fn poll_pid_drop(&mut self, host_id: &str) -> Option<AgentAlert> {
        let pids = scan_proc_pids();
        let n = pids.len();
        if self.last_pid_count == 0 {
            self.last_pid_count = n;
            return None;
        }
        // >40% drop with at least 20 pids disappearing
        let drop = self.last_pid_count.saturating_sub(n);
        let ratio = drop as f64 / self.last_pid_count.max(1) as f64;
        let hit = drop >= 20 && ratio >= 0.4;
        if !hit {
            self.confirm = 0;
            self.last_pid_count = n;
            return None;
        }
        self.confirm = self.confirm.saturating_add(1);
        self.last_pid_count = n;
        if self.confirm < self.need {
            return None;
        }
        self.confirm = 0;
        let msg = format!(
            "pid list collapsed: {prev} → {n} (drop={drop})",
            prev = self.last_pid_count + drop
        );
        Some(AgentAlert::new("agent_kirk_pid_hide", "high", msg, host_id))
    }
}

#[allow(dead_code)]
pub fn baseline_path_default() -> &'static Path {
    Path::new("state/kirk-baseline.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_hide_detected() {
        let kernel: HashSet<_> = ["1", "2", "9"].into_iter().map(str::to_string).collect();
        let proc: HashSet<_> = ["1", "2"].into_iter().map(str::to_string).collect();
        let d = diff_sets(&kernel, &proc);
        assert_eq!(d.kernel_only, vec!["9".to_string()]);
        assert!(is_hide_signal(&d));
    }
}
