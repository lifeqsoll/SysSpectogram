//! Periodic file integrity (sha256) for critical paths — lite/full load profiles.

use crate::types::AgentAlert;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct FimWatcher {
    paths: Vec<PathBuf>,
    hashes: HashMap<PathBuf, String>,
    interval: Duration,
    last: Instant,
    host_id: String,
}

impl FimWatcher {
    pub fn new(paths: Vec<PathBuf>, interval_sec: u64, host_id: String) -> Self {
        let mut w = Self {
            paths,
            hashes: HashMap::new(),
            interval: Duration::from_secs(interval_sec.max(5)),
            last: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(Instant::now),
            host_id,
        };
        w.baseline();
        w
    }

    pub fn default_critical_paths() -> Vec<PathBuf> {
        [
            "/usr/bin/sshd",
            "/usr/sbin/sshd",
            "/bin/login",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ]
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
    }

    fn hash_file(path: &Path) -> Option<String> {
        let data = fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Some(format!("{:x}", hasher.finalize()))
    }

    fn baseline(&mut self) {
        for p in &self.paths {
            if let Some(h) = Self::hash_file(p) {
                self.hashes.insert(p.clone(), h);
            }
        }
        eprintln!(
            "[sysspectogram-agent] FIM baseline {} files",
            self.hashes.len()
        );
    }

    pub fn poll(&mut self) -> Vec<AgentAlert> {
        if self.last.elapsed() < self.interval {
            return Vec::new();
        }
        self.last = Instant::now();
        let mut out = Vec::new();
        for p in &self.paths {
            let Some(new_h) = Self::hash_file(p) else {
                continue;
            };
            match self.hashes.get(p) {
                None => {
                    self.hashes.insert(p.clone(), new_h);
                }
                Some(old) if old != &new_h => {
                    let msg = format!(
                        "FIM change: {} sha256 {} -> {}",
                        p.display(),
                        &old[..8.min(old.len())],
                        &new_h[..8.min(new_h.len())]
                    );
                    let mut a = AgentAlert::new("agent_fim_change", "high", msg, &self.host_id);
                    a.path = Some(p.display().to_string());
                    out.push(a);
                    self.hashes.insert(p.clone(), new_h);
                }
                _ => {}
            }
        }
        out
    }
}
