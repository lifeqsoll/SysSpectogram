//! Periodic file integrity (sha256) for critical paths — lite/full load profiles.
//! Baseline persists to disk so restarts do not forget known-good digests.

use crate::types::AgentAlert;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
struct FimBaselineFile {
    format: String,
    version: u32,
    files: BTreeMap<String, String>,
}

pub struct FimWatcher {
    paths: Vec<PathBuf>,
    hashes: HashMap<PathBuf, String>,
    interval: Duration,
    last: Instant,
    host_id: String,
    baseline_path: Option<PathBuf>,
}

impl FimWatcher {
    pub fn new(
        paths: Vec<PathBuf>,
        interval_sec: u64,
        host_id: String,
        baseline_path: Option<PathBuf>,
    ) -> Self {
        let missing = paths.iter().filter(|p| !p.exists()).count();
        if missing > 0 {
            eprintln!(
                "[sysspectogram-agent] FIM: {missing} configured paths missing on disk (skipped)"
            );
        }
        let existing: Vec<PathBuf> = paths.into_iter().filter(|p| p.exists()).collect();
        let mut w = Self {
            paths: existing,
            hashes: HashMap::new(),
            interval: Duration::from_secs(interval_sec.max(5)),
            last: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(Instant::now),
            host_id,
            baseline_path,
        };
        if let Some(ref bp) = w.baseline_path.clone() {
            if bp.exists() {
                match w.load_baseline(bp) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("[sysspectogram-agent] FIM baseline load failed: {e}");
                        w.baseline();
                    }
                }
            } else {
                w.baseline();
            }
        } else {
            w.baseline();
        }
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
        let _ = self.persist_baseline();
    }

    fn load_baseline(&mut self, path: &Path) -> io::Result<()> {
        if let Some(exp) = read_sidecar_sha(path) {
            let got = file_sha256(path).unwrap_or_default();
            if !exp.is_empty() && exp != got {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("fim baseline sha256 mismatch expected={exp} got={got}"),
                ));
            }
        }
        let text = fs::read_to_string(path)?;
        let parsed: FimBaselineFile = serde_json::from_str(&text).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("fim baseline json: {e}"))
        })?;
        if parsed.format != "sysspectogram.fim.baseline" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported fim baseline format: {}", parsed.format),
            ));
        }
        self.hashes = parsed
            .files
            .into_iter()
            .map(|(k, v)| (PathBuf::from(k), v))
            .collect();
        eprintln!(
            "[sysspectogram-agent] FIM baseline loaded {} files from {}",
            self.hashes.len(),
            path.display()
        );
        Ok(())
    }

    fn persist_baseline(&self) -> io::Result<()> {
        let Some(ref bp) = self.baseline_path else {
            return Ok(());
        };
        if let Some(parent) = bp.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut files = BTreeMap::new();
        for (k, v) in &self.hashes {
            files.insert(k.display().to_string(), v.clone());
        }
        let body = FimBaselineFile {
            format: "sysspectogram.fim.baseline".into(),
            version: 1,
            files,
        };
        let text = serde_json::to_string_pretty(&body).map_err(io::Error::other)?;
        let mut f = fs::File::create(bp)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        if let Some(dig) = file_sha256(bp) {
            let side = PathBuf::from(format!("{}.sha256", bp.display()));
            fs::write(side, format!("{dig}\n"))?;
        }
        Ok(())
    }

    pub fn poll(&mut self) -> Vec<AgentAlert> {
        if self.last.elapsed() < self.interval {
            return Vec::new();
        }
        self.last = Instant::now();
        let mut out = Vec::new();
        let mut changed = false;
        for p in self.paths.clone() {
            let Some(new_h) = Self::hash_file(&p) else {
                continue;
            };
            match self.hashes.get(&p) {
                None => {
                    self.hashes.insert(p, new_h);
                    changed = true;
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
                    self.hashes.insert(p, new_h);
                    changed = true;
                }
                _ => {}
            }
        }
        if changed {
            let _ = self.persist_baseline();
        }
        out
    }
}

fn file_sha256(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("{:x}", hasher.finalize()))
}

fn read_sidecar_sha(path: &Path) -> Option<String> {
    let side = PathBuf::from(format!("{}.sha256", path.display()));
    let t = fs::read_to_string(side).ok()?;
    Some(t.trim().to_string())
}
