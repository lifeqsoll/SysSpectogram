//! Kallsyms / symbol baseline seal (best-effort).
//!
//! Stores **presence** of watchlist symbols, not absolute addresses — addresses
//! change under KASLR and when kptr_restrict hides pointers across privilege levels.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::types::AgentAlert;

/// Default symbols worth watching for syscall / process-table hooks.
pub const DEFAULT_WATCH_SYMBOLS: &[&str] = &[
    "sys_call_table",
    "do_exit",
    "do_fork",
    "commit_creds",
    "prepare_kernel_cred",
    "tcp4_seq_show",
    "udp4_seq_show",
];

#[derive(Debug, Clone)]
pub struct SymbolBaseline {
    /// Symbol names that were visible at seal time.
    pub symbols: BTreeSet<String>,
    /// True if addresses were all zero/masked (kptr_restrict) at seal.
    pub addresses_masked: bool,
}

impl SymbolBaseline {
    pub fn from_kallsyms(path: &Path, names: &[&str]) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        let want: std::collections::HashSet<&str> = names.iter().copied().collect();
        let mut symbols = BTreeSet::new();
        let mut saw_nonzero = false;
        let mut saw_any = false;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let addr = parts.next().unwrap_or("");
            let _typ = parts.next().unwrap_or("");
            let name = parts.next().unwrap_or("");
            if !want.contains(name) {
                continue;
            }
            saw_any = true;
            symbols.insert(name.to_string());
            if addr.chars().any(|c| c != '0') {
                saw_nonzero = true;
            }
        }
        Ok(Self {
            symbols,
            addresses_masked: saw_any && !saw_nonzero,
        })
    }

    /// Drift = sealed symbols that disappeared (or unexpected new watch hits).
    pub fn drift(&self, other: &SymbolBaseline) -> Vec<String> {
        let mut out = Vec::new();
        for k in &self.symbols {
            if !other.symbols.contains(k) {
                out.push(format!("{k}: missing"));
            }
        }
        for k in &other.symbols {
            if !self.symbols.contains(k) {
                out.push(format!("{k}: unexpected"));
            }
        }
        out
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "version": 2,
            "mode": "presence",
            "addresses_masked": self.addresses_masked,
            "symbols": self.symbols.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn from_json_value(v: &serde_json::Value) -> Option<Self> {
        let version = v.get("version").and_then(|x| x.as_u64()).unwrap_or(1);
        let addresses_masked = v
            .get("addresses_masked")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let mut symbols = BTreeSet::new();
        if version >= 2 {
            let arr = v.get("symbols")?.as_array()?;
            for item in arr {
                if let Some(s) = item.as_str() {
                    symbols.insert(s.to_string());
                }
            }
        } else {
            // v1 stored addr map — migrate to presence-only
            let map = v.get("symbols")?.as_object()?;
            for k in map.keys() {
                symbols.insert(k.clone());
            }
        }
        Some(Self {
            symbols,
            addresses_masked,
        })
    }

    pub fn seal_to(&self, path: &Path) -> io::Result<String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(&self.to_json_value())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let digest = format!("{:x}", hasher.finalize());
        fs::write(path, &body)?;
        let side = path.with_extension("json.sha256");
        let mut f = fs::File::create(&side)?;
        writeln!(f, "{digest}  {}", path.display())?;
        Ok(digest)
    }

    pub fn load_from(path: &Path) -> io::Result<(Self, Option<String>)> {
        let body = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let digest = format!("{:x}", hasher.finalize());
        let side = path.with_extension("json.sha256");
        let expected = if side.exists() {
            let t = fs::read_to_string(&side)?;
            Some(t.split_whitespace().next().unwrap_or("").to_string())
        } else {
            None
        };
        if let Some(ref exp) = expected {
            if exp != &digest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("baseline sha256 mismatch expected={exp} got={digest}"),
                ));
            }
        }
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let bl = Self::from_json_value(&v).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid baseline json")
        })?;
        Ok((bl, expected))
    }
}

pub struct BaselineMonitor {
    sealed: Option<SymbolBaseline>,
    kallsyms: std::path::PathBuf,
    names: Vec<String>,
    interval: std::time::Duration,
    last: std::time::Instant,
    degraded: bool,
}

impl BaselineMonitor {
    pub fn try_load(path: &Path, interval_sec: u64) -> Self {
        let sealed = match SymbolBaseline::load_from(path) {
            Ok((b, _)) => {
                eprintln!(
                    "[sysspectogram-agent] kirk baseline loaded {} ({} symbols, masked={})",
                    path.display(),
                    b.symbols.len(),
                    b.addresses_masked
                );
                Some(b)
            }
            Err(e) => {
                eprintln!(
                    "[sysspectogram-agent] kirk baseline not loaded ({}): {e}",
                    path.display()
                );
                None
            }
        };
        Self {
            sealed,
            kallsyms: Path::new("/proc/kallsyms").to_path_buf(),
            names: DEFAULT_WATCH_SYMBOLS.iter().map(|s| (*s).to_string()).collect(),
            interval: std::time::Duration::from_secs(interval_sec.max(30)),
            last: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(u64::MAX / 4))
                .unwrap_or_else(std::time::Instant::now),
            degraded: false,
        }
    }

    pub fn poll(&mut self, host_id: &str) -> Option<AgentAlert> {
        if self.sealed.is_none() {
            return None;
        }
        if self.last.elapsed() < self.interval {
            return None;
        }
        self.last = std::time::Instant::now();
        let names: Vec<&str> = self.names.iter().map(|s| s.as_str()).collect();
        let live = match SymbolBaseline::from_kallsyms(&self.kallsyms, &names) {
            Ok(b) => {
                self.degraded = false;
                b
            }
            Err(e) => {
                if !self.degraded {
                    self.degraded = true;
                    eprintln!("[sysspectogram-agent] kallsyms unreadable: {e} (degraded)");
                }
                return None;
            }
        };
        // If live view is fully masked but seal was not, skip CRITICAL (privilege mismatch).
        if live.addresses_masked && self.sealed.as_ref().is_some_and(|s| !s.addresses_masked) {
            if !self.degraded {
                self.degraded = true;
                eprintln!(
                    "[sysspectogram-agent] kallsyms masked vs unmasked seal — drift degraded (run seal as same user)"
                );
            }
            return None;
        }
        let sealed = self.sealed.as_ref()?;
        let drifts = sealed.drift(&live);
        if drifts.is_empty() {
            return None;
        }
        // Presence-only: missing symbols → high (not critical) to avoid auto_isolate storms.
        // Unexpected new watch symbols after seal is rarer → critical.
        let missing_only = drifts.iter().all(|d| d.ends_with(": missing"));
        let sev = if missing_only { "high" } else { "critical" };
        let msg = format!("kallsyms symbol presence drift: {}", drifts.join("; "));
        let mut a = AgentAlert::new("agent_kirk_symbol_drift", sev, msg, host_id);
        a.extras = Some(serde_json::json!({
            "kirk_evidence": { "drifts": drifts, "mode": "presence" }
        }));
        Some(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_symbol() {
        let dir = std::env::temp_dir();
        let p1 = dir.join(format!("ss-kallsyms-a-{}", std::process::id()));
        let p2 = dir.join(format!("ss-kallsyms-b-{}", std::process::id()));
        fs::write(&p1, "ffffffff81000000 T sys_call_table\nffffffff81000010 T do_exit\n").unwrap();
        fs::write(&p2, "ffffffff81000000 T sys_call_table\n").unwrap();
        let b1 = SymbolBaseline::from_kallsyms(&p1, &["sys_call_table", "do_exit"]).unwrap();
        let b2 = SymbolBaseline::from_kallsyms(&p2, &["sys_call_table", "do_exit"]).unwrap();
        let _ = fs::remove_file(&p1);
        let _ = fs::remove_file(&p2);
        let d = b1.drift(&b2);
        assert!(d.iter().any(|x| x.contains("do_exit")));
        // address change alone is NOT drift
        let p3 = dir.join(format!("ss-kallsyms-c-{}", std::process::id()));
        fs::write(&p3, "deadbeef01000000 T sys_call_table\ndeadbeef01000010 T do_exit\n").unwrap();
        let b3 = SymbolBaseline::from_kallsyms(&p3, &["sys_call_table", "do_exit"]).unwrap();
        let _ = fs::remove_file(&p3);
        assert!(b1.drift(&b3).is_empty());
    }

    #[test]
    fn seal_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ss-kirk-bl-{}.json", std::process::id()));
        let mut symbols = BTreeSet::new();
        symbols.insert("do_exit".into());
        let b = SymbolBaseline {
            symbols,
            addresses_masked: false,
        };
        let dig = b.seal_to(&path).unwrap();
        assert_eq!(dig.len(), 64);
        let (loaded, exp) = SymbolBaseline::load_from(&path).unwrap();
        assert_eq!(exp.as_deref(), Some(dig.as_str()));
        assert!(loaded.symbols.contains("do_exit"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.sha256"));
    }
}
