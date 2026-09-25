//! Narrow inotify watches — avoid /etc and systemd .wants spam.

use crate::types::{EventKind, RawEvent};
use notify::{Config, EventKind as NKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

pub struct PathWatcher {
    _watcher: RecommendedWatcher,
    rx: Receiver<notify::Result<notify::Event>>,
}

impl PathWatcher {
    pub fn try_new(paths: &[PathBuf]) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_secs(1)),
        )
        .map_err(|e| e.to_string())?;

        for p in paths {
            if !p.exists() {
                continue;
            }
            // Files: non-recursive. Dirs we care about: shallow recursive only for .ssh keys.
            let mode = if p.is_dir() {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            let _ = watcher.watch(p, mode);
        }

        Ok(Self {
            _watcher: watcher,
            rx,
        })
    }

    pub fn default_paths() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            let ssh = PathBuf::from(home).join(".ssh");
            // watch individual key files if present; else the dir but we filter noise
            for name in ["id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys", "config"] {
                let f = ssh.join(name);
                if f.exists() {
                    out.push(f);
                }
            }
            if ssh.exists() && out.is_empty() {
                out.push(ssh);
            }
        }
        for p in [
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/crontab",
            "/etc/ssh/sshd_config",
        ] {
            let pb = PathBuf::from(p);
            if pb.exists() {
                out.push(pb);
            }
        }
        let cron = PathBuf::from("/var/spool/cron");
        if cron.exists() {
            out.push(cron);
        }
        out
    }

    pub fn drain_events(&self) -> Vec<RawEvent> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(Ok(ev)) => {
                    // Access floods (reads) — ignore. Only create/modify/remove.
                    let interesting = matches!(
                        ev.kind,
                        NKind::Create(_) | NKind::Modify(_) | NKind::Remove(_)
                    );
                    if !interesting {
                        continue;
                    }
                    for path in ev.paths {
                        let s = path.to_string_lossy();
                        if !is_alert_path(&s) {
                            continue;
                        }
                        out.push(RawEvent {
                            kind: EventKind::OpenSensitive,
                            pid: 0,
                            ppid: 0,
                            comm: "inotify".into(),
                            path: Some(s.into_owned()),
                        });
                    }
                }
                Ok(Err(_)) | Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        out
    }
}

fn is_alert_path(path: &str) -> bool {
    // noise denylist
    if path.contains(".wants")
        || path.contains("/.ssh/agent")
        || path.ends_with("known_hosts")
        || path.ends_with("known_hosts.old")
        || path.contains("timers.target")
        || path.contains("sockets.target")
        || path.contains("sysinit.target")
        || path.contains("multi-user.target")
        || path.contains("getty.target")
        || path.contains("network-online")
    {
        return false;
    }
    if path.contains("/.ssh/") {
        let name = Path::new(path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("");
        return name.starts_with("id_")
            || name == "authorized_keys"
            || name == "config"
            || name == "authorized_keys2";
    }
    path.ends_with("/etc/shadow")
        || path.ends_with("/etc/sudoers")
        || path.ends_with("/etc/crontab")
        || path.contains("/var/spool/cron/")
        || path.ends_with("sshd_config")
        || (path.contains("/systemd/system/")
            && (path.ends_with(".service") || path.ends_with(".timer") || path.ends_with(".socket")))
}
