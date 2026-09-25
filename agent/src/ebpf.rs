//! Aya eBPF loader: sys_enter_execve + sys_enter_openat → AgentAlert.

#[cfg(feature = "ebpf")]
mod imp {
    use std::mem;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, TryRecvError};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use aya::maps::perf::PerfEventArray;
    use aya::programs::TracePoint;
    use aya::util::online_cpus;
    use aya::Ebpf;
    use bytes::BytesMut;
    use sysspectogram_common::{ProbeEvent, KIND_EXECVE, KIND_OPENAT};

    use crate::types::AgentAlert;

    pub struct EbpfStatus {
        pub available: bool,
        pub detail: String,
    }

    pub fn probe_toolchain() -> EbpfStatus {
        let clang = std::process::Command::new("clang")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
        let obj = std::path::Path::new(env!("OUT_DIR")).join("sysspectogram-ebpf");
        if clang && btf && obj.exists() {
            EbpfStatus {
                available: true,
                detail: format!("ready ({})", obj.display()),
            }
        } else {
            EbpfStatus {
                available: false,
                detail: format!(
                    "incomplete clang={} btf={} obj={} — see docs/EBPF_SETUP.md",
                    clang,
                    btf,
                    obj.exists()
                ),
            }
        }
    }

    pub struct EbpfHandle {
        rx: Receiver<AgentAlert>,
        stop: Arc<AtomicBool>,
        _join: JoinHandle<()>,
    }

    impl EbpfHandle {
        pub fn try_recv(&self) -> Option<AgentAlert> {
            match self.rx.try_recv() {
                Ok(a) => Some(a),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => None,
            }
        }
    }

    impl Drop for EbpfHandle {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    pub fn start_runtime(host_id: &str) -> Result<EbpfHandle, String> {
        // Aya finds tracefs via readdir; on Arch /sys/kernel/tracing is root-only (0700).
        // CAP_BPF alone is not enough — need real root (or readable tracefs).
        let tracing = std::path::Path::new("/sys/kernel/tracing");
        if tracing.exists() {
            if let Err(e) = tracing.read_dir() {
                return Err(format!(
                    "tracefs not readable ({e}). Run with sudo -E, not only setcap. \
                     /sys/kernel/tracing is typically mode 0700 root."
                ));
            }
        } else if !std::path::Path::new("/sys/kernel/debug/tracing").exists() {
            return Err("tracefs not found — mount tracefs (usually at /sys/kernel/tracing)".into());
        }

        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe {
            let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
        }

        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sysspectogram-ebpf"));
        let mut bpf = Ebpf::load(bytes).map_err(|e| format!("Ebpf::load: {e}"))?;

        {
            let prog: &mut TracePoint = bpf
                .program_mut("sysspectogram_execve")
                .ok_or("missing sysspectogram_execve")?
                .try_into()
                .map_err(|e| format!("{e}"))?;
            prog.load().map_err(|e| format!("execve load: {e}"))?;
            prog.attach("syscalls", "sys_enter_execve")
                .map_err(|e| format!("execve attach (need root/CAP_BPF?): {e}"))?;
        }
        {
            let prog: &mut TracePoint = bpf
                .program_mut("sysspectogram_openat")
                .ok_or("missing sysspectogram_openat")?
                .try_into()
                .map_err(|e| format!("{e}"))?;
            prog.load().map_err(|e| format!("openat load: {e}"))?;
            prog.attach("syscalls", "sys_enter_openat")
                .map_err(|e| format!("openat attach: {e}"))?;
        }

        let mut perf_map: PerfEventArray<_> = bpf
            .take_map("EVENTS")
            .ok_or("missing map EVENTS")?
            .try_into()
            .map_err(|e| format!("EVENTS map: {e}"))?;

        let (tx, rx) = mpsc::sync_channel(256);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = stop.clone();
        let host = host_id.to_string();
        let cpus = online_cpus().map_err(|e| format!("online_cpus: {e:?}"))?;

        let mut buffers = Vec::new();
        for cpu in &cpus {
            buffers.push(
                perf_map
                    .open(*cpu, None)
                    .map_err(|e| format!("perf open cpu{cpu}: {e}"))?,
            );
        }

        let join = thread::spawn(move || {
            let _keep_maps = (bpf, perf_map);
            let mut pages: Vec<BytesMut> = buffers
                .iter()
                .map(|_| BytesMut::with_capacity(4096))
                .collect();
            while !stop_t.load(Ordering::Relaxed) {
                for (i, buf) in buffers.iter_mut().enumerate() {
                    let page = &mut pages[i];
                    page.clear();
                    page.resize(4096, 0);
                    match buf.read_events(std::slice::from_mut(page)) {
                        Ok(ev) => {
                            if ev.lost > 0 {
                                eprintln!(
                                    "[sysspectogram-agent] eBPF lost {} events on cpu buffer",
                                    ev.lost
                                );
                            }
                            parse_and_send(page, ev.read, &host, &tx);
                        }
                        Err(_) => {}
                    }
                }
                thread::sleep(Duration::from_millis(25));
            }
        });

        Ok(EbpfHandle {
            rx,
            stop,
            _join: join,
        })
    }

    fn parse_and_send(
        page: &BytesMut,
        n_events: usize,
        host: &str,
        tx: &mpsc::SyncSender<AgentAlert>,
    ) {
        let sz = mem::size_of::<ProbeEvent>();
        let data = page.as_ref();
        for i in 0..n_events {
            let off = i * sz;
            if off + sz > data.len() {
                break;
            }
            let ev =
                unsafe { std::ptr::read_unaligned(data[off..].as_ptr() as *const ProbeEvent) };
            if let Some(alert) = event_to_alert(&ev, host) {
                let _ = tx.try_send(alert);
            }
        }
    }

    fn event_to_alert(ev: &ProbeEvent, host: &str) -> Option<AgentAlert> {
        let end = ev
            .path
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ev.path.len());
        let path = String::from_utf8_lossy(&ev.path[..end]).into_owned();
        // openat is extremely noisy — keep sensitive / interesting paths only
        if ev.kind == KIND_OPENAT && !path_interesting_openat(&path) {
            return None;
        }
        let (rule, sev, label) = match ev.kind {
            KIND_EXECVE => ("agent_ebpf_execve", "medium", "execve"),
            KIND_OPENAT => ("agent_ebpf_openat", "medium", "openat"),
            _ => ("agent_ebpf", "low", "syscall"),
        };
        let mut a = AgentAlert::new(
            rule,
            sev,
            format!("{label} pid={} uid={} path={}", ev.pid, ev.uid, path),
            host,
        );
        a.pid = Some(ev.pid);
        a.path = Some(path);
        Some(a)
    }

    fn path_interesting_openat(path: &str) -> bool {
        const HINTS: &[&str] = &[
            "/.ssh/",
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/etc/crontab",
            "/etc/ssh/",
            "/var/spool/cron",
            "/etc/systemd/",
            "/usr/lib/systemd/",
            "/root/",
            "/tmp/",
            "/dev/shm/",
            "/var/tmp/",
        ];
        if path.is_empty() || path.starts_with("/proc/") || path.starts_with("/sys/") {
            return false;
        }
        HINTS.iter().any(|h| path.contains(h))
    }
}

#[cfg(feature = "ebpf")]
pub use imp::{probe_toolchain, start_runtime};

#[cfg(not(feature = "ebpf"))]
pub struct EbpfStatus {
    pub available: bool,
    pub detail: String,
}

#[cfg(not(feature = "ebpf"))]
pub fn probe_toolchain() -> EbpfStatus {
    EbpfStatus {
        available: false,
        detail: "built without `ebpf` feature".into(),
    }
}
