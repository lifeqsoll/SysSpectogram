//! SysSpectogram agent — integrity + lightweight metrics for guard (v3).
//!
//! Default: userspace `/proc` + inotify. `--mode ebpf` probes toolchain and falls back.

mod aggregate;
mod ebpf;
mod emit;
mod fim;
mod metrics;
mod procwatch;
mod rules;
mod types;
mod watch;

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::aggregate::Aggregator;
use crate::ebpf::probe_toolchain;
use crate::emit::Emitter;
use crate::fim::FimWatcher;
use crate::metrics::MetricsSampler;
use crate::procwatch::ProcWatcher;
use crate::rules::RuleEngine;
use crate::watch::PathWatcher;

#[derive(Parser, Debug)]
#[command(name = "sysspectogram-agent", about = "SysSpectogram integrity + metrics sensor")]
struct Args {
    /// userspace = /proc+inotify (default). ebpf = Aya when toolchain ready (fallback today).
    #[arg(long, default_value = "userspace")]
    mode: String,

    /// Unix datagram path where **guard listens** (agent send_to).
    #[arg(long, default_value = "/tmp/sysspectogram-agent.sock")]
    socket: PathBuf,

    /// Append alert NDJSON here (optional). Metrics are not logged here.
    #[arg(long)]
    jsonl: Option<PathBuf>,

    #[arg(long, default_value_t = 500)]
    poll_ms: u64,

    #[arg(long, default_value_t = 2000)]
    flush_ms: u64,

    /// Emit CPU/mem/net samples for the live web / light bus (ms). 0 = off.
    #[arg(long, default_value_t = 1000)]
    metrics_ms: u64,

    /// Enable periodic sha256 FIM on critical paths.
    #[arg(long, default_value_t = false)]
    fim: bool,

    #[arg(long, default_value_t = 60)]
    fim_interval_sec: u64,

    #[arg(long)]
    host_id: Option<String>,
}

fn main() {
    let args = Args::parse();
    let host = args.host_id.unwrap_or_else(hostname_fallback);

    let mut ebpf_rt = None;
    let mut effective_mode = args.mode.as_str();
    if args.mode == "ebpf" {
        let st = probe_toolchain();
        eprintln!(
            "[sysspectogram-agent] eBPF probe: available={} — {}",
            st.available, st.detail
        );
        #[cfg(feature = "ebpf")]
        {
            match crate::ebpf::start_runtime(&host) {
                Ok(h) => {
                    eprintln!("[sysspectogram-agent] eBPF attached: execve+openat");
                    ebpf_rt = Some(h);
                    effective_mode = "ebpf";
                }
                Err(e) => {
                    eprintln!("[sysspectogram-agent] eBPF attach failed: {e} — falling back to userspace");
                    effective_mode = "userspace";
                }
            }
        }
        #[cfg(not(feature = "ebpf"))]
        {
            eprintln!("[sysspectogram-agent] binary built without ebpf feature — userspace");
            effective_mode = "userspace";
        }
    } else if args.mode != "userspace" {
        eprintln!(
            "[sysspectogram-agent] unknown mode {:?}, using userspace",
            args.mode
        );
        effective_mode = "userspace";
    }

    let emitter = match Emitter::new(&args.socket, args.jsonl.as_deref()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[sysspectogram-agent] emit init failed: {e}");
            std::process::exit(1);
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        });
    }

    let mut watcher = ProcWatcher::new();
    let mut agg = Aggregator::new();
    let rules = RuleEngine::default_sensitive();
    let path_watch = PathWatcher::try_new(&PathWatcher::default_paths()).ok();
    if path_watch.is_some() {
        eprintln!("[sysspectogram-agent] inotify watches active");
    }
    let mut fim = if args.fim {
        Some(FimWatcher::new(
            FimWatcher::default_critical_paths(),
            args.fim_interval_sec,
            host.clone(),
        ))
    } else {
        None
    };
    let mut metrics = MetricsSampler::new(host.clone());

    eprintln!(
        "[sysspectogram-agent] host={host} mode={effective_mode} peer_socket={} poll={}ms metrics={}ms",
        args.socket.display(),
        args.poll_ms,
        args.metrics_ms
    );

    let poll = Duration::from_millis(args.poll_ms.max(100));
    let flush_every = Duration::from_millis(args.flush_ms.max(500));
    let metrics_every = if args.metrics_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(args.metrics_ms.max(200)))
    };
    let mut last_flush = Instant::now();
    let mut last_metrics = Instant::now();
    // warm metrics baseline
    let _ = metrics.sample();

    while running.load(Ordering::SeqCst) {
        match watcher.poll() {
            Ok(events) => {
                for ev in events {
                    agg.ingest(ev);
                }
            }
            Err(e) => eprintln!("[sysspectogram-agent] poll: {e}"),
        }
        if let Some(ref pw) = path_watch {
            for ev in pw.drain_events() {
                agg.ingest(ev);
            }
        }
        if let Some(ref mut fim) = fim {
            for alert in fim.poll() {
                if let Err(e) = emitter.emit_alert(&alert) {
                    eprintln!("[sysspectogram-agent] emit: {e}");
                }
            }
        }
        if let Some(ref ebpf) = ebpf_rt {
            while let Some(alert) = ebpf.try_recv() {
                if let Err(e) = emitter.emit_alert(&alert) {
                    eprintln!("[sysspectogram-agent] emit: {e}");
                }
            }
        }

        if last_flush.elapsed() >= flush_every {
            let snaps = agg.flush();
            for snap in snaps {
                for mut alert in rules.eval(&snap) {
                    alert.host_id = host.clone();
                    if let Err(e) = emitter.emit_alert(&alert) {
                        eprintln!("[sysspectogram-agent] emit: {e}");
                    }
                }
            }
            for alert in watcher.module_alerts(&host) {
                if let Err(e) = emitter.emit_alert(&alert) {
                    eprintln!("[sysspectogram-agent] emit: {e}");
                }
            }
            last_flush = Instant::now();
        }

        if let Some(every) = metrics_every {
            if last_metrics.elapsed() >= every {
                match metrics.sample() {
                    Ok(s) => {
                        let _ = emitter.emit_metrics(&s);
                    }
                    Err(e) => eprintln!("[sysspectogram-agent] metrics: {e}"),
                }
                last_metrics = Instant::now();
            }
        }

        std::thread::sleep(poll);
    }

    eprintln!("[sysspectogram-agent] stopped");
}

fn hostname_fallback() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
