//! SysSpectogram agent — integrity + lightweight metrics for guard (v3).
//!
//! Default: userspace `/proc` + inotify. `--mode ebpf` probes toolchain and falls back.

mod aggregate;
mod auth;
mod baseline;
mod crossview;
mod ebpf;
mod emit;
mod fim;
mod metrics;
mod phoenix;
mod procwatch;
mod protect;
mod rules;
mod tg_notify;
mod types;
mod watch;

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::aggregate::Aggregator;
use crate::baseline::{BaselineMonitor, SymbolBaseline, DEFAULT_WATCH_SYMBOLS};
use crate::crossview::CrossViewMonitor;
use crate::ebpf::probe_toolchain;
use crate::emit::Emitter;
use crate::fim::FimWatcher;
use crate::metrics::MetricsSampler;
use crate::phoenix::{run_watchdog_loop, write_pidfile};
use crate::procwatch::ProcWatcher;
use crate::protect::{
    check_install, check_unit_file, emit_clean_shutdown, resolve_exe,
};
use crate::rules::RuleEngine;
use crate::watch::PathWatcher;

#[derive(Parser, Debug)]
#[command(name = "sysspectogram-agent", about = "SysSpectogram integrity + metrics sensor")]
struct Args {
    /// userspace = /proc+inotify (default). ebpf = Aya when toolchain ready (fallback today).
    #[arg(long, default_value = "userspace")]
    mode: String,

    /// agent (default) or watchdog (phoenix twin).
    #[arg(long, default_value = "agent")]
    role: String,

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

    /// Persist FIM known-good digests here (JSON + .sha256 seal).
    #[arg(long, default_value = "state/fim-baseline.json")]
    fim_baseline: PathBuf,

    #[arg(long)]
    host_id: Option<String>,

    /// Seal kallsyms watchlist → JSON (+ .sha256). Exits after write.
    #[arg(long)]
    kirk_seal: bool,

    /// Path for kirk baseline JSON (seal + drift poll).
    #[arg(long, default_value = "state/kirk-baseline.json")]
    kirk_baseline: PathBuf,

    /// Enable /sys/module vs /proc/modules cross-view (and soft PID drop).
    #[arg(long, default_value_t = true)]
    crossview: bool,

    #[arg(long, default_value_t = 2)]
    crossview_confirm: u32,

    #[arg(long, default_value_t = 10)]
    crossview_interval_sec: u64,

    /// Poll sealed kallsyms baseline for drift (needs prior --kirk-seal).
    #[arg(long, default_value_t = true)]
    kirk_baseline_poll: bool,

    #[arg(long, default_value_t = 300)]
    kirk_baseline_interval_sec: u64,

    /// Write our pid here (for phoenix / guard).
    #[arg(long, default_value = "state/agent.pid")]
    pidfile: PathBuf,

    /// Spawn phoenix watchdog twin after start.
    #[arg(long, default_value_t = false)]
    phoenix: bool,

    /// Watchdog: pidfile of peer to watch.
    #[arg(long)]
    watch_pidfile: Option<PathBuf>,

    /// Watchdog: CLEAN_SHUTDOWN marker path.
    #[arg(long, default_value = "state/agent.clean_shutdown")]
    clean_marker: PathBuf,

    /// Watchdog: executable to respawn.
    #[arg(long)]
    respawn_exe: Option<PathBuf>,

    /// Watchdog: args for respawn (repeatable). Values may start with `-`.
    #[arg(long, allow_hyphen_values = true)]
    respawn_arg: Vec<String>,

    /// Shared HMAC secret file (same as guard state/agent_hmac.secret).
    #[arg(long, default_value = "state/agent_hmac.secret")]
    hmac_secret: PathBuf,

    /// Optional systemd unit path to permission-check.
    #[arg(long, default_value = "/etc/systemd/system/sysspectogram-agent.service")]
    unit_file: PathBuf,

    /// Guard pidfile — if guard dies unexpectedly, send TG via curl.
    #[arg(long, default_value = "state/guard.pid")]
    guard_pidfile: PathBuf,

    /// Root-only Telegram notify env for agent→TG bypass.
    #[arg(long, default_value = "/etc/sysspectogram/agent-notify.env")]
    notify_env: PathBuf,

    /// Detect unexpected uid=0 via same /proc walk (lite-friendly). Default on.
    #[arg(long = "root-watch", default_value_t = true, action = clap::ArgAction::SetTrue)]
    root_watch: bool,

    /// Disable root_watch (overrides --root-watch / default).
    #[arg(long = "no-root-watch", action = clap::ArgAction::SetTrue)]
    no_root_watch: bool,

    /// Learn existing root PIDs before alerting (seconds).
    #[arg(long, default_value_t = 300)]
    root_learn_sec: u64,
}

fn main() {
    let args = Args::parse();
    let root_watch = args.root_watch && !args.no_root_watch;
    let host = args.host_id.unwrap_or_else(hostname_fallback);

    if args.role == "watchdog" {
        let running = Arc::new(AtomicBool::new(true));
        {
            let r = running.clone();
            let marker = args.clean_marker.clone();
            let _ = ctrlc::set_handler(move || {
                let _ = std::fs::File::create(&marker);
                r.store(false, Ordering::SeqCst);
            });
        }
        let _ = write_pidfile(&args.pidfile, std::process::id());
        let watch = args
            .watch_pidfile
            .clone()
            .unwrap_or_else(|| PathBuf::from("state/agent.pid"));
        let exe = args
            .respawn_exe
            .clone()
            .unwrap_or_else(resolve_exe);
        eprintln!(
            "[sysspectogram-watch] watching {} respawn={}",
            watch.display(),
            exe.display()
        );
        run_watchdog_loop(
            &watch,
            &args.clean_marker,
            &exe,
            &args.respawn_arg,
            &running,
        );
        return;
    }

    if args.kirk_seal {
        match SymbolBaseline::from_kallsyms(
            std::path::Path::new("/proc/kallsyms"),
            DEFAULT_WATCH_SYMBOLS,
        ) {
            Ok(bl) => match bl.seal_to(&args.kirk_baseline) {
                Ok(dig) => {
                    eprintln!(
                        "[sysspectogram-agent] sealed {} symbols → {} sha256={dig}",
                        bl.symbols.len(),
                        args.kirk_baseline.display()
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("[sysspectogram-agent] seal failed: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("[sysspectogram-agent] kallsyms read failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let exe = resolve_exe();
    let chk = check_install(&exe);
    for w in &chk.warnings {
        eprintln!("[sysspectogram-agent] install: {w}");
    }
    if !chk.ok {
        eprintln!("[sysspectogram-agent] install check FAILED (continuing; harden path for prod)");
    }
    for w in check_unit_file(&args.unit_file) {
        eprintln!("[sysspectogram-agent] unit: {w}");
    }

    #[cfg(feature = "ebpf")]
    let mut ebpf_rt: Option<crate::ebpf::EbpfHandle> = None;
    #[cfg(not(feature = "ebpf"))]
    let _ebpf_rt: Option<()> = None;
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
                    eprintln!("[sysspectogram-agent] eBPF attached: execve+openat+module");
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

    let hmac = crate::auth::load_secret(&args.hmac_secret);
    if hmac.is_some() {
        eprintln!(
            "[sysspectogram-agent] HMAC signing enabled ({})",
            args.hmac_secret.display()
        );
    } else {
        eprintln!(
            "[sysspectogram-agent] HMAC secret missing - critical alerts unsigned ({})",
            args.hmac_secret.display()
        );
    }
    let emitter = match Emitter::new(&args.socket, args.jsonl.as_deref(), hmac) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[sysspectogram-agent] emit init failed: {e}");
            std::process::exit(1);
        }
    };

    let _ = write_pidfile(&args.pidfile, std::process::id());
    // clear stale clean marker
    let _ = std::fs::remove_file(&args.clean_marker);

    let running = Arc::new(AtomicBool::new(true));
    let clean_exit = Arc::new(AtomicBool::new(false));
    {
        let r = running.clone();
        let c = clean_exit.clone();
        let _ = ctrlc::set_handler(move || {
            c.store(true, Ordering::SeqCst);
            r.store(false, Ordering::SeqCst);
        });
    }

    if args.phoenix {
        let mut respawn_args: Vec<String> = vec![
            "--mode".into(),
            args.mode.clone(),
            "--socket".into(),
            args.socket.display().to_string(),
            "--pidfile".into(),
            args.pidfile.display().to_string(),
            "--host-id".into(),
            host.clone(),
        ];
            respawn_args.push("--hmac-secret".into());
            respawn_args.push(args.hmac_secret.display().to_string());
            if let Some(ref j) = args.jsonl {
                respawn_args.push("--jsonl".into());
                respawn_args.push(j.display().to_string());
            }
            if root_watch {
                respawn_args.push("--root-watch".into());
                respawn_args.push("--root-learn-sec".into());
                respawn_args.push(args.root_learn_sec.to_string());
            } else {
                respawn_args.push("--no-root-watch".into());
            }
        match crate::phoenix::spawn_watchdog(
            &exe,
            &respawn_args,
            &args.pidfile,
            &PathBuf::from("state/watchdog.pid"),
        ) {
            Ok(_) => eprintln!("[sysspectogram-agent] phoenix watchdog spawned"),
            Err(e) => eprintln!("[sysspectogram-agent] phoenix spawn failed: {e}"),
        }
    }

    let mut watcher = ProcWatcher::with_root(root_watch, args.root_learn_sec);
    if root_watch {
        eprintln!(
            "[sysspectogram-agent] root_watch learn={}s",
            args.root_learn_sec
        );
    }
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
            Some(args.fim_baseline.clone()),
        ))
    } else {
        None
    };
    let mut metrics = MetricsSampler::new(host.clone());

    let mut cross = if args.crossview {
        Some(CrossViewMonitor::new(args.crossview_confirm))
    } else {
        None
    };
    let cross_every = Duration::from_secs(args.crossview_interval_sec.max(5));
    let mut last_cross = Instant::now()
        .checked_sub(Duration::from_secs(u64::MAX / 4))
        .unwrap_or_else(Instant::now);

    let mut baseline_mon = if args.kirk_baseline_poll {
        Some(BaselineMonitor::try_load(
            &args.kirk_baseline,
            args.kirk_baseline_interval_sec,
        ))
    } else {
        None
    };

    eprintln!(
        "[sysspectogram-agent] host={host} mode={effective_mode} peer_socket={} poll={}ms metrics={}ms crossview={} baseline_poll={}",
        args.socket.display(),
        args.poll_ms,
        args.metrics_ms,
        args.crossview,
        args.kirk_baseline_poll
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
    let mut last_guard_check = Instant::now();
    let mut guard_alerted = false;
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
        #[cfg(feature = "ebpf")]
        if let Some(ref ebpf) = ebpf_rt {
            while let Some(alert) = ebpf.try_recv() {
                if let Err(e) = emitter.emit_alert(&alert) {
                    eprintln!("[sysspectogram-agent] emit: {e}");
                }
            }
        }

        // Guard liveness (every 5s)
        if last_guard_check.elapsed() >= Duration::from_secs(5) {
            last_guard_check = Instant::now();
            if let Some(gpid) = crate::phoenix::read_pidfile(&args.guard_pidfile) {
                if !crate::phoenix::pid_alive(gpid) {
                    if !guard_alerted {
                        guard_alerted = true;
                        let msg = format!(
                            "CRITICAL [{host}] guard pid={gpid} gone — agent_kirk_guard_down"
                        );
                        eprintln!("[sysspectogram-agent] {msg}");
                        match crate::tg_notify::send_critical(&msg, &args.notify_env) {
                            Ok(true) => eprintln!("[sysspectogram-agent] TG notify sent"),
                            Ok(false) => eprintln!(
                                "[sysspectogram-agent] TG skipped (no {})",
                                args.notify_env.display()
                            ),
                            Err(e) => eprintln!("[sysspectogram-agent] TG fail: {e}"),
                        }
                        let a = crate::types::AgentAlert::new(
                            "agent_kirk_guard_down",
                            "critical",
                            msg,
                            &host,
                        );
                        let _ = emitter.emit_alert(&a);
                    }
                } else {
                    guard_alerted = false;
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
            for alert in watcher.drain_root_alerts(&host) {
                if let Err(e) = emitter.emit_alert(&alert) {
                    eprintln!("[sysspectogram-agent] emit: {e}");
                }
            }
            last_flush = Instant::now();
        }

        if let Some(ref mut cv) = cross {
            if last_cross.elapsed() >= cross_every {
                if let Some(alert) = cv.poll_modules(&host) {
                    if let Err(e) = emitter.emit_alert(&alert) {
                        eprintln!("[sysspectogram-agent] emit: {e}");
                    }
                }
                if let Some(alert) = cv.poll_pid_drop(&host) {
                    if let Err(e) = emitter.emit_alert(&alert) {
                        eprintln!("[sysspectogram-agent] emit: {e}");
                    }
                }
                last_cross = Instant::now();
            }
        }

        if let Some(ref mut bm) = baseline_mon {
            if let Some(alert) = bm.poll(&host) {
                if let Err(e) = emitter.emit_alert(&alert) {
                    eprintln!("[sysspectogram-agent] emit: {e}");
                }
            }
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

    if clean_exit.load(Ordering::SeqCst) {
        let _ = std::fs::File::create(&args.clean_marker);
        if let Err(e) = emit_clean_shutdown(&emitter, &host) {
            eprintln!("[sysspectogram-agent] clean_shutdown emit: {e}");
        }
        eprintln!("[sysspectogram-agent] CLEAN_SHUTDOWN");
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
