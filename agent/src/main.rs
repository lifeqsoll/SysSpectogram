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
mod trust;
mod types;
mod watch;

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::exfiltrator::WithOrigin;
use signal_hook::iterator::SignalsInfo;

use crate::aggregate::Aggregator;
use crate::baseline::{BaselineMonitor, SymbolBaseline, DEFAULT_WATCH_SYMBOLS};
use crate::crossview::CrossViewMonitor;
use crate::ebpf::probe_toolchain;
use crate::emit::Emitter;
use crate::fim::FimWatcher;
use crate::metrics::MetricsSampler;
use crate::phoenix::{run_watchdog_loop, write_pidfile};
use crate::procwatch::ProcWatcher;
use crate::protect::{check_install, check_unit_file, emit_clean_shutdown, resolve_exe};
use crate::rules::RuleEngine;
use crate::watch::PathWatcher;

#[derive(Parser, Debug)]
#[command(
    name = "sysspectogram-agent",
    about = "SysSpectogram integrity + metrics sensor"
)]
struct Args {
    /// userspace = /proc+inotify (default). ebpf = Aya when clang, BTF and root are available; otherwise falls back to userspace.
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

    /// Emit a guest pid snapshot every N seconds for VMI cross-check. 0 = off (default).
    #[arg(long, default_value_t = 0)]
    pids_sec: u64,

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
    #[arg(
        long,
        default_value = "/etc/systemd/system/sysspectogram-agent.service"
    )]
    unit_file: PathBuf,

    /// Guard pidfile — if guard dies unexpectedly, send TG via curl.
    #[arg(long, default_value = "state/guard.pid")]
    guard_pidfile: PathBuf,

    /// Phoenix watchdog pidfile (absolutized at start).
    #[arg(long, default_value = "state/watchdog.pid")]
    watchdog_pidfile: PathBuf,

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

    /// Extra root_watch allowlist entries (comm name or absolute exe path). Repeatable.
    #[arg(long = "root-allow")]
    root_allow: Vec<String>,
}

fn main() {
    let mut args = Args::parse();
    absolutize_runtime_paths(&mut args);
    let root_watch = args.root_watch && !args.no_root_watch;
    let host = args.host_id.take().unwrap_or_else(hostname_fallback);

    if args.role == "watchdog" {
        let running = Arc::new(AtomicBool::new(true));
        // Signals stop the loop only. Creating the clean marker here would forge
        // a clean agent shutdown and retire the watchdog.
        arm_watchdog_signals(running.clone());
        let _ = write_pidfile(&args.pidfile, std::process::id());
        let watch = args
            .watch_pidfile
            .clone()
            .unwrap_or_else(|| PathBuf::from("state/agent.pid"));
        let exe = args.respawn_exe.clone().unwrap_or_else(resolve_exe);
        let hmac = crate::auth::load_secret(&args.hmac_secret);
        if hmac.is_none() {
            eprintln!(
                "[sysspectogram-watch] HMAC secret missing — stop markers will not retire the watchdog ({})",
                args.hmac_secret.display()
            );
        }
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
            args.jsonl.as_deref(),
            &host,
            hmac.as_deref(),
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
            match crate::ebpf::start_runtime(
                &host,
                &args.guard_pidfile,
                &args.pidfile,
                &args.watchdog_pidfile,
            ) {
                Ok(h) => {
                    eprintln!("[sysspectogram-agent] eBPF attached: execve+openat+module+kill");
                    ebpf_rt = Some(h);
                    effective_mode = "ebpf";
                }
                Err(e) => {
                    eprintln!(
                        "[sysspectogram-agent] eBPF attach failed: {e} — mode=proc (ebpf unavailable)"
                    );
                    effective_mode = "proc";
                }
            }
        }
        #[cfg(not(feature = "ebpf"))]
        {
            eprintln!(
                "[sysspectogram-agent] binary built without ebpf feature — mode=proc (ebpf unavailable: no-default-features)"
            );
            effective_mode = "proc";
        }
    } else if args.mode == "userspace" || args.mode == "proc" {
        // `userspace` remains the CLI/default alias; logs also say proc for operators.
        effective_mode = "userspace";
        eprintln!("[sysspectogram-agent] mode=userspace (proc fallback path)");
    } else {
        eprintln!(
            "[sysspectogram-agent] unknown mode {:?}, using mode=userspace",
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
    let emitter = match Emitter::new(&args.socket, args.jsonl.as_deref(), hmac.clone()) {
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
    let exit_sig = Arc::new(AtomicU32::new(libc::SIGTERM as u32));
    let exit_sender = Arc::new(AtomicU32::new(0));
    arm_agent_signals(
        running.clone(),
        clean_exit.clone(),
        exit_sig.clone(),
        exit_sender.clone(),
        KillWitnessCtx {
            host: host.clone(),
            jsonl: args.jsonl.clone(),
            socket: args.socket.clone(),
            notify_env: args.notify_env.clone(),
            clean_marker: args.clean_marker.clone(),
            hmac_secret: hmac.clone(),
        },
    );

    if args.phoenix {
        let respawn_args = build_phoenix_respawn_args(&args, &host, root_watch);
        match crate::phoenix::spawn_watchdog(
            &exe,
            &respawn_args,
            &args.pidfile,
            &args.watchdog_pidfile,
            args.jsonl.as_deref(),
            &host,
            &args.clean_marker,
            &args.hmac_secret,
        ) {
            Ok(_) => eprintln!("[sysspectogram-agent] phoenix watchdog spawned"),
            Err(e) => eprintln!("[sysspectogram-agent] phoenix spawn failed: {e}"),
        }
    }

    let mut watcher = ProcWatcher::with_root(root_watch, args.root_learn_sec);
    watcher.set_trust_pidfiles(
        args.guard_pidfile.clone(),
        args.pidfile.clone(),
        args.watchdog_pidfile.clone(),
    );
    if !args.root_allow.is_empty() {
        watcher.set_extra_allows(args.root_allow.clone());
    }
    if root_watch {
        eprintln!(
            "[sysspectogram-agent] root_watch learn={}s allows={}",
            args.root_learn_sec,
            args.root_allow.len()
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
    let mut last_pids = Instant::now();
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

        if args.pids_sec > 0 && last_pids.elapsed() >= Duration::from_secs(args.pids_sec) {
            match crate::metrics::list_pids() {
                Ok(pids) => {
                    if let Err(e) = emitter.emit_pids(&host, &pids) {
                        eprintln!("[sysspectogram-agent] pids emit: {e}");
                    }
                }
                Err(e) => eprintln!("[sysspectogram-agent] pids: {e}"),
            }
            last_pids = Instant::now();
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
        if root_watch {
            if let Err(e) = watcher.save_root_baseline() {
                eprintln!("[sysspectogram-agent] root baseline: {e}");
            }
        }
        match hmac.as_deref() {
            Some(secret) => {
                if let Err(e) = crate::phoenix::write_signed_stop_marker(
                    &args.clean_marker,
                    secret,
                    std::process::id(),
                ) {
                    eprintln!("[sysspectogram-agent] signed stop marker: {e}");
                }
            }
            None => {
                eprintln!(
                    "[sysspectogram-agent] clean exit without HMAC secret — leaving any pre-signed marker in place"
                );
            }
        }
        let sig = exit_sig.load(Ordering::SeqCst);
        let sender = exit_sender.load(Ordering::SeqCst);
        if let Err(e) = emit_clean_shutdown(&emitter, &host, crate::trust::signal_name(sig), sender)
        {
            eprintln!("[sysspectogram-agent] clean_shutdown emit: {e}");
        }
        eprintln!("[sysspectogram-agent] CLEAN_SHUTDOWN");
    }

    eprintln!("[sysspectogram-agent] stopped");
}

/// `Origin.process.pid` is siginfo `si_pid` (`sighook_signal_pid` reads `info->si_pid`).
/// Missing process → 0.
fn si_pid_of(origin: &signal_hook::iterator::exfiltrator::origin::Origin) -> u32 {
    match origin.process {
        Some(process) if process.pid > 0 => process.pid as u32,
        _ => 0,
    }
}

fn arm_watchdog_signals(running: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut signals = match SignalsInfo::<WithOrigin>::new([SIGINT, SIGTERM, SIGHUP]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[sysspectogram-watch] signal hook failed: {e}");
                return;
            }
        };
        if let Some(info) = signals.into_iter().next() {
            let si_pid = si_pid_of(&info);
            let si_code = si_code_label(&info);
            eprintln!(
                "[sysspectogram-watch] signal {} si_pid={si_pid} si_code={si_code} — stop loop, no clean marker",
                info.signal
            );
            running.store(false, Ordering::SeqCst);
        }
    });
}

struct KillWitnessCtx {
    host: String,
    jsonl: Option<PathBuf>,
    socket: PathBuf,
    notify_env: PathBuf,
    clean_marker: PathBuf,
    hmac_secret: Option<String>,
}

fn arm_agent_signals(
    running: Arc<AtomicBool>,
    clean_exit: Arc<AtomicBool>,
    exit_sig: Arc<AtomicU32>,
    exit_sender: Arc<AtomicU32>,
    ctx: KillWitnessCtx,
) {
    std::thread::spawn(move || {
        let mut signals = match SignalsInfo::<WithOrigin>::new([SIGINT, SIGTERM, SIGHUP]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[sysspectogram-agent] signal hook failed: {e}");
                return;
            }
        };
        if let Some(info) = signals.into_iter().next() {
            let sig = u32::try_from(info.signal).unwrap_or(0);
            let sender = si_pid_of(&info);
            let si_code = si_code_of(&info);
            exit_sig.store(sig, Ordering::SeqCst);
            exit_sender.store(sender, Ordering::SeqCst);
            // si_pid / si_code / trusted tree never set clean_exit. Only a
            // pre-existing HMAC stop marker does (systemd/guard writes it, then signals).
            let signature_present = crate::phoenix::stop_marker_valid(
                &ctx.clean_marker,
                ctx.hmac_secret.as_deref(),
                std::process::id(),
            );
            let clean = crate::phoenix::decide_clean_shutdown(
                info.signal,
                sender,
                si_code,
                false,
                signature_present,
            );
            eprintln!(
                "[sysspectogram-agent] signal {sig} si_pid={sender} si_code={} ({si_code}) clean={clean}",
                si_code_label(&info)
            );
            if clean {
                clean_exit.store(true, Ordering::SeqCst);
            } else if let Some(alert) = lethal_signal_alert(sig, sender, &ctx.host) {
                // Jsonl is mandatory when configured. Socket and TG are best-effort
                // and must not take a lock the main loop holds. Never write a marker here.
                if let Some(ref path) = ctx.jsonl {
                    if let Err(e) = crate::emit::append_jsonl(path, &alert) {
                        eprintln!("[sysspectogram-agent] kill witness jsonl: {e}");
                    }
                }
                if let Ok(line) = serde_json::to_string(&alert) {
                    crate::emit::best_effort_socket(&ctx.socket, &line);
                }
                if let Err(e) = crate::tg_notify::send_critical(&alert.message, &ctx.notify_env) {
                    eprintln!("[sysspectogram-agent] kill witness TG: {e}");
                }
            }
            running.store(false, Ordering::SeqCst);
        }
    });
}

fn absolutize_runtime_paths(args: &mut Args) {
    let paths = [
        &mut args.socket,
        &mut args.pidfile,
        &mut args.watchdog_pidfile,
        &mut args.guard_pidfile,
        &mut args.clean_marker,
        &mut args.hmac_secret,
        &mut args.notify_env,
        &mut args.fim_baseline,
        &mut args.kirk_baseline,
        &mut args.unit_file,
    ];
    for p in paths {
        *p = absolutize_path(p.clone());
    }
    if let Some(ref mut j) = args.jsonl {
        *j = absolutize_path(j.clone());
    }
    if let Some(ref mut w) = args.watch_pidfile {
        *w = absolutize_path(w.clone());
    }
    if let Some(ref mut r) = args.respawn_exe {
        *r = absolutize_path(r.clone());
    }
    eprintln!(
        "[sysspectogram-agent] pidfiles agent={} watchdog={} guard={}",
        args.pidfile.display(),
        args.watchdog_pidfile.display(),
        args.guard_pidfile.display()
    );
}

fn absolutize_path(p: PathBuf) -> PathBuf {
    std::path::absolute(&p).unwrap_or(p)
}

/// Build phoenix respawn argv so the twin keeps the same trust/config surface.
fn build_phoenix_respawn_args(args: &Args, host: &str, root_watch: bool) -> Vec<String> {
    let mut respawn_args: Vec<String> = vec![
        "--mode".into(),
        args.mode.clone(),
        "--socket".into(),
        args.socket.display().to_string(),
        "--pidfile".into(),
        args.pidfile.display().to_string(),
        "--watchdog-pidfile".into(),
        args.watchdog_pidfile.display().to_string(),
        "--guard-pidfile".into(),
        args.guard_pidfile.display().to_string(),
        "--host-id".into(),
        host.to_string(),
        "--hmac-secret".into(),
        args.hmac_secret.display().to_string(),
        "--clean-marker".into(),
        args.clean_marker.display().to_string(),
        "--metrics-ms".into(),
        args.metrics_ms.to_string(),
    ];
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
    for allow in &args.root_allow {
        respawn_args.push("--root-allow".into());
        respawn_args.push(allow.clone());
    }
    if args.fim {
        respawn_args.push("--fim".into());
        respawn_args.push("--fim-interval-sec".into());
        respawn_args.push(args.fim_interval_sec.to_string());
        respawn_args.push("--fim-baseline".into());
        respawn_args.push(args.fim_baseline.display().to_string());
    }
    respawn_args
}

/// Best-effort Linux `si_code`. `SI_USER`=0, `SI_QUEUE`=-1, `SI_KERNEL`=0x80.
/// Unknown causes stay 0 and are still not a clean shutdown.
fn si_code_of(origin: &signal_hook::iterator::exfiltrator::origin::Origin) -> i32 {
    use signal_hook::low_level::siginfo::{Cause, Sent};
    match origin.cause {
        Cause::Kernel => 0x80,
        Cause::Sent(sent) => match sent {
            Sent::User => 0,
            Sent::Queue => -1,
            Sent::TKill => -6,
            Sent::MesgQ => -3,
            _ => 0,
        },
        Cause::Unknown => 0,
        _ => 0,
    }
}

fn si_code_label(origin: &signal_hook::iterator::exfiltrator::origin::Origin) -> String {
    use signal_hook::low_level::siginfo::{Cause, Sent};
    match origin.cause {
        Cause::Kernel => "SI_KERNEL".to_string(),
        Cause::Sent(sent) => match sent {
            Sent::User => "SI_USER".to_string(),
            Sent::Queue => "SI_QUEUE".to_string(),
            Sent::TKill => "SI_TKILL".to_string(),
            Sent::MesgQ => "SI_MESGQ".to_string(),
            _ => format!("SI_SENT({sent:?})"),
        },
        Cause::Unknown => "SI_UNKNOWN".to_string(),
        other => format!("si_code({other:?})"),
    }
}

fn lethal_signal_alert(sig: u32, sender: u32, host: &str) -> Option<crate::types::AgentAlert> {
    let targets = crate::trust::KillTargets {
        self_pid: std::process::id(),
        watchdog_pid: None,
        guard_pid: None,
    };
    crate::trust::classify_kill(
        sender,
        std::process::id(),
        sig,
        &targets,
        &std::collections::HashSet::new(),
        host,
    )
}

fn hostname_fallback() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod respawn_args_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn phoenix_respawn_keeps_guard_pidfile_and_root_allow() {
        let args = Args::parse_from([
            "sysspectogram-agent",
            "--mode",
            "userspace",
            "--socket",
            "/tmp/a.sock",
            "--pidfile",
            "/run/agent.pid",
            "--watchdog-pidfile",
            "/run/sysspectogram/watchdog.pid",
            "--guard-pidfile",
            "/var/lib/sysspectogram/state/guard.pid",
            "--hmac-secret",
            "/run/hmac",
            "--clean-marker",
            "/run/clean",
            "--root-allow",
            "/usr/sbin/cron",
            "--metrics-ms",
            "2500",
        ]);
        let out = build_phoenix_respawn_args(&args, "host-x", true);
        assert!(out.windows(2).any(|w| w[0] == "--guard-pidfile"
            && w[1] == "/var/lib/sysspectogram/state/guard.pid"));
        assert!(out.windows(2).any(|w| w[0] == "--watchdog-pidfile"
            && w[1] == "/run/sysspectogram/watchdog.pid"));
        assert!(out.windows(2).any(|w| w[0] == "--root-allow" && w[1] == "/usr/sbin/cron"));
        assert!(out.windows(2).any(|w| w[0] == "--metrics-ms" && w[1] == "2500"));
        assert!(out.iter().any(|a| a == "--root-watch"));
    }

    #[test]
    fn watchdog_pidfile_arg_parsed() {
        let args = Args::parse_from([
            "sysspectogram-agent",
            "--watchdog-pidfile",
            "/run/sysspectogram/watchdog.pid",
        ]);
        assert_eq!(
            args.watchdog_pidfile,
            PathBuf::from("/run/sysspectogram/watchdog.pid")
        );
    }
}
