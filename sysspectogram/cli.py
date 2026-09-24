from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from sysspectogram import __version__
from sysspectogram.config import ROOT, load_config
from sysspectogram.response.actions import NftBackend

console = Console()


def _resolve(path: str | Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return (ROOT / p).resolve()


def _cmd_collect(args: argparse.Namespace) -> int:
    from sysspectogram.collect.daemon import CollectDaemon
    from sysspectogram.collect.metrics import MetricsCollector

    cfg = load_config(args.config)
    col_cfg = cfg.get("collector", {})
    collector = MetricsCollector(
        max_cores=int(col_cfg.get("max_cores", 16)),
        socket_sample_every=int(col_cfg.get("socket_sample_every", 5)),
    )
    daemon = CollectDaemon(
        collector,
        interval_sec=float(col_cfg.get("interval_sec", 1.0)),
        csv_path=Path(args.out),
    )
    console.print(f"collecting -> {args.out} duration={args.duration or 'inf'}")
    n = daemon.run(duration_sec=args.duration)
    console.print(f"wrote {n} samples")
    return 0


def _cmd_build_dataset(args: argparse.Namespace) -> int:
    from sysspectogram.preprocess.dataset_builder import build_dataset

    cfg = load_config(args.config)
    win = cfg.get("window", {})
    train = cfg.get("train", {})
    meta = build_dataset(
        normal_csvs=[Path(p) for p in args.normal],
        anomaly_csvs=[Path(p) for p in args.anomaly],
        out_dir=Path(args.out),
        window_size=int(args.window or win.get("size", 60)),
        stride=int(args.stride or win.get("stride", 5)),
        write_png=args.png,
        val_ratio=float(train.get("val_ratio", 0.2)),
        seed=int(train.get("seed", 42)),
        max_normal_cpu_mean=None if args.max_normal_cpu_mean < 0 else args.max_normal_cpu_mean,
        min_anomaly_cpu_mean=None if args.min_anomaly_cpu_mean < 0 else args.min_anomaly_cpu_mean,
        balance=not args.no_balance,
    )
    console.print(meta)
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    from sysspectogram.ml.train import train_models

    cfg = load_config(args.config)
    t = cfg.get("train", {})
    train_models(
        dataset_dir=Path(args.dataset),
        out_dir=Path(args.out),
        epochs=int(args.epochs or t.get("epochs", 15)),
        batch_size=int(t.get("batch_size", 32)),
        lr=float(t.get("lr", 1e-3)),
        seed=int(t.get("seed", 42)),
        cnn_weight=float(t.get("cnn_weight", 0.6)),
        iforest_weight=float(t.get("iforest_weight", 0.4)),
        recall_target=float(t.get("recall_target", 0.9)),
    )
    return 0


def _cmd_monitor(args: argparse.Namespace) -> int:
    from sysspectogram.runtime_monitor import run_monitor

    cfg = load_config(args.config)
    m = cfg.get("monitor", {})
    c = cfg.get("collector", {})
    run_monitor(
        Path(args.model),
        interval_sec=float(args.interval or m.get("interval_sec", 5)),
        cooldown_sec=float(args.cooldown or m.get("cooldown_sec", 60)),
        top_processes=int(m.get("top_processes", 3)),
        max_cores=int(c.get("max_cores", 16)),
        socket_sample_every=int(c.get("socket_sample_every", 5)),
        jsonl_out=Path(args.jsonl_out) if args.jsonl_out else None,
    )
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    from sysspectogram.runtime_analyze import run_analyze

    cfg = load_config(args.config)
    stride = int(cfg.get("window", {}).get("stride", 5))
    run_analyze(
        csv_path=Path(args.csv),
        artifacts_dir=Path(args.model),
        out_path=Path(args.out) if args.out else None,
        stride=stride,
    )
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    from sysspectogram.audit.ports import list_listening_and_established
    from sysspectogram.audit.processes import list_top_processes, suspicious_heuristics
    from sysspectogram.audit.report import build_report, write_json
    from sysspectogram.audit.rootkit import rootkit_heuristics

    what = args.what
    processes = list_top_processes(10) if what in {"processes", "report"} else None
    suspicious = suspicious_heuristics() if what in {"processes", "report"} else None
    ports = list_listening_and_established() if what in {"ports", "report"} else None
    rootkit = rootkit_heuristics() if what in {"rootkit", "report"} else None

    if what == "processes":
        console.print(processes)
        console.print(suspicious)
    elif what == "ports":
        console.print(ports)
    elif what == "rootkit":
        console.print(rootkit)
    else:
        report = build_report(processes=processes, suspicious=suspicious, ports=ports)
        report["rootkit"] = rootkit
        if args.out:
            write_json(Path(args.out), report)
            console.print(f"wrote {args.out}")
        else:
            console.print(report)
    return 0


def _cmd_simulate(args: argparse.Namespace) -> int:
    from sysspectogram.simulate.loads import (
        burn_cpu,
        burn_gpu,
        flood_local_net,
        pressure_memory,
        thrash_disk,
    )

    kind = args.kind
    duration = float(args.duration)
    console.print(f"simulate {kind} duration={duration}s")
    if kind == "cpu":
        burn_cpu(duration, workers=args.workers)
    elif kind == "mem":
        pressure_memory(duration, megabytes=args.mb)
    elif kind == "disk":
        thrash_disk(duration, block_mb=args.block_mb)
    elif kind == "net":
        flood_local_net(duration, connections_per_sec=args.rate)
    elif kind == "gpu":
        burn_gpu(duration, size=args.gpu_size)
    else:
        console.print(f"unknown kind {kind}")
        return 2
    return 0


def _cmd_watch_perimeter(args: argparse.Namespace) -> int:
    from sysspectogram.perimeter.watcher import PerimeterWatcher

    cfg = load_config(args.config)
    per = cfg.get("perimeter", {})
    recon = cfg.get("recon", {})
    host = cfg.get("host", {})
    denylist = [_resolve(p) for p in (args.denylist or per.get("denylist_paths") or [])]
    watcher = PerimeterWatcher(
        host_id=host.get("id"),
        fail_threshold=int(per.get("fail_threshold", 8)),
        fail_window_sec=float(per.get("fail_window_sec", 60)),
        scan_unique_ips=int(per.get("scan_unique_ips", 8)),
        scan_window_sec=float(per.get("scan_window_sec", 60)),
        denylist_paths=denylist,
        suspicious_domains=set(per.get("suspicious_domains") or []),
        state_path=_resolve(per.get("state_path", "state/perimeter.json")),
        jsonl_out=_resolve(args.jsonl_out or per.get("jsonl_out", "reports/perimeter.jsonl")),
        recon_dir=_resolve(recon.get("dir", "reports/recon")),
        recon_cooldown_sec=float(recon.get("cooldown_sec", 900)),
        auto_recon=bool(recon.get("auto", False)) and not args.no_recon,
        include_nmap=bool(recon.get("nmap", False)),
        lab_nmap_targets=list((cfg.get("lab") or {}).get("nmap_targets") or ["127.0.0.1", "::1"]),
        passive_dns_url=recon.get("passive_dns_url"),
        poll_sec=float(args.poll or per.get("poll_sec", 2.0)),
        alert_new_egress=bool(per.get("alert_new_egress", False)),
        nft=NftBackend(),
        auto_ban_rules=(
            set((per.get("auto_ban") or {}).get("rules") or [])
            if (per.get("auto_ban") or {}).get("enabled")
            else set()
        ),
        auto_ban_ttl_sec=float((per.get("auto_ban") or {}).get("ttl_sec", 3600)),
    )
    watcher.run(duration_sec=args.duration)
    return 0


def _cmd_recon(args: argparse.Namespace) -> int:
    from sysspectogram.osint.recon import run_full_recon, save_report

    cfg = load_config(args.config)
    recon = cfg.get("recon", {})
    lab = cfg.get("lab") or {}
    want_nmap = bool(recon.get("nmap", False)) and not args.no_nmap
    report = run_full_recon(
        args.ip,
        include_nmap=want_nmap,
        include_ct=not args.no_ct,
        passive_dns_url=recon.get("passive_dns_url"),
        lab_targets=list(lab.get("nmap_targets") or ["127.0.0.1", "::1"]),
        require_lab_for_nmap=True,
    )
    out = _resolve(args.out or Path(recon.get("dir", "reports/recon")) / "recon.jsonl")
    save_report(report, out)
    console.print(report.summary_text())
    console.print(f"appended {out}")
    return 0


def _cmd_guard(args: argparse.Namespace) -> int:
    from sysspectogram.guard import run_guard

    cfg = load_config(args.config)
    model = _resolve(args.model) if args.model else None
    jsonl = _resolve(args.jsonl_out) if args.jsonl_out else None
    run_guard(
        artifacts_dir=model,
        config=cfg,
        telegram=bool(args.telegram),
        dry_run_actions=bool(args.dry_run),
        duration_sec=args.duration,
        jsonl_out=jsonl,
    )
    return 0


def _cmd_lab_nmap(args: argparse.Namespace) -> int:
    from sysspectogram.lab_nmap import main as lab_main

    argv = ["--lab", args.target]
    if args.config:
        argv = ["--config", args.config, "--lab", args.target]
    return lab_main(argv)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sysspectogram",
        description="Hybrid ML host anomaly detection + defensive audit (Linux)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", default=None, help="path to YAML config")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="collect system metrics to CSV")
    c.add_argument("--out", required=True)
    c.add_argument("--duration", type=float, default=None)
    c.set_defaults(func=_cmd_collect)

    b = sub.add_parser("build-dataset", help="cut CSV logs into train/val windows")
    b.add_argument("--normal", nargs="+", required=True)
    b.add_argument("--anomaly", nargs="+", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--window", type=int, default=None)
    b.add_argument("--stride", type=int, default=None)
    b.add_argument("--png", action="store_true")
    b.add_argument(
        "--max-normal-cpu-mean",
        type=float,
        default=25.0,
        help="drop normal windows with mean cpu_percent above this (None via -1)",
    )
    b.add_argument(
        "--min-anomaly-cpu-mean",
        type=float,
        default=45.0,
        help="drop anomaly windows with mean cpu_percent below this (-1 disables)",
    )
    b.add_argument("--no-balance", action="store_true", help="do not undersample to equal class counts")
    b.set_defaults(func=_cmd_build_dataset)

    t = sub.add_parser("train", help="train CNN + IsolationForest ensemble")
    t.add_argument("--dataset", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--epochs", type=int, default=None)
    t.set_defaults(func=_cmd_train)

    m = sub.add_parser("monitor", help="realtime anomaly monitoring")
    m.add_argument("--model", required=True, help="artifacts directory")
    m.add_argument("--interval", type=float, default=None)
    m.add_argument("--cooldown", type=float, default=None)
    m.add_argument("--jsonl-out", default=None)
    m.set_defaults(func=_cmd_monitor)

    a = sub.add_parser("analyze", help="offline CSV analysis")
    a.add_argument("--csv", required=True)
    a.add_argument("--model", required=True)
    a.add_argument("--out", default=None)
    a.set_defaults(func=_cmd_analyze)

    au = sub.add_parser("audit", help="defensive host snapshot")
    au.add_argument("what", choices=["processes", "ports", "report", "rootkit"])
    au.add_argument("--out", default=None)
    au.set_defaults(func=_cmd_audit)

    s = sub.add_parser("simulate", help="generate local anomalous load")
    s.add_argument("kind", choices=["cpu", "mem", "disk", "net", "gpu"])
    s.add_argument("--duration", type=float, default=60.0)
    s.add_argument("--workers", type=int, default=None)
    s.add_argument("--mb", type=int, default=512)
    s.add_argument("--block-mb", type=int, default=32)
    s.add_argument("--rate", type=int, default=80)
    s.add_argument("--gpu-size", type=int, default=2048)
    s.set_defaults(func=_cmd_simulate)

    wp = sub.add_parser("watch-perimeter", help="perimeter / egress / DNS watcher")
    wp.add_argument("--duration", type=float, default=None)
    wp.add_argument("--poll", type=float, default=None)
    wp.add_argument("--jsonl-out", default=None)
    wp.add_argument("--denylist", nargs="*", default=None)
    wp.add_argument("--no-recon", action="store_true")
    wp.set_defaults(func=_cmd_watch_perimeter)

    rc = sub.add_parser("recon", help="OSINT + optional nmap on an IP")
    rc.add_argument("ip")
    rc.add_argument("--out", default=None)
    rc.add_argument("--no-nmap", action="store_true")
    rc.add_argument("--no-ct", action="store_true")
    rc.set_defaults(func=_cmd_recon)

    g = sub.add_parser("guard", help="perimeter + host ML + telegram control plane")
    g.add_argument("--model", default=None, help="artifacts directory (optional)")
    g.add_argument("--telegram", action="store_true")
    g.add_argument("--dry-run", action="store_true", help="do not apply nft/kill")
    g.add_argument("--duration", type=float, default=None)
    g.add_argument("--jsonl-out", default=None)
    g.set_defaults(func=_cmd_guard)

    ln = sub.add_parser("lab-nmap", help="nmap allowlisted lab targets only")
    ln.add_argument("target")
    ln.set_defaults(func=_cmd_lab_nmap)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
