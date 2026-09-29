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
    try:
        import torch  # noqa: F401
    except ImportError:
        console.print("[red]train needs PyTorch[/]: pip install -e '.[ml]'")
        return 2
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


def _cmd_export_onnx(args: argparse.Namespace) -> int:
    from sysspectogram.ml.export_onnx import export_cnn_onnx

    meta = export_cnn_onnx(
        _resolve(args.model),
        out_path=_resolve(args.out) if args.out else None,
    )
    console.print(f"[green]exported[/] {meta['onnx']} ({meta['height']}x{meta['width']})")
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
        supply_chain=cfg.get("supply_chain") or {},
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
        supply_chain=cfg.get("supply_chain") or {},
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
        enable_web=bool(getattr(args, "web", False)),
    )
    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    from sysspectogram.web.runtime import run_web_dashboard

    cfg = load_config(args.config)
    model = _resolve(args.model) if args.model else None
    run_web_dashboard(
        config=cfg,
        artifacts_dir=model,
        host=args.host,
        port=args.port,
        duration_sec=args.duration,
    )
    return 0


def _cmd_profiles(args: argparse.Namespace) -> int:
    from sysspectogram.profiles import (
        finetune_note,
        install_profile,
        list_builtin_roles,
        pack_profile,
        pull_profile,
    )

    action = args.profiles_action
    if action == "list":
        for row in list_builtin_roles():
            console.print(f"{row['name']:32} role={row['role']}  {row['note']}")
        console.print(
            "\n[dim]Publish packs as GitHub Release assets: profile-<role>-v1.tar.gz + .sha256[/]"
        )
        return 0
    if action == "pack":
        meta = pack_profile(
            name=args.name,
            role=args.role,
            host_artifacts=_resolve(args.host),
            out_tar=_resolve(args.out),
            agent_iforest=_resolve(args.agent_if) if args.agent_if else None,
            description=args.description or "",
            minisign_secret_key=(
                _resolve(args.minisign_secret_key) if args.minisign_secret_key else None
            ),
        )
        console.print(f"[green]packed[/] {meta['path']} sha256={meta['sha256'][:16]}…")
        return 0
    if action == "pull":
        dest = _resolve(args.out)
        pull_profile(
            args.url,
            dest,
            expected_sha256=args.sha256,
            insecure_no_verify=bool(args.insecure),
        )
        console.print(f"[green]downloaded[/] {dest}")
        return 0
    if action == "install":
        info = install_profile(
            _resolve(args.tar),
            _resolve(args.dest),
            expected_sha256=args.sha256,
            insecure_no_verify=bool(args.insecure),
            public_key=_resolve(args.public_key) if args.public_key else None,
            require_minisign=bool(args.require_signature),
        )
        console.print(f"[green]installed[/] host={info['host']}")
        if info.get("agent_iforest"):
            console.print(f"  agent IF: {info['agent_iforest']}")
        console.print(f"  guard --model {info['host']}")
        return 0
    if action == "finetune-help":
        console.print(finetune_note(_resolve(args.host or "artifacts/profiles/local/host")))
        return 0
    console.print("unknown profiles action")
    return 1


def _cmd_feedback(args: argparse.Namespace) -> int:
    if args.feedback_action == "retrain":
        from sysspectogram.feedback_retrain import retrain_from_feedback

        info = retrain_from_feedback(
            _resolve(args.feedback_dir),
            out_artifacts=_resolve(args.out),
            epochs=int(args.epochs),
        )
        console.print(f"[green]feedback retrain[/] {info}")
        return 0
    if args.feedback_action == "retrain-if":
        from sysspectogram.feedback_iforest import refit_host_iforest

        info = refit_host_iforest(
            _resolve(args.model),
            _resolve(args.feedback_dir),
            supply_chain=(load_config(args.config).get("supply_chain") or {}),
            minisign_secret_key=(
                _resolve(args.minisign_secret_key) if args.minisign_secret_key else None
            ),
        )
        console.print(f"[green]IF refit[/] {info}")
        return 0
    if args.feedback_action == "status":
        from sysspectogram.feedback_learn import FeedbackLearner

        fl = FeedbackLearner(_resolve(args.feedback_dir))
        console.print(f"counts={fl.counts()} bias={fl.threshold_bias():+.3f}")
        return 0
    console.print("unknown feedback action")
    return 1


def _cmd_train_agent_if(args: argparse.Namespace) -> int:
    from sysspectogram.agent_score import train_agent_iforest

    paths = [_resolve(p) for p in args.jsonl]
    meta = train_agent_iforest(paths, _resolve(args.out), contamination=float(args.contamination))
    console.print(f"[green]agent IF[/] wrote {_resolve(args.out)} samples={meta['n_samples']}")
    return 0


def _cmd_data(args: argparse.Namespace) -> int:
    from sysspectogram.data_bridge import create_data_bundle, pull_cmd, unpack_data_bundle

    if args.data_action == "bundle":
        meta = create_data_bundle(
            [_resolve(p) for p in args.csv],
            _resolve(args.out),
            note=args.note or "",
            host_id=args.host_id,
        )
        console.print(
            f"[green]bundled[/] {meta['path']} sha256={meta['sha256'][:16]}… csv={meta['csv']}"
        )
        return 0
    if args.data_action == "unpack":
        info = unpack_data_bundle(_resolve(args.tar), _resolve(args.dest))
        console.print(f"[green]unpacked[/] csv_dir={info['csv_dir']}")
        return 0
    if args.data_action == "pull-cmd":
        console.print(pull_cmd(args.bundle, args.ssh))
        return 0
    console.print("unknown data action")
    return 1


def _cmd_artifacts(args: argparse.Namespace) -> int:
    from sysspectogram.data_bridge import push_artifacts

    if args.artifacts_action == "push":
        info = push_artifacts(
            _resolve(args.model),
            ssh=args.ssh,
            remote_dir=args.remote,
            restart_unit=args.restart_systemd,
        )
        console.print(f"[green]pushed[/] → {info['ssh']}:{info['remote']}")
        return 0
    console.print("unknown artifacts action")
    return 1


def _cmd_setup(args: argparse.Namespace) -> int:
    from sysspectogram.setup_wizard import run_setup

    run_setup(prefix=_resolve(args.prefix), role=getattr(args, "role", None))
    return 0


def _cmd_configure(args: argparse.Namespace) -> int:
    from sysspectogram.configure_tui import run_configure

    run_configure(
        prefix=_resolve(args.prefix),
        config_path=_resolve(args.config) if args.config else None,
        accept_recommended=bool(args.accept_recommended),
        non_interactive=bool(args.non_interactive or args.accept_recommended),
        role=getattr(args, "role", None),
        seed_fp=not bool(args.no_seed_fp),
    )
    return 0


def _cmd_labels(args: argparse.Namespace) -> int:
    from sysspectogram.process_labels import ProcessLabelStore
    from sysspectogram.role_fp import list_seed_roles, seed_role_labels

    store = ProcessLabelStore(_resolve(args.store))
    if args.labels_action == "list":
        for r in store.list_rules():
            console.print(f"{r.id} {r.label} {r.match} {r.pattern} src={r.source}")
        console.print(f"total={len(store.list_rules())}")
        return 0
    if args.labels_action == "seed":
        n = seed_role_labels(store, args.role)
        console.print(f"[green]seeded[/] role={args.role} rules={n} roles={list_seed_roles()}")
        return 0
    if args.labels_action == "del":
        ok = store.delete(args.id)
        console.print("deleted" if ok else "not found")
        return 0 if ok else 1
    console.print("unknown labels action")
    return 1


def _cmd_kirk(args: argparse.Namespace) -> int:
    from sysspectogram.kirk_trust import probe_kirk_trust

    if args.kirk_action == "trust":
        report = probe_kirk_trust(require_tpm=bool(args.require_tpm))
        console.print(f"[cyan]trust[/] {report.trust}")
        console.print(
            f"ima={report.ima_present} measurements={report.ima_measurements} "
            f"secure_boot={report.secure_boot} tpm={report.tpm_present}"
        )
        for d in report.details:
            console.print(f"  - {d}")
        if report.trust == "best-effort":
            console.print(
                "[dim]Without IMA + Secure Boot/TPM this is best-effort, not integrity proof. "
                "VMI deferred to v1.0 (docs/VMI.md).[/]"
            )
        return 0
    console.print("unknown kirk action")
    return 1


def _cmd_supply_chain(args: argparse.Namespace) -> int:
    from sysspectogram.supply_chain import (
        sign_file,
        verify_artifacts,
        verify_file,
        write_manifest,
    )

    if args.supply_action == "manifest":
        path = write_manifest(
            _resolve(args.root),
            output=_resolve(args.output) if args.output else None,
        )
        console.print(f"[green]manifest[/] {path}")
        return 0
    if args.supply_action == "sign":
        path = sign_file(
            _resolve(args.file),
            _resolve(args.secret_key),
            signature_path=_resolve(args.signature) if args.signature else None,
        )
        console.print(f"[green]signed[/] {path}")
        return 0
    if args.supply_action == "sbom":
        from sysspectogram.sbom import write_sbom

        root = _resolve(args.root)
        output = _resolve(args.output)
        files = [root / relative for relative in args.file]
        write_sbom(root, output, include_files=files)
        console.print(f"[green]sbom[/] {output}")
        return 0
    if args.supply_action == "verify":
        root = _resolve(args.root)
        if args.file:
            if not args.public_key:
                raise ValueError("--public-key is required with --file")
            verify_file(
                _resolve(args.file),
                _resolve(args.public_key),
                signature_path=_resolve(args.signature) if args.signature else None,
            )
            result = {
                "file_verified": True,
                "signed": True,
                "enforced": bool(args.enforce),
            }
            manifest = root / "artifacts.manifest.json"
            if manifest.exists():
                result.update(
                    verify_artifacts(
                        root,
                        enforce=bool(args.enforce),
                        public_key=_resolve(args.public_key),
                    )
                )
        else:
            result = verify_artifacts(
                root,
                enforce=bool(args.enforce),
                public_key=_resolve(args.public_key) if args.public_key else None,
            )
        console.print(f"[green]verified[/] {result}")
        return 0
    console.print("unknown supply-chain action")
    return 1


def _cmd_role_lab(args: argparse.Namespace) -> int:
    from sysspectogram.rolelab import list_roles, run_role_collect, train_role_pack

    if args.rolelab_action == "list":
        for r in list_roles():
            console.print(r)
        return 0
    if args.rolelab_action == "run":
        man = run_role_collect(
            args.role,
            out_dir=_resolve(args.out),
            duration_sec=float(args.duration),
            hybrid=not bool(args.synthetic_only),
        )
        console.print(
            f"[green]role-lab[/] role={man['role']} samples_n={man['samples_normal']} "
            f"samples_a={man['samples_anomaly']} → {args.out}"
        )
        return 0
    if args.rolelab_action == "train":
        try:
            import torch  # noqa: F401
        except ImportError:
            console.print("[red]train needs PyTorch[/]: pip install -e '.[ml]'")
            return 2
        info = train_role_pack(
            _resolve(args.role_dir),
            out_artifacts=_resolve(args.out),
            pack_out=_resolve(args.pack) if args.pack else None,
            epochs=int(args.epochs),
            minisign_secret_key=(
                _resolve(args.minisign_secret_key) if args.minisign_secret_key else None
            ),
        )
        console.print(f"[green]trained[/] {info}")
        return 0
    console.print("unknown role-lab action")
    return 1


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

    eo = sub.add_parser("export-onnx", help="export cnn.pt → cnn.onnx (needs .[ml])")
    eo.add_argument("--model", required=True, help="artifacts directory with cnn.pt")
    eo.add_argument("--out", default=None, help="default: <model>/cnn.onnx")
    eo.set_defaults(func=_cmd_export_onnx)

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

    sc = sub.add_parser("supply-chain", help="manifest and minisign artifact trust")
    sc_sub = sc.add_subparsers(dest="supply_action", required=True)
    sc_manifest = sc_sub.add_parser("manifest", help="write a deterministic artifact manifest")
    sc_manifest.add_argument("root")
    sc_manifest.add_argument("--output", default=None)
    sc_manifest.set_defaults(func=_cmd_supply_chain)
    sc_sign = sc_sub.add_parser("sign", help="sign a file with minisign")
    sc_sign.add_argument("file")
    sc_sign.add_argument("--secret-key", required=True)
    sc_sign.add_argument("--signature", default=None)
    sc_sign.set_defaults(func=_cmd_supply_chain)
    sc_sbom = sc_sub.add_parser("sbom", help="write a deterministic SPDX 2.3 SBOM")
    sc_sbom.add_argument("--root", default=".")
    sc_sbom.add_argument("--output", required=True)
    sc_sbom.add_argument("--file", action="append", default=[])
    sc_sbom.set_defaults(func=_cmd_supply_chain)
    sc_verify = sc_sub.add_parser("verify", help="verify a manifest and optional file signature")
    sc_verify.add_argument("root")
    sc_verify.add_argument("--public-key", default=None)
    sc_verify.add_argument("--file", default=None)
    sc_verify.add_argument("--signature", default=None)
    sc_verify.add_argument("--enforce", action="store_true")
    sc_verify.set_defaults(func=_cmd_supply_chain)

    g = sub.add_parser("guard", help="perimeter + host ML + telegram control plane")
    g.add_argument("--model", default=None, help="artifacts directory (optional)")
    g.add_argument("--telegram", action="store_true")
    g.add_argument("--web", action="store_true", help="serve live dashboard (localhost + Mini App URL)")
    g.add_argument("--dry-run", action="store_true", help="do not apply nft/kill")
    g.add_argument("--duration", type=float, default=None)
    g.add_argument("--jsonl-out", default=None)
    g.set_defaults(func=_cmd_guard)

    tai = sub.add_parser("train-agent-if", help="train IsolationForest on agent JSONL windows")
    tai.add_argument("--jsonl", nargs="+", required=True, help="agent NDJSON logs")
    tai.add_argument("--out", required=True, help="output joblib path")
    tai.add_argument("--contamination", type=float, default=0.05)
    tai.set_defaults(func=_cmd_train_agent_if)

    pr = sub.add_parser("profiles", help="shareable baseline packs (tar.gz for GitHub Releases)")
    pr_sub = pr.add_subparsers(dest="profiles_action", required=True)
    pr_list = pr_sub.add_parser("list", help="catalog of role packs")
    pr_list.set_defaults(func=_cmd_profiles)
    pr_pack = pr_sub.add_parser("pack", help="build profile-*.tar.gz")
    pr_pack.add_argument("--name", required=True)
    pr_pack.add_argument("--role", required=True)
    pr_pack.add_argument("--host", required=True, help="host artifacts dir")
    pr_pack.add_argument("--out", required=True, help="output .tar.gz path")
    pr_pack.add_argument("--agent-if", default=None, help="optional agent_iforest.joblib")
    pr_pack.add_argument("--description", default="")
    pr_pack.add_argument(
        "--minisign-secret-key",
        default=None,
        help="optional minisign secret key; writes <pack>.minisig",
    )
    pr_pack.set_defaults(func=_cmd_profiles)
    pr_pull = pr_sub.add_parser("pull", help="download pack URL")
    pr_pull.add_argument("--url", required=True)
    pr_pull.add_argument("--out", required=True)
    pr_pull.add_argument("--sha256", default=None)
    pr_pull.add_argument("--insecure", action="store_true", help="allow pull without sha256")
    pr_pull.set_defaults(func=_cmd_profiles)
    pr_inst = pr_sub.add_parser("install", help="extract pack into artifacts/profiles/...")
    pr_inst.add_argument("tar")
    pr_inst.add_argument("--dest", required=True)
    pr_inst.add_argument("--sha256", default=None)
    pr_inst.add_argument("--insecure", action="store_true", help="allow install without sha256")
    pr_inst.add_argument("--public-key", default=None, help="minisign public key file/value")
    pr_inst.add_argument(
        "--require-signature",
        action="store_true",
        help="require <pack>.minisig and verify it before extraction",
    )
    pr_inst.set_defaults(func=_cmd_profiles)
    pr_ft = pr_sub.add_parser("finetune-help", help="print local fine-tune recipe")
    pr_ft.add_argument("--host", default="artifacts/profiles/local/host")
    pr_ft.set_defaults(func=_cmd_profiles)

    data = sub.add_parser("data", help="VPS↔PC train bridge (bundle CSV / unpack)")
    data_sub = data.add_subparsers(dest="data_action", required=True)
    db = data_sub.add_parser("bundle", help="pack CSVs into data bundle tar.gz")
    db.add_argument("--csv", nargs="+", required=True)
    db.add_argument("--out", required=True)
    db.add_argument("--note", default="")
    db.add_argument("--host-id", default=None)
    db.set_defaults(func=_cmd_data)
    du = data_sub.add_parser("unpack", help="extract data bundle")
    du.add_argument("tar")
    du.add_argument("--dest", required=True)
    du.set_defaults(func=_cmd_data)
    dp = data_sub.add_parser("pull-cmd", help="print rsync one-liner")
    dp.add_argument("--bundle", required=True, help="remote path on VPS")
    dp.add_argument("--ssh", required=True, help="user@host")
    dp.set_defaults(func=_cmd_data)

    ap = sub.add_parser("artifacts", help="push model artifacts to VPS over SSH")
    ap_sub = ap.add_subparsers(dest="artifacts_action", required=True)
    app = ap_sub.add_parser("push", help="rsync model dir → remote (atomic .next swap)")
    app.add_argument("--model", required=True)
    app.add_argument("--ssh", required=True)
    app.add_argument("--remote", required=True, help="e.g. /opt/sysspectogram/artifacts/live")
    app.add_argument("--restart-systemd", default=None)
    app.set_defaults(func=_cmd_artifacts)

    st = sub.add_parser("setup", help="interactive .env / Telegram setup (legacy)")
    st.add_argument("--prefix", default=".", help="install prefix (default: repo root)")
    st.add_argument("--role", default=None, help="role pack hint: nginx|ssh|docker|...")
    st.set_defaults(func=_cmd_setup)

    cfg = sub.add_parser("configure", help="unified Day-0 TUI: probe + profile + agent + TG + labels")
    cfg.add_argument("--prefix", default=".", help="install prefix")
    cfg.add_argument("--config", default=None, help="yaml config to write (default configs/default.yaml)")
    cfg.add_argument("--role", default=None)
    cfg.add_argument(
        "--accept-recommended",
        action="store_true",
        help="non-interactive: apply host_probe recommendations",
    )
    cfg.add_argument("--non-interactive", action="store_true")
    cfg.add_argument("--no-seed-fp", action="store_true", help="skip role FP label seed")
    cfg.set_defaults(func=_cmd_configure)

    lb = sub.add_parser("labels", help="process label rules (As normal / As anomaly store)")
    lb_sub = lb.add_subparsers(dest="labels_action", required=True)
    lb_list = lb_sub.add_parser("list")
    lb_list.add_argument("--store", default="state/process_labels.json")
    lb_list.set_defaults(func=_cmd_labels)
    lb_seed = lb_sub.add_parser("seed", help="seed role FP baselines")
    lb_seed.add_argument("--role", required=True)
    lb_seed.add_argument("--store", default="state/process_labels.json")
    lb_seed.set_defaults(func=_cmd_labels)
    lb_del = lb_sub.add_parser("del")
    lb_del.add_argument("id")
    lb_del.add_argument("--store", default="state/process_labels.json")
    lb_del.set_defaults(func=_cmd_labels)

    kk = sub.add_parser("kirk", help="kernel integrity trust probe (IMA/SB/TPM)")
    kk_sub = kk.add_subparsers(dest="kirk_action", required=True)
    kk_t = kk_sub.add_parser("trust", help="probe best-effort vs measured")
    kk_t.add_argument("--require-tpm", action="store_true")
    kk_t.set_defaults(func=_cmd_kirk)

    rl = sub.add_parser("role-lab", help="simulate VPS roles on PC and train baseline packs (no VMs)")
    rl_sub = rl.add_subparsers(dest="rolelab_action", required=True)
    rl_list = rl_sub.add_parser("list", help="list recipes")
    rl_list.set_defaults(func=_cmd_role_lab)
    rl_run = rl_sub.add_parser("run", help="collect CSV under role workload")
    rl_run.add_argument("--role", required=True, help="ssh|nginx|python|docker")
    rl_run.add_argument("--out", required=True, help="output dir (normal.csv + anomaly.csv)")
    rl_run.add_argument("--duration", type=float, default=600.0, help="seconds of normal collect")
    rl_run.add_argument(
        "--synthetic-only",
        action="store_true",
        help="never touch nginx/docker; pure synthetic load",
    )
    rl_run.set_defaults(func=_cmd_role_lab)
    rl_tr = rl_sub.add_parser("train", help="build-dataset + train (+pack) from role-lab dir")
    rl_tr.add_argument("--role-dir", required=True, help="dir from role-lab run")
    rl_tr.add_argument("--out", required=True, help="artifacts output dir")
    rl_tr.add_argument("--pack", default=None, help="optional profile-*.tar.gz path")
    rl_tr.add_argument("--epochs", type=int, default=12)
    rl_tr.add_argument(
        "--minisign-secret-key",
        default=None,
        help="sign the optional agent IF and profile pack",
    )
    rl_tr.set_defaults(func=_cmd_role_lab)

    fb = sub.add_parser("feedback", help="operator feedback samples / retrain on builder PC")
    fb_sub = fb.add_subparsers(dest="feedback_action", required=True)
    fb_st = fb_sub.add_parser("status", help="show counts + threshold bias")
    fb_st.add_argument("--feedback-dir", default="artifacts/feedback")
    fb_st.set_defaults(func=_cmd_feedback)
    fb_tr = fb_sub.add_parser("retrain", help="train CNN/IF from feedback npy (builder PC)")
    fb_tr.add_argument("--feedback-dir", default="artifacts/feedback")
    fb_tr.add_argument("--out", required=True, help="artifacts output dir")
    fb_tr.add_argument("--epochs", type=int, default=8)
    fb_tr.set_defaults(func=_cmd_feedback)
    fb_if = fb_sub.add_parser(
        "retrain-if",
        help="VPS-safe: refit IsolationForest only (CNN unchanged)",
    )
    fb_if.add_argument("--feedback-dir", default="artifacts/feedback")
    fb_if.add_argument("--model", required=True, help="artifacts dir with iforest.joblib")
    fb_if.add_argument(
        "--minisign-secret-key",
        default=None,
        help="required to re-sign an enforced model after refit",
    )
    fb_if.set_defaults(func=_cmd_feedback)

    w = sub.add_parser("web", help="live local / Telegram Mini App dashboard")
    w.add_argument("--model", default=None, help="optional artifacts for scoring")
    w.add_argument("--host", default=None)
    w.add_argument("--port", type=int, default=None)
    w.add_argument("--duration", type=float, default=None)
    w.set_defaults(func=_cmd_web)

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
