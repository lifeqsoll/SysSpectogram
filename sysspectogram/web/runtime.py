from __future__ import annotations

import socket
import threading
import time
from collections import deque
from pathlib import Path

from rich.console import Console

from sysspectogram.collect.daemon import CollectDaemon
from sysspectogram.collect.metrics import MetricsCollector
from sysspectogram.ml.infer import load_inferencer
from sysspectogram.preprocess.window import rows_to_matrix
from sysspectogram.viz.panels import detect_host_pattern
from sysspectogram.response.actions import NftBackend
from sysspectogram.console_unlock import ConsoleUnlock
from sysspectogram.web.actions import WebControllers
from sysspectogram.web.bus import GLOBAL_BUS, LiveAlert, LiveBus
from sysspectogram.web.server import start_web_server

console = Console()


def run_web_dashboard(
    *,
    config: dict,
    artifacts_dir: Path | None = None,
    host: str | None = None,
    port: int | None = None,
    duration_sec: float | None = None,
    bus: LiveBus | None = None,
) -> None:
    web_cfg = config.get("web") or {}
    tg_cfg = config.get("telegram") or {}
    col_cfg = config.get("collector") or {}
    mon_cfg = config.get("monitor") or {}
    host_cfg = config.get("host") or {}

    bind = host or web_cfg.get("host") or "127.0.0.1"
    listen_port = int(port or web_cfg.get("port") or 8765)
    public_url = web_cfg.get("public_url") or None
    import os

    public_url = os.environ.get("WEBAPP_URL") or os.environ.get("SYSPECTOGRAM_WEB_URL") or public_url

    bus = bus or GLOBAL_BUS
    host_id = host_cfg.get("id") or socket.gethostname()

    infer = None
    threshold = float((config.get("ensemble") or {}).get("default_threshold", 0.5))
    columns: list[str] = []
    if artifacts_dir is not None and Path(artifacts_dir).exists():
        try:
            infer = load_inferencer(
                Path(artifacts_dir),
                runtime="onnx" if (Path(artifacts_dir) / "cnn.onnx").exists() else "torch_ml",
            )
            threshold = infer.threshold
            columns = list(infer.columns)
            console.print(f"[green]web model[/] {artifacts_dir} thr={threshold:.3f}")
        except Exception as exc:
            console.print(f"[yellow]web model unavailable[/] {exc}")
            infer = None

    bus.set_host(host_id, threshold, model_loaded=infer is not None)

    nft = NftBackend()
    # attach a perimeter watcher so allow/mute/lockdown work in standalone web mode
    from sysspectogram.config import ROOT
    from sysspectogram.perimeter.watcher import PerimeterWatcher

    per = config.get("perimeter") or {}

    def _resolve(path: str | Path) -> Path:
        p = Path(path)
        return p if p.is_absolute() else (ROOT / p).resolve()

    watcher = PerimeterWatcher(
        host_id=host_id,
        state_path=_resolve(per.get("state_path", "state/perimeter.json")),
        denylist_paths=[_resolve(p) for p in (per.get("denylist_paths") or [])],
        auto_recon=False,
        include_nmap=False,
        nft=nft,
        alert_new_egress=bool(per.get("alert_new_egress", False)),
    )

    def _print_unlock(code: str) -> None:
        console.print("")
        console.print("[bold red]WEB UNLOCK CODE[/] (Mini App: enter code · or POST /api/unlock)")
        console.print(f"[bold white on red]  {code}  [/]")
        console.print("")

    want_unlock = bool(tg_cfg.get("require_console_unlock", True))
    has_bot_creds = bool(tg_cfg.get("bot_token") and tg_cfg.get("chat_id"))
    unlock_enabled = want_unlock and (bool(public_url) or has_bot_creds)
    unlock_gate = ConsoleUnlock(
        enabled=unlock_enabled,
        ttl_sec=float(tg_cfg.get("unlock_ttl_sec", 7200)),
        on_code=_print_unlock,
    )
    if unlock_gate.enabled and unlock_gate.pending_code:
        _print_unlock(unlock_gate.pending_code)

    controllers = WebControllers(
        bus=bus,
        nft=nft,
        watcher=watcher,
        dry_run=True,
        lab_nmap_targets=list((config.get("lab") or {}).get("nmap_targets") or ["127.0.0.1", "::1"]),
        include_nmap=bool((config.get("recon") or {}).get("nmap", False)),
        recon_dir=_resolve((config.get("recon") or {}).get("dir", "reports/recon")),
        unlock_ok=unlock_gate.unlocked if unlock_gate.enabled else None,
    )

    httpd = start_web_server(
        bus,
        host=bind,
        port=listen_port,
        bot_token=tg_cfg.get("bot_token"),
        allowed_chat_id=tg_cfg.get("chat_id"),
        public_url=public_url,
        controllers=controllers,
        unlock=unlock_gate if unlock_gate.enabled else None,
    )
    local = f"http://{bind}:{listen_port}/"
    console.print(f"[bold]web dashboard[/] {local}")
    if public_url:
        console.print(f"[cyan]Mini App URL[/] {public_url}")
    else:
        console.print(
            "[yellow]tip[/] set WEBAPP_URL to your HTTPS tunnel for Telegram phone access"
        )

    # optional: set Telegram menu button
    if public_url and tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
        try:
            from sysspectogram.notify_telegram import TelegramClient

            client = TelegramClient(token=tg_cfg.get("bot_token"), chat_id=tg_cfg.get("chat_id"))
            res = client.set_chat_menu_button_webapp("Dashboard", public_url)
            if res.get("ok"):
                console.print("[green]Telegram menu button → Dashboard[/]")
            else:
                console.print(f"[yellow]menu button[/] {res.get('description')}")
        except Exception as exc:
            console.print(f"[yellow]menu button soft-fail[/] {exc}")

    stop = threading.Event()
    collector = MetricsCollector(
        max_cores=int(col_cfg.get("max_cores", 16)),
        socket_sample_every=int(col_cfg.get("socket_sample_every", 5)),
    )
    if not columns:
        columns = [c for c in collector.columns if c != "timestamp"]
    buf: deque = deque(maxlen=infer.window_size if infer else 60)
    interval_sec = float(mon_cfg.get("interval_sec", 5))
    last_infer = 0.0
    last_alert_score = -1.0

    def on_sample(row: dict) -> None:
        nonlocal last_infer, last_alert_score
        if stop.is_set():
            raise KeyboardInterrupt
        cpu = float(row.get("cpu_percent") or 0.0)
        mem = float(row.get("mem_percent") or 0.0)
        net = float(
            row.get("net_packets_sent_per_s")
            or row.get("net_packets_recv_per_s")
            or 0.0
        )
        slim = {c: float(row.get(c, 0.0)) for c in columns}
        buf.append(slim)
        score = bus.score
        cnn = bus.cnn
        iforest = bus.iforest
        is_anom = False
        pattern = bus.pattern
        now = time.monotonic()
        if infer is not None and len(buf) >= infer.window_size and now - last_infer >= interval_sec:
            last_infer = now
            matrix = rows_to_matrix(list(buf), columns)
            pred = infer.predict_window(matrix)
            score, cnn, iforest = pred.score, pred.cnn_prob, pred.iforest_score
            is_anom = pred.is_anomaly
            means = matrix.mean(axis=0)
            col_map = {c: float(means[i]) for i, c in enumerate(columns)}
            pattern = detect_host_pattern(
                cpu=col_map.get("cpu_percent"),
                mem=col_map.get("mem_percent"),
                swap=col_map.get("swap_percent"),
                gpu=col_map.get("gpu_util_percent"),
                disk_write=col_map.get("disk_write_bytes_per_s"),
            )
            if is_anom and abs(score - last_alert_score) > 1e-6:
                last_alert_score = score
                bus.push_alert(
                    LiveAlert(
                        ts=time.time(),
                        severity="high",
                        title=f"HOST ANOMALY · {pattern}",
                        body=f"score={score:.3f} thr={pred.threshold:.3f} cnn={cnn:.3f} iforest={iforest:.3f}",
                        kind="host",
                        score=score,
                        rule_id="host_anomaly",
                    )
                )
        bus.push_sample(
            cpu=cpu,
            mem=mem,
            net=net,
            score=score,
            cnn=cnn,
            iforest=iforest,
            is_anomaly=is_anom,
            pattern=pattern if infer else "live metrics",
        )
        if int(time.time()) % 5 == 0:
            try:
                from sysspectogram.audit.processes import list_top_processes

                bus.set_processes(list_top_processes(limit=10))
            except Exception:
                pass

    daemon = CollectDaemon(collector, interval_sec=1.0, buffer_size=None)
    try:
        daemon.run(duration_sec=duration_sec, on_sample=on_sample)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        httpd.shutdown()
