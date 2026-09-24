from __future__ import annotations

import socket
import threading
import time
from collections import deque
from pathlib import Path

import numpy as np
from rich.console import Console

from sysspectogram.audit.processes import list_top_processes
from sysspectogram.audit.report import append_jsonl
from sysspectogram.collect.daemon import CollectDaemon
from sysspectogram.collect.metrics import MetricsCollector
from sysspectogram.config import ROOT
from sysspectogram.explain.templates import explain_host_anomaly
from sysspectogram.ml.calibration import CalibrationState, detect_drift, feature_attribution
from sysspectogram.ml.infer import EnsembleInferencer
from sysspectogram.notify import notify
from sysspectogram.notify_telegram import TelegramClient
from sysspectogram.perimeter.watcher import PerimeterWatcher
from sysspectogram.preprocess.window import rows_to_matrix
from sysspectogram.response.actions import NftBackend
from sysspectogram.response.tokens import TokenStore
from sysspectogram.telegram_bot import TelegramBot
from sysspectogram.integrations.webhook import post_webhook
from sysspectogram.web.actions import WebControllers
from sysspectogram.web.bus import GLOBAL_BUS, LiveAlert
from sysspectogram.web.server import start_web_server
from sysspectogram.viz.panels import (
    ProcessCpuTracker,
    detect_host_pattern,
    format_host_alert_caption,
    render_alert_panel,
)

console = Console()


def _resolve(path: str | Path) -> Path:
    p = Path(path)
    return p if p.is_absolute() else (ROOT / p).resolve()


def _heatmap_png_bytes(window: np.ndarray) -> bytes | None:
    """Legacy single-panel fallback (prefer render_alert_panel)."""
    try:
        import cv2

        img = np.clip(window, 0.0, 1.0)
        img_u8 = (img * 255.0).astype(np.uint8)
        h, w = img_u8.shape
        vis = cv2.resize(img_u8, (w * 8, h * 4), interpolation=cv2.INTER_NEAREST)
        ok, buf = cv2.imencode(".png", vis)
        if not ok:
            return None
        return bytes(buf)
    except Exception:
        return None


def run_guard(
    *,
    artifacts_dir: Path | None,
    config: dict,
    telegram: bool = False,
    dry_run_actions: bool = False,
    duration_sec: float | None = None,
    jsonl_out: Path | None = None,
    enable_web: bool = False,
) -> None:
    # Container metrics are cgroup-scoped — warn early.
    if Path("/.dockerenv").exists():
        console.print(
            "[yellow]WARNING[/] running inside Docker: host CPU/mem/net may not match bare metal. "
            "Prefer native install for monitor/guard."
        )

    host_cfg = config.get("host", {})
    per_cfg = config.get("perimeter", {})
    mon_cfg = config.get("monitor", {})
    col_cfg = config.get("collector", {})
    tg_cfg = config.get("telegram", {})
    recon_cfg = config.get("recon", {})
    web_cfg = config.get("web") or {}
    import os
    webapp_url = (
        os.environ.get("WEBAPP_URL")
        or os.environ.get("SYSPECTOGRAM_WEB_URL")
        or web_cfg.get("public_url")
    )

    host_id = host_cfg.get("id") or socket.gethostname()
    state_path = _resolve(per_cfg.get("state_path", "state/perimeter.json"))
    denylist_paths = [_resolve(p) for p in per_cfg.get("denylist_paths", [])]
    suspicious_domains = set(per_cfg.get("suspicious_domains") or [])

    client = TelegramClient(
        token=tg_cfg.get("bot_token") or None,
        chat_id=tg_cfg.get("chat_id") or None,
    )
    if not tg_cfg.get("token_secret"):
        console.print(
            "[yellow]WARNING[/] telegram.token_secret / TELEGRAM_TOKEN_SECRET unset — "
            "ephemeral HMAC secret for this process only"
        )
    tokens = TokenStore(secret=tg_cfg.get("token_secret"))
    nft = NftBackend()

    bot_holder: dict[str, TelegramBot | None] = {"bot": None}

    siem_cfg = config.get("siem") or {}
    lab_cfg = config.get("lab") or {}
    auto_ban_cfg = per_cfg.get("auto_ban") or {}
    auto_ban_rules = set(auto_ban_cfg.get("rules") or []) if auto_ban_cfg.get("enabled") else set()
    auto_ban_ttl = float(auto_ban_cfg.get("ttl_sec", 3600))

    def on_alert(alert, recon):
        GLOBAL_BUS.push_alert(
            LiveAlert(
                ts=getattr(alert, "ts", None) or __import__("time").time(),
                severity=str(getattr(alert, "severity", "medium")),
                title=f"PERIMETER · {getattr(alert, 'rule_id', 'alert')}",
                body=str(getattr(alert, "message", "")),
                kind="perimeter",
                rule_id=getattr(alert, "rule_id", None),
                extras={"ip": getattr(alert, "ip", None), "port": getattr(alert, "port", None)},
            )
        )
        bot = bot_holder["bot"]
        if bot is not None:
            bot.send_perimeter_alert(alert, recon)
        webhook = siem_cfg.get("webhook_url")
        if webhook:
            post_webhook(
                webhook,
                {
                    "host_id": host_id,
                    "type": "perimeter",
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "message": alert.message,
                    "ip": alert.ip,
                    "port": alert.port,
                },
                secret=siem_cfg.get("webhook_secret"),
            )

    def on_auto_ban(alert):
        if not alert.ip:
            return
        msg = nft.ban_ip(alert.ip, ttl_sec=auto_ban_ttl, dry_run=dry_run_actions)
        console.print(f"[red]auto-ban[/] {msg}")
        if bot_holder["bot"] is not None:
            try:
                bot_holder["bot"].client.send_message(
                    bot_holder["bot"].prefix(f"AUTO-BAN {msg}")
                )
            except Exception:
                pass

    watcher = PerimeterWatcher(
        host_id=host_id,
        fail_threshold=int(per_cfg.get("fail_threshold", 8)),
        fail_window_sec=float(per_cfg.get("fail_window_sec", 60)),
        scan_unique_ips=int(per_cfg.get("scan_unique_ips", 8)),
        scan_window_sec=float(per_cfg.get("scan_window_sec", 60)),
        denylist_paths=denylist_paths,
        suspicious_domains=suspicious_domains,
        state_path=state_path,
        jsonl_out=_resolve(jsonl_out or per_cfg.get("jsonl_out", "reports/perimeter.jsonl")),
        recon_dir=_resolve(recon_cfg.get("dir", "reports/recon")),
        recon_cooldown_sec=float(recon_cfg.get("cooldown_sec", 900)),
        auto_recon=bool(recon_cfg.get("auto", False)),
        include_nmap=bool(recon_cfg.get("nmap", False)),
        lab_nmap_targets=list(lab_cfg.get("nmap_targets") or ["127.0.0.1", "::1"]),
        passive_dns_url=recon_cfg.get("passive_dns_url"),
        poll_sec=float(per_cfg.get("poll_sec", 2.0)),
        alert_new_egress=bool(per_cfg.get("alert_new_egress", False)),
        on_alert=on_alert if (telegram or enable_web) else None,
        on_auto_ban=on_auto_ban if auto_ban_rules else None,
        nft=nft,
        auto_ban_rules=auto_ban_rules,
        auto_ban_ttl_sec=auto_ban_ttl,
    )

    bot = None
    if telegram and client.configured:
        bot = TelegramBot(
            client,
            watcher=watcher,
            nft=nft,
            tokens=tokens,
            host_id=host_id,
            dry_run=dry_run_actions,
            recon_dir=_resolve(recon_cfg.get("dir", "reports/recon")),
            report_path=_resolve(per_cfg.get("jsonl_out", "reports/perimeter.jsonl")),
            model_dir=artifacts_dir,
            project_root=ROOT,
            allow_destructive_sims=bool(tg_cfg.get("allow_destructive_sims", False)),
            lab_nmap_targets=list(lab_cfg.get("nmap_targets") or ["127.0.0.1", "::1"]),
            include_nmap=bool(recon_cfg.get("nmap", False)),
            webapp_url=webapp_url,
        )
        bot_holder["bot"] = bot
        console.print("[green]telegram enabled[/]")
    elif telegram:
        console.print("[yellow]telegram requested but TELEGRAM_BOT_TOKEN/CHAT_ID missing[/]")

    stop = threading.Event()

    httpd = None
    if enable_web or bool(web_cfg.get("enabled")):
        bind = str(web_cfg.get("host") or "127.0.0.1")
        port = int(web_cfg.get("port") or 8765)
        GLOBAL_BUS.set_host(host_id, 0.5, model_loaded=bool(artifacts_dir))
        controllers = WebControllers(
            bus=GLOBAL_BUS,
            nft=nft,
            watcher=watcher,
            dry_run=dry_run_actions,
            lab_nmap_targets=list(lab_cfg.get("nmap_targets") or ["127.0.0.1", "::1"]),
            include_nmap=bool(recon_cfg.get("nmap", False)),
            recon_dir=_resolve(recon_cfg.get("dir", "reports/recon")),
        )
        httpd = start_web_server(
            GLOBAL_BUS,
            host=bind,
            port=port,
            bot_token=tg_cfg.get("bot_token"),
            allowed_chat_id=tg_cfg.get("chat_id"),
            public_url=webapp_url,
            controllers=controllers,
        )
        console.print(f"[bold]web dashboard[/] http://{bind}:{port}/")
        if webapp_url:
            console.print(f"[cyan]Mini App URL[/] {webapp_url}")
            try:
                res = client.set_chat_menu_button_webapp("Dashboard", webapp_url)
                if res.get("ok"):
                    console.print("[green]Telegram menu button → Dashboard[/]")
            except Exception as exc:
                console.print(f"[yellow]menu button[/] {exc}")

    def perimeter_loop():
        t0 = time.monotonic()
        while not stop.is_set():
            try:
                watcher.tick()
            except Exception as exc:
                console.print(f"[yellow]perimeter tick[/] {exc}")
            if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                break
            stop.wait(watcher.poll_sec)
        watcher.persist()

    def telegram_loop():
        if bot is None:
            return
        t0 = time.monotonic()
        while not stop.is_set():
            try:
                bot.poll_once(timeout=2)
            except Exception as exc:
                console.print(f"[yellow]tg poll[/] {exc}")
            if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                break
            # ban TTL cleanup
            try:
                nft.list_bans()
            except Exception:
                pass

    def host_loop():
        web_on = enable_web or bool(web_cfg.get("enabled"))
        if artifacts_dir is None or not artifacts_dir.exists():
            console.print("[yellow]no model artifacts; host ML monitor disabled[/]")
            if not web_on:
                return
            # metrics-only feed for the live web UI
            collector = MetricsCollector(
                max_cores=int(col_cfg.get("max_cores", 16)),
                socket_sample_every=int(col_cfg.get("socket_sample_every", 5)),
            )
            daemon = CollectDaemon(collector, interval_sec=1.0, buffer_size=None)

            def on_metrics(row: dict) -> None:
                if stop.is_set():
                    raise KeyboardInterrupt
                GLOBAL_BUS.push_sample(
                    cpu=float(row.get("cpu_percent") or 0.0),
                    mem=float(row.get("mem_percent") or 0.0),
                    net=float(
                        row.get("net_packets_sent_per_s")
                        or row.get("net_packets_recv_per_s")
                        or 0.0
                    ),
                    pattern="live metrics",
                )

            try:
                daemon.run(duration_sec=duration_sec, on_sample=on_metrics)
            except KeyboardInterrupt:
                return
            return
        try:
            infer = EnsembleInferencer(artifacts_dir)
        except Exception as exc:
            console.print(f"[yellow]host ML unavailable[/] {exc}")
            return
        columns = infer.columns
        collector = MetricsCollector(
            max_cores=int(col_cfg.get("max_cores", 16)),
            socket_sample_every=int(col_cfg.get("socket_sample_every", 5)),
        )
        buf: deque = deque(maxlen=infer.window_size)
        daemon = CollectDaemon(collector, interval_sec=1.0, buffer_size=None)
        interval_sec = float(mon_cfg.get("interval_sec", 5))
        cooldown_sec = float(mon_cfg.get("cooldown_sec", 60))
        top_n = int(mon_cfg.get("top_processes", 3))
        last_alert = 0.0
        last_infer = 0.0
        last_drift_notify = 0.0
        cal_path = _resolve("state/calibration.json")
        calib = CalibrationState.load(cal_path)
        recent_scores: list[float] = []
        proc_track = ProcessCpuTracker(maxlen=infer.window_size, top_k=8)
        proc_track.warm()
        console.print(
            f"[bold]guard host-ml[/] window={infer.window_size} thr={infer.threshold:.3f}"
        )

        def on_sample(row: dict) -> None:
            nonlocal last_alert, last_infer, last_drift_notify
            if stop.is_set():
                raise KeyboardInterrupt
            try:
                proc_track.sample()
            except Exception:
                pass
            slim = {c: float(row.get(c, 0.0)) for c in columns}
            buf.append(slim)
            GLOBAL_BUS.push_sample(
                cpu=float(row.get("cpu_percent") or 0.0),
                mem=float(row.get("mem_percent") or 0.0),
                net=float(
                    row.get("net_packets_sent_per_s")
                    or row.get("net_packets_recv_per_s")
                    or 0.0
                ),
            )
            now = time.monotonic()
            if len(buf) < infer.window_size:
                return
            if now - last_infer < interval_sec:
                return
            last_infer = now
            # refresh process table each infer tick
            try:
                GLOBAL_BUS.set_processes(list_top_processes(limit=max(top_n, 8)))
            except Exception:
                pass
            matrix = rows_to_matrix(list(buf), columns)
            pred = infer.predict_window(matrix)
            recent_scores.append(pred.score)
            if len(recent_scores) > 60:
                del recent_scores[:30]
            if not pred.is_anomaly and len(recent_scores) >= 10:
                calib.update(recent_scores[-10:])
                calib.save(cal_path)
            status = "ANOMALY" if pred.is_anomaly else "ok"
            console.print(
                f"host {status} score={pred.score:.3f} cnn={pred.cnn_prob:.3f} "
                f"iforest={pred.iforest_score:.3f}"
            )
            GLOBAL_BUS.set_host(host_id, pred.threshold, model_loaded=True)
            GLOBAL_BUS.push_sample(
                cpu=float(row.get("cpu_percent") or 0.0),
                mem=float(row.get("mem_percent") or 0.0),
                net=float(
                    row.get("net_packets_sent_per_s")
                    or row.get("net_packets_recv_per_s")
                    or 0.0
                ),
                score=pred.score,
                cnn=pred.cnn_prob,
                iforest=pred.iforest_score,
                is_anomaly=pred.is_anomaly,
            )
            from sysspectogram.ml.calibration import suggested_threshold_hint

            if detect_drift(calib, recent_scores[-20:]):
                hint = suggested_threshold_hint(calib, recent_scores[-20:], infer.threshold)
                if now - last_drift_notify >= max(cooldown_sec * 5, 300.0):
                    last_drift_notify = now
                    msg = "[yellow]drift suspected vs host calibration baseline[/]"
                    if hint is not None:
                        msg += f" — consider threshold≈{hint} (current={infer.threshold:.3f})"
                    console.print(msg)
                    if bot is not None and hint is not None:
                        try:
                            bot.client.send_message(
                                bot.prefix(
                                    f"DRIFT: scores shifted; suggested threshold≈{hint} "
                                    f"(current={infer.threshold:.3f})"
                                )
                            )
                        except Exception:
                            pass
            if not pred.is_anomaly:
                return
            if now - last_alert < cooldown_sec:
                return
            last_alert = now
            tops = list_top_processes(limit=max(top_n, 5))
            means = matrix.mean(axis=0)
            col_map = {c: float(means[i]) for i, c in enumerate(columns)}
            feats = feature_attribution(matrix, columns, top_k=5)
            expl_kw = {
                "cpu": col_map.get("cpu_percent"),
                "mem": col_map.get("mem_percent"),
                "swap": col_map.get("swap_percent"),
                "gpu": col_map.get("gpu_util_percent"),
                "disk_write": col_map.get("disk_write_bytes_per_s") or col_map.get("disk_write_bytes"),
                "top_features": feats,
            }
            pattern = detect_host_pattern(top_procs=tops, **{k: v for k, v in expl_kw.items() if k != "top_features"})
            body = explain_host_anomaly(top_procs=tops, **expl_kw)
            console.print(f"[red bold]HOST ALERT[/] pattern={pattern}\n{body}")
            GLOBAL_BUS.push_alert(
                LiveAlert(
                    ts=__import__("time").time(),
                    severity="high",
                    title=f"HOST ANOMALY · {pattern}",
                    body=body,
                    kind="host",
                    score=pred.score,
                    rule_id="host_anomaly",
                )
            )
            notify("SysSpectogram host anomaly", body)
            webhook = (config.get("siem") or {}).get("webhook_url")
            if webhook:
                post_webhook(
                    webhook,
                    {
                        "host_id": host_id,
                        "type": "host_anomaly",
                        "score": pred.score,
                        "pattern": pattern,
                        "body": body,
                    },
                    secret=siem_cfg.get("webhook_secret"),
                )
            if jsonl_out is not None:
                append_jsonl(
                    jsonl_out,
                    {
                        "type": "host_anomaly",
                        "host_id": host_id,
                        "score": pred.score,
                        "threshold": pred.threshold,
                        "pattern": pattern,
                        "top_processes": tops,
                        "top_features": feats,
                    },
                )
            if bot is not None:
                proc_mat, proc_labels = proc_track.matrix(top_k=8)
                png = render_alert_panel(
                    metric_window=matrix,
                    metric_columns=columns,
                    proc_matrix=proc_mat,
                    proc_labels=proc_labels,
                    title=f"[{host_id}] metrics",
                    score=pred.score,
                )
                if png is None:
                    try:
                        vis = np.clip(matrix / (matrix.max() + 1e-6), 0, 1).astype(np.float32)
                        png = _heatmap_png_bytes(vis)
                    except Exception:
                        png = None
                caption = format_host_alert_caption(
                    host_id=host_id,
                    score=pred.score,
                    threshold=pred.threshold,
                    pattern=pattern,
                    explain=body,
                    top_procs=tops,
                    top_features=feats,
                )
                bot.send_host_alert(
                    score=pred.score,
                    threshold=pred.threshold,
                    top_procs=tops,
                    explain_kwargs=expl_kw,
                    png_bytes=png,
                    caption_override=caption,
                    pattern=pattern,
                )

        try:
            if duration_sec is not None:
                daemon.run(duration_sec=duration_sec, on_sample=on_sample)
            else:
                daemon.run(duration_sec=None, on_sample=on_sample)
        except KeyboardInterrupt:
            return

    console.print(f"[bold]guard[/] host={host_id} telegram={bot is not None}")

    threads = [
        threading.Thread(target=perimeter_loop, name="perimeter", daemon=True),
        threading.Thread(target=telegram_loop, name="telegram", daemon=True),
        threading.Thread(target=host_loop, name="host-ml", daemon=True),
    ]

    honeypot = None
    hp_cfg = config.get("honeypot") or {}
    if hp_cfg.get("enabled"):
        from sysspectogram.perimeter.honeypot import HoneypotListener
        from sysspectogram.perimeter.rules import Alert as PAlert

        honeypot = HoneypotListener(port=int(hp_cfg.get("port", 2222)))
        honeypot.start()
        console.print(f"[cyan]honeypot[/] :{honeypot.port}")

        def honeypot_loop():
            seen = 0
            t0 = time.monotonic()
            while not stop.is_set():
                if len(honeypot.hits) > seen:
                    for hit in honeypot.hits[seen:]:
                        a = PAlert(
                            rule_id="honeypot_hit",
                            severity="high",
                            message=f"Honeypot connect from {hit.remote} to :{hit.port}",
                            ip=hit.remote,
                            port=hit.port,
                        )
                        watcher.emit(a)
                    seen = len(honeypot.hits)
                if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                    break
                stop.wait(1.0)

        threads.append(threading.Thread(target=honeypot_loop, name="honeypot", daemon=True))

    for t in threads:
        t.start()
    try:
        t0 = time.monotonic()
        while True:
            if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                break
            if all(not t.is_alive() for t in threads):
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("stopping guard…")
    finally:
        stop.set()
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
        if honeypot is not None:
            honeypot.stop()
        for t in threads:
            t.join(timeout=3)
        watcher.persist()
