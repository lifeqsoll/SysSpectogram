from __future__ import annotations

import atexit
import fcntl
import os
import signal
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
from sysspectogram.config import ROOT, state_root
from sysspectogram.explain.templates import explain_host_anomaly
from sysspectogram.ml.calibration import CalibrationState, detect_drift, feature_attribution
from sysspectogram.ml.infer import load_inferencer
from sysspectogram.notify import notify
from sysspectogram.notify_telegram import TelegramClient
from sysspectogram.perimeter.watcher import PerimeterWatcher
from sysspectogram.preprocess.window import rows_to_matrix
from sysspectogram.response.actions import NftBackend
from sysspectogram.response.tokens import TokenStore
from sysspectogram.telegram_bot import TelegramBot
from sysspectogram.alert_text import describe, is_unattributed
from sysspectogram.console_unlock import ConsoleUnlock
from sysspectogram.control_socket import ControlSocketServer, make_handler
from sysspectogram.integrations.webhook import post_webhook
from sysspectogram.agent_bridge import AgentSocketListener
from sysspectogram.kirk_trust import ima_watch_new_lines, probe_kirk_trust
from sysspectogram.risk import apply_kirk_override
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


def _ebpf_path_benign(path: str) -> bool:
    """Desktop / toolchain noise that must not spam Telegram."""
    if not path:
        return True
    if path.startswith(("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")):
        return True
    markers = (
        "/.venv/",
        "/venv/",
        "/go/bin/",
        "/.local/bin/",
        "/.cargo/bin/",
        "/.mount_",
        "/tmp/.mount_",
    )
    return any(m in path for m in markers)


def _benign_sudo_sudoers(comm: str | None, path: str | None) -> bool:
    c = (comm or "").rsplit("/", 1)[-1].lower()
    p = path or ""
    if c not in ("sudo", "sudoedit", "su"):
        return False
    return p == "/etc/sudoers" or p.startswith("/etc/sudoers.d/") or "/etc/sudoers" in p


def _resolve(path: str | Path) -> Path:
    p = Path(path)
    return p if p.is_absolute() else (ROOT / p).resolve()


def _write_private(path: Path, text: str) -> None:
    """Write a secret readable by the owner only (0600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")


def _drop_file(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _event_snapshot(ts: float | None, title: str, score: float | None = None) -> bytes | None:
    """Metrics spectrogram for the 2 minutes before an event (None if no data)."""
    if not ts:
        return None
    try:
        from sysspectogram.config import state_root
        from sysspectogram.timeseries.store import TimeseriesStore
        from sysspectogram.viz.snapshot import render_window

        store = TimeseriesStore(state_root() / "state" / "timeseries.sqlite")
        try:
            return render_window(store, float(ts) - 120.0, float(ts) + 60.0, title=title, score=score)
        finally:
            store.close()
    except Exception:
        return None


def _clear_guard_pidfile(pid: int) -> None:
    """Drop state/guard.pid on a clean stop, so the agent does not raise guard_down.

    A crash leaves the pidfile behind on purpose: that is the case the agent must report.
    """
    gp = _resolve("state/guard.pid")
    try:
        if gp.read_text(encoding="utf-8").strip() == str(pid):
            gp.unlink()
    except OSError:
        pass


def _running_agent_pid(pidfile: Path) -> int | None:
    """PID from the agent pidfile if that process is alive and really is the agent."""
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    return pid if "sysspectogram-agent" in cmdline else None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _running_guard_pid(pidfile: Path) -> int | None:
    """PID from state/guard.pid if that process is still a live guard."""
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if pid <= 0 or pid == os.getpid() or not _pid_alive(pid):
        return None
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return None
    if "sysspectogram" in cmdline and "guard" in cmdline:
        return pid
    return None


def _acquire_guard_lock() -> object | None:
    """Exclusive flock so only one guard owns the agent socket / Telegram.

    Returns an open file object that must stay alive for the process lifetime,
    or None if another guard already holds the lock.
    """
    lock_path = _resolve("state/guard.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        other = _running_guard_pid(_resolve("state/guard.pid"))
        fh.close()
        console.print(
            f"[red]guard[/] another instance is already running"
            + (f" (pid {other})" if other else "")
            + " — refuse to start a second one (would steal the agent socket and spam Telegram)"
        )
        return None
    fh.seek(0)
    fh.truncate()
    fh.write(f"{os.getpid()}\n")
    fh.flush()

    def _release() -> None:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            fh.close()
        except OSError:
            pass

    atexit.register(_release)
    return fh


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
    # Container metrics are cgroup-scoped - warn early.
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
    ui_lang = str((config.get("ui") or {}).get("lang") or "en").strip().lower()
    if ui_lang not in ("en", "ru"):
        ui_lang = "en"
    notify_lang = ui_lang  # type: ignore[assignment]
    recon_cfg = config.get("recon", {})
    web_cfg = config.get("web") or {}
    ens_cfg = config.get("ensemble") or {}
    host_weight = float(ens_cfg.get("host_weight", 0.6))
    agent_weight = float(ens_cfg.get("agent_weight", 0.4))
    load_name = str(config.get("load_profile") or "lite")
    risk_state: dict[str, float] = {"agent": 0.0}
    agent_half_life_sec = float(
        (config.get("agent") or {}).get("score_half_life_sec", 60.0)
    )
    console.print(f"[cyan]load_profile[/] {load_name} (lite=small VPS, full=large VDS)")
    import os
    webapp_url = (
        os.environ.get("WEBAPP_URL")
        or os.environ.get("SYSPECTOGRAM_WEB_URL")
        or web_cfg.get("public_url")
    )

    host_id = host_cfg.get("id") or socket.gethostname()
    state_path = _resolve(per_cfg.get("state_path", "state/perimeter.json"))
    # One guard only: multiple instances steal the AF_UNIX agent socket and flood agent_down.
    _guard_lock = _acquire_guard_lock()
    if _guard_lock is None:
        raise SystemExit(2)
    # Agent self-protect: publish guard pid for Rust twin watch
    try:
        gp = _resolve("state/guard.pid")
        gp.parent.mkdir(parents=True, exist_ok=True)
        gp.write_text(f"{os.getpid()}\n", encoding="utf-8")
    except OSError:
        pass
    denylist_paths = [_resolve(p) for p in per_cfg.get("denylist_paths", [])]
    suspicious_domains = set(per_cfg.get("suspicious_domains") or [])

    client = TelegramClient(
        token=tg_cfg.get("bot_token") or None,
        chat_id=tg_cfg.get("chat_id") or None,
    )
    if not tg_cfg.get("token_secret"):
        console.print(
            "[yellow]WARNING[/] telegram.token_secret / TELEGRAM_TOKEN_SECRET unset - "
            "ephemeral HMAC secret for this process only"
        )
    tokens = TokenStore(secret=tg_cfg.get("token_secret"))
    resp_cfg_early = dict(config.get("response") or {})
    nft = NftBackend(
        never_ban_cidrs=[str(x) for x in (resp_cfg_early.get("never_ban_cidrs") or [])]
    )

    kirk_cfg = dict(config.get("kirk") or {})
    kirk_enabled = bool(kirk_cfg.get("enabled", False))
    kirk_auto_isolate = bool(kirk_cfg.get("auto_isolate", False))
    kirk_auto_isolate_host_risk = bool(kirk_cfg.get("auto_isolate_host_risk", False))
    from sysspectogram.confirm_streak import ConfirmStreak

    kirk_confirm = ConfirmStreak(
        need=int(kirk_cfg.get("confirm_streak", 2)),
        ttl_sec=float(kirk_cfg.get("confirm_ttl_sec", 180)),
    )
    kirk_host_risk_threshold = float(kirk_cfg.get("host_risk_threshold", 0.99))
    kirk_allow_cidrs = list(kirk_cfg.get("allow_ssh_cidrs") or [])
    kirk_isolate_ttl = float(kirk_cfg.get("isolate_ttl_sec", 3600))
    kirk_status: dict = {"trust": "best-effort", "report": None, "isolated": False}
    from sysspectogram.alerts import AlertFanout

    alert_fanout = AlertFanout.from_config(config)
    if kirk_enabled:
        trust_mode = str(kirk_cfg.get("trust") or "auto").strip().lower()
        allowed_labels = {"best-effort", "measured", "auto"}
        if trust_mode in ("auto", "measured"):
            report = probe_kirk_trust(require_tpm=bool(kirk_cfg.get("require_tpm", False)))
            kirk_status["report"] = report.to_dict()
            if trust_mode == "auto":
                kirk_status["trust"] = report.trust
            else:
                kirk_status["trust"] = report.trust  # measured only if probe agrees
                if report.trust != "measured":
                    console.print(
                        "[yellow]kirk[/] trust requested measured but probe says best-effort "
                        f"({'; '.join(report.details[:3])})"
                    )
            console.print(
                f"[cyan]kirk trust[/] {kirk_status['trust']} "
                f"ima={report.ima_present} meas={report.ima_measurements} "
                f"sb={report.secure_boot} tpm={report.tpm_present}"
            )
            try:
                GLOBAL_BUS.set_kirk(
                    trust=str(kirk_status["trust"]),
                    isolated=False,
                    details=list(report.details or [])[:6],
                )
            except Exception:
                pass
        elif trust_mode in allowed_labels:
            kirk_status["trust"] = trust_mode
            console.print(f"[cyan]kirk trust[/] {kirk_status['trust']} (forced)")
        else:
            # reject out-of-band / trash labels until VMI ships
            kirk_status["trust"] = "best-effort"
            console.print(
                f"[yellow]kirk[/] unknown trust={trust_mode!r} -> best-effort "
                "(out-of-band needs a separate trust domain; see docs/VMI.md)"
            )
        if kirk_cfg.get("vmi"):
            console.print(
                f"[cyan]kirk.vmi[/] on backend={kirk_cfg.get('vmi_backend', 'mock')} "
                "read-only cross-check (docs/VMI.md)"
            )

    from sysspectogram.process_labels import ProcessLabelStore
    from sysspectogram.feedback_learn import FeedbackLearner
    from sysspectogram.agent_auth import ensure_secret
    from sysspectogram.response_audit import ResponseAudit
    from sysspectogram.host_probe import recommend, save_probe

    feedback = ProcessLabelStore(_resolve("state/process_labels.json"))
    # also migrate legacy path if present
    legacy_fb = _resolve("state/operator_feedback.json")
    if legacy_fb.exists() and not feedback.list_rules():
        from sysspectogram.process_labels import ProcessLabelStore as _PLS

        tmp = _PLS(legacy_fb)
        for r in tmp.list_rules():
            feedback.add_rule(r)
    learner = FeedbackLearner(_resolve("artifacts/feedback"))
    audit = ResponseAudit(_resolve("reports/response_audit.jsonl"))
    hmac_secret = ensure_secret(_resolve("state/agent_hmac.secret"))
    bot_holder: dict[str, TelegramBot | None] = {"bot": None}
    fb_cfg = config.get("feedback") or {}
    widen_rules = fb_cfg.get("widen_rules", "comm_prefix")
    if_refit_enabled = bool(fb_cfg.get("if_refit", False))
    try:
        save_probe(_resolve("state/host_probe.json"), recommend())
    except Exception:
        pass


    siem_cfg = config.get("siem") or {}
    lab_cfg = config.get("lab") or {}
    resp_cfg = config.get("response") or {}
    resp_mode = str(resp_cfg.get("mode") or "observe").strip().lower()
    never_ban = set(str(x) for x in (resp_cfg.get("never_ban_cidrs") or []))
    auto_ban_cfg = dict(per_cfg.get("auto_ban") or {})
    _host_flood_rules = {
        "flow_syn_burst",
        "flow_port_scan",
    }
    _aggressive_rules = {
        "bruteforce_ssh",
        "honeypot_hit",
        "canary_hit",
        "egress_denylist_hit",
        "port_scan_suspected",
        *_host_flood_rules,
    }
    # Derive auto_ban (+ kirk isolate) from response.mode
    if resp_mode == "observe":
        auto_ban_cfg["enabled"] = False
        auto_ban_rules: set[str] = set()
    elif resp_mode in ("shield", "enforce", "soft"):
        # soft/shield: SSH abuse + host flood soft-mitigation (needs never_ban)
        auto_ban_cfg["enabled"] = True
        auto_ban_rules = {
            "bruteforce_ssh",
            "honeypot_hit",
            "canary_hit",
            *_host_flood_rules,
        }
    elif resp_mode == "aggressive":
        auto_ban_cfg["enabled"] = True
        auto_ban_rules = set(auto_ban_cfg.get("rules") or []) or set(_aggressive_rules)
    elif resp_mode == "isolate":
        # Full auto-ban + enable kirk network isolation on critical signals
        auto_ban_cfg["enabled"] = True
        auto_ban_rules = set(auto_ban_cfg.get("rules") or []) or set(_aggressive_rules)
        kirk_auto_isolate = True
        if not kirk_enabled:
            kirk_enabled = True
            console.print("[cyan]response.mode=isolate[/] enabling kirk for auto-isolate")
    else:
        auto_ban_rules = set(auto_ban_cfg.get("rules") or []) if auto_ban_cfg.get("enabled") else set()
    auto_ban_ttl = float(auto_ban_cfg.get("ttl_sec", 3600))
    console.print(
        f"[cyan]response.mode[/] {resp_mode} auto_ban_rules={sorted(auto_ban_rules) or '-'} "
        f"kirk_auto_isolate={kirk_auto_isolate}"
    )

    def on_alert(alert, recon):
        rid = str(getattr(alert, "rule_id", "") or "alert")
        plain = describe(rid, str(getattr(alert, "message", "") or ""), lang=notify_lang)  # type: ignore[arg-type]
        GLOBAL_BUS.push_alert(
            LiveAlert(
                ts=getattr(alert, "ts", None) or __import__("time").time(),
                severity=str(getattr(alert, "severity", "medium")),
                title=plain.title,
                body=f"{plain.what}\n{plain.action}",
                kind="perimeter",
                rule_id=rid,
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
        from ipaddress import ip_network, ip_address

        try:
            addr = ip_address(alert.ip)
            for cidr in never_ban:
                try:
                    if addr in ip_network(cidr, strict=False):
                        console.print(f"[yellow]never_ban[/] skip {alert.ip} ({cidr})")
                        return
                except ValueError:
                    continue
        except ValueError:
            pass
        ttl = auto_ban_ttl
        # OSINT 2.0: scale ban TTL by recon_score when present on extras / recent dossier
        score = None
        try:
            score = float((alert.extras or {}).get("recon_score"))
        except (TypeError, ValueError):
            score = None
        if score is None:
            try:
                from sysspectogram.osint.score import load_recent_hits

                for row in load_recent_hits(_resolve("reports/recon/recon_dossier.jsonl"), window_sec=900):
                    if row.get("ip") == alert.ip:
                        score = float(row.get("recon_score") or 0)
                        break
            except Exception:
                pass
        if score is not None:
            # 0.0 -> 0.5x ttl, 1.0 -> 3x ttl
            ttl = max(300.0, auto_ban_ttl * (0.5 + 2.5 * min(1.0, max(0.0, score))))
        msg = nft.ban_ip(alert.ip, ttl_sec=ttl, dry_run=dry_run_actions)
        console.print(f"[red]auto-ban[/] {msg} (ttl={ttl:.0f}s score={score})")
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
        on_alert=on_alert,
        on_auto_ban=on_auto_ban if auto_ban_rules else None,
        nft=nft,
        auto_ban_rules=auto_ban_rules,
        auto_ban_ttl_sec=auto_ban_ttl,
        dry_run=bool(dry_run_actions),
    )

    bot = None

    unlock_file = _resolve("state/unlock.code")

    def _print_unlock(code: str | None) -> None:
        # The code never goes to the log or to Telegram: it is written 0600 to state/unlock.code,
        # shown in the Control Center on request, and removed once the pairing succeeds.
        if code is None:
            _drop_file(unlock_file)
            console.print("[green]telegram unlocked[/] - pairing code used and removed")
            return
        _write_private(unlock_file, code)
        console.print("")
        console.print(
            "[bold red]TELEGRAM UNLOCK CODE[/] saved to state/unlock.code "
            "(Control Center: Overview -> Show code)"
        )
        console.print("[dim]Stolen bot token alone cannot control the host without this code.[/]")
        console.print("")

    # Shared unlock for Telegram + Mini App + control socket (CC)
    want_unlock = bool(tg_cfg.get("require_console_unlock", True))
    web_on = bool(enable_web or web_cfg.get("enabled"))
    want_telegram = bool(telegram or tg_cfg.get("enabled"))
    tg_on = bool(want_telegram and client.configured)
    has_bot_creds = bool(tg_cfg.get("bot_token") and tg_cfg.get("chat_id"))
    unlock_enabled = want_unlock and (
        tg_on or web_on or bool(webapp_url) or has_bot_creds
    )
    unlock_gate = ConsoleUnlock(
        enabled=unlock_enabled,
        ttl_sec=float(tg_cfg.get("unlock_ttl_sec", 7200)),
        on_code=_print_unlock,
    )
    if unlock_gate.enabled and unlock_gate.pending_code:
        _print_unlock(unlock_gate.pending_code)

    if want_telegram and client.configured:
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
            unlock=unlock_gate,
            kirk_status=kirk_status,
            response_mode=resp_mode,
            feedback=feedback,
            learner=learner,
            audit=audit,
            widen_rules=widen_rules,
            if_refit=if_refit_enabled,
            supply_chain=config.get("supply_chain") or {},
            lang=notify_lang,
        )
        if unlock_gate.enabled:
            try:
                # One language only; skip if we already announced this process start.
                announce = _resolve("state/unlock.tg_announced")
                already = False
                try:
                    if announce.is_file():
                        raw = announce.read_text(encoding="utf-8").strip()
                        # Same pending code → do not spam Telegram on restart loops.
                        already = raw == str(unlock_gate.pending_code or "")
                except OSError:
                    already = False
                if not already:
                    if notify_lang == "ru":
                        locked_msg = (
                            "Управление заблокировано после запуска.\n"
                            "Откройте Control Center → Показать код, затем отправьте боту:\n"
                            "/unlock КОД"
                        )
                    else:
                        locked_msg = (
                            "Control is locked after guard start.\n"
                            "Open Control Center → Show code, then send the bot:\n"
                            "/unlock CODE"
                        )
                    client.send_message(bot.prefix(locked_msg))
                    try:
                        _write_private(announce, str(unlock_gate.pending_code or ""))
                    except OSError:
                        pass
            except Exception:
                pass
        bot_holder["bot"] = bot
        console.print(f"[green]telegram enabled[/] lang={notify_lang}")
    elif want_telegram:
        console.print("[yellow]telegram requested but TELEGRAM_BOT_TOKEN/CHAT_ID missing[/]")

    stop = threading.Event()

    httpd = None
    control_srv = None
    GLOBAL_BUS.set_host(host_id, 0.5, model_loaded=bool(artifacts_dir))
    controllers = WebControllers(
        bus=GLOBAL_BUS,
        nft=nft,
        watcher=watcher,
        dry_run=dry_run_actions,
        lab_nmap_targets=list(lab_cfg.get("nmap_targets") or ["127.0.0.1", "::1"]),
        include_nmap=bool(recon_cfg.get("nmap", False)),
        recon_dir=_resolve(recon_cfg.get("dir", "reports/recon")),
        unlock_ok=unlock_gate.unlocked if unlock_gate.enabled else None,
        feedback=feedback,
    )
    control_path = _resolve("state/control.sock")
    try:
        control_srv = ControlSocketServer(control_path, handler=make_handler(controllers))
        control_srv.start()
        console.print(f"[bold]control socket[/] {control_path}")
    except Exception as exc:
        console.print(f"[yellow]control socket[/] {exc}")
        control_srv = None
    if enable_web or bool(web_cfg.get("enabled")):
        bind = str(web_cfg.get("host") or "127.0.0.1")
        port = int(web_cfg.get("port") or 8765)
        httpd = start_web_server(
            GLOBAL_BUS,
            host=bind,
            port=port,
            bot_token=tg_cfg.get("bot_token"),
            allowed_chat_id=tg_cfg.get("chat_id"),
            public_url=webapp_url,
            controllers=controllers,
            unlock=unlock_gate if unlock_gate.enabled else None,
        )
        console.print(f"[bold]web dashboard[/] http://{bind}:{port}/")
        if webapp_url:
            console.print(f"[cyan]Mini App URL[/] {webapp_url}")
            try:
                res = client.set_chat_menu_button_webapp("Dashboard", webapp_url)
                if res.get("ok"):
                    console.print("[green]Telegram menu button -> Dashboard[/]")
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
        health_h = float(tg_cfg.get("health_ping_hours") or 0)
        health_period = health_h * 3600.0 if health_h > 0 else 0.0
        last_health = time.monotonic()
        while not stop.is_set():
            try:
                bot.poll_once(timeout=2)
            except Exception as exc:
                console.print(f"[yellow]tg poll[/] {exc}")
            if health_period > 0 and (time.monotonic() - last_health) >= health_period:
                last_health = time.monotonic()
                try:
                    bot.client.send_message(bot.prefix(bot._status_text()))
                except Exception as exc:
                    console.print(f"[yellow]health ping[/] {exc}")
            if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                break
            try:
                nft.list_bans()
                if kirk_status.get("isolated") and getattr(nft, "_kirk_expires", None) is None:
                    kirk_status["isolated"] = False
                    try:
                        GLOBAL_BUS.set_kirk(isolated=False)
                    except Exception:
                        pass
            except Exception:
                pass

    def _open_timeseries():
        """Open the SQLite timeseries store (feeds the Control Center Live tab)."""
        ts_cfg = config.get("timeseries") or {}
        if not bool(ts_cfg.get("enabled", True)):
            return None
        from sysspectogram.timeseries.store import TimeseriesStore

        ts_rel = Path(str(ts_cfg.get("path") or "state/timeseries.sqlite"))
        ts_path = ts_rel if ts_rel.is_absolute() else state_root() / ts_rel
        console.print(f"timeseries -> {ts_path}")
        return TimeseriesStore(ts_path)

    def host_loop():
        web_on = enable_web or bool(web_cfg.get("enabled"))
        runtime = str(config.get("runtime") or "notorch").strip().lower()
        if runtime == "notorch" or artifacts_dir is None or not artifacts_dir.exists():
            if runtime == "notorch":
                console.print("[cyan]runtime=notorch[/] host CNN off - perimeter + agent risk only")
            elif artifacts_dir is None or not artifacts_dir.exists():
                console.print("[yellow]no model artifacts; host ML monitor disabled[/]")
            if not web_on and runtime == "notorch":
                # still feed light metrics so bus/risk from agent works
                pass
            if artifacts_dir is None or not artifacts_dir.exists() or runtime == "notorch":
                if not web_on and runtime != "notorch":
                    return
                # metrics-only feed for the live web UI + agent fuse
                collector = MetricsCollector(
                    max_cores=int(col_cfg.get("max_cores", 16)),
                    socket_sample_every=int(col_cfg.get("socket_sample_every", 5)),
                )
                daemon = CollectDaemon(collector, interval_sec=1.0, buffer_size=None)
                mon_cfg_local = config.get("monitor") or {}
                interval_sec = float(mon_cfg_local.get("interval_sec", 5))
                last_print = 0.0
                # notorch: no host CNN, so host_risk mirrors the fused agent/perimeter risk
                nt_store = _open_timeseries()

                def on_metrics(row: dict) -> None:
                    nonlocal last_print
                    if stop.is_set():
                        raise KeyboardInterrupt
                    ascore = float(risk_state.get("agent", 0.0))
                    now = time.monotonic()
                    GLOBAL_BUS.push_sample(
                        cpu=float(row.get("cpu_percent") or 0.0),
                        mem=float(row.get("mem_percent") or 0.0),
                        net=float(
                            row.get("net_packets_sent_per_s")
                            or row.get("net_packets_recv_per_s")
                            or 0.0
                        ),
                        agent_score=ascore,
                        risk=ascore,
                        pattern="live metrics",
                        load_profile=load_name,
                    )
                    if nt_store is not None:
                        nt_store.write_many(
                            {
                                "cpu_percent": row.get("cpu_percent"),
                                "mem_percent": row.get("mem_percent"),
                                "swap_percent": row.get("swap_percent"),
                                "net_bytes_sent_per_s": row.get("net_bytes_sent_per_s"),
                                "net_bytes_recv_per_s": row.get("net_bytes_recv_per_s"),
                                "disk_read_bytes_per_s": row.get("disk_read_bytes_per_s"),
                                "disk_write_bytes_per_s": row.get("disk_write_bytes_per_s"),
                                "gpu_util_percent": row.get("gpu_util_percent"),
                                "gpu_mem_percent": row.get("gpu_mem_percent"),
                                "agent_score": ascore,
                                "host_risk": ascore,
                            }
                        )
                        nt_store.flush()
                        nt_store.maybe_rollup()
                    if now - last_print >= interval_sec:
                        last_print = now
                        console.print(f"host ok risk={ascore:.3f} host=0.000 agent={ascore:.3f} (notorch)")

                try:
                    daemon.run(duration_sec=duration_sec, on_sample=on_metrics)
                except KeyboardInterrupt:
                    return
                return
        try:
            infer = load_inferencer(
                artifacts_dir,
                runtime=runtime,
                supply_chain=config.get("supply_chain") or {},
            )
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
        ts_store = _open_timeseries()
        ts_metrics = (
            "cpu_percent",
            "mem_percent",
            "swap_percent",
            "net_bytes_sent_per_s",
            "net_bytes_recv_per_s",
            "disk_read_bytes_per_s",
            "disk_write_bytes_per_s",
            "gpu_util_percent",
            "gpu_mem_percent",
        )

        def on_sample(row: dict) -> None:
            nonlocal last_alert, last_infer, last_drift_notify
            if stop.is_set():
                raise KeyboardInterrupt
            if ts_store is not None:
                ts_store.write_many({m: row.get(m) for m in ts_metrics})
                ts_store.flush()
                ts_store.maybe_rollup()
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
            host_score = float(pred.score)
            try:
                tops_peek = list_top_processes(limit=3)
            except Exception:
                tops_peek = []
            for p in tops_peek:
                host_score = feedback.adjust_score(
                    host_score,
                    name=str(p.get("name") or ""),
                    comm=str(p.get("name") or ""),
                )
                if feedback.is_ignored(name=str(p.get("name") or "")):
                    host_score = min(host_score, pred.threshold * 0.5)
            recent_scores.append(host_score)
            if len(recent_scores) > 60:
                del recent_scores[:30]
            if not pred.is_anomaly and len(recent_scores) >= 10:
                calib.update(recent_scores[-10:])
                calib.save(cal_path)
            from sysspectogram.risk import decide_risk

            ascore = float(risk_state.get("agent", 0.0))
            agent_ts = risk_state.get("agent_ts")
            agent_age = (time.time() - float(agent_ts)) if agent_ts is not None else None
            risk_thr = ens_cfg.get("risk_threshold")
            if risk_thr is None:
                risk_thr = pred.threshold
            else:
                risk_thr = float(risk_thr)
            risk_thr = learner.apply_bias(float(risk_thr))
            host_thr = learner.apply_bias(float(pred.threshold))
            decision = decide_risk(
                host_score,
                ascore if agent_weight > 0 else None,
                agent_age,
                host_threshold=host_thr,
                risk_threshold=risk_thr,
                host_weight=host_weight,
                agent_weight=agent_weight,
                agent_half_life_sec=agent_half_life_sec,
            )
            risk = decision.risk
            if ts_store is not None:
                ts_store.write_many(
                    {
                        "host_score": host_score,
                        "host_risk": risk,
                        "agent_score": ascore,
                        "threshold": risk_thr,
                    }
                )
            is_anom = decision.is_anomaly
            status = "ANOMALY" if is_anom else "ok"
            console.print(
                f"host {status} risk={risk:.3f} host={host_score:.3f} agent={ascore:.3f} "
                f"cnn={pred.cnn_prob:.3f} iforest={pred.iforest_score:.3f}"
            )
            GLOBAL_BUS.set_host(host_id, float(risk_thr), model_loaded=True)
            GLOBAL_BUS.push_sample(
                cpu=float(row.get("cpu_percent") or 0.0),
                mem=float(row.get("mem_percent") or 0.0),
                net=float(
                    row.get("net_packets_sent_per_s")
                    or row.get("net_packets_recv_per_s")
                    or 0.0
                ),
                score=host_score,
                cnn=pred.cnn_prob,
                iforest=pred.iforest_score,
                agent_score=ascore,
                risk=risk,
                is_anomaly=is_anom,
                load_profile=load_name,
            )
            from sysspectogram.ml.calibration import suggested_threshold_hint

            if detect_drift(calib, recent_scores[-20:]):
                hint = suggested_threshold_hint(calib, recent_scores[-20:], infer.threshold)
                if now - last_drift_notify >= max(cooldown_sec * 5, 300.0):
                    last_drift_notify = now
                    msg = "[yellow]drift suspected vs host calibration baseline[/]"
                    if hint is not None:
                        msg += f" - consider threshold~{hint} (current={infer.threshold:.3f})"
                    console.print(msg)
                    if bot is not None and hint is not None:
                        try:
                            bot.client.send_message(
                                bot.prefix(
                                    f"DRIFT: scores shifted; suggested threshold~{hint} "
                                    f"(current={infer.threshold:.3f})"
                                )
                            )
                        except Exception:
                            pass
            if not is_anom:
                if bot is not None:
                    try:
                        bot.last_host_window = matrix
                        bot.last_host_columns = list(columns)
                        bot.last_host_score = float(host_score)
                    except Exception:
                        pass
                return
            if now - last_alert < cooldown_sec:
                return
            last_alert = now
            if bot is not None:
                try:
                    bot.last_host_window = matrix
                    bot.last_host_columns = list(columns)
                    bot.last_host_score = float(host_score)
                except Exception:
                    pass
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
            body = f"{body}\nrisk={risk:.2f} host={host_score:.2f} agent={ascore:.2f}"
            console.print(f"[red bold]HOST ALERT[/] pattern={pattern}\n{body}")
            host_plain = describe("host_anomaly", lang=notify_lang)  # type: ignore[arg-type]
            GLOBAL_BUS.push_alert(
                LiveAlert(
                    ts=__import__("time").time(),
                    severity="high",
                    title=host_plain.title,
                    body=f"{host_plain.what}\n{body}\n{host_plain.action}",
                    kind="host",
                    score=risk,
                    rule_id="host_anomaly",
                    extras={"host_score": pred.score, "agent_score": ascore, "risk": risk, "pattern": pattern},
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
            alert_fanout.emit(
                {
                    "type": "host_anomaly",
                    "host_id": host_id,
                    "score": pred.score,
                    "threshold": pred.threshold,
                    "pattern": pattern,
                    "top_processes": tops,
                    "top_features": feats,
                }
            )
            if (
                kirk_enabled
                and kirk_auto_isolate
                and kirk_auto_isolate_host_risk
                and not kirk_status.get("isolated")
                and float(pred.score) >= kirk_host_risk_threshold
            ):
                if not kirk_allow_cidrs:
                    console.print(
                        "[red]kirk host-risk isolate skipped[/] - set kirk.allow_ssh_cidrs first"
                    )
                else:
                    try:
                        msg_iso = nft.kirk_isolate(
                            allow_cidrs=kirk_allow_cidrs,
                            ttl_sec=kirk_isolate_ttl,
                            dry_run=dry_run_actions,
                        )
                        if "refused" not in msg_iso and "failed" not in msg_iso:
                            kirk_status["isolated"] = not dry_run_actions
                            console.print(f"[red]kirk isolate (host risk)[/] {msg_iso}")
                            alert_fanout.emit(
                                {
                                    "type": "kirk_auto_isolate",
                                    "reason": "host_risk",
                                    "score": pred.score,
                                    "threshold": kirk_host_risk_threshold,
                                    "message": msg_iso,
                                }
                            )
                    except Exception as exc:
                        console.print(f"[yellow]kirk host-risk isolate failed[/] {exc}")
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
                    score=host_score,
                    threshold=pred.threshold,
                    pattern=pattern,
                    explain=body,
                    top_procs=tops,
                    top_features=feats,
                )
                bot.send_host_alert(
                    score=host_score,
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

    canary = None
    canary_cfg = config.get("canary") or {}
    if canary_cfg.get("enabled"):
        from sysspectogram.perimeter.canary import CanaryBank
        from sysspectogram.perimeter.rules import Alert as PAlert

        ports = list(canary_cfg.get("ports") or [3377, 4488, 5599])
        canary = CanaryBank(ports=ports, bind=str(canary_cfg.get("bind", "0.0.0.0")))
        bound = canary.start()
        console.print(f"[cyan]canary[/] ports={bound}")

        def canary_loop():
            seen = 0
            t0 = time.monotonic()
            while not stop.is_set():
                if len(canary.hits) > seen:
                    for hit in canary.hits[seen:]:
                        a = PAlert(
                            rule_id="canary_hit",
                            severity="critical",
                            message=f"Canary touch from {hit.remote} to :{hit.port}",
                            ip=hit.remote,
                            port=hit.port,
                            extras={"recon_score": 1.0, "canary": True},
                        )
                        watcher.emit(a)
                    seen = len(canary.hits)
                if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                    break
                stop.wait(1.0)

        threads.append(threading.Thread(target=canary_loop, name="canary", daemon=True))

    # OSINT Tor exit list background refresh
    if bool((config.get("osint") or {}).get("tor_refresh", True)):
        def tor_refresh_loop():
            from sysspectogram.osint.cache import tor_exit_refresh

            while not stop.is_set():
                try:
                    n = tor_exit_refresh()
                    if n:
                        console.print(f"[cyan]osint[/] tor exits cached={n}")
                except Exception as exc:
                    console.print(f"[yellow]osint tor[/] {exc}")
                stop.wait(float((config.get("osint") or {}).get("tor_refresh_sec", 21600)))

        threads.append(threading.Thread(target=tor_refresh_loop, name="tor-refresh", daemon=True))

    flow_cfg = config.get("flow") or {}
    if bool(flow_cfg.get("enabled")):
        from sysspectogram.flow import FlowWatcher
        from sysspectogram.perimeter.rules import Alert as PAlert

        flow = FlowWatcher(
            window_sec=float(flow_cfg.get("window_sec", 30)),
            syn_threshold=int(flow_cfg.get("syn_threshold", 80)),
            unique_port_threshold=int(flow_cfg.get("unique_port_threshold", 40)),
            per_ip_syn_threshold=int(flow_cfg.get("per_ip_syn_threshold", 40)),
            backend=str(flow_cfg.get("backend") or ("netview" if load_name == "full" else "proc")),
        )
        console.print(
            f"[cyan]flow[/] backend={flow.backend} window={flow.window_sec}s "
            f"syn>={flow.syn_threshold} ports>={flow.unique_port_threshold}"
        )

        def flow_loop():
            t0 = time.monotonic()
            last_emit: dict[str, float] = {}
            while not stop.is_set():
                try:
                    for a in flow.poll():
                        key = f"{a.get('rule_id')}:{a.get('ip')}"
                        now = time.time()
                        if now - last_emit.get(key, 0) < 60:
                            continue
                        last_emit[key] = now
                        watcher.emit(
                            PAlert(
                                rule_id=str(a["rule_id"]),
                                severity=str(a.get("severity", "high")),
                                message=str(a["message"]),
                                ip=a.get("ip"),
                            )
                        )
                except Exception as exc:
                    console.print(f"[yellow]flow[/] {exc}")
                if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                    break
                stop.wait(2.0)

        threads.append(threading.Thread(target=flow_loop, name="flow", daemon=True))

    agent_listener = None
    agent_proc = None
    agent_cfg = config.get("agent") or {}
    fim_cfg_early = dict(agent_cfg.get("fim") or {})
    fim_confirm = ConfirmStreak(
        need=int(fim_cfg_early.get("confirm_streak", 2)),
        ttl_sec=float(fim_cfg_early.get("confirm_ttl_sec", 300)),
    )
    if agent_cfg.get("enabled"):
        from sysspectogram.agent_score import (
            AgentEventMatrix,
            AgentFeatureWindow,
            AgentIsolationScorer,
        )

        agent_feat = AgentFeatureWindow(window_sec=float(agent_cfg.get("score_window_sec", 120)))
        agent_scorer = AgentIsolationScorer(
            _resolve(agent_cfg["iforest"]) if agent_cfg.get("iforest") else None,
            supply_chain=config.get("supply_chain") or {},
        )
        # Feature layout follows the loaded model (legacy 9 counters or event matrix 2K).
        agent_feature_mode = (
            str(agent_scorer.meta.get("feature_mode", "legacy")) if agent_scorer.model else "legacy"
        )
        agent_mat = AgentEventMatrix(window_sec=int(float(agent_cfg.get("score_window_sec", 120))))
        # Phase 1b (experimental, default off): event spectrogram CNN, see ADR 0002.
        spectro_scorer = None
        spectro_mat = None
        if agent_cfg.get("spectrogram"):
            from sysspectogram.agent_spectro import WINDOW as SPECTRO_WINDOW
            from sysspectogram.agent_spectro import AgentSpectroScorer

            spectro_scorer = AgentSpectroScorer(
                _resolve(agent_cfg.get("spectrogram_model") or "artifacts/agent")
            )
            spectro_mat = AgentEventMatrix(window_sec=SPECTRO_WINDOW)
            if not spectro_scorer.ready:
                console.print("[yellow]agent.spectrogram on but no agent_spectro model - off[/]")
                spectro_scorer = None
        agent_score_threshold = float(agent_cfg.get("score_threshold", 0.65))
        last_agent_seen = {"ts": time.time()}
        agent_heartbeat_sec = float(agent_cfg.get("heartbeat_sec", 180))
        # After auto_start, wait before first "agent down" alert.
        agent_down_grace_until = time.time() + max(120.0, agent_heartbeat_sec)
        agent_down_backoff_sec = float(agent_cfg.get("down_alert_backoff_sec", 1800))  # 30 min
        clean_shutdown_grace = {"until": 0.0}


        raw_sock = agent_cfg.get("socket")
        if not raw_sock:
            runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/sysspectogram-{os.getuid()}"
            Path(runtime).mkdir(parents=True, exist_ok=True)
            raw_sock = str(Path(runtime) / "sysspectogram-agent.sock")
        sock_path = str(raw_sock) if str(raw_sock).startswith("/") else str(_resolve(raw_sock))

        def on_agent_alert(alert) -> None:
            from sysspectogram.perimeter.rules import Alert as PAlert

            if str(alert.rule_id) == "agent_kirk_clean_shutdown":
                if getattr(alert, "hmac_ok", None) is not True:
                    console.print("[yellow]agent[/] clean_shutdown ignored (HMAC required)")
                    return
                last_agent_seen["ts"] = time.time()
                clean_shutdown_grace["until"] = time.time() + 120.0
                console.print("[cyan]agent[/] CLEAN_SHUTDOWN received - Dead-man suppressed 120s")
                GLOBAL_BUS.push_alert(
                    LiveAlert(
                        ts=alert.ts,
                        severity="info",
                        title="AGENT | clean_shutdown",
                        body=str(alert.message),
                        kind="agent",
                        rule_id=alert.rule_id,
                        extras={},
                    )
                )
                return

            # metrics channel is primary liveness; signed alerts also count
            if getattr(alert, "hmac_ok", None) is True:
                last_agent_seen["ts"] = time.time()

            if feedback.is_ignored(
                comm=getattr(alert, "comm", None),
                path=getattr(alert, "path", None),
            ) or feedback.is_rule_muted(str(alert.rule_id)):
                return

            extras = dict(getattr(alert, "extras", None) or {})
            agent_feat.push(
                str(alert.rule_id),
                risky_comm=bool(extras.get("risky_comm")),
                path=getattr(alert, "path", None),
            )
            agent_mat.push(str(alert.rule_id))
            agent_vec = (
                agent_mat.features() if agent_feature_mode == "matrix" else agent_feat.vector()
            )
            ascore = agent_scorer.score(agent_vec)
            if spectro_scorer is not None and spectro_mat is not None:
                spectro_mat.push(str(alert.rule_id))
                spectro_score = spectro_scorer.score(spectro_mat.matrix())
                extras["agent_spectro"] = round(spectro_score, 3)
                ascore = max(ascore, spectro_score)
            ascore = feedback.adjust_score(
                ascore,
                comm=getattr(alert, "comm", None),
                path=getattr(alert, "path", None),
            )
            raw_thr = (config.get("ensemble") or {}).get("risk_threshold", 0.7)
            risk_thr = float(raw_thr if raw_thr is not None else 0.7)
            ascore = apply_kirk_override(
                ascore,
                rule_id=str(alert.rule_id),
                severity=str(alert.severity),
                risk_threshold=risk_thr,
            )
            risk_state["agent"] = float(ascore)
            risk_state["agent_ts"] = time.time()
            extras["agent_score"] = round(ascore, 3)
            extras["kirk_trust"] = kirk_status.get("trust")
            alert.extras = extras

            # auto_isolate: only allowlisted rule_ids (ignore forged severity=critical alone)
            _AUTO_ISOLATE_RULES = frozenset(
                {
                    "agent_kirk_module_hide",
                    "agent_kirk_symbol_drift",
                    "agent_kirk_ima_mismatch",
                }
            )
            _KIRK_CONFIRM_RULES = frozenset(
                {
                    "agent_kirk_module_hide",
                    "agent_kirk_symbol_drift",
                    "agent_kirk_ima_mismatch",
                    "agent_kirk_pid_hide",
                }
            )
            kirk_confirmed = True
            if str(alert.rule_id) in _KIRK_CONFIRM_RULES:
                kkey = (
                    f"{alert.rule_id}:"
                    f"{getattr(alert, 'path', '') or getattr(alert, 'comm', '') or ''}"
                )
                kirk_confirmed = kirk_confirm.hit(kkey)
                extras["kirk_confirmed"] = bool(kirk_confirmed)
                alert.extras = extras
                if not kirk_confirmed:
                    console.print(
                        f"[dim]kirk confirm pending[/] {alert.rule_id} "
                        f"(need {kirk_confirm.need} in {kirk_confirm.ttl_sec:.0f}s)"
                    )
            if (
                kirk_enabled
                and kirk_auto_isolate
                and kirk_confirmed
                and not kirk_status.get("isolated")
                and str(alert.rule_id) in _AUTO_ISOLATE_RULES
                and str(alert.severity).lower() == "critical"
            ):
                if getattr(alert, "hmac_ok", None) is not True:
                    console.print(
                        f"[red]kirk auto_isolate blocked[/] missing/invalid HMAC for {alert.rule_id}"
                    )
                elif not kirk_allow_cidrs:
                    console.print(
                        "[red]kirk auto_isolate skipped[/] - set kirk.allow_ssh_cidrs first"
                    )
                else:
                    try:
                        msg_iso = nft.kirk_isolate(
                            allow_cidrs=kirk_allow_cidrs,
                            ttl_sec=kirk_isolate_ttl,
                            dry_run=dry_run_actions,
                        )
                        if "refused" in msg_iso or "failed" in msg_iso:
                            console.print(f"[yellow]kirk isolate[/] {msg_iso}")
                        else:
                            kirk_status["isolated"] = not dry_run_actions
                            try:
                                GLOBAL_BUS.set_kirk(isolated=bool(kirk_status["isolated"]))
                            except Exception:
                                pass
                            console.print(f"[red]kirk isolate[/] {msg_iso}")
                            bot = bot_holder["bot"]
                            if bot is not None:
                                try:
                                    bot.client.send_message(
                                        bot.prefix(
                                            f"KIRK [critical] AUTO ISOLATE after {alert.rule_id}: {msg_iso}\n"
                                            f"/kirk_release after /unlock (TTL={kirk_isolate_ttl}s)"
                                        )
                                    )
                                except Exception:
                                    pass
                    except Exception as exc:
                        console.print(f"[yellow]kirk isolate failed[/] {exc}")

            # Telegram: default quiet. Only push high-signal rules, or when IF is hot.
            quiet_unless_hot = {
                "agent_path_watch",
                "agent_ebpf_execve",
                "agent_ebpf_openat",
                "agent_ebpf",
            }
            notify_tg = True
            if alert.rule_id in quiet_unless_hot and ascore < agent_score_threshold:
                notify_tg = False
            # FIM: require confirm streak before TG (noise control)
            if str(alert.rule_id).startswith("agent_fim_"):
                fkey = f"{alert.rule_id}:{getattr(alert, 'path', '') or ''}"
                if not fim_confirm.hit(fkey):
                    notify_tg = False
                    console.print(f"[dim]fim confirm pending[/] {alert.rule_id}")
            # kirk: notify hide/drift/ima/down after confirm; module_load has cooldown
            if alert.rule_id.startswith("agent_kirk_"):
                notify_tg = True
                if str(alert.rule_id) in _KIRK_CONFIRM_RULES and not kirk_confirmed:
                    notify_tg = False
                if alert.rule_id in (
                    "agent_kirk_module_load",
                    "agent_kirk_module_delete",
                ):
                    now_m = time.time()
                    last_m = float(kirk_status.get("_last_module_tg") or 0.0)
                    if now_m - last_m < 120.0:
                        notify_tg = False
                    else:
                        kirk_status["_last_module_tg"] = now_m
            path_l = (getattr(alert, "path", None) or "").lower()
            if alert.rule_id.startswith("agent_ebpf") and _ebpf_path_benign(path_l):
                notify_tg = False
            if alert.rule_id == "agent_open_sensitive" and _benign_sudo_sudoers(
                getattr(alert, "comm", None), getattr(alert, "path", None)
            ):
                notify_tg = False

            body = str(alert.message)
            if ascore >= agent_score_threshold and notify_tg:
                body = f"{body}\nagent_score={ascore:.2f} (elevated)"
            if alert.rule_id.startswith("agent_kirk_"):
                body = f"{body}\nkirk.trust={kirk_status.get('trust')}"

            GLOBAL_BUS.push_alert(
                LiveAlert(
                    ts=alert.ts,
                    severity=str(alert.severity),
                    title=f"AGENT | {alert.rule_id}",
                    body=body,
                    kind="agent",
                    rule_id=alert.rule_id,
                    extras={
                        "pid": alert.pid,
                        "ppid": alert.ppid,
                        "comm": alert.comm,
                        "path": alert.path,
                        "agent_score": ascore,
                    },
                )
            )
            pa = PAlert(
                rule_id=alert.rule_id,
                severity=alert.severity,
                message=body,
                extras={
                    "pid": alert.pid,
                    "ppid": alert.ppid,
                    "comm": alert.comm,
                    "path": alert.path,
                    "source": "agent",
                    "agent_score": ascore,
                },
            )
            if jsonl_out or per_cfg.get("jsonl_out"):
                try:
                    append_jsonl(
                        _resolve(jsonl_out or per_cfg.get("jsonl_out", "reports/perimeter.jsonl")),
                        {
                            "type": "agent",
                            "rule_id": alert.rule_id,
                            "severity": alert.severity,
                            "message": alert.message,
                            "pid": alert.pid,
                            "path": alert.path,
                            "ts": alert.ts,
                        },
                    )
                except Exception:
                    pass
            bot = bot_holder["bot"]
            if bot is not None and notify_tg:
                try:
                    if str(alert.rule_id) == "agent_unexpected_root":
                        from types import SimpleNamespace

                        extras_r = getattr(alert, "extras", None) or {}
                        if not isinstance(extras_r, dict):
                            extras_r = {}
                        bot.send_root_alert(
                            SimpleNamespace(
                                pid=int(getattr(alert, "pid", 0) or 0),
                                comm=str(getattr(alert, "comm", "") or ""),
                                exe=str(getattr(alert, "path", "") or ""),
                                cmdline=str(extras_r.get("cmdline") or ""),
                            )
                        )
                    else:
                        alert.message = body
                        if str(alert.rule_id) == "agent_connect_burst" and is_unattributed(
                            getattr(alert, "pid", 0)
                        ):
                            # Unattributed connection bursts are noise on Telegram; they stay in the app log.
                            console.print("[dim]telegram: skipped unattributed connect burst (pid 0)[/]")
                        else:
                            bot.send_agent_alert(
                                alert,
                                png=_event_snapshot(
                                    getattr(alert, "ts", None), f"{alert.rule_id} · {alert.severity}"
                                ),
                            )
                except Exception:
                    pass
            webhook = siem_cfg.get("webhook_url")
            if webhook:
                post_webhook(
                    webhook,
                    {
                        "host_id": host_id,
                        "type": "agent",
                        "rule_id": alert.rule_id,
                        "severity": alert.severity,
                        "message": alert.message,
                        "pid": alert.pid,
                        "path": alert.path,
                    },
                    secret=siem_cfg.get("webhook_secret"),
                )
            _ = pa

        def on_agent_metrics(sample) -> None:
            # Phase 2: feed live web from Rust hot path (ML still uses Python collector).
            last_agent_seen["ts"] = time.time()
            try:
                GLOBAL_BUS.push_sample(
                    cpu=float(sample.cpu_percent),
                    mem=float(sample.mem_percent),
                    net=float(sample.net_packets_sent_per_s or sample.net_packets_recv_per_s or 0.0),
                    pattern="agent metrics",
                )
            except Exception:
                pass

        vmi_source = None
        vmi_cv_state = None
        vmi_state: dict[str, float] = {"last": 0.0}
        vmi_interval = float(kirk_cfg.get("vmi_interval_sec", 30))
        if kirk_cfg.get("vmi"):
            from sysspectogram.vmi.crossview import CrossViewState
            from sysspectogram.vmi.mock import MockGuestTaskSource

            if str(kirk_cfg.get("vmi_backend", "mock")) == "libvmi":
                from sysspectogram.vmi.libvmi import LibvmiTaskSource

                vmi_source = LibvmiTaskSource(
                    str(kirk_cfg.get("vmi_domain") or ""),
                    profile=_resolve(str(kirk_cfg.get("vmi_profile") or "")),
                    trust=str(kirk_cfg.get("vmi_trust", "lab")),
                )
            else:
                vmi_source = MockGuestTaskSource()
            vmi_cv_state = CrossViewState(confirm=int(kirk_cfg.get("vmi_confirm", 2)))

        def on_agent_pids(pids: set[int]) -> None:
            if vmi_source is None or vmi_cv_state is None:
                return
            now = time.time()
            if now - vmi_state["last"] < vmi_interval:
                return
            vmi_state["last"] = now
            from sysspectogram.vmi import crossview

            try:
                alerts = crossview.check(pids, vmi_source, vmi_cv_state, host_id)
            except Exception as exc:  # fail-open: VMI problems must not stop the guard
                console.print(f"[yellow]vmi check skipped[/] {exc}")
                return
            for a in alerts:
                alert_fanout.emit(a)
                console.print(f"[red]VMI[/] {a['message']} trust={vmi_source.trust}")

        agent_listener = AgentSocketListener(
            sock_path,
            on_alert=on_agent_alert,
            on_pids=on_agent_pids if kirk_cfg.get("vmi") else None,
            on_metrics=on_agent_metrics if bool(agent_cfg.get("metrics", True)) else None,
            cooldown_sec=float(agent_cfg.get("cooldown_sec", 60)),
            max_alerts_per_min=int(agent_cfg.get("max_alerts_per_min", 20)),
            require_same_uid=bool(agent_cfg.get("require_same_uid", True)),
            hmac_secret=hmac_secret,
            require_hmac_critical=bool(agent_cfg.get("require_hmac", True)),
        )
        agent_exe_seal: dict[str, str] = {}

        def _on_exe_mismatch(pid: int, exe: str) -> None:
            console.print(f"[red]agent exe mismatch[/] pid={pid} exe={exe}")
            bot = bot_holder["bot"]
            if bot is not None:
                try:
                    from types import SimpleNamespace

                    bot.send_root_alert(
                        SimpleNamespace(
                            pid=pid,
                            comm="agent-swap?",
                            exe=exe,
                            cmdline="agent_exe_mismatch (binary seal failed)",
                        )
                    )
                except Exception:
                    try:
                        bot.client.send_message(
                            bot.prefix(
                                f"KIRK [critical] agent_exe_mismatch\n"
                                f"pid={pid} exe={exe}\n"
                                f"expected={agent_exe_seal.get('path')}"
                            )
                        )
                    except Exception:
                        pass

        agent_listener.on_exe_mismatch = _on_exe_mismatch
        try:
            agent_listener.start()
            console.print(f"[cyan]agent socket[/] listening {sock_path}")
        except OSError as exc:
            console.print(f"[yellow]agent socket[/] {exc}")
            agent_listener = None

        def agent_heartbeat_loop():
            # Persist last TG alert across restarts so we do not re-flood every Start.
            alert_marker = _resolve("state/agent_down_alert.ts")
            try:
                last_alert_sent = float(alert_marker.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                last_alert_sent = 0.0
            agent_pidfile = _resolve(agent_cfg.get("pidfile", "state/agent.pid"))
            while not stop.is_set():
                now = time.time()
                if now < float(clean_shutdown_grace.get("until") or 0):
                    stop.wait(5.0)
                    continue
                if now < agent_down_grace_until:
                    stop.wait(5.0)
                    continue
                # Process alive ⇒ not "down" even if metrics packets were missed
                # (e.g. socket briefly rebound). Still want metrics eventually.
                alive_pid = _running_agent_pid(agent_pidfile)
                if alive_pid is not None:
                    last_agent_seen["ts"] = now
                    stop.wait(15.0)
                    continue
                silence = now - last_agent_seen["ts"]
                # First alert after silence threshold; then at most every backoff (30 min).
                min_gap = agent_down_backoff_sec if last_alert_sent else agent_heartbeat_sec
                if silence >= agent_heartbeat_sec and (now - last_alert_sent) >= min_gap:
                    last_alert_sent = now
                    try:
                        alert_marker.parent.mkdir(parents=True, exist_ok=True)
                        alert_marker.write_text(f"{now:.3f}\n", encoding="utf-8")
                    except OSError:
                        pass
                    plain = describe(
                        "agent_kirk_agent_down",
                        f"silence={silence:.0f}s",
                        lang=notify_lang,  # type: ignore[arg-type]
                    )
                    console.print(f"[red]agent_kirk_agent_down[/] silence={silence:.0f}s")
                    try:
                        alert_fanout.emit(
                            {
                                "type": "agent_kirk_agent_down",
                                "host_id": host_id,
                                "silence_sec": silence,
                                "message": plain.what,
                            }
                        )
                    except Exception:
                        pass
                    bot = bot_holder["bot"]
                    if bot is not None:
                        try:
                            body = f"{plain.title}\n{plain.what}\n{plain.action}"
                            bot.client.send_message(bot.prefix(body))
                        except Exception:
                            pass
                stop.wait(15.0)

        if agent_listener is not None:
            threads.append(
                threading.Thread(target=agent_heartbeat_loop, name="agent-hb", daemon=True)
            )

        def ima_watch_loop():
            if not (kirk_enabled and bool(kirk_cfg.get("ima_watch", True))):
                return
            state_p = _resolve(kirk_cfg.get("ima_state_path", "state/ima_offset.txt"))
            # seed offset so boot history does not flood
            try:
                ima_watch_new_lines(state_p)
            except Exception:
                pass
            while not stop.is_set():
                try:
                    lines = ima_watch_new_lines(state_p)
                except Exception:
                    lines = []
                for ln in lines:
                    low = ln.lower()
                    if "module" not in low and "/lib/modules/" not in low and not low.endswith(".ko"):
                        continue
                    msg = f"IMA new module-related measurement: {ln[:200]}"
                    console.print(f"[magenta]kirk ima[/] {msg}")
                    bot = bot_holder["bot"]
                    if bot is not None:
                        try:
                            bot.client.send_message(
                                bot.prefix(f"KIRK [high] agent_kirk_ima_event\n{msg}\ntrust={kirk_status.get('trust')}")
                            )
                        except Exception:
                            pass
                stop.wait(30.0)

        if kirk_enabled and bool(kirk_cfg.get("ima_watch", True)):
            threads.append(threading.Thread(target=ima_watch_loop, name="ima-watch", daemon=True))

        # Never start a second agent on the same socket/pidfile (duplicate events + watchdog churn).
        running_agent = (
            _running_agent_pid(_resolve(agent_cfg.get("pidfile") or "state/agent.pid"))
            if agent_cfg.get("auto_start")
            else None
        )
        if running_agent is not None:
            console.print(
                f"[yellow]agent auto_start[/] agent already running pid={running_agent}; "
                "reusing it (not starting a second copy)"
            )
        if agent_cfg.get("auto_start") and agent_listener is not None and running_agent is None:
            import shutil
            import subprocess

            bin_path = agent_cfg.get("binary") or shutil.which("sysspectogram-agent")
            if not bin_path:
                cand = ROOT / "agent" / "target" / "release" / "sysspectogram-agent"
                if cand.exists():
                    bin_path = str(cand)
            if bin_path:
                try:
                    from sysspectogram.trusted_pids import seal_binary

                    agent_exe_seal.update(seal_binary(Path(bin_path)))
                    agent_listener.set_exe_seal(
                        {agent_exe_seal["path"], "/usr/local/sbin/sysspectogram-agent"},
                        agent_exe_seal.get("sha256"),
                    )
                    seal_path = _resolve("state/agent_binary.seal.json")
                    seal_path.parent.mkdir(parents=True, exist_ok=True)
                    seal_path.write_text(
                        __import__("json").dumps(agent_exe_seal, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    console.print(
                        f"[cyan]agent seal[/] {agent_exe_seal['path']} "
                        f"sha256={agent_exe_seal['sha256'][:16]}..."
                    )
                except Exception as exc:
                    console.print(f"[yellow]agent seal[/] {exc}")
                cmd = [
                    str(bin_path),
                    "--socket",
                    sock_path,
                    "--host-id",
                    str(host_id),
                    "--hmac-secret",
                    str(_resolve("state/agent_hmac.secret")),
                    "--pidfile",
                    str(_resolve("state/agent.pid")),
                    "--mode",
                    str(agent_cfg.get("mode", "userspace")),
                    "--poll-ms",
                    str(int(agent_cfg.get("poll_ms", 500))),
                ]
                if agent_cfg.get("metrics", True):
                    cmd.extend(["--metrics-ms", str(int(agent_cfg.get("metrics_ms", 1000)))])
                else:
                    cmd.extend(["--metrics-ms", "0"])
                if kirk_cfg.get("vmi"):
                    cmd.extend(["--pids-sec", str(int(kirk_cfg.get("vmi_pids_sec", 5)))])
                fim_cfg = agent_cfg.get("fim") or {}
                if bool(fim_cfg.get("enabled")):
                    cmd.append("--fim")
                    cmd.extend(["--fim-interval-sec", str(int(fim_cfg.get("interval_sec", 60)))])
                    cmd.extend(
                        [
                            "--fim-baseline",
                            str(
                                _resolve(
                                    fim_cfg.get("baseline_path", "state/fim-baseline.json")
                                )
                            ),
                        ]
                    )
                jpath = agent_cfg.get("jsonl")
                if jpath:
                    cmd.extend(["--jsonl", str(_resolve(jpath))])
                if bool(agent_cfg.get("root_watch", True)):
                    cmd.append("--root-watch")
                    cmd.extend(
                        [
                            "--root-learn-sec",
                            str(int(agent_cfg.get("root_learn_sec", 300))),
                        ]
                    )
                else:
                    cmd.append("--no-root-watch")
                wd_cfg = dict(config.get("watchdog") or {})
                if bool(wd_cfg.get("phoenix", True)):
                    cmd.append("--phoenix")
                try:
                    agent_log = _resolve("state/agent.stderr.log")
                    agent_log.parent.mkdir(parents=True, exist_ok=True)
                    log_fh = open(agent_log, "ab", buffering=0)
                    agent_proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=log_fh,
                    )
                    try:
                        log_fh.close()
                    except Exception:
                        pass
                    time.sleep(0.4)
                    rc = agent_proc.poll()
                    if rc is not None:
                        tail = ""
                        try:
                            tail = agent_log.read_bytes()[-800:].decode("utf-8", "replace")
                        except Exception:
                            pass
                        console.print(
                            f"[red]agent auto_start[/] exited rc={rc} — see {agent_log}\n{tail}"
                        )
                        agent_proc = None
                        plain = describe("agent_start_failed", lang=notify_lang)  # type: ignore[arg-type]
                        bot = bot_holder["bot"]
                        if bot is not None:
                            try:
                                bot.client.send_message(
                                    bot.prefix(f"{plain.title}\n{plain.what}\n{plain.action}")
                                )
                            except Exception:
                                pass
                    else:
                        console.print(
                            f"[green]agent auto_start[/] pid={agent_proc.pid} log={agent_log}"
                        )
                        if bool(wd_cfg.get("kernel_protect", False)):
                            try:
                                from sysspectogram.watchdog_kmod import (
                                    kernel_module_present,
                                    register_pid,
                                )

                                if kernel_module_present():
                                    register_pid(int(agent_proc.pid))
                                    console.print("[cyan]watchdog[/] kernel_protect PID registered")
                                else:
                                    console.print(
                                        "[yellow]watchdog[/] kernel_protect enabled but "
                                        "sysspectogram_wd sysfs missing — continuing userspace-only"
                                    )
                            except Exception as exc:
                                console.print(f"[yellow]watchdog kernel_protect[/] {exc}")
                        try:
                            from sysspectogram.trusted_pids import collect_trusted_pids

                            pids = collect_trusted_pids(
                                agent_pidfile=_resolve("state/agent.pid"),
                                watchdog_pidfile=_resolve("state/watchdog.pid"),
                                child_of=int(agent_proc.pid),
                                allowed_exe_paths=set(agent_listener.allowed_exe_paths)
                                or {str(Path(bin_path).resolve())},
                                expected_sha256=agent_exe_seal.get("sha256"),
                            )
                            # Always assign (empty set = drop forgers; never keep stale PIDs).
                            agent_listener.set_allowed_pids(pids if pids else {int(agent_proc.pid)})
                        except Exception:
                            try:
                                agent_listener.set_allowed_pids({int(agent_proc.pid)})
                            except Exception:
                                pass
                except OSError as exc:
                    console.print(f"[yellow]agent auto_start[/] {exc}")
                    plain = describe("agent_start_failed", str(exc), lang=notify_lang)  # type: ignore[arg-type]
                    bot = bot_holder["bot"]
                    if bot is not None:
                        try:
                            bot.client.send_message(
                                bot.prefix(f"{plain.title}\n{plain.what}\n{plain.action}")
                            )
                        except Exception:
                            pass
            else:
                console.print(
                    "[yellow]agent auto_start[/] binary not found - build agent/ "
                    "or put sysspectogram-agent on PATH"
                )
                plain = describe("agent_start_failed", lang=notify_lang)  # type: ignore[arg-type]
                bot = bot_holder["bot"]
                if bot is not None:
                    try:
                        bot.client.send_message(
                            bot.prefix(f"{plain.title}\n{plain.what}\n{plain.action}")
                        )
                    except Exception:
                        pass
        elif agent_listener is not None:
            # external agent (systemd): load prior seal if present
            seal_path = _resolve("state/agent_binary.seal.json")
            if seal_path.exists():
                try:
                    import json as _json

                    agent_exe_seal.update(_json.loads(seal_path.read_text(encoding="utf-8")))
                    agent_listener.set_exe_seal(
                        {
                            agent_exe_seal.get("path", ""),
                            "/usr/local/sbin/sysspectogram-agent",
                        },
                        agent_exe_seal.get("sha256"),
                    )
                except Exception:
                    pass

        def pid_allowlist_loop():
            from sysspectogram.trusted_pids import collect_trusted_pids

            while not stop.is_set():
                if agent_listener is not None:
                    try:
                        extra = set()
                        if agent_proc is not None and agent_proc.poll() is None:
                            extra.add(int(agent_proc.pid))
                        paths = set(agent_listener.allowed_exe_paths) or {
                            "/usr/local/sbin/sysspectogram-agent"
                        }
                        pids = collect_trusted_pids(
                            agent_pidfile=_resolve(
                                agent_cfg.get("pidfile") or "state/agent.pid"
                            ),
                            watchdog_pidfile=_resolve("state/watchdog.pid"),
                            extra=extra,
                            allowed_exe_paths=paths,
                            expected_sha256=agent_exe_seal.get("sha256")
                            or agent_listener.expected_exe_sha256,
                        )
                        # Always refresh — empty means "no trusted sender" (fixes stale PID
                        # after rebuild/seal mismatch that otherwise blocked live metrics).
                        if pids:
                            agent_listener.set_allowed_pids(pids)
                        elif agent_listener.allowed_pids:
                            console.print(
                                "[yellow]agent allowlist[/] empty (dead pidfile or seal "
                                "mismatch) — clearing stale PIDs; reseal after rebuild"
                            )
                            agent_listener.set_allowed_pids(set())
                    except Exception:
                        pass
                stop.wait(5.0)

        if agent_listener is not None:
            threads.append(
                threading.Thread(target=pid_allowlist_loop, name="pid-allow", daemon=True)
            )

        sess_cfg = config.get("sessions") or {}
        if bool(sess_cfg.get("enabled", True)):
            from sysspectogram.session_watch import SessionWatchState, poll_unexpected, session_key
            from sysspectogram.perimeter.rules import Alert as PAlert

            sess_state = SessionWatchState()
            allow_users = set(str(x) for x in (sess_cfg.get("allow_users") or []))
            allow_cidrs = list(sess_cfg.get("allow_cidrs") or kirk_allow_cidrs or [])

            def session_loop():
                t0 = time.monotonic()
                while not stop.is_set():
                    try:
                        unexpected = poll_unexpected(
                            sess_state,
                            allow_users=allow_users,
                            allow_cidrs=allow_cidrs,
                            learn_sec=float(sess_cfg.get("learn_sec", 120)),
                        )
                        for s in unexpected:
                            key = session_key(s)
                            sess_state.seen.add(key)
                            a = PAlert(
                                rule_id="unexpected_ssh_session",
                                severity="high",
                                message=f"Unexpected login {s.user} on {s.tty} from {s.host or '?'}",
                                ip=s.host if s.host and s.host[0].isdigit() else None,
                                extras={"tty": s.tty, "user": s.user, "host": s.host},
                            )
                            watcher.emit(a)
                            bot = bot_holder["bot"]
                            if bot is not None:
                                try:
                                    bot.send_session_alert(s)
                                except Exception:
                                    pass
                    except Exception as exc:
                        console.print(f"[yellow]session watch[/] {exc}")
                    if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                        break
                    stop.wait(float(sess_cfg.get("poll_sec", 15)))

            threads.append(threading.Thread(target=session_loop, name="sessions", daemon=True))

        root_cfg = config.get("root_watch") or {}
        agent_on = bool((config.get("agent") or {}).get("enabled"))
        # Prefer Rust agent root_watch; Python poller only without agent.
        if bool(root_cfg.get("enabled", False)) and not agent_on:
            from sysspectogram.root_watch import RootWatchState, poll_new_root
            from sysspectogram.perimeter.rules import Alert as PAlert

            root_state = RootWatchState()
            allow_comms = set(str(x) for x in (root_cfg.get("allow_comms") or [])) or None

            def root_loop():
                t0 = time.monotonic()
                while not stop.is_set():
                    try:
                        news = poll_new_root(
                            root_state,
                            learn_sec=float(root_cfg.get("learn_sec", 300)),
                            allow_comms=allow_comms,
                        )
                        for p in news:
                            a = PAlert(
                                rule_id="unexpected_root_process",
                                severity="critical",
                                message=(
                                    f"New root process pid={p.pid} comm={p.comm} "
                                    f"exe={p.exe or '?'}"
                                ),
                                extras={
                                    "pid": p.pid,
                                    "comm": p.comm,
                                    "path": p.exe,
                                    "cmdline": p.cmdline,
                                },
                            )
                            watcher.emit(a)
                            bot = bot_holder["bot"]
                            if bot is not None:
                                try:
                                    bot.send_root_alert(p)
                                except Exception:
                                    pass
                    except Exception as exc:
                        console.print(f"[yellow]root watch[/] {exc}")
                    if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                        break
                    stop.wait(float(root_cfg.get("poll_sec", 60)))

            threads.append(threading.Thread(target=root_loop, name="root-watch", daemon=True))
            console.print(
                f"[cyan]root watch[/] python fallback learn={float(root_cfg.get('learn_sec', 300)):.0f}s "
                f"poll={float(root_cfg.get('poll_sec', 60)):.0f}s"
            )
        elif agent_on and bool((config.get("agent") or {}).get("root_watch", True)):
            console.print(
                f"[cyan]root watch[/] via agent learn={int((config.get('agent') or {}).get('root_learn_sec', 300))}s"
            )

    for t in threads:
        t.start()
    # SIGTERM (e.g. the Control Center stopping us) shuts down exactly like Ctrl-C.
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, signal.default_int_handler)
    clean_stop = False
    try:
        t0 = time.monotonic()
        while True:
            if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                break
            if all(not t.is_alive() for t in threads):
                break
            time.sleep(0.5)
        clean_stop = True
    except KeyboardInterrupt:
        console.print("stopping guard...")
        clean_stop = True
    finally:
        stop.set()
        if control_srv is not None:
            try:
                control_srv.stop()
            except Exception:
                pass
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
        if honeypot is not None:
            honeypot.stop()
        if canary is not None:
            canary.stop()
        if agent_listener is not None:
            agent_listener.stop()
        if agent_proc is not None and agent_proc.poll() is None:
            try:
                agent_proc.terminate()
                agent_proc.wait(timeout=3)
            except Exception:
                try:
                    agent_proc.kill()
                except Exception:
                    pass
        for t in threads:
            t.join(timeout=3)
        watcher.persist()
        if clean_stop:
            _clear_guard_pidfile(os.getpid())
            _drop_file(_resolve("state/unlock.code"))
