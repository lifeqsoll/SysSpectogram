from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

from sysspectogram.explain.templates import explain_host_anomaly, explain_perimeter
from sysspectogram.notify_telegram import TelegramClient
from sysspectogram.osint.recon import run_full_recon, save_report
from sysspectogram.perimeter.connections import listening_ports, snapshot_connections
from sysspectogram.perimeter.rules import Alert
from sysspectogram.perimeter.watcher import PerimeterWatcher
from sysspectogram.response.actions import NftBackend, kill_pid, read_proc_comm
from sysspectogram.response.tokens import TokenStore
from sysspectogram.console_unlock import ConsoleUnlock


HELP_TEXT = """\
SysSpectogram TG control (allowlisted chat only)

Status:
/ping /help /menu /version /status /digest /last [n]
/dashboard          # open live Mini App (needs WEBAPP_URL)
/unlock <code>      # console pairing code (required after guard start)
/lock               # re-lock control plane

Host audit (CLI audit):
/audit /processes /ports /rootkit /panel /score

Perimeter / response:
/bans /ban <ip> [ttl_sec|perm]
/unban <ip> /allow <ip> /mute <ip> [sec]
/quiet on|off /lockdown
/recon <ip> /labnmap <ip> /report

Load sims (lab only; telegram.allow_destructive_sims):
/simulate cpu|mem|disk|net|gpu [duration]
/collect [duration]   # short CSV sample, max 180s

Offline (paths relative to project):
/analyze <csv>        # needs --model on guard

Recipes:
/recipes

Destructive = inline YES/NO. No shell from phone.
train / build-dataset — terminal only (see /recipes).
"""

RECIPES_TEXT = """\
Best CLI recipes (run on host):

# 1) Full train pipeline (CPU anomalies)
python -m sysspectogram collect --out data/normal.csv --duration 1800
python -m sysspectogram simulate cpu --duration 900 --workers 8 &
python -m sysspectogram collect --out data/anomaly_cpu.csv --duration 900
python -m sysspectogram build-dataset \\
  --normal data/normal.csv --anomaly data/anomaly_cpu.csv \\
  --out dataset/real --window 60 --stride 5 --png
python -m sysspectogram train --dataset dataset/real --out artifacts/real --epochs 25

# 2) Live guard + Telegram (dry-run safe)
export TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...
python -m sysspectogram guard --model artifacts/real_v3 \\
  --telegram --dry-run --jsonl-out reports/guard.jsonl

# 3) Production guard (real nft/kill after confirm)
python -m sysspectogram guard --model artifacts/real_v3 --telegram

# 4) Perimeter only
python -m sysspectogram watch-perimeter --duration 3600 \\
  --jsonl-out reports/perimeter.jsonl

# 5) OSINT pack
python -m sysspectogram recon 203.0.113.10
python -m sysspectogram lab-nmap 127.0.0.1 --lab

# 6) Offline CSV
python -m sysspectogram analyze --csv data/anomaly_cpu.csv \\
  --model artifacts/real_v3 --out reports/analyze.json

# 7) Audit snapshot
python -m sysspectogram audit report --out reports/audit.json
python -m sysspectogram audit rootkit

# 8) Sims
python -m sysspectogram simulate mem --duration 90 --mb 8192
python -m sysspectogram simulate net --duration 60 --rate 120
python -m sysspectogram simulate gpu --duration 60 --gpu-size 4096

# 9) systemd
# scripts/systemd/sysspectogram-guard.service
"""


def _btn(text: str, data: str) -> dict:
    return {"text": text, "callback_data": data[:64]}


def _markup(rows: list[list[dict]]) -> dict:
    return {"inline_keyboard": rows}


class TelegramBot:
    def __init__(
        self,
        client: TelegramClient,
        *,
        watcher: PerimeterWatcher | None = None,
        nft: NftBackend | None = None,
        tokens: TokenStore | None = None,
        host_id: str | None = None,
        dry_run: bool = False,
        recon_dir: Path | None = None,
        report_path: Path | None = None,
        model_dir: Path | None = None,
        project_root: Path | None = None,
        allow_destructive_sims: bool = False,
        lab_nmap_targets: list[str] | None = None,
        include_nmap: bool = False,
        webapp_url: str | None = None,
        require_console_unlock: bool = True,
        unlock_ttl_sec: float = 7200.0,
        unlock: ConsoleUnlock | None = None,
    ) -> None:
        self.client = client
        self.watcher = watcher
        self.nft = nft or NftBackend()
        self.tokens = tokens or TokenStore()
        self.host_id = host_id or (watcher.host_id if watcher else socket.gethostname())
        self.dry_run = dry_run
        self.recon_dir = recon_dir or Path("reports/recon")
        self.report_path = report_path
        self.model_dir = model_dir
        self.project_root = project_root or Path.cwd()
        self.allow_destructive_sims = allow_destructive_sims
        self.lab_nmap_targets = list(lab_nmap_targets or ["127.0.0.1", "::1"])
        self.include_nmap = include_nmap
        self.webapp_url = (webapp_url or "").rstrip("/") or None
        self.unlock = unlock or ConsoleUnlock(
            enabled=require_console_unlock,
            ttl_sec=float(unlock_ttl_sec),
        )
        self.require_console_unlock = self.unlock.enabled
        self.unlock_ttl_sec = self.unlock.ttl_sec
        self._offset: int | None = None
        self._started = time.time()
        self._alert_count_day = 0
        self._digest_counts: dict[str, int] = {}
        self._busy = False

    def begin_console_unlock(self) -> str:
        return self.unlock.begin()

    def session_unlocked(self) -> bool:
        return self.unlock.unlocked()

    def try_unlock(self, code: str) -> bool:
        return self.unlock.try_unlock(code)

    def lock_session(self) -> str:
        return self.unlock.lock()

    @property
    def _unlock_code(self) -> str | None:
        return self.unlock.pending_code

    @property
    def _unlock_fails(self) -> list[float]:
        return list(self.unlock._fails)

    @property
    def _on_unlock_code(self) -> Any:
        return self.unlock.on_code

    @_on_unlock_code.setter
    def _on_unlock_code(self, cb: Any) -> None:
        self.unlock.on_code = cb

    def prefix(self, text: str) -> str:
        return f"[{self.host_id}]\n{text}"

    def allowed_chat(self, chat_id: Any) -> bool:
        return str(chat_id) == str(self.client.chat_id)

    def alert_keyboard(self, alert: Alert) -> dict:
        ip = alert.ip or ""
        port = alert.port
        rows: list[list[dict]] = []
        if ip:
            t1h = self.tokens.issue("ban", {"ip": ip, "ttl": 3600})
            t24 = self.tokens.issue("ban", {"ip": ip, "ttl": 86400})
            tperm = self.tokens.issue("ban", {"ip": ip, "ttl": None})
            rows.append(
                [
                    _btn("Ban 1h", f"ask|{t1h}"),
                    _btn("Ban 24h", f"ask|{t24}"),
                    _btn("Ban perm", f"ask|{tperm}"),
                ]
            )
            tallow = self.tokens.issue("allow", {"ip": ip})
            tmute = self.tokens.issue("mute", {"ip": ip, "ttl": 3600})
            trecon = self.tokens.issue("recon", {"ip": ip})
            rows.append(
                [
                    _btn("Allowlist", f"ask|{tallow}"),
                    _btn("Mute 1h", f"ask|{tmute}"),
                    _btn("Refresh recon", f"do|{trecon}"),
                ]
            )
        if port:
            tsh = self.tokens.issue("shield", {"port": port, "ttl": 3600})
            rows.append([_btn(f"Shield :{port}", f"ask|{tsh}")])
        pid = (alert.extras or {}).get("pid")
        if pid:
            expect = read_proc_comm(int(pid))
            payload = {"pid": int(pid)}
            if expect:
                payload["expect_comm"] = expect
            tkill = self.tokens.issue("kill", payload)
            rows.append([_btn(f"Kill PID {pid}", f"ask|{tkill}")])
        tign = self.tokens.issue("ignore", {"ip": ip})
        tlock = self.tokens.issue("lockdown", {})
        trep = self.tokens.issue("report", {})
        rows.append(
            [
                _btn("Ignore", f"do|{tign}"),
                _btn("Send report", f"do|{trep}"),
                _btn("Lockdown", f"ask2|{tlock}"),
            ]
        )
        return _markup(rows)

    def send_perimeter_alert(self, alert: Alert, recon=None) -> None:
        if not self.client.configured:
            return
        from sysspectogram.viz.panels import format_perimeter_alert, perimeter_pattern

        self._alert_count_day += 1
        self._digest_counts[alert.rule_id] = self._digest_counts.get(alert.rule_id, 0) + 1
        recon_txt = None
        if recon is not None:
            recon_txt = recon.summary_text()
            if recon_txt.startswith(f"[{self.host_id}]"):
                recon_txt = "\n".join(recon_txt.splitlines()[1:])
        text = format_perimeter_alert(
            host_id=self.host_id,
            severity=alert.severity,
            rule_id=alert.rule_id,
            message=alert.message,
            explain=explain_perimeter(alert),
            pattern=perimeter_pattern(alert.rule_id),
            recon_summary=recon_txt,
        )
        self.client.send_message(text, reply_markup=self.alert_keyboard(alert))

    def send_agent_alert(self, alert) -> None:
        """Agent / integrity sensor alert with Kill PID + Ignore."""
        if not self.client.configured:
            return
        self._alert_count_day += 1
        rid = getattr(alert, "rule_id", "agent")
        self._digest_counts[rid] = self._digest_counts.get(rid, 0) + 1
        sev = getattr(alert, "severity", "medium")
        msg = getattr(alert, "message", "")
        pid = getattr(alert, "pid", None)
        ppid = getattr(alert, "ppid", None)
        comm = getattr(alert, "comm", None)
        path = getattr(alert, "path", None)
        # Re-resolve live /proc identity before offering Kill
        live_comm = read_proc_comm(int(pid)) if pid and int(pid) > 1 else None
        lines = [
            self.prefix(f"AGENT [{sev}] {rid}"),
            str(msg),
        ]
        meta = []
        if comm:
            meta.append(f"comm={comm}")
        if live_comm and live_comm != comm:
            meta.append(f"live_comm={live_comm}")
        if pid:
            meta.append(f"pid={pid}")
        if ppid:
            meta.append(f"ppid={ppid}")
        if path:
            meta.append(f"path={path}")
        if meta:
            lines.append(" · ".join(meta))
        if self.dry_run:
            lines.append("(dry_run: Kill will not SIGKILL)")
        rows: list[list[dict]] = []
        if pid and int(pid) > 1 and live_comm is not None:
            tkill = self.tokens.issue("kill", {"pid": int(pid), "expect_comm": live_comm})
            label = f"Kill {live_comm}({pid})"
            rows.append([_btn(label[:40], f"ask|{tkill}")])
        elif pid and int(pid) > 1:
            lines.append("(pid gone — Kill unavailable)")
        tign = self.tokens.issue("ignore", {"pid": int(pid) if pid else 0, "rule": rid})
        rows.append([_btn("Ignore", f"do|{tign}")])
        self.client.send_message("\n".join(lines), reply_markup=_markup(rows))

    def send_host_alert(
        self,
        *,
        score: float,
        threshold: float,
        top_procs: list[dict],
        explain_kwargs: dict | None = None,
        png_bytes: bytes | None = None,
        caption_override: str | None = None,
        pattern: str | None = None,
    ) -> None:
        if not self.client.configured:
            return
        from sysspectogram.viz.panels import detect_host_pattern, format_host_alert_caption

        expl = explain_host_anomaly(top_procs=top_procs, **(explain_kwargs or {}))
        kw = {k: v for k, v in (explain_kwargs or {}).items() if k != "top_features"}
        pat = pattern or detect_host_pattern(top_procs=top_procs, **kw)
        if caption_override:
            text = caption_override
        else:
            text = format_host_alert_caption(
                host_id=self.host_id,
                score=score,
                threshold=threshold,
                pattern=pat,
                explain=expl,
                top_procs=top_procs,
                top_features=(explain_kwargs or {}).get("top_features"),
            )
        rows = []
        for p in top_procs[:3]:
            pid = int(p.get("pid") or 0)
            if pid > 1:
                expect = read_proc_comm(pid) or str(p.get("name") or "")
                payload: dict[str, Any] = {"pid": pid}
                if expect:
                    payload["expect_comm"] = expect
                tok = self.tokens.issue("kill", payload)
                rows.append([_btn(f"Kill {p.get('name')}({pid})", f"ask|{tok}")])
        rows.append([_btn("Ignore", f"do|{self.tokens.issue('ignore', {})}")])
        markup = _markup(rows) if rows else None
        if png_bytes:
            self.client.send_photo_bytes(png_bytes, caption=text[:900], reply_markup=markup)
        else:
            self.client.send_message(text, reply_markup=markup)

    def _confirm_markup(self, token: str, double: bool = False) -> dict:
        label = "YES LOCKDOWN" if double else "YES"
        return _markup([[_btn(label, f"yes|{token}"), _btn("NO", f"no|{token}")]])

    def _menu_markup(self) -> dict:
        rows = [
            [_btn("Status", "menu|status"), _btn("Audit", "menu|audit"), _btn("Panel", "menu|panel")],
            [_btn("Score", "menu|score"), _btn("Ports", "menu|ports"), _btn("Bans", "menu|bans")],
            [_btn("Digest", "menu|digest"), _btn("Recipes", "menu|recipes"), _btn("Help", "menu|help")],
        ]
        if self.webapp_url:
            rows.insert(
                0,
                [{"text": "Open Dashboard", "web_app": {"url": self.webapp_url}}],
            )
        return _markup(rows)

    def handle_command(self, text: str, chat_id: str) -> None:
        if not self.allowed_chat(chat_id):
            return
        parts = text.strip().split()
        if not parts:
            return
        cmd = parts[0].split("@")[0].lower()
        args = parts[1:]

        # Always allow unlock / lock / ping while pairing
        if cmd == "/unlock":
            if not args:
                self.client.send_message(
                    self.prefix("usage: /unlock <6-digit code from host console>"),
                    chat_id=chat_id,
                )
                return
            if self.try_unlock(args[0]):
                mins = int(self.unlock_ttl_sec // 60) if self.unlock_ttl_sec else 0
                self.client.send_message(
                    self.prefix(f"control plane UNLOCKED ({mins}m TTL). /lock to re-lock."),
                    chat_id=chat_id,
                )
            else:
                nfail = self.unlock.fail_count
                hint = "bad or expired unlock code"
                if nfail >= 8:
                    hint = "too many failed unlocks — wait / check console for a new code"
                elif nfail >= 5:
                    hint = "bad code — new code printed on host console"
                self.client.send_message(self.prefix(hint), chat_id=chat_id)
            return
        if cmd == "/lock":
            if self.require_console_unlock:
                code = self.lock_session()
                self.client.send_message(
                    self.prefix("control plane LOCKED. New code is on the host console."),
                    chat_id=chat_id,
                )
                # code only on console — reprint via attribute for guard logger
                _ = code
            else:
                self.client.send_message(self.prefix("console unlock disabled in config"), chat_id=chat_id)
            return
        if cmd == "/ping":
            state = "unlocked" if self.session_unlocked() else "LOCKED"
            self.client.send_message(self.prefix(f"pong ({state})"), chat_id=chat_id)
            return

        if not self.session_unlocked():
            self.client.send_message(
                self.prefix(
                    "control plane LOCKED. Read the 6-digit code on the host console, "
                    "then send /unlock <code> from this chat."
                ),
                chat_id=chat_id,
            )
            return

        try:
            if cmd in {"/help", "/start"}:
                self.client.send_message(self.prefix(HELP_TEXT), chat_id=chat_id, reply_markup=self._menu_markup())
            elif cmd == "/menu":
                self.client.send_message(self.prefix("quick menu"), chat_id=chat_id, reply_markup=self._menu_markup())
            elif cmd == "/version":
                from sysspectogram import __version__

                self.client.send_message(
                    self.prefix(f"sysspectogram {__version__}\nmodel={self.model_dir or 'none'}\ndry_run={self.dry_run}"),
                    chat_id=chat_id,
                )
            elif cmd == "/recipes":
                self.client.send_message(self.prefix(RECIPES_TEXT), chat_id=chat_id)
            elif cmd == "/status":
                self.client.send_message(self.prefix(self._status_text()), chat_id=chat_id)
            elif cmd == "/dashboard":
                if not self.webapp_url:
                    self.client.send_message(
                        self.prefix(
                            "WEBAPP_URL not set. Run a HTTPS tunnel to the local web UI "
                            "and put the URL in .env (see docs/WEBAPP.md)."
                        ),
                        chat_id=chat_id,
                    )
                else:
                    self.client.send_message(
                        self.prefix("Live dashboard (Mini App):"),
                        chat_id=chat_id,
                        reply_markup={
                            "inline_keyboard": [
                                [{"text": "Open Dashboard", "web_app": {"url": self.webapp_url}}]
                            ]
                        },
                    )
            elif cmd == "/audit":
                self._cmd_audit(chat_id)
            elif cmd == "/processes":
                self._cmd_processes(chat_id)
            elif cmd == "/ports":
                self._cmd_ports(chat_id)
            elif cmd == "/rootkit":
                self._cmd_rootkit(chat_id)
            elif cmd == "/panel":
                self._cmd_panel(chat_id)
            elif cmd == "/score":
                self._cmd_score(chat_id)
            elif cmd == "/last":
                n = int(args[0]) if args and args[0].isdigit() else 5
                self.client.send_message(self.prefix(self._last_text(n)), chat_id=chat_id)
            elif cmd == "/bans":
                self.client.send_message(
                    self.prefix(self._bans_text()),
                    chat_id=chat_id,
                    reply_markup=self._bans_markup(),
                )
            elif cmd == "/digest":
                self.client.send_message(self.prefix(self._digest_text()), chat_id=chat_id)
            elif cmd == "/quiet":
                on = (args[0].lower() == "on") if args else True
                if self.watcher:
                    self.watcher.state.quiet = on
                    self.watcher.persist()
                self.client.send_message(self.prefix(f"quiet={'on' if on else 'off'}"), chat_id=chat_id)
            elif cmd == "/lockdown":
                tok = self.tokens.issue("lockdown", {})
                self.client.send_message(
                    self.prefix("Confirm LOCKDOWN?"),
                    chat_id=chat_id,
                    reply_markup=self._confirm_markup(tok, double=True),
                )
            elif cmd == "/allow" and args:
                ip = args[0]
                tok = self.tokens.issue("allow", {"ip": ip})
                self.client.send_message(
                    self.prefix(f"Confirm allowlist {ip}?"),
                    chat_id=chat_id,
                    reply_markup=self._confirm_markup(tok),
                )
            elif cmd == "/mute" and args:
                ip = args[0]
                dur = float(args[1]) if len(args) > 1 else 3600.0
                tok = self.tokens.issue("mute", {"ip": ip, "ttl": dur})
                self.client.send_message(
                    self.prefix(f"Confirm mute {ip} for {dur}s?"),
                    chat_id=chat_id,
                    reply_markup=self._confirm_markup(tok),
                )
            elif cmd == "/ban" and args:
                ip = args[0]
                ttl: float | None = 3600.0
                if len(args) > 1:
                    if args[1] in {"perm", "permanent", "0"}:
                        ttl = None
                    else:
                        ttl = float(args[1])
                tok = self.tokens.issue("ban", {"ip": ip, "ttl": ttl})
                self.client.send_message(
                    self.prefix(f"Confirm ban {ip} ttl={ttl}?"),
                    chat_id=chat_id,
                    reply_markup=self._confirm_markup(tok),
                )
            elif cmd == "/unban" and args:
                tok = self.tokens.issue("unban", {"ip": args[0]})
                self.client.send_message(
                    self.prefix(f"Confirm unban {args[0]}?"),
                    chat_id=chat_id,
                    reply_markup=self._confirm_markup(tok),
                )
            elif cmd == "/kill" and args:
                pid = int(args[0])
                expect = read_proc_comm(pid)
                payload: dict[str, Any] = {"pid": pid}
                if expect:
                    payload["expect_comm"] = expect
                tok = self.tokens.issue("kill", payload)
                hint = f" ({expect})" if expect else ""
                self.client.send_message(
                    self.prefix(f"Confirm kill pid {args[0]}{hint}?"),
                    chat_id=chat_id,
                    reply_markup=self._confirm_markup(tok),
                )
            elif cmd == "/recon" and args:
                self.client.send_message(self.prefix(f"recon {args[0]}…"), chat_id=chat_id)
                report = run_full_recon(
                    args[0],
                    include_nmap=self.include_nmap,
                    lab_targets=self.lab_nmap_targets,
                    require_lab_for_nmap=True,
                )
                save_report(report, self.recon_dir / "recon.jsonl")
                self.client.send_message(self.prefix(report.summary_text(self.host_id)), chat_id=chat_id)
            elif cmd == "/labnmap" and args:
                self._cmd_labnmap(args[0], chat_id)
            elif cmd == "/report":
                self._send_report(chat_id)
            elif cmd == "/simulate" and args:
                if not self.allow_destructive_sims:
                    self.client.send_message(
                        self.prefix(
                            "simulate disabled (set telegram.allow_destructive_sims: true for lab)"
                        ),
                        chat_id=chat_id,
                    )
                else:
                    kind = args[0].lower()
                    dur = float(args[1]) if len(args) > 1 else 30.0
                    dur = min(max(dur, 5.0), 120.0)
                    tok = self.tokens.issue("simulate", {"kind": kind, "duration": dur})
                    self.client.send_message(
                        self.prefix(f"Confirm local simulate {kind} for {dur}s?"),
                        chat_id=chat_id,
                        reply_markup=self._confirm_markup(tok),
                    )
            elif cmd == "/collect":
                if not self.allow_destructive_sims:
                    self.client.send_message(
                        self.prefix(
                            "collect via TG disabled (set telegram.allow_destructive_sims: true for lab)"
                        ),
                        chat_id=chat_id,
                    )
                else:
                    dur = float(args[0]) if args else 60.0
                    dur = min(max(dur, 10.0), 180.0)
                    tok = self.tokens.issue("collect", {"duration": dur})
                    self.client.send_message(
                        self.prefix(f"Confirm collect metrics {dur}s → reports/tg_collect.csv?"),
                        chat_id=chat_id,
                        reply_markup=self._confirm_markup(tok),
                    )
            elif cmd == "/analyze" and args:
                self._cmd_analyze(args[0], chat_id)
            elif cmd in {"/train", "/build-dataset", "/build_dataset", "/monitor", "/guard", "/watch-perimeter"}:
                self.client.send_message(
                    self.prefix(
                        f"{cmd} is long-running — use host terminal.\n"
                        f"See /recipes for recommended flags."
                    ),
                    chat_id=chat_id,
                )
            else:
                self.client.send_message(self.prefix("unknown; /help or /menu"), chat_id=chat_id)
        except Exception as exc:
            self.client.send_message(self.prefix(f"error: {exc}"), chat_id=chat_id)

    def handle_callback(self, cq: dict) -> None:
        chat = (cq.get("message") or {}).get("chat") or {}
        chat_id = str(chat.get("id", ""))
        if not self.allowed_chat(chat_id):
            self.client.answer_callback(cq.get("id", ""), "unauthorized")
            return
        data = cq.get("data") or ""
        cq_id = cq.get("id", "")
        if not self.session_unlocked():
            if data.startswith("ask|") or data.startswith("ask2|") or data.startswith("yes|"):
                self.client.answer_callback(cq_id, "locked")
                self.client.send_message(
                    self.prefix("LOCKED — /unlock <console code> before actions"),
                    chat_id=chat_id,
                )
                return
            if data.startswith("do|"):
                tok = data.split("|", 1)[1]
                peeked = self.tokens.peek(tok)
                if peeked is None or peeked[0] != "ignore":
                    self.client.answer_callback(cq_id, "locked")
                    return
            if data.startswith("menu|"):
                self.client.answer_callback(cq_id, "locked")
                self.client.send_message(
                    self.prefix("LOCKED — /unlock <console code> first"),
                    chat_id=chat_id,
                )
                return
        if data.startswith("menu|"):
            key = data.split("|", 1)[1]
            self.client.answer_callback(cq_id, key)
            mapping = {
                "status": "/status",
                "audit": "/audit",
                "panel": "/panel",
                "score": "/score",
                "ports": "/ports",
                "bans": "/bans",
                "digest": "/digest",
                "recipes": "/recipes",
                "help": "/help",
            }
            if key in mapping:
                self.handle_command(mapping[key], chat_id)
            return
        if data.startswith("ask|") or data.startswith("ask2|"):
            double = data.startswith("ask2|")
            token = data.split("|", 1)[1]
            peeked = self.tokens.peek(token)
            if peeked is None:
                self.client.answer_callback(cq_id, "expired")
                return
            action, payload = peeked
            self.client.answer_callback(cq_id, "confirm?")
            self.client.send_message(
                self.prefix(f"Confirm {action} {json.dumps(payload)[:200]}?"),
                chat_id=chat_id,
                reply_markup=self._confirm_markup(token, double=double),
            )
            return
        if data.startswith("no|"):
            self.client.answer_callback(cq_id, "cancelled")
            self.client.send_message(self.prefix("cancelled"), chat_id=chat_id)
            return
        if data.startswith("yes|") or data.startswith("do|"):
            token = data.split("|", 1)[1]
            consumed = self.tokens.consume(token)
            if consumed is None:
                self.client.answer_callback(cq_id, "expired/used")
                return
            action, payload = consumed
            result = self._run_action(action, payload)
            self.client.answer_callback(cq_id, "ok")
            self.client.send_message(self.prefix(result), chat_id=chat_id)
            return
        if data.startswith("unban|"):
            token = data.split("|", 1)[1]
            peeked = self.tokens.peek(token)
            if peeked is None:
                self.client.answer_callback(cq_id, "expired")
                return
            self.client.answer_callback(cq_id, "confirm unban?")
            self.client.send_message(
                self.prefix("Confirm unban?"),
                chat_id=chat_id,
                reply_markup=self._confirm_markup(token),
            )
            return
        self.client.answer_callback(cq_id, "noop")

    def _run_action(self, action: str, payload: dict) -> str:
        if action == "ban":
            return self.nft.ban_ip(str(payload.get("ip")), ttl_sec=payload.get("ttl"), dry_run=self.dry_run)
        if action == "unban":
            return self.nft.unban_ip(str(payload.get("ip")), dry_run=self.dry_run)
        if action == "shield":
            return self.nft.shield_port(
                int(payload.get("port")), float(payload.get("ttl") or 3600), dry_run=self.dry_run
            )
        if action == "kill":
            pid = int(payload.get("pid") or 0)
            expect = payload.get("expect_comm")
            return kill_pid(pid, dry_run=self.dry_run, expect_comm=expect)
        if action == "allow":
            ip = str(payload.get("ip"))
            if self.watcher:
                self.watcher.engine.allowlist.add(ip)
                self.watcher.state.allow(ip)
                self.watcher.persist()
            return f"allowlisted {ip}"
        if action == "mute":
            ip = str(payload.get("ip"))
            ttl = float(payload.get("ttl") or 3600)
            if self.watcher:
                self.watcher.state.mute(ip, ttl)
                self.watcher.persist()
            return f"muted {ip} {ttl}s"
        if action == "recon":
            ip = str(payload.get("ip"))
            report = run_full_recon(
                ip,
                include_nmap=self.include_nmap,
                lab_targets=self.lab_nmap_targets,
                require_lab_for_nmap=True,
            )
            save_report(report, self.recon_dir / "recon.jsonl")
            return report.summary_text(self.host_id)
        if action == "ignore":
            return "ignored"
        if action == "report":
            self._send_report(self.client.chat_id)
            return "report sent"
        if action == "lockdown":
            if self.watcher:
                return self.watcher.apply_lockdown(dry_run=self.dry_run)
            return self.nft.apply_lockdown(dry_run=self.dry_run)
        if action == "simulate":
            if not self.allow_destructive_sims:
                return "simulate disabled (allow_destructive_sims=false)"
            return self._start_simulate(str(payload.get("kind")), float(payload.get("duration") or 30))
        if action == "collect":
            if not self.allow_destructive_sims:
                return "collect disabled (allow_destructive_sims=false)"
            return self._start_collect(float(payload.get("duration") or 60))
        return f"unknown action {action}"

    def _start_simulate(self, kind: str, duration: float) -> str:
        if self._busy:
            return "busy: another job running"
        kind = kind.lower()
        if kind not in {"cpu", "mem", "disk", "net", "gpu"}:
            return f"bad kind {kind}"
        duration = min(max(duration, 5.0), 120.0)

        def job() -> None:
            self._busy = True
            try:
                from sysspectogram.simulate.loads import (
                    burn_cpu,
                    burn_gpu,
                    flood_local_net,
                    pressure_memory,
                    thrash_disk,
                )

                if kind == "cpu":
                    burn_cpu(duration, workers=4)
                elif kind == "mem":
                    pressure_memory(duration, megabytes=2048)
                elif kind == "disk":
                    thrash_disk(duration, block_mb=16)
                elif kind == "net":
                    flood_local_net(duration, connections_per_sec=80)
                else:
                    burn_gpu(duration, size=2048)
                self.client.send_message(self.prefix(f"simulate {kind} done ({duration}s)"))
            except Exception as exc:
                self.client.send_message(self.prefix(f"simulate failed: {exc}"))
            finally:
                self._busy = False

        threading.Thread(target=job, daemon=True).start()
        return f"started simulate {kind} for {duration}s (local only)"

    def _start_collect(self, duration: float) -> str:
        if self._busy:
            return "busy: another job running"
        duration = min(max(duration, 10.0), 180.0)
        out = self.project_root / "reports" / "tg_collect.csv"

        def job() -> None:
            self._busy = True
            try:
                from sysspectogram.collect.daemon import CollectDaemon
                from sysspectogram.collect.metrics import MetricsCollector

                col = MetricsCollector()
                n = CollectDaemon(col, csv_path=out).run(duration_sec=duration)
                self.client.send_message(self.prefix(f"collect done: {n} rows → {out}"))
            except Exception as exc:
                self.client.send_message(self.prefix(f"collect failed: {exc}"))
            finally:
                self._busy = False

        threading.Thread(target=job, daemon=True).start()
        return f"started collect {duration}s → {out}"

    def _cmd_audit(self, chat_id: str) -> None:
        from sysspectogram.audit.ports import list_listening_and_established
        from sysspectogram.audit.processes import list_top_processes, suspicious_heuristics
        from sysspectogram.audit.rootkit import rootkit_heuristics
        from sysspectogram.viz.panels import format_audit_message

        ports = list_listening_and_established()
        text = format_audit_message(
            host_id=self.host_id,
            rootkit=rootkit_heuristics(),
            top_procs=list_top_processes(8),
            suspicious=suspicious_heuristics(),
            listen_count=ports.get("listen_count") if isinstance(ports, dict) else None,
        )
        self.client.send_message(text, chat_id=chat_id)

    def _cmd_processes(self, chat_id: str) -> None:
        from sysspectogram.audit.processes import list_top_processes

        tops = list_top_processes(12)
        lines = ["top processes:"]
        for p in tops:
            lines.append(
                f"• {p.get('name')} pid={p.get('pid')} "
                f"cpu={p.get('cpu_percent')}% mem={p.get('memory_percent')}%"
            )
        self.client.send_message(self.prefix("\n".join(lines)), chat_id=chat_id)

    def _cmd_ports(self, chat_id: str) -> None:
        from sysspectogram.audit.ports import list_listening_and_established

        ports = list_listening_and_established()
        listen = ports.get("listen") or ports.get("listening") or []
        est = ports.get("established") or []
        lines = [
            f"listen={ports.get('listen_count', len(listen))} "
            f"established={ports.get('established_count', len(est))}",
        ]
        for row in list(listen)[:20]:
            lines.append(f"L {row}")
        for row in list(est)[:15]:
            lines.append(f"E {row}")
        self.client.send_message(self.prefix("\n".join(lines)[:3800]), chat_id=chat_id)

    def _cmd_rootkit(self, chat_id: str) -> None:
        from sysspectogram.audit.rootkit import rootkit_heuristics

        findings = rootkit_heuristics()
        if not findings:
            self.client.send_message(self.prefix("rootkit heuristics: clean"), chat_id=chat_id)
            return
        lines = [f"rootkit findings: {len(findings)}"]
        for f in findings[:20]:
            lines.append(str(f))
        self.client.send_message(self.prefix("\n".join(lines)[:3800]), chat_id=chat_id)

    def _cmd_panel(self, chat_id: str) -> None:
        import numpy as np

        from sysspectogram.collect.metrics import MetricsCollector
        from sysspectogram.viz.panels import ProcessCpuTracker, render_alert_panel

        self.client.send_message(self.prefix("building panel (~8s)…"), chat_id=chat_id)
        col = MetricsCollector()
        rows = []
        track = ProcessCpuTracker(maxlen=30, top_k=8)
        track.warm()
        for _ in range(12):
            rows.append(col.sample())
            track.sample()
            time.sleep(0.4)
        columns = [c for c in col.columns if c != "timestamp"]
        mat = np.array([[float(r.get(c, 0.0)) for c in columns] for r in rows], dtype=np.float32)
        pm, labels = track.matrix()
        png = render_alert_panel(
            metric_window=mat,
            metric_columns=columns,
            proc_matrix=pm,
            proc_labels=labels,
            title=f"[{self.host_id}] live panel",
        )
        if png:
            self.client.send_photo_bytes(png, caption=self.prefix("live metrics + top PID heat")[:900])
        else:
            self.client.send_message(self.prefix("panel render failed"), chat_id=chat_id)

    def _cmd_score(self, chat_id: str) -> None:
        if not self.model_dir or not Path(self.model_dir).exists():
            self.client.send_message(self.prefix("no model; start guard with --model"), chat_id=chat_id)
            return
        self.client.send_message(self.prefix("scoring ~65s window…"), chat_id=chat_id)

        def job() -> None:
            try:
                from collections import deque

                import numpy as np

                from sysspectogram.collect.daemon import CollectDaemon
                from sysspectogram.collect.metrics import MetricsCollector
                from sysspectogram.ml.infer import EnsembleInferencer
                from sysspectogram.preprocess.window import rows_to_matrix
                from sysspectogram.viz.panels import ProcessCpuTracker, detect_host_pattern, render_alert_panel

                infer = EnsembleInferencer(Path(self.model_dir))
                columns = infer.columns
                buf: deque = deque(maxlen=infer.window_size)
                track = ProcessCpuTracker(maxlen=infer.window_size, top_k=8)
                track.warm()
                collector = MetricsCollector()
                daemon = CollectDaemon(collector, interval_sec=1.0)

                def on_sample(row: dict) -> None:
                    track.sample()
                    buf.append({c: float(row.get(c, 0.0)) for c in columns})

                daemon.run(duration_sec=float(infer.window_size + 2), on_sample=on_sample)
                if len(buf) < infer.window_size:
                    self.client.send_message(self.prefix("score failed: short buffer"))
                    return
                matrix = rows_to_matrix(list(buf), columns)
                pred = infer.predict_window(matrix)
                means = matrix.mean(axis=0)
                col_map = {c: float(means[i]) for i, c in enumerate(columns)}
                pat = detect_host_pattern(
                    cpu=col_map.get("cpu_percent"),
                    mem=col_map.get("mem_percent"),
                    gpu=col_map.get("gpu_util_percent"),
                )
                pm, labels = track.matrix()
                png = render_alert_panel(
                    metric_window=matrix,
                    metric_columns=columns,
                    proc_matrix=pm,
                    proc_labels=labels,
                    title=f"[{self.host_id}] score",
                    score=pred.score,
                )
                text = (
                    f"score={pred.score:.3f} thr={pred.threshold:.3f} "
                    f"anomaly={pred.is_anomaly}\n"
                    f"cnn={pred.cnn_prob:.3f} iforest={pred.iforest_score:.3f}\n"
                    f"pattern: {pat}"
                )
                if png:
                    self.client.send_photo_bytes(png, caption=self.prefix(text)[:900])
                else:
                    self.client.send_message(self.prefix(text))
            except Exception as exc:
                self.client.send_message(self.prefix(f"score failed: {exc}"))

        threading.Thread(target=job, daemon=True).start()

    def _cmd_analyze(self, csv_rel: str, chat_id: str) -> None:
        if not self.model_dir:
            self.client.send_message(self.prefix("no model on guard"), chat_id=chat_id)
            return
        path = Path(csv_rel)
        if not path.is_absolute():
            path = self.project_root / path
        if not path.exists():
            self.client.send_message(self.prefix(f"csv not found: {path}"), chat_id=chat_id)
            return
        self.client.send_message(self.prefix(f"analyze {path.name}…"), chat_id=chat_id)

        def job() -> None:
            try:
                from sysspectogram.runtime_analyze import run_analyze

                out = self.project_root / "reports" / "tg_analyze.json"
                run_analyze(csv_path=path, artifacts_dir=Path(self.model_dir), out_path=out)
                self.client.send_document(out, caption=self.prefix("analyze result"), chat_id=chat_id)
            except Exception as exc:
                self.client.send_message(self.prefix(f"analyze failed: {exc}"), chat_id=chat_id)

        threading.Thread(target=job, daemon=True).start()

    def _cmd_labnmap(self, target: str, chat_id: str) -> None:
        self.client.send_message(self.prefix(f"lab-nmap {target}…"), chat_id=chat_id)

        def job() -> None:
            try:
                from sysspectogram.lab_nmap import main as lab_main
                import io
                from contextlib import redirect_stdout

                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = lab_main([target, "--lab"])
                out = buf.getvalue()[-1500:] or f"exit={code}"
                self.client.send_message(self.prefix(f"lab-nmap exit={code}\n{out}"), chat_id=chat_id)
            except Exception as exc:
                self.client.send_message(self.prefix(f"lab-nmap failed: {exc}"), chat_id=chat_id)

        threading.Thread(target=job, daemon=True).start()

    def _status_text(self) -> str:
        uptime = int(time.time() - self._started)
        listens = sorted(listening_ports(snapshot_connections()))[:30]
        last = None
        if self.watcher and self.watcher.state.last_alerts:
            a = self.watcher.state.last_alerts[0]
            last = f"{a.rule_id} {a.ip} {a.message[:80]}"
        quiet = self.watcher.state.quiet if self.watcher else False
        lockdown = getattr(self.watcher.state, "lockdown", False) if self.watcher else False
        return (
            f"uptime_s={uptime} quiet={quiet} lockdown={lockdown} dry_run={self.dry_run} busy={self._busy}\n"
            f"model={self.model_dir or 'none'}\n"
            f"last_alert={last or 'none'}\n"
            f"listen_ports={listens}\n"
            f"allowlist={sorted(self.watcher.engine.allowlist)[:20] if self.watcher else []}"
        )

    def _last_text(self, n: int) -> str:
        if not self.watcher or not self.watcher.state.last_alerts:
            return "no alerts"
        lines = []
        for a in list(self.watcher.state.last_alerts)[:n]:
            lines.append(f"{a.severity} {a.rule_id} ip={a.ip} {a.message}")
        return "\n".join(lines)

    def _bans_text(self) -> str:
        bans = self.nft.list_bans()
        if not bans:
            return "no active bans tracked"
        return "\n".join(f"{b.ip} exp={b.expires}" for b in bans)

    def _bans_markup(self) -> dict | None:
        bans = self.nft.list_bans()
        if not bans:
            return None
        rows = []
        for b in bans[:10]:
            tok = self.tokens.issue("unban", {"ip": b.ip})
            rows.append([_btn(f"Unban {b.ip}", f"ask|{tok}")])
        return _markup(rows)

    def _digest_text(self) -> str:
        items = sorted(self._digest_counts.items(), key=lambda x: -x[1])
        if not items:
            return f"digest empty; alerts_today={self._alert_count_day}"
        lines = [f"alerts_today={self._alert_count_day}"]
        for rid, c in items[:15]:
            lines.append(f"{rid}: {c}")
        return "\n".join(lines)

    def _send_report(self, chat_id: str) -> None:
        path = self.report_path
        if path is None or not Path(path).exists():
            cand = self.recon_dir / "recon.jsonl"
            if cand.exists():
                path = cand
            else:
                self.client.send_message(self.prefix("no report file"), chat_id=chat_id)
                return
        self.client.send_document(Path(path), caption=self.prefix("report"), chat_id=chat_id)

    def poll_once(self, timeout: int = 2) -> None:
        if not self.client.configured:
            return
        updates = self.client.get_updates(offset=self._offset, timeout=timeout)
        for upd in updates:
            self._offset = int(upd["update_id"]) + 1
            if "message" in upd:
                msg = upd["message"]
                chat_id = str((msg.get("chat") or {}).get("id", ""))
                text = msg.get("text") or ""
                if text.startswith("/"):
                    try:
                        self.handle_command(text, chat_id)
                    except Exception as exc:
                        self.client.send_message(self.prefix(f"cmd error: {exc}"), chat_id=chat_id)
            if "callback_query" in upd:
                try:
                    self.handle_callback(upd["callback_query"])
                except Exception as exc:
                    self.client.answer_callback(
                        upd["callback_query"].get("id", ""), f"err:{exc}"[:180]
                    )
