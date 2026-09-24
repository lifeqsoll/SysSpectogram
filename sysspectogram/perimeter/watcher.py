from __future__ import annotations

import json
import socket
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from sysspectogram.audit.report import append_jsonl
from sysspectogram.perimeter.auth import AuthWatcher
from sysspectogram.perimeter.connections import egress_external, inbound_external, snapshot_connections
from sysspectogram.perimeter.dns_watch import DnsWatcher
from sysspectogram.perimeter.proc_map import inode_to_process
from sysspectogram.perimeter.rules import Alert, Denylist, RuleEngine

console = Console()


@dataclass
class WatcherState:
    allowlist: set[str] = field(default_factory=set)
    muted: dict[str, float] = field(default_factory=dict)
    known_logins: set[str] = field(default_factory=set)
    quiet: bool = False
    last_alerts: deque = field(default_factory=lambda: deque(maxlen=50))
    started_at: float = field(default_factory=time.time)
    last_alert_ts: float | None = None
    lockdown: bool = False

    def is_muted(self, ip: str | None) -> bool:
        if not ip:
            return False
        exp = self.muted.get(ip)
        if exp is None:
            return False
        if exp > 0 and time.time() > exp:
            self.muted.pop(ip, None)
            return False
        return True

    def mute(self, ip: str, duration_sec: float | None = 3600.0) -> None:
        self.muted[ip] = 0.0 if duration_sec is None else time.time() + duration_sec

    def allow(self, ip: str) -> None:
        self.allowlist.add(ip)
        self.muted.pop(ip, None)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "allowlist": sorted(self.allowlist),
            "muted": self.muted,
            "known_logins": sorted(self.known_logins),
            "quiet": self.quiet,
            "lockdown": self.lockdown,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> WatcherState:
        st = cls()
        if not path.exists():
            return st
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            st.allowlist = set(data.get("allowlist") or [])
            st.muted = {k: float(v) for k, v in (data.get("muted") or {}).items()}
            st.known_logins = set(data.get("known_logins") or [])
            st.quiet = bool(data.get("quiet", False))
            st.lockdown = bool(data.get("lockdown", False))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
        return st


class PerimeterWatcher:
    def __init__(
        self,
        *,
        host_id: str | None = None,
        fail_threshold: int = 8,
        fail_window_sec: float = 60.0,
        scan_unique_ips: int = 8,
        scan_window_sec: float = 60.0,
        denylist_paths: list[Path] | None = None,
        suspicious_domains: set[str] | None = None,
        state_path: Path | None = None,
        jsonl_out: Path | None = None,
        recon_dir: Path | None = None,
        recon_cooldown_sec: float = 900.0,
        auto_recon: bool = False,
        include_nmap: bool = False,
        lab_nmap_targets: list[str] | None = None,
        passive_dns_url: str | None = None,
        poll_sec: float = 2.0,
        alert_new_egress: bool = False,
        on_alert: Callable[[Alert, Any], None] | None = None,
        on_auto_ban: Callable[[Alert], None] | None = None,
        nft: Any | None = None,
        auto_ban_rules: set[str] | None = None,
        auto_ban_ttl_sec: float | None = 3600.0,
    ) -> None:
        self.host_id = host_id or socket.gethostname()
        self.state_path = state_path or Path("state/perimeter.json")
        self.state = WatcherState.load(self.state_path)
        self.jsonl_out = jsonl_out
        self.recon_dir = recon_dir or Path("reports/recon")
        self.recon_cooldown_sec = recon_cooldown_sec
        self.auto_recon = auto_recon
        self.include_nmap = include_nmap
        self.lab_nmap_targets = list(lab_nmap_targets or ["127.0.0.1", "::1"])
        self.passive_dns_url = passive_dns_url
        self.poll_sec = poll_sec
        self.on_alert = on_alert
        self.on_auto_ban = on_auto_ban
        self.nft = nft
        self.auto_ban_rules = set(auto_ban_rules or set())
        self.auto_ban_ttl_sec = auto_ban_ttl_sec
        self.suspicious_domains = {d.lower() for d in (suspicious_domains or set())}
        self._recon_last: dict[str, float] = {}
        self._lockdown_seen: dict[str, float] = {}

        denylist = Denylist(denylist_paths or [])
        self.engine = RuleEngine(
            fail_threshold=fail_threshold,
            fail_window_sec=fail_window_sec,
            scan_unique_ips=scan_unique_ips,
            scan_window_sec=scan_window_sec,
            allowlist=set(self.state.allowlist),
            denylist=denylist,
            known_login_ips=set(self.state.known_logins),
            alert_new_egress=alert_new_egress,
        )
        self.auth = AuthWatcher()
        self.dns = DnsWatcher()
        self._stop = False
        self._bootstrapped_conns = False

    def stop(self) -> None:
        self._stop = True

    def persist(self) -> None:
        self.state.allowlist = set(self.engine.allowlist)
        self.state.known_logins = set(self.engine.known_login_ips)
        self.state.save(self.state_path)

    def _should_emit(self, alert: Alert) -> bool:
        if alert.ip and alert.ip in self.engine.allowlist:
            return False
        if self.state.is_muted(alert.ip):
            return False
        if self.state.quiet and alert.severity not in {"critical"}:
            return False
        return True

    def _maybe_recon(self, alert: Alert) -> Any:
        if not self.auto_recon or not alert.ip:
            return None
        now = time.time()
        last = self._recon_last.get(alert.ip, 0.0)
        if now - last < self.recon_cooldown_sec:
            return None
        self._recon_last[alert.ip] = now
        try:
            from sysspectogram.osint.recon import run_full_recon, save_report

            report = run_full_recon(
                alert.ip,
                include_nmap=self.include_nmap,
                include_ct=True,
                passive_dns_url=self.passive_dns_url,
                lab_targets=self.lab_nmap_targets,
                require_lab_for_nmap=True,
            )
            save_report(report, self.recon_dir / "recon.jsonl")
            return report
        except Exception as exc:
            console.print(f"[yellow]recon soft-fail[/] {exc}")
            return None

    def emit(self, alert: Alert) -> None:
        if not self._should_emit(alert):
            return
        recon = self._maybe_recon(alert)
        self.state.last_alerts.appendleft(alert)
        self.state.last_alert_ts = time.time()
        console.print(
            f"[red bold]PERIMETER[/] [{self.host_id}] {alert.severity} "
            f"{alert.rule_id}: {alert.message}"
        )
        if self.jsonl_out is not None:
            row = asdict(alert) if hasattr(alert, "__dataclass_fields__") else {
                "rule_id": alert.rule_id,
                "severity": alert.severity,
                "message": alert.message,
                "ip": alert.ip,
                "port": alert.port,
                "extras": alert.extras,
                "ts": alert.ts,
            }
            row["host_id"] = self.host_id
            if recon is not None:
                row["recon"] = recon.to_dict()
            append_jsonl(self.jsonl_out, row)
        if self.on_alert is not None:
            try:
                self.on_alert(alert, recon)
            except Exception as exc:
                console.print(f"[yellow]on_alert failed[/] {exc}")
        if (
            alert.ip
            and alert.rule_id in self.auto_ban_rules
            and self.on_auto_ban is not None
        ):
            try:
                self.on_auto_ban(alert)
            except Exception as exc:
                console.print(f"[yellow]auto_ban failed[/] {exc}")
        self.persist()

    def apply_lockdown(self, dry_run: bool = False) -> str:
        self.state.lockdown = True
        self.state.quiet = False
        self.persist()
        if self.nft is not None:
            try:
                return str(self.nft.apply_lockdown(dry_run=dry_run))
            except Exception as exc:
                return f"lockdown flag set; nft failed: {exc}"
        return "lockdown flag set (no nft backend)"

    def tick(self) -> list[Alert]:
        emitted: list[Alert] = []

        for ev in self.auth.poll():
            if ev.kind in {"failed", "invalid"}:
                a = self.engine.on_auth_fail(ev.ip, ev.user)
                if a:
                    self.emit(a)
                    emitted.append(a)
            elif ev.kind == "accepted":
                a = self.engine.on_auth_accepted(ev.ip, ev.user)
                if a:
                    self.emit(a)
                    emitted.append(a)

        rows = snapshot_connections()
        if not self._bootstrapped_conns:
            keys = [f"{r.remote_ip}:{r.remote_port}" for r in egress_external(rows)]
            self.engine.seed_egress(keys)
            self._bootstrapped_conns = True

        inbound_seen_tick: set[tuple[str, int]] = set()
        for r in inbound_external(rows):
            key = (r.remote_ip, r.local_port)
            if key in inbound_seen_tick:
                continue
            inbound_seen_tick.add(key)
            if self.state.lockdown and r.remote_ip not in self.engine.allowlist:
                now = time.time()
                last = self._lockdown_seen.get(r.remote_ip, 0.0)
                if now - last >= 60.0:
                    self._lockdown_seen[r.remote_ip] = now
                    a = Alert(
                        rule_id="lockdown_inbound",
                        severity="critical",
                        message=f"Lockdown: inbound from {r.remote_ip} to :{r.local_port}",
                        ip=r.remote_ip,
                        port=r.local_port,
                    )
                    self.emit(a)
                    emitted.append(a)
                    if self.nft is not None and r.remote_ip:
                        try:
                            self.nft.ban_ip(r.remote_ip, ttl_sec=self.auto_ban_ttl_sec)
                        except Exception as exc:
                            console.print(f"[yellow]lockdown ban[/] {exc}")
                continue
            a = self.engine.on_inbound(r.remote_ip, r.local_port)
            if a:
                self.emit(a)
                emitted.append(a)

        egress = egress_external(rows)
        inodes = {r.inode for r in egress}
        proc_map = inode_to_process(inodes)
        for r in egress:
            proc = proc_map.get(r.inode)
            a = self.engine.on_egress(r.remote_ip, r.remote_port, proc)
            if a:
                self.emit(a)
                emitted.append(a)

        for dns_ev in self.dns.poll():
            name = dns_ev.name.lower()
            hit = any(name == d or name.endswith("." + d) for d in self.suspicious_domains)
            if hit:
                a = self.engine.on_suspicious_dns(name)
                if a:
                    self.emit(a)
                    emitted.append(a)

        return emitted

    def run(self, duration_sec: float | None = None) -> None:
        console.print(
            f"[bold]watch-perimeter[/] host={self.host_id} poll={self.poll_sec}s "
            f"auto_recon={self.auto_recon}"
        )
        t0 = time.monotonic()
        while not self._stop:
            try:
                self.tick()
            except Exception as exc:
                console.print(f"[yellow]tick soft-fail[/] {exc}")
            if duration_sec is not None and time.monotonic() - t0 >= duration_sec:
                break
            time.sleep(self.poll_sec)
        self.persist()
