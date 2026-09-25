from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sysspectogram.perimeter.watcher import PerimeterWatcher
from sysspectogram.response.actions import NftBackend, kill_pid
from sysspectogram.web.bus import LiveAlert, LiveBus


@dataclass
class WebControllers:
    bus: LiveBus
    nft: NftBackend
    watcher: PerimeterWatcher | None = None
    dry_run: bool = True
    lab_nmap_targets: list[str] | None = None
    include_nmap: bool = False
    recon_dir: Any = None
    # When set, destructive actions require True (Telegram console unlock).
    unlock_ok: Any = None  # Callable[[], bool] | None

    def status(self) -> dict[str, Any]:
        bans = []
        try:
            for b in self.nft.list_bans():
                bans.append(
                    {
                        "ip": b.ip,
                        "expires": b.expires,
                        "backend": b.backend,
                        "handle": b.handle,
                    }
                )
        except Exception as exc:
            bans = [{"error": str(exc)}]
        quiet = bool(self.watcher.state.quiet) if self.watcher else self.bus.quiet
        lockdown = bool(self.watcher.state.lockdown) if self.watcher else self.bus.lockdown
        allow = sorted(self.watcher.engine.allowlist) if self.watcher else []
        unlocked = True
        if callable(self.unlock_ok):
            try:
                unlocked = bool(self.unlock_ok())
            except Exception:
                unlocked = False
        return {
            "dry_run": self.dry_run,
            "quiet": quiet,
            "lockdown": lockdown,
            "bans": bans,
            "allowlist": allow[:50],
            "control_unlocked": unlocked,
        }

    def run(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        action = (action or "").lower().strip()
        # Gate every control action (incl. recon) when Telegram console unlock is active.
        if action != "refresh_processes" and callable(self.unlock_ok):
            try:
                ok = bool(self.unlock_ok())
            except Exception:
                ok = False
            if not ok:
                return {
                    "ok": False,
                    "error": "control plane LOCKED — unlock via Telegram /unlock <console code>",
                    "status": self.status(),
                }
        try:
            result = self._run(action, payload or {})
            if action not in {"recon", "refresh_processes", "set_dry_run"}:
                self.bus.push_alert(
                    LiveAlert(
                        ts=__import__("time").time(),
                        severity="medium",
                        title=f"ACTION · {action}",
                        body=str(result)[:500],
                        kind="action",
                        rule_id=action,
                    )
                )
            return {"ok": True, "result": result, "status": self.status()}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "status": self.status()}

    def _run(self, action: str, payload: dict[str, Any]) -> str:
        if action == "ban":
            ip = str(payload.get("ip") or "")
            if not ip:
                raise ValueError("ip required")
            ttl = payload.get("ttl", 3600)
            if ttl in (None, ""):
                ttl_f = 3600.0
            elif ttl in ("perm", "permanent", 0, "0"):
                ttl_f = None
            else:
                ttl_f = float(ttl)
            return self.nft.ban_ip(ip, ttl_sec=ttl_f, dry_run=self.dry_run)
        if action == "unban":
            ip = str(payload.get("ip") or "")
            if not ip:
                raise ValueError("ip required")
            return self.nft.unban_ip(ip, dry_run=self.dry_run)
        if action == "shield":
            port = int(payload.get("port") or 0)
            ttl = float(payload.get("ttl") or 3600)
            return self.nft.shield_port(port, ttl_sec=ttl, dry_run=self.dry_run)
        if action == "kill":
            from sysspectogram.response.actions import read_proc_comm

            pid = int(payload.get("pid") or 0)
            live = read_proc_comm(pid)
            if live is None:
                return f"kill skipped: pid {pid} gone"
            expect = payload.get("expect_comm") or payload.get("comm") or live
            if expect != live:
                return f"kill skipped: pid {pid} is {live!r}, expected {expect!r}"
            return kill_pid(pid, dry_run=self.dry_run, expect_comm=live)
        if action == "allow":
            ip = str(payload.get("ip") or "")
            if not ip:
                raise ValueError("ip required")
            if not self.watcher:
                raise RuntimeError("perimeter watcher not attached")
            self.watcher.engine.allowlist.add(ip)
            self.watcher.state.allow(ip)
            self.watcher.persist()
            return f"allowlisted {ip}"
        if action == "mute":
            ip = str(payload.get("ip") or "")
            ttl = float(payload.get("ttl") or 3600)
            if not self.watcher:
                raise RuntimeError("perimeter watcher not attached")
            self.watcher.state.mute(ip, ttl)
            self.watcher.persist()
            return f"muted {ip} for {ttl}s"
        if action == "quiet":
            on = bool(payload.get("on", True))
            if self.watcher:
                self.watcher.state.quiet = on
                self.watcher.persist()
            self.bus.quiet = on
            return f"quiet={'on' if on else 'off'}"
        if action == "lockdown":
            if self.watcher:
                return self.watcher.apply_lockdown(dry_run=self.dry_run)
            msg = self.nft.apply_lockdown(dry_run=self.dry_run)
            self.bus.lockdown = True
            return msg
        if action == "set_dry_run":
            self.dry_run = bool(payload.get("dry_run", True))
            return f"dry_run={self.dry_run}"
        if action == "recon":
            ip = str(payload.get("ip") or "")
            if not ip:
                raise ValueError("ip required")
            from pathlib import Path

            from sysspectogram.osint.recon import run_full_recon, save_report

            report = run_full_recon(
                ip,
                include_nmap=bool(self.include_nmap),
                lab_targets=list(self.lab_nmap_targets or ["127.0.0.1", "::1"]),
                require_lab_for_nmap=True,
            )
            out = Path(self.recon_dir) if self.recon_dir else Path("reports/recon")
            save_report(report, out / "recon.jsonl")
            summary = report.summary_text(self.bus.host_id)
            self.bus.push_alert(
                LiveAlert(
                    ts=__import__("time").time(),
                    severity="medium",
                    title=f"RECON · {ip}",
                    body=summary[:1200],
                    kind="recon",
                    rule_id="recon",
                    extras={"ip": ip},
                )
            )
            return summary[:2000]
        if action == "refresh_processes":
            from sysspectogram.audit.processes import list_top_processes

            tops = list_top_processes(limit=10)
            self.bus.set_processes(tops)
            return f"refreshed {len(tops)} processes"
        raise ValueError(f"unknown action {action}")
