"""Flow / netview heuristics — /proc/net/tcp plus cheaper ss/conntrack when available."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _parse_tcp(path: Path = Path("/proc/net/tcp")) -> list[tuple[str, int, str]]:
    """Return list of (remote_ip, remote_port, state_hex)."""
    out: list[tuple[str, int, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        remote = parts[2]
        state = parts[3]
        try:
            rip_hex, rport_hex = remote.split(":")
            ip_int = int(rip_hex, 16)
            ip = ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))
            port = int(rport_hex, 16)
        except ValueError:
            continue
        out.append((ip, port, state))
    return out


def _parse_ss() -> list[tuple[str, int, str]]:
    """Parse `ss -tnH` → (remote_ip, remote_port, state_name). Empty if ss missing."""
    if not shutil.which("ss"):
        return []
    try:
        proc = subprocess.run(
            ["ss", "-tnH"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[tuple[str, int, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0].upper()
        peer = parts[4]
        try:
            if peer.count(":") >= 1:
                # IPv4 host:port or [ipv6]:port — keep IPv4 simple
                if peer.startswith("["):
                    continue
                host, _, port_s = peer.rpartition(":")
                port = int(port_s)
                if host in ("*", "0.0.0.0", "::"):
                    continue
                out.append((host, port, state))
        except ValueError:
            continue
    return out


# Map ss state names to /proc-like hex for shared logic
_SS_SYNISH = {"SYN-SENT", "SYN-RECV", "SYN_SENT", "SYN_RECV"}


@dataclass
class FlowWatcher:
    """Track unique remote ports / SYN activity over a window.

    backend:
      - proc: /proc/net/tcp only (lite default)
      - netview: prefer ss -tnH, fall back to /proc
      - both: merge both sources
    """

    window_sec: float = 30.0
    syn_threshold: int = 80
    unique_port_threshold: int = 40
    backend: str = "proc"
    _events: list[tuple[float, str, int, str]] = field(default_factory=list)

    def _collect(self) -> list[tuple[str, int, str]]:
        backend = (self.backend or "proc").lower()
        if backend == "proc":
            return _parse_tcp()
        if backend == "netview":
            rows = _parse_ss()
            return rows if rows else _parse_tcp()
        # both
        seen: set[tuple[str, int, str]] = set()
        merged: list[tuple[str, int, str]] = []
        for src in (_parse_ss(), _parse_tcp()):
            for row in src:
                # normalize state to hex-ish tag
                ip, port, st = row
                key = (ip, port, st)
                if key in seen:
                    continue
                seen.add(key)
                merged.append(row)
        return merged

    def poll(self) -> list[dict[str, Any]]:
        now = time.time()
        for ip, port, state in self._collect():
            self._events.append((now, ip, port, state))
        self._events = [e for e in self._events if now - e[0] <= self.window_sec]
        alerts: list[dict[str, Any]] = []
        # TCP_SYN_RECV = 03, SYN_SENT = 02 OR ss SYN-* names
        synish = [
            e
            for e in self._events
            if e[3] in {"02", "03"} or str(e[3]).upper() in _SS_SYNISH
        ]
        if len(synish) >= self.syn_threshold:
            alerts.append(
                {
                    "rule_id": "flow_syn_burst",
                    "severity": "high",
                    "message": (
                        f"SYN-ish TCP states={len(synish)} in {self.window_sec:.0f}s "
                        f"(backend={self.backend})"
                    ),
                    "count": len(synish),
                    "extras": {"backend": self.backend},
                }
            )
        by_ip: dict[str, set[int]] = {}
        for _ts, ip, port, _st in self._events:
            by_ip.setdefault(ip, set()).add(port)
        for ip, ps in by_ip.items():
            if len(ps) >= self.unique_port_threshold:
                alerts.append(
                    {
                        "rule_id": "flow_port_scan",
                        "severity": "high",
                        "message": (
                            f"host {ip} touched {len(ps)} unique remote ports in window "
                            f"(backend={self.backend})"
                        ),
                        "ip": ip,
                        "count": len(ps),
                        "extras": {"backend": self.backend},
                    }
                )
        return alerts

    def snapshot(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "events": len(self._events),
            "window_sec": self.window_sec,
        }
