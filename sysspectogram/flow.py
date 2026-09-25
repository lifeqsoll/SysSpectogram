"""Lightweight flow/SYN heuristics from /proc/net/tcp (no XDP required)."""

from __future__ import annotations

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
            # little-endian IPv4
            ip = ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))
            port = int(rport_hex, 16)
        except ValueError:
            continue
        out.append((ip, port, state))
    return out


@dataclass
class FlowWatcher:
    """Track unique remote ports / SYN_RECV-ish activity over a window."""

    window_sec: float = 30.0
    syn_threshold: int = 80
    unique_port_threshold: int = 40
    _events: list[tuple[float, str, int, str]] = field(default_factory=list)

    def poll(self) -> list[dict[str, Any]]:
        now = time.time()
        for ip, port, state in _parse_tcp():
            self._events.append((now, ip, port, state))
        self._events = [e for e in self._events if now - e[0] <= self.window_sec]
        alerts: list[dict[str, Any]] = []
        # TCP_SYN_RECV = 03, SYN_SENT = 02 (approx scan/flood signal)
        synish = [e for e in self._events if e[3] in {"02", "03"}]
        if len(synish) >= self.syn_threshold:
            alerts.append(
                {
                    "rule_id": "flow_syn_burst",
                    "severity": "high",
                    "message": f"SYN-ish TCP states={len(synish)} in {self.window_sec:.0f}s",
                    "count": len(synish),
                }
            )
        ports = {(e[1], e[2]) for e in self._events}
        by_ip: dict[str, set[int]] = {}
        for _ts, ip, port, _st in self._events:
            by_ip.setdefault(ip, set()).add(port)
        for ip, ps in by_ip.items():
            if len(ps) >= self.unique_port_threshold:
                alerts.append(
                    {
                        "rule_id": "flow_port_scan",
                        "severity": "high",
                        "message": f"host {ip} touched {len(ps)} unique remote ports in window",
                        "ip": ip,
                        "count": len(ps),
                    }
                )
        _ = ports
        return alerts
