"""Flow / netview heuristics — /proc/net/tcp{,6} plus cheaper ss when available."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _parse_tcp4(path: Path = Path("/proc/net/tcp")) -> list[tuple[str, int, str]]:
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


def _parse_tcp6(path: Path = Path("/proc/net/tcp6")) -> list[tuple[str, int, str]]:
    """Parse /proc/net/tcp6 little-endian hextets into compressed IPv6."""
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
            if len(rip_hex) != 32:
                continue
            groups: list[str] = []
            for i in range(0, 32, 8):
                word = rip_hex[i : i + 8]
                # each 32-bit word is little-endian in /proc
                le = "".join(word[j : j + 2] for j in (6, 4, 2, 0))
                groups.append(le[0:4])
                groups.append(le[4:8])
            from ipaddress import IPv6Address

            ip = str(IPv6Address(int("".join(groups), 16)))
            port = int(rport_hex, 16)
        except ValueError:
            continue
        out.append((ip, port, state))
    return out


def _parse_tcp() -> list[tuple[str, int, str]]:
    return _parse_tcp4() + _parse_tcp6()


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
            if peer.startswith("["):
                host, _, port_s = peer[1:].partition("]:")
                port = int(port_s)
            elif peer.count(":") >= 1:
                host, _, port_s = peer.rpartition(":")
                port = int(port_s)
            else:
                continue
            if host in ("*", "0.0.0.0", "::"):
                continue
            out.append((host, port, state))
        except ValueError:
            continue
    return out


_SS_SYN_RECV = {"SYN-RECV", "SYN_RECV"}
_SS_SYN_SENT = {"SYN-SENT", "SYN_SENT"}


@dataclass
class FlowWatcher:
    """Track unique remote ports / SYN_RECV activity over a window.

    backend:
      - proc: /proc/net/tcp + tcp6
      - netview: prefer ss -tnH, fall back to /proc
      - both: merge both sources

    SYN_RECV counts unique (ip, port) once per window (not once per poll).
    SYN_SENT is a separate non-ban alert for outbound hangs.
    """

    window_sec: float = 30.0
    syn_threshold: int = 80
    unique_port_threshold: int = 40
    per_ip_syn_threshold: int = 40
    backend: str = "proc"
    # first-seen timestamp per (ip, port, kind) inside the window
    _seen: dict[tuple[str, int, str], float] = field(default_factory=dict)

    def _collect(self) -> list[tuple[str, int, str]]:
        backend = (self.backend or "proc").lower()
        if backend == "proc":
            return _parse_tcp()
        if backend == "netview":
            rows = _parse_ss()
            return rows if rows else _parse_tcp()
        seen: set[tuple[str, int, str]] = set()
        merged: list[tuple[str, int, str]] = []
        for src in (_parse_ss(), _parse_tcp()):
            for row in src:
                if row in seen:
                    continue
                seen.add(row)
                merged.append(row)
        return merged

    @staticmethod
    def _kind(state: str) -> str | None:
        st = str(state).upper()
        if st in {"03"} or st in _SS_SYN_RECV:
            return "recv"
        if st in {"02"} or st in _SS_SYN_SENT:
            return "sent"
        return None

    def poll(self) -> list[dict[str, Any]]:
        now = time.time()
        for ip, port, state in self._collect():
            kind = self._kind(state)
            if kind is None:
                continue
            key = (ip, port, kind)
            self._seen.setdefault(key, now)
        # drop entries outside the window
        self._seen = {k: ts for k, ts in self._seen.items() if now - ts <= self.window_sec}
        alerts: list[dict[str, Any]] = []
        recv_by_ip: dict[str, set[int]] = {}
        sent_by_ip: dict[str, set[int]] = {}
        for (ip, port, kind), _ts in self._seen.items():
            if kind == "recv":
                recv_by_ip.setdefault(ip, set()).add(port)
            else:
                sent_by_ip.setdefault(ip, set()).add(port)
        per_ip_thr = max(1, int(self.per_ip_syn_threshold))
        for ip, ports in recv_by_ip.items():
            n = len(ports)
            if n >= per_ip_thr:
                alerts.append(
                    {
                        "rule_id": "flow_syn_burst",
                        "severity": "high",
                        "message": (
                            f"SYN-RECV from {ip}: {n} unique peers in {self.window_sec:.0f}s "
                            f"(backend={self.backend}; host mitigation, not anti-DDoS)"
                        ),
                        "ip": ip,
                        "count": n,
                        "extras": {"backend": self.backend, "scope": "per_ip", "state": "syn_recv"},
                    }
                )
        total_recv = sum(len(p) for p in recv_by_ip.values())
        if total_recv >= self.syn_threshold:
            top_ip = ""
            top_n = 0
            if recv_by_ip:
                top_ip, ports = max(recv_by_ip.items(), key=lambda kv: len(kv[1]))
                top_n = len(ports)
            alerts.append(
                {
                    "rule_id": "flow_syn_burst",
                    "severity": "high",
                    "message": (
                        f"SYN-RECV unique={total_recv} in {self.window_sec:.0f}s "
                        f"(backend={self.backend}; top={top_ip or '-'} n={top_n})"
                    ),
                    "ip": top_ip or None,
                    "count": total_recv,
                    "extras": {
                        "backend": self.backend,
                        "scope": "window",
                        "top_ip": top_ip or None,
                        "top_n": top_n,
                        "state": "syn_recv",
                    },
                }
            )
        for ip, ports in sent_by_ip.items():
            n = len(ports)
            if n >= per_ip_thr:
                alerts.append(
                    {
                        "rule_id": "flow_syn_sent_hang",
                        "severity": "medium",
                        "message": (
                            f"outbound SYN-SENT to {ip}: {n} unique peers in "
                            f"{self.window_sec:.0f}s (not ban-capable)"
                        ),
                        "ip": None,
                        "count": n,
                        "extras": {
                            "backend": self.backend,
                            "peer": ip,
                            "state": "syn_sent",
                            "ban": False,
                        },
                    }
                )
        by_ip: dict[str, set[int]] = {}
        for (ip, port, _kind), _ts in self._seen.items():
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
            "events": len(self._seen),
            "window_sec": self.window_sec,
        }
