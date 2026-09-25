"""Bridge: receive NDJSON agent alerts / metrics over a Unix datagram socket."""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class AgentAlert:
    rule_id: str
    severity: str
    message: str
    host_id: str = ""
    ts: float = field(default_factory=time.time)
    pid: int | None = None
    ppid: int | None = None
    comm: str | None = None
    path: str | None = None
    extras: dict = field(default_factory=dict)
    kind: str = "agent"
    ip: str | None = None
    port: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentAlert:
        return cls(
            rule_id=str(data.get("rule_id") or "agent_unknown"),
            severity=str(data.get("severity") or "medium"),
            message=str(data.get("message") or ""),
            host_id=str(data.get("host_id") or ""),
            ts=float(data.get("ts") or time.time()),
            pid=data.get("pid"),
            ppid=data.get("ppid"),
            comm=data.get("comm"),
            path=data.get("path"),
            extras={},  # never trust socket extras for scoring
            kind=str(data.get("kind") or "agent"),
        )


@dataclass
class MetricsSample:
    ts: float
    cpu_percent: float
    mem_percent: float
    net_packets_sent_per_s: float = 0.0
    net_packets_recv_per_s: float = 0.0
    host_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MetricsSample:
        return cls(
            ts=float(data.get("ts") or time.time()),
            cpu_percent=float(data.get("cpu_percent") or 0.0),
            mem_percent=float(data.get("mem_percent") or 0.0),
            net_packets_sent_per_s=float(data.get("net_packets_sent_per_s") or 0.0),
            net_packets_recv_per_s=float(data.get("net_packets_recv_per_s") or 0.0),
            host_id=str(data.get("host_id") or ""),
        )


def _peer_uid(sock: socket.socket) -> int | None:
    """SO_PEERCRED uid for the last datagram (Linux)."""
    try:
        # struct ucred { pid_t; uid_t; gid_t; } — typically 3 ints
        cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", cred)
        return int(uid)
    except OSError:
        return None


class AgentSocketListener:
    """Bind Unix datagram path; dispatch alerts and optional metrics."""

    def __init__(
        self,
        path: str | Path,
        on_alert: Callable[[AgentAlert], None] | None = None,
        *,
        on_metrics: Callable[[MetricsSample], None] | None = None,
        cooldown_sec: float = 60.0,
        require_same_uid: bool = True,  # prefer same-uid; FS mode 0600 is primary control
        max_alerts_per_min: int = 30,
        max_metrics_per_sec: float = 2.0,
    ) -> None:
        self.path = Path(path)
        self.on_alert = on_alert
        self.on_metrics = on_metrics
        self.cooldown_sec = cooldown_sec
        self.require_same_uid = require_same_uid
        self.max_alerts_per_min = max_alerts_per_min
        self.max_metrics_per_sec = max_metrics_per_sec
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._cooldown: dict[str, float] = {}
        self._alert_times: list[float] = []
        self._last_metrics = 0.0
        self._self_uid = os.getuid()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if self.path.exists():
            self.path.unlink(missing_ok=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(str(self.path))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        sock.settimeout(1.0)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="agent-sock", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass

    def _rate_ok_alert(self) -> bool:
        now = time.time()
        self._alert_times = [t for t in self._alert_times if now - t < 60.0]
        if len(self._alert_times) >= self.max_alerts_per_min:
            return False
        self._alert_times.append(now)
        return True

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, _ = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if self.require_same_uid:
                uid = _peer_uid(self._sock)
                # Unbound datagram peers often report uid=-1; treat as unknown → rely on 0600.
                if uid is not None and uid >= 0 and uid != self._self_uid:
                    continue
            for line in data.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                schema = str(obj.get("schema") or "")
                kind = str(obj.get("kind") or "agent")
                if kind == "metrics":
                    if schema != "sysspectogram.metrics.v1":
                        continue
                    now = time.time()
                    if now - self._last_metrics < (1.0 / max(self.max_metrics_per_sec, 0.1)):
                        continue
                    self._last_metrics = now
                    if self.on_metrics:
                        try:
                            self.on_metrics(MetricsSample.from_dict(obj))
                        except Exception:
                            pass
                    continue
                if schema != "sysspectogram.agent.v1":
                    continue
                if not self._rate_ok_alert():
                    continue
                alert = AgentAlert.from_dict(obj)
                # derive risky locally from comm, never from socket extras
                comm = (alert.comm or "").lower()
                risky = any(
                    comm == x or comm.startswith(x)
                    for x in ("bash", "sh", "zsh", "python", "perl", "ruby", "node", "curl", "wget", "nc", "ncat", "socat")
                )
                alert.extras = {"risky_comm": risky}
                key = f"{alert.rule_id}:{alert.pid}:{alert.path}"
                now = time.time()
                prev = self._cooldown.get(key, 0.0)
                if now - prev < self.cooldown_sec:
                    continue
                self._cooldown[key] = now
                if len(self._cooldown) > 5000:
                    # drop oldest half
                    items = sorted(self._cooldown.items(), key=lambda kv: kv[1])
                    self._cooldown = dict(items[len(items) // 2 :])
                if self.on_alert:
                    try:
                        self.on_alert(alert)
                    except Exception:
                        pass
