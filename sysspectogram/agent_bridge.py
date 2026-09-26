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

from sysspectogram.agent_auth import needs_hmac, verify as verify_hmac


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
    hmac_ok: bool | None = None

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
            extras={},
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


def _peer_cred(sock: socket.socket) -> tuple[int | None, int | None]:
    try:
        cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", cred)
        return int(pid), int(uid)
    except OSError:
        return None, None


class AgentSocketListener:
    def __init__(
        self,
        path: str | Path,
        on_alert: Callable[[AgentAlert], None] | None = None,
        *,
        on_metrics: Callable[[MetricsSample], None] | None = None,
        cooldown_sec: float = 60.0,
        require_same_uid: bool = True,
        max_alerts_per_min: int = 30,
        max_metrics_per_sec: float = 2.0,
        hmac_secret: str | None = None,
        require_hmac_critical: bool = True,
    ) -> None:
        self.path = Path(path)
        self.on_alert = on_alert
        self.on_metrics = on_metrics
        self.cooldown_sec = cooldown_sec
        self.require_same_uid = require_same_uid
        self.max_alerts_per_min = max_alerts_per_min
        self.max_metrics_per_sec = max_metrics_per_sec
        self.hmac_secret = hmac_secret
        self.require_hmac_critical = require_hmac_critical
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._cooldown: dict[str, float] = {}
        self._alert_times: list[float] = []
        self._last_metrics = 0.0
        self._self_uid = os.getuid()
        self.allowed_pids: set[int] | None = None
        self.allowed_exe_paths: set[str] = set()
        self.expected_exe_sha256: str | None = None
        self.on_exe_mismatch: Callable[[int, str], None] | None = None

    def set_allowed_pids(self, pids: set[int] | None) -> None:
        self.allowed_pids = pids

    def set_exe_seal(self, paths: set[str], sha256: str | None = None) -> None:
        self.allowed_exe_paths = {str(Path(p).resolve()) for p in paths if p}
        self.expected_exe_sha256 = sha256

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
            if self.require_same_uid or self.allowed_pids is not None:
                pid, uid = _peer_cred(self._sock)
                if self.require_same_uid:
                    if uid is None or uid < 0 or uid != self._self_uid:
                        continue
                if self.allowed_pids is not None:
                    if pid is None or pid <= 0 or pid not in self.allowed_pids:
                        continue
                if pid and (self.allowed_exe_paths or self.expected_exe_sha256):
                    from sysspectogram.trusted_pids import pid_matches_seal, resolve_exe

                    if not pid_matches_seal(
                        int(pid),
                        allowed_paths=self.allowed_exe_paths,
                        expected_sha256=self.expected_exe_sha256,
                    ):
                        exe = resolve_exe(int(pid))
                        if self.on_exe_mismatch:
                            try:
                                self.on_exe_mismatch(int(pid), str(exe or "?"))
                            except Exception:
                                pass
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
                rule = str(obj.get("rule_id") or "")
                hmac_ok: bool | None = None
                if self.hmac_secret:
                    hmac_ok = verify_hmac(self.hmac_secret, obj)
                    if needs_hmac(rule) and self.require_hmac_critical and not hmac_ok:
                        continue
                alert = AgentAlert.from_dict(obj)
                alert.hmac_ok = hmac_ok
                comm = (alert.comm or "").lower()
                risky = any(
                    comm == x or comm.startswith(x)
                    for x in (
                        "bash",
                        "sh",
                        "zsh",
                        "python",
                        "perl",
                        "ruby",
                        "node",
                        "curl",
                        "wget",
                        "nc",
                        "ncat",
                        "socat",
                    )
                )
                alert.extras = {"risky_comm": risky, "hmac_ok": hmac_ok}
                key = f"{alert.rule_id}:{alert.pid}:{alert.path}"
                now = time.time()
                prev = self._cooldown.get(key, 0.0)
                if now - prev < self.cooldown_sec:
                    continue
                self._cooldown[key] = now
                if len(self._cooldown) > 5000:
                    items = sorted(self._cooldown.items(), key=lambda kv: kv[1])
                    self._cooldown = dict(items[len(items) // 2 :])
                if self.on_alert:
                    try:
                        self.on_alert(alert)
                    except Exception:
                        pass
