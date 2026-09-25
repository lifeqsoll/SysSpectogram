from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LiveAlert:
    ts: float
    severity: str
    title: str
    body: str
    rule_id: str | None = None
    kind: str = "host"
    score: float | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LiveBus:
    """Thread-safe ring buffers for the live web dashboard."""

    def __init__(self, window: int = 60, max_alerts: int = 40) -> None:
        self.window = window
        self._lock = threading.Lock()
        self.host_id = "host"
        self.threshold = 0.5
        self.score = 0.0
        self.cnn = 0.0
        self.iforest = 0.0
        self.agent_score = 0.0
        self.risk = 0.0
        self.is_anomaly = False
        self.pattern = "idle"
        self.load_profile = "lite"
        self.cpu: deque[float] = deque(maxlen=window)
        self.mem: deque[float] = deque(maxlen=window)
        self.net: deque[float] = deque(maxlen=window)
        self.alerts: deque[LiveAlert] = deque(maxlen=max_alerts)
        self.started = time.time()
        self.model_loaded = False
        self.quiet = False
        self.lockdown = False
        self.processes: list[dict[str, Any]] = []

    def set_host(self, host_id: str, threshold: float, model_loaded: bool) -> None:
        with self._lock:
            self.host_id = host_id
            self.threshold = threshold
            self.model_loaded = model_loaded

    def set_processes(self, procs: list[dict[str, Any]]) -> None:
        with self._lock:
            self.processes = list(procs[:12])

    def push_sample(
        self,
        *,
        cpu: float,
        mem: float,
        net: float,
        score: float | None = None,
        cnn: float | None = None,
        iforest: float | None = None,
        agent_score: float | None = None,
        risk: float | None = None,
        is_anomaly: bool | None = None,
        pattern: str | None = None,
        processes: list[dict[str, Any]] | None = None,
        load_profile: str | None = None,
    ) -> None:
        with self._lock:
            self.cpu.append(float(cpu))
            self.mem.append(float(mem))
            self.net.append(float(net))
            if score is not None:
                self.score = float(score)
            if cnn is not None:
                self.cnn = float(cnn)
            if iforest is not None:
                self.iforest = float(iforest)
            if agent_score is not None:
                self.agent_score = float(agent_score)
            if risk is not None:
                self.risk = float(risk)
            if is_anomaly is not None:
                self.is_anomaly = bool(is_anomaly)
            if pattern is not None:
                self.pattern = pattern
            if processes is not None:
                self.processes = list(processes[:12])
            if load_profile is not None:
                self.load_profile = load_profile

    def push_alert(self, alert: LiveAlert) -> None:
        with self._lock:
            self.alerts.appendleft(alert)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "host_id": self.host_id,
                "threshold": self.threshold,
                "score": self.score,
                "cnn": self.cnn,
                "iforest": self.iforest,
                "agent_score": self.agent_score,
                "risk": self.risk,
                "is_anomaly": self.is_anomaly,
                "pattern": self.pattern,
                "model_loaded": self.model_loaded,
                "load_profile": self.load_profile,
                "quiet": self.quiet,
                "lockdown": self.lockdown,
                "uptime_s": int(time.time() - self.started),
                "cpu": list(self.cpu),
                "mem": list(self.mem),
                "net": list(self.net),
                "processes": list(self.processes),
                "alerts": [a.to_dict() for a in self.alerts],
                "ts": time.time(),
            }


# process-wide bus for guard ↔ web
GLOBAL_BUS = LiveBus()
