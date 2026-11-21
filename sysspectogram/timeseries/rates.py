"""Rolling per-minute rates for Control Center charts (alerts / perimeter)."""

from __future__ import annotations

import time
from collections import deque


class RateWindow:
    """Count events in a sliding window (default 60s) → events/min."""

    def __init__(self, window_sec: float = 60.0) -> None:
        self.window_sec = float(window_sec)
        self._ts: deque[float] = deque()

    def add(self, ts: float | None = None) -> None:
        now = time.time() if ts is None else float(ts)
        self._ts.append(now)
        self._prune(now)

    def _prune(self, now: float) -> None:
        cut = now - self.window_sec
        while self._ts and self._ts[0] < cut:
            self._ts.popleft()

    def per_min(self, now: float | None = None) -> float:
        now = time.time() if now is None else float(now)
        self._prune(now)
        if self.window_sec <= 0:
            return 0.0
        return len(self._ts) * (60.0 / self.window_sec)


class AlertRateMeter:
    """Severity-split alert rates for stacked charts."""

    def __init__(self, window_sec: float = 60.0) -> None:
        self.total = RateWindow(window_sec)
        self.by_sev = {
            "low": RateWindow(window_sec),
            "medium": RateWindow(window_sec),
            "high": RateWindow(window_sec),
            "critical": RateWindow(window_sec),
        }
        self.perimeter = RateWindow(window_sec)

    def note(self, *, severity: str = "medium", perimeter: bool = False, ts: float | None = None) -> None:
        now = time.time() if ts is None else float(ts)
        sev = (severity or "medium").lower()
        if sev not in self.by_sev:
            sev = "medium"
        self.total.add(now)
        self.by_sev[sev].add(now)
        if perimeter:
            self.perimeter.add(now)

    def snapshot(self, now: float | None = None) -> dict[str, float]:
        now = time.time() if now is None else float(now)
        return {
            "alerts_per_min": self.total.per_min(now),
            "alerts_low_per_min": self.by_sev["low"].per_min(now),
            "alerts_medium_per_min": self.by_sev["medium"].per_min(now),
            "alerts_high_per_min": self.by_sev["high"].per_min(now),
            "alerts_critical_per_min": self.by_sev["critical"].per_min(now),
            "perimeter_events_per_min": self.perimeter.per_min(now),
        }
