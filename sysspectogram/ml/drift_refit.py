"""Drift monitor + sliding refit of host MAD baseline (Phase 7.8).

Wire via ``DriftRefitController(baseline=existing_HostBaseline)`` so refit
updates the same state file the runtime already uses — never spawn a second
silent ``HostBaseline`` that overwrites ``state/host_baseline.json``.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from sysspectogram.ml.calibration import CalibrationState, detect_drift
from sysspectogram.ml.host_baseline import HostBaseline

RECENT_MAX = 200
QUIET_MAX = 5000
FLAG_WINDOW = 200


@dataclass
class DriftRefitController:
    """Tracks recent scores; on drift, refit the shared HostBaseline from quiet values."""

    baseline: HostBaseline | None = None
    calib: CalibrationState = field(default_factory=CalibrationState)
    recent: list[float] = field(default_factory=list)
    quiet_values: list[float] = field(default_factory=list)
    recent_flags: deque[bool] = field(default_factory=lambda: deque(maxlen=FLAG_WINDOW))
    last_refit_ts: float = 0.0
    refit_cooldown_sec: float = 3600.0
    max_flag_rate: float = 0.15

    def __post_init__(self) -> None:
        if self.baseline is None:
            # Opt-in experimental path: share the standard persisted host baseline.
            self.baseline = HostBaseline()
        # Ensure maxlen even if caller passed a plain list/deque.
        if not isinstance(self.recent_flags, deque) or self.recent_flags.maxlen != FLAG_WINDOW:
            self.recent_flags = deque(self.recent_flags, maxlen=FLAG_WINDOW)

    def observe(
        self,
        value: float,
        *,
        alerted: bool,
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = float(now if now is not None else time.time())
        v = float(value)
        self.recent.append(v)
        self.recent = self.recent[-RECENT_MAX:]
        self.recent_flags.append(bool(alerted))
        if not alerted:
            self.quiet_values.append(v)
            self.quiet_values = self.quiet_values[-QUIET_MAX:]

        drift = detect_drift(self.calib, self.recent[-40:])
        n_flags = len(self.recent_flags)
        flag_rate = (sum(1 for x in self.recent_flags if x) / n_flags) if n_flags else 0.0
        need = drift or flag_rate > self.max_flag_rate
        out: dict[str, Any] = {
            "drift": drift,
            "flag_rate": flag_rate,
            "refit": False,
            "message": None,
            "baseline": self.baseline,
        }
        if need and (ts - self.last_refit_ts) >= self.refit_cooldown_sec:
            if len(self.quiet_values) >= 8 and self.baseline is not None:
                # Operator-facing HOST ALERT must NOT use this string.
                out["message"] = "model stale, refitting on quiet windows"
                out["refit"] = True
                self.last_refit_ts = ts
                self.calib.update(list(self.quiet_values[-500:]))
                ok = self.baseline.fit_from_samples(
                    list(self.quiet_values[-200:]),
                    persist=True,
                    now=ts,
                )
                out["baseline_ready"] = bool(ok and self.baseline.ready)
        if not alerted and len(self.quiet_values) >= 20 and self.calib.n < 20:
            self.calib.update(self.quiet_values[-20:])
        return out
