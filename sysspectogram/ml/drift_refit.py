"""Drift monitor + sliding refit of host MAD baseline (Phase 7.8)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from sysspectogram.ml.calibration import CalibrationState, detect_drift
from sysspectogram.ml.host_baseline import HostBaseline


@dataclass
class DriftRefitController:
    """Tracks recent scores; on drift, refit HostBaseline from quiet windows only."""

    calib: CalibrationState = field(default_factory=CalibrationState)
    recent: list[float] = field(default_factory=list)
    quiet_values: list[float] = field(default_factory=list)
    flagged_idxs: set[int] = field(default_factory=set)
    last_refit_ts: float = 0.0
    refit_cooldown_sec: float = 3600.0
    max_flag_rate: float = 0.15
    window_values: list[float] = field(default_factory=list)

    def observe(
        self,
        value: float,
        *,
        alerted: bool,
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = float(now if now is not None else time.time())
        self.window_values.append(float(value))
        self.recent.append(float(value))
        self.recent = self.recent[-200:]
        idx = len(self.window_values) - 1
        if alerted:
            self.flagged_idxs.add(idx)
        else:
            self.quiet_values.append(float(value))
            self.quiet_values = self.quiet_values[-5000:]

        drift = detect_drift(self.calib, self.recent[-40:])
        n = max(1, len(self.recent[-100:]))
        # approximate flag rate from last 100 observes
        recent_flags = sum(1 for i in range(max(0, idx - 99), idx + 1) if i in self.flagged_idxs)
        flag_rate = recent_flags / min(100, idx + 1)
        need = drift or flag_rate > self.max_flag_rate
        out: dict[str, Any] = {
            "drift": drift,
            "flag_rate": flag_rate,
            "refit": False,
            "message": None,
        }
        if need and (ts - self.last_refit_ts) >= self.refit_cooldown_sec:
            if len(self.quiet_values) >= 8:
                out["message"] = "model stale, refitting on quiet windows"
                out["refit"] = True
                self.last_refit_ts = ts
                # Fit calibration on quiet scores
                self.calib.update(list(self.quiet_values[-500:]))
                # Rebuild host baseline quickly from quiet scalars
                hb = HostBaseline(baseline_sec=0.0, now=ts)
                for i, v in enumerate(self.quiet_values[-200:]):
                    hb.observe(v, now=ts + float(i) * 0.001)
                if not hb.ready and len(hb.samples) >= 8:
                    hb._fit()
                    hb._persist()
                out["baseline_ready"] = hb.ready
        # keep calib warm on quiet
        if not alerted and len(self.quiet_values) >= 20 and self.calib.n < 20:
            self.calib.update(self.quiet_values[-20:])
        return out
