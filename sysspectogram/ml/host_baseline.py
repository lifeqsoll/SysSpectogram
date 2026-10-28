"""Per-host MAD/z baseline (Phase 7.2 — **experimental** for v1.4.0).

Fits a simple robust-z model on a baseline window of host scalar samples,
then scores later points. No alerts until the baseline period ends.
Does **not** claim to beat offline CNN baselines — see docs/EVAL.md.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sysspectogram.config import state_root


@dataclass
class HostBaselineStatus:
    ready: bool
    remaining_sec: float
    n_samples: int
    median: float | None
    mad: float | None
    threshold: float | None


def _state_path() -> Path:
    return state_root() / "state" / "host_baseline.json"


def load_state() -> dict[str, Any]:
    path = _state_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(data: dict[str, Any]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _median(xs: list[float]) -> float:
    ys = sorted(xs)
    n = len(ys)
    mid = n // 2
    if n % 2:
        return ys[mid]
    return 0.5 * (ys[mid - 1] + ys[mid])


def _mad(xs: list[float], med: float) -> float:
    return _median([abs(x - med) for x in xs]) or 1e-9


class HostBaseline:
    """Collect → fit → score with MAD robust-z; threshold = quantile of |z| on baseline."""

    def __init__(
        self,
        *,
        baseline_sec: float = 3 * 24 * 3600,
        threshold_quantile: float = 0.999,
        now: float | None = None,
    ) -> None:
        self.baseline_sec = float(baseline_sec)
        self.threshold_quantile = float(threshold_quantile)
        self._now = float(now if now is not None else time.time())
        st = load_state()
        self.started = float(st.get("started", self._now))
        self.samples: list[float] = [float(x) for x in (st.get("samples") or []) if _is_num(x)]
        self.median = _maybe_float(st.get("median"))
        self.mad = _maybe_float(st.get("mad"))
        self.threshold = _maybe_float(st.get("threshold"))
        self.ready = bool(st.get("ready")) and self.median is not None and self.mad is not None

    def status(self) -> HostBaselineStatus:
        elapsed = max(0.0, self._now - self.started)
        rem = max(0.0, self.baseline_sec - elapsed)
        return HostBaselineStatus(
            ready=self.ready and rem <= 0,
            remaining_sec=rem if not self.ready else 0.0,
            n_samples=len(self.samples),
            median=self.median,
            mad=self.mad,
            threshold=self.threshold,
        )

    def observe(self, value: float, *, now: float | None = None) -> dict[str, Any]:
        """Ingest one scalar; during baseline only collect. After fit, return score dict."""
        ts = float(now if now is not None else self._now)
        self._now = ts
        v = float(value)
        st = self.status()
        if not st.ready:
            self.samples.append(v)
            if ts - self.started >= self.baseline_sec and len(self.samples) >= 8:
                self._fit()
            self._persist()
            return {"alert": False, "phase": "learning", "remaining_sec": self.status().remaining_sec}

        z = abs(v - float(self.median)) / float(self.mad)
        thr = float(self.threshold or 3.0)
        return {
            "alert": z >= thr,
            "phase": "scoring",
            "z": z,
            "threshold": thr,
            "value": v,
        }

    def _fit(self) -> None:
        xs = list(self.samples)
        med = _median(xs)
        mad = _mad(xs, med)
        zs = [abs(x - med) / mad for x in xs]
        zs.sort()
        q = min(1.0, max(0.5, self.threshold_quantile))
        idx = min(len(zs) - 1, max(0, int(math.floor(q * (len(zs) - 1)))))
        # Slightly above observed baseline quantile so stationary data stays quiet.
        thr = max(3.0, zs[idx] * 1.05)
        self.median = med
        self.mad = mad
        self.threshold = thr
        self.ready = True

    def _persist(self) -> None:
        save_state(
            {
                "started": self.started,
                "samples": self.samples[-50_000:],
                "median": self.median,
                "mad": self.mad,
                "threshold": self.threshold,
                "ready": self.ready,
                "baseline_sec": self.baseline_sec,
                "threshold_quantile": self.threshold_quantile,
                "experimental": True,
            }
        )


def _is_num(x: Any) -> bool:
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


def _maybe_float(x: Any) -> float | None:
    try:
        return float(x) if x is not None else None
    except (TypeError, ValueError):
        return None


def score_batch(values: Iterable[float], *, baseline_sec: float = 0.0) -> list[dict[str, Any]]:
    """Helper for tests: feed values with instant baseline (baseline_sec=0 after warm-up)."""
    hb = HostBaseline(baseline_sec=max(0.0, baseline_sec), now=0.0)
    out: list[dict[str, Any]] = []
    for i, v in enumerate(values):
        out.append(hb.observe(float(v), now=float(i)))
    return out
