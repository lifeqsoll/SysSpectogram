"""Operator-facing eval metrics: false alerts/day, time-to-detect (Phase 7.5)."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class Episode:
    start_idx: int
    end_idx: int
    label: str  # anomaly scenario name or "anomaly"


def false_alerts_per_day(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    *,
    window_stride_sec: float = 5.0,
    cooldown_sec: float = 60.0,
) -> float:
    """Count FP episodes on normal windows with cooldown, scale to per-day rate."""
    y_true = np.asarray(y_true, dtype=np.int32)
    y_pred = np.asarray(y_pred, dtype=np.int32)
    fp_idx = np.where((y_pred == 1) & (y_true == 0))[0]
    if fp_idx.size == 0:
        return 0.0
    cooldown_windows = max(1, int(np.ceil(cooldown_sec / max(window_stride_sec, 1e-6))))
    kept = 0
    last = -10**9
    for i in fp_idx.tolist():
        if i - last >= cooldown_windows:
            kept += 1
            last = i
    span_sec = max(len(y_true) * window_stride_sec, window_stride_sec)
    per_day = kept * (86400.0 / span_sec)
    return float(per_day)


def time_to_detect(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    *,
    window_stride_sec: float = 5.0,
    episodes: list[Episode] | None = None,
) -> dict[str, float | None]:
    """First true-positive latency from episode start (seconds)."""
    y_true = np.asarray(y_true, dtype=np.int32)
    y_pred = np.asarray(y_pred, dtype=np.int32)
    if episodes is None:
        # one blob of consecutive anomaly labels
        episodes = []
        i = 0
        n = len(y_true)
        while i < n:
            if y_true[i] != 1:
                i += 1
                continue
            j = i
            while j < n and y_true[j] == 1:
                j += 1
            episodes.append(Episode(i, j, "anomaly"))
            i = j
    out: dict[str, float | None] = {}
    for ep in episodes:
        hits = [
            k
            for k in range(ep.start_idx, min(ep.end_idx, len(y_pred)))
            if int(y_pred[k]) == 1
        ]
        key = ep.label
        if not hits:
            out[key] = None
        else:
            out[key] = float((hits[0] - ep.start_idx) * window_stride_sec)
    return out


def heavy_legit_flag_rate(
    y_pred: np.ndarray,
    legit_mask: np.ndarray,
) -> float:
    """Fraction of legitimate-heavy windows that were flagged."""
    legit_mask = np.asarray(legit_mask, dtype=bool)
    if not legit_mask.any():
        return 0.0
    return float(np.mean(y_pred[legit_mask] == 1))


def summarize_user_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    *,
    window_stride_sec: float = 5.0,
    cooldown_sec: float = 60.0,
    episodes: list[Episode] | None = None,
    legit_mask: np.ndarray | None = None,
) -> dict:
    ttd = time_to_detect(
        y_true, y_pred, window_stride_sec=window_stride_sec, episodes=episodes
    )
    row = {
        "false_alerts_per_day": round(
            false_alerts_per_day(
                y_true,
                y_pred,
                window_stride_sec=window_stride_sec,
                cooldown_sec=cooldown_sec,
            ),
            4,
        ),
        "time_to_detect_sec": ttd,
    }
    if legit_mask is not None:
        row["heavy_legit_flag_rate"] = round(
            heavy_legit_flag_rate(y_pred, legit_mask), 4
        )
    return row
