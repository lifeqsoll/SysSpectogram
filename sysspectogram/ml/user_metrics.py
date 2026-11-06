"""Operator-facing eval metrics: false alerts/day, time-to-detect (Phase 7.5)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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


def _auto_episodes(y_true: np.ndarray) -> list[Episode]:
    episodes: list[Episode] = []
    i = 0
    n = len(y_true)
    while i < n:
        if int(y_true[i]) != 1:
            i += 1
            continue
        j = i
        while j < n and int(y_true[j]) == 1:
            j += 1
        episodes.append(Episode(i, j, "anomaly"))
        i = j
    return episodes


def _unique_labels(episodes: list[Episode]) -> list[str]:
    used: set[str] = set()
    out: list[str] = []
    for ep in episodes:
        base = str(ep.label or "anomaly")
        if base not in used:
            used.add(base)
            out.append(base)
            continue
        k = 2
        while f"{base}#{k}" in used:
            k += 1
        lab = f"{base}#{k}"
        used.add(lab)
        out.append(lab)
    return out


def time_to_detect(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    *,
    window_stride_sec: float = 5.0,
    episodes: list[Episode] | None = None,
) -> dict[str, Any]:
    """First true-positive latency from each episode start (seconds).

    Returns a dict with:
    - ``episodes``: list of ``{label, start_idx, end_idx, time_to_detect_sec}``
      (labels uniquified as ``anomaly``, ``anomaly#2``, … when colliding)
    - ``time_to_detect_sec_mean``: mean over caught episodes only
    - ``missed_episodes``: count with ``time_to_detect_sec is None``
    - plus top-level unique label keys for single-episode callers
      (``result["miner"]`` still works when the label is unique)
    """
    y_true = np.asarray(y_true, dtype=np.int32)
    y_pred = np.asarray(y_pred, dtype=np.int32)
    eps = list(episodes) if episodes is not None else _auto_episodes(y_true)
    labels = _unique_labels(eps)
    rows: list[dict[str, Any]] = []
    for ep, lab in zip(eps, labels):
        hits = [
            k
            for k in range(ep.start_idx, min(ep.end_idx, len(y_pred)))
            if int(y_pred[k]) == 1
        ]
        ttd = None if not hits else float((hits[0] - ep.start_idx) * window_stride_sec)
        rows.append(
            {
                "label": lab,
                "start_idx": int(ep.start_idx),
                "end_idx": int(ep.end_idx),
                "time_to_detect_sec": ttd,
            }
        )
    caught = [r["time_to_detect_sec"] for r in rows if r["time_to_detect_sec"] is not None]
    out: dict[str, Any] = {
        "episodes": rows,
        "time_to_detect_sec_mean": (
            float(sum(caught) / len(caught)) if caught else None
        ),
        "missed_episodes": int(sum(1 for r in rows if r["time_to_detect_sec"] is None)),
    }
    for r in rows:
        # Unique labels only — collisions already renamed above.
        out[str(r["label"])] = r["time_to_detect_sec"]
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
    eps = list(ttd.get("episodes") or [])
    # Compat: single episode → scalar/None under time_to_detect_sec;
    # multiple → keep aggregates + list (see docs/EVAL.md).
    if len(eps) <= 1:
        ttd_field: Any = eps[0]["time_to_detect_sec"] if eps else None
    else:
        ttd_field = {
            "mean": ttd.get("time_to_detect_sec_mean"),
            "missed_episodes": ttd.get("missed_episodes"),
            "episodes": eps,
        }
    row: dict[str, Any] = {
        "false_alerts_per_day": round(
            false_alerts_per_day(
                y_true,
                y_pred,
                window_stride_sec=window_stride_sec,
                cooldown_sec=cooldown_sec,
            ),
            4,
        ),
        "time_to_detect_sec": ttd_field,
        "time_to_detect_episodes": eps,
        "time_to_detect_sec_mean": ttd.get("time_to_detect_sec_mean"),
        "missed_episodes": ttd.get("missed_episodes"),
    }
    if legit_mask is not None:
        row["heavy_legit_flag_rate"] = round(
            heavy_legit_flag_rate(y_pred, legit_mask), 4
        )
    return row
