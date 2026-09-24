from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np


@dataclass
class CalibrationState:
    score_mean: float = 0.0
    score_std: float = 1.0
    n: int = 0
    updated_at: float = field(default_factory=time.time)

    def update(self, scores: list[float]) -> None:
        if not scores:
            return
        arr = np.asarray(scores, dtype=np.float64)
        if self.n == 0:
            self.score_mean = float(arr.mean())
            self.score_std = float(arr.std() + 1e-6)
            self.n = len(arr)
        else:
            # running merge
            n2 = len(arr)
            mean2 = float(arr.mean())
            std2 = float(arr.std() + 1e-6)
            n = self.n + n2
            mean = (self.score_mean * self.n + mean2 * n2) / n
            self.score_mean = mean
            self.score_std = max(1e-6, 0.5 * (self.score_std + std2))
            self.n = n
        self.updated_at = time.time()

    def zscore(self, score: float) -> float:
        return (score - self.score_mean) / self.score_std

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "score_mean": self.score_mean,
                    "score_std": self.score_std,
                    "n": self.n,
                    "updated_at": self.updated_at,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: Path) -> CalibrationState:
        st = cls()
        if not path.exists():
            return st
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            st.score_mean = float(data.get("score_mean", 0.0))
            st.score_std = float(data.get("score_std", 1.0)) or 1.0
            st.n = int(data.get("n", 0))
            st.updated_at = float(data.get("updated_at", time.time()))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
        return st


def detect_drift(state: CalibrationState, recent_scores: list[float], z_thresh: float = 3.0) -> bool:
    if state.n < 20 or not recent_scores:
        return False
    mean = float(np.mean(recent_scores))
    return abs(state.zscore(mean)) >= z_thresh


def feature_attribution(window: np.ndarray, columns: list[str], top_k: int = 5) -> list[dict]:
    """Rank features by mean absolute deviation from column median (template-friendly)."""
    if window.ndim != 2 or not columns:
        return []
    means = window.mean(axis=0)
    med = np.median(window, axis=0)
    scores = np.abs(means - med)
    order = np.argsort(-scores)[:top_k]
    out = []
    for i in order:
        name = columns[i] if i < len(columns) else f"f{i}"
        out.append({"feature": name, "score": float(scores[i]), "mean": float(means[i])})
    return out


def suggested_threshold_hint(
    state: CalibrationState,
    recent_scores: list[float],
    current_threshold: float,
    z_thresh: float = 3.0,
) -> float | None:
    """If drift vs calibration baseline, hint a slightly higher decision threshold."""
    if not detect_drift(state, recent_scores, z_thresh=z_thresh):
        return None
    if not recent_scores:
        return None
    arr = np.asarray(recent_scores, dtype=np.float64)
    hint = float(np.clip(arr.mean() + arr.std(), current_threshold, 0.99))
    if hint <= current_threshold + 1e-3:
        return None
    return round(hint, 4)
