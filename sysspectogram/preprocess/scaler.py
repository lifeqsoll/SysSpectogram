from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.preprocessing import RobustScaler


def _preprocess_features(flat: np.ndarray) -> np.ndarray:
    # Stabilize heavy-tailed rate columns (bytes/s, switches/s, etc.)
    return np.log1p(np.clip(flat, a_min=0.0, a_max=None))


class WindowScaler:
    """RobustScaler on log1p features; fit on train windows only."""

    def __init__(self) -> None:
        self.scaler = RobustScaler()
        self.n_features: int | None = None

    def fit(self, windows: list[np.ndarray]) -> "WindowScaler":
        if not windows:
            raise ValueError("no windows to fit scaler")
        stacked = np.concatenate([w.reshape(-1, w.shape[1]) for w in windows], axis=0)
        self.n_features = stacked.shape[1]
        self.scaler.fit(_preprocess_features(stacked))
        return self

    def transform(self, window: np.ndarray) -> np.ndarray:
        if self.n_features is None:
            raise RuntimeError("scaler is not fitted")
        flat = window.reshape(-1, window.shape[1])
        scaled = self.scaler.transform(_preprocess_features(flat))
        # Squash to roughly [0,1]-ish for CNN stability without clipping all signal
        scaled = np.tanh(scaled / 3.0) * 0.5 + 0.5
        return scaled.reshape(window.shape).astype(np.float32)

    def fit_transform_list(self, windows: list[np.ndarray]) -> list[np.ndarray]:
        self.fit(windows)
        return [self.transform(w) for w in windows]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": self.scaler, "n_features": self.n_features}, path)

    @classmethod
    def load(cls, path: Path) -> "WindowScaler":
        payload = joblib.load(path)
        obj = cls()
        obj.scaler = payload["scaler"]
        obj.n_features = payload["n_features"]
        return obj
