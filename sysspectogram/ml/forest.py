from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class ForestDetector:
    def __init__(self, contamination: float = 0.1, random_state: int = 42) -> None:
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

    def fit(self, x: np.ndarray) -> "ForestDetector":
        self.model.fit(x)
        return self

    def anomaly_score(self, x: np.ndarray) -> np.ndarray:
        # decision_function: higher = more normal; map to [0,1] anomaly
        raw = -self.model.decision_function(x)
        # logistic-ish squash relative to batch; for single sample use sigmoid of centered score
        return 1.0 / (1.0 + np.exp(-raw))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path: Path) -> "ForestDetector":
        obj = cls()
        obj.model = joblib.load(path)
        return obj
