from __future__ import annotations

from io import BufferedIOBase, BytesIO
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from sysspectogram.safe_artifacts import (
    IFOREST_SSF_META,
    SsfIsolationScorer,
    is_joblib_path,
    load_ssf_scorer,
    save_ssf,
)


class ForestDetector:
    def __init__(self, contamination: float = 0.1, random_state: int = 42) -> None:
        self.model: IsolationForest | SsfIsolationScorer = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

    def fit(self, x: np.ndarray) -> "ForestDetector":
        if not isinstance(self.model, IsolationForest):
            self.model = IsolationForest(
                n_estimators=200,
                contamination=0.1,
                random_state=42,
                n_jobs=-1,
            )
        self.model.fit(x)
        return self

    def anomaly_score(self, x: np.ndarray) -> np.ndarray:
        raw = -self.model.decision_function(x)
        return 1.0 / (1.0 + np.exp(-raw))

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".joblib" or is_joblib_path(path):
            raise RuntimeError(
                "joblib iforest writes removed; save as iforest.ssf.npz "
                "(migrate: python -m sysspectogram artifacts migrate --model DIR)"
            )
        if not str(path).endswith(".ssf.npz"):
            path = path.parent / "iforest.ssf.npz"
        if not isinstance(self.model, IsolationForest):
            raise RuntimeError("SSF save requires a fitted sklearn IsolationForest")
        if path.name == "iforest.ssf.npz":
            meta = path.with_name(IFOREST_SSF_META)
        else:
            stem = path.name[: -len(".ssf.npz")]
            meta = path.with_name(stem + ".ssf.meta.json")
        save_ssf(self.model, path, meta)

    @classmethod
    def load(
        cls,
        path: Path | BufferedIOBase,
        *,
        enforce: bool = False,
    ) -> "ForestDetector":
        del enforce
        if isinstance(path, (BufferedIOBase, BytesIO)) or (
            hasattr(path, "read") and not isinstance(path, (str, Path))
        ):
            raise RuntimeError(
                "iforest must be loaded from filesystem .ssf.npz path "
                "(needs meta sidecar); use load_forest_for_artifacts"
            )

        path = Path(path)
        if is_joblib_path(path):
            raise RuntimeError(
                f"legacy joblib refused at runtime ({path}); "
                "python -m sysspectogram artifacts migrate --model DIR"
            )
        if path.name.endswith(".ssf.npz"):
            if path.name == "iforest.ssf.npz":
                meta = path.with_name(IFOREST_SSF_META)
            else:
                stem = path.name[: -len(".ssf.npz")]
                meta = path.with_name(stem + ".ssf.meta.json")
            obj = cls()
            obj.model = load_ssf_scorer(path, meta if meta.is_file() else None)
            return obj
        raise RuntimeError(f"unsupported iforest artifact: {path}")
