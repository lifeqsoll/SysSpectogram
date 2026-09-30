from __future__ import annotations

import json
from io import BufferedIOBase, BytesIO
from pathlib import Path

import numpy as np
from sklearn.preprocessing import RobustScaler

from sysspectogram.safe_artifacts import (
    is_joblib_path,
    scaler_from_json_payload,
    scaler_to_json_payload,
)


def _preprocess_features(flat: np.ndarray) -> np.ndarray:
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
        scaled = np.tanh(scaled / 3.0) * 0.5 + 0.5
        return scaled.reshape(window.shape).astype(np.float32)

    def fit_transform_list(self, windows: list[np.ndarray]) -> list[np.ndarray]:
        self.fit(windows)
        return [self.transform(w) for w in windows]

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".joblib" or is_joblib_path(path):
            raise RuntimeError(
                "joblib scaler writes removed; save as scaler.json "
                "(migrate: python -m sysspectogram artifacts migrate --model DIR)"
            )
        if path.suffix != ".json":
            path = path.parent / "scaler.json"
        payload = scaler_to_json_payload(self.scaler, self.n_features)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def load(
        cls,
        path: Path | BufferedIOBase,
        *,
        enforce: bool = False,
    ) -> "WindowScaler":
        del enforce  # kept for call-site compatibility
        if isinstance(path, (BufferedIOBase, BytesIO)) or (
            hasattr(path, "read") and not isinstance(path, (str, Path))
        ):
            raw = path.read()
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            try:
                text = raw.decode("utf-8")
                if text.lstrip().startswith("{"):
                    payload = json.loads(text)
                    obj = cls()
                    obj.scaler, obj.n_features = scaler_from_json_payload(payload)
                    return obj
            except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError, KeyError) as exc:
                raise RuntimeError(
                    "scaler stream is not JSON; migrate legacy joblib artifacts first"
                ) from exc
            raise RuntimeError("scaler stream is not JSON; migrate legacy joblib artifacts first")

        path = Path(path)
        if is_joblib_path(path):
            raise RuntimeError(
                f"legacy joblib refused at runtime ({path}); "
                "python -m sysspectogram artifacts migrate --model DIR"
            )
        if path.suffix == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            obj = cls()
            obj.scaler, obj.n_features = scaler_from_json_payload(payload)
            return obj
        raise RuntimeError(f"unsupported scaler artifact: {path}")
