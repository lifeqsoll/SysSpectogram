"""ML package — torch is optional; do not import cnn/train at package import time."""

from __future__ import annotations

from typing import Any

from sysspectogram.ml.infer import EnsembleInferencer, Prediction, load_inferencer

__all__ = [
    "AnomalyCNN",
    "EnsembleInferencer",
    "Prediction",
    "load_inferencer",
    "train_models",
]


def __getattr__(name: str) -> Any:
    if name == "AnomalyCNN":
        from sysspectogram.ml.cnn import AnomalyCNN

        return AnomalyCNN
    if name == "train_models":
        from sysspectogram.ml.train import train_models

        return train_models
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
