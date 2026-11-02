"""Shared feature helpers for IForest / baselines (train ↔ refit ↔ infer)."""

from __future__ import annotations

import numpy as np

from sysspectogram.preprocess.heatmap import tabular_features
from sysspectogram.preprocess.scaler import WindowScaler


def features_for_iforest(
    window: np.ndarray,
    scaler: WindowScaler | None = None,
) -> np.ndarray:
    """Tabular vector in the same space as live ``predict_window`` / forest.

    If ``scaler`` is set, scale the raw window once, then aggregate.
    """
    arr = np.asarray(window, dtype=np.float32)
    if arr.ndim == 3:
        arr = arr[0] if arr.shape[0] == 1 else arr.reshape(arr.shape[-2], arr.shape[-1])
    if arr.ndim != 2:
        raise ValueError(f"expected 2D window, got {arr.shape}")
    if scaler is not None:
        arr = scaler.transform(arr)
    return tabular_features(arr).astype(np.float32)


def core_invariant_cpu_stats(core_matrix: np.ndarray) -> dict[str, float]:
    """Permute-invariant stats over per-core CPU columns (T×C)."""
    if core_matrix.size == 0:
        return {"cpu_core_max": 0.0, "cpu_core_p90": 0.0, "cpu_core_std": 0.0, "cpu_cores_hot": 0.0}
    # mean over time per core, then across cores
    per_core = np.asarray(core_matrix, dtype=np.float64).mean(axis=0)
    hot = float(np.sum(per_core >= 90.0))
    return {
        "cpu_core_max": float(np.max(per_core)),
        "cpu_core_p90": float(np.percentile(per_core, 90)),
        "cpu_core_std": float(np.std(per_core)),
        "cpu_cores_hot": hot,
    }
