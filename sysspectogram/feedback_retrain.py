"""Rebuild host model from operator feedback samples (builder PC)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import numpy as np


def retrain_from_feedback(
    feedback_dir: Path,
    *,
    out_artifacts: Path,
    epochs: int = 8,
) -> dict[str, Any]:
    """Merge feedback npy windows into a tiny dataset and train (builder PC only)."""
    from sysspectogram.ml.train import train_models
    from sysspectogram.preprocess.scaler import WindowScaler

    feedback_dir = Path(feedback_dir)
    normal_src = list((feedback_dir / "normal").glob("*.npy")) if (feedback_dir / "normal").exists() else []
    anomaly_src = list((feedback_dir / "anomaly").glob("*.npy")) if (feedback_dir / "anomaly").exists() else []
    if len(normal_src) < 2 or len(anomaly_src) < 2:
        raise RuntimeError(
            f"need >=2 normal and >=2 anomaly .npy under {feedback_dir} "
            f"(got {len(normal_src)}/{len(anomaly_src)})"
        )

    windows_n = [np.load(p) for p in normal_src]
    windows_a = [np.load(p) for p in anomaly_src]
    scaler = WindowScaler().fit(windows_n + windows_a)
    scaled_n = [scaler.transform(w) for w in windows_n]
    scaled_a = [scaler.transform(w) for w in windows_a]

    ds = Path(out_artifacts).parent / "feedback_dataset"
    if ds.exists():
        shutil.rmtree(ds)

    def _dump(label: str, arrs: list[np.ndarray]) -> None:
        cut = max(1, int(len(arrs) * 0.8))
        for i, w in enumerate(arrs):
            split = "train" if i < cut else "val"
            dest = ds / split / label
            dest.mkdir(parents=True, exist_ok=True)
            np.save(dest / f"{label}_{i:04d}.npy", w)

    _dump("normal", scaled_n)
    _dump("anomaly", scaled_a)
    scaler.save(ds / "scaler.json")
    meta = {
        "window_size": int(scaled_n[0].shape[0]),
        "n_features": int(scaled_n[0].shape[1]),
        "source": "feedback_retrain",
        "counts": {"normal": len(scaled_n), "anomaly": len(scaled_a)},
    }
    (ds / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    out_artifacts = Path(out_artifacts)
    train_models(
        dataset_dir=ds,
        out_dir=out_artifacts,
        epochs=epochs,
        batch_size=16,
        lr=0.001,
        cnn_weight=0.55,
        iforest_weight=0.45,
        recall_target=0.85,
        seed=42,
    )
    return {
        "dataset": str(ds),
        "artifacts": str(out_artifacts),
        "n_normal": len(scaled_n),
        "n_anomaly": len(scaled_a),
    }
