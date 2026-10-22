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
    min_per_class: int = 8,
    base_dataset: Path | None = None,
) -> dict[str, Any]:
    """Merge feedback npy windows into a dataset and train (builder PC only).

    Feedback windows are treated as **raw** (same as live guard windows).
    Optional ``base_dataset`` (schema v2 raw) is copied first, then feedback
    samples are appended under train/val.
    """
    from sysspectogram.ml.train import train_models
    from sysspectogram.preprocess.scaler import WindowScaler

    feedback_dir = Path(feedback_dir)
    normal_src = list((feedback_dir / "normal").glob("*.npy")) if (feedback_dir / "normal").exists() else []
    anomaly_src = list((feedback_dir / "anomaly").glob("*.npy")) if (feedback_dir / "anomaly").exists() else []
    if len(normal_src) < min_per_class or len(anomaly_src) < min_per_class:
        raise RuntimeError(
            f"need >={min_per_class} normal and >={min_per_class} anomaly .npy under "
            f"{feedback_dir} (got {len(normal_src)}/{len(anomaly_src)})"
        )

    windows_n = [np.load(p).astype(np.float32) for p in normal_src]
    windows_a = [np.load(p).astype(np.float32) for p in anomaly_src]
    # Normalize shapes to (T, F)
    def _tf(w: np.ndarray) -> np.ndarray:
        if w.ndim == 3 and w.shape[0] == 1:
            return w[0]
        if w.ndim == 2:
            return w
        return w.reshape(w.shape[-2], w.shape[-1])

    windows_n = [_tf(w) for w in windows_n]
    windows_a = [_tf(w) for w in windows_a]

    ds = Path(out_artifacts).parent / "feedback_dataset"
    if ds.exists():
        shutil.rmtree(ds)

    columns: list[str] = []
    window_size = int(windows_n[0].shape[0])
    n_features = int(windows_n[0].shape[1])

    if base_dataset is not None:
        base_dataset = Path(base_dataset)
        base_meta_path = base_dataset / "meta.json"
        if not base_meta_path.exists():
            raise RuntimeError(f"base dataset missing meta.json: {base_dataset}")
        base_meta = json.loads(base_meta_path.read_text(encoding="utf-8"))
        if str(base_meta.get("windows_format") or "") != "raw":
            raise RuntimeError(
                "base_dataset must be schema v2 raw (rebuild with build-dataset); "
                f"got windows_format={base_meta.get('windows_format')!r}"
            )
        shutil.copytree(base_dataset, ds)
        columns = list(base_meta.get("columns") or [])
        window_size = int(base_meta.get("window_size") or window_size)
        n_features = int(base_meta.get("n_features") or n_features)
    else:
        ds.mkdir(parents=True, exist_ok=True)

    def _dump(label: str, arrs: list[np.ndarray], start: int = 0) -> int:
        cut = max(1, int(len(arrs) * 0.8))
        for i, w in enumerate(arrs):
            split = "train" if i < cut else "val"
            dest = ds / split / label
            dest.mkdir(parents=True, exist_ok=True)
            np.save(dest / f"feedback_{label}_{start + i:04d}.npy", w)
        return len(arrs)

    _dump("normal", windows_n)
    _dump("anomaly", windows_a)

    # Refit scaler on all train raw windows under ds.
    train_raw: list[np.ndarray] = []
    for label in ("normal", "anomaly"):
        folder = ds / "train" / label
        if not folder.exists():
            continue
        for p in sorted(folder.glob("*.npy")):
            train_raw.append(_tf(np.load(p).astype(np.float32)))
    if not train_raw:
        raise RuntimeError("no train windows after merge")
    scaler = WindowScaler().fit(train_raw)
    scaler.save(ds / "scaler.json")

    meta = {
        "schema_version": 2,
        "windows_format": "raw",
        "window_size": window_size,
        "n_features": n_features,
        "columns": columns,
        "source": "feedback_retrain",
        "base_dataset": str(base_dataset) if base_dataset else None,
        "counts": {
            "feedback_normal": len(windows_n),
            "feedback_anomaly": len(windows_a),
        },
        "scaler_path": str(ds / "scaler.json"),
    }
    (ds / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    out_artifacts = Path(out_artifacts)
    train_models(
        dataset_dir=ds,
        out_dir=out_artifacts,
        epochs=epochs,
        batch_size=16,
        lr=0.001,
        cnn_weight=0.6,
        iforest_weight=0.4,
        recall_target=0.85,
        seed=42,
    )
    return {
        "dataset": str(ds),
        "artifacts": str(out_artifacts),
        "n_normal": len(windows_n),
        "n_anomaly": len(windows_a),
        "min_per_class": min_per_class,
        "base_dataset": str(base_dataset) if base_dataset else None,
    }
