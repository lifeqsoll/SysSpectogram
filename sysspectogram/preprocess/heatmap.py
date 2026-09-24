from __future__ import annotations

from pathlib import Path

import numpy as np


def window_to_tensor(window: np.ndarray) -> np.ndarray:
    """Return shape (1, H, W) float32 tensor-ready array."""
    if window.ndim != 2:
        raise ValueError(f"expected 2D window, got {window.shape}")
    return window.astype(np.float32)[np.newaxis, ...]


def save_npy(path: Path, window: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    np.save(path, window_to_tensor(window))


def save_png(path: Path, window: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import cv2
    except ImportError as exc:
        raise RuntimeError("opencv is required for PNG export") from exc
    img = np.clip(window, 0.0, 1.0)
    img_u8 = (img * 255.0).astype(np.uint8)
    # Upscale for human viewing; model uses .npy
    h, w = img_u8.shape
    vis = cv2.resize(img_u8, (w * 8, h * 4), interpolation=cv2.INTER_NEAREST)
    cv2.imwrite(str(path), vis)


def tabular_features(window: np.ndarray) -> np.ndarray:
    """Aggregate stats over time axis for IsolationForest."""
    mean = window.mean(axis=0)
    std = window.std(axis=0)
    mx = window.max(axis=0)
    p95 = np.percentile(window, 95, axis=0)
    return np.concatenate([mean, std, mx, p95]).astype(np.float32)
