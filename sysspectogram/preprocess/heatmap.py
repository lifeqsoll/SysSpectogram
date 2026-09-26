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
    """Human-readable heatmap preview (model trains on .npy, not PNG)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    img = np.clip(np.asarray(window, dtype=np.float64), 0.0, 1.0)
    if img.ndim != 2:
        raise ValueError(f"expected 2D window, got {img.shape}")

    # Prefer matplotlib (nicer colormap); fall back to OpenCV grayscale upscale.
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import Normalize

        h, w = img.shape
        fig_w = max(4.0, w / 12.0)
        fig_h = max(2.5, h / 8.0)
        fig, ax = plt.subplots(figsize=(fig_w, fig_h), facecolor="#0f1419")
        ax.set_facecolor("#0f1419")
        im = ax.imshow(
            img.T,
            aspect="auto",
            origin="lower",
            interpolation="nearest",
            cmap="inferno",
            norm=Normalize(0, 1),
        )
        ax.set_xlabel("time (seconds in window)", color="#9aa7b2", fontsize=8)
        ax.set_ylabel("features", color="#9aa7b2", fontsize=8)
        ax.set_title(path.stem, color="#e6edf3", fontsize=9, loc="left")
        ax.tick_params(colors="#8b949e", labelsize=7)
        for spine in ax.spines.values():
            spine.set_color("#3a4550")
        cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
        cbar.ax.tick_params(colors="#8b949e", labelsize=6)
        fig.savefig(path, dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        return
    except Exception:
        pass

    try:
        import cv2
    except ImportError as exc:
        raise RuntimeError(
            "PNG export needs matplotlib or opencv-python-headless"
        ) from exc
    img_u8 = (img * 255.0).astype(np.uint8)
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
