from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from torch.utils.data import Dataset

from sysspectogram.preprocess.heatmap import tabular_features
from sysspectogram.preprocess.scaler import WindowScaler


def _as_tf(arr: np.ndarray) -> np.ndarray:
    """Normalize loaded array to (T, F)."""
    a = np.asarray(arr, dtype=np.float32)
    if a.ndim == 2:
        return a
    if a.ndim == 3 and a.shape[0] == 1:
        return a[0]
    return a.reshape(a.shape[-2], a.shape[-1])


class NpyWindowDataset(Dataset):
    """Load window .npy files.

    ``windows_format``:
      - ``raw``: apply ``scaler.transform`` (schema v2 builder output)
      - ``scaled``: legacy pre-scaled datasets (no second transform)
    """

    def __init__(
        self,
        root: Path,
        *,
        scaler: WindowScaler | None = None,
        windows_format: str = "scaled",
    ) -> None:
        self.items: list[tuple[Path, int]] = []
        self.scaler = scaler
        self.windows_format = (windows_format or "scaled").strip().lower()
        if self.windows_format == "raw" and scaler is None:
            raise ValueError("windows_format=raw requires a fitted WindowScaler")
        for label_name, label in (("normal", 0), ("anomaly", 1)):
            folder = root / label_name
            if not folder.exists():
                continue
            for path in sorted(folder.glob("*.npy")):
                self.items.append((path, label))
        if not self.items:
            raise FileNotFoundError(f"no .npy samples under {root}")

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, idx: int):
        path, label = self.items[idx]
        window = _as_tf(np.load(path))
        if self.windows_format == "raw":
            assert self.scaler is not None
            window = self.scaler.transform(window)
        arr = window[np.newaxis, ...]
        tensor = torch.from_numpy(arr.astype(np.float32))
        tab = torch.from_numpy(tabular_features(window))
        return tensor, tab, label
