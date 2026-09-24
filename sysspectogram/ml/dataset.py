from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from torch.utils.data import Dataset

from sysspectogram.preprocess.heatmap import tabular_features


class NpyWindowDataset(Dataset):
    def __init__(self, root: Path) -> None:
        self.items: list[tuple[Path, int]] = []
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
        arr = np.load(path).astype(np.float32)
        if arr.ndim == 2:
            arr = arr[np.newaxis, ...]
        tensor = torch.from_numpy(arr)
        tab = torch.from_numpy(tabular_features(arr[0]))
        return tensor, tab, label
