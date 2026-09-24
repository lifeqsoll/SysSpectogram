from __future__ import annotations

from typing import Iterator

import numpy as np
import pandas as pd

META_COLS = {"timestamp"}


def feature_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in META_COLS]


def dataframe_to_matrix(df: pd.DataFrame, columns: list[str] | None = None) -> np.ndarray:
    cols = columns or feature_columns(df)
    return df[cols].to_numpy(dtype=np.float32, copy=True)


def iter_windows(
    matrix: np.ndarray,
    window_size: int = 60,
    stride: int = 5,
) -> Iterator[tuple[int, np.ndarray]]:
    n = matrix.shape[0]
    if n < window_size:
        return
    for start in range(0, n - window_size + 1, stride):
        yield start, matrix[start : start + window_size]


def rows_to_matrix(rows: list[dict], columns: list[str]) -> np.ndarray:
    data = [[float(row.get(c, 0.0)) for c in columns] for row in rows]
    return np.asarray(data, dtype=np.float32)
