"""Train/infer window scaler contract (schema v2 raw .npy)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sysspectogram.preprocess.dataset_builder import build_dataset
from sysspectogram.preprocess.scaler import WindowScaler


def _tiny_csvs(tmp: Path) -> tuple[Path, Path]:
    rows_n = [
        {
            "timestamp": i,
            "cpu_percent": 8.0 + (i % 3),
            "mem_percent": 30.0,
            "net_packets_sent_per_s": 10.0,
        }
        for i in range(40)
    ]
    rows_a = [
        {
            "timestamp": i,
            "cpu_percent": 90.0,
            "mem_percent": 70.0,
            "net_packets_sent_per_s": 200.0,
        }
        for i in range(40)
    ]
    ncsv = tmp / "n.csv"
    acsv = tmp / "a.csv"
    pd.DataFrame(rows_n).to_csv(ncsv, index=False)
    pd.DataFrame(rows_a).to_csv(acsv, index=False)
    return ncsv, acsv


def test_build_dataset_stores_raw_windows(tmp_path: Path) -> None:
    ncsv, acsv = _tiny_csvs(tmp_path)
    out = tmp_path / "ds"
    meta = build_dataset(
        [ncsv],
        [acsv],
        out,
        window_size=10,
        stride=10,
        val_ratio=0.2,
        max_normal_cpu_mean=50,
        min_anomaly_cpu_mean=40,
        max_normal_mem_mean=90,
        min_anomaly_mem_mean=10,
        max_normal_pkt_mean=500,
        min_anomaly_pkt_mean=1,
        balance=True,
    )
    assert meta["windows_format"] == "raw"
    assert meta["schema_version"] == 2
    sample = next((out / "train" / "normal").glob("*.npy"))
    raw = np.load(sample)
    # save_npy may wrap as (1, T, F)
    assert raw.ndim in (2, 3)
    flat = raw[0] if raw.ndim == 3 else raw
    # Raw CPU percent stays in metric space, not tanh-squashed ~[0,1] only.
    assert float(flat[:, 0].max()) > 1.5


def test_dataset_scale_matches_scaler_transform(tmp_path: Path) -> None:
    torch = pytest.importorskip("torch")
    from sysspectogram.ml.dataset import NpyWindowDataset

    ncsv, acsv = _tiny_csvs(tmp_path)
    out = tmp_path / "ds"
    build_dataset(
        [ncsv],
        [acsv],
        out,
        window_size=10,
        stride=10,
        val_ratio=0.2,
        max_normal_cpu_mean=50,
        min_anomaly_cpu_mean=40,
        max_normal_mem_mean=90,
        min_anomaly_mem_mean=10,
        max_normal_pkt_mean=500,
        min_anomaly_pkt_mean=1,
        balance=True,
    )
    scaler = WindowScaler.load(out / "scaler.json")
    path = next((out / "train" / "normal").glob("*.npy"))
    raw = np.load(path).astype(np.float32)
    if raw.ndim == 3:
        raw = raw[0]
    expected = scaler.transform(raw)
    ds = NpyWindowDataset(out / "train", scaler=scaler, windows_format="raw")
    idx = next(i for i, (p, _) in enumerate(ds.items) if p == path)
    tensor, _tab, _ = ds[idx]
    got = tensor.numpy()[0]
    assert np.allclose(got, expected, atol=1e-5)
    del torch
