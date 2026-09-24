from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from sysspectogram.preprocess.heatmap import save_npy, save_png, tabular_features
from sysspectogram.preprocess.scaler import WindowScaler
from sysspectogram.preprocess.window import dataframe_to_matrix, feature_columns, iter_windows


def _load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "timestamp" not in df.columns:
        raise ValueError(f"{path} missing timestamp column")
    return df.fillna(0.0)


def _col_index(columns: list[str], name: str) -> int | None:
    try:
        return columns.index(name)
    except ValueError:
        return None


def _window_ok(
    window: np.ndarray,
    label: str,
    columns: list[str],
    max_normal_cpu_mean: float | None,
    min_anomaly_cpu_mean: float | None,
    max_normal_cpu_std: float | None,
    min_anomaly_cpu_std_max: float | None,
    max_normal_mem_mean: float | None = 45.0,
    min_anomaly_mem_mean: float | None = 55.0,
    max_normal_pkt_mean: float | None = 200.0,
    min_anomaly_pkt_mean: float | None = 80.0,
) -> bool:
    cpu_idx = _col_index(columns, "cpu_percent")
    mem_idx = _col_index(columns, "mem_percent")
    pkt_idx = _col_index(columns, "net_packets_sent_per_s")

    cpu_mean = float(window[:, cpu_idx].mean()) if cpu_idx is not None else 0.0
    cpu_std = float(window[:, cpu_idx].std()) if cpu_idx is not None else 0.0
    mem_mean = float(window[:, mem_idx].mean()) if mem_idx is not None else 0.0
    pkt_mean = float(window[:, pkt_idx].mean()) if pkt_idx is not None else 0.0

    if label == "normal":
        if max_normal_cpu_mean is not None and cpu_mean > max_normal_cpu_mean:
            return False
        if max_normal_cpu_std is not None and cpu_std > max_normal_cpu_std:
            return False
        if max_normal_mem_mean is not None and mem_mean > max_normal_mem_mean:
            return False
        if max_normal_pkt_mean is not None and pkt_mean > max_normal_pkt_mean:
            return False
        return True

    # anomaly: accept if any attack signature is strong enough
    cpu_hit = min_anomaly_cpu_mean is not None and cpu_mean >= min_anomaly_cpu_mean
    if cpu_hit and min_anomaly_cpu_std_max is not None and cpu_std > min_anomaly_cpu_std_max:
        cpu_hit = False
    mem_hit = min_anomaly_mem_mean is not None and mem_mean >= min_anomaly_mem_mean
    pkt_hit = min_anomaly_pkt_mean is not None and pkt_mean >= min_anomaly_pkt_mean
    return bool(cpu_hit or mem_hit or pkt_hit)


def build_dataset(
    normal_csvs: list[Path],
    anomaly_csvs: list[Path],
    out_dir: Path,
    window_size: int = 60,
    stride: int = 5,
    write_png: bool = False,
    val_ratio: float = 0.2,
    seed: int = 42,
    max_normal_cpu_mean: float | None = 25.0,
    min_anomaly_cpu_mean: float | None = 45.0,
    max_normal_cpu_std: float | None = None,
    min_anomaly_cpu_std_max: float | None = 15.0,
    max_normal_mem_mean: float | None = 50.0,
    min_anomaly_mem_mean: float | None = 55.0,
    max_normal_pkt_mean: float | None = 80.0,
    min_anomaly_pkt_mean: float | None = 100.0,
    balance: bool = True,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    samples: list[tuple[str, np.ndarray]] = []
    columns: list[str] | None = None
    dropped = {"normal": 0, "anomaly": 0}

    for label, paths in (("normal", normal_csvs), ("anomaly", anomaly_csvs)):
        for csv_path in paths:
            df = _load_csv(csv_path)
            cols = feature_columns(df)
            if columns is None:
                columns = cols
            elif cols != columns:
                missing = [c for c in columns if c not in df.columns]
                for c in missing:
                    df[c] = 0.0
                df = df[columns]
            matrix = dataframe_to_matrix(df, columns)
            for _, window in iter_windows(matrix, window_size=window_size, stride=stride):
                if not _window_ok(
                    window,
                    label,
                    columns,
                    max_normal_cpu_mean,
                    min_anomaly_cpu_mean,
                    max_normal_cpu_std,
                    min_anomaly_cpu_std_max,
                    max_normal_mem_mean,
                    min_anomaly_mem_mean,
                    max_normal_pkt_mean,
                    min_anomaly_pkt_mean,
                ):
                    dropped[label] += 1
                    continue
                samples.append((label, window))

    if not samples:
        raise RuntimeError(
            "no windows after quality filters; loosen max_normal_cpu_mean / "
            "min_anomaly_cpu_mean or collect cleaner logs"
        )
    assert columns is not None

    if balance:
        by_label: dict[str, list[tuple[str, np.ndarray]]] = {"normal": [], "anomaly": []}
        for item in samples:
            by_label[item[0]].append(item)
        n_keep = min(len(by_label["normal"]), len(by_label["anomaly"]))
        if n_keep == 0:
            raise RuntimeError("need both classes after filtering")
        samples = []
        for label in ("normal", "anomaly"):
            pool = by_label[label]
            pick = rng.choice(len(pool), size=n_keep, replace=False)
            samples.extend(pool[i] for i in pick)

    # Temporal hold-out: last val_ratio fraction per class (no random leakage across time).
    val_idx: set[int] = set()
    by_label_idx: dict[str, list[int]] = {"normal": [], "anomaly": []}
    for i, (label, _) in enumerate(samples):
        by_label_idx.setdefault(label, []).append(i)
    for label, idxs in by_label_idx.items():
        if len(idxs) <= 1:
            continue
        n_val_l = max(1, int(len(idxs) * val_ratio)) if val_ratio > 0 else 0
        val_idx.update(idxs[-n_val_l:])

    train_windows = [samples[i][1] for i in range(len(samples)) if i not in val_idx]
    scaler = WindowScaler().fit(train_windows)

    counts = {"train": {"normal": 0, "anomaly": 0}, "val": {"normal": 0, "anomaly": 0}}

    for i, (label, window) in enumerate(samples):
        split = "val" if i in val_idx else "train"
        scaled = scaler.transform(window)
        dest = out_dir / split / label
        dest.mkdir(parents=True, exist_ok=True)
        name = f"{label}_{i:06d}"
        save_npy(dest / f"{name}.npy", scaled)
        if write_png:
            save_png(dest / f"{name}.png", scaled)
        counts[split][label] += 1

    scaler_path = out_dir / "scaler.joblib"
    scaler.save(scaler_path)
    meta = {
        "columns": columns,
        "window_size": window_size,
        "stride": stride,
        "counts": counts,
        "dropped_windows": dropped,
        "filters": {
            "max_normal_cpu_mean": max_normal_cpu_mean,
            "min_anomaly_cpu_mean": min_anomaly_cpu_mean,
            "max_normal_cpu_std": max_normal_cpu_std,
            "min_anomaly_cpu_std_max": min_anomaly_cpu_std_max,
            "max_normal_mem_mean": max_normal_mem_mean,
            "min_anomaly_mem_mean": min_anomaly_mem_mean,
            "max_normal_pkt_mean": max_normal_pkt_mean,
            "min_anomaly_pkt_mean": min_anomaly_pkt_mean,
            "balance": balance,
        },
        "n_features": len(columns),
        "scaler_path": str(scaler_path),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta
