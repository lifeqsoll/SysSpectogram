from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from sysspectogram.preprocess.heatmap import save_npy, save_png
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
    max_normal_mem_mean: float | None = None,
    min_anomaly_mem_mean: float | None = None,
    max_normal_pkt_mean: float | None = None,
    min_anomaly_pkt_mean: float | None = None,
) -> bool:
    """Lab filters — all thresholds default off (None)."""
    if all(
        v is None
        for v in (
            max_normal_cpu_mean,
            min_anomaly_cpu_mean,
            max_normal_cpu_std,
            min_anomaly_cpu_std_max,
            max_normal_mem_mean,
            min_anomaly_mem_mean,
            max_normal_pkt_mean,
            min_anomaly_pkt_mean,
        )
    ):
        return True

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

    if (
        min_anomaly_cpu_mean is None
        and min_anomaly_mem_mean is None
        and min_anomaly_pkt_mean is None
    ):
        return True
    cpu_hit = min_anomaly_cpu_mean is not None and cpu_mean >= min_anomaly_cpu_mean
    if cpu_hit and min_anomaly_cpu_std_max is not None and cpu_std > min_anomaly_cpu_std_max:
        cpu_hit = False
    mem_hit = min_anomaly_mem_mean is not None and mem_mean >= min_anomaly_mem_mean
    pkt_hit = min_anomaly_pkt_mean is not None and pkt_mean >= min_anomaly_pkt_mean
    return bool(cpu_hit or mem_hit or pkt_hit)


def _row_overlap(a: dict, b: dict) -> bool:
    return int(a["start"]) < int(b["end"]) and int(b["start"]) < int(a["end"])


def _assign_splits(
    samples: list[dict],
    *,
    window_size: int,
    val_ratio: float,
    test_ratio: float,
) -> dict[int, str]:
    """Time-ordered train/val/test with no shared rows; gap ≥ window_size starts."""
    by_series: dict[str, list[int]] = {}
    for i, s in enumerate(samples):
        by_series.setdefault(str(s["series_id"]), []).append(i)

    assign: dict[int, str] = {}
    for idxs in by_series.values():
        idxs = sorted(idxs, key=lambda i: int(samples[i]["start"]))
        n = len(idxs)
        if n == 0:
            continue
        n_test = int(n * test_ratio) if test_ratio > 0 else 0
        n_val = int(n * val_ratio) if val_ratio > 0 else 0
        if n >= 3 and test_ratio > 0 and n_test < 1:
            n_test = 1
        if n >= 3 and val_ratio > 0 and n_val < 1:
            n_val = 1
        while n_test + n_val >= n and (n_test + n_val) > 0:
            if n_test > 0:
                n_test -= 1
            elif n_val > 0:
                n_val -= 1
            else:
                break
        n_train = n - n_val - n_test
        train_idxs = list(idxs[:n_train])
        val_idxs = list(idxs[n_train : n_train + n_val])
        test_idxs = list(idxs[n_train + n_val :])

        def _purge(prev: list[int], nxt: list[int]) -> list[int]:
            if not prev or not nxt:
                return nxt
            # Require start gap ≥ window_size from last prev start (no shared rows).
            last_start = int(samples[prev[-1]]["start"])
            floor = last_start + window_size
            kept = [i for i in nxt if int(samples[i]["start"]) >= floor]
            # Also drop anything that still overlaps any prev window rows.
            cleaned: list[int] = []
            for i in kept:
                if any(_row_overlap(samples[i], samples[j]) for j in prev):
                    continue
                cleaned.append(i)
            return cleaned

        val_idxs = _purge(train_idxs, val_idxs)
        test_idxs = _purge(val_idxs if val_idxs else train_idxs, test_idxs)
        # Windows trimmed by the gap are discarded (not reassigned) to avoid leaks.
        for i in train_idxs:
            assign[i] = "train"
        for i in val_idxs:
            assign[i] = "val"
        for i in test_idxs:
            assign[i] = "test"
    return assign


def _balance_train_only(
    samples: list[dict],
    assign: dict[int, str],
    rng: np.random.Generator,
) -> dict[int, str]:
    """Undersample majority class inside train only; val/test untouched."""
    train_by: dict[str, list[int]] = {"normal": [], "anomaly": []}
    for i, split in assign.items():
        if split != "train":
            continue
        train_by[str(samples[i]["label"])].append(i)
    n_keep = min(len(train_by["normal"]), len(train_by["anomaly"]))
    if n_keep == 0:
        return assign
    drop: set[int] = set()
    for label, pool in train_by.items():
        if len(pool) <= n_keep:
            continue
        pick = set(int(x) for x in rng.choice(pool, size=n_keep, replace=False))
        for i in pool:
            if i not in pick:
                drop.add(i)
    out = {i: s for i, s in assign.items() if i not in drop}
    return out


def build_dataset(
    normal_csvs: list[Path],
    anomaly_csvs: list[Path],
    out_dir: Path,
    window_size: int = 60,
    stride: int = 5,
    write_png: bool = False,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
    max_normal_cpu_mean: float | None = None,
    min_anomaly_cpu_mean: float | None = None,
    max_normal_cpu_std: float | None = None,
    min_anomaly_cpu_std_max: float | None = None,
    max_normal_mem_mean: float | None = None,
    min_anomaly_mem_mean: float | None = None,
    max_normal_pkt_mean: float | None = None,
    min_anomaly_pkt_mean: float | None = None,
    balance: bool = False,
    lab_filters: bool = False,
) -> dict:
    """Cut CSV metrics into raw windows with a leak-free train/val/test split.

    Lab CPU/mem/pkt filters are **off** unless ``lab_filters=True`` (or explicit
    thresholds are passed). ``balance`` undersamples **train only** after split.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    if lab_filters:
        # Restore historical lab defaults when explicitly requested.
        if max_normal_cpu_mean is None:
            max_normal_cpu_mean = 25.0
        if min_anomaly_cpu_mean is None:
            min_anomaly_cpu_mean = 45.0
        if min_anomaly_cpu_std_max is None:
            min_anomaly_cpu_std_max = 15.0
        if max_normal_mem_mean is None:
            max_normal_mem_mean = 50.0
        if min_anomaly_mem_mean is None:
            min_anomaly_mem_mean = 55.0
        if max_normal_pkt_mean is None:
            max_normal_pkt_mean = 80.0
        if min_anomaly_pkt_mean is None:
            min_anomaly_pkt_mean = 100.0

    samples: list[dict] = []
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
            series_id = f"{label}:{csv_path.resolve()}"
            for start, window in iter_windows(matrix, window_size=window_size, stride=stride):
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
                samples.append(
                    {
                        "label": label,
                        "window": window,
                        "series_id": series_id,
                        "start": int(start),
                        "end": int(start) + int(window_size),
                    }
                )

    if not samples:
        raise RuntimeError(
            "no windows after quality filters; loosen filters / disable --lab-filters "
            "or collect cleaner logs"
        )
    assert columns is not None

    assign = _assign_splits(
        samples,
        window_size=window_size,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
    )
    if balance:
        assign = _balance_train_only(samples, assign, rng)

    train_normal = [
        samples[i]["window"]
        for i, sp in assign.items()
        if sp == "train" and samples[i]["label"] == "normal"
    ]
    if not train_normal:
        train_normal = [samples[i]["window"] for i, sp in assign.items() if sp == "train"]
    if not train_normal:
        raise RuntimeError("empty train after split")
    scaler = WindowScaler().fit(train_normal)

    counts = {
        "train": {"normal": 0, "anomaly": 0},
        "val": {"normal": 0, "anomaly": 0},
        "test": {"normal": 0, "anomaly": 0},
    }

    for i, sample in enumerate(samples):
        split = assign.get(i)
        if split is None:
            continue
        label = sample["label"]
        window = sample["window"]
        dest = out_dir / split / label
        dest.mkdir(parents=True, exist_ok=True)
        name = f"{label}_{i:06d}"
        save_npy(dest / f"{name}.npy", window.astype(np.float32))
        if write_png:
            save_png(dest / f"{name}.png", scaler.transform(window))
        # sidecar for leak audits
        (dest / f"{name}.meta.json").write_text(
            json.dumps(
                {
                    "series_id": sample["series_id"],
                    "start": sample["start"],
                    "end": sample["end"],
                    "split": split,
                    "label": label,
                }
            ),
            encoding="utf-8",
        )
        counts[split][label] += 1

    scaler_path = out_dir / "scaler.json"
    scaler.save(scaler_path)
    lab_on = bool(lab_filters) or any(
        v is not None
        for v in (
            max_normal_cpu_mean,
            min_anomaly_cpu_mean,
            max_normal_cpu_std,
            min_anomaly_cpu_std_max,
            max_normal_mem_mean,
            min_anomaly_mem_mean,
            max_normal_pkt_mean,
            min_anomaly_pkt_mean,
        )
    )
    meta = {
        "schema_version": 2,
        "windows_format": "raw",
        "columns": columns,
        "window_size": window_size,
        "stride": stride,
        "counts": counts,
        "dropped_windows": dropped,
        "split": {
            "val_ratio": val_ratio,
            "test_ratio": test_ratio,
            "gap_rows": window_size,
            "balance_train_only": bool(balance),
        },
        "filters": {
            "lab_filters": lab_on,
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
        "warnings": (
            ["lab_filters enabled — classes may be separable by construction"]
            if lab_on
            else []
        ),
        "n_features": len(columns),
        "scaler_path": str(scaler_path),
        "scaler_fit": "train_normal_only",
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta
