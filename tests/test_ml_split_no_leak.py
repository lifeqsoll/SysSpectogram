"""Phase 7.1 — train/val/test row overlap must be empty; gap ≥ window."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from sysspectogram.preprocess.dataset_builder import build_dataset


def _long_csvs(tmp: Path) -> tuple[Path, Path]:
    # Long enough for train/val/test with gap
    rows_n = [
        {"timestamp": i, "cpu_percent": 10.0 + (i % 5), "mem_percent": 30.0, "net_packets_sent_per_s": 5.0}
        for i in range(400)
    ]
    rows_a = [
        {"timestamp": i, "cpu_percent": 80.0 + (i % 3), "mem_percent": 60.0, "net_packets_sent_per_s": 100.0}
        for i in range(400)
    ]
    n = tmp / "n.csv"
    a = tmp / "a.csv"
    pd.DataFrame(rows_n).to_csv(n, index=False)
    pd.DataFrame(rows_a).to_csv(a, index=False)
    return n, a


def _row_spans(split_dir: Path) -> set[tuple[str, int, int]]:
    spans: set[tuple[str, int, int]] = set()
    for meta in split_dir.rglob("*.meta.json"):
        data = json.loads(meta.read_text(encoding="utf-8"))
        spans.add((str(data["series_id"]), int(data["start"]), int(data["end"])))
    return spans


def _overlap(a: set[tuple[str, int, int]], b: set[tuple[str, int, int]]) -> int:
    n = 0
    for sid, s0, e0 in a:
        for sid2, s1, e1 in b:
            if sid != sid2:
                continue
            if s0 < e1 and s1 < e0:
                n += 1
    return n


def test_split_no_row_leak_and_gap(tmp_path: Path) -> None:
    ncsv, acsv = _long_csvs(tmp_path)
    out = tmp_path / "ds"
    window = 20
    meta = build_dataset(
        [ncsv],
        [acsv],
        out,
        window_size=window,
        stride=10,
        val_ratio=0.2,
        test_ratio=0.2,
        balance=False,
        lab_filters=False,
    )
    assert meta["filters"]["lab_filters"] is False
    assert meta["split"]["gap_rows"] == window
    train = _row_spans(out / "train")
    val = _row_spans(out / "val")
    test = _row_spans(out / "test")
    assert train and val and test
    assert _overlap(train, val) == 0
    assert _overlap(train, test) == 0
    assert _overlap(val, test) == 0


def test_balance_only_affects_train(tmp_path: Path) -> None:
    ncsv, acsv = _long_csvs(tmp_path)
    out = tmp_path / "ds"
    meta = build_dataset(
        [ncsv],
        [acsv],
        out,
        window_size=20,
        stride=20,
        val_ratio=0.15,
        test_ratio=0.15,
        balance=True,
    )
    tr = meta["counts"]["train"]
    assert tr["normal"] == tr["anomaly"]
