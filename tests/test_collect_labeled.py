"""Phase 7.3 — labels.csv rows match scheduled scenarios."""

from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_collect_labeled_dry_run(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "labels.csv"
    path = ROOT / "scripts" / "collect_labeled.py"
    spec = importlib.util.spec_from_file_location("collect_labeled_ut", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(
        sys,
        "argv",
        ["collect_labeled.py", "--out", str(out), "--dry-run", "--base-ts", "1000"],
    )
    assert mod.main() == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert rows[0]["scenario"] == "normal"
    assert rows[0]["label"] == "normal"
    assert any(r["scenario"] == "miner_high" and r["label"] == "anomaly" for r in rows)
    assert any(r["scenario"] == "legit_build" and r["label"] == "normal" for r in rows)
    # contiguous non-overlapping
    for a, b in zip(rows, rows[1:]):
        assert float(a["end"]) <= float(b["start"])
