"""Lightweight accuracy gate on the checked-in mini reference set (no torch)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "tests" / "data" / "ml_reference_mini.json"


def test_reference_mini_gate_balance_and_labels():
    data = json.loads(REF.read_text(encoding="utf-8"))
    windows = data["windows"]
    assert len(windows) >= 4
    labels = [int(w["label"]) for w in windows]
    n_pos = sum(1 for x in labels if x == 1)
    n_neg = sum(1 for x in labels if x == 0)
    assert n_pos >= 1 and n_neg >= 1
    # Separation on first feature of first timestep (fixture design).
    scores = []
    for w in windows:
        row = w["data"][0]
        scores.append((float(row[0]), int(w["label"])))
    neg_max = max(s for s, y in scores if y == 0)
    pos_min = min(s for s, y in scores if y == 1)
    assert pos_min > neg_max, f"reference set not separable: neg_max={neg_max} pos_min={pos_min}"


def test_reference_fp_budget():
    """With a threshold between classes, FPR on the mini set is 0."""
    data = json.loads(REF.read_text(encoding="utf-8"))
    scores = []
    for w in data["windows"]:
        scores.append((float(w["data"][0][0]), int(w["label"])))
    thr = (max(s for s, y in scores if y == 0) + min(s for s, y in scores if y == 1)) / 2.0
    fp = sum(1 for s, y in scores if y == 0 and s >= thr)
    tp = sum(1 for s, y in scores if y == 1 and s >= thr)
    tn = sum(1 for s, y in scores if y == 0 and s < thr)
    fn = sum(1 for s, y in scores if y == 1 and s < thr)
    assert fp == 0
    assert tp == sum(1 for _, y in scores if y == 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    assert precision >= 0.99
    assert recall >= 0.99
    assert fpr <= 0.01


def test_one_class_mode_default_in_bundled_config():
    from pathlib import Path

    import yaml

    cfg = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "sysspectogram" / "resources" / "configs" / "default.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert (cfg.get("ml") or {}).get("mode") == "one_class"
    assert (cfg.get("ml") or {}).get("adaptive_thresholds") is True
