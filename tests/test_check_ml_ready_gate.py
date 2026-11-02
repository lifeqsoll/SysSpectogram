"""Phase 7.4 — fuse worse than baseline → non-zero gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _gate(metrics: dict):
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_ml_ready.py"
    spec = importlib.util.spec_from_file_location("check_ml_ready_ut", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.gate_from_metrics(metrics)


def test_gate_fails_when_fuse_worse_than_baseline() -> None:
    metrics = {
        "best_baseline": "robust_z",
        "baselines": {
            "robust_z": {"pr_auc": 0.91, "recall_at_fpr_1pct": 0.4},
            "zscore": {"pr_auc": 0.80, "recall_at_fpr_1pct": 0.3},
        },
        "methods": {
            "fuse": {"pr_auc": 0.70, "recall_at_fpr_1pct": 0.2},
            "robust_z": {"pr_auc": 0.91, "recall_at_fpr_1pct": 0.4},
        },
        "warnings": [],
    }
    code, msg = _gate(metrics)
    assert code != 0
    assert "PR-AUC" in msg or "<=" in msg


def test_gate_ok_when_fuse_beats_baseline() -> None:
    metrics = {
        "best_baseline": "robust_z",
        "baselines": {"robust_z": {"pr_auc": 0.70, "recall_at_fpr_1pct": 0.3}},
        "methods": {"fuse": {"pr_auc": 0.85, "recall_at_fpr_1pct": 0.5}},
        "warnings": [],
    }
    code, msg = _gate(metrics)
    assert code == 0
    assert "ok" in msg
