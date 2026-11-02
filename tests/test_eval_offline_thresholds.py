"""Phase 7.1 — scaled datasets error; per-method thresholds."""

from __future__ import annotations

import importlib.util
import json
import runpy
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_eval_mod():
    path = ROOT / "scripts" / "eval_offline.py"
    spec = importlib.util.spec_from_file_location("eval_offline_under_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_scaled_dataset_is_hard_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ds = tmp_path / "ds"
    (ds / "train" / "normal").mkdir(parents=True)
    (ds / "val" / "normal").mkdir(parents=True)
    np.save(ds / "train" / "normal" / "n.npy", np.zeros((10, 3), dtype=np.float32))
    np.save(ds / "val" / "normal" / "n.npy", np.zeros((10, 3), dtype=np.float32))
    (ds / "meta.json").write_text(json.dumps({"windows_format": "scaled"}), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["eval_offline.py", "--dataset", str(ds), "--methods", "zscore", "--out", str(tmp_path / "out")],
    )
    with pytest.raises(SystemExit) as ei:
        runpy.run_path(str(ROOT / "scripts" / "eval_offline.py"), run_name="__main__")
    assert ei.value.code == 2


def test_iforest_threshold_from_model_meta_not_fuse() -> None:
    mod = _load_eval_mod()
    meta = {"threshold": 0.9, "thresholds": {"iforest": 0.3, "cnn": 0.8, "fuse": 0.7}}
    assert mod._method_threshold(meta, "iforest") == 0.3
    assert mod._method_threshold(meta, "cnn") == 0.8
    assert mod._method_threshold(meta, "fuse") == 0.7
