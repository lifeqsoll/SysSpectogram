"""Phase 7.7 — mark normal suppresses similar window; TTL; undo clears flag."""

from __future__ import annotations

import json
import time

import numpy as np

from sysspectogram.ml import feedback_suppress as fs
from sysspectogram.ml.feedback_suppress import mark_normal, should_suppress, undo_last


def test_mark_normal_suppresses_similar(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    rng = np.random.default_rng(0)
    base = rng.normal(10, 1, size=(30, 4)).astype(np.float32)
    mark_normal(base)
    assert should_suppress(base) is True
    similar = base + rng.normal(0, 0.01, size=base.shape).astype(np.float32)
    assert should_suppress(similar) is True
    other = base.copy()
    other[:, 0] = 200.0
    assert should_suppress(other) is False
    undo_last()
    assert should_suppress(base) is False
    data = fs.load()
    assert "refit_pending" not in data


def test_prototype_ttl_expires(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    rng = np.random.default_rng(1)
    base = rng.normal(10, 1, size=(30, 4)).astype(np.float32)
    now = time.time()
    mark_normal(base, now=now)
    assert should_suppress(base, now=now) is True
    # Force stale ts on disk
    path = tmp_path / "state" / "ml_fp_suppress.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["prototypes"][0]["ts"] = now - fs.PROTOTYPE_TTL_SEC - 10
    path.write_text(json.dumps(data), encoding="utf-8")
    assert should_suppress(base, now=now) is False
