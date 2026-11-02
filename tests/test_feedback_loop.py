"""Phase 7.7 — mark normal suppresses similar window; other pattern still alerts."""

from __future__ import annotations

import numpy as np

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
