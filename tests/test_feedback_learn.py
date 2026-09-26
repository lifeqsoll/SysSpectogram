"""Feedback learner tests."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from sysspectogram.feedback_learn import FeedbackLearner


def test_record_bias(tmp_path: Path):
    fl = FeedbackLearner(tmp_path)
    w = np.zeros((8, 4), dtype=np.float32)
    info = fl.record("baseline", window=w, columns=["a", "b", "c", "d"], score=0.2)
    assert info["threshold_bias"] > 0
    info2 = fl.record("anomaly", window=w, score=0.9, process_key="xmrig")
    assert info2["counts"]["anomaly"] == 1
    thr = fl.apply_bias(0.5)
    assert thr != 0.5
