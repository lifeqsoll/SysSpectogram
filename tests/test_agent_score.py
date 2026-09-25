from __future__ import annotations

import numpy as np

from sysspectogram.agent_score import (
    FEATURE_NAMES,
    AgentFeatureWindow,
    AgentIsolationScorer,
    train_agent_iforest,
)


def test_feature_window_vector():
    w = AgentFeatureWindow(window_sec=60)
    w.push("agent_open_sensitive", risky_comm=True, path="/a")
    w.push("agent_connect_burst")
    v = w.vector()
    assert v.shape == (len(FEATURE_NAMES),)
    assert v[FEATURE_NAMES.index("open_sensitive")] == 1
    assert v[FEATURE_NAMES.index("risky_comm")] == 1


def test_heuristic_scorer():
    s = AgentIsolationScorer(None)
    v = np.zeros(len(FEATURE_NAMES))
    assert s.score(v) == 0.0
    v[0] = 8
    assert s.score(v) >= 0.9


def test_train_agent_iforest(tmp_path):
    out = tmp_path / "if.joblib"
    meta = train_agent_iforest([], out)
    assert out.exists()
    assert meta["n_samples"] >= 10
    scorer = AgentIsolationScorer(out)
    assert scorer.model is not None
    score = scorer.score(np.zeros(len(FEATURE_NAMES)))
    assert 0.0 <= score <= 1.0
