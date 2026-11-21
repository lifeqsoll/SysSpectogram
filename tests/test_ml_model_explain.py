"""Model-occlusion explain falls back cleanly without a live inferencer."""

from __future__ import annotations

import numpy as np

from sysspectogram.ml.explain import model_based_explain, plain_ml_line


class _FakeInfer:
    def predict_window(self, window):
        arr = np.asarray(window, dtype=np.float64)
        score = float(arr[:, 0].mean() / 100.0)

        class P:
            pass

        p = P()
        p.score = score
        return p


def test_plain_ml_line_has_method():
    window = np.array([[10.0, 1.0], [20.0, 2.0], [30.0, 3.0]] * 3, dtype=np.float64)
    out = plain_ml_line(window, ["cpu_percent", "mem_percent"])
    assert out["method"] == "stats"
    assert out["primary"]


def test_model_based_explain_ranks_first_feature():
    window = np.zeros((12, 2), dtype=np.float64)
    window[:, 0] = 80.0
    window[:, 1] = 1.0
    out = model_based_explain(_FakeInfer(), window, ["cpu_percent", "mem_percent"])
    assert out is not None
    assert out["method"] == "model_occlusion"
    assert out["primary"] == "cpu_percent"
    assert out["top_features"][0]["feature"] == "cpu_percent"


def test_model_based_explain_none_without_inferencer():
    window = np.ones((8, 1), dtype=np.float64)
    assert model_based_explain(None, window, ["cpu_percent"]) is None
