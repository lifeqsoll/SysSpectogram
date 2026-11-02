"""Phase 7.1 — refit and infer share features_for_iforest(+scaler) space."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from sysspectogram.feedback_iforest import windows_to_tabular
from sysspectogram.ml.features import features_for_iforest
from sysspectogram.preprocess.scaler import WindowScaler


def test_features_for_iforest_matches_windows_to_tabular(tmp_path: Path) -> None:
    rng = np.random.default_rng(0)
    windows = [rng.normal(10, 2, size=(20, 4)).astype(np.float32) for _ in range(8)]
    scaler = WindowScaler().fit(windows)
    scaler.save(tmp_path / "scaler.json")
    loaded = WindowScaler.load(tmp_path / "scaler.json")

    tab = windows_to_tabular(windows, scaler=loaded)
    one = features_for_iforest(windows[0], loaded)
    assert tab.shape[0] == 8
    assert np.allclose(tab[0], one, atol=1e-5)

    # Anomaly spike stays higher than normal mean after scale+tabular
    normal = windows_to_tabular(windows[:4], scaler=loaded)
    spike = windows[0].copy()
    spike[:, 0] = 500.0
    anom = features_for_iforest(spike, loaded)
    assert float(np.linalg.norm(anom)) > float(np.linalg.norm(normal.mean(axis=0)))
