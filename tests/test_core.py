from __future__ import annotations

import numpy as np

from sysspectogram.ml.cnn import AnomalyCNN
from sysspectogram.ml.ensemble import fuse_scores, pick_threshold
from sysspectogram.preprocess.heatmap import tabular_features, window_to_tensor
from sysspectogram.preprocess.scaler import WindowScaler
from sysspectogram.preprocess.window import iter_windows


def test_iter_windows_stride():
    matrix = np.zeros((100, 4), dtype=np.float32)
    starts = [s for s, _ in iter_windows(matrix, window_size=60, stride=10)]
    assert starts[0] == 0
    assert starts[1] == 10
    assert starts[-1] == 40


def test_scaler_roundtrip(tmp_path):
    windows = [np.random.rand(60, 5).astype(np.float32) * 100 for _ in range(8)]
    scaler = WindowScaler().fit(windows)
    out = scaler.transform(windows[0])
    assert out.shape == (60, 5)
    assert out.min() >= -1e-5
    assert out.max() <= 1.0 + 1e-5
    path = tmp_path / "scaler.joblib"
    scaler.save(path)
    loaded = WindowScaler.load(path)
    assert np.allclose(loaded.transform(windows[0]), out, atol=1e-5)


def test_tabular_and_tensor():
    w = np.random.rand(60, 8).astype(np.float32)
    t = window_to_tensor(w)
    assert t.shape == (1, 60, 8)
    feat = tabular_features(w)
    assert feat.shape == (8 * 4,)


def test_cnn_forward():
    import torch

    model = AnomalyCNN(height=60, width=12)
    x = torch.randn(2, 1, 60, 12)
    y = model(x)
    assert y.shape == (2, 2)


def test_fusion_and_threshold():
    scores = np.array([0.1, 0.4, 0.7, 0.9])
    labels = np.array([0, 0, 1, 1])
    fused = fuse_scores(0.8, 0.2, 0.6, 0.4)
    assert abs(fused - 0.56) < 1e-6
    thr = pick_threshold(scores, labels, recall_target=1.0)
    # Highest threshold that still catches both positives (0.7 and 0.9)
    assert thr == 0.7
    pred = scores >= thr
    assert pred.tolist() == [False, False, True, True]


def test_threshold_does_not_flag_everything():
    # Separable scores: normals low, anomalies high
    scores = np.array([0.1, 0.2, 0.15, 0.8, 0.9, 0.85])
    labels = np.array([0, 0, 0, 1, 1, 1])
    thr = pick_threshold(scores, labels, recall_target=0.9)
    pred = scores >= thr
    # Should not classify all normals as anomaly
    assert int(pred[:3].sum()) < 3
    assert int(pred[3:].sum()) >= 2
