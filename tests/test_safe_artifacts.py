from __future__ import annotations

import json

import numpy as np
import pytest

from sysspectogram.ml.forest import ForestDetector
from sysspectogram.safe_artifacts import migrate_artifacts_dir
from sysspectogram.preprocess.scaler import WindowScaler


def test_scaler_json_roundtrip(tmp_path):
    windows = [np.random.rand(60, 5).astype(np.float32) * 100 for _ in range(8)]
    scaler = WindowScaler().fit(windows)
    out = scaler.transform(windows[0])
    path = tmp_path / "scaler.json"
    scaler.save(path)
    loaded = WindowScaler.load(path)
    assert np.allclose(loaded.transform(windows[0]), out, atol=1e-5)


def test_scaler_joblib_save_refused(tmp_path):
    windows = [np.random.rand(60, 4).astype(np.float32) for _ in range(4)]
    scaler = WindowScaler().fit(windows)
    with pytest.raises(RuntimeError, match="joblib"):
        scaler.save(tmp_path / "scaler.joblib")


def test_scaler_joblib_load_refused(tmp_path):
    # craft a fake joblib path name — load must refuse without reading pickle
    path = tmp_path / "scaler.joblib"
    path.write_bytes(b"not-a-real-joblib")
    with pytest.raises(RuntimeError, match="joblib|migrate"):
        WindowScaler.load(path)


def test_iforest_ssf_parity(tmp_path):
    rng = np.random.default_rng(0)
    x = rng.normal(size=(80, 12)).astype(np.float64)
    probe = rng.normal(size=(5, 12)).astype(np.float64)
    forest = ForestDetector(contamination=0.1, random_state=0)
    forest.fit(x)
    expected = forest.anomaly_score(probe)
    path = tmp_path / "iforest.ssf.npz"
    forest.save(path)
    assert path.is_file()
    assert (tmp_path / "iforest.ssf.meta.json").is_file()
    loaded = ForestDetector.load(path)
    got = loaded.anomaly_score(probe)
    assert np.allclose(expected, got, atol=1e-5)


def test_iforest_joblib_load_refused(tmp_path):
    path = tmp_path / "iforest.joblib"
    path.write_bytes(b"nope")
    with pytest.raises(RuntimeError, match="joblib|migrate"):
        ForestDetector.load(path)


def test_migrate_artifacts_dir(tmp_path):
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler

    windows = [np.random.rand(60, 4).astype(np.float32) for _ in range(4)]
    scaler = WindowScaler().fit(windows)
    # write legacy via joblib directly (public save refuses)
    joblib.dump({"scaler": scaler.scaler, "n_features": scaler.n_features}, tmp_path / "scaler.joblib")
    rng = np.random.default_rng(1)
    model = IsolationForest(n_estimators=50, random_state=1).fit(rng.normal(size=(40, 16)))
    joblib.dump(model, tmp_path / "iforest.joblib")
    done = migrate_artifacts_dir(tmp_path, delete_legacy=True)
    assert (tmp_path / "scaler.json").is_file()
    assert (tmp_path / "iforest.ssf.npz").is_file()
    assert not (tmp_path / "scaler.joblib").exists()
    assert not (tmp_path / "iforest.joblib").exists()
    assert "scaler" in done and "iforest" in done
    WindowScaler.load(tmp_path / "scaler.json")
    ForestDetector.load(tmp_path / "iforest.ssf.npz")


def test_migrate_minmax_scaler_joblib(tmp_path):
    import joblib
    from sklearn.preprocessing import MinMaxScaler

    ms = MinMaxScaler()
    x = np.random.rand(30, 5).astype(np.float64)
    ms.fit(x)
    joblib.dump({"scaler": ms, "n_features": 5}, tmp_path / "scaler.joblib")
    done = migrate_artifacts_dir(tmp_path)
    assert "scaler" in done
    loaded = WindowScaler.load(tmp_path / "scaler.json")
    assert isinstance(loaded.scaler, MinMaxScaler)
    assert np.allclose(loaded.scaler.transform(x[:1]), ms.transform(x[:1]), atol=1e-6)
