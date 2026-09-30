from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest

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
    out = tmp_path / "if.ssf.npz"
    meta = train_agent_iforest([], out)
    assert out.exists()
    assert (tmp_path / "if.ssf.meta.json").exists()
    assert meta["n_samples"] >= 10
    scorer = AgentIsolationScorer(out)
    assert scorer.model is not None
    score = scorer.score(np.zeros(len(FEATURE_NAMES)))
    assert 0.0 <= score <= 1.0


def test_enforced_agent_iforest_requires_signature(tmp_path):
    model = tmp_path / "agent_iforest.ssf.npz"
    # minimal invalid npz-like — scorer should fail closed under enforce+missing key
    model.write_bytes(b"PK\x03\x04notreal")
    (tmp_path / "agent_iforest.ssf.meta.json").write_text(
        '{"format":"sysspectogram.iforest.ssf","version":1,"n_estimators":0,'
        '"offset":0,"max_samples":2,"n_features":9,"contamination":0.1}\n',
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="public key|signature|enforced"):
        AgentIsolationScorer(model, supply_chain={"enforce": True})


def test_legacy_agent_joblib_refused(tmp_path):
    model = tmp_path / "agent_iforest.joblib"
    model.write_bytes(b"untrusted")
    with pytest.raises(RuntimeError, match="joblib|migrate|re-train"):
        AgentIsolationScorer(model)


@pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign CLI unavailable")
def test_enforced_agent_iforest_requires_meta_signature(tmp_path: Path):
    out = tmp_path / "agent_if.ssf.npz"
    train_agent_iforest([], out)
    meta = tmp_path / "agent_if.ssf.meta.json"
    public = tmp_path / "minisign.pub"
    secret = tmp_path / "minisign.key"
    subprocess.run(
        ["minisign", "-G", "-p", str(public), "-s", str(secret), "-W"],
        check=True,
        capture_output=True,
    )
    from sysspectogram.supply_chain import sign_file

    sign_file(out, secret)
    # meta unsigned → must fail under enforce
    with pytest.raises(Exception, match="signature|minisign|does not exist"):
        AgentIsolationScorer(
            out,
            supply_chain={"enforce": True, "public_key": str(public)},
        )
    # sign meta → loads
    sign_file(meta, secret)
    scorer = AgentIsolationScorer(
        out,
        supply_chain={"enforce": True, "public_key": str(public)},
    )
    assert scorer.model is not None


@pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign CLI unavailable")
def test_enforced_agent_iforest_no_silent_heuristic_fallback(tmp_path: Path):
    out = tmp_path / "broken.ssf.npz"
    meta = tmp_path / "broken.ssf.meta.json"
    # Valid-looking signed garbage that passes minisign but fails SSF parse
    out.write_bytes(b"not-a-real-npz")
    meta.write_text(
        json.dumps(
            {
                "format": "sysspectogram.iforest.ssf",
                "version": 1,
                "n_estimators": 1,
                "offset": 0.0,
                "max_samples": 2,
                "n_features": 9,
                "contamination": 0.1,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    public = tmp_path / "minisign.pub"
    secret = tmp_path / "minisign.key"
    subprocess.run(
        ["minisign", "-G", "-p", str(public), "-s", str(secret), "-W"],
        check=True,
        capture_output=True,
    )
    from sysspectogram.supply_chain import sign_file

    sign_file(out, secret)
    sign_file(meta, secret)
    with pytest.raises(Exception):
        AgentIsolationScorer(
            out,
            supply_chain={"enforce": True, "public_key": str(public)},
        )
