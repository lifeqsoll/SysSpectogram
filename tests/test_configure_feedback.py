"""Configure merge + response audit + feedback iforest smoke tests."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import yaml

from sysspectogram.configure_tui import apply_overlay
from sysspectogram.feedback_iforest import refit_host_iforest, windows_to_tabular
from sysspectogram.ml.forest import ForestDetector
from sysspectogram.response_audit import ResponseAudit


def test_apply_overlay_preserves_keys(tmp_path: Path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        yaml.safe_dump({"keep_me": 1, "agent": {"enabled": False, "custom": 9}}),
        encoding="utf-8",
    )
    apply_overlay(cfg, {"agent": {"enabled": True}, "load_profile": "lite"})
    data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert data["keep_me"] == 1
    assert data["agent"]["enabled"] is True
    assert data["agent"]["custom"] == 9
    assert data["load_profile"] == "lite"


def test_response_audit(tmp_path: Path):
    a = ResponseAudit(tmp_path / "audit.jsonl")
    a.record("kill", dry_run=True, detail="dry", payload={"pid": 1, "token": "secret"})
    rows = a.tail(5)
    assert len(rows) == 1
    assert rows[0]["action"] == "kill"
    assert "token" not in (rows[0].get("payload") or {})


def test_windows_to_tabular():
    w = np.random.randn(60, 8).astype(np.float32)
    tab = windows_to_tabular([w, w])
    assert tab.shape[0] == 2
    assert tab.shape[1] == 8 * 4  # mean std max p95


def test_refit_host_iforest(tmp_path: Path):
    model = tmp_path / "model"
    model.mkdir()
    # bootstrap forest
    x = np.random.randn(20, 32).astype(np.float32)
    ForestDetector(contamination=0.1).fit(x).save(model / "iforest.ssf.npz")
    (model / "meta.json").write_text('{"iforest_contamination": 0.05}\n', encoding="utf-8")

    fb = tmp_path / "feedback"
    (fb / "normal").mkdir(parents=True)
    (fb / "anomaly").mkdir(parents=True)
    for i in range(3):
        np.save(fb / "normal" / f"n{i}.npy", np.random.randn(60, 8).astype(np.float32) * 0.1)
        np.save(fb / "anomaly" / f"a{i}.npy", np.random.randn(60, 8).astype(np.float32) + 2)

    info = refit_host_iforest(model, fb)
    assert info["ok"] is True
    assert info["cnn"] == "unchanged"
    assert (model / "iforest.ssf.npz").exists()
