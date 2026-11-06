"""Phase 7.2 light — experimental host MAD baseline."""

from __future__ import annotations

import json
import time

from sysspectogram.ml.drift_refit import DriftRefitController
from sysspectogram.ml.host_baseline import HostBaseline, load_state
from sysspectogram.risk import decide_risk


def test_host_baseline_learns_then_alerts_on_spike(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    hb = HostBaseline(baseline_sec=10.0, threshold_quantile=0.9, now=0.0)
    # stationary (baseline_sec=10 → still learning through t=10)
    for i in range(11):
        r = hb.observe(1.0 + (i % 3) * 0.01, now=float(i))
        assert r["phase"] == "learning"
        assert r["alert"] is False
    # past baseline
    r = hb.observe(1.02, now=11.0)
    assert r["phase"] == "scoring"
    assert r["alert"] is False
    spike = hb.observe(50.0, now=12.0)
    assert spike["alert"] is True
    # persist / reload
    path_ok = (tmp_path / "state" / "host_baseline.json").is_file()
    assert path_ok
    st = load_state()
    assert st.get("ready") is True
    hb2 = HostBaseline(baseline_sec=10.0, now=20.0)
    assert hb2.ready is True
    assert hb2.observe(1.0, now=21.0)["alert"] is False
    assert hb2.observe(80.0, now=22.0)["alert"] is True


def test_host_baseline_no_alert_during_learning(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    hb = HostBaseline(baseline_sec=100.0, now=0.0)
    for i in range(30):
        # huge values still "learning"
        r = hb.observe(1000.0, now=float(i))
        assert r["alert"] is False
        assert r["phase"] == "learning"


def test_score_ready_no_mutate_no_persist(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    hb = HostBaseline(baseline_sec=0.0, now=0.0)
    quiet = [1.0 + (i % 3) * 0.01 for i in range(20)]
    assert hb.fit_from_samples(quiet, persist=True, now=100.0)
    path = tmp_path / "state" / "host_baseline.json"
    before = path.read_text(encoding="utf-8")
    mtime = path.stat().st_mtime
    n = len(hb.samples)
    time.sleep(0.02)
    assert hb.score(1.02)["alert"] is False
    spike = hb.score(80.0)
    assert spike["alert"] is True
    assert spike["ready"] is True
    assert spike["z"] is not None and spike["z"] > 3.0
    assert len(hb.samples) == n
    assert path.read_text(encoding="utf-8") == before
    assert path.stat().st_mtime == mtime


def test_score_not_ready_does_not_append(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    hb = HostBaseline(baseline_sec=100.0, now=0.0)
    assert hb.ready is False
    n = len(hb.samples)
    out = hb.score(999.0)
    assert out["ready"] is False
    assert out["alert"] is False
    assert out["phase"] == "learning"
    assert len(hb.samples) == n


def test_decide_risk_baseline_promote_only() -> None:
    # No baseline args — same as classic quiet / host alert.
    quiet = decide_risk(0.2, 0.0, 0.0, host_threshold=0.99, risk_threshold=0.7)
    assert not quiet.is_anomaly and quiet.reason == "none"
    assert quiet.baseline_promoted is False
    same = decide_risk(
        0.2,
        0.0,
        0.0,
        host_threshold=0.99,
        risk_threshold=0.7,
        baseline_z=None,
        baseline_alert=None,
    )
    assert same.is_anomaly == quiet.is_anomaly and same.reason == quiet.reason

    # Fuse anomaly + quiet baseline → still anomaly, not promoted.
    fused = decide_risk(
        0.995,
        None,
        None,
        host_threshold=0.99,
        risk_threshold=0.7,
        baseline_z=0.1,
        baseline_alert=False,
    )
    assert fused.is_anomaly and fused.reason == "host"
    assert fused.baseline_promoted is False

    # Fuse quiet + baseline alert → promote.
    promo = decide_risk(
        0.2,
        0.0,
        0.0,
        host_threshold=0.99,
        risk_threshold=0.7,
        baseline_z=12.0,
        baseline_alert=True,
    )
    assert promo.is_anomaly and promo.reason == "baseline"
    assert promo.baseline_promoted is True
    assert promo.baseline_z == 12.0


def test_controller_baseline_score_then_promote(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    hb = HostBaseline(baseline_sec=0.0, now=0.0)
    ctl = DriftRefitController(baseline=hb, refit_cooldown_sec=0.0)
    quiet = [1.0 + (i % 3) * 0.01 for i in range(20)]
    assert hb.fit_from_samples(quiet, persist=True, now=50.0)
    assert ctl.baseline is hb
    # Quiet score does not promote.
    view_q = hb.score(1.02)
    d_q = decide_risk(
        0.2,
        None,
        None,
        host_threshold=0.99,
        risk_threshold=0.7,
        baseline_z=view_q.get("z"),
        baseline_alert=bool(view_q.get("alert")),
    )
    assert not d_q.is_anomaly
    assert d_q.baseline_promoted is False
    # Spike promotes quiet fuse.
    view_s = hb.score(80.0)
    assert view_s["alert"] is True
    d_s = decide_risk(
        0.2,
        None,
        None,
        host_threshold=0.99,
        risk_threshold=0.7,
        baseline_z=view_s.get("z"),
        baseline_alert=True,
    )
    assert d_s.is_anomaly and d_s.baseline_promoted is True
    # Disk still valid JSON after score-only path.
    raw = json.loads((tmp_path / "state" / "host_baseline.json").read_text(encoding="utf-8"))
    assert raw.get("ready") is True
