"""Phase 7.2 light — experimental host MAD baseline."""

from __future__ import annotations

from sysspectogram.ml.host_baseline import HostBaseline, load_state


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
