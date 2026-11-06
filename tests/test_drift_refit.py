"""Phase 7.8 — controller refits its own baseline; memory stays bounded."""

from __future__ import annotations

from sysspectogram.ml.drift_refit import FLAG_WINDOW, QUIET_MAX, RECENT_MAX, DriftRefitController
from sysspectogram.ml.host_baseline import HostBaseline


def test_drift_refit_then_spike_on_controller_baseline(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    hb = HostBaseline(baseline_sec=0.0, now=0.0)
    # Warm the shared baseline so scoring works after refit.
    for i in range(20):
        hb.observe(1.0 + (i % 3) * 0.01, now=float(i))
    assert hb.ready or hb.fit_from_samples([1.0 + (i % 3) * 0.01 for i in range(20)])

    ctl = DriftRefitController(
        baseline=hb,
        refit_cooldown_sec=0.0,
        max_flag_rate=0.05,
    )
    for i in range(40):
        ctl.observe(1.0 + (i % 3) * 0.01, alerted=False, now=float(i))
    did = False
    for i in range(40, 90):
        r = ctl.observe(5.0, alerted=True, now=float(i))
        if r.get("refit"):
            did = True
            assert r.get("baseline") is hb
            break
    assert did is True
    # Same object the controller refit — quiet vs spike.
    assert hb.ready is True
    assert hb.observe(1.02, now=200.0)["alert"] is False
    assert hb.observe(80.0, now=201.0)["alert"] is True


def test_drift_refit_memory_bounded(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    ctl = DriftRefitController(refit_cooldown_sec=10**9, max_flag_rate=1.0)
    for i in range(10_000):
        ctl.observe(float(i % 7), alerted=(i % 17 == 0), now=float(i))
    assert len(ctl.recent) <= RECENT_MAX
    assert len(ctl.quiet_values) <= QUIET_MAX
    assert len(ctl.recent_flags) <= FLAG_WINDOW
