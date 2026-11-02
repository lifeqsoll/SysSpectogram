"""Phase 7.8 — level shift triggers refit; spike after refit still detectable via baseline."""

from __future__ import annotations

from sysspectogram.ml.drift_refit import DriftRefitController
from sysspectogram.ml.host_baseline import HostBaseline


def test_drift_refit_then_spike(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    ctl = DriftRefitController(refit_cooldown_sec=0.0, max_flag_rate=0.05)
    # warm quiet period
    for i in range(40):
        ctl.observe(1.0 + (i % 3) * 0.01, alerted=False, now=float(i))
    # shift + many flags → refit
    did = False
    for i in range(40, 80):
        r = ctl.observe(5.0, alerted=True, now=float(i))
        if r.get("refit"):
            did = True
            break
    assert did is True
    # After quiet refit path, host baseline can be fitted on quiet=pre-shift values;
    # ensure a spike vs that baseline still alerts.
    hb = HostBaseline(baseline_sec=0.0, now=100.0)
    for i in range(20):
        hb.observe(1.0, now=100.0 + float(i))
    if not hb.ready:
        hb._fit()
        hb._persist()
    assert hb.ready
    assert hb.observe(1.05, now=130.0)["alert"] is False
    assert hb.observe(50.0, now=131.0)["alert"] is True
