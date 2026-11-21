from sysspectogram.timeseries.rates import AlertRateMeter, RateWindow


def test_rate_window_per_min():
    w = RateWindow(60.0)
    for i in range(30):
        w.add(1_000_000.0 + i)
    assert abs(w.per_min(1_000_000.0 + 30) - 30.0) < 1e-6


def test_alert_rate_meter_snapshot():
    m = AlertRateMeter(60.0)
    m.note(severity="high", perimeter=True, ts=100.0)
    m.note(severity="critical", perimeter=True, ts=101.0)
    m.note(severity="low", perimeter=False, ts=102.0)
    snap = m.snapshot(160.0)
    assert snap["alerts_per_min"] == 3.0
    assert snap["alerts_high_per_min"] == 1.0
    assert snap["alerts_critical_per_min"] == 1.0
    assert snap["perimeter_events_per_min"] == 2.0
