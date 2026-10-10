from __future__ import annotations

from sysspectogram.timeseries.store import TimeseriesStore


def test_rollup_builds_ten_second_buckets(tmp_path):
    store = TimeseriesStore(tmp_path / "ts.sqlite")
    t0 = 1_700_000_000  # divisible by 10, so bucket 0 covers t0..t0+9
    for i in range(200):
        store.write("host_risk", float(i), ts=t0 + i)
    store.flush()
    now = t0 + 700
    store.rollup(now)
    points = store.query("host_risk", "6h", now=now)
    assert len(points) == 20
    first = points[0]
    assert first.n == 10
    assert first.min == 0.0 and first.max == 9.0
    assert abs(first.avg - 4.5) < 1e-9
    store.close()


def test_range_names_are_validated(tmp_path):
    store = TimeseriesStore(tmp_path / "ts.sqlite")
    try:
        store.query("host_risk", "2y")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown range must raise")
    finally:
        store.close()


def test_metrics_listing(tmp_path):
    store = TimeseriesStore(tmp_path / "ts.sqlite")
    store.write("cpu_percent", 1.0, ts=1_700_000_000)
    store.write("host_risk", 0.2, ts=1_700_000_000)
    store.flush()
    assert store.metrics() == ["cpu_percent", "host_risk"]
    store.close()
