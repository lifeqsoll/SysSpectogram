"""Disk-full flush must not raise; buffer stays bounded."""

from __future__ import annotations

import sqlite3

from sysspectogram.timeseries.store import TimeseriesStore


def test_flush_survives_disk_full(tmp_path):
    path = tmp_path / "ts.sqlite"
    store = TimeseriesStore(path)
    store.write("cpu_percent", 1.0)
    # Force tiny DB so inserts fail after a few pages.
    store._db.execute("PRAGMA max_page_count=2")
    # Fill until write fails.
    for i in range(5000):
        store.write("cpu_percent", float(i))
    n = store.flush()
    # Either succeeded partially or returned 0 without raising.
    assert n >= 0
    assert isinstance(store.flush_errors, int)
    # Buffer must not grow without bound.
    for i in range(100_000):
        store.write("cpu_percent", float(i))
    assert len(store._buffer) <= store._buffer_cap
    assert store.dropped >= 0


def test_flush_rollback_only_when_in_transaction(tmp_path):
    path = tmp_path / "ts2.sqlite"
    store = TimeseriesStore(path)
    store.write("mem_percent", 2.0)
    # Break the connection to force failure after BEGIN.
    store._db.close()
    store._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
    # Drop table to cause INSERT failure inside transaction.
    store._db.execute("DROP TABLE IF EXISTS raw")
    assert store.flush() == 0
    assert store.flush_errors >= 1
