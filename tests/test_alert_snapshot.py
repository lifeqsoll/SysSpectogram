"""Alert snapshots, plain-language alert text, and unlock-code lifecycle."""

from __future__ import annotations

import time

import pytest

from sysspectogram.alert_text import describe, is_unattributed
from sysspectogram.console_unlock import ConsoleUnlock
from sysspectogram.timeseries.store import TimeseriesStore
from sysspectogram.viz.snapshot import render_window


def test_window_returns_absolute_range(tmp_path):
    store = TimeseriesStore(tmp_path / "ts.sqlite")
    try:
        now = time.time()
        for i in range(200):
            store.write_many({"cpu_percent": float(i % 50)}, ts=now - 200 + i)
        store.flush()
        pts = store.window("cpu_percent", now - 200, now)
        assert len(pts) >= 150
        assert all(now - 200 <= ts <= now for ts, _ in pts)
    finally:
        store.close()


def test_render_window_produces_png(tmp_path):
    pytest.importorskip("matplotlib")
    store = TimeseriesStore(tmp_path / "ts.sqlite")
    try:
        now = time.time()
        for i in range(200):
            store.write_many(
                {"cpu_percent": float(i % 50), "mem_percent": 40.0 + i / 10},
                ts=now - 200 + i,
            )
        store.flush()
        png = render_window(store, now - 200, now - 1, title="test")
        assert png is not None
        assert png[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        store.close()


def test_render_window_without_data_returns_none(tmp_path):
    store = TimeseriesStore(tmp_path / "empty.sqlite")
    try:
        now = time.time()
        assert render_window(store, now - 100, now) is None
    finally:
        store.close()


def test_unlock_code_is_announced_and_cleared_on_success():
    seen: list[str | None] = []
    gate = ConsoleUnlock(enabled=True, on_code=seen.append)
    code = gate.pending_code
    assert code is not None
    assert seen == [code]
    assert gate.try_unlock(code)
    assert seen[-1] is None
    assert gate.unlocked()


def test_unlock_wrong_code_does_not_clear():
    seen: list[str | None] = []
    gate = ConsoleUnlock(enabled=True, on_code=seen.append)
    assert not gate.try_unlock("000000" if gate.pending_code != "000000" else "111111")
    assert None not in seen


def test_describe_known_rule():
    assert "всплеск" in describe("agent_connect_burst").title.lower()
    assert "burst" in describe("agent_connect_burst", lang="en").title.lower()


def test_describe_ssh_brute_and_miner():
    assert "брутфорс" in describe("bruteforce_ssh").title.lower()
    assert "brute" in describe("bruteforce_ssh", lang="en").title.lower()
    assert "майнер" in describe("host_anomaly").title.lower()
    assert "miner" in describe("host_anomaly", lang="en").title.lower()


def test_describe_unknown_rule_keeps_message():
    text = describe("some_new_rule", "raw detail")
    assert text.what == "raw detail"


def test_unattributed_pid():
    assert is_unattributed(0)
    assert is_unattributed(None)
    assert not is_unattributed(42)
