"""Phase 6.3 — repeated ban TTL grows then caps."""

from __future__ import annotations

from sysspectogram.response.ban_increment import next_ttl


def test_ban_increment_grows_then_caps(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    ip = "198.51.100.77"
    base = 3600.0
    cap = 8 * 3600.0
    t0 = 1_700_000_000.0
    t1 = next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, now=t0)
    t2 = next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, now=t0 + 10)
    t3 = next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, now=t0 + 20)
    t4 = next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, now=t0 + 30)
    assert t1 == 3600.0
    assert t2 == 7200.0
    assert t3 == 14400.0  # would be 4x but capped? 4*3600=14400 < 28800
    assert t4 == cap  # 8x = 28800 == cap
    # disabled path
    assert next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, enabled=False) == base


def test_ban_increment_window_expiry(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    ip = "198.51.100.88"
    base = 1000.0
    cap = 10_000.0
    t0 = 1_700_000_000.0
    assert next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, now=t0, window_sec=100) == 1000.0
    # outside window → count resets to 1
    assert (
        next_ttl(ip, base_ttl=base, max_ban_ttl_sec=cap, now=t0 + 500, window_sec=100) == 1000.0
    )
