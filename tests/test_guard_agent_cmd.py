"""п.14: guard always passes absolute guard/watchdog pidfiles."""

from __future__ import annotations

from pathlib import Path


def test_packaged_units_set_watchdog_and_guard_pidfiles() -> None:
    root = Path(__file__).resolve().parents[1]
    units = [
        root / "packaging/sysspectogram-agent.service",
        root / "packaging/distro/sysspectogram-agent.service",
    ]
    for unit in units:
        text = unit.read_text(encoding="utf-8")
        assert "--guard-pidfile" in text, unit
        assert "--watchdog-pidfile" in text, unit


def test_guard_pidfile_passed_without_root_watch(tmp_path, monkeypatch) -> None:
    """Agent argv must include both pidfiles even when root_watch is off."""
    import inspect
    import sysspectogram.guard as guard

    src = inspect.getsource(guard.run_guard)
    assert "--guard-pidfile" in src
    assert "--watchdog-pidfile" in src
    # The extend that adds pidfiles is outside the root_watch branch.
    assert "Always pass absolute guard/watchdog pidfiles" in src
