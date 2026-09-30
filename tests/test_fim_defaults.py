from __future__ import annotations

from sysspectogram.load_profile import PRESETS, apply_load_profile


def test_lite_fim_enabled_by_default():
    cfg = apply_load_profile({"load_profile": "lite"})
    fim = (cfg.get("agent") or {}).get("fim") or {}
    assert fim.get("enabled") is True
    assert int(fim.get("interval_sec", 0)) >= 60


def test_full_fim_enabled():
    assert PRESETS["full"]["agent"]["fim"]["enabled"] is True
