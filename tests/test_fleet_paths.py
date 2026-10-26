"""Portable fleet.json paths (Windows APPDATA, macOS Application Support, Linux XDG)."""

from __future__ import annotations

from pathlib import Path

import sysspectogram.fleet.store as store


def test_override_fleet_path(monkeypatch, tmp_path: Path):
    target = tmp_path / "custom" / "fleet.json"
    monkeypatch.setenv("SYSSPECTOGRAM_FLEET_PATH", str(target))
    assert store.default_fleet_path() == target


def test_windows_appdata(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("SYSSPECTOGRAM_FLEET_PATH", raising=False)
    appdata = tmp_path / "Roaming"
    monkeypatch.setattr(store.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(appdata))
    assert store.default_fleet_path() == appdata / "sysspectogram" / "fleet.json"


def test_windows_appdata_fallback_home(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("SYSSPECTOGRAM_FLEET_PATH", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(store.sys, "platform", "win32")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert store.default_fleet_path() == tmp_path / "AppData" / "Roaming" / "sysspectogram" / "fleet.json"


def test_macos_application_support(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("SYSSPECTOGRAM_FLEET_PATH", raising=False)
    monkeypatch.setattr(store.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert (
        store.default_fleet_path()
        == tmp_path / "Library" / "Application Support" / "sysspectogram" / "fleet.json"
    )


def test_linux_xdg_config_home(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("SYSSPECTOGRAM_FLEET_PATH", raising=False)
    xdg = tmp_path / "xdg-config"
    monkeypatch.setattr(store.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert store.default_fleet_path() == xdg / "sysspectogram" / "fleet.json"


def test_linux_default_dot_config(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("SYSSPECTOGRAM_FLEET_PATH", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(store.sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert store.default_fleet_path() == tmp_path / ".config" / "sysspectogram" / "fleet.json"
