"""Wheel must ship default.yaml; runtime state follows SYSSPECTOGRAM_HOME."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.config import configs_dir, default_config_path, load_config, state_root
from sysspectogram.guard import _resolve


def test_default_config_resolves_and_loads():
    path = default_config_path()
    assert path.is_file(), path
    assert (configs_dir() / "schema.yaml").is_file()
    cfg = load_config(path)
    assert isinstance(cfg, dict)
    assert "monitor" in cfg or "response" in cfg or "telegram" in cfg


def test_control_sock_follows_state_root(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    # Re-import path helpers see env via state_root()
    assert state_root() == tmp_path
    sock = _resolve("state/control.sock")
    assert sock == (tmp_path / "state" / "control.sock").resolve()
