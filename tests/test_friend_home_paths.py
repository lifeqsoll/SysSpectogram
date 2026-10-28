"""Friend/wheel installs must write config and .env under SYSSPECTOGRAM_HOME."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def test_configure_role_ssh_under_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "ss-home"
    home.mkdir()
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(home))
    # Reset dotenv cache between tests.
    import sysspectogram.config as cfg

    monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)

    from sysspectogram.configure_tui import run_configure
    from sysspectogram.config import load_config, writable_config_path

    run_configure(
        prefix=Path("."),
        accept_recommended=True,
        non_interactive=True,
        role="ssh",
        seed_fp=False,
    )
    wrote = writable_config_path()
    assert wrote.is_file()
    assert home in wrote.resolve().parents or wrote.resolve().parent.parent == home.resolve()
    assert "site-packages" not in str(wrote)
    data = load_config()
    assert data.get("role") == "ssh"


def test_home_env_writes_under_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "ss-home"
    home.mkdir()
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(home))
    import sysspectogram.config as cfg

    monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)

    from argparse import Namespace

    from sysspectogram.cli import _cmd_home_env
    from sysspectogram.config import dotenv_path

    rc = _cmd_home_env(
        Namespace(
                bot_token="123:TEST_TOKEN",
                chat_id="42",
                from_stdin=False,
        )
    )
    assert rc == 0
    env = dotenv_path()
    assert env.is_file()
    assert env.parent == home
    text = env.read_text(encoding="utf-8")
    assert "TELEGRAM_BOT_TOKEN=" in text
    assert "TELEGRAM_CHAT_ID=42" in text


def test_state_root_site_packages_uses_home_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sysspectogram.config as cfg

    fake_site = tmp_path / "lib" / "python3.12" / "site-packages" / "sysspectogram"
    fake_site.mkdir(parents=True)
    home_share = tmp_path / "home-share"
    home_share.mkdir()
    monkeypatch.delenv("SYSSPECTOGRAM_HOME", raising=False)
    monkeypatch.setattr(cfg, "_PKG_DIR", fake_site)
    monkeypatch.setattr(cfg, "_dev_checkout_root", lambda: None)
    monkeypatch.setattr(cfg, "_user_data_root", lambda: home_share)
    monkeypatch.setattr(cfg, "_installed_in_site_packages", lambda: True)
    monkeypatch.setattr(cfg, "_running_from_home_venv", lambda: False)
    assert cfg.state_root() == home_share


def test_friend_day0_help_mentions_no_menu() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "friend-day0.sh"
    text = script.read_text(encoding="utf-8")
    assert "--no-menu" in text
    assert "[[ ! -t 0 ]]" in text or '[ ! -t 0 ]' in text
