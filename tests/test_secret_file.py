from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sysspectogram.secret_file import (
    ensure_secret_mode,
    validate_bot_token,
    validate_chat_id,
    write_secret_file,
)


def test_write_secret_file_mode_0600(tmp_path: Path):
    old = os.umask(0o022)
    try:
        path = tmp_path / "secret.env"
        write_secret_file(path, "TELEGRAM_BOT_TOKEN=1\n")
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600
    finally:
        os.umask(old)


def test_write_secret_file_refuses_symlink(tmp_path: Path):
    target = tmp_path / "real"
    target.write_text("x\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symlink"):
        write_secret_file(link, "nope\n")
    assert target.read_text(encoding="utf-8") == "x\n"


def test_validate_rejects_newline_injection():
    with pytest.raises(ValueError):
        validate_chat_id("42\nTELEGRAM_ALLOWED_USER_IDS=666")
    with pytest.raises(ValueError):
        validate_bot_token("12345:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nX=1")


def test_validate_bot_token_ok():
    tok = "123456789:AA" + ("x" * 30)
    assert validate_bot_token(tok) == tok
    assert validate_chat_id("-100123") == "-100123"


def test_ensure_secret_mode_tightens(tmp_path: Path):
    path = tmp_path / ".env"
    path.write_text("A=1\n", encoding="utf-8")
    os.chmod(path, 0o644)
    ensure_secret_mode(path)
    assert path.stat().st_mode & 0o777 == 0o600


def test_cmd_home_env_rejects_injection(tmp_path: Path, monkeypatch):
    from sysspectogram import cli

    monkeypatch.setattr(cli, "ROOT", tmp_path)
    env = tmp_path / ".env"
    env.write_text("OLD=1\n", encoding="utf-8")
    os.chmod(env, 0o644)
    ns = type(
        "A",
        (),
        {
            "bot_token": None,
            "chat_id": "42\nTELEGRAM_ALLOWED_USER_IDS=666",
            "from_stdin": False,
        },
    )()
    rc = cli._cmd_home_env(ns)
    assert rc == 2
    assert "TELEGRAM_ALLOWED_USER_IDS" not in env.read_text(encoding="utf-8")


def test_cmd_home_env_mode(tmp_path: Path, monkeypatch):
    from sysspectogram import cli

    monkeypatch.setattr(cli, "ROOT", tmp_path)
    old = os.umask(0o022)
    try:
        tok = "123456789:AA" + ("x" * 30)
        ns = type(
            "A",
            (),
            {"bot_token": tok, "chat_id": "42", "from_stdin": False},
        )()
        assert cli._cmd_home_env(ns) == 0
        env = tmp_path / ".env"
        assert stat.S_IMODE(env.stat().st_mode) == 0o600
        body = env.read_text(encoding="utf-8")
        assert f"TELEGRAM_BOT_TOKEN={tok}" in body
        assert "TELEGRAM_CHAT_ID=42" in body
    finally:
        os.umask(old)
