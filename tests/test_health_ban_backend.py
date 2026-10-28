"""F-04: health ban_backend check."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest


def _run_health(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    mode: str,
    ban_ok: bool,
    ssh_ok: bool = True,
) -> dict:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    import sysspectogram.config as cfg

    monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)

    # Stub load_config mode
    def fake_load(_path=None):
        return {"response": {"mode": mode}, "telegram": {}, "kirk": {}}

    monkeypatch.setattr("sysspectogram.cli.load_config", fake_load)
    monkeypatch.setattr("sysspectogram.config.load_config", fake_load)

    if ban_ok:
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr("shutil.which", lambda n: "/usr/sbin/nft" if n == "nft" else None)
    else:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        monkeypatch.setattr(
            "sysspectogram.response.helper_ban.helper_available",
            lambda path=None: False,
        )

    if ssh_ok:
        monkeypatch.setattr(
            "sysspectogram.perimeter.auth.ssh_auth_lines",
            lambda n=50: (["sshd[1]: Failed password for x from 203.0.113.1 port 22 ssh2"], "journal"),
        )
    else:
        monkeypatch.setattr(
            "sysspectogram.perimeter.auth.ssh_auth_lines",
            lambda n=50: ([], "none"),
        )

    from sysspectogram.cli import _cmd_home_health
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _cmd_home_health(Namespace(ping=False))
    data = json.loads(buf.getvalue())
    data["_rc"] = rc
    return data


def test_health_ban_ok_as_root_observe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _run_health(monkeypatch, tmp_path, mode="observe", ban_ok=True)
    ban = next(c for c in data["checks"] if c["id"] == "ban_backend")
    assert ban["ok"] is True


def test_health_soft_without_ban_is_not_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _run_health(monkeypatch, tmp_path, mode="soft", ban_ok=False)
    ban = next(c for c in data["checks"] if c["id"] == "ban_backend")
    assert ban["ok"] is False
    assert data["ok"] is False
    assert data["_rc"] == 1


def test_health_soft_without_ssh_source_is_not_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _run_health(monkeypatch, tmp_path, mode="soft", ban_ok=True, ssh_ok=False)
    ssh = next(c for c in data["checks"] if c["id"] == "ssh_source")
    assert ssh["ok"] is False
    assert "systemd-journal" in ssh["detail"]
    assert data["ok"] is False
