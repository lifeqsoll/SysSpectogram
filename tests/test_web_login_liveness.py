"""web login must not treat a live foreign pid as dead, or a reused pid as web."""

from __future__ import annotations

import errno
import json
from argparse import Namespace
from pathlib import Path

import pytest

from sysspectogram.response.actions import NftBackend, _strict_port
from sysspectogram.web.login_code import login_process_alive


def test_strict_port_rejects_non_ascii_digits() -> None:
    with pytest.raises(ValueError):
        _strict_port("٣")
    assert _strict_port("22") == 22


def test_shield_refuses_22_when_ssh_is_2222() -> None:
    nft = NftBackend(ssh_port=2222)
    assert nft.shield_port(22).startswith("shield refused")
    assert nft.shield_port(2222).startswith("shield refused")
    assert nft.quarantine_ports([22]).startswith("quarantine refused")
    assert nft.quarantine_ports([2222]).startswith("quarantine refused")


def test_eperm_with_sysspectogram_cmdline_is_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(pid: int, sig: int) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr("sysspectogram.web.login_code.os.kill", boom)

    real = Path.read_bytes

    def fake_read(self: Path) -> bytes:
        if self.name == "cmdline":
            return b"python\x00-m\x00sysspectogram\x00web\x00"
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", fake_read)
    assert login_process_alive(4242) is True


def test_reused_pid_is_not_web(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sysspectogram.web.login_code.os.kill", lambda pid, sig: None)

    def fake_read(self: Path) -> bytes:
        if self.name == "cmdline":
            return b"bash\x00"
        raise AssertionError(self)

    monkeypatch.setattr(Path, "read_bytes", fake_read)
    assert login_process_alive(4242) is False


def test_stale_login_file_says_stale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    state = tmp_path / "state"
    state.mkdir()
    (state / "web.login").write_text("ABCDEFGH\n9999999999.0\n999999\n", encoding="utf-8")
    from sysspectogram.cli import _cmd_web

    rc = _cmd_web(Namespace(web_op="login"))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["ok"] is False
    assert "stale" in payload["error"]
    assert "no state/web.login" not in payload["error"]


def test_missing_login_file_says_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    from sysspectogram.cli import _cmd_web

    rc = _cmd_web(Namespace(web_op="login"))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert "no state/web.login" in payload["error"]


def test_server_close_removes_login_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    from sysspectogram.web.bus import LiveBus
    from sysspectogram.web.server import start_web_server

    httpd = start_web_server(LiveBus(), host="127.0.0.1", port=0)
    path = tmp_path / "state" / "web.login"
    try:
        assert path.is_file()
        assert getattr(httpd, "login_gate", None) is not None
        httpd.login_gate.close()
        assert not path.exists()
    finally:
        httpd.shutdown()
        httpd.server_close()
