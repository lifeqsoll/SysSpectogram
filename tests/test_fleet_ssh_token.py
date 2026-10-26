"""device_token must not appear in remote SSH command argv string."""

from __future__ import annotations

from unittest.mock import patch

from sysspectogram.fleet.ssh import remote_control
from sysspectogram.fleet.store import FleetHost


def test_remote_control_token_on_stdin_not_argv():
    host = FleetHost(
        id="web1",
        label="web1",
        ssh="user@example.com",
        home_path="/home/u/ss",
        device_token="SECRET_TOKEN_XYZ",
        host_key_line="ssh-ed25519 AAAAB3NzaC1yc2E",
    )
    captured: dict = {}

    def fake_ssh_run(h, remote_command, *, timeout=60.0, identity=None, stdin_data=None):
        captured["remote"] = remote_command
        captured["stdin"] = stdin_data
        from sysspectogram.fleet.ssh import SshResult

        return SshResult(True, '{"ok":true,"host_id":"web1"}', "", 0)

    with patch("sysspectogram.fleet.ssh.ssh_run", side_effect=fake_ssh_run):
        out = remote_control(host, {"op": "status"}, mutating=False)

    assert out.get("ok") is True
    assert "SECRET_TOKEN_XYZ" not in captured["remote"]
    assert "SECRET_TOKEN_XYZ" in (captured["stdin"] or "")


def test_mutating_refuses_without_pin():
    host = FleetHost(id="x", label="x", ssh="u@h", device_token="t")
    out = remote_control(host, {"op": "action", "name": "ban", "payload": {"ip": "1.2.3.4"}}, mutating=True)
    assert out.get("ok") is False
    assert "host_key_line" in str(out.get("error"))
