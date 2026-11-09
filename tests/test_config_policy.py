"""ssh.port and kirk.egress_allow_cidrs must not fail silently."""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from sysspectogram.response.actions import policy_from_config


def test_egress_string_is_rejected() -> None:
    with pytest.raises(ValueError, match="list"):
        policy_from_config({"kirk": {"egress_allow_cidrs": "203.0.113.0/24"}})


def test_bogus_egress_cidr_is_rejected() -> None:
    with pytest.raises(ValueError, match="bogus"):
        policy_from_config({"kirk": {"egress_allow_cidrs": ["203.0.113.0/24", "bogus"]}})


def test_bool_ssh_port_is_rejected() -> None:
    with pytest.raises(ValueError, match="ssh.port"):
        policy_from_config({"ssh": {"port": True}})


def test_valid_policy_still_loads() -> None:
    port, egress = policy_from_config(
        {"ssh": {"port": 2222}, "kirk": {"egress_allow_cidrs": []}}
    )
    assert port == 2222
    assert egress == []


def test_health_reports_bool_ssh_port(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        "sysspectogram.cli.load_config",
        lambda *args, **kwargs: {"ssh": {"port": True}, "response": {"mode": "observe"}},
    )
    from sysspectogram.cli import _cmd_home_health

    rc = _cmd_home_health(Namespace(ping=False, strict=False))
    data = json.loads(capsys.readouterr().out)
    check = next(c for c in data["checks"] if c["id"] == "config_policy")
    assert check["ok"] is False
    assert "ssh.port" in check["detail"]
    assert rc != 0
