"""F-07: is_protected admin / session guards."""

from __future__ import annotations

import pytest

from sysspectogram.response.protect import is_protected


def test_ignoreself_loopback():
    assert is_protected("127.0.0.1") == "ignoreself special"


def test_never_ban_cidr(monkeypatch):
    monkeypatch.setattr("sysspectogram.response.protect._host_addrs", lambda: set())
    monkeypatch.setattr("sysspectogram.response.protect._ssh_session_ips", lambda **k: set())
    reason = is_protected("203.0.113.10", never_ban_cidrs=["203.0.113.0/24"])
    assert reason is not None
    assert reason.startswith("never_ban")


def test_active_ssh_session(monkeypatch):
    monkeypatch.setattr("sysspectogram.response.protect._host_addrs", lambda: set())
    monkeypatch.setattr(
        "sysspectogram.response.protect._ssh_session_ips",
        lambda **k: {"203.0.113.55"},
    )
    assert is_protected("203.0.113.55") == "active ssh session"
    assert is_protected("203.0.113.56") is None


def test_host_address_protected(monkeypatch):
    monkeypatch.setattr(
        "sysspectogram.response.protect._host_addrs",
        lambda: {"203.0.113.99"},
    )
    monkeypatch.setattr("sysspectogram.response.protect._ssh_session_ips", lambda **k: set())
    assert is_protected("203.0.113.99") == "ignoreself host address"
