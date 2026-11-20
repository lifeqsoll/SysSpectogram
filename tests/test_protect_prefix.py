"""Prefix bans must not cover the host, an SSH session, or a non-default ssh port."""

from __future__ import annotations

import pytest

from sysspectogram.response.actions import NftBackend
from sysspectogram.response.protect import is_protected


def _quiet_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sysspectogram.response.protect._host_addrs", lambda: set())
    monkeypatch.setattr("sysspectogram.response.protect._resolver_addrs", lambda: set())
    monkeypatch.setattr("sysspectogram.response.protect._gateway_addrs", lambda: set())
    monkeypatch.setattr("sysspectogram.response.protect._ssh_session_ips", lambda **k: set())


def test_prefix_with_ssh_session_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_host(monkeypatch)
    monkeypatch.setattr(
        "sysspectogram.response.protect._ssh_session_ips",
        lambda **k: {"203.0.113.55"},
    )
    assert is_protected("203.0.113.0/24") == "active ssh session"
    assert is_protected("198.51.100.0/24") is None


def test_prefix_with_host_addr_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_host(monkeypatch)
    monkeypatch.setattr(
        "sysspectogram.response.protect._host_addrs",
        lambda: {"2001:db8::99"},
    )
    assert is_protected("2001:db8::/32") == "ignoreself host address"
    assert is_protected("2001:db8:1::/64") is None


def test_ssh_session_uses_configured_port(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []

    def fake(*, ssh_port: int = 22) -> set[str]:
        seen.append(int(ssh_port))
        if int(ssh_port) == 2222:
            return {"203.0.113.55"}
        return set()

    _quiet_host(monkeypatch)
    monkeypatch.setattr("sysspectogram.response.protect._ssh_session_ips", fake)
    assert is_protected("203.0.113.55", ssh_port=2222) == "active ssh session"
    assert is_protected("203.0.113.55", ssh_port=22) is None
    assert is_protected("203.0.113.0/24", ssh_port=2222) == "active ssh session"
    nft = NftBackend(ssh_port=2222)
    out = nft.ban_ip("203.0.113.55", dry_run=True)
    assert out.startswith("protected skip")
    assert 2222 in seen
