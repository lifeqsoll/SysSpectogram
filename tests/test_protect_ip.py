"""F-07 is_protected."""

from __future__ import annotations

from sysspectogram.response.protect import is_protected


def test_ignoreself_loopback():
    assert is_protected("127.0.0.1") == "ignoreself special"


def test_never_ban():
    r = is_protected("198.51.100.7", never_ban_cidrs=["198.51.100.0/24"])
    assert r and "never_ban" in r


def test_docs_ip_not_protected_by_default():
    assert is_protected("203.0.113.50", never_ban_cidrs=[], protect_ssh_sessions=False) is None
