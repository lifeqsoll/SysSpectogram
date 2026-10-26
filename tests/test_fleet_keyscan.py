"""fleet keyscan host/port parsing (IPv6, non-default port, injection)."""

from __future__ import annotations

from sysspectogram.fleet.pair import parse_ssh_host_port, suggest_keyscan


def test_parse_user_host():
    assert parse_ssh_host_port("alice@example.com") == ("example.com", None)


def test_parse_user_host_port():
    assert parse_ssh_host_port("alice@example.com:2222") == ("example.com", 2222)


def test_parse_bracketed_ipv6_port():
    assert parse_ssh_host_port("alice@[2001:db8::1]:2222") == ("2001:db8::1", 2222)


def test_parse_bracketed_ipv6():
    assert parse_ssh_host_port("alice@[2001:db8::1]") == ("2001:db8::1", None)


def test_parse_bare_ipv6():
    assert parse_ssh_host_port("root@2001:db8::7") == ("2001:db8::7", None)


def test_parse_rejects_option_injection():
    assert parse_ssh_host_port("-oProxyCommand=evil") is None
    assert parse_ssh_host_port("user@-oProxyCommand=evil") is None
    assert parse_ssh_host_port("") is None


def test_suggest_keyscan_rejects_injection():
    out = suggest_keyscan("-oProxyCommand=evil")
    assert out["ok"] is False
    assert out.get("host") is None
