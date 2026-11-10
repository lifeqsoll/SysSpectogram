"""Refuse spoofed SYN auto-ban of Telegram, resolvers, gateways, and RFC1918."""

from __future__ import annotations

import pytest

from sysspectogram.net_ip import parse_ban_ip
from sysspectogram.response.actions import NftBackend
from sysspectogram.response.autoban_policy import FLOW_ALERT_RULES, derive_auto_ban_rules
from sysspectogram.response.protect import is_protected


@pytest.fixture
def isolated_protect(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("sysspectogram.response.protect._host_addrs", lambda: set())
    monkeypatch.setattr("sysspectogram.response.protect._ssh_session_ips", lambda **k: set())
    monkeypatch.setattr("sysspectogram.response.protect._resolver_addrs", lambda: {"192.0.2.53"})
    monkeypatch.setattr("sysspectogram.response.protect._gateway_addrs", lambda: {"203.0.113.1"})


def test_flow_rules_not_in_default_auto_ban() -> None:
    for mode in ("shield", "soft", "aggressive", "isolate"):
        rules = derive_auto_ban_rules(mode, flow_auto_ban=False)
        assert rules.isdisjoint(FLOW_ALERT_RULES)
    on = derive_auto_ban_rules("shield", flow_auto_ban=True)
    assert "flow_syn_burst" in on


def test_telegram_and_resolver_and_gateway_protected(isolated_protect) -> None:
    assert is_protected("149.154.167.220") is not None
    assert "telegram" in (is_protected("149.154.167.220") or "")
    assert is_protected("192.0.2.53") == "resolver"
    assert is_protected("203.0.113.1") == "default gateway"


def test_ban_ip_refuses_telegram_and_lan(isolated_protect) -> None:
    nft = NftBackend()
    tg = nft.ban_ip("149.154.167.220", dry_run=True)
    assert tg.startswith("protected skip") or tg.startswith("refuse ban")
    lan = nft.ban_ip("10.0.0.2", dry_run=True)
    assert lan.startswith("protected skip") or lan.startswith("refuse ban")


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.2", "172.16.1.1", "192.168.1.1", "100.64.0.1", "fc00::1"],
)
def test_parse_ban_ip_rejects_private(ip: str) -> None:
    with pytest.raises(ValueError):
        parse_ban_ip(ip)
    assert parse_ban_ip(ip, allow_private=True)


def test_opt_in_private_ban(isolated_protect) -> None:
    nft = NftBackend(allow_private_bans=True)
    # 203.0.113.9 is documentation, still bannable.
    out = nft.ban_ip("203.0.113.9", dry_run=True)
    assert "dry-run ban" in out
