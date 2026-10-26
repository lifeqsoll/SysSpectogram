"""H1/H2/L2: strict ban IP parsing + auth.log CIDR injection."""

from __future__ import annotations

import pytest

from sysspectogram.net_ip import nft_saddr_family, parse_ban_ip
from sysspectogram.perimeter.auth import parse_auth_lines
from sysspectogram.response.actions import NftBackend


def test_parse_ban_ip_accepts_host():
    assert parse_ban_ip("203.0.113.9") == "203.0.113.9"
    assert parse_ban_ip("2001:db8::1") == "2001:db8::1"


@pytest.mark.parametrize(
    "bad",
    [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "junk",
        "1.2.3.4 drop ; flush ruleset",
        "0.0.0.0",
        "::",
        "",
        "127.0.0.1",
        "::1",
        "fe80::1",
        "fe80::1%eth0",
    ],
)
def test_parse_ban_ip_rejects(bad):
    with pytest.raises(ValueError):
        parse_ban_ip(bad)


def test_nft_cidr_family_ipv6():
    from sysspectogram.net_ip import nft_cidr_family

    fam, cidr = nft_cidr_family("2001:db8::/64")
    assert fam == "ip6"
    assert cidr == "2001:db8::/64"
    fam4, c4 = nft_cidr_family("203.0.113.0/24")
    assert fam4 == "ip"
    assert c4 == "203.0.113.0/24"


def test_nft_family_ipv6():
    fam, ip = nft_saddr_family("2001:db8::7")
    assert fam == "ip6"
    assert ip == "2001:db8::7"


def test_nft_ban_refuses_cidr_injection():
    nft = NftBackend(never_ban_cidrs=[])
    out = nft.ban_ip("1.2.3.4 drop ; flush ruleset", dry_run=True)
    assert out.startswith("refuse ban")
    out2 = nft.ban_ip("0.0.0.0/0", dry_run=True)
    assert out2.startswith("refuse ban")


def test_auth_injection_uses_real_port_ip():
    lines = [
        "Invalid user x from 0.0.0.0/0 from 203.0.113.9 port 5555 ssh2",
    ]
    ev = parse_auth_lines(lines)
    assert len(ev) == 1
    assert ev[0].ip == "203.0.113.9"
