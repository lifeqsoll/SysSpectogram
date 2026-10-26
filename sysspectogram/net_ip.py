"""Strict IP parsing for ban / never-ban paths (no CIDR injection, no nft metacharacters)."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any


def parse_ban_ip(raw: Any) -> str:
    """Return a canonical single-host IP string, or raise ValueError.

    Rejects CIDRs (``0.0.0.0/0``), unspecified/loopback/link-local, zone IDs
    (``fe80::1%eth0``), junk, and metacharacters.
    Use this on every ban/unban path before nft/iptables.
    """
    token = str(raw or "").strip()
    if not token or "/" in token or "%" in token:
        raise ValueError(f"invalid ban ip: {token!r}")
    if any(c in token for c in ";|&`$(){}[]<>\\\"' \t\n\r"):
        raise ValueError(f"invalid ban ip: {token!r}")
    addr = ip_address(token)
    if not isinstance(addr, (IPv4Address, IPv6Address)):
        raise ValueError(f"invalid ban ip: {token!r}")
    if (
        addr.is_unspecified
        or addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
    ):
        raise ValueError(f"refusing ban of special address: {addr}")
    return str(addr)


def nft_saddr_family(ip: str) -> tuple[str, str]:
    """Return ``(family_token, canonical_ip)`` for nft: ``ip`` or ``ip6``."""
    canonical = parse_ban_ip(ip)
    addr = ip_address(canonical)
    return ("ip6" if addr.version == 6 else "ip"), canonical


def nft_cidr_family(cidr: str) -> tuple[str, str]:
    """Return ``(family_token, canonical_cidr)`` for nft allow rules."""
    from ipaddress import ip_network

    token = str(cidr or "").strip()
    if not token:
        raise ValueError("empty cidr")
    net = ip_network(token, strict=False)
    return ("ip6" if net.version == 6 else "ip"), str(net)


def validate_allow_ssh_cidr(raw: Any) -> str:
    """Canonical CIDR for kirk.allow_ssh_cidrs / lockdown allows, or raise ValueError.

    Rejects junk, over-wide prefixes (``/0``…), and IPv4-mapped IPv6 (``::ffff:…``).
    """
    from ipaddress import IPv4Network, IPv6Network, ip_network

    token = str(raw or "").strip()
    if not token:
        raise ValueError("empty cidr")
    try:
        net = ip_network(token, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid cidr: {token!r}") from exc
    if isinstance(net, IPv4Network):
        if net.prefixlen < 8:
            raise ValueError(f"cidr too wide: {token!r}")
        if net.network_address.is_unspecified and net.prefixlen == 0:
            raise ValueError(f"cidr too wide: {token!r}")
    elif isinstance(net, IPv6Network):
        if net.prefixlen < 32:
            raise ValueError(f"cidr too wide: {token!r}")
        if getattr(net.network_address, "ipv4_mapped", None) is not None:
            raise ValueError(f"ipv4-mapped address not allowed: {token!r}")
    else:
        raise ValueError(f"invalid cidr: {token!r}")
    return str(net)


def validate_allow_ssh_cidrs(raw: list[Any] | None) -> list[str]:
    """Validate a full allow list; raise ValueError on the first bad entry."""
    out: list[str] = []
    for item in raw or []:
        out.append(validate_allow_ssh_cidr(item))
    return out
