"""Strict IP parsing for ban / never-ban paths (no CIDR injection, no nft metacharacters)."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from typing import Any

# RFC1918 / CGNAT / ULA only — not TEST-NET (192.0.2.0/24, 203.0.113.0/24, 2001:db8::/32).
# Python ``is_private`` treats documentation ranges as private.
_RFC1918 = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
_CGNAT = IPv4Network("100.64.0.0/10")
_ULA = IPv6Network("fc00::/7")


def unwrap_mapped_ip(addr: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
    """Map ``::ffff:x.x.x.x`` to the inner IPv4 address."""
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def is_lan_like(addr: IPv4Address | IPv6Address) -> bool:
    """True for RFC1918, ULA, and CGNAT (spoofed SYN must not ban these)."""
    addr = unwrap_mapped_ip(addr)
    if isinstance(addr, IPv4Address):
        return any(addr in net for net in _RFC1918) or addr in _CGNAT
    if isinstance(addr, IPv6Address):
        return addr in _ULA
    return False


def parse_ban_ip(raw: Any, *, allow_private: bool = False) -> str:
    """Return a canonical single-host IP string, or raise ValueError.

    Rejects CIDRs (``0.0.0.0/0``), unspecified/loopback/link-local, zone IDs
    (``fe80::1%eth0``), junk, and metacharacters.
    Private / ULA / CGNAT are refused unless ``allow_private`` is true.
    Use this on every ban/unban path before nft/iptables.
    """
    token = str(raw or "").strip()
    if not token or "/" in token or "%" in token:
        raise ValueError(f"invalid ban ip: {token!r}")
    if any(c in token for c in ";|&`$(){}[]<>\\\"' \t\n\r"):
        raise ValueError(f"invalid ban ip: {token!r}")
    raw_addr = ip_address(token)
    if getattr(raw_addr, "ipv4_mapped", None) is not None:
        raise ValueError(f"refusing ban of special address: {raw_addr}")
    addr = unwrap_mapped_ip(raw_addr)
    if not isinstance(addr, (IPv4Address, IPv6Address)):
        raise ValueError(f"invalid ban ip: {token!r}")
    if (
        addr.is_unspecified
        or addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
    ):
        raise ValueError(f"refusing ban of special address: {addr}")
    if isinstance(addr, IPv4Address) and (int(addr) == 0xFFFFFFFF or addr.packed[0] >= 240):
        raise ValueError(f"refusing ban of special address: {addr}")
    if not allow_private and is_lan_like(addr):
        raise ValueError(f"refusing ban of private/ULA/CGNAT address: {addr}")
    return str(addr)


def parse_ban_target(raw: Any, *, allow_private: bool = False) -> str:
    """Host IP or IPv6 prefix (``2001:db8:1::/64``) for ban sets with interval."""
    token = str(raw or "").strip()
    if "/" not in token:
        return parse_ban_ip(token, allow_private=allow_private)
    from ipaddress import ip_network

    if any(c in token for c in ";|&`$(){}[]<>\\\"' \t\n\r"):
        raise ValueError(f"invalid ban target: {token!r}")
    try:
        net = ip_network(token, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid ban target: {token!r}") from exc
    if net.version != 6:
        raise ValueError(f"IPv4 prefix bans are not supported: {token!r}")
    if net.prefixlen < 48 or net.prefixlen > 128:
        raise ValueError(f"IPv6 ban prefix must be /48../128: {token!r}")
    if not allow_private and is_lan_like(net.network_address):
        raise ValueError(f"refusing ban of private/ULA/CGNAT address: {net}")
    return str(net)


def nft_saddr_family(ip: str, *, allow_private: bool = False) -> tuple[str, str]:
    """Return ``(family_token, canonical_ip_or_cidr)`` for nft: ``ip`` or ``ip6``."""
    if "/" in str(ip):
        canonical = parse_ban_target(ip, allow_private=allow_private)
        return "ip6", canonical
    canonical = parse_ban_ip(ip, allow_private=allow_private)
    addr = ip_address(canonical)
    return ("ip6" if addr.version == 6 else "ip"), canonical


def validate_v6_brute_prefix(raw: object) -> int:
    """Return 0 (off) or an integer in 48..128. Reject junk that used to crash guard."""
    if raw is None or raw is False:
        return 0
    if isinstance(raw, bool):
        raise ValueError(f"perimeter.v6_brute_prefix must be 0 or 48..128, got {raw!r}")
    if isinstance(raw, float):
        if not raw.is_integer():
            raise ValueError(f"perimeter.v6_brute_prefix must be 0 or 48..128, got {raw!r}")
        raw = int(raw)
    if isinstance(raw, str):
        if not raw.isascii() or not raw.isdigit():
            raise ValueError(f"perimeter.v6_brute_prefix must be 0 or 48..128, got {raw!r}")
        raw = int(raw)
    if not isinstance(raw, int):
        raise ValueError(f"perimeter.v6_brute_prefix must be 0 or 48..128, got {raw!r}")
    if raw == 0:
        return 0
    if 48 <= raw <= 128:
        return raw
    raise ValueError(f"perimeter.v6_brute_prefix must be 0 or 48..128, got {raw!r}")


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
