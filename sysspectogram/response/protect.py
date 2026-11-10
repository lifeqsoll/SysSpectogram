"""Admin / self-ban protection (F-07)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from ipaddress import ip_address, ip_network
from typing import Iterable


def _host_addrs() -> set[str]:
    out: set[str] = set()
    try:
        import psutil

        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family.name in {"AF_INET", "AF_INET6"} and a.address:
                    # strip zone id
                    out.add(a.address.split("%", 1)[0])
    except Exception:
        pass
    return out


def _ssh_session_ips(*, ssh_port: int = 22) -> set[str]:
    ips: set[str] = set()
    env = os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT") or ""
    if env:
        parts = env.split()
        if parts:
            ips.add(parts[0].split("%", 1)[0])
    if not shutil.which("ss"):
        return ips
    try:
        proc = subprocess.run(
            ["ss", "-Htn", "state", "established", f"( sport = :{int(ssh_port)} )"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ips
    # peer address is last column-ish: 203.0.113.5:45678
    for line in (proc.stdout or "").splitlines():
        m = re.search(r"\[?([0-9a-fA-F:.]+)\]?:(\d+)\s*$", line.strip())
        if not m:
            cols = line.split()
            if len(cols) >= 4:
                peer = cols[3]
                host = peer.rsplit(":", 1)[0].strip("[]")
                ips.add(host)
            continue
        ips.add(m.group(1))
    return ips


def _resolver_addrs() -> set[str]:
    """Nameservers from resolv.conf and resolvectl (non-loopback)."""
    from sysspectogram.net_ip import unwrap_mapped_ip

    out: set[str] = set()
    try:
        text = __import__("pathlib").Path("/etc/resolv.conf").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        text = ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        try:
            addr = unwrap_mapped_ip(ip_address(parts[1].split("%", 1)[0]))
        except ValueError:
            continue
        if addr.is_loopback:
            continue
        out.add(str(addr))
    try:
        from sysspectogram.response.actions import _resolvectl_upstreams

        for spec in _resolvectl_upstreams():
            out.add(str(spec[1]))
    except Exception:
        pass
    return out


def _gateway_addrs() -> set[str]:
    """Default gateway(s) from ``ip route``."""
    from sysspectogram.net_ip import unwrap_mapped_ip

    if not shutil.which("ip"):
        return set()
    out: set[str] = set()
    try:
        proc = subprocess.run(
            ["ip", "-o", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return out
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if "via" not in parts:
            continue
        idx = parts.index("via")
        if idx + 1 >= len(parts):
            continue
        try:
            addr = unwrap_mapped_ip(ip_address(parts[idx + 1].split("%", 1)[0]))
        except ValueError:
            continue
        out.add(str(addr))
    return out


def is_protected(
    ip: str,
    *,
    never_ban_cidrs: Iterable[str] | None = None,
    ignoreself: bool = True,
    protect_ssh_sessions: bool = True,
    allow_private_bans: bool = False,
    extra_cidrs: Iterable[str] | None = None,
) -> str | None:
    """Return reason string if ``ip`` must not be auto-banned, else None."""
    from sysspectogram.net_ip import is_lan_like, unwrap_mapped_ip

    try:
        addr = unwrap_mapped_ip(ip_address(str(ip).strip()))
    except ValueError:
        return "invalid ip"
    if ignoreself:
        if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast:
            return "ignoreself special"
        if str(addr) in _host_addrs():
            return "ignoreself host address"
    if not allow_private_bans and is_lan_like(addr):
        return "private/ULA/CGNAT"
    try:
        from sysspectogram.response.actions import DEFAULT_TELEGRAM_EGRESS_CIDRS
    except Exception:
        DEFAULT_TELEGRAM_EGRESS_CIDRS = ()
    protect_nets = list(DEFAULT_TELEGRAM_EGRESS_CIDRS) + [str(c) for c in (extra_cidrs or [])]
    for cidr in protect_nets:
        try:
            if addr in ip_network(str(cidr).strip(), strict=False):
                return f"telegram/egress {cidr}"
        except ValueError:
            continue
    if str(addr) in _resolver_addrs():
        return "resolver"
    if str(addr) in _gateway_addrs():
        return "default gateway"
    for cidr in never_ban_cidrs or []:
        try:
            if addr in ip_network(str(cidr).strip(), strict=False):
                return f"never_ban {cidr}"
        except ValueError:
            continue
    if protect_ssh_sessions and str(addr) in _ssh_session_ips():
        return "active ssh session"
    return None
