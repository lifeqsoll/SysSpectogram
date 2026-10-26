from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


@dataclass
class IpEnrichment:
    ip: str
    ptr: str | None = None
    asn_org: str | None = None
    country: str | None = None
    raw: dict = field(default_factory=dict)


def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        return None


def enrich_ip_http(ip: str, timeout: float = 4.0) -> IpEnrichment:
    """Best-effort free enrichment via ipapi.co (soft-fail)."""
    from sysspectogram.net_ip import parse_ban_ip

    ip = parse_ban_ip(ip)
    info = IpEnrichment(ip=ip, ptr=reverse_dns(ip))
    # Path-safe: parse_ban_ip already rejected ../ and metacharacters.
    url = f"https://ipapi.co/{urllib.parse.quote(ip, safe=':')}/json/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sysspectogram/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(data, dict) and not data.get("error"):
            info.asn_org = data.get("org") or data.get("asn")
            info.country = data.get("country_name") or data.get("country")
            info.raw = data
    except Exception:
        pass
    return info
