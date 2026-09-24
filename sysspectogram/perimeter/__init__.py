from __future__ import annotations

from sysspectogram.perimeter.auth import AuthEvent, AuthWatcher, is_public_ip, parse_auth_lines
from sysspectogram.perimeter.connections import (
    ConnRow,
    egress_external,
    inbound_external,
    listening_ports,
    snapshot_connections,
)
from sysspectogram.perimeter.dns_watch import DnsEvent, DnsWatcher
from sysspectogram.perimeter.enrich import IpEnrichment, enrich_ip_http, reverse_dns
from sysspectogram.perimeter.rules import Alert, Denylist, RuleEngine

__all__ = [
    "AuthEvent",
    "AuthWatcher",
    "is_public_ip",
    "parse_auth_lines",
    "ConnRow",
    "egress_external",
    "inbound_external",
    "listening_ports",
    "snapshot_connections",
    "DnsEvent",
    "DnsWatcher",
    "IpEnrichment",
    "enrich_ip_http",
    "reverse_dns",
    "Alert",
    "Denylist",
    "RuleEngine",
]


def __getattr__(name: str):
    if name == "PerimeterWatcher":
        from sysspectogram.perimeter.watcher import PerimeterWatcher

        return PerimeterWatcher
    raise AttributeError(name)
