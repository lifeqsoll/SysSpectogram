"""Append-only attacker dossier + recon_score."""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sysspectogram.osint.cache import ReconCache, dnsbl_zen_listed, get_cache, is_tor_exit


@dataclass
class DossierHit:
    ip: str
    ts: float
    rule_id: str
    severity: str
    asn_org: str | None = None
    country: str | None = None
    recon_score: float = 0.0
    notes: list[str] = field(default_factory=list)


def _slash24(ip: str) -> str:
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return ip


def append_dossier(path: Path, hit: DossierHit) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(hit), ensure_ascii=False) + "\n")


def compute_recon_score(
    *,
    ip: str,
    asn_org: str | None = None,
    country: str | None = None,
    open_ports: list[int] | None = None,
    canary_hit: bool = False,
    cache: ReconCache | None = None,
) -> tuple[float, list[str]]:
    """0..1 score. Uses cache only for DNSBL/Tor (no blocking refresh here)."""
    if canary_hit:
        return 1.0, ["canary_hit"]
    notes: list[str] = []
    score = 0.15
    cache = cache or get_cache()
    zen = dnsbl_zen_listed(ip, cache)
    if zen is True:
        score += 0.45
        notes.append("dnsbl_zen")
    elif zen is False:
        notes.append("dnsbl_clean")
    if is_tor_exit(ip, cache):
        score += 0.25
        notes.append("tor_exit")
    org = (asn_org or "").lower()
    if any(x in org for x in ("digitalocean", "ovh", "hetzner", "contabo", "vultr", "linode", "cloud")):
        score += 0.1
        notes.append("cloud_asn")
    if any(x in org for x in ("consumer", "residential", "telecom", "mobile")):
        score = max(0.05, score - 0.1)
        notes.append("residential_hint")
    ports = open_ports or []
    if len(ports) >= 10:
        score += 0.15
        notes.append("wide_scan")
    return min(1.0, score), notes


def campaign_key(ip: str, asn_org: str | None = None) -> str:
    return f"{_slash24(ip)}|{asn_org or '-'}"


def load_recent_hits(path: Path, *, window_sec: float = 3600.0, limit: int = 500) -> list[dict]:
    if not path.exists():
        return []
    now = time.time()
    out: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if now - float(row.get("ts") or 0) > window_sec:
            break
        out.append(row)
        if len(out) >= limit:
            break
    return out
