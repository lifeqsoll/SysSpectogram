"""Repeated-ban TTL multiplier (fail2ban-style ``bantime.increment``).

Counter lives under ``SYSSPECTOGRAM_HOME/state/ban_repeat.json``. Window defaults
to 7 days; TTL grows ``base * 2**(n-1)`` capped at ``max_ban_ttl_sec``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root

DEFAULT_WINDOW_SEC = 7 * 24 * 3600


def _path() -> Path:
    return state_root() / "state" / "ban_repeat.json"


def _load() -> dict[str, Any]:
    path = _path()
    if not path.is_file():
        return {"ips": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ips": {}}
    if not isinstance(data, dict):
        return {"ips": {}}
    ips = data.get("ips")
    if not isinstance(ips, dict):
        data["ips"] = {}
    return data


def _save(data: dict[str, Any]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def next_ttl(
    ip: str,
    *,
    base_ttl: float,
    max_ban_ttl_sec: float,
    enabled: bool = True,
    window_sec: float = DEFAULT_WINDOW_SEC,
    now: float | None = None,
) -> float:
    """Return clamped TTL and bump the per-IP repeat counter when ``enabled``."""
    base = max(60.0, float(base_ttl))
    cap = max(base, float(max_ban_ttl_sec))
    if not enabled:
        return min(base, cap)
    ts = float(now if now is not None else time.time())
    data = _load()
    ips: dict[str, Any] = data.setdefault("ips", {})
    # prune stale
    stale = [
        k
        for k, v in list(ips.items())
        if not isinstance(v, dict) or ts - float(v.get("last", 0) or 0) > window_sec
    ]
    for k in stale:
        ips.pop(k, None)
    row = ips.get(ip) if isinstance(ips.get(ip), dict) else None
    count = 0
    if row is not None and ts - float(row.get("last", 0) or 0) <= window_sec:
        count = int(row.get("count", 0) or 0)
    count += 1
    ips[ip] = {"count": count, "last": ts}
    data["ips"] = ips
    _save(data)
    # 1st ban: 1x, 2nd: 2x, 3rd: 4x, …
    mult = 2 ** max(0, count - 1)
    return min(base * mult, cap)
