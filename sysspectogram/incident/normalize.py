"""Normalize heterogeneous alert records (guard, agent, perimeter) for correlation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_ENTITY_KEYS = ("pid", "comm", "path", "ip")
_IP_KEYS = ("ip", "src_ip", "remote_ip", "peer_ip")
_MAX_TOP_PIDS = 3


def to_epoch(value: Any) -> float | None:
    """Accept epoch seconds (int/float/numeric str) or ISO-8601 (with or without Z)."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _severity(event: Mapping[str, Any]) -> str:
    raw = str(event.get("severity") or "").strip().lower()
    if raw in SEVERITY_ORDER:
        return raw
    if str(event.get("type") or "") == "host_anomaly":
        score = _float(event.get("score"))
        thr = _float(event.get("threshold"))
        if score is not None and thr is not None and score >= thr:
            return "high"
        return "low"
    return "medium"


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _risk(event: Mapping[str, Any]) -> float | None:
    for key in ("risk", "score", "agent_score"):
        val = _float(event.get(key))
        if val is not None:
            return val
    extras = event.get("extras")
    if isinstance(extras, Mapping):
        val = _float(extras.get("agent_score"))
        if val is not None:
            return val
    return None


def _entities(event: Mapping[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    pid = event.get("pid")
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
        out["pid"] = [str(pid)]
    comm = str(event.get("comm") or "").strip()
    if comm:
        out["comm"] = [comm.lower()]
    path = str(event.get("path") or "").strip()
    if path:
        out["path"] = [path]
    for key in _IP_KEYS:
        ip = str(event.get(key) or "").strip()
        if ip:
            out.setdefault("ip", []).append(ip)
    top = event.get("top_processes")
    if isinstance(top, list):
        pids: list[str] = []
        for proc in top[:_MAX_TOP_PIDS]:
            if isinstance(proc, Mapping):
                p = proc.get("pid")
                if isinstance(p, int) and not isinstance(p, bool) and p > 0:
                    pids.append(str(p))
        if pids:
            out.setdefault("pid", []).extend(pids)
    for k in list(out):
        out[k] = sorted(set(out[k]))
    return out


def normalize(event: Mapping[str, Any], source_index: int = -1) -> dict[str, Any] | None:
    """Return a flat record or None when the event has no usable timestamp."""
    ts = to_epoch(event.get("ts"))
    if ts is None:
        return None
    rule = str(event.get("rule_id") or event.get("pattern") or event.get("type") or "unknown")
    return {
        "ts": ts,
        "host_id": str(event.get("host_id") or ""),
        "kind": str(event.get("type") or "agent"),
        "rule_id": rule,
        "severity": _severity(event),
        "message": str(event.get("message") or "")[:300],
        "risk": _risk(event),
        "entities": _entities(event),
        "source_index": source_index,
    }
