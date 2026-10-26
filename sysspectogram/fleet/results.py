"""Structured per-host fleet op results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FleetHostResult:
    host_id: str
    ok: bool
    error: str | None = None
    latency_ms: float | None = None
    detail: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d.get("error"):
            d.pop("error", None)
        if d.get("latency_ms") is None:
            d.pop("latency_ms", None)
        if not d.get("detail"):
            d.pop("detail", None)
        return d


@dataclass
class FleetOpReport:
    ok: bool
    scope: str
    results: list[FleetHostResult] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ok": self.ok,
            "scope": self.scope,
            "results": [r.to_dict() for r in self.results],
        }
        out.update(self.extra)
        return out


def wrap_host_dict(row: dict[str, Any], *, latency_ms: float | None = None) -> FleetHostResult:
    host_id = str(row.get("host_id") or row.get("id") or "?")
    ok = bool(row.get("ok"))
    err = row.get("error")
    if err is not None:
        err = str(err)
    lat = latency_ms
    if lat is None and row.get("latency_ms") is not None:
        try:
            lat = float(row["latency_ms"])
        except (TypeError, ValueError):
            lat = None
    detail = {
        k: v
        for k, v in row.items()
        if k not in ("host_id", "id", "ok", "error", "latency_ms")
    }
    return FleetHostResult(
        host_id=host_id,
        ok=ok,
        error=err,
        latency_ms=lat,
        detail=detail or None,
    )
