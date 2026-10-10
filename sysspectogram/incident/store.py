"""JSONL store for incidents (schema incident.v1). Upsert by id, atomic replace."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping


def read_incidents(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("schema") == "incident.v1" and obj.get("id"):
            out.append(obj)
    return out


def upsert_incidents(path: Path, incidents: Iterable[Mapping[str, Any]]) -> int:
    """Merge new incidents into the store by id. Returns the number written."""
    existing = {inc["id"]: inc for inc in read_incidents(path)}
    count = 0
    for inc in incidents:
        existing[str(inc["id"])] = dict(inc)
        count += 1
    ordered = sorted(existing.values(), key=lambda i: float(i.get("first_ts") or 0.0))
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for inc in ordered:
            fh.write(json.dumps(inc, ensure_ascii=False, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return count


def find_incident(path: Path, incident_id: str) -> dict[str, Any] | None:
    for inc in read_incidents(path):
        if inc.get("id") == incident_id:
            return inc
    return None
