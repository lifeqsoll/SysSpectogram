"""Tail local alert/incident JSONL for fleet aggregation."""

from __future__ import annotations

import json
from typing import Any

from sysspectogram.config import state_root


def feed_tail(*, limit: int = 40, host_id: str | None = None) -> dict[str, Any]:
    root = state_root()
    rows: list[dict[str, Any]] = []
    for name in ("incidents.jsonl", "alerts.jsonl"):
        path = root / "reports" / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, limit) :]
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            if host_id:
                obj.setdefault("host_id", host_id)
            obj["_source_file"] = name
            rows.append(obj)
    return {"ok": True, "rows": rows[-max(1, limit) :], "n": len(rows)}


def record_false_positive(*, label: str = "host_fp", source: str = "local") -> dict[str, Any]:
    path = state_root() / "state" / "operator_feedback.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data: list[Any] = []
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                data = raw
            elif isinstance(raw, dict):
                data = list(raw.get("entries") or [])
        except (OSError, json.JSONDecodeError):
            data = []
    import time

    data.append({"ts": time.time(), "kind": "false_positive", "label": label, "source": source})
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return {"ok": True, "n": len(data), "path": str(path)}
