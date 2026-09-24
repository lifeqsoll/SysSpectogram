from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")


def build_report(
    *,
    processes: list[dict] | None = None,
    suspicious: list[dict] | None = None,
    ports: dict | None = None,
    anomalies: list[dict] | None = None,
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "sysspectogram",
        "processes_top": processes or [],
        "suspicious_processes": suspicious or [],
        "ports": ports or {},
        "anomalies": anomalies or [],
    }
