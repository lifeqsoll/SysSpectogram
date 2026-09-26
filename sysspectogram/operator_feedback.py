"""Operator feedback: ignore / baseline / anomaly for processes."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Kind = Literal["ignore", "baseline", "anomaly"]


@dataclass
class FeedbackEntry:
    kind: Kind
    key: str
    ts: float = field(default_factory=time.time)
    rule_id: str = ""
    path: str = ""
    note: str = ""


def process_key(*, comm: str | None = None, path: str | None = None, name: str | None = None) -> str:
    """Stable key for a process identity (prefer basename of path, else comm/name)."""
    if path:
        base = Path(path).name.strip()
        if base and base not in (".", "/"):
            return base.lower()
    for raw in (comm, name):
        if raw:
            s = str(raw).strip().lower()
            if s:
                return s
    return ""


class OperatorFeedback:
    """Persisted process memories used to mute FP and boost known-bad shapes."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.entries: dict[str, FeedbackEntry] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        rows = data.get("entries") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or "").strip().lower()
            kind = str(row.get("kind") or "")
            if not key or kind not in ("ignore", "baseline", "anomaly"):
                continue
            self.entries[key] = FeedbackEntry(
                kind=kind,  # type: ignore[arg-type]
                key=key,
                ts=float(row.get("ts") or time.time()),
                rule_id=str(row.get("rule_id") or ""),
                path=str(row.get("path") or ""),
                note=str(row.get("note") or ""),
            )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "sysspectogram.operator_feedback.v1",
            "entries": [asdict(e) for e in self.entries.values()],
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def remember(
        self,
        kind: Kind,
        *,
        comm: str | None = None,
        path: str | None = None,
        name: str | None = None,
        rule_id: str = "",
        note: str = "",
    ) -> FeedbackEntry | None:
        key = process_key(comm=comm, path=path, name=name)
        if not key:
            return None
        entry = FeedbackEntry(
            kind=kind,
            key=key,
            rule_id=rule_id or "",
            path=(path or "")[:512],
            note=note[:200],
        )
        with self._lock:
            self.entries[key] = entry
            self.save()
        return entry

    def forget(self, key: str) -> bool:
        key = key.strip().lower()
        with self._lock:
            if key not in self.entries:
                return False
            del self.entries[key]
            self.save()
            return True

    def lookup(
        self,
        *,
        comm: str | None = None,
        path: str | None = None,
        name: str | None = None,
    ) -> FeedbackEntry | None:
        key = process_key(comm=comm, path=path, name=name)
        if not key:
            return None
        with self._lock:
            return self.entries.get(key)

    def is_ignored(self, **kwargs: Any) -> bool:
        e = self.lookup(**kwargs)
        return e is not None and e.kind == "ignore"

    def is_baseline(self, **kwargs: Any) -> bool:
        e = self.lookup(**kwargs)
        return e is not None and e.kind == "baseline"

    def is_anomaly(self, **kwargs: Any) -> bool:
        e = self.lookup(**kwargs)
        return e is not None and e.kind == "anomaly"

    def adjust_score(self, score: float, **kwargs: Any) -> float:
        """baseline lowers score; anomaly raises it toward 1.0."""
        e = self.lookup(**kwargs)
        if e is None:
            return float(score)
        s = float(score)
        if e.kind == "ignore":
            return 0.0
        if e.kind == "baseline":
            return max(0.0, s * 0.35)
        if e.kind == "anomaly":
            return min(1.0, max(s, 0.85) + 0.1)
        return s
