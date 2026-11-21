"""Guard-scoring feature events for weak-label training (schema v1, JSONL stream)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

FEATURE_SCHEMA_VERSION = 1

_POSITIVE = frozenset({"ban", "kill", "isolate"})
_NEGATIVE = frozenset({"mute", "fp", "allow", "false_positive", "host_fp"})


@dataclass
class FeatureEvent:
    """One scored guard tick aligned with operator feedback for later ML."""

    rule_id: str
    severity: str
    exe: str
    ppid: int
    scores: dict[str, float]
    ts: float
    schema_version: int = FEATURE_SCHEMA_VERSION
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def append_feature_event(path: Path, event: FeatureEvent) -> None:
    """Append one event as a JSONL line (creates parent dirs)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")


def weak_label_from_decision(action: str) -> int | None:
    """Map operator/guard response to weak supervision: +1 bad, -1 benign, None skip."""
    key = (action or "").strip().lower().replace("-", "_")
    if key in ("ignore", ""):
        return None
    if key in _POSITIVE:
        return 1
    if key in _NEGATIVE:
        return -1
    return None