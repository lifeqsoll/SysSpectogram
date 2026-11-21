"""Golden alert JSON from guard-core matches perimeter Alert field set."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "guard-core" / "fixtures" / "alert_bruteforce.json"

REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "rule_id",
        "severity",
        "message",
        "ip",
        "port",
        "extras",
        "ts",
    }
)


def test_golden_alert_schema_keys() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert REQUIRED_KEYS <= set(data.keys())
    assert data["schema_version"] == "1"
    assert data["rule_id"] == "bruteforce_ssh"
    assert isinstance(data["extras"], dict)