"""Feature event schema and weak labels (§5.3 prep)."""

from __future__ import annotations

import json
from pathlib import Path

from sysspectogram.ml.feature_events import (
    FEATURE_SCHEMA_VERSION,
    FeatureEvent,
    append_feature_event,
    weak_label_from_decision,
)


def test_feature_event_schema_version_and_jsonl(tmp_path: Path) -> None:
    ev = FeatureEvent(
        rule_id="R-TEST",
        severity="high",
        exe="/usr/bin/curl",
        ppid=1,
        scores={"fuse": 0.91, "host_score": 0.88},
        ts=1_700_000_000.0,
        extras={"comm": "curl"},
    )
    assert ev.schema_version == FEATURE_SCHEMA_VERSION
    assert ev.to_dict()["schema_version"] == 1

    out = tmp_path / "features.jsonl"
    append_feature_event(out, ev)
    line = json.loads(out.read_text(encoding="utf-8").strip())
    assert line["rule_id"] == "R-TEST"
    assert line["scores"]["fuse"] == 0.91
    assert line["schema_version"] == FEATURE_SCHEMA_VERSION


def test_weak_label_from_decision() -> None:
    assert weak_label_from_decision("ban") == 1
    assert weak_label_from_decision("KILL") == 1
    assert weak_label_from_decision("isolate") == 1
    assert weak_label_from_decision("mute") == -1
    assert weak_label_from_decision("fp") == -1
    assert weak_label_from_decision("allow") == -1
    assert weak_label_from_decision("host_fp") == -1
    assert weak_label_from_decision("ignore") is None
    assert weak_label_from_decision("") is None
    assert weak_label_from_decision("recon") is None