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


def test_telegram_decisions_append_weak_labels(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    from sysspectogram.telegram_bot import TelegramBot

    class _Client:
        pass

    bot = TelegramBot(_Client(), config={"ml": {}}, nft=object())
    bot._note_weak_label("ban", {"ip": "203.0.113.10", "rule": "bruteforce_ssh"})
    bot._note_weak_label("ignore", {"ip": "203.0.113.10", "rule": "bruteforce_ssh"})
    bot._note_weak_label("host_fp", {"score": 0.2})
    bot._note_weak_label("mute", {"ip": "198.51.100.7", "rule": "port_scan"})
    dest = tmp_path / "reports" / "feature_events.jsonl"
    rows = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines()]
    labels = [(row["extras"]["action"], row["extras"]["weak_label"]) for row in rows]
    assert ("ban", 1) in labels
    assert ("mute", -1) in labels
    assert ("host_fp", -1) in labels
    assert all(row["extras"]["action"] != "ignore" for row in rows)
    assert any(row["rule_id"] == "host_anomaly" for row in rows)
    assert "ml_phase=off" in bot._status_text()