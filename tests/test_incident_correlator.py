from __future__ import annotations

import json

from sysspectogram.incident.attack_map import techniques_for
from sysspectogram.incident.correlator import correlate
from sysspectogram.incident.normalize import to_epoch
from sysspectogram.incident.report import render_html
from sysspectogram.incident.store import find_incident, upsert_incidents


def test_to_epoch_accepts_epoch_and_iso():
    assert to_epoch(1_700_000_000) == 1_700_000_000.0
    assert to_epoch("2023-11-14T22:13:20+00:00") == 1_700_000_000.0


def test_shared_pid_within_window_is_one_incident():
    events = [
        {"ts": 1000.0, "host_id": "h", "type": "agent", "rule_id": "exec", "pid": 42, "comm": "sh"},
        {"ts": 1100.0, "host_id": "h", "type": "agent", "rule_id": "openat", "pid": 42, "comm": "sh"},
        {"ts": 9000.0, "host_id": "h", "type": "agent", "rule_id": "exec", "pid": 7, "comm": "cron"},
    ]
    incidents = correlate(events, window_sec=300.0)
    assert len(incidents) == 2
    big = max(incidents, key=lambda i: i["event_count"])
    assert big["event_count"] == 2
    assert big["schema"] == "incident.v1"


def test_different_hosts_never_merge():
    events = [
        {"ts": 1000.0, "host_id": "a", "rule_id": "exec", "pid": 42},
        {"ts": 1001.0, "host_id": "b", "rule_id": "exec", "pid": 42},
    ]
    assert len(correlate(events)) == 2


def test_unknown_rule_has_no_techniques():
    assert techniques_for("definitely_not_a_rule") == []


def test_html_report_escapes_message():
    events = [{"ts": 1000.0, "host_id": "h", "rule_id": "x", "pid": 1, "message": "<script>alert(1)</script>"}]
    inc = correlate(events)[0]
    html = render_html(inc)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_store_upsert_is_idempotent(tmp_path):
    path = tmp_path / "incidents.jsonl"
    events = [{"ts": 1000.0, "host_id": "h", "rule_id": "x", "pid": 1}]
    incidents = correlate(events)
    upsert_incidents(path, incidents)
    upsert_incidents(path, incidents)
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert find_incident(path, incidents[0]["id"]) is not None
