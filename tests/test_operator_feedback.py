"""Operator feedback store tests."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.operator_feedback import OperatorFeedback, process_key


def test_process_key_prefers_basename():
    assert process_key(path="/usr/sbin/nginx", comm="nginx") == "nginx"
    assert process_key(comm="python3") == "python3"


def test_remember_ignore_and_adjust(tmp_path: Path):
    fb = OperatorFeedback(tmp_path / "fb.json")
    e = fb.remember("ignore", comm="curl", path="/usr/bin/curl")
    assert e is not None and e.key == "curl"
    assert fb.is_ignored(comm="curl")
    assert fb.adjust_score(0.9, comm="curl") == 0.0


def test_baseline_and_anomaly(tmp_path: Path):
    fb = OperatorFeedback(tmp_path / "fb.json")
    fb.remember("baseline", name="nginx")
    assert fb.adjust_score(0.8, name="nginx") < 0.4
    fb.remember("anomaly", name="xmrig")
    assert fb.adjust_score(0.2, name="xmrig") >= 0.85
    fb2 = OperatorFeedback(tmp_path / "fb.json")
    assert fb2.is_anomaly(name="xmrig")
