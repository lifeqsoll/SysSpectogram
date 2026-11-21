"""Per-rule EWMA thresholds. Critical is never softened."""

from __future__ import annotations

import json
from pathlib import Path

from sysspectogram.ml.rule_thresholds import RuleThresholdStore


def test_fp_softens_high_but_never_critical(tmp_path: Path) -> None:
    path = tmp_path / "state" / "rule_thresholds.json"
    store = RuleThresholdStore(path, alpha=1.0)
    store.record_fp("port_scan")
    assert store.effective_severity_adjust("port_scan", "high") == "medium"
    assert store.effective_severity_adjust("port_scan", "critical") == "critical"
    assert store.effective_severity_adjust("port_scan", "CRITICAL") == "critical"
    for _ in range(8):
        store.record_fp("bruteforce_ssh")
    assert store.effective_severity_adjust("bruteforce_ssh", "critical") == "critical"


def test_hit_pulls_ewma_back(tmp_path: Path) -> None:
    path = tmp_path / "thresholds.json"
    store = RuleThresholdStore(path, alpha=1.0)
    store.record_fp("scan")
    assert store.effective_severity_adjust("scan", "medium") == "low"
    store.record_hit("scan", severity="medium")
    assert store.effective_severity_adjust("scan", "medium") == "medium"
    store.flush()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["rules"]["scan"]["hits"] == 1
    assert payload["rules"]["scan"]["fps"] == 1
    assert payload["rules"]["scan"]["base_severity"] == "medium"


def test_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "thresholds.json"
    RuleThresholdStore(path, alpha=1.0).record_fp("egress")
    again = RuleThresholdStore(path, alpha=1.0)
    assert again.effective_severity_adjust("egress", "high") == "medium"
    assert again.rules["egress"]["threshold"] > 0.5


def test_disabled_store_does_not_change_severity(tmp_path: Path) -> None:
    path = tmp_path / "thresholds.json"
    store = RuleThresholdStore(path, enabled=False)
    store.record_fp("scan")
    store.record_hit("scan", severity="high")
    assert store.effective_severity_adjust("scan", "high") == "high"
    assert store.effective_severity_adjust("scan", "critical") == "critical"
    assert not path.exists()
