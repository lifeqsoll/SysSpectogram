"""Process label rules tests."""

from __future__ import annotations

import json
from pathlib import Path

from sysspectogram.process_labels import ProcessLabelRule, ProcessLabelStore, process_key
from sysspectogram.role_fp import seed_role_labels


def test_process_key_prefers_basename():
    assert process_key(path="/usr/bin/firefox", comm="foo") == "firefox"
    assert process_key(comm="sshd") == "sshd"


def test_exact_and_priority(tmp_path: Path):
    store = ProcessLabelStore(tmp_path / "labels.json")
    store.add_from_alert("baseline", comm="firefox", widen=False)
    store.add_from_alert("anomaly", comm="firefox", widen=False)
    m = store.match(comm="firefox")
    assert m is not None
    assert m.label == "anomaly"  # anomaly wins over baseline


def test_comm_prefix_widen(tmp_path: Path):
    store = ProcessLabelStore(tmp_path / "labels.json")
    created = store.add_from_alert("baseline", comm="firefox", widen="comm_prefix")
    assert len(created) >= 2
    assert store.match(comm="firefox-bin") is not None
    assert store.adjust_score(0.9, comm="firefox-bin") < 0.5


def test_path_glob(tmp_path: Path):
    store = ProcessLabelStore(tmp_path / "labels.json")
    store.add_rule(
        ProcessLabelRule(
            id="1",
            label="baseline",
            match="path_glob",
            pattern="/usr/lib/firefox/*",
            source="test",
        )
    )
    assert store.match(path="/usr/lib/firefox/firefox") is not None


def test_migrate_v1(tmp_path: Path):
    legacy = tmp_path / "operator_feedback.json"
    legacy.write_text(
        json.dumps(
            {
                "schema": "sysspectogram.operator_feedback.v1",
                "entries": [{"key": "nginx", "kind": "baseline", "ts": 1.0}],
            }
        ),
        encoding="utf-8",
    )
    store = ProcessLabelStore(tmp_path / "process_labels.json")
    # trigger migrate by constructing with empty then loading legacy path
    store2 = ProcessLabelStore(tmp_path / "missing.json")
    # manual migrate helper: load v1 file into store
    data = json.loads(legacy.read_text(encoding="utf-8"))
    store2._load_v1_entries(data["entries"])
    assert store2.match(comm="nginx") is not None


def test_seed_ssh(tmp_path: Path):
    store = ProcessLabelStore(tmp_path / "labels.json")
    n = seed_role_labels(store, "ssh")
    assert n > 3
    assert store.is_baseline(comm="sshd")


def test_mute_rule_id(tmp_path: Path):
    store = ProcessLabelStore(tmp_path / "labels.json")
    # No process identity — remember still mutes by rule_id
    entry = store.remember("ignore", rule_id="agent_kirk_module_hide")
    assert entry is not None
    assert entry.match == "rule_id"
    assert store.is_rule_muted("agent_kirk_module_hide")
    assert not store.is_rule_muted("agent_kirk_pid_hide")
    # Persists
    store2 = ProcessLabelStore(tmp_path / "labels.json")
    assert store2.is_rule_muted("agent_kirk_module_hide")
