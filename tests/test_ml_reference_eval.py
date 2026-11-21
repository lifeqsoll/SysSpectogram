"""Reference mini-dataset structure for future eval harness (no torch)."""

from __future__ import annotations

import json
from pathlib import Path

REF = Path(__file__).resolve().parent / "data" / "ml_reference_mini.json"

EXPECTED_COLUMNS = ["cpu_percent", "mem_percent", "net_packets_sent_per_s"]


def _load_reference() -> dict:
    return json.loads(REF.read_text(encoding="utf-8"))


def test_ml_reference_mini_columns_and_labels() -> None:
    doc = _load_reference()
    assert doc["schema_version"] == 1
    assert doc["columns"] == EXPECTED_COLUMNS
    windows = doc["windows"]
    assert 2 <= len(windows) <= 8
    labels = {int(w["label"]) for w in windows}
    assert labels == {0, 1}
    ncol = len(doc["columns"])
    for w in windows:
        assert int(w["label"]) in (0, 1)
        for row in w["data"]:
            assert len(row) == ncol