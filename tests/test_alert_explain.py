"""Phase 7.6 — CPU spike is primary feature; no miner diagnosis."""

from __future__ import annotations

import numpy as np

from sysspectogram.ml.explain import plain_ml_line


def test_plain_ml_line_names_cpu_first() -> None:
    cols = ["cpu_percent", "mem_percent", "net_packets_sent_per_s"]
    w = np.ones((60, 3), dtype=np.float32) * 10.0
    w[:, 0] = 95.0  # CPU spike
    out = plain_ml_line(w, cols, lang="en")
    assert out["primary"] == "cpu_percent"
    assert "cpu" in out["sentence"].lower()
    assert out["top_features"][0]["feature"] == "cpu_percent"
    low = out["sentence"].lower()
    assert "miner" not in low
    assert "malware" not in low
    ru = plain_ml_line(w, cols, lang="ru")
    assert "майнер" not in ru["sentence"].lower()
