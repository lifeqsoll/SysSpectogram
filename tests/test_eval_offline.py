from __future__ import annotations

import json
from pathlib import Path

import numpy as np


def test_eval_offline_zscore(tmp_path, monkeypatch):
    ds = tmp_path / "dataset"
    for split in ("train", "val"):
        for lab in ("normal", "anomaly"):
            (ds / split / lab).mkdir(parents=True)
    rng = np.random.default_rng(0)
    for i in range(6):
        np.save(ds / "train" / "normal" / f"n{i}.npy", rng.normal(size=(60, 4)).astype(np.float32))
        np.save(ds / "val" / "normal" / f"n{i}.npy", rng.normal(size=(60, 4)).astype(np.float32))
    for i in range(6):
        np.save(
            ds / "train" / "anomaly" / f"a{i}.npy",
            (rng.normal(size=(60, 4)) + 5).astype(np.float32),
        )
        np.save(
            ds / "val" / "anomaly" / f"a{i}.npy",
            (rng.normal(size=(60, 4)) + 5).astype(np.float32),
        )
    out = tmp_path / "eval"
    import subprocess
    import sys

    r = subprocess.run(
        [
            sys.executable,
            "scripts/eval_offline.py",
            "--dataset",
            str(ds),
            "--methods",
            "zscore",
            "--out",
            str(out),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert "zscore" in metrics["methods"]
    assert (out / "metrics.md").is_file()
