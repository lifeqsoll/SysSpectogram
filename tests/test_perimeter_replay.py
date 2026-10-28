"""Offline ``perimeter replay --file`` (parse only, no ban)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_perimeter_replay_fixture(tmp_path: Path) -> None:
    log = tmp_path / "auth-sample.log"
    log.write_text(
        "\n".join(
            [
                "Failed password for root from 203.0.113.9 port 22 ssh2",
                "Invalid user admin from 198.51.100.1 port 22 ssh2",
                "noise line ignored",
            ]
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sysspectogram",
            "perimeter",
            "replay",
            "--file",
            str(log),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["kind"] == "failed"
    assert first["ip"] == "203.0.113.9"
    second = json.loads(lines[1])
    assert second["kind"] == "invalid"
    assert second["ip"] == "198.51.100.1"
