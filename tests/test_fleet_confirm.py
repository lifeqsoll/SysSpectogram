"""Fleet destructive ops require --yes when stdin is not a TTY."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, "-m", "sysspectogram", *argv],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_attack_rejects_without_yes(tmp_path: Path):
    fleet = tmp_path / "fleet.json"
    fleet.write_text(
        json.dumps(
            {
                "schema": "fleet.v1",
                "hosts": [
                    {
                        "id": "h1",
                        "label": "h1",
                        "ssh": "user@127.0.0.1",
                        "host_key_line": "ssh-ed25519 AAAA",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = _run(["fleet", "attack", "--scope", "h1", "--level", "L3", "--path", str(fleet)])
    assert proc.returncode == 2, proc.stderr + proc.stdout
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data.get("ok") is False
    assert "need --yes" in str(data.get("error"))


def test_ban_rejects_without_yes(tmp_path: Path):
    fleet = tmp_path / "fleet.json"
    fleet.write_text('{"schema":"fleet.v1","hosts":[]}\n', encoding="utf-8")
    proc = _run(["fleet", "ban", "--ip", "203.0.113.9", "--scope", "all", "--path", str(fleet)])
    assert proc.returncode == 2, proc.stderr + proc.stdout
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data.get("error") == "need --yes"
