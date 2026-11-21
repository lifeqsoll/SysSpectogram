"""Fleet remote timeseries SSH command is injection-safe."""

from __future__ import annotations

import ast
import json

from sysspectogram.fleet.ops import _REMOTE_TS_SCRIPT, build_remote_ts_command


def test_remote_ts_command_quotes_home_and_python():
    cmd = build_remote_ts_command(
        home="/tmp/evil home/ssx",
        python_bin="/tmp/evil home/ssx/.venv/bin/python",
        op="metrics",
    )
    assert "cd '/tmp/evil home/ssx'" in cmd or 'cd "/tmp/evil home/ssx"' in cmd
    assert "&&" in cmd
    assert "-c" in cmd


def test_remote_ts_command_metric_injection_stays_inside_json_payload():
    import base64
    import shlex

    evil = '"; rm -rf /; #'
    cmd = build_remote_ts_command(
        home="/root/.local/share/sysspectogram",
        python_bin="/root/.local/share/sysspectogram/.venv/bin/python",
        op="query",
        metrics=evil,
        range_name="1h",
    )
    # Outer shell only sees cd + python -c <one arg>; payload lives inside that arg.
    before_c, _, after_c = cmd.partition(" -c ")
    assert "rm -rf" not in before_c
    tokens = shlex.split(cmd)
    assert tokens.count("-c") == 1
    script = tokens[tokens.index("-c") + 1]
    assert "rm -rf" in script
    cfg_line = next(line for line in script.splitlines() if line.startswith("sys.argv="))
    # sys.argv=[sys.argv[0], '<json>']
    cfg_json = ast.literal_eval(cfg_line[len("sys.argv=[sys.argv[0], ") : -1])
    cfg = json.loads(cfg_json)
    assert cfg["metrics"] == [evil]
    expected_b64 = base64.b64encode(_REMOTE_TS_SCRIPT.encode("utf-8")).decode("ascii")
    assert expected_b64 in cmd


def test_remote_ts_script_query_downsamples(tmp_path):
    """Run the remote script locally against a tiny sqlite (no SSH)."""
    import sqlite3
    import subprocess
    import sys
    import time

    home = tmp_path
    db = home / "state"
    db.mkdir()
    path = db / "timeseries.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE raw (metric TEXT NOT NULL, ts INTEGER NOT NULL, value REAL NOT NULL, "
        "PRIMARY KEY (metric, ts))"
    )
    now = int(time.time())
    for i in range(1000):
        conn.execute(
            "INSERT INTO raw(metric, ts, value) VALUES (?,?,?)",
            ("host_risk", now - 1000 + i, float(i) / 1000.0),
        )
    conn.commit()
    conn.close()

    cfg = json.dumps(
        {
            "home": str(home),
            "op": "query",
            "metrics": ["host_risk"],
            "range": "1h",
            "max_points": 50,
        }
    )
    # Prefer raw fallback when r10s missing — script falls back to raw.
    proc = subprocess.run(
        [sys.executable, "-c", _REMOTE_TS_SCRIPT, cfg],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    pts = data["series"]["host_risk"]
    assert len(pts) <= 50
    assert len(pts) > 0


def test_remote_ts_script_rejects_unknown_range(tmp_path):
    import subprocess
    import sys

    home = tmp_path
    (home / "state").mkdir()
    # empty missing db → ok empty
    cfg = json.dumps(
        {
            "home": str(home),
            "op": "query",
            "metrics": ["host_risk"],
            "range": "not-a-range",
            "max_points": 10,
        }
    )
    # create empty raw so we hit range check
    import sqlite3

    conn = sqlite3.connect(home / "state" / "timeseries.sqlite")
    conn.execute(
        "CREATE TABLE raw (metric TEXT NOT NULL, ts INTEGER NOT NULL, value REAL NOT NULL, "
        "PRIMARY KEY (metric, ts))"
    )
    conn.commit()
    conn.close()
    proc = subprocess.run(
        [sys.executable, "-c", _REMOTE_TS_SCRIPT, cfg],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)
    assert data["ok"] is False
    assert "bad range" in data["error"]
