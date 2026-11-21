"""guard-core CLI parity (documentation IPs only: 192.0.2 / 198.51.100 / 203.0.113)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "guard-core"
BIN = CRATE / "target" / "debug" / "sysspectogram-guard-core"

DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


def _bin() -> Path:
    if not BIN.is_file():
        proc = subprocess.run(
            ["cargo", "build", "-q"],
            cwd=CRATE,
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            pytest.fail(proc.stderr or proc.stdout or "cargo build failed")
    assert BIN.is_file(), BIN
    return BIN


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(_bin()), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_metrics_and_once_json() -> None:
    for args in (("metrics",), ("--once",)):
        proc = _run(*args)
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        assert payload["schema_version"] == "1"
        assert 0.0 <= float(payload["cpu_percent"]) <= 100.0
        assert 0.0 <= float(payload["mem_percent"]) <= 100.0


def test_auth_fail_ip_documentation_ranges() -> None:
    cases = {
        "Failed password for root from 203.0.113.9 port 22 ssh2": "203.0.113.9",
        "Invalid user x from 192.0.2.8 from 198.51.100.7 port 22 ssh2": "198.51.100.7",
        "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.15": None,
    }
    # The third line has no ` from <ip>` token, so the parser returns nothing.
    proc = _run(
        "auth-fail-ip",
        "--line",
        "Failed password for root from 203.0.113.9 port 22 ssh2",
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "203.0.113.9"
    assert proc.stdout.strip().startswith(DOC_PREFIXES)

    proc = _run(
        "auth-fail-ip",
        "--line",
        "Invalid user x from 192.0.2.8 from 198.51.100.7 port 22 ssh2",
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "198.51.100.7"

    proc = _run("auth-fail-ip", "--line", "Accepted password for root from 203.0.113.9 port 22")
    assert proc.returncode != 0
    assert proc.stdout.strip() == ""
    assert cases["Failed password for root from 203.0.113.9 port 22 ssh2"].startswith("203.0.113.")


def test_tcp_addr_documentation_ips() -> None:
    # Little-endian /proc/net/tcp fields for TEST-NET addresses.
    proc = _run("tcp-addr", "--field", "0A7100CB:0016")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout.strip())
    assert payload == {"ip": "203.0.113.10", "port": 22}

    proc = _run("tcp-addr", "--field", "010200C0:0050")
    assert json.loads(proc.stdout)["ip"] == "192.0.2.1"
    proc = _run("tcp-addr", "--field", "076433C6:01BB")
    body = json.loads(proc.stdout)
    assert body["ip"] == "198.51.100.7"
    assert body["port"] == 443
    for ip in ("203.0.113.10", "192.0.2.1", "198.51.100.7"):
        assert ip.startswith(DOC_PREFIXES)


def test_render_png(tmp_path: Path) -> None:
    out = tmp_path / "metric.png"
    proc = _run("render", "--points", "[[1, 0.1], [2, 0.4], [3, 0.2]]", "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    blob = out.read_bytes()
    assert blob[:4] == b"\x89PNG"
    assert len(blob) > 32
