"""Parity: Rust RuleEngine / decide_risk via serve socket."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from sysspectogram.guard_core_bridge import find_bin
from sysspectogram.guard_core_client import GuardCoreClient, ensure_guard_core_serve
from sysspectogram.perimeter.rules import RuleEngine
from sysspectogram.risk import decide_risk


@pytest.fixture(scope="module")
def core_sock(tmp_path_factory):
    root = Path(__file__).resolve().parents[1] / "guard-core"
    exe = find_bin()
    built = root / "target" / "debug" / "sysspectogram-guard-core"
    if exe is None and not built.is_file():
        proc = subprocess.run(
            ["cargo", "build", "-q"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            pytest.skip(proc.stderr or "cargo build failed")
    sock = tmp_path_factory.mktemp("gc") / "guard-core.sock"
    ensure_guard_core_serve(sock, bin_path=find_bin() or built)
    for _ in range(40):
        if sock.is_socket():
            break
        time.sleep(0.05)
    if not sock.is_socket():
        pytest.skip("guard-core serve did not bind")
    yield sock


def test_rust_bruteforce_matches_python(core_sock: Path):
    client = GuardCoreClient(core_sock)
    client.configure_rules(fail_threshold=5, allowlist=[])
    py = RuleEngine(fail_threshold=5, fail_window_sec=60)
    last_py = last_rs = None
    for _ in range(5):
        last_py = py.on_auth_fail("203.0.113.20", "root")
        last_rs = client.on_auth_fail("203.0.113.20", "root")
    assert last_py is not None and last_rs is not None
    assert last_py.rule_id == last_rs.rule_id == "bruteforce_ssh"
    assert last_rs.ip == "203.0.113.20"


def test_rust_port_scan_per_source(core_sock: Path):
    client = GuardCoreClient(core_sock)
    # fresh engine state is process-global — use a fresh IP
    client.configure_rules(
        scan_unique_ports=4,
        public_ports=[80, 443],
        fail_threshold=99,
    )
    last = None
    for port in (22, 23, 25, 8080):
        a = client.on_inbound("198.51.100.50", port)
        if a:
            last = a
    assert last is not None
    assert last.rule_id == "port_scan_suspected"
    assert last.ip == "198.51.100.50"


def test_decide_risk_parity(core_sock: Path):
    client = GuardCoreClient(core_sock)
    from sysspectogram.guard_core_client import set_risk_client

    set_risk_client(client)
    try:
        py = decide_risk(0.9, None, None, host_threshold=0.7, risk_threshold=0.8)
        # force python path by clearing client briefly for comparison values
        set_risk_client(None)
        py2 = decide_risk(0.9, None, None, host_threshold=0.7, risk_threshold=0.8)
        set_risk_client(client)
        rs = decide_risk(0.9, None, None, host_threshold=0.7, risk_threshold=0.8)
        assert py2.is_anomaly and rs.is_anomaly
        assert rs.reason == py2.reason == "host"
        assert abs(rs.risk - py2.risk) < 1e-9
        assert py.is_anomaly
    finally:
        set_risk_client(None)
