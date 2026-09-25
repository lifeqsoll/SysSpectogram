from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

from sysspectogram.agent_bridge import AgentAlert, AgentSocketListener


def test_agent_alert_from_dict():
    a = AgentAlert.from_dict(
        {
            "rule_id": "agent_open_sensitive",
            "severity": "high",
            "message": "touch ssh",
            "pid": 42,
            "path": "/root/.ssh/id_rsa",
        }
    )
    assert a.rule_id == "agent_open_sensitive"
    assert a.pid == 42
    assert a.path.endswith("id_rsa")


def test_agent_socket_listener_roundtrip(tmp_path: Path):
    sock_path = tmp_path / "agent.sock"
    got: list[AgentAlert] = []
    ready = threading.Event()

    def on_alert(a: AgentAlert) -> None:
        got.append(a)
        ready.set()

    listener = AgentSocketListener(sock_path, on_alert=on_alert, cooldown_sec=0)
    listener.start()
    time.sleep(0.25)

    payload = {
        "schema": "sysspectogram.agent.v1",
        "kind": "agent",
        "rule_id": "agent_module_load",
        "severity": "high",
        "message": "new kernel module appeared: demo",
        "host_id": "test",
        "ts": time.time(),
        "path": "demo",
    }
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.sendto((json.dumps(payload) + "\n").encode(), str(sock_path))
    client.close()

    assert ready.wait(3), "timeout waiting for agent alert"
    listener.stop()
    assert len(got) == 1
    assert got[0].rule_id == "agent_module_load"
    assert got[0].path == "demo"


def test_metrics_dispatch(tmp_path: Path):
    sock_path = tmp_path / "metrics.sock"
    got_m = []
    ready = threading.Event()

    def on_m(s):
        got_m.append(s)
        ready.set()

    listener = AgentSocketListener(sock_path, on_metrics=on_m, cooldown_sec=0)
    listener.start()
    time.sleep(0.25)
    payload = {
        "schema": "sysspectogram.metrics.v1",
        "kind": "metrics",
        "host_id": "t",
        "ts": time.time(),
        "cpu_percent": 12.5,
        "mem_percent": 40.0,
        "net_packets_sent_per_s": 3.0,
        "net_packets_recv_per_s": 1.0,
    }
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.sendto((json.dumps(payload) + "\n").encode(), str(sock_path))
    client.close()
    assert ready.wait(3)
    listener.stop()
    assert got_m[0].cpu_percent == 12.5
