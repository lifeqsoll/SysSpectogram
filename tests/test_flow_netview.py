"""Flow netview backend smoke."""

from __future__ import annotations

from unittest.mock import patch

from sysspectogram.flow import FlowWatcher, _parse_ss


def test_flow_proc_backend_empty_ok():
    w = FlowWatcher(backend="proc", syn_threshold=9999, unique_port_threshold=9999)
    alerts = w.poll()
    assert isinstance(alerts, list)


@patch("sysspectogram.flow._parse_ss", return_value=[("1.2.3.4", 22, "SYN-SENT")] * 100)
@patch("sysspectogram.flow._parse_tcp", return_value=[])
def test_netview_syn_burst(_tcp, _ss):
    w = FlowWatcher(backend="netview", syn_threshold=50, unique_port_threshold=9999, window_sec=60)
    alerts = w.poll()
    assert any(a["rule_id"] == "flow_syn_burst" for a in alerts)
