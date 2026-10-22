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
    w = FlowWatcher(
        backend="netview",
        syn_threshold=50,
        unique_port_threshold=9999,
        per_ip_syn_threshold=40,
        window_sec=60,
    )
    alerts = w.poll()
    syn = [a for a in alerts if a["rule_id"] == "flow_syn_burst"]
    assert syn
    assert any(a.get("ip") == "1.2.3.4" for a in syn)


def test_confirm_streak():
    from sysspectogram.confirm_streak import ConfirmStreak

    s = ConfirmStreak(need=2, ttl_sec=60)
    assert s.hit("k") is False
    assert s.hit("k") is True


def test_lockdown_refuses_empty_allow():
    from sysspectogram.response.actions import NftBackend

    nft = NftBackend(never_ban_cidrs=[])
    msg = nft.apply_lockdown(dry_run=True, allow_cidrs=[])
    # dry-run still describes; empty real path refuses
    msg2 = nft.apply_lockdown(dry_run=False, allow_cidrs=[])
    assert "refused" in msg2 or "empty" in msg2
    assert "allow" in msg.lower() or "dry-run" in msg.lower()
