"""Flow netview backend smoke."""

from __future__ import annotations

from unittest.mock import patch

from sysspectogram.flow import FlowWatcher, _parse_ss


def test_flow_proc_backend_empty_ok():
    w = FlowWatcher(backend="proc", syn_threshold=9999, unique_port_threshold=9999)
    alerts = w.poll()
    assert isinstance(alerts, list)


@patch(
    "sysspectogram.flow._parse_ss",
    return_value=[(f"203.0.113.{i}", 22, "SYN-RECV") for i in range(1, 51)],
)
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


@patch(
    "sysspectogram.flow._parse_ss",
    return_value=[("203.0.113.9", i, "SYN-SENT") for i in range(50)],
)
@patch("sysspectogram.flow._parse_tcp", return_value=[])
def test_netview_syn_sent_not_burst(_tcp, _ss):
    w = FlowWatcher(
        backend="netview",
        syn_threshold=10,
        unique_port_threshold=9999,
        per_ip_syn_threshold=40,
        window_sec=60,
    )
    alerts = w.poll()
    assert not any(a["rule_id"] == "flow_syn_burst" for a in alerts)
    assert any(a["rule_id"] == "flow_syn_sent_hang" for a in alerts)


def test_syn_sent_never_port_scan():
    sent = [("203.0.113.9", i, "02") for i in range(50)]
    watcher = FlowWatcher(
        backend="proc",
        syn_threshold=9999,
        unique_port_threshold=10,
        per_ip_syn_threshold=9999,
        window_sec=60,
    )
    with patch("sysspectogram.flow._parse_tcp", return_value=sent):
        alerts = watcher.poll()
    assert not any(a["rule_id"] == "flow_port_scan" for a in alerts)

    recv = [("198.51.100.9", i, "03") for i in range(15)]
    inbound = FlowWatcher(
        backend="proc",
        syn_threshold=9999,
        unique_port_threshold=10,
        per_ip_syn_threshold=9999,
        window_sec=60,
    )
    with patch("sysspectogram.flow._parse_tcp", return_value=recv):
        inbound_alerts = inbound.poll()
    assert any(a["rule_id"] == "flow_port_scan" for a in inbound_alerts)


def test_v4_mapped_merged():
    socks = [("::ffff:203.0.113.9", 1000 + i, "03") for i in range(20)]
    socks += [("203.0.113.9", 2000 + i, "03") for i in range(21)]
    watcher = FlowWatcher(
        backend="proc",
        syn_threshold=9999,
        unique_port_threshold=9999,
        per_ip_syn_threshold=40,
        window_sec=60,
    )
    with patch("sysspectogram.flow._parse_tcp", return_value=socks):
        alerts = watcher.poll()
    per_ip = [
        a
        for a in alerts
        if a["rule_id"] == "flow_syn_burst" and a.get("extras", {}).get("scope") == "per_ip"
    ]
    assert len(per_ip) == 1
    assert per_ip[0]["ip"] == "203.0.113.9"
    assert per_ip[0]["count"] == 41
    assert not any("ffff" in str(a.get("ip")) for a in alerts)


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
