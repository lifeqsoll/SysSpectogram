"""Telegram notify group filters."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.telegram_notify_prefs import NotifyPrefs


def test_internet_noise_off_blocks_flood_but_port_scans_can_stay(tmp_path: Path) -> None:
    prefs = NotifyPrefs.load(
        tmp_path / "telegram_notify.json",
        config={
            "groups": {
                "internet_noise": False,
                "port_scans": True,
                "ssh_auth": True,
            }
        },
    )
    assert prefs.should_notify(rule_id="port_scan_suspected", severity="high") is True
    assert prefs.should_notify(rule_id="inbound_flood_suspected", severity="medium") is False
    assert prefs.should_notify(rule_id="flow_syn_burst", severity="medium") is False
    assert prefs.should_notify(rule_id="bruteforce_ssh", severity="critical") is True


def test_port_scans_off(tmp_path: Path) -> None:
    prefs = NotifyPrefs.load(
        tmp_path / "n.json",
        config={"groups": {"internet_noise": False, "port_scans": False}},
    )
    assert prefs.should_notify(rule_id="port_scan_suspected", severity="high") is False


def test_subtle_host_pattern_suppressed(tmp_path: Path) -> None:
    prefs = NotifyPrefs.load(tmp_path / "n.json", config={"groups": {"host_ml": True}})
    assert (
        prefs.should_notify(
            rule_id="host_anomaly",
            severity="high",
            pattern="mixed / subtle deviation",
        )
        is False
    )
    assert prefs.should_notify(rule_id="host_anomaly", severity="high", pattern="CPU spike / compute") is True


def test_master_off_and_rule_override(tmp_path: Path) -> None:
    prefs = NotifyPrefs.load(tmp_path / "n.json")
    prefs.set_master(False)
    assert prefs.should_notify(rule_id="bruteforce_ssh", severity="critical") is False
    prefs.set_master(True)
    prefs.set_rule("port_scan_suspected", False)
    assert prefs.should_notify(rule_id="port_scan_suspected", severity="high") is False
    prefs.set_min_severity("high")
    assert prefs.should_notify(rule_id="suspicious_dns", severity="medium") is False
    assert prefs.should_notify(rule_id="bruteforce_ssh", severity="critical") is True


def test_persist_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "telegram_notify.json"
    prefs = NotifyPrefs.load(path, config={"groups": {"internet_noise": True}})
    prefs.set_group("internet_noise", False)
    again = NotifyPrefs.load(path)
    assert again.groups["internet_noise"] is False
