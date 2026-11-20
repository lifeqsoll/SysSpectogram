"""H1 residual: forged username must not autoban a victim IP."""

from __future__ import annotations

from unittest.mock import patch

from sysspectogram.perimeter.auth import parse_auth_lines
from sysspectogram.perimeter.watcher import PerimeterWatcher


def _injection_line(tail: str, embedded: str = "198.51.100.77") -> str:
    return (
        f"Failed password for invalid user x from {embedded} port 22 "
        f"from {tail} port 5555 ssh2"
    )


def _tick(watcher: PerimeterWatcher, lines: list[str]):
    watcher.auth.poll = lambda: parse_auth_lines(lines)
    with patch("sysspectogram.perimeter.watcher.snapshot_connections", return_value=[]):
        return watcher.tick()


def test_forged_username_from_ip_not_parsed():
    # Attacker sets invalid-user name to include ``from VICTIM port 22``.
    # Real sshd lines for Disconnected/Connection closed have no ``from`` before IP.
    lines = [
        "sshd[123]: Disconnected from invalid user x from 198.51.100.77 port 22 "
        "from 203.0.113.9 port 5555 ssh2",
        "sshd[124]: Connection closed by invalid user x from 198.51.100.77 port 22 "
        "[preauth]",
        "Oct 26 12:00:00 box sshd[125]: Failed password for x from 198.51.100.77 "
        "port 22 from 203.0.113.9 port 5555 ssh2",
    ]
    # First two are noise (Disconnected / Connection closed).
    # Third embeds a forged from in the username → injection, not a fail on either IP.
    ev = parse_auth_lines(lines)
    assert len(ev) == 1
    assert ev[0].kind == "injection"
    assert set(ev[0].extras.get("ips") or []) == {"198.51.100.77", "203.0.113.9"}


def test_username_inject_without_real_from_at_end_rejected():
    # Pure inject into username on a Disconnected-style line (no Failed/Invalid kind).
    lines = [
        "Disconnected from invalid user Failed password for x from 198.51.100.77 port 22",
        "Connection closed by invalid user x from 198.51.100.77 port 22 [preauth]",
    ]
    assert parse_auth_lines(lines) == []


def test_syslog_and_journal_formats():
    lines = [
        "Oct 26 12:00:01 host sshd[9]: Failed password for root from 203.0.113.10 port 22 ssh2",
        "Invalid user admin from 198.51.100.20 port 22 ssh2",
        "sshd[11]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2",
    ]
    ev = parse_auth_lines(lines)
    assert [e.kind for e in ev] == ["failed", "invalid", "accepted"]
    assert [e.ip for e in ev] == ["203.0.113.10", "198.51.100.20", "192.0.2.10"]


def test_accepted_publickey_with_fingerprint_tail():
    # Real OpenSSH key login appends ``ssh2: ALG SHA256:…`` after the port.
    lines = [
        "sshd[512]: Accepted publickey for root from 203.0.113.50 port 51234 "
        "ssh2: ED25519 SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        "2024-10-26T12:00:01.123456+00:00 box sshd-session[99]: "
        "Accepted publickey for alice from 198.51.100.9 port 22 "
        "ssh2: RSA SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
    ]
    ev = parse_auth_lines(lines)
    assert [e.kind for e in ev] == ["accepted", "accepted"]
    assert [e.ip for e in ev] == ["203.0.113.50", "198.51.100.9"]


def test_rfc3339_and_sshd_session_failed():
    lines = [
        "2024-10-26T12:00:01+00:00 host sshd-session[7]: "
        "Failed password for root from 203.0.113.77 port 22 ssh2",
    ]
    ev = parse_auth_lines(lines)
    assert len(ev) == 1
    assert ev[0].ip == "203.0.113.77"
    assert ev[0].kind == "failed"


def test_injection_flood_one_alert_per_ip(tmp_path) -> None:
    watcher = PerimeterWatcher(state_path=tmp_path / "perimeter.json", fail_threshold=1000)
    line = _injection_line("203.0.113.9")
    alerts = _tick(watcher, [line] * 25)
    inj = [a for a in alerts if a.rule_id == "auth_log_injection"]
    assert len(inj) == 1
    assert inj[0].ip == "203.0.113.9"
    assert inj[0].extras.get("suppressed") == 24
    again = _tick(watcher, [line] * 5)
    assert not any(a.rule_id == "auth_log_injection" for a in again)


def test_injection_counts_fail_on_tail_ip(tmp_path) -> None:
    watcher = PerimeterWatcher(
        state_path=tmp_path / "perimeter.json",
        fail_threshold=3,
        fail_window_sec=60,
    )
    alerts = _tick(watcher, [_injection_line("203.0.113.9")] * 3)
    brute = [a for a in alerts if a.rule_id == "bruteforce_ssh"]
    assert brute
    assert brute[0].ip == "203.0.113.9"
    assert len(watcher.engine._fails.get("203.0.113.9", [])) == 3


def test_injection_host_cap_suppresses_rest(tmp_path) -> None:
    watcher = PerimeterWatcher(state_path=tmp_path / "perimeter.json", fail_threshold=1000)
    lines = [_injection_line(f"203.0.113.{i}") for i in range(1, 16)]
    alerts = _tick(watcher, lines)
    inj = [a for a in alerts if a.rule_id == "auth_log_injection"]
    assert len(inj) == 10
    assert sum(int(a.extras.get("host_suppressed") or 0) for a in inj) == 5
    assert any(a.extras.get("digest") for a in inj)


def test_injection_never_fails_embedded_ip(tmp_path) -> None:
    watcher = PerimeterWatcher(
        state_path=tmp_path / "perimeter.json",
        fail_threshold=2,
        fail_window_sec=60,
    )
    alerts = _tick(watcher, [_injection_line("203.0.113.9", "198.51.100.77")] * 5)
    assert not any(
        a.rule_id == "bruteforce_ssh" and a.ip == "198.51.100.77" for a in alerts
    )
    assert len(watcher.engine._fails.get("198.51.100.77", [])) == 0
    assert len(watcher.engine._fails.get("203.0.113.9", [])) == 5
