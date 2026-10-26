"""H1 residual: forged username must not autoban a victim IP."""

from __future__ import annotations

from sysspectogram.perimeter.auth import parse_auth_lines


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
    # Third is a real Failed password but end-anchored: the LAST ``from IP port`` wins
    # only if the line ends with it — here trailing ``ssh2`` after an earlier forge
    # still ends with ``port 5555 ssh2``, so real source 203.0.113.9 is kept.
    ev = parse_auth_lines(lines)
    assert all(e.ip != "198.51.100.77" for e in ev)
    assert [e.ip for e in ev] == ["203.0.113.9"]


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
