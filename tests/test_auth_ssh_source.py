"""F-03: ssh journal sources and AuthWatcher helper fallback."""

from __future__ import annotations

from sysspectogram.perimeter.auth import AuthWatcher, parse_auth_lines, ssh_auth_lines


def test_sshd_session_failed_password_parsed():
    line = (
        "2024-10-26T12:00:01+00:00 host sshd-session[7]: "
        "Failed password for root from 203.0.113.77 port 22 ssh2"
    )
    ev = parse_auth_lines([line])
    assert len(ev) == 1
    assert ev[0].kind == "failed"
    assert ev[0].ip == "203.0.113.77"


def test_ssh_auth_lines_journal_first(monkeypatch):
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._journal_ssh",
        lambda lines=200: ["sshd[1]: Failed password for x from 203.0.113.1 port 22 ssh2"],
    )
    monkeypatch.setattr("sysspectogram.perimeter.auth._auth_tail_helper", lambda *a, **k: [])

    got, src = ssh_auth_lines()
    assert src == "journal"
    assert len(got) == 1


def test_ssh_auth_lines_helper_fallback(monkeypatch):
    monkeypatch.setattr("sysspectogram.perimeter.auth._journal_ssh", lambda lines=200: [])
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._auth_tail_helper",
        lambda lines=200, cursor=None: [
            "sshd-session[2]: Failed password for admin from 198.51.100.5 port 22 ssh2"
        ],
    )

    got, src = ssh_auth_lines()
    assert src == "helper"
    assert len(got) == 1


def test_auth_watcher_uses_helper_when_journal_empty(monkeypatch):
    line = "sshd-session[2]: Failed password for admin from 198.51.100.5 port 22 ssh2"
    seen: list[list[str]] = [[], [line]]

    def fake_ssh_auth_lines(lines: int = 200):
        batch = seen.pop(0) if seen else [line]
        src = "journal" if not seen else "helper"
        return batch, src if batch else "none"

    monkeypatch.setattr("sysspectogram.perimeter.auth.ssh_auth_lines", fake_ssh_auth_lines)

    w = AuthWatcher()
    assert w.poll() == []
    ev = w.poll()
    assert len(ev) == 1
    assert ev[0].ip == "198.51.100.5"
