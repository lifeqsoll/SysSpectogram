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
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._auth_tail_helper",
        lambda *a, **k: ([], False),
    )

    got, src = ssh_auth_lines()
    assert src == "journal"
    assert len(got) == 1


def test_ssh_auth_lines_helper_fallback(monkeypatch):
    monkeypatch.setattr("sysspectogram.perimeter.auth._journal_ssh", lambda lines=200: [])
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._journal_ssh_reachable",
        lambda lines=1: False,
    )
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._auth_tail_helper",
        lambda lines=200, cursor=None: (
            ["sshd-session[2]: Failed password for admin from 198.51.100.5 port 22 ssh2"],
            True,
        ),
    )

    got, src = ssh_auth_lines()
    assert src == "helper"
    assert len(got) == 1


def test_journal_reachable_rejects_empty_and_denied(monkeypatch):
    from sysspectogram.perimeter.auth import _journal_ssh_reachable

    class _Proc:
        def __init__(self, out: str, err: str, code: int = 0):
            self.stdout = out
            self.stderr = err
            self.returncode = code

    seen: list[list[str]] = []

    def _run_denied(argv, *_a, **_k):
        seen.append(list(argv))
        return _Proc("", "No journal files were found.\n", 0)

    monkeypatch.setattr("sysspectogram.perimeter.auth.subprocess.run", _run_denied)
    monkeypatch.setattr("sysspectogram.perimeter.auth.os.geteuid", lambda: 0)
    assert _journal_ssh_reachable() is False
    assert seen and "-q" not in seen[0]
    assert "--system" in seen[0]

    def _run_other_users(*_a, **_k):
        return _Proc("", "Hint: You are currently not seeing messages from other users and the system.\n", 0)

    monkeypatch.setattr("sysspectogram.perimeter.auth.subprocess.run", _run_other_users)
    assert _journal_ssh_reachable() is False


def test_ssh_auth_lines_helper_empty_still_ok(monkeypatch):
    monkeypatch.setattr("sysspectogram.perimeter.auth._journal_ssh", lambda lines=200: [])
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._journal_ssh_reachable",
        lambda lines=1: False,
    )
    monkeypatch.setattr(
        "sysspectogram.perimeter.auth._auth_tail_helper",
        lambda lines=200, cursor=None: ([], True),
    )
    got, src = ssh_auth_lines()
    assert src == "helper"
    assert got == []


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
