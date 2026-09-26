"""Trusted PIDs + session watch + pack sign tests."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.pack_sign import ensure_pack_key, sign_file, verify_file
from sysspectogram.session_watch import _parse_who, is_allowed_host, session_key
from sysspectogram.trusted_pids import collect_trusted_pids, read_pidfile


def test_read_pidfile(tmp_path: Path):
    import os

    p = tmp_path / "a.pid"
    p.write_text(f"{os.getpid()}\n", encoding="utf-8")
    assert read_pidfile(p) == os.getpid()


def test_collect_includes_extra(tmp_path: Path):
    import os

    ap = tmp_path / "agent.pid"
    ap.write_text(f"{os.getpid()}\n", encoding="utf-8")
    pids = collect_trusted_pids(agent_pidfile=ap, extra={999999})
    assert os.getpid() in pids


def test_pid_matches_self_exe():
    import os
    import sys

    from sysspectogram.trusted_pids import pid_matches_seal, resolve_exe, seal_binary

    exe = resolve_exe(os.getpid())
    assert exe is not None
    # python interpreter path
    seal = seal_binary(Path(sys.executable))
    # current process exe is python - should match seal of sys.executable when same
    ok = pid_matches_seal(
        os.getpid(),
        allowed_paths={seal["path"], str(exe)},
        expected_sha256=None,
    )
    assert ok


def test_parse_who_and_allow():
    rows = _parse_who("alice pts/0 2026-01-01 12:00 (1.2.3.4)\n")
    assert rows[0].user == "alice" and rows[0].host == "1.2.3.4"
    assert is_allowed_host("1.2.3.4", ["1.2.3.0/24"])
    assert not is_allowed_host("9.9.9.9", ["1.2.3.0/24"])
    assert "alice|pts/0|1.2.3.4" == session_key(rows[0])


def test_pack_sign(tmp_path: Path):
    f = tmp_path / "p.tar.gz"
    f.write_bytes(b"abc123")
    key = ensure_pack_key(tmp_path / "k")
    sig = sign_file(f, key)
    assert verify_file(f, key, sig)
    f.write_bytes(b"tampered")
    assert not verify_file(f, key, sig)
