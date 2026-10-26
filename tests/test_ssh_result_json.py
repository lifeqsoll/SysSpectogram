"""SshResult.json must find the last JSON object across stdout/stderr (ssh -tt)."""

from __future__ import annotations

from sysspectogram.fleet.ssh import SshResult


def test_json_from_stdout_with_banner():
    r = SshResult(
        ok=True,
        stdout="Welcome to Ubuntu\n{\"ok\": true, \"pair_code\": \"ABCD\"}\n",
        stderr="",
        returncode=0,
    )
    assert r.json() == {"ok": True, "pair_code": "ABCD"}


def test_json_from_stderr_when_stdout_noisy():
    r = SshResult(
        ok=True,
        stdout="Pseudo-terminal will not be allocated\r\n",
        stderr='{"ok": true, "pair_code": "ZZZZ"}\n',
        returncode=0,
    )
    assert r.json() == {"ok": True, "pair_code": "ZZZZ"}
