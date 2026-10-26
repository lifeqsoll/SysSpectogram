"""SshResult.json must parse pretty JSON without merging stdout+stderr."""

from __future__ import annotations

import json

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


def test_pretty_json_stdout_survives_ssh_tt_stderr():
    # home pair-remote prints indent=2; ssh -tt adds Connection closed on stderr.
    payload = {
        "ok": True,
        "pair_code": "WXYZ",
        "ttl_sec": 300,
        "label": "laptop",
        "hint": "Enter this code on the admin PC within ttl_sec.",
    }
    stdout = json.dumps(payload, indent=2).replace("\n", "\r\n") + "\r\n"
    stderr = "Warning: Permanently added '203.0.113.9' (ED25519) to the list of known hosts.\n"
    stderr += "Connection to 203.0.113.9 closed.\n"
    r = SshResult(ok=True, stdout=stdout, stderr=stderr, returncode=0)
    assert r.json() == payload


def test_does_not_merge_streams_into_invalid_json():
    # Merging would break; stdout-only loads must win.
    r = SshResult(
        ok=True,
        stdout='{\n  "ok": true,\n  "pair_code": "AAAA"\n}\n',
        stderr="Connection to h closed.\n",
        returncode=0,
    )
    assert r.json() == {"ok": True, "pair_code": "AAAA"}


def test_banner_then_outer_object_with_nested_list():
    # Top→bottom raw_decode must return the outer object, not the last nested dict.
    outer = {
        "ok": True,
        "items": [{"pair_code": "FAKE"}, {"pair_code": "REAL"}],
        "pair_code": "OUTER",
    }
    stdout = "Welcome\n" + json.dumps(outer, indent=2) + "\n"
    r = SshResult(ok=True, stdout=stdout, stderr="Connection to h closed.\n", returncode=0)
    assert r.json() == outer
    assert r.json()["pair_code"] == "OUTER"
