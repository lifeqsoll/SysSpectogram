"""HMAC agent auth tests."""

from __future__ import annotations

import time

from sysspectogram.agent_auth import canonical_payload, needs_hmac, sign, verify


def test_sign_verify_roundtrip():
    secret = "a" * 64
    obj = {
        "rule_id": "agent_kirk_module_hide",
        "severity": "critical",
        "ts": time.time(),
        "pid": 1,
        "path": "/evil.ko",
        "message": "hide",
    }
    obj["hmac"] = sign(secret, obj)
    assert verify(secret, obj)
    obj["message"] = "tampered"
    assert not verify(secret, obj)


def test_critical_rules():
    assert needs_hmac("agent_kirk_module_hide")
    assert needs_hmac("agent_unexpected_root")
    assert not needs_hmac("agent_ebpf_execve")


def test_canonical_stable():
    a = {"rule_id": "r", "severity": "high", "ts": 1.0, "pid": None, "path": "", "message": "m"}
    assert "v1|r|high|" in canonical_payload(a)
