from __future__ import annotations

from sysspectogram.response.auto_kill import looks_malware, want_auto_kill


def test_observe_never_auto_kills():
    assert not want_auto_kill("canary_hit", auto_ban_enabled=False)
    assert not want_auto_kill("honeypot_hit", auto_ban_enabled=False)
    assert not want_auto_kill("agent_exec", comm="xmrig", path="/tmp/a", auto_ban_enabled=False)
    assert not want_auto_kill("agent_unexpected_root", auto_ban_enabled=False)


def test_shield_hard_and_malware():
    assert want_auto_kill("canary_hit", auto_ban_enabled=True)
    assert want_auto_kill("honeypot_hit", auto_ban_enabled=True)
    assert want_auto_kill("agent_exec", comm="xmrig", path="/tmp/a", auto_ban_enabled=True)
    assert want_auto_kill("agent_unexpected_root", auto_ban_enabled=True)
    assert not want_auto_kill("bruteforce_ssh", auto_ban_enabled=True)


def test_malware_heuristic():
    assert looks_malware("xmrig", "/tmp/x")
    assert not looks_malware("nginx", "/usr/sbin/nginx")
