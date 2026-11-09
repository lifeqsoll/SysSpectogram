"""Web allow/mute/quiet payload validation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sysspectogram.web.actions import WebControllers
from sysspectogram.web.bus import LiveBus


class _Watch:
    def __init__(self):
        self.engine = SimpleNamespace(allowlist=set())
        self.state = SimpleNamespace(
            quiet=False,
            lockdown=False,
            allow=lambda ip: self.engine.allowlist.add(ip),
            mute=lambda ip, ttl: None,
        )
        self.persisted = 0

    def persist(self):
        self.persisted += 1


def _ctrl():
    bus = LiveBus()
    nft = SimpleNamespace(list_bans=lambda: [], never_ban_cidrs=[])
    return WebControllers(bus=bus, nft=nft, watcher=_Watch(), dry_run=True)


def test_allow_rejects_wide_and_junk():
    c = _ctrl()
    assert c.run("allow", {"ip": "0.0.0.0/0"})["ok"] is False
    assert c.run("allow", {"ip": "<script>alert(1)</script>"})["ok"] is False


def test_mute_rejects_nan_ttl():
    c = _ctrl()
    assert c.run("mute", {"ip": "203.0.113.9", "ttl": "nan"})["ok"] is False
    assert c.run("mute", {"ip": "x", "ttl": "1e308"})["ok"] is False


def test_shield_and_quarantine_refuse_are_not_ok():
    c = _ctrl()

    def boom(*_a, **_k):
        raise AssertionError("nft should not be called")

    c.nft.shield_port = lambda *a, **k: "shield refused: port 22 is SSH"
    c.nft.quarantine_ports = lambda *a, **k: "quarantine refused: port 22 (SSH)"
    assert c.run("shield", {"port": 22})["ok"] is False
    assert c.run("quarantine", {"ports": [22]})["ok"] is False
    c.nft.shield_port = lambda *a, **k: "shield refused: port out of range 0"
    assert c.run("shield", {"port": 0})["ok"] is False
    assert c.run("shield", {"port": 70000})["ok"] is False
    assert c.run("shield", {"port": "x"})["ok"] is False
    bad = c.run("quarantine", {"ports": ["x", 80]})
    assert bad["ok"] is False
    assert "invalid port" in bad["error"]
    _ = boom


def test_quiet_requires_bool():
    c = _ctrl()
    assert c.run("quiet", {"on": "false"})["ok"] is False
    assert c.run("quiet", {})["ok"] is False
    ok = c.run("quiet", {"on": False})
    assert ok["ok"] is True
    assert "off" in ok["result"]
