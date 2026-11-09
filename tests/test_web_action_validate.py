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


def test_quiet_requires_bool():
    c = _ctrl()
    assert c.run("quiet", {"on": "false"})["ok"] is False
    assert c.run("quiet", {})["ok"] is False
    ok = c.run("quiet", {"on": False})
    assert ok["ok"] is True
    assert "off" in ok["result"]
