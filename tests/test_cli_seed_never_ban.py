"""home seed-never-ban CLI guards."""

from __future__ import annotations

import json
from types import SimpleNamespace

from sysspectogram.cli import _cmd_home_seed_never_ban


def test_empty_ip_refused(capsys, monkeypatch) -> None:
    called = {"n": 0}

    def boom(**_kwargs):
        called["n"] += 1
        return {"ok": True}

    monkeypatch.setattr("sysspectogram.admin_ip.seed_never_ban", boom)
    rc = _cmd_home_seed_never_ban(SimpleNamespace(dry_run=True, force=False, ip=""))
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert out["ok"] is False
    assert "empty --ip" in out["error"]
    assert called["n"] == 0
