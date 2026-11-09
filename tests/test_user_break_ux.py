"""User-break fixes: unlock form, mode allowlist, honest bans list, anycast seed, LOCKED status."""

from __future__ import annotations

import json
import re
import time
from argparse import Namespace
from http.client import HTTPConnection
from pathlib import Path

import pytest
import yaml

from sysspectogram.admin_ip import seed_never_ban
from sysspectogram.cli import _cmd_bans, _cmd_home_settings
from sysspectogram.console_unlock import ConsoleUnlock, DEFAULT_CODE_LEN
from sysspectogram.response.actions import BanRecord, NftBackend
from sysspectogram.response.helper_ban import NoneBanBackend
from sysspectogram.web.actions import WebControllers
from sysspectogram.web.bus import LiveBus
from sysspectogram.web.server import start_web_server

ROOT = Path(__file__).resolve().parents[1]


def test_unlock_input_maxlength_matches_configured_len() -> None:
    cfg = yaml.safe_load((ROOT / "configs" / "default.yaml").read_text(encoding="utf-8"))
    want = int((cfg.get("telegram") or {}).get("unlock_code_len") or DEFAULT_CODE_LEN)
    html = (ROOT / "sysspectogram" / "web" / "static" / "index.html").read_text(encoding="utf-8")
    m = re.search(r'id="set-unlock"[^>]*>', html)
    assert m, "set-unlock input missing"
    tag = m.group(0)
    ml = re.search(r'maxlength="(\d+)"', tag)
    assert ml, "maxlength missing on set-unlock"
    assert int(ml.group(1)) >= want
    assert 'inputmode="numeric"' not in tag
    assert "123456" not in tag


def test_home_settings_rejects_junk_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    rc = _cmd_home_settings(Namespace(changes=json.dumps({"response.mode": "../pwn"}), no_rollback=True))
    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert not (tmp_path / "state" / "user-settings.json").exists()


def test_home_settings_observe_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    rc = _cmd_home_settings(Namespace(changes=json.dumps({"response.mode": "notify"}), no_rollback=True))
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["applied"]["response.mode"] == "observe"
    data = json.loads((tmp_path / "state" / "user-settings.json").read_text(encoding="utf-8"))
    assert data["response.mode"] == "observe"


def test_home_settings_soft_without_helper_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr(
        "sysspectogram.response.helper_ban.helper_available",
        lambda *a, **k: False,
    )
    rc = _cmd_home_settings(Namespace(changes=json.dumps({"response.mode": "soft"}), no_rollback=True))
    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert "helper" in (out.get("error") or "").lower()
    assert not (tmp_path / "state" / "user-settings.json").exists()


def test_bans_list_without_privileges_not_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    monkeypatch.setattr(
        "sysspectogram.response.helper_ban.select_ban_backend",
        lambda **kwargs: NoneBanBackend(),
    )
    rc = _cmd_bans(Namespace(bans_action="list"))
    assert rc != 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out.get("ips") == []
    assert "error" in out


def test_seed_rejects_well_known_anycast_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    out = seed_never_ban(write=True, ip="8.8.8.8")
    assert out["ok"] is False
    assert out["reason"] == "well_known_anycast"
    assert not (tmp_path / "state" / "user-settings.json").exists()
    out2 = seed_never_ban(write=True, ip="8.8.8.8", force=True)
    assert out2["ok"] is True
    assert "8.8.8.8/32" in out2["never_ban_cidrs"]
    assert "warning" in out2
    out3 = seed_never_ban(write=True, ip="203.0.113.55")
    assert out3["ok"] is True
    assert "203.0.113.55/32" in out3["never_ban_cidrs"]


def test_api_status_redacts_bans_when_locked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    bus = LiveBus()
    bus.set_processes([{"pid": 1, "name": "secret-proc", "cpu_percent": 1.0}])
    nft = NftBackend()
    nft.bans["198.51.100.9"] = BanRecord(
        "198.51.100.9", time.time(), None, "t", None, "memory"
    )
    unlock = ConsoleUnlock(enabled=True, ttl_sec=60, code_ttl_sec=300, code_len=10)
    assert unlock.unlocked() is False
    ctl = WebControllers(bus=bus, nft=nft, watcher=None, dry_run=True, unlock_ok=unlock.unlocked)
    httpd = start_web_server(
        bus,
        host="127.0.0.1",
        port=0,
        controllers=ctl,
        unlock=unlock,
        token_path=False,
    )
    port = httpd.server_address[1]
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("GET", "/api/status", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.endheaders()
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        assert resp.status == 200
        assert body.get("bans") == []
        assert body.get("control_unlocked") is False
        conn.close()

        conn2 = HTTPConnection("127.0.0.1", port, timeout=5)
        conn2.putrequest("GET", "/api/health", skip_host=True)
        conn2.putheader("Host", "127.0.0.1")
        conn2.endheaders()
        hresp = conn2.getresponse()
        health = json.loads(hresp.read().decode("utf-8"))
        assert health.get("ok") is True
        assert health.get("unlock_code_len") == unlock.code_len
        conn2.close()
    finally:
        httpd.shutdown()
