"""User-break fixes: unlock form, mode allowlist, honest bans list, anycast seed, auth reads."""

from __future__ import annotations

import json
import re
import time
from argparse import Namespace
from http.client import HTTPConnection
from pathlib import Path

import pytest
import yaml

from sysspectogram.admin_ip import WELL_KNOWN_ANYCAST_HOSTS, seed_never_ban
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


def _get_json(port: int, path: str, *, cookie: str | None = None) -> tuple[int, dict]:
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("GET", path, skip_host=True)
    conn.putheader("Host", "127.0.0.1")
    if cookie:
        conn.putheader("Cookie", cookie)
    conn.endheaders()
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()
    try:
        body = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        body = {"_raw": raw}
    return resp.status, body


def _unlock_cookie(port: int, code: str) -> str:
    raw = json.dumps({"code": code}).encode()
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("POST", "/api/unlock", skip_host=True)
    conn.putheader("Host", "127.0.0.1")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(raw)))
    conn.putheader("X-SS-CSRF", "1")
    conn.endheaders()
    conn.send(raw)
    resp = conn.getresponse()
    data = json.loads(resp.read().decode("utf-8"))
    assert resp.status == 200 and data.get("ok") is True, data
    set_cookie = ""
    for k, v in resp.getheaders():
        if k.lower() == "set-cookie" and v.startswith("ss_session="):
            set_cookie = v.split(";", 1)[0]
    conn.close()
    assert set_cookie.startswith("ss_session=")
    return set_cookie


def test_read_apis_require_session_before_and_after_unlock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    bus = LiveBus()
    bus.set_processes([{"pid": 1, "name": "secret-proc", "cpu_percent": 1.0}])
    nft = NftBackend()
    nft.bans["198.51.100.9"] = BanRecord(
        "198.51.100.9", time.time(), None, "t", None, "memory"
    )
    unlock = ConsoleUnlock(enabled=True, ttl_sec=60, code_ttl_sec=300, code_len=10)
    code = unlock.pending_code
    assert code
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
        for path in ("/api/status", "/api/snapshot", "/api/stream"):
            st, body = _get_json(port, path)
            assert st == 401, (path, st, body)
            assert body.get("ok") is False
            assert body.get("error") == "auth required"

        hst, health = _get_json(port, "/api/health")
        assert hst == 200
        assert set(health.keys()) <= {"ok", "unlock_code_len"}
        assert "public_url" not in health and "actions" not in health and "host" not in health

        cookie = _unlock_cookie(port, code)
        assert unlock.unlocked()

        # Still 401 without cookie even after control unlock.
        for path in ("/api/status", "/api/snapshot", "/api/stream"):
            st, body = _get_json(port, path)
            assert st == 401, (path, st, body)
            assert body.get("error") == "auth required"

        st, status = _get_json(port, "/api/status", cookie=cookie)
        assert st == 200
        assert status.get("ok") is True
        st2, snap = _get_json(port, "/api/snapshot", cookie=cookie)
        assert st2 == 200
        assert "host_id" in snap or "score" in snap or "ok" in snap
    finally:
        httpd.shutdown()


def test_api_status_redacts_bans_when_locked_with_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Second layer: authorized but LOCKED still redacts bans/processes."""
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    bus = LiveBus()
    bus.set_processes([{"pid": 1, "name": "secret-proc", "cpu_percent": 1.0}])
    nft = NftBackend()
    nft.bans["198.51.100.9"] = BanRecord(
        "198.51.100.9", time.time(), None, "t", None, "memory"
    )
    # Gate enabled but we never unlock control — mint session via Bearer instead.
    unlock = ConsoleUnlock(enabled=True, ttl_sec=60, code_ttl_sec=300, code_len=10)
    token_path = tmp_path / "state" / "web.token"
    ctl = WebControllers(bus=bus, nft=nft, watcher=None, dry_run=True, unlock_ok=unlock.unlocked)
    httpd = start_web_server(
        bus,
        host="127.0.0.1",
        port=0,
        controllers=ctl,
        unlock=unlock,
        token_path=token_path,
    )
    port = httpd.server_address[1]
    token = token_path.read_text(encoding="utf-8").strip()
    try:
        # Issue session with Bearer on unlock while still LOCKED (wrong path: already locked).
        # Use Bearer directly on status.
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("GET", "/api/status", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Authorization", f"Bearer {token}")
        conn.endheaders()
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        conn.close()
        assert resp.status == 200
        assert body.get("bans") == []
        assert body.get("control_unlocked") is False
    finally:
        httpd.shutdown()


def test_seed_rejects_well_known_anycast_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    sample = [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
        "208.67.220.220",
        "149.112.112.112",
        "94.140.14.14",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ]
    for ip in sample:
        assert ip in WELL_KNOWN_ANYCAST_HOSTS
        out = seed_never_ban(write=True, ip=ip)
        assert out["ok"] is False, ip
        assert out["reason"] == "well_known_anycast", (ip, out)
        assert not (tmp_path / "state" / "user-settings.json").exists()
        out_f = seed_never_ban(write=True, ip=ip, force=True)
        assert out_f["ok"] is True, (ip, out_f)
        assert "warning" in out_f
        (tmp_path / "state" / "user-settings.json").unlink(missing_ok=True)

    for cidr in ("8.8.8.0/24", "1.1.1.0/24", "2606:4700:4700::1111/64"):
        out_c = seed_never_ban(write=True, ip=cidr)
        assert out_c["ok"] is False, cidr
        assert out_c["reason"] == "well_known_anycast", (cidr, out_c)

    # Near-miss and documentation-style admin still OK without force.
    ok = seed_never_ban(write=True, ip="8.8.8.9")
    assert ok["ok"] is True
    assert "8.8.8.9/32" in ok["never_ban_cidrs"]
    (tmp_path / "state" / "user-settings.json").unlink(missing_ok=True)
    out3 = seed_never_ban(write=True, ip="203.0.113.55")
    assert out3["ok"] is True
    assert "203.0.113.55/32" in out3["never_ban_cidrs"]

    (tmp_path / "state" / "user-settings.json").unlink(missing_ok=True)
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.7 5555 10.0.0.1 22")
    ssh = seed_never_ban(write=True)
    assert ssh["ok"] is True
    assert "203.0.113.7/32" in ssh["never_ban_cidrs"]
    assert ssh.get("source") == "ssh_connection"


def test_seed_rejects_loopback_and_multicast(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    for ip, reason in (
        ("127.0.0.1", "loopback"),
        ("224.0.0.1", "multicast"),
        ("fe80::1", "link_local"),
        ("::", "unspecified"),
    ):
        out = seed_never_ban(write=True, ip=ip)
        assert out["ok"] is False, (ip, out)
        assert out["reason"] == reason, (ip, out)


def test_seed_accepts_private_and_ula_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    for ip, needle in (
        ("192.168.1.5", "192.168.1.5/32"),
        ("10.0.0.0/24", "10.0.0.0/24"),
        ("fd00::5", "fd00::5/128"),
    ):
        (tmp_path / "state" / "user-settings.json").unlink(missing_ok=True)
        out = seed_never_ban(write=True, ip=ip)
        assert out["ok"] is True, (ip, out)
        assert out.get("written") is True
        assert needle in out["never_ban_cidrs"]
        assert "warning" in out
        assert "LAN" in out["warning"] or "private" in out["warning"].lower() or "локал" in out["warning"].lower() or "network" in out["warning"].lower()

    (tmp_path / "state" / "user-settings.json").unlink(missing_ok=True)
    cgnat = seed_never_ban(write=True, ip="100.64.1.5")
    assert cgnat["ok"] is True
    assert "warning" in cgnat
    assert "CGNAT" in cgnat["warning"] or "100.64" in cgnat["warning"]


def test_web_login_code_mints_session_without_control_unlock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sysspectogram.web.login_code import WebLoginCode

    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    bus = LiveBus()
    login = WebLoginCode(persist_path=tmp_path / "state" / "web.login", ttl_sec=300)
    code = login.pending_code
    assert code
    unlock = ConsoleUnlock(enabled=True, ttl_sec=60, code_ttl_sec=300, code_len=10)
    assert unlock.unlocked() is False
    ctl = WebControllers(
        bus=bus, nft=NftBackend(), watcher=None, dry_run=True, unlock_ok=unlock.unlocked
    )
    httpd = start_web_server(
        bus,
        host="127.0.0.1",
        port=0,
        controllers=ctl,
        unlock=unlock,
        login=login,
        token_path=False,
    )
    port = httpd.server_address[1]
    try:
        st, _ = _get_json(port, "/api/status")
        assert st == 401
        raw = json.dumps({"code": code}).encode()
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("POST", "/api/login", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(raw)))
        conn.putheader("X-SS-CSRF", "1")
        conn.endheaders()
        conn.send(raw)
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        assert resp.status == 200 and body.get("ok") is True
        cookie = ""
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie" and v.startswith("ss_session="):
                cookie = v.split(";", 1)[0]
        conn.close()
        assert cookie
        st2, status = _get_json(port, "/api/status", cookie=cookie)
        assert st2 == 200
        assert status.get("control_unlocked") is False
        # one-shot
        conn2 = HTTPConnection("127.0.0.1", port, timeout=5)
        conn2.putrequest("POST", "/api/login", skip_host=True)
        conn2.putheader("Host", "127.0.0.1")
        conn2.putheader("Content-Type", "application/json")
        conn2.putheader("Content-Length", str(len(raw)))
        conn2.putheader("X-SS-CSRF", "1")
        conn2.endheaders()
        conn2.send(raw)
        resp2 = conn2.getresponse()
        assert resp2.status == 401
        resp2.read()
        conn2.close()
        # next code is already on disk — second browser does not need a failed login
        nxt = (tmp_path / "state" / "web.login").read_text(encoding="utf-8").splitlines()[0]
        assert nxt and nxt != code
        raw3 = json.dumps({"code": nxt}).encode()
        conn3 = HTTPConnection("127.0.0.1", port, timeout=5)
        conn3.putrequest("POST", "/api/login", skip_host=True)
        conn3.putheader("Host", "127.0.0.1")
        conn3.putheader("Content-Type", "application/json")
        conn3.putheader("Content-Length", str(len(raw3)))
        conn3.putheader("X-SS-CSRF", "1")
        conn3.endheaders()
        conn3.send(raw3)
        resp3 = conn3.getresponse()
        assert resp3.status == 200
        resp3.read()
        conn3.close()
    finally:
        httpd.shutdown()


def test_bans_list_root_without_nft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    backend = NftBackend(never_ban_cidrs=[])
    monkeypatch.setattr("sysspectogram.response.actions.os.geteuid", lambda: 0)
    monkeypatch.setattr("sysspectogram.response.actions.shutil.which", lambda _n: None)
    monkeypatch.setattr(
        "sysspectogram.response.helper_ban.select_ban_backend",
        lambda **kwargs: backend,
    )
    rc = _cmd_bans(Namespace(bans_action="list"))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out.get("error") == "nft not found"


def test_bans_list_root_nft_list_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    backend = NftBackend(never_ban_cidrs=[])
    monkeypatch.setattr("sysspectogram.response.actions.os.geteuid", lambda: 0)
    monkeypatch.setattr("sysspectogram.response.actions.shutil.which", lambda _n: "/usr/sbin/nft")
    monkeypatch.setattr(backend, "_run", lambda argv: (1, "Error: No such file or directory"))
    monkeypatch.setattr(
        "sysspectogram.response.helper_ban.select_ban_backend",
        lambda **kwargs: backend,
    )
    rc = _cmd_bans(Namespace(bans_action="list"))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert "nft list set failed" in (out.get("error") or "")
