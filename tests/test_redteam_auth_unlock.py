"""Auth first-from-IP, mapped never_ban, v6 /64, unlock lockout, health --config."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest

from sysspectogram.perimeter.auth import parse_auth_lines
from sysspectogram.perimeter.rules import RuleEngine
from sysspectogram.response.actions import NftBackend
from sysspectogram.web.bus import LiveBus
from sysspectogram.web.server import UNLOCK_RATE_MAX, start_web_server


def test_injected_invalid_user_is_injection_not_fail() -> None:
    lines = [
        "Invalid user x from 192.0.2.11 port 22 from 203.0.113.9 port 4242",
        "Failed password for invalid user x from 149.154.167.220 port 22 from 203.0.113.9 port 4242 ssh2",
        "Failed password for root from 203.0.113.9 port 22 ssh2 from 192.0.2.11 port 22",
    ]
    ev = parse_auth_lines(lines)
    assert len(ev) == 3
    assert all(e.kind == "injection" for e in ev)
    assert all(e.kind != "failed" and e.kind != "invalid" for e in ev)
    assert "192.0.2.11" in (ev[0].extras.get("ips") or [])
    assert "203.0.113.9" in (ev[0].extras.get("ips") or [])
    assert "149.154.167.220" not in {e.ip for e in ev if e.kind in {"failed", "invalid"}}


def test_single_sshd_tail_ip_is_real_peer() -> None:
    line = "Failed password for root from 203.0.113.9 port 4242 ssh2"
    ev = parse_auth_lines([line])
    assert len(ev) == 1
    assert ev[0].kind == "failed"
    assert ev[0].ip == "203.0.113.9"


def test_mapped_auth_ip_is_ipv4() -> None:
    line = "Failed password for root from ::ffff:203.0.113.9 port 22 ssh2"
    ev = parse_auth_lines([line])
    assert ev[0].ip == "203.0.113.9"


def test_mapped_matches_never_ban() -> None:
    nft = NftBackend(never_ban_cidrs=["203.0.113.0/24"])
    assert nft.is_never_ban("::ffff:203.0.113.9") is True


def test_v6_brute_aggregates_slash64() -> None:
    eng = RuleEngine(fail_threshold=8, fail_window_sec=60, v6_brute_prefix=64)
    last = None
    for i in range(8):
        last = eng.on_auth_fail(f"2001:db8:1::{i:x}", "root")
    assert last is not None
    assert last.rule_id == "bruteforce_ssh"
    assert last.ip == "2001:db8:1::/64"
    assert eng.on_auth_fail("2001:db8:1::9", "root") is None  # cooldown on the /64


def test_unlock_lockout_has_retry_after_without_fails() -> None:
    from http.client import HTTPConnection
    from sysspectogram.console_unlock import ConsoleUnlock

    unlock = ConsoleUnlock(enabled=True, ttl_sec=3600)
    httpd = start_web_server(
        LiveBus(), host="127.0.0.1", port=0, unlock=unlock, token_path=False
    )
    port = httpd.server_address[1]
    try:
        last_st, last_data, last_retry = 0, {}, ""
        for _ in range(UNLOCK_RATE_MAX + 1):
            body = json.dumps({"code": "WRONGWRONG"}).encode()
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.putrequest("POST", "/api/unlock", skip_host=True)
            conn.putheader("Host", "127.0.0.1")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
            conn.putheader("X-SS-CSRF", "1")
            conn.endheaders()
            conn.send(body)
            resp = conn.getresponse()
            last_st = resp.status
            last_retry = resp.getheader("Retry-After") or ""
            last_data = json.loads(resp.read().decode())
            conn.close()
        assert last_st == 429, last_data
        assert "fails" not in last_data
        assert int(last_retry) >= 60
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_logout_revokes_session() -> None:
    from sysspectogram.web.server import WebAppState

    app = WebAppState(
        LiveBus(),
        bot_token="t",
        allowed_chat_id="1",
        public_url=None,
        bind_host="127.0.0.1",
    )
    tok = app.issue_session()
    assert app.session_ok(tok)
    app.revoke_session(tok)
    assert app.session_ok(tok) is False


def test_guard_interrupt_raises() -> None:
    from sysspectogram.guard import _guard_interrupt

    with pytest.raises(KeyboardInterrupt):
        _guard_interrupt(2, None)


def test_health_uses_args_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("ssh:\n  port: true\nresponse:\n  mode: observe\n", encoding="utf-8")
    from sysspectogram.cli import _cmd_home_health

    rc = _cmd_home_health(Namespace(ping=False, strict=False, config=str(cfg)))
    data = json.loads(capsys.readouterr().out)
    check = next(c for c in data["checks"] if c["id"] == "config_policy")
    assert check["ok"] is False
    assert rc != 0
