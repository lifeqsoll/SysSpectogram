"""Red-team fixes after c252126: auth injection, v6 /64, gateway, flow, login, miniapp."""

from __future__ import annotations

import json
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import pytest

from sysspectogram.flow import FlowWatcher
from sysspectogram.net_ip import parse_ban_target, validate_v6_brute_prefix
from sysspectogram.perimeter.auth import parse_auth_lines
from sysspectogram.perimeter.rules import RuleEngine
from sysspectogram.response.actions import NftBackend, backend_from_config, policy_from_config
from sysspectogram.response.protect import _parse_route_gateways, is_protected
from sysspectogram.web.bus import LiveBus
from sysspectogram.web.login_code import WebLoginCode
from sysspectogram.web.server import UNLOCK_RATE_MAX, start_web_server


def test_auth_injection_poc_no_chosen_ip() -> None:
    lines = [
        "Invalid user x from 192.0.2.11 port 22 from 203.0.113.9 port 4242",
        "Failed password for invalid user x from 149.154.167.220 port 22 from 203.0.113.9 port 4242 ssh2",
    ]
    ev = parse_auth_lines(lines)
    assert all(e.kind == "injection" for e in ev)
    assert {e.ip for e in ev if e.kind in {"failed", "invalid"}} == set()


def test_first_from_ip_wins_rewritten_to_sshd_tail_or_injection() -> None:
    # Single from → peer IP from sshd tail.
    one = parse_auth_lines(["Failed password for root from 203.0.113.9 port 4242 ssh2"])
    assert one[0].kind == "failed" and one[0].ip == "203.0.113.9"
    # Multi from → injection, neither IP gets a fail.
    multi = parse_auth_lines(
        ["Invalid user x from 192.0.2.11 port 22 from 203.0.113.9 port 4242"]
    )
    assert multi[0].kind == "injection"
    assert multi[0].ip is None or multi[0].kind == "injection"


def test_accepted_still_uses_first_from() -> None:
    line = (
        "Accepted publickey for alice from 203.0.113.9 port 22 ssh2: "
        "RSA SHA256:abc ID cert from 192.0.2.11 port 22 (serial 1) CA SHA256:def"
    )
    # sanitize may drop forged cert tail; first from after user is peer
    ev = parse_auth_lines([line])
    assert ev
    assert ev[0].kind in {"accepted", "accepted_unparsed"}
    if ev[0].ip:
        assert ev[0].ip == "203.0.113.9"


def test_v6_brute_alert_ip_is_prefix() -> None:
    eng = RuleEngine(fail_threshold=8, fail_window_sec=60, v6_brute_prefix=64)
    last = None
    for i in range(8):
        last = eng.on_auth_fail(f"2001:db8:1::{i:x}", "root")
    assert last is not None
    assert last.ip == "2001:db8:1::/64"


@pytest.mark.parametrize("bad", ["abc", "200", "8", "-1", True])
def test_v6_brute_prefix_refuses_junk(bad: object) -> None:
    with pytest.raises(ValueError):
        validate_v6_brute_prefix(bad)
    with pytest.raises(ValueError):
        policy_from_config({"perimeter": {"v6_brute_prefix": bad}})


def test_v6_brute_prefix_ok_values() -> None:
    assert validate_v6_brute_prefix(0) == 0
    assert validate_v6_brute_prefix(64) == 64
    assert validate_v6_brute_prefix(128) == 128


def test_parse_ban_target_prefix() -> None:
    assert parse_ban_target("2001:db8:1::/64") == "2001:db8:1::/64"
    with pytest.raises(ValueError):
        parse_ban_target("203.0.113.0/24")


def test_gateway_parses_v6_and_nexthop() -> None:
    text = (
        "default via 203.0.113.1 dev eth0\n"
        "default via 2001:db8:feed::fffe dev eth0 metric 1024\n"
        "default nexthop via 2001:db8::1 weight 1 nexthop via 2001:db8::2 weight 1\n"
    )
    gws = _parse_route_gateways(text)
    assert "203.0.113.1" in gws
    assert "2001:db8:feed::fffe" in gws
    assert "2001:db8::1" in gws
    assert "2001:db8::2" in gws


def test_v6_gateway_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sysspectogram.response.protect._host_addrs", lambda: set())
    monkeypatch.setattr("sysspectogram.response.protect._ssh_session_ips", lambda **k: set())
    monkeypatch.setattr("sysspectogram.response.protect._resolver_addrs", lambda: set())
    monkeypatch.setattr(
        "sysspectogram.response.protect._gateway_addrs",
        lambda: {"2001:db8:feed::fffe"},
    )
    assert is_protected("2001:db8:feed::fffe") == "default gateway"
    nft = NftBackend()
    out = nft.ban_ip("2001:db8:feed::fffe", dry_run=True)
    assert out.startswith("protected skip")


def test_prefix_overlap_never_ban() -> None:
    nft = NftBackend(never_ban_cidrs=["2001:db8:1::11/128"])
    assert nft.is_never_ban("2001:db8:1::/64") is True


def test_flow_dedupe_same_sockets_no_burst() -> None:
    socks = [
        ("203.0.113.80", 1000, "03"),
        ("203.0.113.80", 1001, "03"),
        ("203.0.113.80", 1002, "03"),
    ]
    w = FlowWatcher(
        backend="proc",
        syn_threshold=9999,
        unique_port_threshold=9999,
        per_ip_syn_threshold=40,
        window_sec=30,
    )
    with patch("sysspectogram.flow._parse_tcp", return_value=socks):
        for _ in range(15):
            alerts = w.poll()
    syn = [a for a in alerts if a["rule_id"] == "flow_syn_burst"]
    assert not syn


def test_flow_syn_sent_not_ban_capable() -> None:
    socks = [("203.0.113.90", i, "02") for i in range(50)]
    w = FlowWatcher(
        backend="proc",
        syn_threshold=10,
        unique_port_threshold=9999,
        per_ip_syn_threshold=40,
        window_sec=30,
    )
    with patch("sysspectogram.flow._parse_tcp", return_value=socks):
        alerts = w.poll()
    assert not any(a["rule_id"] == "flow_syn_burst" for a in alerts)
    hang = [a for a in alerts if a["rule_id"] == "flow_syn_sent_hang"]
    assert hang
    assert hang[0].get("ip") is None
    assert hang[0]["extras"].get("ban") is False


def test_flow_unique_syn_recv_alerts() -> None:
    socks = [("203.0.113.80", 2000 + i, "03") for i in range(41)]
    w = FlowWatcher(
        backend="proc",
        syn_threshold=9999,
        unique_port_threshold=9999,
        per_ip_syn_threshold=40,
        window_sec=30,
    )
    with patch("sysspectogram.flow._parse_tcp", return_value=socks):
        alerts = w.poll()
    syn = [a for a in alerts if a["rule_id"] == "flow_syn_burst"]
    assert syn
    assert syn[0]["ip"] == "203.0.113.80"
    assert syn[0]["count"] == 41


def test_login_correct_after_lockout() -> None:
    login = WebLoginCode(persist_path=None, ttl_sec=300)
    assert login.pending_code
    httpd = start_web_server(
        LiveBus(), host="127.0.0.1", port=0, login=login, token_path=False
    )
    port = httpd.server_address[1]
    try:
        for _ in range(UNLOCK_RATE_MAX):
            body = json.dumps({"code": "WRONGWRONG"}).encode()
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.putrequest("POST", "/api/login", skip_host=True)
            conn.putheader("Host", "127.0.0.1")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
            conn.putheader("X-SS-CSRF", "1")
            conn.endheaders()
            conn.send(body)
            conn.getresponse().read()
            conn.close()
        # Still rate-limited for wrong guesses…
        body = json.dumps({"code": "WRONGWRONG"}).encode()
        conn = HTTPConnection("127.0.0.1", port, timeout=3)
        conn.putrequest("POST", "/api/login", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("X-SS-CSRF", "1")
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        assert resp.status == 429
        conn.close()
        # Fresh rotated code still wins despite 429 for wrong guesses.
        code = login.pending_code
        assert code
        body = json.dumps({"code": code}).encode()
        conn = HTTPConnection("127.0.0.1", port, timeout=3)
        conn.putrequest("POST", "/api/login", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("X-SS-CSRF", "1")
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        assert resp.status == 200, data
        assert data.get("ok") is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_login_rotates_after_fails() -> None:
    login = WebLoginCode(persist_path=None, ttl_sec=300)
    old = login.pending_code
    for _ in range(5):
        assert login.try_consume("WRONGWRONG") is False
    new = login.pending_code
    assert new and new != old
    assert login.try_consume(new) is True


def test_login_unlock_buckets_separate() -> None:
    from sysspectogram.console_unlock import ConsoleUnlock

    unlock = ConsoleUnlock(enabled=True, ttl_sec=3600)
    login = WebLoginCode(persist_path=None, ttl_sec=300)
    httpd = start_web_server(
        LiveBus(),
        host="127.0.0.1",
        port=0,
        unlock=unlock,
        login=login,
        token_path=False,
    )
    port = httpd.server_address[1]
    try:
        for _ in range(UNLOCK_RATE_MAX):
            body = json.dumps({"code": "WRONGWRONG"}).encode()
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.putrequest("POST", "/api/unlock", skip_host=True)
            conn.putheader("Host", "127.0.0.1")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
            conn.putheader("X-SS-CSRF", "1")
            conn.endheaders()
            conn.send(body)
            conn.getresponse().read()
            conn.close()
        # Unlock bucket full — login still accepts wrong then correct path.
        code = login.pending_code
        body = json.dumps({"code": code}).encode()
        conn = HTTPConnection("127.0.0.1", port, timeout=3)
        conn.putrequest("POST", "/api/login", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("X-SS-CSRF", "1")
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        assert resp.status == 200
        conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_miniapp_group_chat_alone_403() -> None:
    import hashlib
    import hmac
    import time
    from urllib.parse import quote

    token = "123456:ABC"

    def init_data(user_id: int, chat_id: int) -> str:
        user = json.dumps({"id": user_id, "first_name": "T"}, separators=(",", ":"))
        auth_date = str(int(time.time()))
        chat = json.dumps({"id": chat_id, "type": "supergroup"}, separators=(",", ":"))
        pairs = {"auth_date": auth_date, "user": user, "chat": chat}
        data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        digest = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
        return (
            f"auth_date={auth_date}&user={quote(user)}&chat={quote(chat)}&hash={digest}"
        )

    httpd = start_web_server(
        LiveBus(),
        host="127.0.0.1",
        port=0,
        bot_token=token,
        allowed_chat_id="-100123",
        public_url="https://ss.example/app",
        token_path=False,
    )
    port = httpd.server_address[1]
    try:
        body = json.dumps({"initData": init_data(777, -100123)}).encode()
        conn = HTTPConnection("127.0.0.1", port, timeout=3)
        conn.putrequest("POST", "/api/auth/telegram", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        assert resp.status == 403, data
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_bot_uses_tg_cfg_allowed_users() -> None:
    from sysspectogram.notify_telegram import TelegramClient
    from sysspectogram.telegram_bot import TelegramBot

    client = TelegramClient(token="t", chat_id="-100123")
    bot = TelegramBot(client, tg_cfg={"allowed_user_ids": [555]})
    assert bot.allowed_chat("-100123", chat_type="supergroup", from_user_id=555)
    assert not bot.allowed_chat("-100123", chat_type="supergroup", from_user_id=777)


def test_backend_from_config_passes_private() -> None:
    be = backend_from_config({"response": {"allow_private_bans": True}, "ssh": {"port": 22}})
    assert be.allow_private_bans is True


def test_resolv_stub_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stub = tmp_path / "resolv.conf"
    stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
    upstream = tmp_path / "resolved.conf"
    upstream.write_text("nameserver 192.0.2.53\n", encoding="utf-8")

    real_read = Path.read_text

    def fake_read(self, *a, **k):  # noqa: ANN001
        if str(self) == "/etc/resolv.conf":
            return stub.read_text(encoding="utf-8")
        if str(self) == "/run/systemd/resolve/resolv.conf":
            return upstream.read_text(encoding="utf-8")
        return real_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", fake_read)
    monkeypatch.setattr(
        "sysspectogram.response.actions._resolvectl_upstreams",
        lambda: [],
    )
    from sysspectogram.response.protect import _resolver_addrs

    assert "192.0.2.53" in _resolver_addrs()


def test_ban_prefix_dry_run_uses_interval_path() -> None:
    nft = NftBackend()
    out = nft.ban_ip("2001:db8:1::/64", ttl_sec=60, dry_run=True)
    assert "dry-run ban" in out
    assert "2001:db8:1::/64" in out
