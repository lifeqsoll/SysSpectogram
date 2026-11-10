"""Mini App must not treat stripped group chat ids as user ids."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from http.client import HTTPConnection
from urllib.parse import quote

from sysspectogram.web.bus import LiveBus
from sysspectogram.web.server import start_web_server


def _init_data(bot_token: str, user_id: int, chat_id: int | None = None) -> str:
    user = json.dumps({"id": user_id, "first_name": "T"}, separators=(",", ":"))
    auth_date = str(int(time.time()))
    pairs = {"auth_date": auth_date, "user": user}
    if chat_id is not None:
        pairs["chat"] = json.dumps({"id": chat_id, "type": "supergroup"}, separators=(",", ":"))
    data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
    parts = [f"auth_date={auth_date}", f"user={quote(user)}"]
    if "chat" in pairs:
        parts.append(f"chat={quote(pairs['chat'])}")
    parts.append(f"hash={digest}")
    return "&".join(parts)


def _post_auth(port: int, init_data: str) -> tuple[int, dict]:
    body = json.dumps({"initData": init_data}).encode()
    conn = HTTPConnection("127.0.0.1", port, timeout=3)
    conn.putrequest("POST", "/api/auth/telegram", skip_host=True)
    conn.putheader("Host", "127.0.0.1")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    resp = conn.getresponse()
    data = json.loads(resp.read().decode())
    conn.close()
    return resp.status, data


def test_group_chat_id_does_not_match_stripped_user() -> None:
    token = "123456:ABC"
    httpd = start_web_server(
        LiveBus(),
        host="127.0.0.1",
        port=0,
        bot_token=token,
        allowed_chat_id="-100123",
        public_url="https://example.invalid/app",
        token_path=False,
    )
    port = httpd.server_address[1]
    try:
        st, data = _post_auth(port, _init_data(token, 100123))
        assert st == 403, data
        assert data.get("ok") is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_allowed_user_id_grants_session() -> None:
    token = "123456:ABC"
    httpd = start_web_server(
        LiveBus(),
        host="127.0.0.1",
        port=0,
        bot_token=token,
        allowed_chat_id="-100123",
        allowed_user_ids={"42"},
        public_url="https://example.invalid/app",
        token_path=False,
    )
    port = httpd.server_address[1]
    try:
        st, data = _post_auth(port, _init_data(token, 42, chat_id=-100123))
        assert st == 200, data
        assert data.get("ok") is True
    finally:
        httpd.shutdown()
        httpd.server_close()
