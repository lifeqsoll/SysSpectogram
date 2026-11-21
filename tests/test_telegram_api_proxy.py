"""Telegram Bot API optional local CONNECT proxy + pre-send direct fallback."""

from __future__ import annotations

import http.client
from unittest.mock import MagicMock, patch

import pytest

from sysspectogram.notify_telegram import (
    TelegramClient,
    normalize_telegram_api_proxy,
)


def test_normalize_proxy_accepts_loopback_http():
    assert normalize_telegram_api_proxy("http://127.0.0.1:1080") == "http://127.0.0.1:1080"
    assert normalize_telegram_api_proxy("http://localhost:9050/") == "http://127.0.0.1:9050"
    assert normalize_telegram_api_proxy("  HTTP://[::1]:1080  ") == "http://[::1]:1080"


def test_normalize_proxy_rejects_remote_and_junk():
    assert normalize_telegram_api_proxy("") is None
    assert normalize_telegram_api_proxy(None) is None
    assert normalize_telegram_api_proxy("https://127.0.0.1:1080") is None
    assert normalize_telegram_api_proxy("http://evil.example:1080") is None
    assert normalize_telegram_api_proxy("http://127.0.0.1:1080/path") is None
    assert normalize_telegram_api_proxy("http://user:pass@127.0.0.1:1080") is None
    assert normalize_telegram_api_proxy("socks5://127.0.0.1:1080") is None


def test_client_env_proxy(monkeypatch):
    monkeypatch.setenv("TELEGRAM_API_PROXY", "http://127.0.0.1:1080")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    c = TelegramClient(token="t", chat_id="1")
    assert c.proxy_url == "http://127.0.0.1:1080"


def test_client_config_proxy_ignored_if_env_set(monkeypatch):
    monkeypatch.setenv("TELEGRAM_API_PROXY", "http://127.0.0.1:1080")
    c = TelegramClient(token="t", chat_id="1", api_proxy="http://127.0.0.1:9999")
    assert c.proxy_url == "http://127.0.0.1:1080"


def test_open_request_rejects_non_telegram_host(monkeypatch):
    monkeypatch.delenv("TELEGRAM_API_PROXY", raising=False)
    c = TelegramClient(token="t", chat_id="1")
    import urllib.request

    req = urllib.request.Request("https://evil.example/bot", method="GET")
    with pytest.raises(OSError, match="destination rejected"):
        c._open_request(req, timeout=5)


def test_proxy_connect_failure_falls_back_direct(monkeypatch):
    monkeypatch.setenv("TELEGRAM_API_PROXY", "http://127.0.0.1:1080")
    c = TelegramClient(token="t", chat_id="1")
    import urllib.request

    req = urllib.request.Request(
        "https://api.telegram.org/bott/getMe",
        data=b"x=1",
        method="POST",
    )

    proxy_conn = MagicMock()
    proxy_conn.connect.side_effect = OSError("proxy down")
    direct_conn = MagicMock()
    direct_resp = MagicMock()
    direct_resp.status = 200
    direct_resp.read.return_value = b'{"ok":true,"result":{}}'
    direct_conn.getresponse.return_value = direct_resp

    with patch("sysspectogram.notify_telegram.http.client.HTTPSConnection") as HC:
        HC.side_effect = [proxy_conn, direct_conn]
        with c._open_request(req, timeout=5) as resp:
            assert resp is direct_resp
        assert proxy_conn.close.called
        direct_conn.request.assert_called_once()
        assert HC.call_count == 2


def test_post_uses_open_request(monkeypatch):
    monkeypatch.delenv("TELEGRAM_API_PROXY", raising=False)
    c = TelegramClient(token="tok", chat_id="1")
    fake = MagicMock()
    fake.__enter__ = MagicMock(return_value=MagicMock(status=200, read=MagicMock(return_value=b'{"ok":true}')))
    fake.__exit__ = MagicMock(return_value=False)
    with patch.object(c, "_open_request", return_value=fake) as op:
        out = c._post("getMe", {})
    assert out == {"ok": True}
    op.assert_called_once()
