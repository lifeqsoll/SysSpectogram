from __future__ import annotations

import http.client
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def normalize_telegram_api_proxy(raw: str | None) -> str | None:
    """Accept only loopback HTTP CONNECT proxies (no auth, no path).

    Operators run sing-box / similar on localhost with their own subscription.
    Remote proxies are refused to avoid accidental SSRF / credential leakage.
    """
    text = (raw or "").strip()
    if not text:
        return None
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() != "http":
        return None
    if parsed.path not in ("", "/"):
        return None
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1"):
        host_out = "127.0.0.1"
    elif host in ("::1", "[::1]"):
        host_out = "[::1]"
    else:
        return None
    if parsed.port is None:
        return None
    try:
        port = int(parsed.port)
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None
    return f"http://{host_out}:{port}"


class _ManagedResponse:
    def __init__(self, connection: http.client.HTTPSConnection, response: http.client.HTTPResponse) -> None:
        self.connection = connection
        self.response = response

    def __enter__(self) -> http.client.HTTPResponse:
        return self.response

    def __exit__(self, *_: object) -> None:
        self.response.close()
        self.connection.close()


class TelegramClient:
    def __init__(
        self,
        token: str | None = None,
        chat_id: str | None = None,
        *,
        api_proxy: str | None = None,
    ) -> None:
        from sysspectogram.config import load_dotenv

        load_dotenv()
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = str(chat_id or os.environ.get("TELEGRAM_CHAT_ID", ""))
        self.base = f"https://api.telegram.org/bot{self.token}" if self.token else ""
        env_proxy = os.environ.get("TELEGRAM_API_PROXY", "")
        # Env wins so operators can override without rewriting YAML.
        chosen = env_proxy.strip() or (api_proxy or "")
        self.proxy_url = normalize_telegram_api_proxy(chosen)

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def _open_request(self, request: urllib.request.Request, timeout: float) -> _ManagedResponse:
        target = urllib.parse.urlsplit(request.full_url)
        if target.scheme != "https" or target.hostname != "api.telegram.org":
            raise OSError("Telegram client destination rejected")
        connection: http.client.HTTPSConnection | None = None
        if self.proxy_url:
            proxy = urllib.parse.urlsplit(self.proxy_url)
            # Re-validate — proxy_url is already normalized, but be strict.
            if normalize_telegram_api_proxy(self.proxy_url) is None:
                raise OSError("Telegram API proxy configuration rejected")
            assert proxy.hostname is not None and proxy.port is not None
            connection = http.client.HTTPSConnection(proxy.hostname, proxy.port, timeout=timeout)
            connection.set_tunnel(target.hostname, target.port or 443)
            try:
                connection.connect()
            except (OSError, ssl.SSLError, http.client.HTTPException):
                connection.close()
                connection = None
        if connection is None:
            # Only connect/tunnel setup may fall back: request data has not been sent yet.
            connection = http.client.HTTPSConnection(target.hostname, target.port or 443, timeout=timeout)
            connection.connect()
        path = urllib.parse.urlunsplit(("", "", target.path or "/", target.query, ""))
        try:
            headers = dict(request.header_items())
            if request.data is not None and not any(name.lower() == "content-type" for name in headers):
                # urllib's HTTPHandler supplies this default for form encoded Bot API requests.
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            connection.request(request.get_method(), path, body=request.data, headers=headers)
            return _ManagedResponse(connection, connection.getresponse())
        except Exception:
            connection.close()
            raise

    def _post(self, method: str, payload: dict[str, Any], timeout: float = 30.0) -> dict:
        if not self.token:
            return {"ok": False, "description": "no token"}
        url = f"{self.base}/{method}"
        flat: dict[str, str] = {}
        for k, v in payload.items():
            if v is None:
                continue
            if isinstance(v, bool):
                flat[k] = "true" if v else "false"
            elif isinstance(v, (dict, list)):
                flat[k] = json.dumps(v, separators=(",", ":"))
            else:
                flat[k] = str(v)
        data = urllib.parse.urlencode(flat).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        try:
            with self._open_request(req, timeout=timeout) as resp:
                result = json.loads(resp.read().decode("utf-8", errors="replace"))
                if resp.status >= 400:
                    return {"ok": False, "description": f"Telegram API request failed (HTTP {resp.status})"}
                return result
        except urllib.error.HTTPError as exc:
            return {"ok": False, "description": f"Telegram API request failed (HTTP {exc.code})"}
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
            return {"ok": False, "description": f"Telegram connection failed ({type(exc).__name__})"}

    def send_message(
        self,
        text: str,
        *,
        chat_id: str | None = None,
        reply_markup: dict | None = None,
        parse_mode: str | None = None,
    ) -> dict:
        payload: dict[str, Any] = {
            "chat_id": chat_id or self.chat_id,
            "text": text[:4000],
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        if parse_mode:
            payload["parse_mode"] = parse_mode
        return self._post("sendMessage", payload)

    def send_document(
        self,
        path: Path,
        *,
        caption: str = "",
        chat_id: str | None = None,
    ) -> dict:
        if not self.token:
            return {"ok": False, "description": "no token"}
        boundary = "----sysspectogram"
        chat = chat_id or self.chat_id
        body = Path(path).read_bytes()
        filename = Path(path).name
        parts = []
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat}\r\n".encode()
        )
        if caption:
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption[:900]}\r\n".encode()
            )
        parts.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
                f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'
            ).encode()
            + body
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        data = b"".join(parts)
        url = f"{self.base}/sendDocument"
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with self._open_request(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8", errors="replace"))
                return (
                    result
                    if resp.status < 400
                    else {"ok": False, "description": f"Telegram API request failed (HTTP {resp.status})"}
                )
        except Exception as exc:
            return {"ok": False, "description": f"Telegram connection failed ({type(exc).__name__})"}

    def _send_multipart(
        self,
        method: str,
        *,
        field: str,
        filename: str,
        content_type: str,
        payload: bytes,
        caption: str = "",
        chat_id: str | None = None,
        reply_markup: dict | None = None,
    ) -> dict:
        if not self.token:
            return {"ok": False, "description": "no token"}
        boundary = "----sysspectogram"
        chat = chat_id or self.chat_id
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat}\r\n".encode(),
        ]
        if caption:
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption[:900]}\r\n".encode()
            )
        if reply_markup is not None:
            parts.append(
                (
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"reply_markup\"\r\n\r\n"
                    f"{json.dumps(reply_markup)}\r\n"
                ).encode()
            )
        parts.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; "
                f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
            ).encode()
            + payload
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        req = urllib.request.Request(
            f"{self.base}/{method}",
            data=b"".join(parts),
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with self._open_request(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8", errors="replace"))
                return (
                    result
                    if resp.status < 400
                    else {"ok": False, "description": f"Telegram API request failed (HTTP {resp.status})"}
                )
        except Exception as exc:
            return {"ok": False, "description": f"Telegram connection failed ({type(exc).__name__})"}

    def send_photo_bytes(
        self,
        png_bytes: bytes,
        *,
        caption: str = "",
        chat_id: str | None = None,
        reply_markup: dict | None = None,
    ) -> dict:
        return self._send_multipart(
            "sendPhoto",
            field="photo",
            filename="chart.png",
            content_type="image/png",
            payload=png_bytes,
            caption=caption,
            chat_id=chat_id,
            reply_markup=reply_markup,
        )

    def send_animation_bytes(
        self,
        gif_bytes: bytes,
        *,
        caption: str = "",
        chat_id: str | None = None,
        reply_markup: dict | None = None,
    ) -> dict:
        return self._send_multipart(
            "sendAnimation",
            field="animation",
            filename="charts.gif",
            content_type="image/gif",
            payload=gif_bytes,
            caption=caption,
            chat_id=chat_id,
            reply_markup=reply_markup,
        )

    def answer_callback(self, callback_query_id: str, text: str = "") -> dict:
        return self._post(
            "answerCallbackQuery",
            {"callback_query_id": callback_query_id, "text": text[:180]},
        )

    def set_chat_menu_button_webapp(self, text: str, url: str, chat_id: str | None = None) -> dict:
        """Attach a Mini App menu button (HTTPS URL required for phones)."""
        payload: dict[str, Any] = {
            "menu_button": {
                "type": "web_app",
                "text": text[:20] or "Dashboard",
                "web_app": {"url": url},
            }
        }
        if chat_id or self.chat_id:
            payload["chat_id"] = chat_id or self.chat_id
        return self._post("setChatMenuButton", payload)

    def get_updates(self, offset: int | None = None, timeout: int = 25) -> list[dict]:
        payload: dict[str, Any] = {"timeout": timeout}
        if offset is not None:
            payload["offset"] = offset
        res = self._post("getUpdates", payload, timeout=timeout + 10)
        if not res.get("ok"):
            return []
        return list(res.get("result") or [])
