from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class TelegramClient:
    def __init__(self, token: str | None = None, chat_id: str | None = None) -> None:
        from sysspectogram.config import load_dotenv

        load_dotenv()
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = str(chat_id or os.environ.get("TELEGRAM_CHAT_ID", ""))
        self.base = f"https://api.telegram.org/bot{self.token}" if self.token else ""

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

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
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            return {"ok": False, "description": f"HTTP {exc.code}: {body or exc.reason}"}
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "description": str(exc)}

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
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return {"ok": False, "description": str(exc)}

    def send_photo_bytes(
        self,
        png_bytes: bytes,
        *,
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
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; "
                f'filename="heatmap.png"\r\nContent-Type: image/png\r\n\r\n'
            ).encode()
            + png_bytes
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        req = urllib.request.Request(
            f"{self.base}/sendPhoto",
            data=b"".join(parts),
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return {"ok": False, "description": str(exc)}

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
