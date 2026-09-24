from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sysspectogram.web.actions import WebControllers
from sysspectogram.web.auth import validate_webapp_init_data
from sysspectogram.web.bus import LiveBus

STATIC_DIR = Path(__file__).resolve().parent / "static"


class WebAppState:
    def __init__(
        self,
        bus: LiveBus,
        *,
        bot_token: str | None,
        allowed_chat_id: str | None,
        public_url: str | None,
        bind_host: str,
        controllers: WebControllers | None = None,
    ) -> None:
        self.bus = bus
        self.bot_token = bot_token or ""
        self.allowed_chat_id = str(allowed_chat_id or "")
        self.public_url = (public_url or "").rstrip("/")
        self.bind_host = bind_host
        self.controllers = controllers
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def issue_session(self) -> str:
        tok = secrets.token_urlsafe(24)
        with self._lock:
            self._sessions[tok] = time.time() + 86400.0
        return tok

    def session_ok(self, tok: str | None) -> bool:
        if not tok:
            return False
        with self._lock:
            exp = self._sessions.get(tok)
            if not exp:
                return False
            if exp < time.time():
                self._sessions.pop(tok, None)
                return False
            return True

    def allow_local_unauth(self, client_ip: str) -> bool:
        return client_ip in {"127.0.0.1", "::1", "localhost"} and self.bind_host in {
            "127.0.0.1",
            "localhost",
            "::1",
        }

    def enriched_snapshot(self) -> dict[str, Any]:
        snap = self.bus.snapshot()
        if self.controllers is not None:
            st = self.controllers.status()
            snap.update(st)
            if self.controllers.watcher is not None:
                snap["quiet"] = self.controllers.watcher.state.quiet
                snap["lockdown"] = self.controllers.watcher.state.lockdown
        return snap


def _make_handler(app: WebAppState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            return

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _cookie(self, name: str) -> str | None:
            raw = self.headers.get("Cookie") or ""
            for part in raw.split(";"):
                part = part.strip()
                if part.startswith(name + "="):
                    return part.split("=", 1)[1]
            return None

        def _authorized(self) -> bool:
            if app.session_ok(self._cookie("ss_session")):
                return True
            if app.allow_local_unauth(self._client_ip()):
                return True
            return False

        def _send(self, code: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if extra:
                for k, v in extra.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: Any, extra: dict | None = None) -> None:
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self._send(code, data, "application/json; charset=utf-8", extra)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Telegram-Init-Data")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in {"/", "/index.html"}:
                return self._static("index.html", "text/html; charset=utf-8")
            if path == "/styles.css":
                return self._static("styles.css", "text/css; charset=utf-8")
            if path == "/app.js":
                return self._static("app.js", "application/javascript; charset=utf-8")
            if path == "/api/health":
                return self._json(
                    200,
                    {
                        "ok": True,
                        "public_url": app.public_url or None,
                        "actions": app.controllers is not None,
                    },
                )
            if not self._authorized():
                return self._json(401, {"ok": False, "error": "unauthorized"})
            if path == "/api/snapshot":
                return self._json(200, app.enriched_snapshot())
            if path == "/api/status":
                if app.controllers is None:
                    return self._json(200, {"ok": True, "dry_run": True, "bans": []})
                return self._json(200, {"ok": True, **app.controllers.status()})
            if path == "/api/stream":
                return self._sse()
            self._json(404, {"ok": False, "error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return self._json(400, {"ok": False, "error": "bad json"})

            if path == "/api/auth/telegram":
                init_data = payload.get("initData") or self.headers.get("X-Telegram-Init-Data") or ""
                parsed = validate_webapp_init_data(init_data, app.bot_token)
                if parsed is None:
                    return self._json(403, {"ok": False, "error": "invalid initData"})
                user = parsed.get("user") or {}
                uid = str(user.get("id") or "")
                allowed = app.allowed_chat_id
                if allowed:
                    ok = uid == allowed or uid == allowed.lstrip("-")
                    if not ok:
                        return self._json(403, {"ok": False, "error": "chat not allowlisted"})
                sess = app.issue_session()
                secure = bool(app.public_url and str(app.public_url).startswith("https"))
                cookie = (
                    f"ss_session={sess}; Path=/; HttpOnly; "
                    + ("SameSite=None; Secure" if secure else "SameSite=Lax")
                )
                return self._json(200, {"ok": True, "user": user}, extra={"Set-Cookie": cookie})

            if not self._authorized():
                return self._json(401, {"ok": False, "error": "unauthorized"})

            if path == "/api/action":
                if app.controllers is None:
                    return self._json(503, {"ok": False, "error": "actions not configured"})
                action = str(payload.get("action") or "")
                data = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
                # strip action key from payload copy
                body = {k: v for k, v in (data or {}).items() if k != "action"}
                if "action" in payload and isinstance(payload.get("payload"), dict):
                    body = payload["payload"]
                elif "action" in payload:
                    body = {k: v for k, v in payload.items() if k != "action"}
                return self._json(200, app.controllers.run(action, body))

            self._json(404, {"ok": False, "error": "not found"})

        def _static(self, name: str, ctype: str) -> None:
            path = STATIC_DIR / name
            if not path.exists():
                return self._json(404, {"ok": False, "error": "missing static"})
            self._send(200, path.read_bytes(), ctype)

        def _sse(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    snap = app.enriched_snapshot()
                    line = f"data: {json.dumps(snap, ensure_ascii=False)}\n\n"
                    self.wfile.write(line.encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(1.0)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

    return Handler


def start_web_server(
    bus: LiveBus,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    bot_token: str | None = None,
    allowed_chat_id: str | None = None,
    public_url: str | None = None,
    controllers: WebControllers | None = None,
) -> ThreadingHTTPServer:
    app = WebAppState(
        bus,
        bot_token=bot_token,
        allowed_chat_id=allowed_chat_id,
        public_url=public_url,
        bind_host=host,
        controllers=controllers,
    )

    class ReusableServer(ThreadingHTTPServer):
        allow_reuse_address = True

    try:
        httpd = ReusableServer((host, port), _make_handler(app))
    except OSError as exc:
        raise OSError(
            f"web dashboard cannot bind {host}:{port} ({exc}). "
            f"Free the port (fuser -k {port}/tcp) or set web.port / --port"
        ) from exc
    thread = threading.Thread(target=httpd.serve_forever, name="sysspectogram-web", daemon=True)
    thread.start()
    return httpd
