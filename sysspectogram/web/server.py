from __future__ import annotations

import hmac
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
from sysspectogram.console_unlock import ConsoleUnlock

STATIC_DIR = Path(__file__).resolve().parent / "static"

# L-01: cap concurrent handler threads + SSE fan-out.
MAX_WEB_CONNECTIONS = 32
MAX_SSE_STREAMS = 4
SSE_MAX_LIFE_SEC = 30 * 60
HANDLER_SOCKET_TIMEOUT = 15.0


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
        unlock: ConsoleUnlock | None = None,
        launch_token: str | None = None,
    ) -> None:
        self.bus = bus
        self.bot_token = bot_token or ""
        self.allowed_chat_id = str(allowed_chat_id or "")
        self.public_url = (public_url or "").rstrip("/")
        self.bind_host = bind_host
        self.controllers = controllers
        self.unlock = unlock
        self.launch_token = (launch_token or "").strip() or None
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sse_slots = threading.BoundedSemaphore(MAX_SSE_STREAMS)

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

    def bearer_ok(self, header: str | None) -> bool:
        if not self.launch_token or not header:
            return False
        raw = header.strip()
        if raw.lower().startswith("bearer "):
            raw = raw[7:].strip()
        return hmac.compare_digest(raw, self.launch_token)

    def allow_local_unauth(self, client_ip: str) -> bool:
        # Read-only local convenience only. Mutations need session/Bearer (M-01).
        # Never treat tunnel→localhost as trusted when a public Mini App URL is configured.
        if self.public_url:
            return False
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
        # Mutations locked → hide process list / ban details (stolen token can still see scores)
        locked = False
        if self.unlock is not None and self.unlock.enabled and not self.unlock.unlocked():
            locked = True
        elif callable(getattr(self.controllers, "unlock_ok", None)):
            try:
                locked = not bool(self.controllers.unlock_ok())
            except Exception:
                locked = True
        if locked:
            snap["processes"] = []
            snap["bans"] = []
            snap["allowlist"] = []
            snap["control_unlocked"] = False
        return snap


def _host_header_name(raw: str) -> str:
    """Extract hostname from Host header; keep IPv6 literals like ``[::1]:port``."""
    h = (raw or "").strip().lower()
    if not h:
        return ""
    if h.startswith("["):
        end = h.find("]")
        if end > 0:
            return h[1:end]
        return h.strip("[]")
    # hostname:port or ipv4:port — only strip a numeric port.
    if h.count(":") == 1:
        host, maybe_port = h.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return h


def _make_handler(app: WebAppState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = HANDLER_SOCKET_TIMEOUT

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
            """Mutating / privileged: session cookie or launch Bearer only."""
            if app.session_ok(self._cookie("ss_session")):
                return True
            if app.bearer_ok(self.headers.get("Authorization")):
                return True
            return False

        def _authorized_read(self) -> bool:
            if self._authorized():
                return True
            if app.allow_local_unauth(self._client_ip()):
                return True
            return False

        def _allowed_hosts(self) -> set[str]:
            allowed = {"127.0.0.1", "localhost", "::1"}
            if app.bind_host:
                bh = str(app.bind_host).strip().lower()
                if bh.startswith("[") and bh.endswith("]"):
                    bh = bh[1:-1]
                allowed.add(bh)
            if app.public_url:
                try:
                    ph = (urlparse(app.public_url).hostname or "").lower()
                    if ph:
                        allowed.add(ph)
                except Exception:
                    pass
            return allowed

        def _host_ok(self) -> bool:
            # Fail closed: missing/empty Host must not skip the allowlist
            # (HTTP/1.0 or stripped-header clients).
            host_hdr = _host_header_name(self.headers.get("Host") or "")
            if not host_hdr:
                return False
            return host_hdr in self._allowed_hosts()

        def _require_json_ctype(self) -> bool:
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            return ctype == "application/json"

        def _csrf_ok(self) -> bool:
            origin = (self.headers.get("Origin") or "").rstrip("/")
            if app.public_url:
                expect = app.public_url.rstrip("/")
                return bool(origin) and origin == expect
            if origin:
                ohost = (urlparse(origin).hostname or "").lower()
                if ohost not in {"127.0.0.1", "localhost", "::1"}:
                    return False
            return (self.headers.get("X-SS-CSRF") or "").strip() == "1"

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

        def _cors_origin(self) -> str | None:
            """Only echo Origin when it matches configured public_url (no *)."""
            if not app.public_url:
                return None
            origin = (self.headers.get("Origin") or "").rstrip("/")
            if origin and origin == app.public_url.rstrip("/"):
                return origin
            return None

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            allow = self._cors_origin()
            if allow:
                self.send_header("Access-Control-Allow-Origin", allow)
                self.send_header("Vary", "Origin")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, X-Telegram-Init-Data, X-SS-CSRF",
            )
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            # Host check first for every path (DNS rebinding / M-05).
            if not self._host_ok():
                return self._json(403, {"ok": False, "error": "bad host"})
            if path in {"/", "/index.html"}:
                return self._static("index.html", "text/html; charset=utf-8")
            if path == "/styles.css":
                return self._static("styles.css", "text/css; charset=utf-8")
            if path == "/app.js":
                return self._static("app.js", "application/javascript; charset=utf-8")
            if path == "/api/health":
                body: dict[str, Any] = {"ok": True}
                if self._authorized():
                    body["public_url"] = app.public_url or None
                    body["actions"] = app.controllers is not None
                return self._json(200, body)
            if path in {"/api/snapshot", "/api/status", "/api/stream"}:
                if not self._authorized_read():
                    return self._json(401, {"ok": False, "error": "unauthorized"})
            elif not self._authorized():
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

            if not self._host_ok():
                return self._json(403, {"ok": False, "error": "bad host"})

            if path in {"/api/auth/telegram", "/api/unlock", "/api/action"}:
                if not self._require_json_ctype():
                    return self._json(415, {"ok": False, "error": "Content-Type must be application/json"})

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
                allowed = (app.allowed_chat_id or "").strip()
                # Public Mini App must pin chat/user; empty allowlist was any valid initData.
                if app.public_url and not allowed:
                    return self._json(
                        403,
                        {"ok": False, "error": "allowed_chat_id required when public_url is set"},
                    )
                if allowed:
                    ok = uid == allowed or uid == allowed.lstrip("-")
                    if not ok:
                        return self._json(403, {"ok": False, "error": "chat not allowlisted"})
                sess = app.issue_session()
                cookie = f"ss_session={sess}; Path=/; HttpOnly; SameSite=Lax"
                if app.public_url and str(app.public_url).startswith("https"):
                    cookie += "; Secure"
                extra = {"Set-Cookie": cookie}
                allow = self._cors_origin()
                if allow:
                    extra["Access-Control-Allow-Origin"] = allow
                    extra["Vary"] = "Origin"
                return self._json(200, {"ok": True, "user": user}, extra=extra)

            # Console unlock via Mini App / local UI (code never in .env).
            # M-01: never mint ss_session for an unauthenticated loopback client —
            # require Bearer (state/web.token) / existing session, OR a correct code
            # in this request. Gate-off / already-unlocked alone is not enough.
            if path == "/api/unlock":
                if not self._csrf_ok():
                    return self._json(403, {"ok": False, "error": "csrf"})
                authed = self._authorized()
                if app.public_url and not authed:
                    return self._json(401, {"ok": False, "error": "unauthorized"})

                def _session_extra() -> dict[str, str]:
                    sess = app.issue_session()
                    cookie = f"ss_session={sess}; Path=/; HttpOnly; SameSite=Lax"
                    if app.public_url and str(app.public_url).startswith("https"):
                        cookie += "; Secure"
                    return {"Set-Cookie": cookie}

                if app.unlock is None or not app.unlock.enabled:
                    if not authed:
                        return self._json(401, {"ok": False, "error": "unauthorized"})
                    return self._json(
                        200,
                        {"ok": True, "unlocked": True, "note": "gate off"},
                        extra=_session_extra(),
                    )

                if app.unlock.unlocked():
                    if not authed:
                        return self._json(401, {"ok": False, "error": "unauthorized"})
                    return self._json(
                        200,
                        {
                            "ok": True,
                            "unlocked": True,
                            "status": app.controllers.status() if app.controllers else {},
                        },
                        extra=_session_extra(),
                    )

                code = str(payload.get("code") or "")
                if not code.strip():
                    return self._json(401, {"ok": False, "error": "unauthorized"})
                # Unauthenticated callers: only a correct code mints a session.
                # Wrong guesses must not burn fail_count (local uid lockout DoS).
                if not authed:
                    if not app.unlock.code_matches(code):
                        return self._json(
                            403,
                            {"ok": False, "error": "bad unlock code", "unlocked": False},
                        )
                if app.unlock.try_unlock(code):
                    return self._json(
                        200,
                        {
                            "ok": True,
                            "unlocked": True,
                            "status": app.controllers.status() if app.controllers else {},
                        },
                        extra=_session_extra(),
                    )
                return self._json(
                    403,
                    {
                        "ok": False,
                        "error": "bad unlock code",
                        "fails": app.unlock.fail_count,
                        "unlocked": False,
                    },
                )

            if not self._authorized():
                return self._json(401, {"ok": False, "error": "unauthorized"})

            if path == "/api/action":
                if app.controllers is None:
                    return self._json(503, {"ok": False, "error": "actions not configured"})
                if not self._csrf_ok():
                    return self._json(403, {"ok": False, "error": "csrf"})
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
            if not app._sse_slots.acquire(blocking=False):
                return self._json(503, {"ok": False, "error": "too many streams"})
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                deadline = time.time() + SSE_MAX_LIFE_SEC
                while time.time() < deadline:
                    snap = app.enriched_snapshot()
                    line = f"data: {json.dumps(snap, ensure_ascii=False)}\n\n"
                    self.wfile.write(line.encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(1.0)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            finally:
                app._sse_slots.release()

    return Handler


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with a hard cap on concurrent connections (L-01)."""

    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, *, max_connections: int = MAX_WEB_CONNECTIONS):
        self._conn_sem = threading.BoundedSemaphore(max(1, int(max_connections)))
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address) -> None:  # noqa: ANN001
        if not self._conn_sem.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
            return
        t = threading.Thread(
            target=self._process_request_release,
            args=(request, client_address),
            daemon=True,
        )
        t.start()

    def _process_request_release(self, request, client_address) -> None:  # noqa: ANN001
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                self._conn_sem.release()


def start_web_server(
    bus: LiveBus,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    bot_token: str | None = None,
    allowed_chat_id: str | None = None,
    public_url: str | None = None,
    controllers: WebControllers | None = None,
    unlock: ConsoleUnlock | None = None,
    token_path: Path | None | bool = True,
    max_connections: int = MAX_WEB_CONNECTIONS,
) -> ThreadingHTTPServer:
    launch_token = secrets.token_urlsafe(32)
    # token_path=True → default state/web.token; Path → that path; False/None → memory only.
    write_path: Path | None
    if token_path is True:
        try:
            from sysspectogram.config import state_root

            write_path = state_root() / "state" / "web.token"
        except Exception:
            write_path = None
    elif isinstance(token_path, Path):
        write_path = token_path
    else:
        write_path = None
    if write_path is not None:
        try:
            from sysspectogram.secret_file import write_secret_file

            write_secret_file(write_path, launch_token + "\n")
        except OSError:
            pass

    app = WebAppState(
        bus,
        bot_token=bot_token,
        allowed_chat_id=allowed_chat_id,
        public_url=public_url,
        bind_host=host,
        controllers=controllers,
        unlock=unlock,
        launch_token=launch_token,
    )

    try:
        httpd = LimitedThreadingHTTPServer(
            (host, port),
            _make_handler(app),
            max_connections=max_connections,
        )
    except OSError as exc:
        raise OSError(
            f"web dashboard cannot bind {host}:{port} ({exc}). "
            f"Free the port (fuser -k {port}/tcp) or set web.port / --port"
        ) from exc
    thread = threading.Thread(target=httpd.serve_forever, name="sysspectogram-web", daemon=True)
    thread.start()
    return httpd
