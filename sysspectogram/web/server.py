from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sysspectogram.web.actions import WebControllers
from sysspectogram.web.auth import validate_webapp_init_data
from sysspectogram.web.bus import LiveBus
from sysspectogram.web.login_code import WebLoginCode
from sysspectogram.console_unlock import ConsoleUnlock

STATIC_DIR = Path(__file__).resolve().parent / "static"

# L-01: cap concurrent handler threads + SSE fan-out.
MAX_WEB_CONNECTIONS = 32
MAX_SSE_STREAMS = 4
SSE_MAX_LIFE_SEC = 30 * 60
HANDLER_SOCKET_TIMEOUT = 15.0
SECURITY_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://telegram.org; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'self' https://web.telegram.org"
)
UNLOCK_RATE_MAX = 5
UNLOCK_RATE_WINDOW_SEC = 300.0
UNLOCK_LOCKOUT_SEC = 300.0
SSE_SESSION_RECHECK_SEC = 5.0


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
        login: WebLoginCode | None = None,
        launch_token: str | None = None,
        allowed_user_ids: set[str] | list[str] | None = None,
    ) -> None:
        self.bus = bus
        self.bot_token = bot_token or ""
        self.allowed_chat_id = str(allowed_chat_id or "")
        self.allowed_user_ids = {str(x).strip() for x in (allowed_user_ids or set()) if str(x).strip()}
        self.public_url = (public_url or "").rstrip("/")
        self.bind_host = bind_host
        self.controllers = controllers
        self.unlock = unlock
        self.login = login
        self.launch_token = (launch_token or "").strip() or None
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sse_slots = threading.BoundedSemaphore(MAX_SSE_STREAMS)
        self._unlock_fails: dict[str, deque[float]] = {}
        self._unlock_rl_lock = threading.Lock()

    def _unlock_rate_status(self, ip: str) -> tuple[bool, float, int]:
        """Return (allowed, backoff_sec, recent_fail_count)."""
        now = time.time()
        with self._unlock_rl_lock:
            q = self._unlock_fails.setdefault(ip, deque())
            while q and now - q[0] >= UNLOCK_RATE_WINDOW_SEC:
                q.popleft()
            n = len(q)
            if n >= UNLOCK_RATE_MAX:
                locked_from = q[UNLOCK_RATE_MAX - 1]
                remaining = UNLOCK_LOCKOUT_SEC - (now - locked_from)
                if remaining > 0:
                    return False, remaining, n
            backoff = min(1.5, 0.08 * (2 ** n)) if n else 0.0
            return True, backoff, n

    def _unlock_record_fail(self, ip: str) -> None:
        with self._unlock_rl_lock:
            self._unlock_fails.setdefault(ip, deque()).append(time.time())

    def issue_session(self) -> str:
        tok = secrets.token_urlsafe(24)
        with self._lock:
            self._sessions[tok] = time.time() + 86400.0
        return tok

    def revoke_session(self, tok: str | None) -> None:
        if not tok:
            return
        with self._lock:
            self._sessions.pop(tok, None)

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

    def control_locked(self) -> bool:
        """True when console unlock is required and not yet satisfied."""
        if self.unlock is not None and self.unlock.enabled and not self.unlock.unlocked():
            return True
        if callable(getattr(self.controllers, "unlock_ok", None)):
            try:
                return not bool(self.controllers.unlock_ok())
            except Exception:
                return True
        return False

    def redact_locked_fields(self, snap: dict[str, Any]) -> dict[str, Any]:
        """When LOCKED, drop bans/processes/allowlist (scores may remain)."""
        if not self.control_locked():
            return snap
        out = dict(snap)
        out["processes"] = []
        out["bans"] = []
        out["allowlist"] = []
        out["control_unlocked"] = False
        return out

    def enriched_snapshot(self) -> dict[str, Any]:
        snap = self.bus.snapshot()
        if self.controllers is not None:
            st = self.controllers.status()
            snap.update(st)
            if self.controllers.watcher is not None:
                snap["quiet"] = self.controllers.watcher.state.quiet
                snap["lockdown"] = self.controllers.watcher.state.lockdown
        return self.redact_locked_fields(snap)

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
            self.send_header("Content-Security-Policy", SECURITY_CSP)
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
            if path == "/chart.umd.min.js":
                return self._static("chart.umd.min.js", "application/javascript; charset=utf-8")
            if path == "/api/health":
                # unlock_code_len is not secret — UI needs it for maxlength (codes are alphanumeric).
                code_len = int(app.unlock.code_len) if app.unlock is not None else 10
                body: dict[str, Any] = {"ok": True, "unlock_code_len": code_len}
                if self._authorized():
                    body["public_url"] = app.public_url or None
                    body["actions"] = app.controllers is not None
                return self._json(200, body)
            # Read metrics require a real session/Bearer — loopback alone is not enough.
            if path in {"/api/snapshot", "/api/status", "/api/stream"}:
                if not self._authorized():
                    return self._json(401, {"ok": False, "error": "auth required"})
            elif not self._authorized():
                return self._json(401, {"ok": False, "error": "unauthorized"})
            if path == "/api/snapshot":
                return self._json(200, app.enriched_snapshot())
            if path == "/api/status":
                if app.controllers is None:
                    return self._json(200, app.redact_locked_fields({"ok": True, "dry_run": True, "bans": []}))
                st = {"ok": True, **app.controllers.status()}
                return self._json(200, app.redact_locked_fields(st))
            if path == "/api/stream":
                return self._sse()
            self._json(404, {"ok": False, "error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            # Host before body (DoS / DNS-rebinding) — reject early.
            if not self._host_ok():
                return self._json(403, {"ok": False, "error": "bad host"})
            cl_raw = (self.headers.get("Content-Length") or "0").strip()
            try:
                length = int(cl_raw)
            except ValueError:
                return self._json(400, {"ok": False, "error": "bad Content-Length"})
            if length < 0:
                return self._json(400, {"ok": False, "error": "bad Content-Length"})
            if length > 64 * 1024:
                return self._json(413, {"ok": False, "error": "body too large"})
            raw = self.rfile.read(length) if length else b"{}"

            if path in {"/api/auth/telegram", "/api/unlock", "/api/login", "/api/logout", "/api/action"}:
                if not self._require_json_ctype():
                    return self._json(415, {"ok": False, "error": "Content-Type must be application/json"})

            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return self._json(400, {"ok": False, "error": "bad json"})
            if not isinstance(payload, dict):
                return self._json(400, {"ok": False, "error": "body must be an object"})

            if path == "/api/auth/telegram":
                init_data = payload.get("initData") or self.headers.get("X-Telegram-Init-Data") or ""
                parsed = validate_webapp_init_data(init_data, app.bot_token)
                if parsed is None:
                    return self._json(403, {"ok": False, "error": "invalid initData"})
                user = parsed.get("user") or {}
                uid = str(user.get("id") or "")
                chat_from = ""
                raw_chat = (parsed.get("chat") or {})
                if isinstance(raw_chat, dict):
                    chat_from = str(raw_chat.get("id") or "")
                allowed_chat = (app.allowed_chat_id or "").strip()
                allowed_users = set(app.allowed_user_ids)
                # Public Mini App must pin user allowlist and/or chat; never lstrip("-")
                # (group -100123 must not match user 100123).
                if app.public_url and not allowed_chat and not allowed_users:
                    return self._json(
                        403,
                        {"ok": False, "error": "allowed_chat_id or allowed_user_ids required when public_url is set"},
                    )
                ok = True
                if allowed_users or allowed_chat:
                    ok = False
                    if allowed_users and uid in allowed_users:
                        ok = True
                        if allowed_chat and chat_from and chat_from != allowed_chat:
                            ok = False
                    elif not allowed_users and allowed_chat:
                        ok = uid == allowed_chat or (bool(chat_from) and chat_from == allowed_chat)
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

            # Dashboard login code → ss_session only (does NOT unlock control plane).
            if path == "/api/login":
                if not self._csrf_ok():
                    return self._json(403, {"ok": False, "error": "csrf"})
                if app.login is None:
                    return self._json(503, {"ok": False, "error": "login codes unavailable"})
                code = str(payload.get("code") or "")
                if not code.strip():
                    return self._json(401, {"ok": False, "error": "auth required"})
                ip = self._client_ip()
                allowed, backoff, _n = app._unlock_rate_status(ip)
                if not allowed:
                    retry = str(max(1, int(backoff + 0.999)))
                    return self._json(
                        429,
                        {"ok": False, "error": "rate limited"},
                        extra={"Retry-After": retry},
                    )
                if not app.login.try_consume(code):
                    app._unlock_record_fail(ip)
                    return self._json(401, {"ok": False, "error": "bad login code"})
                sess = app.issue_session()
                cookie = f"ss_session={sess}; Path=/; HttpOnly; SameSite=Lax"
                if app.public_url and str(app.public_url).startswith("https"):
                    cookie += "; Secure"
                return self._json(
                    200,
                    {"ok": True, "session": True, "control_unlocked": False},
                    extra={"Set-Cookie": cookie},
                )

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
                # Unauthenticated callers: correct code always wins; rate-limit wrong guesses only.
                if not authed:
                    if app.unlock.code_matches(code) and app.unlock.try_unlock(code):
                        return self._json(
                            200,
                            {
                                "ok": True,
                                "unlocked": True,
                                "status": app.controllers.status() if app.controllers else {},
                            },
                            extra=_session_extra(),
                        )
                    ip = self._client_ip()
                    allowed, backoff, _n = app._unlock_rate_status(ip)
                    if not allowed:
                        retry = str(max(1, int(backoff + 0.999)))
                        return self._json(
                            429,
                            {"ok": False, "error": "rate limited", "unlocked": False},
                            extra={"Retry-After": retry},
                        )
                    app._unlock_record_fail(ip)
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
                        "unlocked": False,
                    },
                )

            if path == "/api/logout":
                if not self._csrf_ok():
                    return self._json(403, {"ok": False, "error": "csrf"})
                app.revoke_session(self._cookie("ss_session"))
                extra = {
                    "Set-Cookie": "ss_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                }
                return self._json(200, {"ok": True, "logged_out": True}, extra=extra)

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
                last_auth = 0.0
                while time.time() < deadline:
                    now = time.time()
                    if now - last_auth >= SSE_SESSION_RECHECK_SEC:
                        if not self._authorized():
                            return
                        last_auth = now
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
    login: WebLoginCode | None = None,
    token_path: Path | None | bool = True,
    max_connections: int = MAX_WEB_CONNECTIONS,
    allowed_user_ids: set[str] | list[str] | None = None,
) -> ThreadingHTTPServer:
    launch_token = secrets.token_urlsafe(32)
    # token_path=True → default state/web.token; Path → that path; False/None → memory only.
    write_path: Path | None
    state_dir: Path | None = None
    if token_path is True:
        try:
            from sysspectogram.config import state_root

            state_dir = state_root() / "state"
            write_path = state_dir / "web.token"
        except Exception:
            write_path = None
    elif isinstance(token_path, Path):
        write_path = token_path
        state_dir = token_path.parent
    else:
        write_path = None
    if write_path is not None:
        try:
            from sysspectogram.secret_file import write_secret_file

            write_secret_file(write_path, launch_token + "\n")
        except OSError:
            pass

    owned_login = False
    if login is None and state_dir is not None:
        login = WebLoginCode(persist_path=state_dir / "web.login")
        owned_login = True
    elif login is None:
        login = WebLoginCode(persist_path=None)

    app = WebAppState(
        bus,
        bot_token=bot_token,
        allowed_chat_id=allowed_chat_id,
        public_url=public_url,
        bind_host=host,
        controllers=controllers,
        unlock=unlock,
        login=login,
        launch_token=launch_token,
        allowed_user_ids=allowed_user_ids,
    )

    try:
        httpd = LimitedThreadingHTTPServer(
            (host, port),
            _make_handler(app),
            max_connections=max_connections,
        )
    except OSError as exc:
        if owned_login:
            login.close()
        raise OSError(
            f"web dashboard cannot bind {host}:{port} ({exc}). "
            f"Free the port (fuser -k {port}/tcp) or set web.port / --port"
        ) from exc
    httpd.login_gate = login  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, name="sysspectogram-web", daemon=True)
    thread.start()
    return httpd
