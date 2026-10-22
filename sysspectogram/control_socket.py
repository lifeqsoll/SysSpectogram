"""Local Unix-socket control plane for SOAR actions (Control Center + tooling).

Same WebControllers path as the web dashboard; unlock gate matches Telegram.
Socket path: state/control.sock (mode 0600 when possible).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

DEFAULT_SOCK = Path("state/control.sock")


class ControlSocketServer:
    def __init__(
        self,
        path: Path | str,
        *,
        handler: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.path = Path(path)
        self.handler = handler
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.path))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        sock.listen(8)
        sock.settimeout(1.0)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="control-sock", daemon=True)
        self._thread.start()
        log.info("control socket listening on %s", self.path)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        try:
            with conn:
                conn.settimeout(30.0)
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 1_000_000:
                        break
                line = buf.split(b"\n", 1)[0]
                try:
                    req = json.loads(line.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    resp = {"ok": False, "error": "invalid json"}
                else:
                    if not isinstance(req, dict):
                        resp = {"ok": False, "error": "request must be an object"}
                    else:
                        try:
                            resp = self.handler(req)
                        except Exception as exc:
                            resp = {"ok": False, "error": str(exc)}
                raw = (json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8")
                conn.sendall(raw)
        except Exception as exc:
            log.debug("control client error: %s", exc)


def request(path: Path | str, payload: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    """One-shot client used by Control Center / CLI helpers."""
    sock_path = str(path)
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall(data)
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    line = buf.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8") or "{}")


def make_handler(controllers: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Adapt WebControllers into a control-socket request handler."""

    def handle(req: dict[str, Any]) -> dict[str, Any]:
        op = str(req.get("op") or req.get("action") or "").strip().lower()
        if op in ("", "ping", "status"):
            return {"ok": True, "status": controllers.status()}
        if op == "action":
            action = str(req.get("name") or req.get("action_name") or "")
            payload = req.get("payload") if isinstance(req.get("payload"), dict) else {}
            # allow flat fields
            if not payload:
                payload = {k: v for k, v in req.items() if k not in ("op", "action", "name", "action_name")}
            return controllers.run(action, payload)
        # shorthand: {"op":"ban","ip":"..."}
        payload = {k: v for k, v in req.items() if k not in ("op", "action")}
        return controllers.run(op, payload)

    return handle
