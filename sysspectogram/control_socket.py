"""Local Unix-socket control plane for SOAR actions (Control Center + tooling).

Same WebControllers path as the web dashboard; unlock gate matches Telegram.
Socket path: state/control.sock (mode 0600 when possible).

Linux: SO_PEERCRED — reject peers whose UID != server UID (cross-user).
Same-UID malware after unlock remains a residual threat (threat model #2);
shorter unlock TTL + unlock gate on actions mitigate it.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

DEFAULT_SOCK = Path("state/control.sock")

# Linux socket.SO_PEERCRED; value is portable across arches for struct ucred.
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
_UCRED_FMT = "3i"  # pid, uid, gid
_UCRED_SIZE = struct.calcsize(_UCRED_FMT)


def peer_credentials(conn: socket.socket) -> tuple[int, int, int] | None:
    """Return (pid, uid, gid) from SO_PEERCRED, or None if unavailable."""
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, _UCRED_SIZE)
        pid, uid, gid = struct.unpack(_UCRED_FMT, raw)
        return int(pid), int(uid), int(gid)
    except (OSError, struct.error):
        return None


class ControlSocketServer:
    def __init__(
        self,
        path: Path | str,
        *,
        handler: Callable[[dict[str, Any]], dict[str, Any]],
        require_same_uid: bool = True,
    ) -> None:
        self.path = Path(path)
        self.handler = handler
        self.require_same_uid = bool(require_same_uid)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._uid = os.getuid()

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
        log.info("control socket listening on %s (same_uid=%s)", self.path, self.require_same_uid)

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
                if self.require_same_uid:
                    creds = peer_credentials(conn)
                    if creds is None:
                        log.warning("control sock: no PEERCRED — refusing")
                        conn.sendall(
                            b'{"ok":false,"error":"peercred required"}\n'
                        )
                        return
                    _pid, uid, _gid = creds
                    if uid != self._uid:
                        log.warning("control sock: uid %s != %s — refusing", uid, self._uid)
                        conn.sendall(
                            b'{"ok":false,"error":"peer uid mismatch"}\n'
                        )
                        return
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


def make_handler(
    controllers: Any,
    unlock_gate: Any | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Adapt WebControllers into a control-socket request handler.

    When remote devices are paired, mutating ops require a valid device_token
    (SSH forward looks like same-UID PEERCRED, so token is the real gate).
    """

    def handle(req: dict[str, Any]) -> dict[str, Any]:
        from sysspectogram.remote_devices import devices_configured, verify_token

        op = str(req.get("op") or req.get("action") or "").strip().lower()
        if op in ("", "ping", "status"):
            return {"ok": True, "status": controllers.status()}
        # Pairing is CLI-only (home pair-remote / pair-complete). Exposing it on the
        # socket let any same-UID client mint a device_token without an unlock.
        if op in ("pair_begin", "pair_complete"):
            return {
                "ok": False,
                "error": "pair_* not available on control socket — use home pair-remote / pair-complete on the VPS console",
            }
        if op in ("list_devices", "devices"):
            from sysspectogram.remote_devices import list_devices

            return {
                "ok": True,
                "devices": [
                    {"device_id": d.device_id, "label": d.label, "created_at": d.created_at}
                    for d in list_devices()
                ],
            }

        if op == "unlock":
            from sysspectogram.unlock_help import locked_playbook

            if unlock_gate is None:
                return {"ok": True, "unlocked": True, "note": "gate off"}
            code = str(req.get("code") or "")
            if unlock_gate.try_unlock(code):
                return {"ok": True, "unlocked": True}
            return {
                "ok": False,
                "error": "bad or expired unlock code",
                "help": locked_playbook(),
            }

        # Mutating ops always require a device_token once any device is paired.
        # Before first pair, require an unlocked console session.
        if devices_configured():
            token = req.get("device_token") or req.get("token")
            if verify_token(str(token) if token else None) is None:
                return {
                    "ok": False,
                    "error": "device_token required (pair with home pair-remote / fleet pair)",
                }
        elif unlock_gate is not None and unlock_gate.enabled and not unlock_gate.unlocked():
            from sysspectogram.unlock_help import locked_playbook

            return {
                "ok": False,
                "error": "LOCKED",
                "help": locked_playbook(),
            }

        if op == "action":
            action = str(req.get("name") or req.get("action_name") or "")
            payload = req.get("payload") if isinstance(req.get("payload"), dict) else {}
            if not payload:
                payload = {
                    k: v
                    for k, v in req.items()
                    if k
                    not in (
                        "op",
                        "action",
                        "name",
                        "action_name",
                        "device_token",
                        "token",
                    )
                }
            return controllers.run(action, payload)
        payload = {
            k: v
            for k, v in req.items()
            if k not in ("op", "action", "device_token", "token")
        }
        return controllers.run(op, payload)

    return handle
