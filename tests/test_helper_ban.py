"""HelperBanBackend protocol tests (F-02) with a fake unix server."""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest


def _serve_once(sock_path: Path, handler) -> threading.Thread:
    if sock_path.exists():
        sock_path.unlink()

    def run() -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(1)
        srv.settimeout(2.0)
        try:
            conn, _ = srv.accept()
            with conn:
                data = b""
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                line = data.splitlines()[0].decode("utf-8")
                req = json.loads(line)
                reply = handler(req)
                conn.sendall((json.dumps(reply) + "\n").encode("utf-8"))
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_helper_ban_add_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sock = tmp_path / "helper.sock"
    monkeypatch.setenv("SYSSPECTOGRAM_HELPER_SOCKET", str(sock))

    def handler(req: dict):
        assert req["op"] == "ban.add"
        assert req["args"]["ip"] == "198.51.100.7"
        return {"ok": True, "data": {"ip": "198.51.100.7", "ttl_sec": 60, "set": "ban4"}}

    _serve_once(sock, handler)
    # wait for bind
    import time

    for _ in range(50):
        if sock.exists():
            break
        time.sleep(0.02)

    from sysspectogram.response.helper_ban import HelperBanBackend

    b = HelperBanBackend(socket_path=sock, never_ban_cidrs=[])
    msg = b.ban_ip("198.51.100.7", ttl_sec=60)
    assert msg.startswith("banned")
    assert "backend=helper" in msg


def test_helper_ban_not_authorized(tmp_path: Path) -> None:
    sock = tmp_path / "helper.sock"

    def handler(req: dict):
        return {"ok": False, "message": "not authorized: not in group sysspectogram"}

    _serve_once(sock, handler)
    import time

    for _ in range(50):
        if sock.exists():
            break
        time.sleep(0.02)

    from sysspectogram.response.helper_ban import HelperBanBackend

    b = HelperBanBackend(socket_path=sock)
    msg = b.ban_ip("198.51.100.7", ttl_sec=60)
    assert msg.startswith("nft failed")
    assert "not authorized" in msg


def test_none_backend_honest() -> None:
    from sysspectogram.response.helper_ban import NoneBanBackend

    b = NoneBanBackend()
    msg = b.ban_ip("198.51.100.7", ttl_sec=60)
    assert msg.startswith("nft failed")
    assert "helper" in msg.lower() or "privileges" in msg.lower()
    assert "banned" not in msg.lower() or "failed" in msg.lower()
