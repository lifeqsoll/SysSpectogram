"""Local control socket: status + unlock gate for destructive actions."""

from __future__ import annotations

import tempfile
from pathlib import Path

from sysspectogram.control_socket import ControlSocketServer, make_handler, request
from sysspectogram.web.actions import WebControllers
from sysspectogram.web.bus import LiveBus


class _Nft:
    def list_bans(self):
        return []

    def ban_ip(self, ip, ttl_sec=None, dry_run=True):
        return f"ban {ip} dry_run={dry_run}"


def test_control_socket_status_and_ban_when_unlocked(tmp_path):
    bus = LiveBus()
    unlocked = {"ok": True}
    ctl = WebControllers(
        bus=bus,
        nft=_Nft(),  # type: ignore[arg-type]
        dry_run=True,
        unlock_ok=lambda: unlocked["ok"],
    )
    sock = tmp_path / "control.sock"
    srv = ControlSocketServer(sock, handler=make_handler(ctl))
    srv.start()
    try:
        st = request(sock, {"op": "status"})
        assert st["ok"] is True
        assert st["status"]["control_unlocked"] is True
        ban = request(sock, {"op": "ban", "ip": "203.0.113.9", "ttl": 60})
        assert ban["ok"] is True
        unlocked["ok"] = False
        locked = request(sock, {"op": "ban", "ip": "203.0.113.10"})
        assert locked["ok"] is False
        assert "LOCKED" in str(locked.get("error") or "")
    finally:
        srv.stop()
