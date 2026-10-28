"""Ban via sysspectogram-helper unix socket (F-02). Same string API as NftBackend.ban_ip."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any


DEFAULT_HELPER_SOCK = "/run/sysspectogram/helper.sock"


def helper_socket_path() -> Path:
    return Path(os.environ.get("SYSSPECTOGRAM_HELPER_SOCKET", DEFAULT_HELPER_SOCK))


def helper_available(path: Path | None = None) -> bool:
    p = path or helper_socket_path()
    try:
        return p.is_socket()
    except OSError:
        return False


class HelperBanBackend:
    """Talk ban.add/del/list/selftest to the root helper (group-authorized)."""

    def __init__(
        self,
        *,
        socket_path: Path | str | None = None,
        never_ban_cidrs: list[str] | None = None,
        timeout_sec: float = 5.0,
    ) -> None:
        self.socket_path = Path(socket_path) if socket_path else helper_socket_path()
        self.never_ban_cidrs = list(never_ban_cidrs or [])
        self.timeout_sec = float(timeout_sec)
        self.bans: dict[str, Any] = {}

    def is_never_ban(self, ip: str) -> bool:
        from sysspectogram.response.actions import NftBackend

        return NftBackend(never_ban_cidrs=self.never_ban_cidrs).is_never_ban(ip)

    def _call(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        req = json.dumps({"op": op, "args": args or {}}, separators=(",", ":")) + "\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_sec)
            sock.connect(str(self.socket_path))
            sock.sendall(req.encode("utf-8"))
            chunks: list[bytes] = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
        if not raw:
            return {"ok": False, "message": "empty helper reply"}
        try:
            return json.loads(raw.splitlines()[0])
        except json.JSONDecodeError as exc:
            return {"ok": False, "message": f"bad helper json: {exc}"}

    def ban_ip(self, ip: str, ttl_sec: float | None = 3600.0, dry_run: bool = False) -> str:
        from sysspectogram.net_ip import parse_ban_ip

        try:
            ip = parse_ban_ip(ip)
        except ValueError as exc:
            return f"refuse ban: {exc}"
        if self.is_never_ban(ip):
            return f"never_ban skip {ip}"
        force = bool(getattr(self, "_force_ban", False))
        if not force:
            from sysspectogram.response.protect import is_protected

            reason = is_protected(ip, never_ban_cidrs=self.never_ban_cidrs)
            if reason:
                return f"protected skip {ip} ({reason})"
        if dry_run:
            return f"dry-run ban {ip} ttl={ttl_sec} backend=helper"
        ttl = int(ttl_sec) if ttl_sec is not None else 3600
        reply = self._call("ban.add", {"ip": ip, "ttl_sec": ttl, "reason": "guard"})
        if not reply.get("ok"):
            return f"nft failed: {reply.get('message') or 'helper error'}"
        data = reply.get("data") or {}
        return f"banned {ip} ttl={data.get('ttl_sec', ttl)} backend=helper"

    def unban_ip(self, ip: str, dry_run: bool = False) -> str:
        from sysspectogram.net_ip import parse_ban_ip

        try:
            ip = parse_ban_ip(ip)
        except ValueError as exc:
            return f"refuse unban: {exc}"
        if dry_run:
            return f"dry-run unban {ip}"
        reply = self._call("ban.del", {"ip": ip})
        if not reply.get("ok"):
            return f"nft unban failed: {reply.get('message') or 'helper error'}"
        return f"unbanned {ip} backend=helper"

    def list_bans(self) -> list[Any]:
        reply = self._call("ban.list", {})
        if not reply.get("ok"):
            return []
        data = reply.get("data") or {}
        return list(data.get("ips") or [])

    def selftest(self) -> str:
        reply = self._call("ban.selftest", {})
        if not reply.get("ok"):
            return f"helper selftest failed: {reply.get('message')}"
        detail = (reply.get("data") or {}).get("detail") or "ok"
        return str(detail)


def select_ban_backend(*, never_ban_cidrs: list[str] | None = None):
    """Root → NftBackend; else helper socket → HelperBanBackend; else NoneBackend."""
    from sysspectogram.response.actions import NftBackend

    never = list(never_ban_cidrs or [])
    if os.geteuid() == 0:
        return NftBackend(never_ban_cidrs=never)
    if helper_available():
        return HelperBanBackend(never_ban_cidrs=never)
    return NoneBanBackend()


class NoneBanBackend:
    """Honest failure when neither root nor helper is available (F-02)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.bans: dict[str, Any] = {}
        self.never_ban_cidrs: list[str] = []

    def is_never_ban(self, ip: str) -> bool:
        return False

    def ban_ip(self, ip: str, ttl_sec: float | None = 3600.0, dry_run: bool = False) -> str:
        if dry_run:
            return f"dry-run ban {ip} ttl={ttl_sec} backend=none"
        return "nft failed: no privileges (install helper and join group sysspectogram)"

    def unban_ip(self, ip: str, dry_run: bool = False) -> str:
        if dry_run:
            return f"dry-run unban {ip}"
        return "nft unban failed: no privileges (install helper)"

    def list_bans(self) -> list[Any]:
        return []

    def selftest(self) -> str:
        return "no privileges (run helper install)"
