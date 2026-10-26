"""Detect admin public IP and seed response.never_ban_cidrs safely."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from ipaddress import ip_address, ip_network
from typing import Any

DETECT_URLS = (
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://icanhazip.com",
)
UA = "SysSpectogram/1.2 (+never-ban seed)"


def cidr_for_ip(ip: str) -> str:
    token = (ip or "").strip()
    if not token:
        return ""
    if "/" in token:
        return token
    addr = ip_address(token)
    return f"{addr}/32" if addr.version == 4 else f"{addr}/128"


def detect_public_ip(*, timeout: float = 5.0) -> str | None:
    last = ""
    for url in DETECT_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                body = (resp.read() or b"").decode("utf-8", errors="replace").strip()
            ip_address(body)  # validate
            return body
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = f"{url}: {exc}"
            continue
    _ = last
    return None


def _covers(cidrs: list[str], ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    for raw in cidrs:
        try:
            if addr in ip_network(raw, strict=False):
                return True
        except ValueError:
            continue
    return False


def merge_never_ban(existing: list[str] | None, ip: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in existing or []:
        c = str(item).strip()
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    bare = (ip or "").strip()
    if not bare:
        return out
    cidr = cidr_for_ip(bare)
    if not cidr:
        return out
    if _covers(out, bare.split("/")[0]):
        return out
    if cidr not in seen:
        out.append(cidr)
    return out


def seed_never_ban(*, write: bool = True, force: bool = False) -> dict[str, Any]:
    """Merge detected public IP into user-settings never_ban. Never wipes existing."""
    from sysspectogram.config import load_config, user_settings_path

    cfg = load_config()
    cur = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
    ip = detect_public_ip()
    if not ip:
        return {
            "ok": False,
            "written": False,
            "ip": None,
            "never_ban_cidrs": cur,
            "reason": "detect_failed",
        }
    if _covers(cur, ip) and not force:
        return {
            "ok": True,
            "written": False,
            "ip": ip,
            "never_ban_cidrs": cur,
            "reason": "already_covered",
        }
    merged = merge_never_ban(cur, ip)
    if merged == cur:
        return {
            "ok": True,
            "written": False,
            "ip": ip,
            "never_ban_cidrs": cur,
            "reason": "unchanged",
        }
    if write:
        path = user_settings_path()
        data: dict[str, Any] = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
        if not isinstance(data, dict):
            data = {}
        # Overlay stores CIDR lists as a comma-separated string (see friend_menu / home settings).
        data["response.never_ban_cidrs"] = ", ".join(merged)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return {
        "ok": True,
        "written": bool(write),
        "ip": ip,
        "never_ban_cidrs": merged,
        "reason": "seeded",
        "hint": "may be shared NAT — edit never_ban if needed",
    }
