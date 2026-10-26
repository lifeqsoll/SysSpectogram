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


def seed_never_ban(
    *,
    write: bool = True,
    force: bool = False,
    ip: str | None = None,
) -> dict[str, Any]:
    """Merge public IP into user-settings never_ban.

    Detects *this machine's* egress IP unless ``ip`` is passed. On a VPS that is
    usually the VPS address — pass ``--ip`` from the admin PC for the laptop IP.
    Refuses to clobber a corrupt user-settings.json unless ``force``.
    """
    from sysspectogram.config import load_config, user_settings_path

    cfg = load_config()
    cur = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
    detected = (ip or "").strip() or None
    if not detected:
        detected = detect_public_ip()
    if not detected:
        return {
            "ok": False,
            "written": False,
            "ip": None,
            "never_ban_cidrs": cur,
            "reason": "detect_failed",
            "hint": "pass --ip A.B.C.D if detect fails (admin egress, not VPS)",
        }
    if _covers(cur, detected) and not force:
        return {
            "ok": True,
            "written": False,
            "ip": detected,
            "never_ban_cidrs": cur,
            "reason": "already_covered",
        }
    merged = merge_never_ban(cur, detected)
    if merged == cur:
        return {
            "ok": True,
            "written": False,
            "ip": detected,
            "never_ban_cidrs": cur,
            "reason": "unchanged",
        }
    if write:
        path = user_settings_path()
        data: dict[str, Any] = {}
        corrupt = False
        if path.is_file():
            try:
                raw = path.read_text(encoding="utf-8")
                parsed = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                corrupt = True
                parsed = None
            if corrupt and not force:
                return {
                    "ok": False,
                    "written": False,
                    "ip": detected,
                    "never_ban_cidrs": cur,
                    "reason": "user_settings_corrupt",
                    "hint": "fix state/user-settings.json or re-run with --force (backs up .bak)",
                }
            if isinstance(parsed, dict):
                data = parsed
            elif parsed is not None and not force:
                return {
                    "ok": False,
                    "written": False,
                    "ip": detected,
                    "never_ban_cidrs": cur,
                    "reason": "user_settings_not_object",
                    "hint": "fix state/user-settings.json or re-run with --force",
                }
            if corrupt and force:
                bak = path.with_suffix(path.suffix + ".bak")
                try:
                    bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
                except OSError:
                    pass
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
        "ip": detected,
        "never_ban_cidrs": merged,
        "reason": "seeded",
        "hint": (
            "seeds THIS machine egress IP — on a VPS that is the VPS, not your laptop; "
            "pass --ip from admin PC if needed; may be shared NAT"
        ),
    }
