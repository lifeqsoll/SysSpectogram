"""Detect admin public IP and seed response.never_ban_cidrs safely."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any  # noqa: TC003 — used at runtime in validate_never_ban_value

DETECT_URLS = (
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://icanhazip.com",
)
UA = "SysSpectogram/1.2 (+never-ban seed)"

# Never-ban is for admin egress, not "disable soft-ban for the internet".
MAX_V4_PREFIX_LEN = 24  # /24 or narrower (/25…/32)
MAX_V6_PREFIX_LEN = 64  # /64 or narrower

# Well-known public resolvers / anycast — not a typical admin SSH source.
# Seeding these without --force can build a lockdown allowlist that is useless
# (or dangerous) for the operator's real laptop IP. Compare via str(ip_address(...)).
WELL_KNOWN_ANYCAST_HOSTS = frozenset(
    {
        # Google Public DNS
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        # Cloudflare
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        # Quad9
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9",
        # OpenDNS
        "208.67.222.222",
        "208.67.220.220",
        "2620:119:35::35",
        "2620:119:53::53",
        # AdGuard DNS
        "94.140.14.14",
        "94.140.15.15",
        "2a10:50c0::ad1:ff",
        "2a10:50c0::ad2:ff",
    }
)

# TEST-NET / documentation ranges used in docs and tests — not RFC1918 LAN.
_DOCUMENTATION_NETS = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
    ip_network("2001:db8::/32"),
)


def _canon_host(raw: str) -> str:
    return str(ip_address((raw or "").strip().split("/", 1)[0]))


def _is_documentation(addr: Any) -> bool:
    return any(addr in net for net in _DOCUMENTATION_NETS)


def _seed_special_reason(addr: Any) -> str | None:
    """Reason string if seed should refuse without ``--force``; None if OK."""
    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link_local"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_reserved:
        return "reserved"
    if _is_documentation(addr):
        return None
    if addr.is_private:
        return "private"
    return None

def cidr_for_ip(ip: str) -> str:
    token = (ip or "").strip()
    if not token:
        return ""
    if "/" in token:
        return token
    addr = ip_address(token)
    return f"{addr}/32" if addr.version == 4 else f"{addr}/128"


def validate_never_ban_cidr(raw: str) -> tuple[str | None, str | None]:
    """Return ``(canonical_cidr, error_reason)``.

    Rejects junk, ``/0``, unspecified/loopback (``0.0.0.0``, ``127.0.0.1``),
    and prefixes wider than /24 (v4) or /64 (v6).
    """
    token = (raw or "").strip()
    if not token:
        return None, "empty"
    try:
        if "/" in token:
            net = ip_network(token, strict=False)
        else:
            addr = ip_address(token)
            net = ip_network(f"{addr}/32" if addr.version == 4 else f"{addr}/128", strict=False)
    except ValueError:
        return None, "invalid_ip"
    addr = net.network_address
    if isinstance(net, IPv4Network):
        if net.prefixlen < MAX_V4_PREFIX_LEN:
            return None, "too_wide"
        if addr.is_unspecified or (addr.version == 4 and int(addr) >> 24 == 0):
            return None, "unspecified"
        if addr.is_loopback:
            return None, "loopback"
        if addr.is_multicast:
            return None, "multicast"
        if addr.is_link_local:
            return None, "link_local"
        if addr.is_reserved:
            return None, "reserved"
    elif isinstance(net, IPv6Network):
        if net.prefixlen < MAX_V6_PREFIX_LEN:
            return None, "too_wide"
        if addr.is_unspecified:
            return None, "unspecified"
        if addr.is_loopback:
            return None, "loopback"
        if addr.is_multicast:
            return None, "multicast"
        if addr.is_link_local:
            return None, "link_local"
        if addr.is_reserved:
            return None, "reserved"
        # Keep never_ban consistent with Rust helper (reject IPv4-mapped).
        if getattr(addr, "ipv4_mapped", None) is not None:
            return None, "ipv4_mapped"
    else:
        return None, "invalid_ip"
    # Host routes stay as /32 or /128; otherwise keep the network form.
    return str(net), None


def validate_never_ban_value(raw: Any) -> tuple[str | None, str | None]:
    """Validate a never_ban overlay value (comma string or list of CIDRs).

    Returns ``(canonical_comma_string, error)``. Empty list/string is allowed
    (operator may clear), but every non-empty entry must pass
    :func:`validate_never_ban_cidr`.
    """
    if raw is None:
        return "", None
    if isinstance(raw, list):
        parts = [str(x).strip() for x in raw if str(x).strip()]
    else:
        text = str(raw).strip()
        if not text:
            return "", None
        parts = [p.strip() for p in text.replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        cidr, err = validate_never_ban_cidr(part)
        if err or not cidr:
            return None, err or "invalid_ip"
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)
    return ", ".join(out), None


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
        # Accept bare IP or single-host CIDR for coverage checks.
        token = (ip or "").strip()
        if "/" in token:
            addr = ip_network(token, strict=False).network_address
        else:
            addr = ip_address(token)
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
    cidr, err = validate_never_ban_cidr(bare)
    if err or not cidr:
        return out
    host_for_cover = cidr.split("/")[0]
    if _covers(out, host_for_cover):
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
    Refuses to clobber a corrupt / non-object user-settings.json unless ``force``
    (always writes ``.bak`` before replace when force-clobbering).
    """
    from sysspectogram.config import load_config, user_settings_path

    cfg = load_config()
    cur = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
    raw_ip = (ip or "").strip() or None
    anycast_warning: str | None = None
    if raw_ip:
        canonical, err = validate_never_ban_cidr(raw_ip)
        if err or not canonical:
            return {
                "ok": False,
                "written": False,
                "ip": raw_ip,
                "never_ban_cidrs": cur,
                "reason": err or "invalid_ip",
                "hint": (
                    "pass a host IP or narrow CIDR "
                    f"(IPv4 /{MAX_V4_PREFIX_LEN}+, IPv6 /{MAX_V6_PREFIX_LEN}+); "
                    "reject /0 and junk"
                ),
            }
        host_only = _canon_host(canonical)
        special = _seed_special_reason(ip_address(host_only))
        if special and not force:
            return {
                "ok": False,
                "written": False,
                "ip": canonical,
                "never_ban_cidrs": cur,
                "reason": special,
                "warning": (
                    f"{host_only} is {special}; not a typical admin SSH source. "
                    "Pass your real admin egress IP, or --force if you really mean it."
                ),
                "hint": "use --ip <your-admin-egress> or --force to override",
            }
        if host_only in WELL_KNOWN_ANYCAST_HOSTS and not force:
            return {
                "ok": False,
                "written": False,
                "ip": canonical,
                "never_ban_cidrs": cur,
                "reason": "well_known_anycast",
                "warning": (
                    f"{host_only} looks like a public DNS/anycast resolver, not an admin SSH source; "
                    "lockdown would allowlist this address instead of your laptop. "
                    "Pass your real admin IP, or --force if you really mean it."
                ),
                "hint": "use --ip <your-admin-egress> or --force to override",
            }
        if host_only in WELL_KNOWN_ANYCAST_HOSTS and force:
            anycast_warning = (
                f"{host_only} is a well-known anycast/DNS address; "
                "lockdown allowlist will use never_ban only — confirm this is intentional"
            )
        elif special and force:
            anycast_warning = (
                f"{host_only} is {special}; "
                "lockdown allowlist will use never_ban only — confirm this is intentional"
            )
        detected = canonical
    else:
        detected_bare = detect_public_ip()
        if not detected_bare:
            return {
                "ok": False,
                "written": False,
                "ip": None,
                "never_ban_cidrs": cur,
                "reason": "detect_failed",
                "hint": "pass --ip A.B.C.D if detect fails (admin egress, not VPS)",
            }
        canonical, err = validate_never_ban_cidr(detected_bare)
        if err or not canonical:
            return {
                "ok": False,
                "written": False,
                "ip": detected_bare,
                "never_ban_cidrs": cur,
                "reason": err or "invalid_ip",
            }
        detected = canonical
    cover_ip = detected.split("/")[0]
    if _covers(cur, cover_ip) and not force:
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
        if path.is_file():
            raw_text = ""
            try:
                raw_text = path.read_text(encoding="utf-8")
            except OSError as exc:
                return {
                    "ok": False,
                    "written": False,
                    "ip": detected,
                    "never_ban_cidrs": cur,
                    "reason": "user_settings_unreadable",
                    "hint": str(exc),
                }
            try:
                parsed: Any = json.loads(raw_text)
            except json.JSONDecodeError:
                parsed = None
                if not force:
                    return {
                        "ok": False,
                        "written": False,
                        "ip": detected,
                        "never_ban_cidrs": cur,
                        "reason": "user_settings_corrupt",
                        "hint": "fix state/user-settings.json or re-run with --force (backs up .bak)",
                    }
                bak = path.with_suffix(path.suffix + ".bak")
                try:
                    bak.write_text(raw_text, encoding="utf-8")
                except OSError:
                    pass
            else:
                if isinstance(parsed, dict):
                    data = parsed
                else:
                    if not force:
                        return {
                            "ok": False,
                            "written": False,
                            "ip": detected,
                            "never_ban_cidrs": cur,
                            "reason": "user_settings_not_object",
                            "hint": "fix state/user-settings.json or re-run with --force (backs up .bak)",
                        }
                    bak = path.with_suffix(path.suffix + ".bak")
                    try:
                        bak.write_text(raw_text, encoding="utf-8")
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
    out: dict[str, Any] = {
        "ok": True,
        "written": bool(write),
        "ip": detected,
        "never_ban_cidrs": merged,
        "reason": "seeded",
    }
    if anycast_warning:
        out["warning"] = anycast_warning
    if not raw_ip:
        out["hint"] = (
            "seeds THIS machine egress IP — on a VPS that is the VPS, not your laptop; "
            "pass --ip from admin PC if needed; may be shared NAT"
        )
    return out
