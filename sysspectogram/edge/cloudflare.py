"""Thin Cloudflare Zone Settings client (Under Attack Mode)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from sysspectogram.edge.playbook import playbook_m

API = "https://api.cloudflare.com/client/v4"
UA = "SysSpectogram-Edge/1.2"


def _load_creds() -> tuple[str | None, str | None]:
    try:
        from sysspectogram.config import load_dotenv

        load_dotenv()
    except Exception:
        pass
    token = (os.environ.get("CLOUDFLARE_API_TOKEN") or "").strip()
    zone = (os.environ.get("CLOUDFLARE_ZONE_ID") or "").strip()
    return (token or None, zone or None)


def _cf_request(
    method: str,
    path: str,
    *,
    token: str,
    body: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    url = f"{API}{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {"success": True}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body)
        except json.JSONDecodeError:
            parsed = {"errors": [{"message": err_body or str(exc)}]}
        parsed.setdefault("success", False)
        parsed["_http_status"] = exc.code
        return parsed
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {"success": False, "errors": [{"message": str(exc)}]}


def edge_status(*, lang: str = "en") -> dict[str, Any]:
    token, zone = _load_creds()
    base = {
        "provider": "cloudflare" if token and zone else "none",
        "zone_set": bool(zone),
        "token_set": bool(token),
        "playbook": playbook_m(lang),
    }
    if not token or not zone:
        return {
            "ok": False,
            "need_config": True,
            "error": "set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in .env",
            **base,
        }
    data = _cf_request("GET", f"/zones/{zone}/settings/security_level", token=token)
    if not data.get("success"):
        errs = data.get("errors") or [{"message": "cloudflare error"}]
        msg = errs[0].get("message") if isinstance(errs[0], dict) else str(errs[0])
        return {"ok": False, "need_config": False, "error": msg, **base}
    result = data.get("result") or {}
    return {
        "ok": True,
        "need_config": False,
        "security_level": result.get("value"),
        "zone_id_suffix": zone[-6:] if len(zone) > 6 else zone,
        **base,
    }


def set_under_attack() -> dict[str, Any]:
    token, zone = _load_creds()
    if not token or not zone:
        return {
            "ok": False,
            "need_config": True,
            "error": "set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in .env",
            "playbook": playbook_m("en"),
        }
    data = _cf_request(
        "PATCH",
        f"/zones/{zone}/settings/security_level",
        token=token,
        body={"value": "under_attack"},
    )
    if not data.get("success"):
        errs = data.get("errors") or [{"message": "cloudflare error"}]
        msg = errs[0].get("message") if isinstance(errs[0], dict) else str(errs[0])
        return {"ok": False, "error": msg}
    result = data.get("result") or {}
    return {"ok": True, "security_level": result.get("value", "under_attack")}


def clear_under_attack(*, level: str = "high") -> dict[str, Any]:
    allowed = {
        "off",
        "essentially_off",
        "low",
        "medium",
        "high",
        "under_attack",
    }
    level = (level or "high").strip().lower()
    if level not in allowed:
        return {"ok": False, "error": f"invalid level {level}"}
    token, zone = _load_creds()
    if not token or not zone:
        return {
            "ok": False,
            "need_config": True,
            "error": "set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in .env",
        }
    data = _cf_request(
        "PATCH",
        f"/zones/{zone}/settings/security_level",
        token=token,
        body={"value": level},
    )
    if not data.get("success"):
        errs = data.get("errors") or [{"message": "cloudflare error"}]
        msg = errs[0].get("message") if isinstance(errs[0], dict) else str(errs[0])
        return {"ok": False, "error": msg}
    result = data.get("result") or {}
    return {"ok": True, "security_level": result.get("value", level)}
