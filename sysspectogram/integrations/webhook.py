from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any

from sysspectogram.net_safe import post_json_pinned, resolve_public_host


def post_webhook(
    url: str,
    payload: dict[str, Any],
    timeout: float = 8.0,
    *,
    secret: str | None = None,
    allow_private: bool = False,
) -> tuple[bool, str]:
    """Generic SIEM/webhook POST (JSON). Soft-fail. Optional HMAC-SHA256 signature.

    Resolves host once and connects to the pinned IP (SSRF TOCTOU mitigation).
    """
    if not url:
        return False, "no url"
    if not allow_private:
        try:
            import urllib.parse

            host = urllib.parse.urlparse(url).hostname or ""
            resolve_public_host(host, allow_private=False)
        except Exception as exc:  # noqa: BLE001
            return False, f"webhook host check failed: {exc}"
    body = dict(payload)
    body.setdefault("ts", time.time())
    data = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "sysspectogram/0.2",
    }
    sec = secret or os.environ.get("SIEM_WEBHOOK_SECRET") or None
    if sec:
        sig = hmac.new(sec.encode("utf-8"), data, hashlib.sha256).hexdigest()
        headers["X-SysSpectogram-Signature"] = f"sha256={sig}"
    try:
        status, _ = post_json_pinned(
            url,
            data,
            headers,
            timeout=timeout,
            allow_private=allow_private,
        )
        if 200 <= status < 300:
            return True, f"status={status}"
        return False, f"status={status}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
