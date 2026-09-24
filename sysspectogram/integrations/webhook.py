from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any


def post_webhook(
    url: str,
    payload: dict[str, Any],
    timeout: float = 8.0,
    *,
    secret: str | None = None,
) -> tuple[bool, str]:
    """Generic SIEM/webhook POST (JSON). Soft-fail. Optional HMAC-SHA256 signature."""
    if not url:
        return False, "no url"
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
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"status={resp.status}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc)
