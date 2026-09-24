from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl


def validate_webapp_init_data(init_data: str, bot_token: str, max_age_sec: float = 86400.0) -> dict | None:
    """Validate Telegram.WebApp.initData per https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app."""
    if not init_data or not bot_token:
        return None
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return None
    data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    calc = hmac.new(secret_key, data_check.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, received_hash):
        return None
    try:
        auth_date = int(pairs.get("auth_date") or 0)
    except ValueError:
        return None
    if auth_date and time.time() - auth_date > max_age_sec:
        return None
    user = None
    if pairs.get("user"):
        try:
            user = json.loads(pairs["user"])
        except json.JSONDecodeError:
            return None
    return {"user": user, "auth_date": auth_date, "raw": pairs}
