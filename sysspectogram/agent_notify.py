"""Minimal Telegram Bot API send from agent-side notify helpers (Python).

Rust agent prefers curl; this is used by guard/tests and optional scripts.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def load_agent_notify_env(path: Path | None = None) -> dict[str, str]:
    p = path or Path(os.environ.get("SS_AGENT_NOTIFY_ENV", "/etc/sysspectogram/agent-notify.env"))
    out: dict[str, str] = {}
    if not p.exists():
        # fallback to process env
        tok = os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("SS_TG_TOKEN")
        chat = os.environ.get("TELEGRAM_CHAT_ID") or os.environ.get("SS_TG_CHAT")
        if tok and chat:
            return {"TELEGRAM_BOT_TOKEN": tok, "TELEGRAM_CHAT_ID": chat}
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def send_telegram_critical(text: str, *, env_path: Path | None = None) -> str:
    cfg = load_agent_notify_env(env_path)
    token = cfg.get("TELEGRAM_BOT_TOKEN") or cfg.get("BOT_TOKEN")
    chat = cfg.get("TELEGRAM_CHAT_ID") or cfg.get("CHAT_ID")
    if not token or not chat:
        return "skip: no TELEGRAM_BOT_TOKEN/CHAT_ID in agent-notify.env"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = json.dumps({"chat_id": chat, "text": text[:3500]}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "sysspectogram-agent-notify"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return f"ok status={resp.status}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return f"fail: {exc}"
