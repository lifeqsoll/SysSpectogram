#!/usr/bin/env python3
"""Smoke: ping Telegram + synthetic perimeter alert with buttons."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sysspectogram.config import load_dotenv, load_config
from sysspectogram.explain.templates import explain_perimeter
from sysspectogram.notify_telegram import TelegramClient
from sysspectogram.perimeter.rules import Alert
from sysspectogram.perimeter.watcher import PerimeterWatcher
from sysspectogram.response.actions import NftBackend
from sysspectogram.response.tokens import TokenStore
from sysspectogram.telegram_bot import TelegramBot


def main() -> int:
    load_dotenv()
    cfg = load_config()
    tg = cfg.get("telegram") or {}
    client = TelegramClient(token=tg.get("bot_token"), chat_id=tg.get("chat_id"))
    if not client.configured:
        print("Нет TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID.")
        print("Заполни .env (см. .env.example) или export в shell.")
        return 2

    r = client.send_message(f"[{cfg.get('host', {}).get('id') or 'sysspectogram'}]\nTG smoke: ping OK")
    print("ping:", r.get("ok"), r.get("description", ""))
    if not r.get("ok"):
        return 1

    watcher = PerimeterWatcher(auto_recon=False, poll_sec=1.0)
    bot = TelegramBot(
        client,
        watcher=watcher,
        nft=NftBackend(),
        tokens=TokenStore(secret=tg.get("token_secret")),
        dry_run=True,
    )
    alert = Alert(
        rule_id="bruteforce_ssh",
        severity="critical",
        message="SSH brute suspected from 203.0.113.50: 12 fails / 60s (SMOKE TEST)",
        ip="203.0.113.50",
        extras={"fails": 12, "user": "root"},
    )
    bot.send_perimeter_alert(alert, recon=None)
    print("alert sent; check Telegram for inline buttons (dry-run actions)")
    print("template:", explain_perimeter(alert))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
