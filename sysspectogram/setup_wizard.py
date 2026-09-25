"""Minimal interactive setup after bootstrap."""

from __future__ import annotations

from pathlib import Path


def run_setup(*, prefix: Path, env_path: Path | None = None) -> dict[str, str]:
    """Write/update .env with Telegram credentials (interactive)."""
    env_path = env_path or (prefix / ".env")
    example = prefix / ".env.example"
    if not env_path.exists() and example.exists():
        env_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Setup prefix={prefix}")
    print("Enter Telegram bot token (empty=keep):")
    token = input("> ").strip()
    print("Enter Telegram chat id (empty=keep):")
    chat = input("> ").strip()
    lines = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    kv: dict[str, str] = {}
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip()
    if token:
        kv["TELEGRAM_BOT_TOKEN"] = token
    if chat:
        kv["TELEGRAM_CHAT_ID"] = chat
    out = []
    for k, v in kv.items():
        out.append(f"{k}={v}")
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"Wrote {env_path}")
    print("Start guard, read UNLOCK CODE on console, then TG: /unlock CODE")
    return kv
