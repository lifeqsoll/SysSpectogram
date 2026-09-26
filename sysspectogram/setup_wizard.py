"""Minimal interactive setup after bootstrap."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.rolelab.recipes import list_roles


def run_setup(
    *,
    prefix: Path,
    env_path: Path | None = None,
    role: str | None = None,
) -> dict[str, str]:
    """Write/update .env with Telegram credentials (interactive)."""
    env_path = env_path or (prefix / ".env")
    example = prefix / ".env.example"
    if not env_path.exists() and example.exists():
        env_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Setup prefix={prefix}")
    roles = list_roles() + ["generic-linux"]
    print(f"Roles: {', '.join(roles)}")
    if role is None:
        print("Enter role (empty=generic-linux):")
        role = input("> ").strip() or "generic-linux"
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
    kv["SYSSPECTOGRAM_ROLE"] = role
    out = [f"{k}={v}" for k, v in kv.items()]
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")

    cfg = prefix / "configs" / "default.yaml"
    if cfg.exists() and role and role != "generic-linux":
        text = cfg.read_text(encoding="utf-8")
        if "role:" in text:
            import re

            text = re.sub(r"(?m)^role:\s*.*$", f"role: {role}", text, count=1)
        else:
            text = f"role: {role}\n" + text
        cfg.write_text(text, encoding="utf-8")

    print(f"Wrote {env_path} role={role}")
    print("Start guard, read UNLOCK CODE on console, then TG: /unlock CODE")
    print(f"Optional pack: dist/profile-{role}-v1.tar.gz after role-lab train")
    return kv
