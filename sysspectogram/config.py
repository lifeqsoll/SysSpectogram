from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs" / "default.yaml"
_DOTENV_LOADED = False


def load_dotenv(path: Path | None = None) -> None:
    """Load KEY=VALUE from .env into os.environ (does not override existing)."""
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    env_path = path or (ROOT / ".env")
    if not env_path.exists():
        _DOTENV_LOADED = True
        return
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass
    _DOTENV_LOADED = True


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    load_dotenv()
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    with cfg_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    # Env overrides for telegram (preferred over null YAML)
    tg = data.setdefault("telegram", {})
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        tg["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
    if os.environ.get("TELEGRAM_CHAT_ID"):
        tg["chat_id"] = os.environ["TELEGRAM_CHAT_ID"]
    if os.environ.get("TELEGRAM_TOKEN_SECRET"):
        tg["token_secret"] = os.environ["TELEGRAM_TOKEN_SECRET"]
    return data
