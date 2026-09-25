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
    web = data.setdefault("web", {})
    if os.environ.get("WEBAPP_URL"):
        web["public_url"] = os.environ["WEBAPP_URL"]
    elif os.environ.get("SYSPECTOGRAM_WEB_URL"):
        web["public_url"] = os.environ["SYSPECTOGRAM_WEB_URL"]
    if os.environ.get("SYSSPECTOGRAM_LOAD_PROFILE"):
        data["load_profile"] = os.environ["SYSSPECTOGRAM_LOAD_PROFILE"]
    if os.environ.get("SYSSPECTOGRAM_RUNTIME"):
        data["runtime"] = os.environ["SYSSPECTOGRAM_RUNTIME"].strip().lower()
    from sysspectogram.load_profile import apply_load_profile

    data = apply_load_profile(data)
    # notorch: don't fuse host CNN weight unless user overrode
    runtime = str(data.get("runtime") or "notorch").strip().lower()
    data["runtime"] = runtime
    if runtime == "notorch":
        ens = data.setdefault("ensemble", {})
        # YAML defaults host_weight=0.6 for onnx/torch; zero host CNN for notorch
        # unless operator explicitly set SYSSPECTOGRAM_HOST_WEIGHT
        if os.environ.get("SYSSPECTOGRAM_HOST_WEIGHT") is None:
            ens["host_weight"] = 0.0
            ens["agent_weight"] = 1.0
        elif ens.get("agent_weight") is None:
            ens["agent_weight"] = 1.0
    if data.get("ensemble", {}).get("risk_threshold") is None:
        data.setdefault("ensemble", {})["risk_threshold"] = 0.7
    return data
