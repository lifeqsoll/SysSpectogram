from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs" / "default.yaml"
STATE_ENV = "SYSSPECTOGRAM_HOME"
_DOTENV_LOADED = False


def state_root() -> Path:
    """Directory that holds runtime state (state/, reports/, artifacts/).

    Defaults to the source tree. Set SYSSPECTOGRAM_HOME to the installed state
    directory (/var/lib/sysspectogram). The Control Center reads the same variable,
    so the guard and the dashboards always use the same timeseries file.
    """
    env = os.environ.get(STATE_ENV)
    return Path(env) if env else ROOT


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


SETTINGS_OVERLAY_ENV = "SYSSPECTOGRAM_SETTINGS_OVERLAY"
DEFAULT_SETTINGS_OVERLAY = Path("/etc/sysspectogram/settings.json")
_OVERLAY_TYPES = (bool, int, float, str)

# Keys the overlay may set. Must match HELPER allowlist (helper/src/ops.rs SETTINGS_RULES)
# and configs/schema.yaml. A test keeps the three in sync.
OVERLAY_ALLOWED = frozenset(
    {
        "agent.enabled",
        "agent.mode",
        "agent.score_half_life_sec",
        "agent.spectrogram",
        "alerts.strict_secrets",
        "ensemble.host_weight",
        "ensemble.agent_weight",
        "ensemble.risk_threshold",
        "kirk.vmi",
        "kirk.vmi_backend",
        "kirk.vmi_trust",
        "kirk.vmi_confirm",
        "monitor.interval_sec",
        "response.mode",
        "telegram.require_console_unlock",
        "timeseries.enabled",
    }
)


def _overlay_trusted(path: Path) -> bool:
    """Trust an overlay only if root owns it and group/other cannot write it."""
    if os.name != "posix":
        return False
    try:
        st = path.stat()
    except OSError:
        return False
    return st.st_uid == 0 and not (st.st_mode & 0o022)


def settings_overlay_path() -> Path:
    raw = os.environ.get(SETTINGS_OVERLAY_ENV)
    return Path(raw) if raw else DEFAULT_SETTINGS_OVERLAY


def _apply_settings_overlay(data: dict[str, Any]) -> dict[str, Any]:
    """Merge root-written overrides (written by sysspectogram-helper) on top of YAML.

    The overlay is a JSON object of dotted keys to scalars. Only keys in OVERLAY_ALLOWED
    are applied, and only from a root-owned file that others cannot write. Anything else
    is ignored, so a bad overlay can never stop the guard from starting.
    """
    import json

    path = settings_overlay_path()
    try:
        if not path.is_file() or not _overlay_trusted(path):
            return data
        overlay = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return data
    if not isinstance(overlay, dict):
        return data
    for dotted, value in overlay.items():
        if dotted not in OVERLAY_ALLOWED or not isinstance(value, _OVERLAY_TYPES):
            continue
        cur: dict[str, Any] = data
        parts = dotted.split(".")
        for part in parts[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        cur[parts[-1]] = value
    return data


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
    data = _apply_settings_overlay(data)
    from sysspectogram.load_profile import apply_load_profile

    data = apply_load_profile(data)
    # notorch: don't fuse host CNN weight unless user overrode
    runtime_raw = data.get("runtime")
    if isinstance(runtime_raw, dict):
        runtime_raw = runtime_raw.get("prefer")
    runtime = str(runtime_raw or "notorch").strip().lower()
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
    supply = data.setdefault("supply_chain", {})
    supply["enforce"] = bool(supply.get("enforce", False))
    supply["manifest_name"] = str(
        supply.get("manifest_name") or "artifacts.manifest.json"
    )
    supply["signature_name"] = str(
        supply.get("signature_name") or "artifacts.manifest.json.minisig"
    )
    return data
