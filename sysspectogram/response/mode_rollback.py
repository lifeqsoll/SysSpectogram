"""Auto-rollback enforcing response.mode if not confirmed (F-07)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root, user_settings_path

ENFORCING_MODES = frozenset({"soft", "full", "isolate", "shield", "aggressive", "enforce"})
DEFAULT_ROLLBACK_SEC = 600


def mode_pending_path() -> Path:
    return state_root() / "state" / "mode_pending.json"


def schedule_mode_pending(
    new_mode: str,
    *,
    rollback_sec: float = DEFAULT_ROLLBACK_SEC,
) -> dict[str, Any]:
    """Record deadline after switching to an enforcing mode."""
    mode = str(new_mode or "").strip().lower()
    if mode == "enforce":
        mode = "shield"
    if mode not in ENFORCING_MODES:
        clear_mode_pending()
        return {"scheduled": False, "mode": mode}
    deadline = time.time() + float(rollback_sec)
    payload = {
        "mode": mode,
        "deadline": deadline,
        "rollback_sec": float(rollback_sec),
        "created_at": time.time(),
    }
    path = mode_pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        import os

        os.chmod(path, 0o600)
    except OSError:
        pass
    return {"scheduled": True, "path": str(path), **payload}


def clear_mode_pending() -> None:
    try:
        mode_pending_path().unlink(missing_ok=True)
    except OSError:
        pass


def load_mode_pending() -> dict[str, Any] | None:
    path = mode_pending_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _write_observe_mode() -> None:
    path = user_settings_path()
    current: dict[str, Any] = {}
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                current = raw
        except (OSError, json.JSONDecodeError):
            current = {}
    current["response.mode"] = "observe"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        import os

        os.chmod(path, 0o600)
    except OSError:
        pass


def _clear_all_bans(nft: Any) -> None:
    if nft is None:
        return
    try:
        ips = list(getattr(nft, "list_bans", lambda: [])() or [])
    except Exception:
        ips = []
    for ip in ips:
        try:
            nft.unban_ip(str(ip), dry_run=bool(getattr(nft, "dry_run", False)))
        except Exception:
            continue


def maybe_rollback_mode(*, watcher: Any | None = None, nft: Any | None = None) -> bool:
    """If pending deadline passed, revert to observe and clear bans. Returns True if rolled back."""
    pending = load_mode_pending()
    if not pending:
        return False
    deadline = float(pending.get("deadline") or 0)
    if deadline <= 0 or time.time() < deadline:
        return False
    _write_observe_mode()
    _clear_all_bans(nft)
    clear_mode_pending()
    if watcher is not None:
        watcher.auto_ban_rules = set()
    return True
