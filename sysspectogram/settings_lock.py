"""Exclusive flock around user-settings.json read-modify-write."""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any


def update_user_settings(
    mutator: Callable[[dict[str, Any]], dict[str, Any] | None],
    *,
    path: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Apply ``mutator`` under an exclusive lock. Returns a result dict.

    ``mutator`` receives the current object (or ``{}``) and returns the new
    object to write, or ``None`` to abort without writing.
    """
    from sysspectogram.config import user_settings_path

    target = path or user_settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    lock_path = target.with_suffix(target.suffix + ".lock")
    with open(lock_path, "a+", encoding="utf-8") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
        try:
            data: dict[str, Any] = {}
            if target.is_file():
                raw = ""
                try:
                    raw = target.read_text(encoding="utf-8")
                    parsed: Any = json.loads(raw)
                except OSError as exc:
                    return {
                        "ok": False,
                        "written": False,
                        "reason": "user_settings_unreadable",
                        "hint": str(exc),
                    }
                except json.JSONDecodeError as exc:
                    if not force:
                        return {
                            "ok": False,
                            "written": False,
                            "reason": "user_settings_corrupt",
                            "hint": str(exc),
                        }
                    bak = target.with_suffix(target.suffix + ".bak")
                    try:
                        bak.write_text(raw, encoding="utf-8")
                    except OSError:
                        pass
                    parsed = {}
                if not isinstance(parsed, dict):
                    if not force:
                        return {
                            "ok": False,
                            "written": False,
                            "reason": "user_settings_not_object",
                        }
                    bak = target.with_suffix(target.suffix + ".bak")
                    try:
                        bak.write_text(raw, encoding="utf-8")
                    except OSError:
                        pass
                    parsed = {}
                data = parsed
            new_data = mutator(dict(data))
            if new_data is None:
                return {"ok": True, "written": False, "data": data}
            text = json.dumps(new_data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            target.write_text(text, encoding="utf-8")
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
            return {"ok": True, "written": True, "data": new_data}
        finally:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
