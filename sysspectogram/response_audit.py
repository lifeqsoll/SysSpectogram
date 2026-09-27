"""Append-only audit log for response / feedback actions."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any


class ResponseAudit:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        action: str,
        *,
        dry_run: bool = False,
        ok: bool = True,
        detail: str = "",
        payload: dict[str, Any] | None = None,
        host_id: str = "",
        actor: str = "telegram",
    ) -> None:
        row = {
            "ts": time.time(),
            "action": str(action),
            "dry_run": bool(dry_run),
            "ok": bool(ok),
            "detail": str(detail)[:500],
            "host_id": host_id,
            "actor": actor,
        }
        if payload:
            # strip secrets
            safe = {
                k: v
                for k, v in payload.items()
                if k.lower() not in ("token", "secret", "hmac", "password", "bot_token")
            }
            row["payload"] = safe
        line = json.dumps(row, ensure_ascii=True) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for line in lines[-max(1, n) :]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
