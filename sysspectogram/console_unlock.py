"""Host-console pairing code for Telegram / Mini App control plane."""

from __future__ import annotations

import secrets
import time
from typing import Any, Callable


class ConsoleUnlock:
    """6-digit console code; stolen bot token alone cannot unlock."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        ttl_sec: float = 7200.0,
        on_code: Callable[[str], None] | None = None,
    ) -> None:
        self.enabled = enabled
        self.ttl_sec = float(ttl_sec)
        self.on_code = on_code
        self._code: str | None = None
        self._unlocked = not enabled
        self._deadline = 0.0
        self._fails: list[float] = []
        if enabled:
            self.begin()

    def begin(self) -> str:
        self._code = f"{secrets.randbelow(1_000_000):06d}"
        self._unlocked = False
        self._deadline = 0.0
        self._fails = []
        if self.on_code:
            try:
                self.on_code(self._code)
            except Exception:
                pass
        return self._code

    @property
    def pending_code(self) -> str | None:
        return self._code

    def unlocked(self) -> bool:
        if not self.enabled:
            return True
        if not self._unlocked:
            return False
        if self.ttl_sec > 0 and time.time() > self._deadline:
            self._unlocked = False
            return False
        return True

    def try_unlock(self, code: str) -> bool:
        if not self.enabled:
            self._unlocked = True
            return True
        if not self._code:
            return False
        now = time.time()
        self._fails = [t for t in self._fails if now - t < 300.0]
        if len(self._fails) >= 8:
            return False
        ok = secrets.compare_digest(str(code).strip(), self._code)
        if ok:
            self._unlocked = True
            self._deadline = time.time() + self.ttl_sec
            self._code = None
            self._fails = []
            return True
        self._fails.append(now)
        if len(self._fails) >= 5:
            self.begin()
        return False

    def lock(self) -> str:
        return self.begin()

    @property
    def fail_count(self) -> int:
        now = time.time()
        self._fails = [t for t in self._fails if now - t < 300.0]
        return len(self._fails)

    def status_label(self) -> str:
        if not self.enabled:
            return "unlocked (gate off)"
        return "unlocked" if self.unlocked() else "LOCKED"
