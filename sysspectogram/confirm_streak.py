"""Require N hits within a TTL before treating a signal as confirmed."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class ConfirmStreak:
    need: int = 2
    ttl_sec: float = 180.0
    _hits: dict[str, list[float]] = field(default_factory=dict)

    def hit(self, key: str, *, now: float | None = None) -> bool:
        """Record a hit; return True when streak reaches ``need``."""
        need = max(1, int(self.need))
        now = time.time() if now is None else float(now)
        xs = [t for t in self._hits.get(key, []) if now - t <= self.ttl_sec]
        xs.append(now)
        self._hits[key] = xs
        return len(xs) >= need

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)
