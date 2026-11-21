"""Debounce / cache matplotlib alert panels off the hot path."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

_lock = threading.Lock()
_last_png: bytes | None = None
_last_key: str | None = None
_last_at = 0.0
_min_interval_sec = 1.0


def configure(*, min_interval_sec: float = 1.0) -> None:
    global _min_interval_sec
    _min_interval_sec = max(0.0, float(min_interval_sec))


def clear() -> None:
    global _last_png, _last_key, _last_at
    with _lock:
        _last_png = None
        _last_key = None
        _last_at = 0.0


def render_debounced(
    key: str,
    render_fn: Callable[[], bytes | None],
    *,
    force: bool = False,
    now: float | None = None,
) -> bytes | None:
    """Return cached PNG if called again within min_interval for the same key."""
    global _last_png, _last_key, _last_at
    ts = time.time() if now is None else float(now)
    with _lock:
        if (
            not force
            and _last_png is not None
            and _last_key == key
            and (ts - _last_at) < _min_interval_sec
        ):
            return _last_png
    png = render_fn()
    with _lock:
        if png is not None:
            _last_png = png
            _last_key = key
            _last_at = ts
        return png


def cached_last() -> bytes | None:
    with _lock:
        return _last_png
