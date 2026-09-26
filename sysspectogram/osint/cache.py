"""OSINT reputation cache — never block hot path on network."""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class ReconCache:
    """In-memory TTL + optional SQLite for Tor exits / DNSBL /24 results."""

    def __init__(self, *, db_path: Path | None = None, ttl_sec: float = 3600.0) -> None:
        self.ttl_sec = float(ttl_sec)
        self._mem: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self.db_path = Path(db_path) if db_path else None
        if self.db_path:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._conn() as con:
                con.execute(
                    "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, exp REAL, v TEXT)"
                )

    def _conn(self) -> sqlite3.Connection:
        assert self.db_path is not None
        return sqlite3.connect(str(self.db_path), timeout=5)

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            hit = self._mem.get(key)
            if hit and hit[0] > now:
                return hit[1]
            if hit:
                del self._mem[key]
        if self.db_path:
            try:
                with self._conn() as con:
                    row = con.execute("SELECT exp, v FROM kv WHERE k=?", (key,)).fetchone()
                if row and float(row[0]) > now:
                    val = json.loads(row[1])
                    with self._lock:
                        self._mem[key] = (float(row[0]), val)
                    return val
            except (OSError, sqlite3.Error, json.JSONDecodeError):
                return None
        return None

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        exp = time.time() + float(ttl if ttl is not None else self.ttl_sec)
        with self._lock:
            self._mem[key] = (exp, value)
        if self.db_path:
            try:
                with self._conn() as con:
                    con.execute(
                        "INSERT OR REPLACE INTO kv(k, exp, v) VALUES (?,?,?)",
                        (key, exp, json.dumps(value)),
                    )
                    con.commit()
            except (OSError, sqlite3.Error, TypeError):
                pass


_GLOBAL: ReconCache | None = None
_TOR: set[str] | None = None
_TOR_TS = 0.0


def get_cache(db_path: Path | None = None, ttl_sec: float = 3600.0) -> ReconCache:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = ReconCache(db_path=db_path, ttl_sec=ttl_sec)
    return _GLOBAL


def dnsbl_zen_listed(ip: str, cache: ReconCache | None = None) -> bool | None:
    """
    Spamhaus ZEN-style reverse DNSBL. Returns True/False from cache or live lookup.
    On network error returns None (caller must not block).
    """
    cache = cache or get_cache()
    key = f"zen:{ip}"
    hit = cache.get(key)
    if hit is not None:
        return bool(hit)
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    q = ".".join(reversed(parts)) + ".zen.spamhaus.org"
    try:
        socket.setdefaulttimeout(1.5)
        socket.getaddrinfo(q, None)
        listed = True
    except socket.gaierror:
        listed = False
    except OSError:
        return None
    cache.set(key, listed, ttl=86400.0)
    return listed


def tor_exit_refresh(cache: ReconCache | None = None, url: str | None = None) -> int:
    """Background-friendly Tor exit list pull into cache key tor:set."""
    import urllib.request

    cache = cache or get_cache()
    url = url or "https://check.torproject.org/torbulkexitlist"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sysspectogram/0.5"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        exits = {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")}
        cache.set("tor:set", sorted(exits), ttl=21600.0)
        return len(exits)
    except Exception:
        return 0


def is_tor_exit(ip: str, cache: ReconCache | None = None) -> bool:
    cache = cache or get_cache()
    raw = cache.get("tor:set")
    if not raw:
        return False
    return ip in set(raw)
