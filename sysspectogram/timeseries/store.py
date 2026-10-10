"""SQLite time-series store with rollup levels (schema timeseries.v1).

Levels and retention:
  raw   1 s   kept 1 h      (ranges: 1 h)
  r10s  10 s  kept 12 h     (ranges: 6 h, 12 h)
  r1m   60 s  kept 7 d      (ranges: 24 h, 7 d)
  r5m   300 s kept 30 d     (ranges: 30 d)

Writes are buffered and flushed in one transaction. Rollups are idempotent:
a bucket is (re)computed from the level below only once it is complete.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

SCHEMA = "timeseries.v1"

RANGES: dict[str, float] = {
    "1h": 3600.0,
    "6h": 6 * 3600.0,
    "12h": 12 * 3600.0,
    "24h": 24 * 3600.0,
    "7d": 7 * 86400.0,
    "30d": 30 * 86400.0,
}

# range -> (table, bucket seconds)
_RANGE_LEVEL: dict[str, tuple[str, int]] = {
    "1h": ("raw", 1),
    "6h": ("r10s", 10),
    "12h": ("r10s", 10),
    "24h": ("r1m", 60),
    "7d": ("r1m", 60),
    "30d": ("r5m", 300),
}

_LEVELS: dict[str, tuple[int, float]] = {
    # table -> (bucket seconds, retention seconds)
    "raw": (1, 3600.0),
    "r10s": (10, 12 * 3600.0),
    "r1m": (60, 7 * 86400.0),
    "r5m": (300, 30 * 86400.0),
}


@dataclass(frozen=True)
class Point:
    ts: float
    avg: float
    min: float
    max: float
    n: int


class TimeseriesStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        self._buffer: list[tuple[float, str, float]] = []
        self._last_rollup = 0.0

    def _init_schema(self) -> None:
        with self._lock:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS raw (ts INTEGER NOT NULL, metric TEXT NOT NULL, "
                "value REAL NOT NULL, PRIMARY KEY (metric, ts))"
            )
            for table in ("r10s", "r1m", "r5m"):
                self._db.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} (ts INTEGER NOT NULL, metric TEXT NOT NULL, "
                    "avg REAL NOT NULL, min REAL NOT NULL, max REAL NOT NULL, n INTEGER NOT NULL, "
                    "PRIMARY KEY (metric, ts))"
                )
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self._db.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema', ?)", (SCHEMA,)
            )

    def write(self, metric: str, value: float, ts: float | None = None) -> None:
        now = time.time() if ts is None else float(ts)
        self._buffer.append((int(now), metric, float(value)))

    def write_many(self, values: Mapping[str, float], ts: float | None = None) -> None:
        for metric, value in values.items():
            if value is None:
                continue
            self.write(metric, float(value), ts)

    def flush(self) -> int:
        if not self._buffer:
            return 0
        rows = self._buffer
        self._buffer = []
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.executemany(
                    "INSERT OR REPLACE INTO raw(ts, metric, value) VALUES (?, ?, ?)", rows
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return len(rows)

    def rollup(self, now: float | None = None) -> None:
        """Compute complete buckets from the level below, then apply retention."""
        now = time.time() if now is None else float(now)
        with self._lock:
            self._db.execute("BEGIN")
            try:
                # r10s from raw: buckets fully older than 30 s (raw is 1 s, late writes tolerated)
                self._aggregate("raw", "r10s", 10, now - 30.0)
                # r1m from raw: buckets fully older than 120 s
                self._aggregate("raw", "r1m", 60, now - 120.0)
                # r5m from r1m: buckets fully older than 600 s
                self._aggregate("r1m", "r5m", 300, now - 600.0, src_bucket=60)
                for table, (_, keep) in _LEVELS.items():
                    cutoff = int(now - keep)
                    self._db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            self._last_rollup = now

    def _aggregate(
        self, src: str, dst: str, bucket: int, complete_before: float, src_bucket: int = 1
    ) -> None:
        if src == "raw":
            value_expr = "value"
            sql = (
                f"INSERT OR REPLACE INTO {dst} (ts, metric, avg, min, max, n) "
                f"SELECT (ts / {bucket}) * {bucket} AS b, metric, AVG({value_expr}), "
                f"MIN({value_expr}), MAX({value_expr}), COUNT(*) "
                f"FROM raw WHERE ts < ? GROUP BY b, metric"
            )
            self._db.execute(sql, (int(complete_before),))
        else:
            sql = (
                f"INSERT OR REPLACE INTO {dst} (ts, metric, avg, min, max, n) "
                f"SELECT (ts / {bucket}) * {bucket} AS b, metric, "
                f"SUM(avg * n) / SUM(n), MIN(min), MAX(max), SUM(n) "
                f"FROM {src} WHERE ts < ? GROUP BY b, metric"
            )
            self._db.execute(sql, (int(complete_before),))

    def query(self, metric: str, range_name: str, now: float | None = None) -> list[Point]:
        if range_name not in RANGES:
            raise ValueError(f"unknown range {range_name!r}; use one of {sorted(RANGES)}")
        now = time.time() if now is None else float(now)
        start = int(now - RANGES[range_name])
        table, _bucket = _RANGE_LEVEL[range_name]
        with self._lock:
            if table == "raw":
                rows = self._db.execute(
                    "SELECT ts, value, value, value, 1 FROM raw "
                    "WHERE metric = ? AND ts >= ? ORDER BY ts",
                    (metric, start),
                ).fetchall()
            else:
                rows = self._db.execute(
                    f"SELECT ts, avg, min, max, n FROM {table} "
                    "WHERE metric = ? AND ts >= ? ORDER BY ts",
                    (metric, start),
                ).fetchall()
        return [Point(ts=float(r[0]), avg=r[1], min=r[2], max=r[3], n=int(r[4])) for r in rows]

    def window(self, metric: str, t0: float, t1: float) -> list[tuple[float, float]]:
        """(ts, value) pairs inside an absolute [t0, t1] window.

        Uses 1 s raw samples while they still exist, then the 1 min rollup, so old
        incidents remain renderable after raw retention has passed.
        """
        age = time.time() - float(t0)
        # finest level whose retention still covers the window start
        table = next(
            (name for name, (_bucket, keep) in _LEVELS.items() if age <= keep),
            "r5m",
        )
        with self._lock:
            if table == "raw":
                rows = self._db.execute(
                    "SELECT ts, value FROM raw WHERE metric = ? AND ts BETWEEN ? AND ? ORDER BY ts",
                    (metric, float(t0), float(t1)),
                ).fetchall()
            else:
                rows = self._db.execute(
                    f"SELECT ts, avg FROM {table} WHERE metric = ? AND ts BETWEEN ? AND ? ORDER BY ts",
                    (metric, float(t0), float(t1)),
                ).fetchall()
        return [(float(r[0]), float(r[1])) for r in rows if r[1] is not None]

    def metrics(self) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT metric FROM raw ORDER BY metric"
            ).fetchall()
        return [r[0] for r in rows]

    def maybe_rollup(self, every_sec: float = 60.0, now: float | None = None) -> bool:
        now = time.time() if now is None else float(now)
        if now - self._last_rollup < every_sec:
            return False
        self.rollup(now)
        return True

    def close(self) -> None:
        self.flush()
        with self._lock:
            self._db.close()


def describe_levels() -> Iterable[tuple[str, int, float]]:
    for table, (bucket, keep) in _LEVELS.items():
        yield table, bucket, keep
