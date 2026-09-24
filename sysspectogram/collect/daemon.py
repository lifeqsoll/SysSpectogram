from __future__ import annotations

import csv
import signal
import time
from collections import deque
from pathlib import Path
from typing import Callable

from sysspectogram.collect.metrics import MetricsCollector


class CollectDaemon:
    def __init__(
        self,
        collector: MetricsCollector,
        interval_sec: float = 1.0,
        csv_path: Path | None = None,
        buffer_size: int | None = None,
    ) -> None:
        self.collector = collector
        self.interval_sec = interval_sec
        self.csv_path = csv_path
        self.buffer: deque[dict[str, float]] | None = (
            deque(maxlen=buffer_size) if buffer_size else None
        )
        self._stop = False
        self._writer = None
        self._fh = None

    def _install_signals(self) -> None:
        import threading

        if threading.current_thread() is not threading.main_thread():
            return

        def _handler(signum, frame):  # noqa: ARG001
            self._stop = True

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except ValueError:
            return

    def _open_csv(self) -> None:
        if self.csv_path is None:
            return
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        new_file = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        self._fh = self.csv_path.open("a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=self.collector.columns)
        if new_file:
            self._writer.writeheader()
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
            self._writer = None

    def run(
        self,
        duration_sec: float | None = None,
        on_sample: Callable[[dict[str, float]], None] | None = None,
    ) -> int:
        self._install_signals()
        self._open_csv()
        started = time.monotonic()
        count = 0
        try:
            while not self._stop:
                if duration_sec is not None and (time.monotonic() - started) >= duration_sec:
                    break
                t0 = time.monotonic()
                row = self.collector.sample()
                if self.buffer is not None:
                    self.buffer.append(row)
                if self._writer is not None:
                    self._writer.writerow(row)
                    self._fh.flush()
                if on_sample is not None:
                    on_sample(row)
                count += 1
                elapsed = time.monotonic() - t0
                sleep_for = self.interval_sec - elapsed
                if sleep_for > 0:
                    time.sleep(sleep_for)
        finally:
            self.close()
        return count
