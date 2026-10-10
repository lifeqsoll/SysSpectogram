"""Metrics spectrogram around an event (alert or incident), from the timeseries store.

Used by the Control Center (on demand) and by Telegram alerts (attached photo).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from sysspectogram.viz.panels import render_alert_panel

SNAPSHOT_METRICS: tuple[str, ...] = (
    "cpu_percent",
    "mem_percent",
    "swap_percent",
    "gpu_util_percent",
    "net_bytes_recv_per_s",
    "net_bytes_sent_per_s",
    "disk_write_bytes_per_s",
    "disk_read_bytes_per_s",
)


def render_window(
    store: Any,
    t0: float,
    t1: float,
    *,
    title: str = "SysSpectogram",
    score: float | None = None,
    step: float = 1.0,
) -> bytes | None:
    """PNG spectrogram of metrics over [t0, t1]; None when the store has no data there."""
    if t1 <= t0:
        return None
    grid = np.arange(float(t0), float(t1), float(step))
    if grid.size < 2:
        return None
    available = set(store.metrics())
    columns: list[np.ndarray] = []
    names: list[str] = []
    for metric in SNAPSHOT_METRICS:
        if metric not in available:
            continue
        pts = store.window(metric, t0, t1)
        if len(pts) < 2:
            continue
        xs = np.asarray([p[0] for p in pts], dtype=np.float64)
        ys = np.asarray([p[1] for p in pts], dtype=np.float64)
        columns.append(np.interp(grid, xs, ys, left=0.0, right=0.0))
        names.append(metric)
    if not columns:
        return None
    window = np.stack(columns, axis=1)  # time x features, as render_alert_panel expects
    return render_alert_panel(
        metric_window=window,
        metric_columns=names,
        proc_matrix=np.zeros((0, 0)),  # per-process history is not stored
        proc_labels=[],
        title=title,
        score=score,
    )


def render_to_file(
    store_path: Path,
    t0: float,
    t1: float,
    out: Path,
    *,
    title: str = "SysSpectogram",
    score: float | None = None,
) -> bool:
    """Render [t0, t1] from the sqlite store into `out`. Returns False when there is no data."""
    from sysspectogram.timeseries.store import TimeseriesStore

    store = TimeseriesStore(store_path)
    try:
        png = render_window(store, t0, t1, title=title, score=score)
    finally:
        store.close()
    if not png:
        return False
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(png)
    return True
