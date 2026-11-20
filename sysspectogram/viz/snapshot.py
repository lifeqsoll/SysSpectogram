"""Metrics spectrogram around an event (alert or incident), from the timeseries store.

Used by the Control Center (on demand) and by Telegram alerts (attached photo).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from sysspectogram.viz.panels import ProcessCpuTracker, render_alert_panel

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


def live_proc_matrix(top_k: int = 8) -> tuple[np.ndarray, list[str]]:
    """At least one live process CPU sample for alert spectrograms.

    Timeseries store does not keep per-PID history; without this the panel
    showed ``n/a``. Warm + two samples so cpu_percent is non-trivial when possible.
    """
    import time

    track = ProcessCpuTracker(maxlen=max(4, top_k), top_k=top_k)
    try:
        track.warm()
        track.sample()
        time.sleep(0.05)
        track.sample()
    except Exception:
        return np.zeros((1, 1), dtype=np.float32), ["sample"]
    mat, labels = track.matrix(top_k=top_k)
    if mat.size == 0 or not labels:
        return np.zeros((1, 1), dtype=np.float32), ["sample"]
    return mat, labels


def render_window(
    store: Any,
    t0: float,
    t1: float,
    *,
    title: str = "SysSpectogram",
    score: float | None = None,
    step: float = 1.0,
    proc_matrix: np.ndarray | None = None,
    proc_labels: list[str] | None = None,
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
    if proc_matrix is None or proc_labels is None:
        proc_matrix, proc_labels = live_proc_matrix(top_k=8)
    return render_alert_panel(
        metric_window=window,
        metric_columns=names,
        proc_matrix=proc_matrix,
        proc_labels=proc_labels,
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
