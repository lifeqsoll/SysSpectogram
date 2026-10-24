"""Telegram-friendly metric charts (PNG snapshot or short GIF), app-like series."""

from __future__ import annotations

import time
from io import BytesIO
from pathlib import Path
from typing import Iterable, Sequence

SERIES: dict[str, tuple[str, str]] = {
    # key -> (timeseries metric name, display label)
    "cpu": ("cpu_percent", "CPU %"),
    "mem": ("mem_percent", "Memory %"),
    "net": ("net_bytes_recv_per_s", "Net B/s (recv)"),
    "gpu": ("gpu_util_percent", "GPU %"),
    "disk": ("disk_write_bytes_per_s", "Disk write B/s"),
    "disk_r": ("disk_read_bytes_per_s", "Disk read B/s"),
    "swap": ("swap_percent", "Swap %"),
}

# Overview stack order (skip empty series at render time)
ALL_KEYS = ("cpu", "mem", "net", "gpu", "disk", "disk_r", "swap")
CORE_KEYS = ("cpu", "mem", "net")

COLORS = {
    "cpu": "#2dd4bf",
    "mem": "#f0a060",
    "net": "#60a5fa",
    "gpu": "#c084fc",
    "disk": "#f472b6",
    "disk_r": "#fb7185",
    "swap": "#a3e635",
}


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def _style_ax(ax, title: str) -> None:
    ax.set_facecolor("#0f1419")
    ax.tick_params(colors="#c8d0d8", labelsize=8)
    for spine in ax.spines.values():
        spine.set_color("#3a4550")
    ax.set_title(title, color="#f0f3f6", fontsize=11, pad=6, loc="left")
    ax.set_xlabel("time →", color="#9aa7b2", fontsize=8)
    ax.grid(True, color="#2a333c", linewidth=0.6, alpha=0.8)


def render_line_chart(
    *,
    values: Sequence[float],
    title: str,
    color: str = "#2dd4bf",
    ylabel: str = "",
) -> bytes | None:
    if not values:
        return None
    try:
        plt = _plt()
    except ImportError:
        return None
    fig, ax = plt.subplots(figsize=(8.2, 3.4), facecolor="#0f1419")
    _style_ax(ax, title)
    ys = [float(v) for v in values]
    xs = list(range(len(ys)))
    ax.plot(xs, ys, color=color, linewidth=1.8)
    ax.fill_between(xs, ys, color=color, alpha=0.18)
    if ylabel:
        ax.set_ylabel(ylabel, color="#9aa7b2", fontsize=8)
    fig.text(0.01, 0.01, "SysSpectogram", color="#5a6772", fontsize=7)
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return buf.getvalue()


def render_multi_chart(
    *,
    series: dict[str, Sequence[float]],
    title: str = "Live metrics",
    keys: Sequence[str] | None = None,
) -> bytes | None:
    """Stacked panels — mirrors the web Mini App layout."""
    order = tuple(keys) if keys else ALL_KEYS
    use = [k for k in order if k in series and series[k]]
    if not use:
        return None
    try:
        plt = _plt()
    except ImportError:
        return None
    fig, axes = plt.subplots(
        len(use),
        1,
        figsize=(8.4, 2.4 * len(use)),
        sharex=True,
        facecolor="#0f1419",
        gridspec_kw={"hspace": 0.28},
    )
    if len(use) == 1:
        axes = [axes]
    for ax, key in zip(axes, use):
        label = SERIES[key][1]
        ys = [float(v) for v in series[key]]
        xs = list(range(len(ys)))
        _style_ax(ax, f"{title} · {label}" if ax is axes[0] else label)
        color = COLORS.get(key, "#2dd4bf")
        ax.plot(xs, ys, color=color, linewidth=1.7)
        ax.fill_between(xs, ys, color=color, alpha=0.16)
    fig.text(0.01, 0.005, "SysSpectogram", color="#5a6772", fontsize=7)
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return buf.getvalue()


def frames_to_gif(frames: Iterable[bytes], *, duration_ms: int = 120) -> bytes | None:
    try:
        from PIL import Image
    except ImportError:
        return None
    images: list = []
    for raw in frames:
        if not raw:
            continue
        images.append(Image.open(BytesIO(raw)).convert("P", palette=Image.ADAPTIVE))
    if len(images) < 2:
        return None
    out = BytesIO()
    images[0].save(
        out,
        format="GIF",
        save_all=True,
        append_images=images[1:],
        duration=duration_ms,
        loop=0,
        optimize=True,
    )
    return out.getvalue()


def load_series_from_store(
    store_path: Path,
    *,
    seconds: float = 60.0,
    now: float | None = None,
) -> dict[str, list[float]]:
    """Pull last `seconds` of metrics from timeseries.sqlite."""
    from sysspectogram.timeseries.store import TimeseriesStore

    now = time.time() if now is None else float(now)
    t0 = now - float(seconds)
    out: dict[str, list[float]] = {}
    store = TimeseriesStore(Path(store_path))
    try:
        for key, (metric, _label) in SERIES.items():
            pts = store.window(metric, t0, now)
            if not pts and key == "net":
                for alt in ("net_packets_recv_per_s", "net_bytes_sent_per_s"):
                    pts = store.window(alt, t0, now)
                    if pts:
                        break
            if not pts and key == "disk":
                pts = store.window("disk_write_bytes_per_s", t0, now)
            out[key] = [v for _ts, v in pts]
    finally:
        try:
            store.close()
        except Exception:
            pass
    return out


def live_sample_series(*, seconds: float = 15.0, interval: float = 1.0) -> dict[str, list[float]]:
    """Short live collect when timeseries is empty."""
    from sysspectogram.collect.metrics import MetricsCollector

    col = MetricsCollector()
    buckets: dict[str, list[float]] = {k: [] for k in ALL_KEYS}
    n = max(3, int(seconds / max(interval, 0.2)))
    for _ in range(n):
        row = col.sample()
        buckets["cpu"].append(float(row.get("cpu_percent") or 0.0))
        buckets["mem"].append(float(row.get("mem_percent") or 0.0))
        buckets["swap"].append(float(row.get("swap_percent") or 0.0))
        buckets["gpu"].append(float(row.get("gpu_util_percent") or 0.0))
        buckets["disk"].append(float(row.get("disk_write_bytes_per_s") or 0.0))
        buckets["disk_r"].append(float(row.get("disk_read_bytes_per_s") or 0.0))
        net = row.get("net_bytes_recv_per_s")
        if net is None:
            net = row.get("net_packets_recv_per_s") or 0.0
        buckets["net"].append(float(net))
        time.sleep(interval)
    return buckets


def build_chart_pngs(
    series: dict[str, Sequence[float]],
    *,
    which: str = "all",
    host_id: str = "host",
) -> list[tuple[str, bytes]]:
    """Return list of (label, png_bytes). which: cpu|mem|net|gpu|disk|disk_r|swap|all."""
    which = (which or "all").lower().strip()
    out: list[tuple[str, bytes]] = []
    if which == "all":
        png = render_multi_chart(series=series, title=f"[{host_id}] live", keys=ALL_KEYS)
        if png:
            out.append(("all", png))
        return out
    if which == "core":
        png = render_multi_chart(series=series, title=f"[{host_id}] core", keys=CORE_KEYS)
        if png:
            out.append(("core", png))
        return out
    if which not in SERIES:
        which = "cpu"
    vals = series.get(which) or []
    png = render_line_chart(
        values=vals,
        title=f"[{host_id}] {SERIES[which][1]}",
        color=COLORS.get(which, "#2dd4bf"),
        ylabel=SERIES[which][1],
    )
    if png:
        out.append((which, png))
    return out


def build_rolling_gif(
    series: dict[str, Sequence[float]],
    *,
    which: str = "all",
    host_id: str = "host",
    window: int = 12,
    step: int = 1,
) -> bytes | None:
    """Animate last points as a short GIF (≈15s history scrub)."""
    which = (which or "all").lower().strip()
    if which == "all":
        # GIF with every panel is huge; scrub core + extras that have signal
        keys = [k for k in ALL_KEYS if series.get(k)]
        if len(keys) > 4:
            keys = list(CORE_KEYS) + [k for k in ("gpu", "disk", "swap") if series.get(k)][:1]
    elif which == "core":
        keys = list(CORE_KEYS)
    else:
        keys = [which if which in SERIES else "cpu"]
    max_len = max((len(series.get(k) or []) for k in keys), default=0)
    if max_len < 4:
        return None
    window = max(4, min(window, max_len))
    frames: list[bytes] = []
    for end in range(window, max_len + 1, max(1, step)):
        start = end - window
        slice_s = {k: list(series.get(k) or [])[start:end] for k in keys}
        if len(keys) > 1:
            png = render_multi_chart(
                series=slice_s, title=f"[{host_id}] {end - window}…{end}s", keys=keys
            )
        else:
            k = keys[0]
            png = render_line_chart(
                values=slice_s[k],
                title=f"[{host_id}] {SERIES[k][1]}",
                color=COLORS.get(k, "#2dd4bf"),
            )
        if png:
            frames.append(png)
    return frames_to_gif(frames, duration_ms=100)
