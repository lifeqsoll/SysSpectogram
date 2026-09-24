from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

import numpy as np


@dataclass
class ProcessCpuTracker:
    """Rolling CPU% samples for top processes (for TG heatmaps)."""

    maxlen: int = 60
    top_k: int = 8
    history: deque = field(default_factory=lambda: deque(maxlen=60))
    _warmed: bool = False

    def __post_init__(self) -> None:
        self.history = deque(maxlen=self.maxlen)

    def warm(self) -> None:
        import psutil

        for p in psutil.process_iter(["pid"]):
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._warmed = True

    def sample(self) -> list[dict[str, Any]]:
        import psutil

        if not self._warmed:
            self.warm()
        rows: list[dict[str, Any]] = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                with p.oneshot():
                    cpu = float(p.cpu_percent(interval=None))
                    name = p.info.get("name") or "?"
                    pid = int(p.info.get("pid") or 0)
                    if pid <= 1:
                        continue
                    rows.append({"pid": pid, "name": name, "cpu": cpu})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        rows.sort(key=lambda r: r["cpu"], reverse=True)
        snap = rows[: max(self.top_k * 3, 20)]
        self.history.append(snap)
        return snap[: self.top_k]

    def matrix(self, top_k: int | None = None) -> tuple[np.ndarray, list[str]]:
        k = top_k or self.top_k
        if not self.history:
            return np.zeros((k, 1), dtype=np.float32), [f"p{i}" for i in range(k)]
        # Pick stable top labels by peak CPU across history
        peak: dict[tuple[int, str], float] = {}
        for snap in self.history:
            for r in snap:
                key = (int(r["pid"]), str(r["name"]))
                peak[key] = max(peak.get(key, 0.0), float(r["cpu"]))
        keys = sorted(peak.keys(), key=lambda x: peak[x], reverse=True)[:k]
        labels = [f"{name}({pid})"[:22] for pid, name in keys]
        idx = {keys[i]: i for i in range(len(keys))}
        mat = np.zeros((len(keys), len(self.history)), dtype=np.float32)
        for t, snap in enumerate(self.history):
            for r in snap:
                key = (int(r["pid"]), str(r["name"]))
                if key in idx:
                    mat[idx[key], t] = float(r["cpu"])
        return mat, labels


def _png_from_fig(fig) -> bytes:
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor())
    import matplotlib.pyplot as plt

    plt.close(fig)
    return buf.getvalue()


def render_alert_panel(
    *,
    metric_window: np.ndarray,
    metric_columns: list[str],
    proc_matrix: np.ndarray,
    proc_labels: list[str],
    title: str = "SysSpectogram",
    score: float | None = None,
) -> bytes | None:
    """Two-panel PNG: metrics spectrogram + top-PID CPU heat over time."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import Normalize
    except ImportError:
        return None

    # Robust per-feature scale for metrics (time x feat)
    w = np.asarray(metric_window, dtype=np.float64)
    if w.ndim != 2:
        return None
    # Focus on readable subset of columns
    prefer = [
        "cpu_percent",
        "mem_percent",
        "swap_percent",
        "gpu_util_percent",
        "net_bytes_recv_per_s",
        "net_bytes_sent_per_s",
        "disk_write_bytes_per_s",
        "disk_read_bytes_per_s",
        "ctx_switches_per_s",
        "pgfault_per_s",
        "sock_established",
    ]
    idxs: list[int] = []
    names: list[str] = []
    for name in prefer:
        if name in metric_columns:
            idxs.append(metric_columns.index(name))
            names.append(name.replace("_percent", "%").replace("_per_s", "/s").replace("_bytes", "B"))
    if not idxs:
        idxs = list(range(min(12, w.shape[1])))
        names = [metric_columns[i] if i < len(metric_columns) else f"f{i}" for i in idxs]
    sub = w[:, idxs].T  # features x time
    scaled = np.zeros_like(sub)
    for i in range(sub.shape[0]):
        row = sub[i]
        lo, hi = np.percentile(row, [5, 95])
        if hi - lo < 1e-9:
            hi = lo + 1.0
        scaled[i] = np.clip((row - lo) / (hi - lo), 0, 1)

    fig, axes = plt.subplots(
        2,
        1,
        figsize=(9.5, 7.2),
        gridspec_kw={"height_ratios": [1.15, 1.0], "hspace": 0.35},
        facecolor="#0f1419",
    )
    for ax in axes:
        ax.set_facecolor("#0f1419")
        ax.tick_params(colors="#c8d0d8", labelsize=8)
        for spine in ax.spines.values():
            spine.set_color("#3a4550")

    im0 = axes[0].imshow(
        scaled,
        aspect="auto",
        origin="lower",
        interpolation="nearest",
        cmap="inferno",
        norm=Normalize(0, 1),
    )
    axes[0].set_yticks(range(len(names)))
    axes[0].set_yticklabels(names, fontsize=8, color="#e6edf3")
    axes[0].set_xlabel("time → (seconds in window)", color="#9aa7b2", fontsize=9)
    ttl = title
    if score is not None:
        ttl = f"{title}  ·  score={score:.3f}"
    axes[0].set_title(ttl, color="#f0f3f6", fontsize=11, pad=8, loc="left")
    cbar0 = fig.colorbar(im0, ax=axes[0], fraction=0.02, pad=0.02)
    cbar0.ax.tick_params(colors="#c8d0d8", labelsize=7)
    cbar0.set_label("relative", color="#9aa7b2", fontsize=8)

    pm = np.asarray(proc_matrix, dtype=np.float64)
    if pm.size == 0:
        pm = np.zeros((1, 1))
        proc_labels = ["n/a"]
    im1 = axes[1].imshow(
        pm,
        aspect="auto",
        origin="upper",
        interpolation="nearest",
        cmap="magma",
        vmin=0,
        vmax=max(100.0, float(np.nanmax(pm)) if pm.size else 100.0),
    )
    axes[1].set_yticks(range(len(proc_labels)))
    axes[1].set_yticklabels(proc_labels, fontsize=8, color="#e6edf3")
    axes[1].set_xlabel("time → (process samples)", color="#9aa7b2", fontsize=9)
    axes[1].set_title("Top processes · CPU% over time", color="#f0f3f6", fontsize=11, pad=8, loc="left")
    cbar1 = fig.colorbar(im1, ax=axes[1], fraction=0.02, pad=0.02)
    cbar1.ax.tick_params(colors="#c8d0d8", labelsize=7)
    cbar1.set_label("CPU%", color="#9aa7b2", fontsize=8)

    fig.text(0.01, 0.01, "SysSpectogram", color="#5a6772", fontsize=7)
    return _png_from_fig(fig)


def format_host_alert_caption(
    *,
    host_id: str,
    score: float,
    threshold: float,
    pattern: str,
    explain: str,
    top_procs: list[dict],
    top_features: list[dict] | None = None,
) -> str:
    lines = [
        f"[{host_id}] HOST ANOMALY",
        f"score {score:.3f}  (thr {threshold:.3f})",
        f"pattern: {pattern}",
        explain.replace("Template: ", ""),
        "",
        "top processes:",
    ]
    for p in top_procs[:5]:
        lines.append(
            f"• {p.get('name')}  pid={p.get('pid')}  "
            f"cpu={p.get('cpu_percent')}%  mem={p.get('memory_percent')}%"
        )
    if top_features:
        lines.append("")
        lines.append("dominant metrics:")
        for f in top_features[:4]:
            lines.append(f"• {f.get('feature')}: {float(f.get('mean') or 0):.1f}")
    return "\n".join(lines)[:900]


def detect_host_pattern(
    *,
    cpu: float | None = None,
    mem: float | None = None,
    swap: float | None = None,
    gpu: float | None = None,
    disk_write: float | None = None,
    top_procs: list[dict] | None = None,
) -> str:
    proc_cpu = 0.0
    if top_procs:
        proc_cpu = max(float(p.get("cpu_percent") or 0.0) for p in top_procs[:5])
    scores = {
        "cpu_spike": max(cpu or 0.0, min(proc_cpu, 100.0)),
        "mem_pressure": max(mem or 0.0, (swap or 0.0) * 1.2),
        "gpu_load": gpu or 0.0,
        "disk_thrash": min((disk_write or 0.0) / 5e6, 100.0),
    }
    names = {
        "cpu_spike": "CPU spike / compute",
        "mem_pressure": "memory pressure",
        "gpu_load": "GPU load",
        "disk_thrash": "disk thrash",
    }
    primary = max(scores, key=scores.get)
    if scores[primary] < 20:
        return "mixed / subtle deviation"
    if top_procs and primary == "cpu_spike":
        names_l = " ".join(str(p.get("name", "")).lower() for p in top_procs[:3])
        if any(x in names_l for x in ("miner", "xmrig", "hash")):
            return f"{names[primary]} (miner-like)"
        if "ffmpeg" in names_l:
            return f"{names[primary]} (media/encode)"
        if "python" in names_l:
            return f"{names[primary]} (python workers)"
    return names[primary]


def format_audit_message(
    *,
    host_id: str,
    rootkit: list[dict],
    top_procs: list[dict],
    suspicious: list[dict],
    listen_count: int | None = None,
) -> str:
    # Soft-filter AppImage / flatpak false positives for display
    real_sus = []
    soft = 0
    for s in suspicious:
        exe = str(s.get("exe") or "")
        reasons = s.get("reasons") or []
        if "/tmp/.mount_" in exe or "/app/" in exe:
            soft += 1
            continue
        if reasons == ["executable from world-writable path"] and "/tmp/" in exe:
            soft += 1
            continue
        real_sus.append(s)

    lines = [
        f"[{host_id}] AUDIT",
        f"rootkit findings: {len(rootkit)}",
    ]
    for x in rootkit[:5]:
        lines.append(f"  ! {x.get('check')}: {x.get('path') or x.get('hint') or x.get('pid')}")
    lines.append("top CPU:")
    for p in top_procs[:5]:
        lines.append(
            f"  {p.get('name')}  pid={p.get('pid')}  "
            f"cpu={p.get('cpu_percent')}%  mem={p.get('memory_percent')}%"
        )
    lines.append(f"suspicious: {len(real_sus)} hard" + (f", {soft} soft(AppImage/tmp)" if soft else ""))
    for s in real_sus[:6]:
        lines.append(
            f"  • {s.get('name')} pid={s.get('pid')} — {', '.join(s.get('reasons') or [])}"
        )
    if listen_count is not None:
        lines.append(f"listening sockets: {listen_count}")
    return "\n".join(lines)[:3800]


def format_perimeter_alert(
    *,
    host_id: str,
    severity: str,
    rule_id: str,
    message: str,
    explain: str,
    pattern: str,
    recon_summary: str | None = None,
) -> str:
    lines = [
        f"[{host_id}] {severity.upper()}",
        f"rule: {rule_id}",
        f"pattern: {pattern}",
        message,
        explain.replace("Template: ", ""),
    ]
    if recon_summary:
        lines.append("")
        lines.append(recon_summary)
    return "\n".join(lines)[:3900]


def perimeter_pattern(rule_id: str) -> str:
    return {
        "bruteforce_ssh": "SSH brute-force",
        "port_scan_suspected": "inbound port scan",
        "new_login_source": "new login source",
        "egress_denylist_hit": "egress denylist / C2-like",
        "suspicious_egress": "unusual outbound",
        "suspicious_dns": "suspicious DNS",
        "honeypot_hit": "honeypot touch",
    }.get(rule_id, rule_id)
