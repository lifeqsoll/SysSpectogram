from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import psutil


def _read_vmstat() -> dict[str, int]:
    path = Path("/proc/vmstat")
    if not path.exists():
        return {}
    out: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in {"pgfault", "pgmajfault"}:
                out[parts[0]] = int(parts[1])
    except OSError:
        return {}
    return out


def _count_sockets_proc() -> tuple[int, int]:
    established = 0
    listen = 0
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        path = Path(name)
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 4:
                continue
            state = cols[3]
            if state == "01":
                established += 1
            elif state == "0A":
                listen += 1
    return established, listen


def _read_gpu() -> tuple[float, float]:
    """Best-effort NVIDIA GPU util/mem via nvidia-smi. Soft-fail -> (0,0)."""
    import shutil
    import subprocess

    if shutil.which("nvidia-smi") is None:
        return 0.0, 0.0
    try:
        proc = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return 0.0, 0.0
        line = proc.stdout.strip().splitlines()[0]
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            return 0.0, 0.0
        util = float(parts[0])
        used = float(parts[1])
        total = float(parts[2]) or 1.0
        return util, 100.0 * used / total
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0.0, 0.0


class MetricsCollector:
    """Collects per-second system rates with a stable column schema."""

    def __init__(self, max_cores: int = 16, socket_sample_every: int = 5) -> None:
        self.max_cores = max_cores
        self.socket_sample_every = max(1, socket_sample_every)
        self._tick = 0
        self._prev_cpu_stats: Any | None = None
        self._prev_net: Any | None = None
        self._prev_disk: Any | None = None
        self._prev_vm: dict[str, int] = {}
        self._prev_ts: float | None = None
        self._sock_est = 0
        self._sock_listen = 0
        self.columns = self._build_columns()
        # Warm up first cpu_percent call
        psutil.cpu_percent(percpu=True)

    def _build_columns(self) -> list[str]:
        cols = [
            "timestamp",
            "cpu_percent",
        ]
        cols.extend(f"cpu_core_{i}" for i in range(self.max_cores))
        cols.extend(
            [
                "ctx_switches_per_s",
                "interrupts_per_s",
                "soft_interrupts_per_s",
                "syscalls_per_s",
                "mem_percent",
                "swap_percent",
                "pgfault_per_s",
                "pgmajfault_per_s",
                "net_bytes_sent_per_s",
                "net_bytes_recv_per_s",
                "net_packets_sent_per_s",
                "net_packets_recv_per_s",
                "sock_established",
                "sock_listen",
                "disk_read_bytes_per_s",
                "disk_write_bytes_per_s",
                "disk_read_count_per_s",
                "disk_write_count_per_s",
                "gpu_util_percent",
                "gpu_mem_percent",
            ]
        )
        return cols

    def _rate(self, cur: float, prev: float | None, dt: float) -> float:
        if prev is None or dt <= 0:
            return 0.0
        delta = cur - prev
        if delta < 0:
            return 0.0
        return float(delta / dt)

    def sample(self) -> dict[str, float]:
        now = time.time()
        dt = 1.0 if self._prev_ts is None else max(now - self._prev_ts, 1e-6)

        cpu_total = float(psutil.cpu_percent(interval=None))
        per_core = [float(x) for x in psutil.cpu_percent(percpu=True, interval=None)]
        cores = [0.0] * self.max_cores
        for i, val in enumerate(per_core[: self.max_cores]):
            cores[i] = val

        cpu_stats = psutil.cpu_stats()
        if self._prev_cpu_stats is None:
            ctx_r = int_r = soft_r = sys_r = 0.0
        else:
            prev = self._prev_cpu_stats
            ctx_r = self._rate(cpu_stats.ctx_switches, prev.ctx_switches, dt)
            int_r = self._rate(cpu_stats.interrupts, prev.interrupts, dt)
            soft_r = self._rate(cpu_stats.soft_interrupts, prev.soft_interrupts, dt)
            syscalls = getattr(cpu_stats, "syscalls", 0) or 0
            prev_sys = getattr(prev, "syscalls", 0) or 0
            sys_r = self._rate(syscalls, prev_sys, dt)
        self._prev_cpu_stats = cpu_stats

        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        vm = _read_vmstat()
        pgfault_r = self._rate(vm.get("pgfault", 0), self._prev_vm.get("pgfault"), dt)
        pgmaj_r = self._rate(vm.get("pgmajfault", 0), self._prev_vm.get("pgmajfault"), dt)
        self._prev_vm = vm

        net = psutil.net_io_counters()
        if self._prev_net is None:
            net_sent = net_recv = pkt_sent = pkt_recv = 0.0
        else:
            p = self._prev_net
            net_sent = self._rate(net.bytes_sent, p.bytes_sent, dt)
            net_recv = self._rate(net.bytes_recv, p.bytes_recv, dt)
            pkt_sent = self._rate(net.packets_sent, p.packets_sent, dt)
            pkt_recv = self._rate(net.packets_recv, p.packets_recv, dt)
        self._prev_net = net

        if self._tick % self.socket_sample_every == 0:
            self._sock_est, self._sock_listen = _count_sockets_proc()

        disk = psutil.disk_io_counters()
        if disk is None or self._prev_disk is None:
            d_rb = d_wb = d_rc = d_wc = 0.0
        else:
            p = self._prev_disk
            d_rb = self._rate(disk.read_bytes, p.read_bytes, dt)
            d_wb = self._rate(disk.write_bytes, p.write_bytes, dt)
            d_rc = self._rate(disk.read_count, p.read_count, dt)
            d_wc = self._rate(disk.write_count, p.write_count, dt)
        if disk is not None:
            self._prev_disk = disk

        gpu_util, gpu_mem = _read_gpu()

        self._prev_ts = now
        self._tick += 1

        row: dict[str, float] = {
            "timestamp": now,
            "cpu_percent": cpu_total,
            "ctx_switches_per_s": ctx_r,
            "interrupts_per_s": int_r,
            "soft_interrupts_per_s": soft_r,
            "syscalls_per_s": sys_r,
            "mem_percent": float(mem.percent),
            "swap_percent": float(swap.percent),
            "pgfault_per_s": pgfault_r,
            "pgmajfault_per_s": pgmaj_r,
            "net_bytes_sent_per_s": net_sent,
            "net_bytes_recv_per_s": net_recv,
            "net_packets_sent_per_s": pkt_sent,
            "net_packets_recv_per_s": pkt_recv,
            "sock_established": float(self._sock_est),
            "sock_listen": float(self._sock_listen),
            "disk_read_bytes_per_s": d_rb,
            "disk_write_bytes_per_s": d_wb,
            "disk_read_count_per_s": d_rc,
            "disk_write_count_per_s": d_wc,
            "gpu_util_percent": gpu_util,
            "gpu_mem_percent": gpu_mem,
        }
        for i, val in enumerate(cores):
            row[f"cpu_core_{i}"] = val
        return row
