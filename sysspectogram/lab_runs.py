"""Registry of lab runs for the Control Center and `python -m sysspectogram lab`.

Every run is localhost-only, needs no root, and states the alert it should produce.
Runs that use the intrusion scripts are marked `lab_flag`: the UI asks for consent
before starting them. The egress run also passes `--lab` to its script.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class LabRun:
    id: str
    title: dict[str, str]
    description: dict[str, str]
    argv: tuple[str, ...]
    expect_rule: str  # rule_id or perimeter pattern that should appear in alerts
    duration_sec: int
    lab_flag: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)


def _sim(*args: str) -> tuple[str, ...]:
    return (sys.executable, "-m", "sysspectogram", "simulate", *args)


def _script(name: str, *args: str) -> tuple[str, ...]:
    return (sys.executable, str(ROOT / "simulations" / "intrusion" / name), *args)


RUNS: tuple[LabRun, ...] = (
    LabRun(
        id="sim-cpu",
        title={"en": "CPU load (localhost)", "ru": "Нагрузка CPU (localhost)"},
        description={
            "en": "Busy loops on this machine for 30 s. Expect a host ML anomaly on the CPU channels.",
            "ru": "Циклы нагрузки на этой машине на 30 с. Ожидается аномалия ML по каналам CPU.",
        },
        argv=_sim("cpu", "--duration", "30", "--workers", "2"),
        expect_rule="host_anomaly",
        duration_sec=30,
        tags=("host",),
    ),
    LabRun(
        id="sim-mem",
        title={"en": "Memory pressure (localhost)", "ru": "Давление на память (localhost)"},
        description={
            "en": "Allocates 512 MB for 20 s. Expect a host ML anomaly on memory channels.",
            "ru": "Выделяет 512 МБ на 20 с. Ожидается аномалия ML по каналам памяти.",
        },
        argv=_sim("mem", "--duration", "20", "--mb", "512"),
        expect_rule="host_anomaly",
        duration_sec=20,
        tags=("host",),
    ),
    LabRun(
        id="sim-disk",
        title={"en": "Disk churn (localhost)", "ru": "Нагрузка на диск (localhost)"},
        description={
            "en": "Writes and reads 16 MB blocks for 20 s in the working directory.",
            "ru": "Записывает и читает блоки по 16 МБ в течение 20 с в рабочем каталоге.",
        },
        argv=_sim("disk", "--duration", "20", "--block-mb", "16"),
        expect_rule="host_anomaly",
        duration_sec=20,
        tags=("host",),
    ),
    LabRun(
        id="sim-net",
        title={"en": "Loopback connects (localhost)", "ru": "Соединения на loopback (localhost)"},
        description={
            "en": "Connects to 127.0.0.1 at 40 per second for 20 s. Never leaves the machine.",
            "ru": "Соединения к 127.0.0.1 по 40 в секунду в течение 20 с. Трафик не покидает машину.",
        },
        argv=_sim("net", "--duration", "20", "--rate", "40"),
        expect_rule="agent_connect_burst",
        duration_sec=20,
        tags=("agent",),
    ),
    LabRun(
        id="lab-port-scan",
        title={"en": "Connect flood (localhost)", "ru": "Поток соединений (localhost)"},
        description={
            "en": "Many connects to a local port for 5 s. An alert appears only if the agent or perimeter rules see the burst.",
            "ru": "Множество соединений к локальному порту на 5 с. Алерт появится, только если правила агента или периметра увидят всплеск.",
        },
        argv=_script("port_scan_local.py", "--duration", "5", "--count", "40"),
        expect_rule="agent_connect_burst",
        duration_sec=5,
        lab_flag=True,
        tags=("perimeter", "agent"),
    ),
    LabRun(
        id="lab-egress-beacon",
        title={"en": "Egress beacon (local sink)", "ru": "Исходящий «маячок» (локальный приёмник)"},
        description={
            "en": "Beacons to 127.0.0.1 only, for 8 s. Never sends traffic to a remote address.",
            "ru": "Шлёт «маячок» только на 127.0.0.1, 8 с. Трафик на внешние адреса не отправляется.",
        },
        argv=_script("egress_beacon.py", "--local-sink", "--lab", "--duration", "8"),
        expect_rule="egress",
        duration_sec=8,
        lab_flag=True,
        tags=("perimeter",),
    ),
    LabRun(
        id="sim-cpu-spike",
        title={"en": "CPU spike (short, localhost)", "ru": "Короткий всплеск CPU (localhost)"},
        description={
            "en": "Four busy workers for 8 s. A short, sharp spike, unlike the sustained CPU run.",
            "ru": "Четыре рабочих потока на 8 с. Короткий резкий всплеск, в отличие от длительной нагрузки CPU.",
        },
        argv=_sim("cpu", "--duration", "8", "--workers", "4"),
        expect_rule="host_anomaly",
        duration_sec=8,
        tags=("host",),
    ),
    LabRun(
        id="sim-gpu",
        title={"en": "GPU compute (localhost)", "ru": "Вычисления на GPU (localhost)"},
        description={
            "en": "CUDA matmul load for 20 s. Needs a CUDA build of torch. Fails with a clear message otherwise.",
            "ru": "Нагрузка matmul на CUDA, 20 с. Нужна CUDA-сборка torch. Иначе запуск завершится с понятной ошибкой.",
        },
        argv=_sim("gpu", "--duration", "20", "--gpu-size", "2048"),
        expect_rule="host_anomaly",
        duration_sec=20,
        tags=("host", "gpu"),
    ),
    LabRun(
        id="sim-gpu-mem",
        title={"en": "GPU memory pressure (localhost)", "ru": "Давление на память GPU (localhost)"},
        description={
            "en": "Holds 1 GB of GPU memory for 20 s. Needs a CUDA build of torch.",
            "ru": "Удерживает 1 ГБ памяти GPU на 20 с. Нужна CUDA-сборка torch.",
        },
        argv=_sim("gpu-mem", "--duration", "20", "--gpu-mb", "1024"),
        expect_rule="host_anomaly",
        duration_sec=20,
        tags=("host", "gpu"),
    ),
)

_BY_ID = {r.id: r for r in RUNS}


def get_run(run_id: str) -> LabRun:
    if run_id not in _BY_ID:
        raise KeyError(f"unknown lab run {run_id!r}")
    return _BY_ID[run_id]


def run_lab(run_id: str, *, timeout_sec: float | None = None) -> int:
    """Execute a registered run as the current user. Returns the exit code."""
    run = get_run(run_id)
    limit = timeout_sec if timeout_sec is not None else run.duration_sec * 3 + 30
    completed = subprocess.run(
        list(run.argv),
        cwd=str(ROOT),
        timeout=limit,
        check=False,
    )
    return int(completed.returncode)


def list_runs() -> Sequence[LabRun]:
    return RUNS
