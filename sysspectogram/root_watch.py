"""Watch for unexpected uid=0 processes (privilege to root)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path


# Common always-root daemons - still learned in baseline; used only as soft hints.
DEFAULT_ALLOW_COMMS = frozenset(
    {
        "systemd",
        "kthreadd",
        "rcu_sched",
        "migration",
        "ksoftirqd",
        "kworker",
        "sshd",
        "systemd-journal",
        "systemd-udevd",
        "systemd-logind",
        "cron",
        "crond",
        "dbus-daemon",
        "NetworkManager",
        "nftables",
        "sysspectogram-a",  # truncated comm
        "sysspectogram-agent",
    }
)


@dataclass
class RootProc:
    pid: int
    comm: str
    exe: str
    cmdline: str
    euid: int
    ruid: int


@dataclass
class RootWatchState:
    baseline: set[int] = field(default_factory=set)
    baseline_until: float = 0.0
    alerted: set[int] = field(default_factory=set)


def _read_status_uids(pid: int) -> tuple[int, int] | None:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            # Uid: real effective saved fs
            if len(parts) >= 3:
                return int(parts[1]), int(parts[2])
    return None


def _read_comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return "?"


def _read_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()[:200]
    except OSError:
        return ""


def _read_exe(pid: int) -> str:
    try:
        return str(Path(f"/proc/{pid}/exe").resolve())
    except OSError:
        return ""


def list_root_pids_cheap() -> set[int]:
    """Only read /proc/*/status Uid lines - no exe/cmdline (lite VPS friendly)."""
    out: set[int] = set()
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return out
    for ent in entries:
        name = ent.name
        if not name.isdigit():
            continue
        pid = int(name)
        if pid <= 1:
            continue
        uids = _read_status_uids(pid)
        if uids is None:
            continue
        ruid, euid = uids
        if euid == 0 or ruid == 0:
            out.add(pid)
    return out


def describe_root_pid(pid: int) -> RootProc:
    uids = _read_status_uids(pid) or (0, 0)
    ruid, euid = uids
    return RootProc(
        pid=pid,
        comm=_read_comm(pid),
        exe=_read_exe(pid),
        cmdline=_read_cmdline(pid),
        euid=euid,
        ruid=ruid,
    )


def list_root_procs(*, include_kernel: bool = False) -> list[RootProc]:
    out: list[RootProc] = []
    for pid in list_root_pids_cheap():
        p = describe_root_pid(pid)
        if not include_kernel and not p.exe and p.comm:
            continue
        out.append(p)
    return out


def poll_new_root(
    state: RootWatchState,
    *,
    learn_sec: float = 300.0,
    allow_comms: set[str] | None = None,
) -> list[RootProc]:
    """Learn baseline root PIDs (cheap), deep-describe only newcomers."""
    now = time.time()
    if state.baseline_until <= 0:
        state.baseline_until = now + float(learn_sec)
    pids = list_root_pids_cheap()
    unexpected: list[RootProc] = []
    allow = allow_comms if allow_comms is not None else set(DEFAULT_ALLOW_COMMS)
    if now < state.baseline_until:
        state.baseline |= pids
        return []
    for pid in pids:
        if pid in state.baseline or pid in state.alerted:
            continue
        p = describe_root_pid(pid)
        if not p.exe and p.comm:
            # kernel thread - ignore
            state.baseline.add(pid)
            continue
        soft = any(p.comm == a or p.comm.startswith(a) for a in allow)
        if soft:
            # known daemon name appearing after learn - still alert once? keep quiet
            state.baseline.add(pid)
            continue
        unexpected.append(p)
        state.alerted.add(pid)
    return unexpected
