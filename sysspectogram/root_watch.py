"""Watch for unexpected uid=0 processes (privilege to root)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path


# Common always-root daemons - still learned in baseline; used only as soft hints.
# Utility names also require a matching system exe path when available.
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
        "journalctl",
        "systemctl",
        "nft",
        "ip",
        "ss",
        "pacman",
        "sudo",  # sudo itself only — children still checked
        "logrotate",
        "man-db",
        "mandb",
        "updatedb",
        "fstrim",
    }
)

_UTILITY_COMMS = frozenset(
    {
        "journalctl",
        "systemctl",
        "nft",
        "ip",
        "ss",
        "pacman",
        "sudo",
        "logrotate",
        "man-db",
        "mandb",
        "updatedb",
        "fstrim",
    }
)

_DEFAULT_ALLOW_EXES = frozenset(
    {
        "/usr/bin/journalctl",
        "/usr/bin/systemctl",
        "/usr/sbin/nft",
        "/usr/bin/nft",
        "/usr/sbin/ip",
        "/usr/bin/ip",
        "/usr/bin/ss",
        "/usr/bin/pacman",
        "/usr/bin/sudo",
        "/usr/sbin/logrotate",
        "/usr/bin/logrotate",
        "/usr/bin/mandb",
        "/usr/bin/updatedb",
        "/usr/sbin/fstrim",
        "/usr/bin/fstrim",
        "/usr/local/sbin/sysspectogram-agent",
        "/usr/sbin/sysspectogram-agent",
    }
)

_DEDUP_SEC = 600.0


@dataclass
class RootProc:
    pid: int
    comm: str
    exe: str
    cmdline: str
    euid: int
    ruid: int
    severity: str = "critical"
    parent_comm: str = ""


@dataclass
class RootWatchState:
    baseline: set[int] = field(default_factory=set)
    baseline_until: float = 0.0
    alerted: set[int] = field(default_factory=set)
    dedup: dict[tuple[str, str], float] = field(default_factory=dict)
    trusted_pids: set[int] = field(default_factory=set)


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


def _read_ppid(pid: int) -> int | None:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("PPid:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
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
        # strict: kernel threads have no exe symlink — must not fake "/proc/N/exe".
        return str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    except OSError:
        return ""


def pid_under_trusted(pid: int, trusted: set[int]) -> bool:
    """True if pid is trusted or any ancestor ppid is."""
    if not trusted:
        return False
    if pid in trusted:
        return True
    cur = pid
    for _ in range(64):
        ppid = _read_ppid(cur)
        if ppid is None or ppid <= 0 or ppid == cur:
            return False
        if ppid in trusted:
            return True
        cur = ppid
    return False


def _exe_allowed(exe: str, allow_comms: set[str]) -> bool:
    if not exe:
        return False
    if exe in _DEFAULT_ALLOW_EXES:
        return True
    base = Path(exe).name
    if base in DEFAULT_ALLOW_COMMS or base in allow_comms:
        if exe.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
            return True
    for a in allow_comms:
        if a.startswith("/") and (exe == a or exe.endswith(a)):
            return True
    return False


def soft_allow(comm: str, exe: str, allow_comms: set[str]) -> bool:
    """Allow known daemons/utilities; utilities need a matching system exe when set."""
    name_ok = any(comm == a or comm.startswith(a) for a in allow_comms)
    if name_ok:
        if comm in _UTILITY_COMMS and exe and not _exe_allowed(exe, allow_comms):
            return False
        return True
    if exe and _exe_allowed(exe, allow_comms):
        return True
    return False


def root_severity(exe: str, parent_comm: str) -> str:
    if exe.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
        return "critical"
    parent = (parent_comm or "").lower()
    if parent in {"systemd", "cron", "crond"} or parent.startswith(("systemd", "cron")):
        return "medium"
    return "critical"


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
    ppid = _read_ppid(pid) or 0
    return RootProc(
        pid=pid,
        comm=_read_comm(pid),
        exe=_read_exe(pid),
        cmdline=_read_cmdline(pid),
        euid=euid,
        ruid=ruid,
        parent_comm=_read_comm(ppid) if ppid > 1 else "",
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
    trusted_pids: set[int] | None = None,
) -> list[RootProc]:
    """Learn baseline root PIDs (cheap), deep-describe only newcomers."""
    now = time.time()
    if state.baseline_until <= 0:
        state.baseline_until = now + float(learn_sec)
    if trusted_pids is not None:
        state.trusted_pids = set(trusted_pids)
    pids = list_root_pids_cheap()
    unexpected: list[RootProc] = []
    allow = set(allow_comms) if allow_comms is not None else set(DEFAULT_ALLOW_COMMS)
    # Keep defaults even when config adds extras.
    allow |= set(DEFAULT_ALLOW_COMMS)
    # Drop stale dedup entries.
    state.dedup = {k: t for k, t in state.dedup.items() if now - t < _DEDUP_SEC}
    if now < state.baseline_until:
        state.baseline |= pids
        return []
    for pid in pids:
        if pid in state.baseline or pid in state.alerted:
            continue
        if pid_under_trusted(pid, state.trusted_pids):
            state.baseline.add(pid)
            continue
        p = describe_root_pid(pid)
        if not p.exe and p.comm:
            # kernel thread - ignore
            state.baseline.add(pid)
            continue
        if soft_allow(p.comm, p.exe, allow):
            state.baseline.add(pid)
            continue
        p.severity = root_severity(p.exe, p.parent_comm)
        key = (p.comm, p.exe or "?")
        prev = state.dedup.get(key)
        if prev is not None and now - prev < _DEDUP_SEC:
            state.alerted.add(pid)
            continue
        state.dedup[key] = now
        unexpected.append(p)
        state.alerted.add(pid)
    return unexpected
