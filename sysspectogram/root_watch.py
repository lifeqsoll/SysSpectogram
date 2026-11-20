"""Watch for unexpected uid=0 processes (privilege to root)."""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path


# Old comm names. Not consulted by soft_allow and not merged into operator config.
# Kept so tests can pass the historical set and prove prefix matching is gone.
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

# Exact executable paths. Comm is not part of this allowlist.
DEFAULT_ALLOW_EXES = frozenset(
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
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/sbin/cron",
        "/usr/bin/cron",
        "/usr/sbin/crond",
        "/usr/bin/crond",
        "/usr/bin/dbus-daemon",
        "/usr/sbin/NetworkManager",
        "/usr/bin/NetworkManager",
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd-journald",
        "/usr/lib/systemd/systemd-udevd",
        "/usr/lib/systemd/systemd-logind",
        "/usr/lib/systemd/systemd-networkd",
        "/usr/lib/systemd/systemd-resolved",
        "/usr/lib/systemd/systemd-timesyncd",
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

_KTHREAD_PREFIXES = ("kworker/", "ksoftirqd/", "migration/", "rcu_", "kthreadd")
_DENY_EXE_PREFIXES = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/home/",
    "/root/",
    "memfd:",
)
_SYSTEM_EXE_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/")

_DEDUP_SEC = 600.0
_BASELINE_MAX_AGE_SEC = 900.0
_DEFAULT_BASELINE_PATH = Path("state/root_baseline.py.json")


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
    baseline: set[int | tuple[int, int, str]] = field(default_factory=set)
    baseline_until: float = 0.0
    alerted: dict[int, int] = field(default_factory=dict)
    dedup: dict[tuple[str, str], float] = field(default_factory=dict)
    trusted_pids: set[int] = field(default_factory=set)
    baseline_path: Path = field(default_factory=lambda: Path("state/root_baseline.py.json"))
    last_baseline_save: float = 0.0
    track_baseline: bool = False


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
        # Kernel threads have no exe symlink. Do not invent "/proc/N/exe".
        link = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""
    return _interpret_exe_link(link)


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


def _exe_denied(path: str) -> bool:
    return path.endswith(" (deleted)") or path.startswith(_DENY_EXE_PREFIXES)


def _canonical_exe(path: str) -> str:
    try:
        return str(Path(path).resolve(strict=True))
    except OSError:
        return path


def _interpret_exe_link(link: str) -> str:
    """Keep a deleted or memfd link as readlink wrote it; otherwise canonicalize."""
    if link.endswith(" (deleted)") or link.startswith("memfd:"):
        return link
    return _canonical_exe(link)


@cache
def _builtin_allow_exes() -> frozenset[str]:
    """Built-in exes compared after canonicalize. Missing entries stay as written."""
    return frozenset(_canonical_exe(entry) for entry in DEFAULT_ALLOW_EXES)


def soft_allow(comm: str, exe: str, allow_comms: set[str]) -> bool:
    """Allow exact built-in exes, exact config paths, or a bare config name on a system exe.

    No exe (empty string): only kernel-thread comm prefixes. Comm is never a prefix match.
    """
    if not exe:
        return comm.startswith(_KTHREAD_PREFIXES)
    if _exe_denied(exe):
        return False
    path = _canonical_exe(exe)
    if _exe_denied(path):
        return False
    if path in _builtin_allow_exes():
        return True
    for entry in allow_comms:
        item = entry.strip()
        if not item:
            continue
        if "/" in item:
            if path == _canonical_exe(item):
                return True
        elif comm == item and path.startswith(_SYSTEM_EXE_PREFIXES):
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


def _read_starttime(pid: int) -> int | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Field 22 is starttime, after the last ')' because comm can contain spaces.
    cut = text.rfind(")")
    if cut < 0:
        return None
    fields = text[cut + 1 :].split()
    if len(fields) <= 19:
        return None
    try:
        return int(fields[19])
    except ValueError:
        return None


def _read_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _baseline_file_trusted(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    if stat.S_IMODE(info.st_mode) & 0o077:
        return False
    euid = os.geteuid()
    if euid == 0:
        return info.st_uid == 0
    return info.st_uid == euid


def _baseline_has(state: RootWatchState, pid: int, starttime: int) -> bool:
    for entry in state.baseline:
        if entry == pid:
            return True
        if (
            isinstance(entry, tuple)
            and len(entry) >= 2
            and entry[0] == pid
            and entry[1] == starttime
        ):
            return True
    return False


def _remember_root(state: RootWatchState, pid: int, starttime: int | None, exe: str) -> None:
    if starttime is None:
        state.baseline.add(pid)
    else:
        state.baseline.add((pid, starttime, exe))


# Trust the baseline only for this boot when it is owner-only and newer than 15 minutes.
def _load_root_baseline(state: RootWatchState, path: Path, now: float) -> bool:
    if not _baseline_file_trusted(path):
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False
    if not isinstance(payload, dict):
        return False
    boot_id = _read_boot_id()
    if not boot_id or payload.get("boot_id") != boot_id:
        return False
    saved_at = payload.get("saved_at")
    if isinstance(saved_at, bool) or not isinstance(saved_at, (int, float)):
        return False
    if float(saved_at) < now - _BASELINE_MAX_AGE_SEC:
        return False
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return False
    loaded: set[int | tuple[int, int, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item["pid"])
            starttime = int(item["starttime"])
        except (KeyError, TypeError, ValueError):
            continue
        exe = item.get("exe", "")
        if not isinstance(exe, str):
            exe = str(exe)
        loaded.add((pid, starttime, exe))
    state.baseline = loaded
    state.baseline_until = now
    return True


def save_root_baseline(state: RootWatchState, path: Path | None = None) -> None:
    dest = Path(path) if path is not None else state.baseline_path
    try:
        info = os.lstat(dest)
    except FileNotFoundError:
        info = None
    if info is not None and stat.S_ISLNK(info.st_mode):
        raise OSError(f"root baseline path is a symlink: {dest}")
    boot_id = _read_boot_id()
    if not boot_id:
        raise OSError("boot_id unavailable")
    entries = []
    for entry in state.baseline:
        if isinstance(entry, tuple) and len(entry) >= 3:
            entries.append(
                {"pid": int(entry[0]), "starttime": int(entry[1]), "exe": str(entry[2])}
            )
    payload = {"boot_id": boot_id, "saved_at": int(time.time()), "entries": entries}
    data = json.dumps(payload).encode("utf-8")
    parent = dest.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.{os.getpid()}.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, data)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    if dest.is_symlink():
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise OSError(f"root baseline path is a symlink: {dest}")
    try:
        os.replace(tmp, dest)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(dest, 0o600)


def _maybe_save_root_baseline(state: RootWatchState, now: float) -> None:
    # Save during the learn window too. A crash there must reuse the snapshot
    # instead of opening another blind learn on the next start.
    if not state.track_baseline:
        return
    if state.last_baseline_save and now - state.last_baseline_save < 30.0:
        return
    try:
        save_root_baseline(state, state.baseline_path)
    except OSError:
        return
    state.last_baseline_save = now


def poll_new_root(
    state: RootWatchState,
    *,
    learn_sec: float = 300.0,
    allow_comms: set[str] | None = None,
    trusted_pids: set[int] | None = None,
    baseline_path: Path | None = None,
) -> list[RootProc]:
    """Learn baseline root PIDs (cheap), deep-describe only newcomers."""
    now = time.time()
    path = Path(baseline_path) if baseline_path is not None else _DEFAULT_BASELINE_PATH
    if state.baseline_until <= 0:
        state.baseline_path = path
        state.track_baseline = True
        if not _load_root_baseline(state, path, now):
            state.baseline_until = now + float(learn_sec)
    if trusted_pids is not None:
        state.trusted_pids = set(trusted_pids)
    pids = list_root_pids_cheap()
    unexpected: list[RootProc] = []
    # Operator config only. Built-in defaults are exact exes inside soft_allow.
    allow = set(allow_comms) if allow_comms is not None else set()
    # Drop stale dedup entries.
    state.dedup = {k: t for k, t in state.dedup.items() if now - t < _DEDUP_SEC}
    if now < state.baseline_until:
        for pid in pids:
            _remember_root(state, pid, _read_starttime(pid), _read_exe(pid))
        _maybe_save_root_baseline(state, now)
        return []
    for pid in pids:
        starttime = _read_starttime(pid)
        if starttime is not None and state.alerted.get(pid) == starttime:
            continue
        if starttime is None and pid in state.alerted:
            continue
        if starttime is not None:
            if _baseline_has(state, pid, starttime):
                continue
        elif pid in state.baseline:
            continue
        if pid_under_trusted(pid, state.trusted_pids):
            _remember_root(state, pid, starttime, "")
            continue
        p = describe_root_pid(pid)
        if not p.exe and p.comm:
            # kernel thread - ignore
            _remember_root(state, pid, starttime, p.exe)
            continue
        if soft_allow(p.comm, p.exe, allow):
            _remember_root(state, pid, starttime, p.exe)
            continue
        p.severity = root_severity(p.exe, p.parent_comm)
        key = (p.comm, p.exe or "?")
        prev = state.dedup.get(key)
        if prev is not None and now - prev < _DEDUP_SEC:
            state.alerted[pid] = -1 if starttime is None else starttime
            continue
        state.dedup[key] = now
        unexpected.append(p)
        state.alerted[pid] = -1 if starttime is None else starttime
    _maybe_save_root_baseline(state, now)
    return unexpected
