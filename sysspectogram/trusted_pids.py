"""Trusted sender PIDs for agent UDS (anti same-UID forge + anti binary swap)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


def read_pidfile(path: Path) -> int | None:
    try:
        raw = Path(path).read_text(encoding="utf-8").strip().split()[0]
        pid = int(raw)
        if pid <= 1:
            return None
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError, IndexError):
        return None


def resolve_exe(pid: int) -> Path | None:
    try:
        return Path(f"/proc/{int(pid)}/exe").resolve()
    except (OSError, ValueError):
        return None


def sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def seal_binary(path: Path) -> dict[str, str]:
    path = Path(path).resolve()
    dig = sha256_file(path)
    if not dig:
        raise FileNotFoundError(f"cannot seal {path}")
    return {"path": str(path), "sha256": dig}


def pid_matches_seal(
    pid: int,
    *,
    allowed_paths: set[str],
    expected_sha256: str | None = None,
) -> bool:
    """True if /proc/pid/exe is under an allowed path and optional hash matches."""
    exe = resolve_exe(pid)
    if exe is None:
        return False
    exe_s = str(exe)
    path_ok = False
    for allow in allowed_paths:
        a = str(Path(allow).resolve()) if allow else ""
        if not a:
            continue
        if exe_s == a or exe_s.startswith(a + "/"):
            path_ok = True
            break
        # exact basename match only for known install dirs
        if Path(a).name and exe.name == Path(a).name and (
            exe_s.startswith("/usr/local/sbin/")
            or exe_s.startswith("/usr/sbin/")
            or exe_s.startswith("/opt/")
        ):
            path_ok = True
            break
    if not path_ok:
        return False
    if expected_sha256:
        got = sha256_file(exe)
        if not got or got.lower() != expected_sha256.lower():
            return False
    return True


def collect_trusted_pids(
    *,
    agent_pidfile: Path,
    watchdog_pidfile: Path | None = None,
    extra: set[int] | None = None,
    child_of: int | None = None,
    allowed_exe_paths: set[str] | None = None,
    expected_sha256: str | None = None,
) -> set[int]:
    """PIDs allowed to speak on the agent socket.

    Same-UID alone is not enough: only these PIDs pass PEERCRED allowlist.
    Optional exe path + sha256 seal rejects a replaced binary that reused the pidfile.
    """
    out: set[int] = set(extra or ())
    for p in (agent_pidfile, watchdog_pidfile):
        if p is None:
            continue
        pid = read_pidfile(Path(p))
        if pid is not None:
            out.add(pid)
    if child_of is not None and child_of > 1:
        try:
            os.kill(child_of, 0)
            out.add(int(child_of))
        except OSError:
            pass
    if allowed_exe_paths or expected_sha256:
        trusted: set[int] = set()
        paths = set(allowed_exe_paths or ())
        for pid in out:
            if pid_matches_seal(pid, allowed_paths=paths, expected_sha256=expected_sha256):
                trusted.add(pid)
        return trusted
    return out
