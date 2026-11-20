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


def _read_uid(pid: int) -> int | None:
    try:
        text = Path(f"/proc/{int(pid)}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def _read_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()[:400]


def looks_like_guard(pid: int) -> bool:
    """True when the process looks like ``python -m sysspectogram … guard|protect``."""
    exe = resolve_exe(pid)
    exe_s = str(exe) if exe is not None else ""
    base = Path(exe_s).name if exe_s else ""
    cmdline = _read_cmdline(pid).lower()
    has_mod = "sysspectogram" in cmdline
    has_role = "guard" in cmdline or "protect" in cmdline
    if has_mod and has_role:
        return True
    return "sysspectogram" in exe_s and "guard" in exe_s and bool(base)


def read_guard_pidfile(path: Path) -> int | None:
    """Accept guard.pid only when cmdline/uid match the file owner."""
    path = Path(path)
    pid = read_pidfile(path)
    if pid is None:
        return None
    try:
        file_uid = path.stat().st_uid
    except OSError:
        return None
    uid = _read_uid(pid)
    if uid is None:
        return None
    if file_uid != 0 and uid != file_uid:
        return None
    if not looks_like_guard(pid):
        return None
    return pid


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


def _ppid_of(pid: int) -> int | None:
    try:
        text = Path(f"/proc/{int(pid)}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("PPid:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def expand_descendant_pids(roots: set[int]) -> set[int]:
    """Add every live process whose ppid chain reaches one of ``roots``."""
    if not roots:
        return set()
    children: dict[int, list[int]] = {}
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return set(roots)
    for ent in entries:
        if not ent.name.isdigit():
            continue
        pid = int(ent.name)
        ppid = _ppid_of(pid)
        if ppid is None:
            continue
        children.setdefault(ppid, []).append(pid)
    out = set(roots)
    stack = list(roots)
    while stack:
        cur = stack.pop()
        for kid in children.get(cur, ()):
            if kid not in out:
                out.add(kid)
                stack.append(kid)
    return out


def collect_trusted_pids(
    *,
    agent_pidfile: Path,
    watchdog_pidfile: Path | None = None,
    guard_pidfile: Path | None = None,
    extra: set[int] | None = None,
    child_of: int | None = None,
    allowed_exe_paths: set[str] | None = None,
    expected_sha256: str | None = None,
    include_descendants: bool = False,
) -> set[int]:
    """PIDs allowed to speak on the agent socket.

    Same-UID alone is not enough: only these PIDs pass PEERCRED allowlist.
    Optional exe path + sha256 seal rejects a replaced binary that reused the pidfile.
    When ``include_descendants`` is true, children of trusted roots are included
    (guard probes, agent helpers) — never matched by forged ``comm``.
    """
    out: set[int] = set(extra or ())
    for p, kind in (
        (agent_pidfile, "agent"),
        (watchdog_pidfile, "watchdog"),
        (guard_pidfile, "guard"),
    ):
        if p is None:
            continue
        path = Path(p)
        if kind == "guard":
            pid = read_guard_pidfile(path)
        else:
            pid = read_pidfile(path)
            if pid is not None and allowed_exe_paths:
                # seal check applied below for the whole set
                pass
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
        out = trusted
    if include_descendants:
        out = expand_descendant_pids(out)
    return out
