from __future__ import annotations

import os
from pathlib import Path


def inode_to_process(inodes: set[str]) -> dict[str, str]:
    """Map socket inode -> 'name(pid)' best-effort via /proc."""
    if not inodes:
        return {}
    found: dict[str, str] = {}
    proc = Path("/proc")
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit()]
    except OSError:
        return {}
    for pdir in pids:
        if len(found) >= len(inodes):
            break
        fd_dir = pdir / "fd"
        if not fd_dir.is_dir():
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if not target.startswith("socket:["):
                    continue
                inode = target[8:-1]
                if inode in inodes and inode not in found:
                    name = _comm(pdir)
                    found[inode] = f"{name}({pdir.name})"
        except OSError:
            continue
    return found


def _comm(pdir: Path) -> str:
    try:
        return (pdir / "comm").read_text(encoding="utf-8").strip() or "?"
    except OSError:
        return "?"
