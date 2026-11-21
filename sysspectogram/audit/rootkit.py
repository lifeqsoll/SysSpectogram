from __future__ import annotations

import os
import re
import time
from pathlib import Path

_SUSPICIOUS_PREFIXES = (
    "/tmp/",
    "/dev/shm/",
    "/run/",
    "/var/tmp/",
    "memfd:",
)

_SYSTEM_PREFIXES = (
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/opt/",
)

_APT_UPGRADE_RE = re.compile(
    r"^(Upgrade|Install):\s+(.+)$",
    re.MULTILINE,
)
_DPKG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+status\s+installed\s+(\S+)",
)
_PACMAN_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\]\s+\[ALPM\]\s+(upgraded|installed)\s+(\S+)",
    re.MULTILINE,
)


def _strip_deleted(path: str) -> str:
    s = str(path).strip()
    if s.endswith(" (deleted)"):
        return s[: -len(" (deleted)")]
    return s


def _is_suspicious_deleted_path(clean: str) -> bool:
    if clean.startswith("memfd:"):
        return True
    for p in _SUSPICIOUS_PREFIXES:
        if clean.startswith(p):
            return True
    return False


def _looks_system_path(clean: str) -> bool:
    return any(clean.startswith(p) for p in _SYSTEM_PREFIXES)


def _pkg_name_guess(clean: str) -> str | None:
    """Best-effort package name from a binary path (for log substring match)."""
    base = Path(clean).name
    if not base:
        return None
    # systemd-logind → systemd; nginx → nginx
    if base.startswith("systemd"):
        return "systemd"
    return base.split(".")[0]


def _parse_apt_history(text: str, *, now: float, window_sec: float) -> set[str]:
    """Return package names touched by recent Upgrade/Install stanzas."""
    pkgs: set[str] = set()
    # Stanzas separated by blank lines; Start-Date marks time.
    blocks = re.split(r"\n\s*\n", text)
    for block in blocks:
        m_date = re.search(r"^Start-Date:\s*(.+)$", block, re.MULTILINE)
        if not m_date:
            continue
        try:
            # apt: 2024-01-02  03:04:05
            ts = time.mktime(time.strptime(m_date.group(1).strip()[:19], "%Y-%m-%d  %H:%M:%S"))
        except ValueError:
            try:
                ts = time.mktime(time.strptime(m_date.group(1).strip()[:19], "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                continue
        if now - ts > window_sec:
            continue
        for m in _APT_UPGRADE_RE.finditer(block):
            # "foo:amd64 (1.0, 1.1), bar:amd64 (...)"
            for part in m.group(2).split(","):
                name = part.strip().split()[0].split(":")[0]
                if name:
                    pkgs.add(name)
    return pkgs


def _parse_dpkg_log(text: str, *, now: float, window_sec: float) -> set[str]:
    pkgs: set[str] = set()
    for m in _DPKG_RE.finditer(text):
        try:
            ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
        if now - ts > window_sec:
            continue
        pkgs.add(m.group(2).split(":")[0])
    return pkgs


def _parse_pacman_log(text: str, *, now: float, window_sec: float) -> set[str]:
    pkgs: set[str] = set()
    for m in _PACMAN_RE.finditer(text):
        raw = m.group(1)
        try:
            # 2024-01-02T03:04:05+0000
            ts = time.mktime(time.strptime(raw[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            continue
        if now - ts > window_sec:
            continue
        pkgs.add(m.group(3))
    return pkgs


def recent_package_upgrades(
    *,
    now: float | None = None,
    window_sec: float = 7 * 86400.0,
    apt_history: Path | None = Path("/var/log/apt/history.log"),
    dpkg_log: Path | None = Path("/var/log/dpkg.log"),
    pacman_log: Path | None = Path("/var/log/pacman.log"),
) -> set[str]:
    """Package names recently installed/upgraded (best-effort from PM logs)."""
    now = time.time() if now is None else now
    pkgs: set[str] = set()
    for path, parser in (
        (apt_history, _parse_apt_history),
        (dpkg_log, _parse_dpkg_log),
        (pacman_log, _parse_pacman_log),
    ):
        if path is None:
            continue
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        pkgs |= parser(text, now=now, window_sec=window_sec)
    return pkgs


def deleted_exe_replaced_by_upgrade(
    deleted_path: str,
    *,
    pid: int | str | None = None,
    upgraded_packages: set[str] | None = None,
    now: float | None = None,
) -> bool:
    """True when (deleted) looks like a package binary replaced on disk."""
    clean = _strip_deleted(deleted_path)
    if _is_suspicious_deleted_path(clean):
        return False
    if not _looks_system_path(clean):
        return False
    now = time.time() if now is None else now
    # Replacement on disk newer than process start → classic apt/pacman upgrade.
    try:
        p = Path(clean)
        if p.is_file():
            mtime = p.stat().st_mtime
            start = None
            if pid is not None:
                try:
                    # /proc/PID/stat field 22 is starttime (clock ticks); prefer mtime of /proc/PID
                    start = Path(f"/proc/{pid}").stat().st_mtime
                except OSError:
                    start = None
            if start is not None and mtime >= start - 1.0:
                return True
            # Even without pid: recent mtime + matching package log.
            if mtime >= now - 7 * 86400:
                guess = _pkg_name_guess(clean)
                if upgraded_packages and guess and guess in upgraded_packages:
                    return True
                if upgraded_packages and any(g in clean for g in upgraded_packages):
                    return True
    except OSError:
        pass
    guess = _pkg_name_guess(clean)
    if upgraded_packages and guess and guess in upgraded_packages:
        return True
    if upgraded_packages and any(pkg and pkg in clean for pkg in upgraded_packages):
        return True
    return False


def classify_deleted_exe(
    deleted_path: str,
    *,
    pid: int | str | None = None,
    downgrade_on_upgrade: bool = True,
    upgraded_packages: set[str] | None = None,
    now: float | None = None,
) -> dict:
    """Build a deleted_exe finding with severity high|info."""
    clean = _strip_deleted(deleted_path)
    finding: dict = {
        "check": "deleted_exe",
        "pid": str(pid) if pid is not None else None,
        "path": str(deleted_path),
        "clean_path": clean,
        "severity": "high",
    }
    if not downgrade_on_upgrade:
        finding["note"] = "paranoid: auto-downgrade disabled"
        return finding
    if _is_suspicious_deleted_path(clean):
        finding["note"] = "suspicious location"
        return finding
    pkgs = upgraded_packages if upgraded_packages is not None else recent_package_upgrades(now=now)
    if deleted_exe_replaced_by_upgrade(
        deleted_path, pid=pid, upgraded_packages=pkgs, now=now
    ):
        finding["severity"] = "info"
        finding["note"] = "suppressed: package upgrade"
        unit_guess = Path(clean).name
        finding["hint"] = f"restart service using {unit_guess} (e.g. systemctl restart <unit>)"
        return finding
    if not _looks_system_path(clean):
        finding["note"] = "non-system path"
    else:
        finding["note"] = "no matching package upgrade"
    return finding


def rootkit_heuristics(
    *,
    downgrade_on_upgrade: bool = True,
    upgraded_packages: set[str] | None = None,
    proc_root: Path | None = None,
    max_pids: int = 200,
) -> list[dict]:
    """Best-effort Linux rootkit/tamper hints. Not authoritative."""
    findings: list[dict] = []
    # hidden process: /proc entry without matching cmdline readable? skip heavy scan
    for path in (Path("/usr/bin/ls"), Path("/bin/ls"), Path("/usr/bin/ps")):
        if path.exists():
            try:
                st = path.stat()
                # world-writable binary is suspicious
                if st.st_mode & 0o002:
                    findings.append({"check": "world_writable", "path": str(path)})
            except OSError:
                pass
    # unexpected LKM listing soft-fail
    modules = Path("/proc/modules")
    if modules.exists():
        try:
            text = modules.read_text(encoding="utf-8", errors="replace")
            for name in ("Diamorphine", "hide", "rootkit"):
                if name.lower() in text.lower():
                    findings.append({"check": "module_name", "hint": name})
        except OSError:
            pass
    # deleted binary still running: scan a few /proc/*/exe
    proc = proc_root or Path("/proc")
    pkgs = upgraded_packages
    if pkgs is None and downgrade_on_upgrade:
        pkgs = recent_package_upgrades()
    try:
        for pdir in list(proc.iterdir())[:max_pids]:
            if not pdir.name.isdigit():
                continue
            exe = pdir / "exe"
            try:
                target = exe.readlink()
            except OSError:
                continue
            if "(deleted)" in str(target) or str(target).startswith("memfd:"):
                findings.append(
                    classify_deleted_exe(
                        str(target),
                        pid=pdir.name,
                        downgrade_on_upgrade=downgrade_on_upgrade,
                        upgraded_packages=pkgs or set(),
                    )
                )
                if len(findings) > 20:
                    break
    except OSError:
        pass
    return findings
