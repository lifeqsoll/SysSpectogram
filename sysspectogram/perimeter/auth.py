from __future__ import annotations

import ipaddress
import re
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)",
    re.I,
)
_INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)",
    re.I,
)
_ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)",
    re.I,
)


@dataclass
class AuthEvent:
    kind: str  # failed | invalid | accepted
    ip: str
    user: str
    raw: str
    ts: float


def _parse_line(line: str, ts: float | None = None) -> AuthEvent | None:
    ts = ts if ts is not None else datetime.now(timezone.utc).timestamp()
    m = _FAILED_RE.search(line)
    if m:
        return AuthEvent("failed", m.group("ip"), m.group("user"), line.strip(), ts)
    m = _INVALID_RE.search(line)
    if m:
        return AuthEvent("invalid", m.group("ip"), m.group("user"), line.strip(), ts)
    m = _ACCEPTED_RE.search(line)
    if m:
        return AuthEvent("accepted", m.group("ip"), m.group("user"), line.strip(), ts)
    return None


def parse_auth_lines(lines: list[str]) -> list[AuthEvent]:
    out: list[AuthEvent] = []
    for line in lines:
        ev = _parse_line(line)
        if ev is not None:
            out.append(ev)
    return out


def _tail_file(path: Path, max_bytes: int = 65536) -> list[str]:
    if not path.exists():
        return []
    try:
        data = path.read_bytes()
        if len(data) > max_bytes:
            data = data[-max_bytes:]
        text = data.decode("utf-8", errors="replace")
        return text.splitlines()
    except OSError:
        return []


def _journal_ssh(lines: int = 200) -> list[str]:
    for unit in ("sshd", "ssh"):
        try:
            proc = subprocess.run(
                ["journalctl", "-u", unit, "-n", str(lines), "-o", "cat", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            continue
    return []


class AuthWatcher:
    """Poll auth sources and yield only newly seen lines."""

    def __init__(self, extra_paths: list[Path] | None = None) -> None:
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._bootstrapped = False
        self.extra_paths = list(extra_paths or [])

    def poll(self) -> list[AuthEvent]:
        lines: list[str] = []
        lines.extend(_journal_ssh())
        for path in (Path("/var/log/auth.log"), Path("/var/log/secure"), *self.extra_paths):
            lines.extend(_tail_file(path))

        events: list[AuthEvent] = []
        for line in lines:
            key = line.strip()
            if not key or key in self._seen:
                continue
            self._seen[key] = None
            if not self._bootstrapped:
                continue
            ev = _parse_line(key)
            if ev is not None:
                events.append(ev)
        if not self._bootstrapped:
            self._bootstrapped = True
            return []
        while len(self._seen) > 5000:
            self._seen.popitem(last=False)
        return events


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )
