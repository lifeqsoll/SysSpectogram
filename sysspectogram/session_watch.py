"""Detect unexpected SSH / login sessions; optional kick."""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Iterable


@dataclass
class LoginSession:
    user: str
    tty: str
    host: str
    raw: str = ""


@dataclass
class SessionWatchState:
    seen: set[str] = field(default_factory=set)
    baseline_until: float = 0.0


def _parse_who(text: str) -> list[LoginSession]:
    rows: list[LoginSession] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # who -u / default: user tty date host
        parts = line.split()
        if len(parts) < 2:
            continue
        user, tty = parts[0], parts[1]
        host = ""
        m = re.search(r"\(([^)]+)\)", line)
        if m:
            host = m.group(1)
        rows.append(LoginSession(user=user, tty=tty, host=host, raw=line))
    return rows


def list_sessions() -> list[LoginSession]:
    try:
        out = subprocess.run(
            ["who"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if out.returncode != 0:
            return []
        return _parse_who(out.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        return []


def session_key(s: LoginSession) -> str:
    return f"{s.user}|{s.tty}|{s.host}"


def is_allowed_host(host: str, allow_cidrs: Iterable[str]) -> bool:
    if not host or host in ("-", ":0", "console"):
        return True
    # strip port-ish
    h = host.split("/")[0].strip()
    try:
        ip = ip_address(h)
    except ValueError:
        # hostname: allow if empty allowlist means "learn mode"
        return not list(allow_cidrs)
    nets = []
    for c in allow_cidrs:
        try:
            nets.append(ip_network(c, strict=False))
        except ValueError:
            continue
    if not nets:
        return True
    return any(ip in n for n in nets)


def kick_tty(tty: str, *, dry_run: bool = False) -> str:
    """Force logout of a tty (e.g. pts/0). Requires privileges."""
    tty = tty.strip()
    if not tty or "/" in tty or ".." in tty:
        return "refused bad tty"
    # who prints pts/0; pkill -t wants pts/0
    if dry_run:
        return f"dry-run kick {tty}"
    try:
        r = subprocess.run(
            ["pkill", "-KILL", "-t", tty],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if r.returncode in (0, 1):
            return f"kicked {tty}"
        return f"kick failed {tty}: {(r.stderr or r.stdout or '').strip()}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"kick error: {exc}"


def poll_unexpected(
    state: SessionWatchState,
    *,
    allow_users: set[str],
    allow_cidrs: list[str],
    learn_sec: float = 120.0,
) -> list[LoginSession]:
    """First learn_sec: record baseline. After: return new unexpected sessions."""
    now = time.time()
    if state.baseline_until <= 0:
        state.baseline_until = now + float(learn_sec)
    sessions = list_sessions()
    unexpected: list[LoginSession] = []
    for s in sessions:
        key = session_key(s)
        if now < state.baseline_until:
            state.seen.add(key)
            continue
        if key in state.seen:
            continue
        if allow_users and s.user not in allow_users:
            unexpected.append(s)
            continue
        if not is_allowed_host(s.host, allow_cidrs):
            unexpected.append(s)
            continue
        # new but allowed user/host - remember, no alert
        state.seen.add(key)
    return unexpected
