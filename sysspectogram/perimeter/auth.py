from __future__ import annotations

import ipaddress
import re
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# Real sshd auth lines only. Kind must be Failed/Invalid/Accepted — so
# ``Disconnected from invalid user …`` / ``Connection closed by …`` never match
# (no separate noise filter: a substring ``Disconnected`` must not hide real fails).
#
# Optional classic syslog or RFC3339 prefix + ``sshd`` / ``sshd-session`` tag
# (journalctl -o cat may strip both). End-anchored ``from <ip> port N`` so a forged
# CIDR earlier in the line cannot win. Accepted publickey may append
# ``ssh2: ED25519 SHA256:…`` or certificate
# ``ssh2: ED25519-CERT SHA256:… ID user@corp (serial N) CA ED25519 SHA256:…``.
_AUTH_RE = re.compile(
    r"^(?:"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+"
    r")?"
    r"(?:sshd(?:-session)?\[\d+\]:\s+)?"
    r"(?P<kind>Failed password for invalid user |Failed password for |Invalid user |Accepted \S+ for )"
    r"(?P<user>\S+)"
    r".* from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
    r"(?: ssh2(?:: \S+ SHA256:\S+"
    r"(?: ID (?P<cert_id>.+?) \(serial (?P<cert_serial>\d+)\) CA \S+ SHA256:\S+)?"
    r")?)?\s*$",
    re.I,
)

# Loose Accepted line when the strict cert/fingerprint tail fails (spaces in cert ID, etc.).
_ACCEPTED_LOOSE_RE = re.compile(
    r"^(?:"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+"
    r")?"
    r"(?:sshd(?:-session)?\[\d+\]:\s+)?"
    r"Accepted \S+ for (?P<user>\S+)"
    r".* from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)",
    re.I,
)


@dataclass
class AuthEvent:
    kind: str  # failed | invalid | accepted
    ip: str
    user: str
    raw: str
    ts: float
    cert_id: str | None = None
    cert_serial: str | None = None


def _normalize_auth_ip(raw: str) -> str | None:
    """Keep only a bare host address; drop forged CIDRs / junk from log injection."""
    token = (raw or "").strip()
    if not token or "/" in token or "%" in token:
        return None
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        return None
    return str(addr)


def _kind_from_match(kind_token: str) -> str:
    low = (kind_token or "").lower()
    if "invalid user" in low:
        return "invalid"
    if low.startswith("accepted"):
        return "accepted"
    return "failed"


def _parse_line(line: str, ts: float | None = None) -> AuthEvent | None:
    ts = ts if ts is not None else datetime.now(timezone.utc).timestamp()
    text = (line or "").strip()
    if not text:
        return None
    m = _AUTH_RE.match(text)
    if m:
        ip = _normalize_auth_ip(m.group("ip"))
        if ip is None:
            return None
        return AuthEvent(
            _kind_from_match(m.group("kind")),
            ip,
            m.group("user"),
            text,
            ts,
            cert_id=m.groupdict().get("cert_id"),
            cert_serial=m.groupdict().get("cert_serial"),
        )
    # Accepted with unusual cert ID (spaces / quotes) that broke the strict tail.
    if re.search(r"(?i)\bAccepted \S+ for ", text):
        loose = _ACCEPTED_LOOSE_RE.search(text)
        if loose:
            ip = _normalize_auth_ip(loose.group("ip"))
            if ip is not None:
                return AuthEvent(
                    "accepted_unparsed",
                    ip,
                    loose.group("user"),
                    text,
                    ts,
                )
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
