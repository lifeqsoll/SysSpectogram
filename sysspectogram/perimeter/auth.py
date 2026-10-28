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
    r".*? from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
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
    r".*? from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)",
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


def _sanitize_cert_id(raw: str | None) -> str | None:
    """Drop forged ``from … port …`` tails that leaked into the cert ID capture."""
    if raw is None:
        return None
    s = raw.strip().strip('"')
    for sep in (" from ", " port "):
        idx = s.find(sep)
        if idx >= 0:
            s = s[:idx].rstrip()
    if not s or s.lower().startswith("from"):
        return None
    return s


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
        cert_id = _sanitize_cert_id(m.groupdict().get("cert_id"))
        cert_serial = m.groupdict().get("cert_serial")
        if cert_id is None and cert_serial and "ID " in text:
            loose = _ACCEPTED_LOOSE_RE.search(text)
            if loose and _normalize_auth_ip(loose.group("ip")) == ip:
                return AuthEvent(
                    "accepted_unparsed",
                    ip,
                    m.group("user"),
                    text,
                    ts,
                )
        return AuthEvent(
            _kind_from_match(m.group("kind")),
            ip,
            m.group("user"),
            text,
            ts,
            cert_id=cert_id,
            cert_serial=cert_serial,
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
    specs: list[list[str]] = [
        ["-u", "sshd"],
        ["-u", "sshd-session"],
        ["-u", "ssh"],
        ["_COMM=sshd-session"],
        ["_COMM=sshd"],
    ]
    for spec in specs:
        try:
            proc = subprocess.run(
                ["journalctl", *spec, "-n", str(lines), "-o", "cat", "--no-pager"],
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


def _auth_tail_helper(lines: int = 200, cursor: str | None = None) -> list[str]:
    from sysspectogram.response.helper_ban import HelperBanBackend, helper_available

    if not helper_available():
        return []
    args: dict[str, object] = {"limit": int(lines)}
    if cursor:
        args["cursor"] = cursor
    reply = HelperBanBackend()._call("auth.tail", args)
    if not reply.get("ok"):
        return []
    data = reply.get("data") or {}
    raw = data.get("lines") or []
    return [str(x) for x in raw if str(x).strip()]


def ssh_auth_lines(lines: int = 200) -> tuple[list[str], str]:
    """Recent sshd journal lines and a short source tag (journal | helper | none)."""
    got = _journal_ssh(lines)
    if got:
        return got, "journal"
    got = _auth_tail_helper(lines)
    if got:
        return got, "helper"
    return [], "none"


class AuthWatcher:
    """Poll auth sources and yield only newly seen lines."""

    def __init__(self, extra_paths: list[Path] | None = None) -> None:
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._bootstrapped = False
        self.extra_paths = list(extra_paths or [])

    def poll(self) -> list[AuthEvent]:
        lines: list[str] = []
        journal_lines, _src = ssh_auth_lines()
        lines.extend(journal_lines)
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
