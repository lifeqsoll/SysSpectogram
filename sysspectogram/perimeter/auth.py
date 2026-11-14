from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# Real sshd auth lines only. Kind must be Failed/Invalid/Accepted — so
# ``Disconnected from invalid user …`` / ``Connection closed by …`` never match.
#
# Invalid-user names are attacker-controlled and may embed ``from <ip> port N``.
# For Failed/Invalid we take the sshd-written tail when it is unique; if the line
# has more than one ``from <ip> port``, we emit ``injection`` (no fail / no ban).
# For Accepted (validated user) the first ``from`` after the user wins.
_AUTH_RE = re.compile(
    r"^(?:"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+"
    r")?"
    r"(?:sshd(?:-session)?\[\d+\]:\s+)?"
    r"(?P<kind>Failed password for invalid user |Failed password for |Invalid user |Accepted \S+ for )"
    r"(?P<user>\S+)"
    r"(?P<rest>.*)$",
    re.I,
)
_FROM_IP_RE = re.compile(
    r" from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)",
    re.I,
)
# sshd writes the peer address at the end: ``from IP port N`` then optional ssh2/preauth.
_SSHD_TAIL_RE = re.compile(
    r" from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
    r"(?: ssh2)?(?: \[preauth\])?\s*$",
    re.I,
)
_CERT_TAIL_RE = re.compile(
    r"ssh2: \S+ SHA256:\S+(?: ID (?P<cert_id>.+?) \(serial (?P<cert_serial>\d+)\) CA \S+ SHA256:\S+)?",
    re.I,
)

_ACCEPTED_LOOSE_RE = re.compile(
    r"^(?:"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+"
    r")?"
    r"(?:sshd(?:-session)?\[\d+\]:\s+)?"
    r"Accepted \S+ for (?P<user>\S+)"
    r"(?P<rest>.*)$",
    re.I,
)


@dataclass
class AuthEvent:
    kind: str  # failed | invalid | accepted | injection | accepted_unparsed
    ip: str | None
    user: str
    raw: str
    ts: float
    cert_id: str | None = None
    cert_serial: str | None = None
    extras: dict = field(default_factory=dict)


def _normalize_auth_ip(raw: str) -> str | None:
    """Keep only a bare host address; drop forged CIDRs / junk from log injection.

    ``::ffff:x.x.x.x`` becomes the inner IPv4 so never_ban CIDRs match.
    """
    token = (raw or "").strip()
    if not token or "/" in token or "%" in token:
        return None
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        return None
    return str(addr)


def _all_from_ips(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _FROM_IP_RE.finditer(text or ""):
        ip = _normalize_auth_ip(match.group("ip"))
        if ip is None or ip in seen:
            continue
        seen.add(ip)
        out.append((ip, match.group("port")))
    return out


def _first_from_ip(text: str) -> tuple[str, str] | None:
    found = _all_from_ips(text)
    return found[0] if found else None


def _sshd_tail_ip(text: str) -> tuple[str, str] | None:
    match = _SSHD_TAIL_RE.search(text or "")
    if not match:
        return None
    ip = _normalize_auth_ip(match.group("ip"))
    if ip is None:
        return None
    return ip, match.group("port")


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
        kind = _kind_from_match(m.group("kind"))
        rest = m.group("rest") or ""
        all_ips = _all_from_ips(rest)
        if kind in {"failed", "invalid"}:
            if len(all_ips) > 1:
                ips = [ip for ip, _ in all_ips]
                tail = _sshd_tail_ip(rest)
                return AuthEvent(
                    "injection",
                    tail[0] if tail else None,
                    m.group("user"),
                    text,
                    ts,
                    extras={"ips": ips, "rule_hint": "auth_log_injection"},
                )
            if not all_ips:
                return None
            # Prefer the sshd-written end-of-line peer when present.
            tail = _sshd_tail_ip(rest)
            ip, _port = tail if tail else all_ips[0]
            return AuthEvent(kind, ip, m.group("user"), text, ts)
        # Accepted: first from after user (cert ID may contain forged from).
        found = _first_from_ip(rest)
        if found is None:
            return None
        ip, _port = found
        cert_m = _CERT_TAIL_RE.search(rest)
        cert_id = _sanitize_cert_id(cert_m.group("cert_id") if cert_m else None)
        cert_serial = cert_m.group("cert_serial") if cert_m else None
        if cert_id is None and cert_serial and "ID " in text:
            return AuthEvent(
                "accepted_unparsed",
                ip,
                m.group("user"),
                text,
                ts,
            )
        return AuthEvent(
            kind,
            ip,
            m.group("user"),
            text,
            ts,
            cert_id=cert_id,
            cert_serial=cert_serial,
        )
    if re.search(r"(?i)\bAccepted \S+ for ", text):
        loose = _ACCEPTED_LOOSE_RE.search(text)
        if loose:
            found = _first_from_ip(loose.group("rest") or "")
            if found is not None:
                ip, _port = found
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


def _auth_tail_helper(lines: int = 200, cursor: str | None = None) -> tuple[list[str], bool]:
    """Return ``(lines, available)``. ``available`` is True when helper answered ok."""
    from sysspectogram.response.helper_ban import HelperBanBackend, helper_available

    if not helper_available():
        return [], False
    args: dict[str, object] = {"limit": int(lines)}
    if cursor:
        args["cursor"] = cursor
    reply = HelperBanBackend()._call("auth.tail", args)
    if not reply.get("ok"):
        return [], False
    data = reply.get("data") or {}
    raw = data.get("lines") or []
    return [str(x) for x in raw if str(x).strip()], True


def _journal_denied(text: str) -> bool:
    low = (text or "").lower()
    return "no journal files" in low or "not seeing messages from other users" in low


def _in_journal_group() -> bool:
    import grp

    wanted = {"systemd-journal", "adm", "wheel"}
    try:
        names = {grp.getgrgid(gid).gr_name for gid in os.getgroups()}
    except OSError:
        return False
    return bool(names & wanted)


def _journal_ssh_reachable(lines: int = 1) -> bool:
    """True only when this user can actually read the system journal.

    ``journalctl`` exits 0 for "No journal files were found" and for a user
    who only sees their own journal. Those are not an ssh source.
    """
    import os

    try:
        # No -q: it hides "No journal files were found", which still exits 0.
        proc = subprocess.run(
            ["journalctl", "--system", "-n", str(max(1, lines)), "--no-pager"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if _journal_denied(blob):
        return False
    if (proc.stdout or "").strip():
        return True
    # Journal exists but has no lines yet (rc 0, no denial text).
    privileged = os.geteuid() == 0 or _in_journal_group()
    return privileged and proc.returncode == 0


def ssh_auth_lines(lines: int = 200) -> tuple[list[str], str]:
    """Recent sshd journal lines and a short source tag (journal | helper | none).

    Empty lines with a working source still return ``journal`` / ``helper`` so
    health can distinguish «no access» from «fresh server, zero events».
    """
    got = _journal_ssh(lines)
    if got:
        return got, "journal"
    helper_lines, helper_ok = _auth_tail_helper(lines)
    if helper_lines:
        return helper_lines, "helper"
    if helper_ok:
        return [], "helper"
    if _journal_ssh_reachable():
        return [], "journal"
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
