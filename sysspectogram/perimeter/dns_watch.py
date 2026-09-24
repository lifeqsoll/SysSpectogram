from __future__ import annotations

import re
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone


_QUERY_RE = re.compile(r"(?:query|lookup).*?\b(?P<name>[a-zA-Z0-9._-]+\.[a-zA-Z]{2,})\b", re.I)


@dataclass
class DnsEvent:
    name: str
    raw: str
    ts: float


class DnsWatcher:
    def __init__(self) -> None:
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._bootstrapped = False

    def poll(self) -> list[DnsEvent]:
        lines: list[str] = []
        try:
            proc = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    "systemd-resolved",
                    "-n",
                    "100",
                    "-o",
                    "cat",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                lines = proc.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            lines = []

        out: list[DnsEvent] = []
        now = datetime.now(timezone.utc).timestamp()
        for line in lines:
            key = line.strip()
            if not key or key in self._seen:
                continue
            self._seen[key] = None
            if not self._bootstrapped:
                continue
            m = _QUERY_RE.search(key)
            if m:
                out.append(DnsEvent(m.group("name").lower(), key, now))
        if not self._bootstrapped:
            self._bootstrapped = True
        while len(self._seen) > 3000:
            self._seen.popitem(last=False)
        return out
