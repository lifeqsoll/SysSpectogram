#!/usr/bin/env python3
"""CI check: every top-level CLI subcommand has a row in docs/CONTROL_CENTER.md.

Top-level commands are the `sub.add_parser(...)` calls at the root parser level.
Nested subcommands (for example `profiles pack`) are not listed separately.
Exit code 0 when the table and the CLI agree, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "sysspectogram" / "cli.py"
DOC = ROOT / "docs" / "CONTROL_CENTER.md"

TOP_LEVEL = re.compile(r'^    \w+ = sub\.add_parser\("([\w-]+)"', re.M)
ROW = re.compile(r"^\| `([\w-]+)` \|", re.M)
SECTION = "## CLI parity matrix"


def cli_commands(text: str) -> set[str]:
    return set(TOP_LEVEL.findall(text))


def documented_commands(text: str) -> set[str]:
    start = text.find(SECTION)
    if start < 0:
        return set()
    body = text[start + len(SECTION) :]
    end = body.find("\n## ")
    if end >= 0:
        body = body[:end]
    return set(ROW.findall(body))


def main() -> int:
    cli = cli_commands(CLI.read_text(encoding="utf-8"))
    doc = documented_commands(DOC.read_text(encoding="utf-8"))
    missing = sorted(cli - doc)
    extra = sorted(doc - cli)
    for name in missing:
        print(f"FAIL missing from {DOC.name}: {name}")
    for name in extra:
        print(f"FAIL documented but not in CLI: {name}")
    print(f"cli={len(cli)} documented={len(doc)} missing={len(missing)} extra={len(extra)}")
    return 1 if missing or extra else 0


if __name__ == "__main__":
    sys.exit(main())
