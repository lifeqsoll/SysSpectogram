"""Tests must not embed realistic Telegram bot tokens (F-19)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"

# Realistic BotFather shape: long digit id + colon + long secret (often starts with AA).
_FORBIDDEN = re.compile(r"\b\d{8,}:[A-Za-z0-9_-]{20,}\b")


def test_no_realistic_bot_tokens_in_tests():
    offenders: list[str] = []
    for path in sorted(TESTS.rglob("*.py")):
        if path.name == "test_no_secret_like.py":
            continue
        text = path.read_text(encoding="utf-8")
        for m in _FORBIDDEN.finditer(text):
            token = m.group(0)
            if token.startswith("123:TEST_TOKEN"):
                continue
            offenders.append(f"{path.relative_to(ROOT)}:{token!r}")
    assert not offenders, "use 123:TEST_TOKEN instead:\n" + "\n".join(offenders)
