"""README must not state bare ML F1/% claims without EVAL.md."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_READMES = (ROOT / "README.md", ROOT / "README_RU.md")

# Headline performance claims (not the word F1 in troubleshooting tables).
_CLAIM_RE = re.compile(
    r"(?<![\w/])(?:F1\s*[=>:~]?\s*\d|(?:\d+(?:\.\d+)?)\s*%\s*(?:FP|FPR|false\s+positive))",
    re.I,
)


def test_readme_ml_claims_link_eval() -> None:
    for path in _READMES:
        text = path.read_text(encoding="utf-8")
        assert "EVAL.md" in text, f"{path.name} must link docs/EVAL.md for ML honesty"
        for i, line in enumerate(text.splitlines(), 1):
            if _CLAIM_RE.search(line):
                assert "EVAL" in line or "eval" in line.lower(), (
                    f"{path.name}:{i} performance claim without EVAL reference: {line.strip()!r}"
                )
