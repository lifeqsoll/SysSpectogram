"""SECURITY.md policy strings for v1.4 polish."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "SECURITY.md"


def test_security_supported_versions_and_reporting() -> None:
    text = SECURITY.read_text(encoding="utf-8")
    assert "**1.4.x**" in text
    assert "**1.3.x**" in text
    assert "security/advisories/new" in text
    assert "sysspectogram" in text.lower()
    assert "Ban operations" in text or "ban operations" in text.lower()
