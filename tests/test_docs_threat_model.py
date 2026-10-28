"""Phase 0.2 — threat model documents helper ban group."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_threat_model_and_security_cover_helper_ban_group() -> None:
    threat = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "sysspectogram" in threat.lower()
    assert "ban.add" in threat or "ban.add" in security
    assert "Helper ban path" in threat or "group" in threat.lower()
    assert "Ban operations" in security
    assert "never_ban" in threat.lower() or "never_ban" in security.lower()
