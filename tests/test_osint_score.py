"""OSINT score + cache unit tests."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.osint.cache import ReconCache
from sysspectogram.osint.score import compute_recon_score, append_dossier, DossierHit


def test_canary_score_one():
    s, notes = compute_recon_score(ip="1.2.3.4", canary_hit=True)
    assert s == 1.0
    assert "canary_hit" in notes


def test_cache_roundtrip(tmp_path: Path):
    c = ReconCache(db_path=tmp_path / "c.sqlite", ttl_sec=60)
    c.set("k", {"a": 1})
    assert c.get("k") == {"a": 1}


def test_dossier_append(tmp_path: Path):
    p = tmp_path / "d.jsonl"
    append_dossier(p, DossierHit(ip="9.9.9.9", ts=1.0, rule_id="x", severity="high", recon_score=0.5))
    assert p.read_text(encoding="utf-8").strip().startswith("{")
