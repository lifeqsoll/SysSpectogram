"""CHANGELOG.md tracks Keep-a-Changelog sections."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"


def _project_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m
    return m.group(1)


def test_changelog_keep_a_changelog_and_version_section() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    assert "keepachangelog.com" in text.lower() or "Keep a Changelog" in text
    assert "## [Unreleased]" in text
    assert "## [1.4.0]" in text
    ver = _project_version()
    assert f"## [{ver}]" in text, f"missing changelog section for pyproject version {ver}"
    assert "docs/RELEASE_" in text
