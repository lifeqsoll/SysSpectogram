"""Non-UTF8 /proc comm must not crash perimeter mapping."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.perimeter.proc_map import _comm


def test_comm_replaces_invalid_utf8(tmp_path: Path):
    pdir = tmp_path / "1234"
    pdir.mkdir()
    (pdir / "comm").write_bytes(b"ev\xff\xfel\n")
    name = _comm(pdir)
    assert isinstance(name, str)
    assert name != ""
    assert "\ufffd" in name or "ev" in name


def test_comm_missing_file(tmp_path: Path):
    pdir = tmp_path / "999"
    pdir.mkdir()
    assert _comm(pdir) == "?"
