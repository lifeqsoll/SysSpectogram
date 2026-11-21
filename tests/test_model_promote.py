"""Shadow → live promotion and rollback, gated by the supply-chain manifest."""

from __future__ import annotations

from pathlib import Path

import pytest

from sysspectogram.ml.model_promote import (
    promote,
    read_ml_phase,
    rollback,
    stage,
    write_ml_phase,
)
from sysspectogram.supply_chain import ManifestError, write_manifest


def _tree(path: Path, body: bytes) -> Path:
    path.mkdir(parents=True)
    (path / "model.bin").write_bytes(body)
    write_manifest(path)
    return path


def test_phase_roundtrip(tmp_path: Path) -> None:
    dest = tmp_path / "state" / "ml_phase.json"
    assert read_ml_phase(dest) == "off"
    write_ml_phase(dest, "shadow")
    assert read_ml_phase(dest) == "shadow"
    write_ml_phase(dest, "LIVE")
    assert read_ml_phase(dest) == "live"
    with pytest.raises(ValueError):
        write_ml_phase(dest, "prod")


def test_stage_promote_rollback(tmp_path: Path) -> None:
    src = _tree(tmp_path / "candidate", b"shadow-model")
    live = _tree(tmp_path / "ml-live", b"live-model")
    previous = tmp_path / "ml-previous"
    shadow = stage(src, tmp_path / "ml-shadow")
    assert (shadow / "model.bin").read_bytes() == b"shadow-model"

    promote(shadow, live, previous, supply_chain={"enforce": False})
    assert (live / "model.bin").read_bytes() == b"shadow-model"
    assert (previous / "model.bin").read_bytes() == b"live-model"
    assert not shadow.exists()

    rollback(live, previous)
    assert (live / "model.bin").read_bytes() == b"live-model"
    assert (previous / "model.bin").read_bytes() == b"shadow-model"


def test_promote_refuses_tampered_manifest(tmp_path: Path) -> None:
    src = _tree(tmp_path / "candidate", b"good")
    live = _tree(tmp_path / "ml-live", b"keep")
    shadow = stage(src, tmp_path / "ml-shadow")
    (shadow / "model.bin").write_bytes(b"tampered")
    with pytest.raises(ManifestError):
        promote(shadow, live, tmp_path / "ml-previous", supply_chain={"enforce": False})
    assert (live / "model.bin").read_bytes() == b"keep"
    assert shadow.is_dir()
