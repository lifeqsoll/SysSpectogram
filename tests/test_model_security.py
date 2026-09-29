"""Model artifact trust-boundary tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from sysspectogram.ml.infer import load_inferencer
from sysspectogram.supply_chain import ManifestError, write_manifest


def _minimal_model_dir(tmp_path: Path) -> Path:
    model = tmp_path / "model"
    model.mkdir()
    (model / "meta.json").write_text(
        '{"columns": ["cpu_percent"], "window_size": 2}\n',
        encoding="utf-8",
    )
    (model / "cnn.pt").write_bytes(b"not a checkpoint")
    return model


def test_enforced_inference_rejects_unsigned_artifacts_before_deserialization(
    tmp_path: Path,
):
    model = _minimal_model_dir(tmp_path)
    with pytest.raises(ManifestError, match="manifest required"):
        load_inferencer(model, runtime="torch_ml", supply_chain={"enforce": True})


def test_manifest_is_required_before_legacy_model_loading(tmp_path: Path):
    model = _minimal_model_dir(tmp_path)
    write_manifest(model)
    with pytest.raises(Exception) as error:
        load_inferencer(model, runtime="torch_ml", supply_chain={"enforce": False})
    assert "checkpoint" in str(error.value).lower() or "torch" in str(error.value).lower()


def test_checkpoint_loader_never_falls_back_to_unsafe_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    model = _minimal_model_dir(tmp_path)
    write_manifest(model)
    import torch

    calls: list[dict] = []

    def fake_load(*args, **kwargs):
        calls.append(kwargs)
        raise RuntimeError("safe loader rejected checkpoint")

    monkeypatch.setattr(torch, "load", fake_load)
    with pytest.raises(RuntimeError, match="safe loader rejected"):
        load_inferencer(model, runtime="torch_ml", supply_chain={"enforce": False})
    assert calls == [{"map_location": "cpu", "weights_only": True}]
